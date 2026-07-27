//! File-system access layer for cached PostgreSQL binaries and database
//! clusters.
//!
//! [`PgAccess`] encapsulates all paths used by pg-embed (cache dir, database
//! dir, executable paths, password file) and provides the operations that act
//! on those paths: downloading, unpacking, writing the password file, and
//! cleaning up.
//!
//! The module-level static `ACQUIRED_PG_BINS` prevents concurrent downloads
//! of the same binaries when multiple [`crate::postgres::PgEmbed`] instances
//! start simultaneously.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::pg_enums::{OperationSystem, PgAcquisitionStatus};
use crate::pg_errors::Error;
use crate::pg_errors::Result;
use crate::pg_fetch::PgFetchSettings;
use crate::pg_unpack;

/// Guards concurrent binary downloads across multiple
/// [`crate::postgres::PgEmbed`] instances.
///
/// The key is the cache directory path; the value tracks whether acquisition
/// is in progress or finished.  Protected by a [`Mutex`] to allow only one
/// download per unique cache path at a time.
static ACQUIRED_PG_BINS: LazyLock<Arc<Mutex<HashMap<PathBuf, PgAcquisitionStatus>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::with_capacity(5))));

const PG_EMBED_CACHE_DIR_NAME: &str = "pg-embed";
const PG_VERSION_FILE_NAME: &str = "PG_VERSION";
const VERIFIED_PACKAGE_MARKER: &str = ".olympus-verified-package.sha256";
const MAX_POSTGRES_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const CACHE_LEASE_TIMEOUT: Duration = Duration::from_secs(30);
const CACHE_LEASE_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// Retained no-follow directory handles for a security-sensitive path and its
/// mutable ancestors.
///
/// On Windows the handles deny delete sharing, preventing junction/ancestor
/// replacement while a cache or instance lock is live. Unix relies on
/// owner/mode validation and retains the handles for identity diagnostics.
#[derive(Debug)]
pub struct PrivateDirectoryGuard {
    _handles: Vec<File>,
}

/// Create missing components one at a time and retain a validated,
/// owner-private directory chain.
///
/// Existing ancestors must be owned by the current account or by the
/// operating-system root and must not grant untrusted mutation. Symlinks,
/// junctions, and all other reparse points fail closed.
pub fn ensure_private_directory(path: &Path) -> Result<PrivateDirectoryGuard> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| Error::ReadFileError(error.to_string()))?
            .join(path)
    };
    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        if current.as_os_str().is_empty() {
            continue;
        }
        let target = current == absolute;
        let created = match std::fs::symlink_metadata(&current) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = std::fs::DirBuilder::new();
                    builder.mode(0o700);
                    builder
                        .create(&current)
                        .map_err(|error| Error::DirCreationError(error.to_string()))?;
                }
                #[cfg(target_os = "windows")]
                std::fs::create_dir(&current)
                    .map_err(|error| Error::DirCreationError(error.to_string()))?;
                true
            }
            Err(error) => return Err(Error::ReadFileError(error.to_string())),
        };
        let handle = open_directory_no_follow(&current, created || target)?;
        validate_directory_handle(&handle, created || target, target)?;
        handles.push(handle);
    }
    Ok(PrivateDirectoryGuard { _handles: handles })
}

/// Validate and owner-harden an already-open regular file without following a
/// replacement pathname.
pub fn secure_private_file_handle(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::InvalidPgPackage);
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::InvalidPgPackage);
        }
        if metadata.permissions().mode() & 0o077 != 0
            && unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
        {
            return Err(Error::WriteFileError(
                std::io::Error::last_os_error().to_string(),
            ));
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::InvalidPgPackage);
        }
        restrict_windows_handle_to_current_user(file)?;
        if !windows_handle_permissions_are_private(file)? {
            return Err(Error::InvalidPgPackage);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_directory_no_follow(path: &Path, _writable_security: bool) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|error| Error::ReadFileError(error.to_string()))
}

#[cfg(target_os = "windows")]
fn open_directory_no_follow(path: &Path, writable_security: bool) -> Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
        WRITE_DAC,
    };

    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let access =
        FILE_READ_ATTRIBUTES | READ_CONTROL | if writable_security { WRITE_DAC } else { 0 };
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(Error::ReadFileError(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let owned = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    Ok(File::from(owned))
}

#[cfg(unix)]
fn validate_directory_handle(handle: &File, private: bool, target: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = handle
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::InvalidPgPackage);
    }
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid && metadata.uid() != 0 {
        return Err(Error::InvalidPgPackage);
    }
    let mode = metadata.permissions().mode();
    if private {
        if metadata.uid() != euid {
            return Err(Error::InvalidPgPackage);
        }
        if mode & 0o077 != 0 && unsafe { libc::fchmod(handle.as_raw_fd(), 0o700) } != 0 {
            return Err(Error::WriteFileError(
                std::io::Error::last_os_error().to_string(),
            ));
        }
    } else if mode & 0o022 != 0 {
        // Root-owned sticky directories such as /tmp protect entries from
        // other accounts and are acceptable ancestors, but never targets.
        let sticky_root = metadata.uid() == 0 && mode & 0o1000 != 0 && !target;
        if !sticky_root {
            return Err(Error::InvalidPgPackage);
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn validate_directory_handle(handle: &File, private: bool, _target: bool) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let metadata = handle
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::InvalidPgPackage);
    }
    if private {
        restrict_windows_handle_to_current_user(handle)?;
        if !windows_handle_permissions_are_private(handle)? {
            return Err(Error::InvalidPgPackage);
        }
    }
    // Non-target ancestors may legitimately inherit broad creation rights
    // (for example a user's Downloads directory or the system temp root).
    // Their retained handles deliberately omit FILE_SHARE_DELETE, so the
    // already-open ancestor chain cannot be renamed, deleted, or replaced
    // while the private target is live. Only the target itself needs a
    // current-user-only DACL.
    Ok(())
}

/// Manages all file-system paths and I/O operations for a single pg-embed
/// instance.
///
/// Created by [`PgAccess::new`], which also creates the required directory
/// structure.  All path fields are derived from the fetch settings and the
/// caller-supplied database directory.
///
/// # Cache layout
///
/// ```text
/// {cache_dir}/pg-embed/{os}/{arch}/{version}/
///   bin/pg_ctl
///   bin/initdb
///   bin/postgres
///   {platform}-{version}.zip
/// ```
pub struct PgAccess {
    /// Stable owner-private root containing every versioned cache and lock.
    cache_root: PathBuf,
    /// Root of the per-version binary cache.
    pub cache_dir: PathBuf,
    /// Directory that holds the PostgreSQL cluster data files.
    pub database_dir: PathBuf,
    /// Path to the `pg_ctl` executable inside the cache.
    pub pg_ctl_exe: PathBuf,
    /// Path to the `initdb` executable inside the cache.
    pub init_db_exe: PathBuf,
    /// Path to the password file used by `initdb`.
    pub pw_file_path: PathBuf,
    /// Path where the downloaded JAR is written before unpacking.
    pub zip_file_path: PathBuf,
    /// `PG_VERSION` file inside the cluster directory; used to detect an
    /// already-initialised cluster.
    pg_version_file: PathBuf,
    /// Download settings used to reconstruct the cache path.
    fetch_settings: PgFetchSettings,
}

/// Canonical server path plus its archive-derived SHA-256 identity.
#[derive(Clone, Debug)]
pub struct AuthenticatedPostgresExecutable {
    pub path: PathBuf,
    pub sha256: [u8; 32],
    _executable: VerifiedExecutable,
}

impl PartialEq for AuthenticatedPostgresExecutable {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.sha256 == other.sha256
    }
}

impl Eq for AuthenticatedPostgresExecutable {}

#[derive(Debug)]
struct CacheLease {
    _lock: File,
    _lock_namespace: PrivateDirectoryGuard,
    _cache_parent: PrivateDirectoryGuard,
}

/// An executable opened and hashed while the versioned cache lease is held.
///
/// Windows keeps a no-write/no-delete sharing handle open. Unix validates a
/// regular no-follow inode inside an owner-controlled, non-group/world-writable
/// cache tree and keeps both that inode and the cross-process cache lease open.
#[derive(Clone, Debug)]
pub struct VerifiedExecutable {
    path: PathBuf,
    sha256: [u8; 32],
    handle: Arc<File>,
    lease: Arc<CacheLease>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(target_os = "windows")]
    volume_serial: u32,
    #[cfg(target_os = "windows")]
    file_index: u64,
}

impl VerifiedExecutable {
    /// Canonical executable pathname retained for process-identity reporting.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Archive-derived SHA-256 of this executable.
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Clone the already-open image handle for capability-owned launch.
    pub(crate) fn retained_file(&self) -> Arc<File> {
        self.handle.clone()
    }

    /// Recheck the pathname immediately before capability-owned launch.
    ///
    /// The launched Unix image is the retained descriptor itself. Windows
    /// additionally keeps the executable and ancestor handles open without
    /// delete sharing while `CreateProcessW` resolves this checked pathname.
    pub(crate) fn verify_for_launch(&self) -> Result<()> {
        let _lease = &self.lease;
        let (file, digest) = open_verified_file(&self.path)?;
        if digest != self.sha256 {
            return Err(Error::InvalidPgPackage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = file
                .metadata()
                .map_err(|error| Error::ReadFileError(error.to_string()))?;
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(Error::InvalidPgPackage);
            }
        }
        #[cfg(target_os = "windows")]
        {
            let (volume_serial, file_index) = windows_file_identity(&file)?;
            if volume_serial != self.volume_serial || file_index != self.file_index {
                return Err(Error::InvalidPgPackage);
            }
        }
        Ok(())
    }
}

/// Complete retained executable/cache capability for one PgEmbed lifecycle.
#[derive(Clone, Debug)]
pub struct AuthenticatedPostgresExecutables {
    pub initdb: VerifiedExecutable,
    pub pg_ctl: VerifiedExecutable,
    pub postgres: VerifiedExecutable,
    _lease: Arc<CacheLease>,
}

impl AuthenticatedPostgresExecutables {
    fn postgres_identity(&self) -> AuthenticatedPostgresExecutable {
        AuthenticatedPostgresExecutable {
            path: self.postgres.path.clone(),
            sha256: self.postgres.sha256,
            _executable: self.postgres.clone(),
        }
    }
}

fn open_regular_file_no_follow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::InvalidPgPackage);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::InvalidPgPackage);
        }
    }
    Ok(file)
}

fn open_verified_file(path: &Path) -> Result<(File, [u8; 32])> {
    let mut file = open_regular_file_no_follow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::ReadFileError(error.to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    file.rewind()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    Ok((file, hasher.finalize().into()))
}

fn verified_executable(
    path: &Path,
    expected_sha256: [u8; 32],
    lease: Arc<CacheLease>,
) -> Result<VerifiedExecutable> {
    let canonical =
        std::fs::canonicalize(path).map_err(|error| Error::ReadFileError(error.to_string()))?;
    let (file, digest) = open_verified_file(&canonical)?;
    if digest != expected_sha256 {
        return Err(Error::InvalidPgPackage);
    }
    #[cfg(unix)]
    let metadata = file
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    #[cfg(target_os = "windows")]
    let (volume_serial, file_index) = windows_file_identity(&file)?;
    Ok(VerifiedExecutable {
        path: canonical,
        sha256: digest,
        handle: Arc::new(file),
        lease,
        #[cfg(unix)]
        device: {
            use std::os::unix::fs::MetadataExt;
            metadata.dev()
        },
        #[cfg(unix)]
        inode: {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        },
        #[cfg(target_os = "windows")]
        volume_serial,
        #[cfg(target_os = "windows")]
        file_index,
    })
}

#[cfg(target_os = "windows")]
fn windows_file_identity(file: &File) -> Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` owns a valid handle and `information` is writable for the
    // documented output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0 {
        return Err(Error::ReadFileError(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, file_index))
}

#[cfg(target_os = "windows")]
fn windows_current_user_sid_buffer() -> Result<Vec<usize>> {
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle is valid and `token` is a writable out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
        || token.is_null()
    {
        return Err(Error::ReadFileError(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    // SAFETY: OpenProcessToken returned a new owned kernel handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };

    let mut token_bytes = 0_u32;
    // SAFETY: a null buffer with zero length requests the required size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut token_bytes,
        );
    }
    if (token_bytes as usize) < size_of::<TOKEN_USER>() {
        return Err(Error::InvalidPgPackage);
    }
    let mut token_buffer = vec![0_usize; (token_bytes as usize).div_ceil(size_of::<usize>())];
    // SAFETY: the usize-backed allocation is aligned and sized for TOKEN_USER
    // plus its variable-length SID.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            token_buffer.as_mut_ptr().cast(),
            token_bytes,
            &mut token_bytes,
        )
    } == 0
    {
        return Err(Error::ReadFileError(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(token_buffer)
}

#[cfg(target_os = "windows")]
fn windows_handle_permissions_are_private(file: &File) -> Result<bool> {
    windows_handle_permissions(file, true)
}

#[cfg(target_os = "windows")]
fn windows_handle_permissions(file: &File, private: bool) -> Result<bool> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetExplicitEntriesFromAclW,
        GetSecurityInfo, SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_IS_SID,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorControl,
        OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED, SECURITY_MAX_SID_SIZE, TOKEN_USER,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES,
        FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    };

    struct LocalAllocation(*mut std::ffi::c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    let current_user = windows_current_user_sid_buffer()?;
    let current_sid = unsafe { (*(current_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    if current_sid.is_null() {
        return Err(Error::InvalidPgPackage);
    }
    let mut system_sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut system_len = system_sid.len() as u32;
    let mut admins_sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut admins_len = admins_sid.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            system_sid.as_mut_ptr().cast(),
            &mut system_len,
        )
    } == 0
        || unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                admins_sid.as_mut_ptr().cast(),
                &mut admins_len,
            )
        } == 0
    {
        return Err(Error::ReadFileError(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let system_sid_ptr: PSID = system_sid.as_mut_ptr().cast();
    let admins_sid_ptr: PSID = admins_sid.as_mut_ptr().cast();
    // Installation roots are commonly owned by the Windows Modules Installer
    // service rather than SYSTEM or the Administrators group.
    let trusted_installer_text: Vec<u16> =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
            .encode_utf16()
            .chain(Some(0))
            .collect();
    let mut trusted_installer_sid = std::ptr::null_mut();
    if unsafe {
        ConvertStringSidToSidW(trusted_installer_text.as_ptr(), &mut trusted_installer_sid)
    } == 0
        || trusted_installer_sid.is_null()
    {
        return Err(Error::ReadFileError(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    let mut owner_sid = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner_sid,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
        unsafe {
            if !descriptor.is_null() {
                LocalFree(descriptor);
            }
            LocalFree(trusted_installer_sid);
        }
        return Err(Error::ReadFileError(
            std::io::Error::from_raw_os_error(status as i32).to_string(),
        ));
    }

    let result = (|| {
        if owner_sid.is_null() || dacl.is_null() {
            return Ok(false);
        }
        let trusted_sid = |sid: PSID| {
            !sid.is_null()
                && (unsafe { EqualSid(current_sid, sid) } != 0
                    || unsafe { EqualSid(system_sid_ptr, sid) } != 0
                    || unsafe { EqualSid(admins_sid_ptr, sid) } != 0
                    || unsafe { EqualSid(trusted_installer_sid, sid) } != 0)
        };
        if private {
            if unsafe { EqualSid(current_sid, owner_sid) } == 0 {
                return Ok(false);
            }
            let mut control = 0_u16;
            let mut revision = 0_u32;
            if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
                || control & SE_DACL_PROTECTED == 0
            {
                return Ok(false);
            }
        } else if !trusted_sid(owner_sid) {
            return Ok(false);
        }

        let mut entry_count = 0_u32;
        let mut entries: *mut EXPLICIT_ACCESS_W = std::ptr::null_mut();
        let entries_status =
            unsafe { GetExplicitEntriesFromAclW(dacl, &mut entry_count, &mut entries) };
        if entries_status != ERROR_SUCCESS {
            return Err(Error::ReadFileError(
                std::io::Error::from_raw_os_error(entries_status as i32).to_string(),
            ));
        }
        let _entries = LocalAllocation(entries.cast());
        let entries_slice = if entries.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(entries, entry_count as usize) }
        };
        let mutation_mask = FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | FILE_DELETE_CHILD
            | DELETE
            | WRITE_DAC
            | WRITE_OWNER
            | GENERIC_WRITE
            | GENERIC_ALL;
        let valid = if private {
            entries_slice.len() == 1
                && entries_slice.iter().all(|entry| {
                    let sid: PSID = entry.Trustee.ptstrName.cast();
                    (entry.grfAccessMode == SET_ACCESS || entry.grfAccessMode == GRANT_ACCESS)
                        && entry.grfAccessPermissions & FILE_ALL_ACCESS == FILE_ALL_ACCESS
                        && entry.Trustee.TrusteeForm == TRUSTEE_IS_SID
                        && !sid.is_null()
                        && unsafe { EqualSid(current_sid, sid) } != 0
                })
        } else {
            entries_slice.iter().all(|entry| {
                if entry.grfAccessMode != SET_ACCESS && entry.grfAccessMode != GRANT_ACCESS {
                    return true;
                }
                if entry.grfAccessPermissions & mutation_mask == 0 {
                    return true;
                }
                entry.Trustee.TrusteeForm == TRUSTEE_IS_SID
                    && trusted_sid(entry.Trustee.ptstrName.cast())
            })
        };
        Ok(valid)
    })();
    unsafe {
        LocalFree(descriptor);
        LocalFree(trusted_installer_sid);
    }
    result
}

#[cfg(target_os = "windows")]
fn restrict_windows_handle_to_current_user(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetSecurityInfo,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    let current_user = windows_current_user_sid_buffer()?;
    let current_sid = unsafe { (*(current_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    if current_sid.is_null() {
        return Err(Error::InvalidPgPackage);
    }
    let mut access: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };
    access.grfAccessPermissions = FILE_ALL_ACCESS;
    access.grfAccessMode = SET_ACCESS;
    access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = current_sid.cast();
    let mut dacl = std::ptr::null_mut();
    let acl_status = unsafe { SetEntriesInAclW(1, &access, std::ptr::null(), &mut dacl) };
    if acl_status != ERROR_SUCCESS || dacl.is_null() {
        return Err(Error::WriteFileError(
            std::io::Error::from_raw_os_error(acl_status as i32).to_string(),
        ));
    }
    let set_status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(dacl.cast());
    }
    if set_status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Error::WriteFileError(
            std::io::Error::from_raw_os_error(set_status as i32).to_string(),
        ))
    }
}

fn acquire_cache_lease_sync(
    cache_root: &Path,
    cache_dir: &Path,
    shared: bool,
    timeout: Duration,
) -> Result<Arc<CacheLease>> {
    let lock_namespace = cache_root.join(".locks");
    let lock_namespace_guard = ensure_private_directory(&lock_namespace)?;
    let cache_parent = cache_dir.parent().ok_or(Error::InvalidPgUrl)?;
    let cache_parent_guard = ensure_private_directory(cache_parent)?;
    let cache_key = hex::encode(Sha256::digest(
        cache_dir.as_os_str().to_string_lossy().as_bytes(),
    ));
    let lock_path = lock_namespace.join(format!("{cache_key}.lock"));
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
            WRITE_DAC,
        };
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(&lock_path)
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::InvalidPgPackage);
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::InvalidPgPackage);
        }
        if metadata.permissions().mode() & 0o077 != 0
            && unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
        {
            return Err(Error::WriteFileError(
                std::io::Error::last_os_error().to_string(),
            ));
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::InvalidPgPackage);
        }
        // Reparse validation must precede every ACL mutation.
        restrict_windows_handle_to_current_user(&file)?;
        if !windows_handle_permissions_are_private(&file)? {
            return Err(Error::InvalidPgPackage);
        }
    }
    let deadline = Instant::now() + timeout;
    loop {
        let acquisition = if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };
        match acquisition {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return Err(Error::PgCacheLeaseTimedOut);
                };
                if remaining.is_zero() {
                    return Err(Error::PgCacheLeaseTimedOut);
                }
                std::thread::sleep(remaining.min(CACHE_LEASE_RETRY_INTERVAL));
            }
            Err(_) => return Err(Error::PgLockError),
        }
    }
    Ok(Arc::new(CacheLease {
        _lock: file,
        _lock_namespace: lock_namespace_guard,
        _cache_parent: cache_parent_guard,
    }))
}

async fn acquire_cache_lease(
    cache_root: &Path,
    cache_dir: &Path,
    shared: bool,
) -> Result<Arc<CacheLease>> {
    let cache_root = cache_root.to_path_buf();
    let cache_dir = cache_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        acquire_cache_lease_sync(&cache_root, &cache_dir, shared, CACHE_LEASE_TIMEOUT)
    })
    .await
    .map_err(|error| Error::PgTaskJoinError(error.to_string()))?
}

fn verify_cache_permissions(cache_dir: &Path, executable_paths: [&Path; 3]) -> Result<()> {
    let bin_dir = cache_dir.join("bin");
    for path in [cache_dir, bin_dir.as_path()] {
        if !std::fs::symlink_metadata(path)
            .map_err(|error| Error::ReadFileError(error.to_string()))?
            .is_dir()
        {
            return Err(Error::InvalidPgPackage);
        }
    }
    for path in executable_paths {
        if !std::fs::symlink_metadata(path)
            .map_err(|error| Error::ReadFileError(error.to_string()))?
            .is_file()
        {
            return Err(Error::InvalidPgPackage);
        }
    }

    #[cfg(unix)]
    fn visit(path: &Path) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| Error::ReadFileError(error.to_string()))?;
        if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
            return Err(Error::InvalidPgPackage);
        }
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o222 != 0
        {
            return Err(Error::InvalidPgPackage);
        }
        if metadata.is_dir() {
            for entry in
                std::fs::read_dir(path).map_err(|error| Error::ReadFileError(error.to_string()))?
            {
                let entry = entry.map_err(|error| Error::ReadFileError(error.to_string()))?;
                visit(&entry.path())?;
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    {
        visit(cache_dir)
    }
    #[cfg(target_os = "windows")]
    {
        let mut entries = Vec::new();
        collect_windows_tree(cache_dir, &mut entries)?;
        for entry in &entries {
            if !windows_handle_permissions_are_private(&entry.handle)? {
                return Err(Error::InvalidPgPackage);
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn make_cache_immutable(cache_dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fn visit(path: &Path) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| Error::ReadFileError(error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(Error::InvalidPgPackage);
        }
        if metadata.is_dir() {
            for entry in
                std::fs::read_dir(path).map_err(|error| Error::ReadFileError(error.to_string()))?
            {
                let entry = entry.map_err(|error| Error::ReadFileError(error.to_string()))?;
                visit(&entry.path())?;
            }
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555))
                .map_err(|error| Error::WriteFileError(error.to_string()))?;
        } else if metadata.is_file() {
            let current = metadata.permissions().mode();
            let mode = if current & 0o111 != 0 { 0o555 } else { 0o444 };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .map_err(|error| Error::WriteFileError(error.to_string()))?;
        } else {
            return Err(Error::InvalidPgPackage);
        }
        Ok(())
    }

    visit(cache_dir)
}

#[cfg(unix)]
fn make_cache_removable(cache_dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fn visit(path: &Path) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| Error::ReadFileError(error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(Error::InvalidPgPackage);
        }
        if metadata.is_dir() {
            for entry in
                std::fs::read_dir(path).map_err(|error| Error::ReadFileError(error.to_string()))?
            {
                visit(
                    &entry
                        .map_err(|error| Error::ReadFileError(error.to_string()))?
                        .path(),
                )?;
            }
        } else if !metadata.is_file() {
            return Err(Error::InvalidPgPackage);
        }
        let current = metadata.permissions().mode();
        let mode = if metadata.is_dir() || current & 0o111 != 0 {
            0o700
        } else {
            0o600
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|error| Error::WriteFileError(error.to_string()))
    }
    visit(cache_dir)
}

#[cfg(target_os = "windows")]
struct WindowsTreeEntry {
    path: PathBuf,
    handle: File,
    directory: bool,
}

#[cfg(target_os = "windows")]
fn open_windows_tree_entry(path: &Path) -> Result<WindowsTreeEntry> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
        OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(Error::ReadFileError(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let owned = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    let handle = File::from(owned);
    let metadata = handle
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (!metadata.is_dir() && !metadata.is_file())
    {
        return Err(Error::InvalidPgPackage);
    }
    Ok(WindowsTreeEntry {
        path: path.to_path_buf(),
        handle,
        directory: metadata.is_dir(),
    })
}

#[cfg(target_os = "windows")]
fn collect_windows_tree(path: &Path, entries: &mut Vec<WindowsTreeEntry>) -> Result<()> {
    let entry = open_windows_tree_entry(path)?;
    let directory = entry.directory;
    entries.push(entry);
    if directory {
        for child in
            std::fs::read_dir(path).map_err(|error| Error::ReadFileError(error.to_string()))?
        {
            collect_windows_tree(
                &child
                    .map_err(|error| Error::ReadFileError(error.to_string()))?
                    .path(),
                entries,
            )?;
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn make_cache_removable(cache_dir: &Path) -> Result<()> {
    let mut entries = Vec::new();
    collect_windows_tree(cache_dir, &mut entries)?;
    // All entries are now held no-follow with delete sharing denied. Only
    // after the complete tree passes reparse validation may ACL/attribute
    // mutation begin.
    for entry in entries.iter().rev() {
        restrict_windows_handle_to_current_user(&entry.handle)?;
        let mut permissions = entry
            .handle
            .metadata()
            .map_err(|error| Error::ReadFileError(error.to_string()))?
            .permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&entry.path, permissions)
            .map_err(|error| Error::WriteFileError(error.to_string()))?;
    }
    Ok(())
}

fn remove_cache_tree_sync(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(Error::InvalidPgPackage),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::ReadFileError(error.to_string())),
    }
    make_cache_removable(path)?;
    std::fs::remove_dir_all(path).map_err(|error| Error::PgPurgeFailure(error.to_string()))
}

async fn remove_cache_tree(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || remove_cache_tree_sync(&path))
        .await
        .map_err(|error| Error::PgTaskJoinError(error.to_string()))?
}

fn harden_staging_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| Error::ReadFileError(error.to_string()))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::InvalidPgPackage);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| Error::WriteFileError(error.to_string()))?;
    }
    #[cfg(target_os = "windows")]
    {
        let handle = open_directory_no_follow(path, true)?;
        validate_directory_handle(&handle, true, true)?;
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|error| Error::DirCreationError(error.to_string()))?;
    }
    #[cfg(target_os = "windows")]
    {
        std::fs::create_dir(path).map_err(|error| Error::DirCreationError(error.to_string()))?;
    }
    harden_staging_directory(path)
}

fn create_private_directories(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Error::InvalidPgPackage);
            }
            let _handle = directory_handle_no_follow(path)?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::ReadFileError(error.to_string())),
    }
    let parent = path.parent().ok_or(Error::InvalidPgPackage)?;
    if !parent.is_dir() {
        create_private_directories(parent)?;
    }
    create_private_directory(path)
}

fn create_new_private_file(path: &Path, executable: bool) -> Result<File> {
    #[cfg(target_os = "windows")]
    let _ = executable;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options
            .mode(if executable { 0o700 } else { 0o600 })
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_WRITE, READ_CONTROL, WRITE_DAC,
        };

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .access_mode(FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| Error::WriteFileError(error.to_string()))?;
    secure_private_file_handle(&file)?;
    Ok(file)
}

fn open_private_file_for_replace(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_WRITE, READ_CONTROL, WRITE_DAC,
        };

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .access_mode(FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| Error::WriteFileError(error.to_string()))?;
    secure_private_file_handle(&file)?;
    Ok(file)
}

fn directory_handle_no_follow(path: &Path) -> Result<File> {
    let handle = open_directory_no_follow(path, false)?;
    let metadata = handle
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::InvalidPgPackage);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::InvalidPgPackage);
        }
    }
    Ok(handle)
}

fn copy_open_file(source: &mut File, destination: &Path, executable: bool) -> Result<()> {
    source
        .rewind()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    let mut destination_file = create_new_private_file(destination, executable)?;
    std::io::copy(source, &mut destination_file)
        .map_err(|error| Error::WriteFileError(error.to_string()))?;
    destination_file
        .flush()
        .map_err(|error| Error::WriteFileError(error.to_string()))?;
    destination_file
        .sync_all()
        .map_err(|error| Error::WriteFileError(error.to_string()))
}

fn copy_cache_tree_contents(source: &Path, destination: &Path) -> Result<()> {
    let _source_handle = directory_handle_no_follow(source)?;
    for entry in
        std::fs::read_dir(source).map_err(|error| Error::ReadFileError(error.to_string()))?
    {
        let entry = entry.map_err(|error| Error::ReadFileError(error.to_string()))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&source_path)
            .map_err(|error| Error::ReadFileError(error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(Error::InvalidPgPackage);
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::MetadataExt;

            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(Error::InvalidPgPackage);
            }
        }
        if metadata.is_dir() {
            create_private_directory(&destination_path)?;
            copy_cache_tree_contents(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            let mut source_file = open_regular_file_no_follow(&source_path)?;
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            };
            #[cfg(target_os = "windows")]
            let executable = false;
            copy_open_file(&mut source_file, &destination_path, executable)?;
        } else {
            return Err(Error::InvalidPgPackage);
        }
    }
    Ok(())
}

fn hash_open_file(file: &mut File) -> Result<[u8; 32]> {
    file.rewind()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::ReadFileError(error.to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    file.rewind()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    Ok(hasher.finalize().into())
}

#[cfg(target_os = "windows")]
fn make_cache_immutable(cache_dir: &Path) -> Result<()> {
    let mut entries = Vec::new();
    collect_windows_tree(cache_dir, &mut entries)?;
    for entry in entries.iter().rev() {
        if !entry.directory {
            let mut permissions = entry
                .handle
                .metadata()
                .map_err(|error| Error::ReadFileError(error.to_string()))?
                .permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(&entry.path, permissions)
                .map_err(|error| Error::WriteFileError(error.to_string()))?;
        }
        restrict_windows_handle_to_current_user(&entry.handle)?;
        if !windows_handle_permissions_are_private(&entry.handle)? {
            return Err(Error::InvalidPgPackage);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AuthenticatedCacheDigests {
    initdb: [u8; 32],
    pg_ctl: [u8; 32],
    postgres: [u8; 32],
}

fn verify_authenticated_cache_sync(
    cache_dir: &Path,
    archive_path: &Path,
    marker_path: &Path,
    initdb_path: &Path,
    pg_ctl_path: &Path,
    postgres_path: &Path,
    expected_archive_sha256: &str,
    expected_executables: AuthenticatedCacheDigests,
) -> Result<()> {
    verify_cache_permissions(cache_dir, [initdb_path, pg_ctl_path, postgres_path])?;

    let marker_file = open_regular_file_no_follow(marker_path)?;
    let marker_metadata = marker_file
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    if marker_metadata.len() > 128 {
        return Err(Error::InvalidPgPackage);
    }
    let mut marker = Vec::with_capacity(marker_metadata.len() as usize);
    marker_file
        .take(129)
        .read_to_end(&mut marker)
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    if marker.len() > 128
        || std::str::from_utf8(&marker)
            .map_err(|error| Error::ReadFileError(error.to_string()))?
            .trim()
            != expected_archive_sha256
    {
        return Err(Error::InvalidPgPackage);
    }

    let mut archive_file = open_regular_file_no_follow(archive_path)?;
    let archive_metadata = archive_file
        .metadata()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    if archive_metadata.len() > MAX_POSTGRES_ARCHIVE_BYTES {
        return Err(Error::InvalidPgPackage);
    }
    let archive_digest = hex::encode(hash_open_file(&mut archive_file)?);
    if archive_digest != expected_archive_sha256 {
        return Err(Error::PgPackageDigestMismatch {
            expected: expected_archive_sha256.to_owned(),
            actual: archive_digest,
        });
    }

    for (path, expected) in [
        (initdb_path, expected_executables.initdb),
        (pg_ctl_path, expected_executables.pg_ctl),
        (postgres_path, expected_executables.postgres),
    ] {
        if open_verified_file(path)?.1 != expected {
            return Err(Error::InvalidPgPackage);
        }
    }
    Ok(())
}

fn replace_from_open_file(source: &mut File, destination: &Path) -> Result<()> {
    source
        .rewind()
        .map_err(|error| Error::ReadFileError(error.to_string()))?;
    let mut destination_file = open_private_file_for_replace(destination)?;
    std::io::copy(source, &mut destination_file)
        .map_err(|error| Error::WriteFileError(error.to_string()))?;
    destination_file
        .flush()
        .map_err(|error| Error::WriteFileError(error.to_string()))?;
    destination_file
        .sync_all()
        .map_err(|error| Error::WriteFileError(error.to_string()))
}

fn share_extension_dir_sync(cache_dir: &Path) -> PathBuf {
    [
        cache_dir.join("share/postgresql/extension"),
        cache_dir.join("share/extension"),
    ]
    .into_iter()
    .find(|candidate| {
        std::fs::symlink_metadata(candidate)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    })
    .unwrap_or_else(|| cache_dir.join("share/postgresql/extension"))
}

fn install_extension_into_stage(stage_dir: &Path, extension_dir: &Path) -> Result<()> {
    let _source_directory = directory_handle_no_follow(extension_dir)?;
    let lib_dir = stage_dir.join("lib");
    let share_extension_dir = share_extension_dir_sync(stage_dir);
    create_private_directories(&lib_dir)?;
    create_private_directories(&share_extension_dir)?;

    for entry in
        std::fs::read_dir(extension_dir).map_err(|error| Error::ReadFileError(error.to_string()))?
    {
        let entry = entry.map_err(|error| Error::ReadFileError(error.to_string()))?;
        let source_path = entry.path();
        let metadata = std::fs::symlink_metadata(&source_path)
            .map_err(|error| Error::ReadFileError(error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(Error::InvalidPgPackage);
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::MetadataExt;

            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(Error::InvalidPgPackage);
            }
        }
        if !metadata.is_file() {
            continue;
        }
        let destination_directory = match source_path.extension().and_then(|value| value.to_str()) {
            Some("so") | Some("dylib") | Some("dll") => &lib_dir,
            Some("control") | Some("sql") => &share_extension_dir,
            _ => continue,
        };
        let file_name = source_path.file_name().ok_or(Error::InvalidPgPackage)?;
        let mut source_file = open_regular_file_no_follow(&source_path)?;
        replace_from_open_file(&mut source_file, &destination_directory.join(file_name))?;
    }
    Ok(())
}

struct PendingCacheTree {
    path: PathBuf,
    armed: bool,
}

impl PendingCacheTree {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingCacheTree {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_cache_tree_sync(&self.path);
        }
    }
}

#[cfg(test)]
static EXTENSION_TRANSACTION_TEST_HOOK: LazyLock<
    std::sync::Mutex<Option<(PathBuf, Arc<(std::sync::Barrier, std::sync::Barrier)>)>>,
> = LazyLock::new(|| std::sync::Mutex::new(None));

fn install_extension_transaction(
    cache_root: &Path,
    cache_dir: &Path,
    archive_path: &Path,
    marker_path: &Path,
    initdb_path: &Path,
    pg_ctl_path: &Path,
    postgres_path: &Path,
    extension_dir: &Path,
    expected_archive_sha256: &str,
    expected_executables: AuthenticatedCacheDigests,
) -> Result<()> {
    let _lease = acquire_cache_lease_sync(cache_root, cache_dir, false, CACHE_LEASE_TIMEOUT)?;
    verify_authenticated_cache_sync(
        cache_dir,
        archive_path,
        marker_path,
        initdb_path,
        pg_ctl_path,
        postgres_path,
        expected_archive_sha256,
        expected_executables,
    )?;

    let cache_name = cache_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::InvalidPgPackage)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let suffix = format!("{}-{nonce}", std::process::id());
    let stage_path = cache_dir.with_file_name(format!(".{cache_name}.extension-stage-{suffix}"));
    let backup_path = cache_dir.with_file_name(format!(".{cache_name}.extension-backup-{suffix}"));
    if std::fs::symlink_metadata(&stage_path).is_ok()
        || std::fs::symlink_metadata(&backup_path).is_ok()
    {
        return Err(Error::InvalidPgPackage);
    }

    create_private_directory(&stage_path)?;
    let mut pending_stage = PendingCacheTree::new(stage_path.clone());
    copy_cache_tree_contents(cache_dir, &stage_path)?;
    install_extension_into_stage(&stage_path, extension_dir)?;
    #[cfg(test)]
    {
        let hook = EXTENSION_TRANSACTION_TEST_HOOK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .filter(|(expected_cache, _)| expected_cache == cache_dir)
            .map(|(_, hook)| hook);
        if let Some(hook) = hook {
            hook.0.wait();
            hook.1.wait();
        }
    }
    make_cache_immutable(&stage_path)?;

    let stage_archive = stage_path.join(archive_path.file_name().ok_or(Error::InvalidPgPackage)?);
    let stage_marker = stage_path.join(marker_path.file_name().ok_or(Error::InvalidPgPackage)?);
    let stage_initdb = stage_path
        .join("bin")
        .join(initdb_path.file_name().ok_or(Error::InvalidPgPackage)?);
    let stage_pg_ctl = stage_path
        .join("bin")
        .join(pg_ctl_path.file_name().ok_or(Error::InvalidPgPackage)?);
    let stage_postgres = stage_path
        .join("bin")
        .join(postgres_path.file_name().ok_or(Error::InvalidPgPackage)?);
    verify_authenticated_cache_sync(
        &stage_path,
        &stage_archive,
        &stage_marker,
        &stage_initdb,
        &stage_pg_ctl,
        &stage_postgres,
        expected_archive_sha256,
        expected_executables,
    )?;

    make_cache_removable(cache_dir)?;
    if let Err(rename_error) = std::fs::rename(cache_dir, &backup_path) {
        let harden_result = make_cache_immutable(cache_dir);
        return match harden_result {
            Ok(()) => Err(Error::WriteFileError(rename_error.to_string())),
            Err(harden_error) => Err(Error::WriteFileError(format!(
                "{rename_error}; additionally failed to re-harden the original cache: {harden_error}"
            ))),
        };
    }

    if let Err(publish_error) = std::fs::rename(&stage_path, cache_dir) {
        let rollback_result = std::fs::rename(&backup_path, cache_dir)
            .map_err(|error| Error::WriteFileError(error.to_string()))
            .and_then(|()| make_cache_immutable(cache_dir));
        return match rollback_result {
            Ok(()) => Err(Error::WriteFileError(publish_error.to_string())),
            Err(rollback_error) => {
                // The backup is still the last authenticated cache. Even when
                // the directory rename itself cannot be recovered, do not
                // leave that recovery artifact writable.
                let _ = make_cache_immutable(&backup_path);
                Err(Error::WriteFileError(format!(
                    "{publish_error}; rollback failed: {rollback_error}"
                )))
            }
        };
    }
    pending_stage.disarm();

    if let Err(cleanup_error) = remove_cache_tree_sync(&backup_path) {
        let _ = make_cache_immutable(&backup_path);
        log::warn!(
            "extension cache was published, but its immutable backup could not be removed: {cleanup_error}"
        );
    }
    Ok(())
}

impl PgAccess {
    /// Creates a new [`PgAccess`] and ensures the required directories exist.
    ///
    /// Both the per-version binary cache directory and `database_dir` are
    /// created with [`tokio::fs::create_dir_all`] if they do not already exist.
    ///
    /// # Arguments
    ///
    /// * `fetch_settings` — Determines the OS, architecture, and version used
    ///   to construct the cache path.
    /// * `database_dir` — Where the PostgreSQL cluster data files will live.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPgUrl`] if the OS cache directory cannot be
    /// resolved.
    /// Returns [`Error::DirCreationError`] if either directory cannot be
    /// created.
    pub async fn new(fetch_settings: &PgFetchSettings, database_dir: &Path) -> Result<Self> {
        let (cache_root, cache_dir) = Self::create_cache_dir_structure(fetch_settings).await?;
        Self::create_db_dir_structure(database_dir).await?;
        let platform = fetch_settings.platform();
        let pg_ctl = if cfg!(windows) {
            cache_dir.join("bin/pg_ctl.exe")
        } else {
            cache_dir.join("bin/pg_ctl")
        };
        let init_db = if cfg!(windows) {
            cache_dir.join("bin/initdb.exe")
        } else {
            cache_dir.join("bin/initdb")
        };
        let zip_file_path =
            cache_dir.join(format!("{}-{}.zip", platform, fetch_settings.version.0));
        let mut pw_file = database_dir.to_path_buf();
        pw_file.set_extension("pwfile");
        let pg_version_file = database_dir.join(PG_VERSION_FILE_NAME);

        Ok(PgAccess {
            cache_root,
            cache_dir,
            database_dir: database_dir.to_path_buf(),
            pg_ctl_exe: pg_ctl,
            init_db_exe: init_db,
            pw_file_path: pw_file,
            zip_file_path,
            pg_version_file,
            fetch_settings: fetch_settings.clone(),
        })
    }

    /// Creates the OS-specific cache directory tree for this OS/arch/version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPgUrl`] if the OS cache directory cannot be
    /// resolved.
    /// Returns [`Error::DirCreationError`] if the directory cannot be created.
    async fn create_cache_dir_structure(
        fetch_settings: &PgFetchSettings,
    ) -> Result<(PathBuf, PathBuf)> {
        let cache_base = dirs::cache_dir().ok_or(Error::InvalidPgUrl)?;
        let cache_root = cache_base.join(PG_EMBED_CACHE_DIR_NAME);
        let os_string = match fetch_settings.operating_system {
            OperationSystem::Darwin | OperationSystem::Windows | OperationSystem::Linux => {
                fetch_settings.operating_system.to_string()
            }
            OperationSystem::AlpineLinux => {
                format!("arch_{}", fetch_settings.operating_system)
            }
        };
        let cache_dir = cache_root
            .join(os_string)
            .join(fetch_settings.architecture.to_string())
            .join(fetch_settings.version.0.to_string());
        let cache_root_for_create = cache_root.clone();
        let cache_dir_for_create = cache_dir.clone();
        tokio::task::spawn_blocking(move || {
            let _root_guard = ensure_private_directory(&cache_root_for_create)?;
            let _version_guard = ensure_private_directory(&cache_dir_for_create)?;
            Ok::<(), Error>(())
        })
        .await
        .map_err(|error| Error::PgTaskJoinError(error.to_string()))??;
        Ok((cache_root, cache_dir))
    }

    /// Creates the database cluster directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DirCreationError`] if the directory cannot be created.
    async fn create_db_dir_structure(db_dir: &Path) -> Result<()> {
        let db_dir = db_dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let _guard = ensure_private_directory(&db_dir)?;
            Ok::<(), Error>(())
        })
        .await
        .map_err(|error| Error::PgTaskJoinError(error.to_string()))?
    }

    /// Downloads and unpacks the PostgreSQL binaries if they are not already
    /// cached.
    ///
    /// Acquires the `ACQUIRED_PG_BINS` lock for the duration.  If another
    /// instance already cached the binaries (i.e.
    /// [`Self::pg_executables_cached`] returns `true`), this method returns
    /// immediately without downloading.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DirCreationError`] if directories cannot be created.
    /// Returns [`Error::DownloadFailure`] or [`Error::ConversionFailure`] if
    /// the HTTP download fails.
    /// Returns [`Error::WriteFileError`] if the JAR cannot be written to disk.
    /// Returns [`Error::UnpackFailure`] or [`Error::InvalidPgPackage`] if
    /// extraction fails.
    pub async fn maybe_acquire_postgres(&self) -> Result<()> {
        let expected = self.fetch_settings.expected_sha256()?;
        match self.authenticated_postgres_executables().await {
            Ok(Some(_)) => {
                log::info!("pg_executables_cached=true, skipping download/unpack");
                return Ok(());
            }
            Ok(None) | Err(Error::InvalidPgPackage) => {}
            Err(error) => return Err(error),
        }
        let cache_lease = acquire_cache_lease(&self.cache_root, &self.cache_dir, false).await?;

        // Re-check after obtaining the exclusive lease: another process may
        // have completed an atomic install while this process was waiting.
        match self
            .authenticated_postgres_executables_with_lease(expected, cache_lease.clone())
            .await
        {
            Ok(Some(_)) => {
                log::info!("pg_executables_cached=true, skipping download/unpack");
                return Ok(());
            }
            Ok(None) | Err(Error::InvalidPgPackage) => {}
            Err(error) => return Err(error),
        }

        log::info!(
            "verified pg executable cache unavailable (checked {}), rebuilding...",
            self.init_db_exe.display()
        );
        ACQUIRED_PG_BINS
            .lock()
            .await
            .insert(self.cache_dir.clone(), PgAcquisitionStatus::InProgress);

        let cache_name = self
            .cache_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::InvalidPgUrl)?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let suffix = format!("{}-{nonce}", std::process::id());
        let stage_dir = self
            .cache_dir
            .with_file_name(format!(".{cache_name}.stage-{suffix}"));
        let backup_dir = self
            .cache_dir
            .with_file_name(format!(".{cache_name}.backup-{suffix}"));
        tokio::fs::create_dir(&stage_dir)
            .await
            .map_err(|e| Error::DirCreationError(e.to_string()))?;
        if let Err(error) = harden_staging_directory(&stage_dir) {
            let _ = remove_cache_tree(&stage_dir).await;
            return Err(error);
        }

        let install_result: Result<()> = async {
            let archive_name = self
                .zip_file_path
                .file_name()
                .ok_or(Error::InvalidPgPackage)?;
            let stage_archive = stage_dir.join(archive_name);
            let partial_path = stage_archive.with_extension("zip.partial");
            self.fetch_settings
                .fetch_postgres_to_file(&partial_path)
                .await?;
            tokio::fs::rename(&partial_path, &stage_archive)
                .await
                .map_err(|e| Error::WriteFileError(e.to_string()))?;

            log::info!(
                "Unpacking authenticated postgres snapshot {} -> {}",
                stage_archive.display(),
                stage_dir.display()
            );
            let archive_snapshot =
                Self::authenticated_archive_snapshot_path(&stage_archive, expected).await?;
            pg_unpack::unpack_postgres_snapshot(archive_snapshot.clone(), &stage_dir).await?;

            let initdb = stage_dir.join("bin").join(
                self.init_db_exe
                    .file_name()
                    .ok_or(Error::InvalidPgPackage)?,
            );
            let pg_ctl = stage_dir
                .join("bin")
                .join(self.pg_ctl_exe.file_name().ok_or(Error::InvalidPgPackage)?);
            let postgres = stage_dir.join("bin").join(
                self.postgres_executable_path()
                    .file_name()
                    .ok_or(Error::InvalidPgPackage)?,
            );
            let authenticated = pg_unpack::authenticate_executables_from_archive_snapshot(
                archive_snapshot,
                &initdb,
                &pg_ctl,
                &postgres,
            )
            .await?
            .ok_or(Error::InvalidPgPackage)?;
            for (path, expected_digest) in [
                (initdb.as_path(), authenticated.initdb_sha256),
                (pg_ctl.as_path(), authenticated.pg_ctl_sha256),
                (postgres.as_path(), authenticated.sha256),
            ] {
                if open_verified_file(path)?.1 != expected_digest {
                    return Err(Error::InvalidPgPackage);
                }
            }

            // Publish the trust marker only inside the completed staging tree.
            tokio::fs::write(stage_dir.join(VERIFIED_PACKAGE_MARKER), expected.as_bytes())
                .await
                .map_err(|e| Error::WriteFileError(e.to_string()))?;
            make_cache_immutable(&stage_dir)?;

            let had_existing = tokio::fs::try_exists(&self.cache_dir)
                .await
                .map_err(|e| Error::ReadFileError(e.to_string()))?;
            if had_existing {
                tokio::fs::rename(&self.cache_dir, &backup_dir)
                    .await
                    .map_err(|e| Error::PgPurgeFailure(e.to_string()))?;
            }
            if let Err(error) = tokio::fs::rename(&stage_dir, &self.cache_dir).await {
                if had_existing {
                    let _ = tokio::fs::rename(&backup_dir, &self.cache_dir).await;
                }
                return Err(Error::WriteFileError(error.to_string()));
            }
            if had_existing {
                let _ = remove_cache_tree(&backup_dir).await;
            }
            Ok(())
        }
        .await;

        if let Err(error) = install_result {
            let _ = remove_cache_tree(&stage_dir).await;
            if let Some(status) = ACQUIRED_PG_BINS.lock().await.get_mut(&self.cache_dir) {
                *status = PgAcquisitionStatus::Undefined;
            }
            return Err(error);
        }

        if self
            .authenticated_postgres_executables_with_lease(expected, cache_lease)
            .await?
            .is_none()
        {
            return Err(Error::InvalidPgPackage);
        }

        if let Some(status) = ACQUIRED_PG_BINS.lock().await.get_mut(&self.cache_dir) {
            *status = PgAcquisitionStatus::Finished;
        }
        Ok(())
    }

    /// Returns `true` only for a post-verification executable cache.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadFileError`] if the filesystem existence check
    /// fails.
    pub async fn pg_executables_cached(&self) -> Result<bool> {
        Ok(self.authenticated_postgres_executable().await?.is_some())
    }

    /// Return the canonical path and SHA-256 identity of `postgres` from the exact
    /// source-pinned archive snapshot, but only when the retained marker and
    /// all three extracted executables match that same snapshot.
    ///
    /// The digest is archive-derived rather than self-pinned from a mutable
    /// executable pathname. Olympus carries it into post-start process
    /// verification. This authenticates the executable image itself; dynamic
    /// libraries loaded by PostgreSQL remain a separate platform-loader trust
    /// boundary and must be protected by cache-directory permissions.
    pub async fn authenticated_postgres_executable(
        &self,
    ) -> Result<Option<AuthenticatedPostgresExecutable>> {
        Ok(self
            .authenticated_postgres_executables()
            .await?
            .map(|executables| executables.postgres_identity()))
    }

    /// Retain the verified executable inodes/handles and a shared
    /// cross-process cache lease through launch and server lifetime.
    pub async fn authenticated_postgres_executables(
        &self,
    ) -> Result<Option<AuthenticatedPostgresExecutables>> {
        let expected = self.fetch_settings.expected_sha256()?;
        let lease = acquire_cache_lease(&self.cache_root, &self.cache_dir, true).await?;
        self.authenticated_postgres_executables_with_lease(expected, lease)
            .await
    }

    #[cfg(test)]
    async fn authenticated_postgres_executable_for_expected(
        &self,
        expected: &str,
    ) -> Result<Option<AuthenticatedPostgresExecutable>> {
        let lease = acquire_cache_lease(&self.cache_root, &self.cache_dir, true).await?;
        Ok(self
            .authenticated_postgres_executables_with_lease(expected, lease)
            .await?
            .map(|executables| executables.postgres_identity()))
    }

    async fn authenticated_postgres_executables_with_lease(
        &self,
        expected: &str,
        lease: Arc<CacheLease>,
    ) -> Result<Option<AuthenticatedPostgresExecutables>> {
        if !Self::path_exists(self.init_db_exe.as_path()).await?
            || !Self::path_exists(self.pg_ctl_exe.as_path()).await?
            || !Self::path_exists(&self.postgres_executable_path()).await?
            || !Self::path_exists(self.zip_file_path.as_path()).await?
            || !Self::path_exists(&self.verified_package_marker()).await?
        {
            return Ok(None);
        }

        let marker_file = tokio::fs::File::open(self.verified_package_marker())
            .await
            .map_err(|e| Error::ReadFileError(e.to_string()))?;
        let marker_metadata = marker_file
            .metadata()
            .await
            .map_err(|e| Error::ReadFileError(e.to_string()))?;
        if !marker_metadata.is_file() || marker_metadata.len() > 128 {
            return Ok(None);
        }
        let mut marker = Vec::with_capacity(marker_metadata.len() as usize);
        marker_file
            .take(129)
            .read_to_end(&mut marker)
            .await
            .map_err(|e| Error::ReadFileError(e.to_string()))?;
        if marker.len() > 128 {
            return Ok(None);
        }
        let marker =
            std::str::from_utf8(&marker).map_err(|e| Error::ReadFileError(e.to_string()))?;
        if marker.trim() != expected {
            log::warn!("PostgreSQL executable cache marker does not match the package pin");
            return Ok(None);
        }

        let archive_snapshot = match self.authenticated_archive_snapshot(expected).await {
            Ok(snapshot) => snapshot,
            Err(Error::PgPackageDigestMismatch { expected, actual }) => {
                log::warn!(
                    "cached PostgreSQL package failed SHA-256 verification: expected {expected}, got {actual}"
                );
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let Some(canonical_before) = self.canonical_postgres_path_in_bin()? else {
            log::warn!("cached PostgreSQL server resolves outside its authenticated bin directory");
            return Ok(None);
        };
        let authenticated = self
            .authenticate_extracted_executables(archive_snapshot)
            .await?;
        if authenticated.is_none() {
            log::warn!(
                "cached PostgreSQL initdb, pg_ctl, or postgres differs from the verified archive"
            );
        }
        let Some(authenticated) = authenticated else {
            return Ok(None);
        };
        if self.canonical_postgres_path_in_bin()?.as_ref() != Some(&canonical_before) {
            log::warn!("cached PostgreSQL server path changed during authentication");
            return Ok(None);
        }
        let postgres_path = self.postgres_executable_path();
        verify_cache_permissions(
            &self.cache_dir,
            [
                self.init_db_exe.as_path(),
                self.pg_ctl_exe.as_path(),
                postgres_path.as_path(),
            ],
        )?;
        let executables = AuthenticatedPostgresExecutables {
            initdb: verified_executable(
                &self.init_db_exe,
                authenticated.initdb_sha256,
                lease.clone(),
            )?,
            pg_ctl: verified_executable(
                &self.pg_ctl_exe,
                authenticated.pg_ctl_sha256,
                lease.clone(),
            )?,
            postgres: verified_executable(&postgres_path, authenticated.sha256, lease.clone())?,
            _lease: lease,
        };
        if executables.postgres.path != canonical_before {
            return Ok(None);
        }
        Ok(Some(executables))
    }

    fn verified_package_marker(&self) -> PathBuf {
        self.cache_dir.join(VERIFIED_PACKAGE_MARKER)
    }

    /// Path to the `postgres` server executable authenticated by
    /// [`Self::authenticated_postgres_executable`].
    pub fn postgres_executable_path(&self) -> PathBuf {
        self.pg_ctl_exe.with_file_name(
            if self
                .pg_ctl_exe
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
            {
                "postgres.exe"
            } else {
                "postgres"
            },
        )
    }

    fn canonical_postgres_path_in_bin(&self) -> Result<Option<PathBuf>> {
        let canonical_bin = std::fs::canonicalize(self.cache_dir.join("bin"))
            .map_err(|e| Error::ReadFileError(e.to_string()))?;
        let canonical_postgres = std::fs::canonicalize(self.postgres_executable_path())
            .map_err(|e| Error::ReadFileError(e.to_string()))?;
        Ok(
            (canonical_postgres.parent() == Some(canonical_bin.as_path()))
                .then_some(canonical_postgres),
        )
    }

    async fn authenticated_archive_snapshot(&self, expected_sha256: &str) -> Result<Arc<[u8]>> {
        Self::authenticated_archive_snapshot_path(&self.zip_file_path, expected_sha256).await
    }

    async fn authenticated_archive_snapshot_path(
        archive_path: &Path,
        expected_sha256: &str,
    ) -> Result<Arc<[u8]>> {
        let file = tokio::fs::File::open(archive_path)
            .await
            .map_err(|e| Error::ReadFileError(e.to_string()))?;
        let metadata = file
            .metadata()
            .await
            .map_err(|e| Error::ReadFileError(e.to_string()))?;
        if !metadata.is_file() || metadata.len() > MAX_POSTGRES_ARCHIVE_BYTES {
            return Err(Error::InvalidPgPackage);
        }

        let mut snapshot = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_POSTGRES_ARCHIVE_BYTES + 1)
            .read_to_end(&mut snapshot)
            .await
            .map_err(|e| Error::ReadFileError(e.to_string()))?;
        if snapshot.len() as u64 > MAX_POSTGRES_ARCHIVE_BYTES {
            return Err(Error::InvalidPgPackage);
        }
        let actual = hex::encode(Sha256::digest(&snapshot));
        if actual != expected_sha256 {
            return Err(Error::PgPackageDigestMismatch {
                expected: expected_sha256.to_owned(),
                actual,
            });
        }
        Ok(Arc::from(snapshot))
    }

    async fn authenticate_extracted_executables(
        &self,
        archive_snapshot: Arc<[u8]>,
    ) -> Result<Option<pg_unpack::ArchiveExecutableDigests>> {
        let postgres_exe = self.postgres_executable_path();
        pg_unpack::authenticate_executables_from_archive_snapshot(
            archive_snapshot,
            &self.init_db_exe,
            &self.pg_ctl_exe,
            &postgres_exe,
        )
        .await
    }

    /// Returns `true` if both the executables and the cluster version file
    /// exist.
    ///
    /// A `true` result indicates the cluster was previously initialised with
    /// `initdb` and does not need to be re-initialised.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadFileError`] if either filesystem check fails.
    pub async fn db_files_exist(&self) -> Result<bool> {
        Ok(self.pg_executables_cached().await?
            && Self::path_exists(self.pg_version_file.as_path()).await?)
    }

    /// Returns `true` if the `PG_VERSION` file exists inside `db_dir`.
    ///
    /// Useful for confirming that a cluster directory is non-empty without
    /// holding a [`PgAccess`] instance.
    ///
    /// # Arguments
    ///
    /// * `db_dir` — The cluster data directory to inspect.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadFileError`] if the filesystem check fails.
    pub async fn pg_version_file_exists(db_dir: &Path) -> Result<bool> {
        let pg_version_file = db_dir.join(PG_VERSION_FILE_NAME);
        Self::path_exists(&pg_version_file).await
    }

    /// Returns `true` if `file` exists on the filesystem.
    ///
    /// Uses [`tokio::fs::try_exists`] which returns `false` (not an error) for
    /// permission-denied on the file itself; see its documentation for edge
    /// cases.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadFileError`] if the syscall itself fails (e.g.
    /// the parent directory is inaccessible).
    async fn path_exists(file: &Path) -> Result<bool> {
        tokio::fs::try_exists(file)
            .await
            .map_err(|e| Error::ReadFileError(e.to_string()))
    }

    /// Returns the current acquisition status for this instance's cache
    /// directory.
    pub async fn acquisition_status(&self) -> PgAcquisitionStatus {
        let lock = ACQUIRED_PG_BINS.lock().await;
        let acquisition_status = lock.get(&self.cache_dir);
        match acquisition_status {
            None => PgAcquisitionStatus::Undefined,
            Some(status) => *status,
        }
    }

    /// Removes the database cluster directory and the password file.
    ///
    /// Both removals are attempted even if the first one fails; the first
    /// error encountered is returned.  Called synchronously from
    /// [`crate::postgres::PgEmbed`]'s `Drop` implementation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PgCleanUpFailure`] if either removal fails.
    pub fn clean(&self) -> Result<()> {
        let dir_result = std::fs::remove_dir_all(&self.database_dir)
            .map_err(|e| Error::PgCleanUpFailure(e.to_string()));
        let file_result = std::fs::remove_file(&self.pw_file_path)
            .map_err(|e| Error::PgCleanUpFailure(e.to_string()));
        // Both operations run before returning the first error (if any)
        dir_result.and(file_result)
    }

    /// Removes the entire `pg-embed` binary cache directory.
    ///
    /// Useful for freeing disk space or forcing a fresh download.  Errors
    /// during removal are silently ignored (the function always returns `Ok`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadFileError`] if the OS cache directory cannot be
    /// resolved.
    pub async fn purge() -> Result<()> {
        Err(Error::PgPurgeFailure(
            "whole-cache purge is disabled: it cannot be synchronized with retained executable \
             capabilities in other processes"
                .to_owned(),
        ))
    }

    /// Removes `database_dir` and `pw_file` asynchronously.
    ///
    /// Unlike [`Self::clean`], this is an `async` free-standing helper and
    /// stops on the first error.
    ///
    /// # Arguments
    ///
    /// * `database_dir` — The cluster data directory to remove.
    /// * `pw_file` — The password file to remove.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PgCleanUpFailure`] if either removal fails.
    pub async fn clean_up(database_dir: PathBuf, pw_file: PathBuf) -> Result<()> {
        tokio::fs::remove_dir_all(&database_dir)
            .await
            .map_err(|e| Error::PgCleanUpFailure(e.to_string()))?;

        tokio::fs::remove_file(&pw_file)
            .await
            .map_err(|e| Error::PgCleanUpFailure(e.to_string()))
    }

    /// Writes `password` bytes to [`Self::pw_file_path`].
    ///
    /// `initdb` reads this file via `--pwfile` to set the superuser password
    /// without exposing it on the command line.
    ///
    /// # Arguments
    ///
    /// * `password` — The password bytes to write (UTF-8 text is expected but
    ///   not enforced).
    ///
    /// # Errors
    ///
    /// Returns [`Error::WriteFileError`] if the file cannot be created or the
    /// write fails.
    pub async fn create_password_file(&self, password: &[u8]) -> Result<()> {
        let mut file = tokio::fs::File::create(self.pw_file_path.as_path())
            .await
            .map_err(|e| Error::WriteFileError(e.to_string()))?;
        file.write_all(password)
            .await
            .map_err(|e| Error::WriteFileError(e.to_string()))
    }

    /// Compatibility factory retained from pg-embed 1.0.
    ///
    /// Olympus itself never uses this pathname-based command. Lifecycle code
    /// uses [`crate::postgres::PgEmbed::stop_db_sync`] so shutdown authority is
    /// retained from launch rather than reconstructed later.
    #[allow(deprecated)]
    #[deprecated(note = "use PgEmbed::stop_db_sync for retained-authority shutdown")]
    pub fn stop_db_command_sync(&self, database_dir: &Path) -> crate::pg_types::PgCommandSync {
        let mut command = std::process::Command::new(&self.pg_ctl_exe);
        command
            .arg("stop")
            .arg("-w")
            .arg("-t")
            .arg("120")
            .arg("-D")
            .arg(database_dir);
        Box::new(std::cell::Cell::new(command))
    }

    /// Installs a third-party extension into the binary cache.
    ///
    /// Copies files from `extension_dir` into the appropriate subdirectory of
    /// [`Self::cache_dir`]:
    ///
    /// | Source extension | Destination |
    /// |---|---|
    /// | `.so`, `.dylib`, `.dll` | `{cache_dir}/lib/` |
    /// | `.control`, `.sql` | `{cache_dir}/share/postgresql/extension/` (or equivalent) |
    /// | anything else, subdirectories | silently skipped |
    ///
    /// Call this method after [`crate::postgres::PgEmbed::setup`] and before
    /// [`crate::postgres::PgEmbed::start_db`], then run
    /// `CREATE EXTENSION IF NOT EXISTS <name>` once the server is up.
    ///
    /// # Arguments
    ///
    /// * `extension_dir` — Directory containing the extension files to install.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DirCreationError`] if the target directories cannot be
    /// created.
    /// Returns [`Error::ReadFileError`] if `extension_dir` cannot be read or a
    /// directory entry cannot be inspected.
    /// Returns [`Error::WriteFileError`] if a file cannot be copied.
    /// Installation is staged into a complete sibling cache and published by
    /// directory rename while an exclusive cross-process cache lease is held.
    /// Once the blocking transaction begins, cancellation of the async caller
    /// cannot leave the live cache partially modified.
    pub async fn install_extension(&self, extension_dir: &Path) -> Result<()> {
        let expected_archive_sha256 = self.fetch_settings.expected_sha256()?.to_owned();
        let authenticated = self
            .authenticated_postgres_executables()
            .await?
            .ok_or(Error::InvalidPgPackage)?;
        let expected_executables = AuthenticatedCacheDigests {
            initdb: authenticated.initdb.sha256,
            pg_ctl: authenticated.pg_ctl.sha256,
            postgres: authenticated.postgres.sha256,
        };
        // The exclusive transaction below cannot begin while this shared lease
        // is retained. It revalidates these archive-derived identities after
        // acquiring exclusive authority.
        drop(authenticated);

        let cache_root = self.cache_root.clone();
        let cache_dir = self.cache_dir.clone();
        let archive_path = self.zip_file_path.clone();
        let marker_path = self.verified_package_marker();
        let initdb_path = self.init_db_exe.clone();
        let pg_ctl_path = self.pg_ctl_exe.clone();
        let postgres_path = self.postgres_executable_path();
        let extension_dir = extension_dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            install_extension_transaction(
                &cache_root,
                &cache_dir,
                &archive_path,
                &marker_path,
                &initdb_path,
                &pg_ctl_path,
                &postgres_path,
                &extension_dir,
                &expected_archive_sha256,
                expected_executables,
            )
        })
        .await
        .map_err(|error| Error::PgTaskJoinError(error.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pg_fetch::{PG_V15, PgFetchSettings};
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};

    fn cache_fixture(cache_path: &Path) -> PgAccess {
        let cache_root = cache_path.join("cache-root");
        let cache_dir = cache_root.join("test-version");
        std::fs::create_dir_all(&cache_dir).unwrap();
        PgAccess {
            cache_root,
            cache_dir: cache_dir.clone(),
            database_dir: cache_path.join("db"),
            pg_ctl_exe: cache_dir.join("bin/pg_ctl"),
            init_db_exe: cache_dir.join("bin/initdb"),
            pw_file_path: cache_path.join("db.pwfile"),
            zip_file_path: cache_dir.join("linux-amd64-15.16.0.zip"),
            pg_version_file: cache_path.join("db/PG_VERSION"),
            fetch_settings: PgFetchSettings {
                operating_system: crate::pg_enums::OperationSystem::Linux,
                architecture: crate::pg_enums::Architecture::Amd64,
                version: PG_V15,
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn executable_cache_without_verification_marker_is_rejected() {
        let cache_dir = tempfile::TempDir::new().unwrap();
        let pg_access = cache_fixture(cache_dir.path());
        tokio::fs::create_dir_all(pg_access.cache_dir.join("bin"))
            .await
            .unwrap();
        tokio::fs::write(&pg_access.init_db_exe, b"unverified initdb")
            .await
            .unwrap();
        tokio::fs::write(&pg_access.pg_ctl_exe, b"unverified pg_ctl")
            .await
            .unwrap();
        tokio::fs::write(pg_access.postgres_executable_path(), b"unverified postgres")
            .await
            .unwrap();
        tokio::fs::write(&pg_access.zip_file_path, b"unverified archive")
            .await
            .unwrap();

        assert!(!pg_access.pg_executables_cached().await.unwrap());
    }

    #[tokio::test]
    async fn executable_cache_with_tampered_archive_is_rejected() {
        let cache_dir = tempfile::TempDir::new().unwrap();
        let pg_access = cache_fixture(cache_dir.path());
        tokio::fs::create_dir_all(pg_access.cache_dir.join("bin"))
            .await
            .unwrap();
        tokio::fs::write(&pg_access.init_db_exe, b"initdb")
            .await
            .unwrap();
        tokio::fs::write(&pg_access.pg_ctl_exe, b"pg_ctl")
            .await
            .unwrap();
        tokio::fs::write(pg_access.postgres_executable_path(), b"postgres")
            .await
            .unwrap();
        tokio::fs::write(&pg_access.zip_file_path, b"tampered archive")
            .await
            .unwrap();
        tokio::fs::write(
            pg_access.verified_package_marker(),
            pg_access.fetch_settings.expected_sha256().unwrap(),
        )
        .await
        .unwrap();

        assert!(!pg_access.pg_executables_cached().await.unwrap());
    }

    #[tokio::test]
    async fn executable_cache_with_tampered_executable_is_rejected() {
        let cache_dir = tempfile::TempDir::new().unwrap();
        let pg_access = cache_fixture(cache_dir.path());
        write_test_package(&pg_access.zip_file_path);
        pg_unpack::unpack_postgres(&pg_access.zip_file_path, &pg_access.cache_dir)
            .await
            .unwrap();
        let bytes = tokio::fs::read(&pg_access.zip_file_path).await.unwrap();
        let expected_package_sha256 = hex::encode(Sha256::digest(&bytes));
        let snapshot = pg_access
            .authenticated_archive_snapshot(&expected_package_sha256)
            .await
            .expect("test package snapshot must authenticate against its explicit test pin");
        tokio::fs::write(
            pg_access.verified_package_marker(),
            &expected_package_sha256,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                pg_access
                    .authenticated_postgres_executable_for_expected(&expected_package_sha256)
                    .await,
                Err(Error::InvalidPgPackage)
            ),
            "a writable or inherited-permission cache must fail closed"
        );
        make_cache_immutable(&pg_access.cache_dir).unwrap();
        let identity = pg_access
            .authenticated_postgres_executable_for_expected(&expected_package_sha256)
            .await
            .unwrap()
            .expect("matching extracted executables");
        assert_eq!(
            identity.path,
            std::fs::canonicalize(pg_access.postgres_executable_path()).unwrap()
        );
        let expected_postgres_digest: [u8; 32] = Sha256::digest(b"expected postgres").into();
        assert_eq!(identity.sha256, expected_postgres_digest);
        drop(identity);

        make_cache_removable(&pg_access.cache_dir).unwrap();
        tokio::fs::write(&pg_access.init_db_exe, b"tampered initdb")
            .await
            .unwrap();
        make_cache_immutable(&pg_access.cache_dir).unwrap();

        assert!(
            pg_access
                .authenticated_postgres_executable_for_expected(&expected_package_sha256)
                .await
                .unwrap()
                .is_none(),
            "tampered initdb must fail the exact authenticated snapshot comparison"
        );

        make_cache_removable(&pg_access.cache_dir).unwrap();
        pg_unpack::unpack_postgres_snapshot(snapshot.clone(), &pg_access.cache_dir)
            .await
            .unwrap();
        tokio::fs::write(pg_access.postgres_executable_path(), b"tampered postgres")
            .await
            .unwrap();
        make_cache_immutable(&pg_access.cache_dir).unwrap();
        assert!(
            pg_access
                .authenticated_postgres_executable_for_expected(&expected_package_sha256)
                .await
                .unwrap()
                .is_none(),
            "tampered postgres must fail the exact authenticated snapshot comparison"
        );

        make_cache_removable(&pg_access.cache_dir).unwrap();
        pg_unpack::unpack_postgres_snapshot(snapshot.clone(), &pg_access.cache_dir)
            .await
            .unwrap();
        tokio::fs::write(&pg_access.pg_ctl_exe, b"tampered pg_ctl")
            .await
            .unwrap();
        make_cache_immutable(&pg_access.cache_dir).unwrap();
        assert!(
            pg_access
                .authenticated_postgres_executable_for_expected(&expected_package_sha256)
                .await
                .unwrap()
                .is_none(),
            "tampered pg_ctl must fail the exact authenticated snapshot comparison"
        );
        make_cache_removable(&pg_access.cache_dir).unwrap();
    }

    fn write_test_package(zip_path: &Path) {
        let mut tar_content = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut tar_content);
            for (path, content) in [
                ("./bin/initdb", b"expected initdb".as_slice()),
                ("./bin/pg_ctl", b"expected pg_ctl".as_slice()),
                ("./bin/postgres", b"expected postgres".as_slice()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                archive.append_data(&mut header, path, content).unwrap();
            }
            archive.finish().unwrap();
        }
        let mut xz_content = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(tar_content), &mut xz_content).unwrap();
        let file = std::fs::File::create(zip_path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.start_file("postgres-test.txz", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&xz_content).unwrap();
        zip.finish().unwrap();
    }

    async fn prepare_authenticated_test_cache(
        pg_access: &PgAccess,
    ) -> (String, AuthenticatedCacheDigests) {
        write_test_package(&pg_access.zip_file_path);
        pg_unpack::unpack_postgres(&pg_access.zip_file_path, &pg_access.cache_dir)
            .await
            .unwrap();
        let archive = tokio::fs::read(&pg_access.zip_file_path).await.unwrap();
        let expected_archive_sha256 = hex::encode(Sha256::digest(&archive));
        tokio::fs::write(
            pg_access.verified_package_marker(),
            &expected_archive_sha256,
        )
        .await
        .unwrap();
        make_cache_immutable(&pg_access.cache_dir).unwrap();
        (
            expected_archive_sha256,
            AuthenticatedCacheDigests {
                initdb: Sha256::digest(b"expected initdb").into(),
                pg_ctl: Sha256::digest(b"expected pg_ctl").into(),
                postgres: Sha256::digest(b"expected postgres").into(),
            },
        )
    }

    #[tokio::test]
    async fn test_install_extension_transaction() {
        let src_dir = tempfile::TempDir::new().unwrap();
        let src_path = src_dir.path();

        std::fs::write(src_path.join("myvec.so"), b"fake so").unwrap();
        std::fs::write(src_path.join("myvec.dylib"), b"fake dylib").unwrap();
        std::fs::write(src_path.join("myvec.control"), b"# control").unwrap();
        std::fs::write(src_path.join("myvec--1.0.sql"), b"-- sql").unwrap();
        std::fs::write(src_path.join("README.txt"), b"readme").unwrap();

        let cache_dir = tempfile::TempDir::new().unwrap();
        let cache_path = cache_dir.path().to_path_buf();
        let pg_access = cache_fixture(&cache_path);
        let (expected_archive_sha256, expected_executables) =
            prepare_authenticated_test_cache(&pg_access).await;

        install_extension_transaction(
            &pg_access.cache_root,
            &pg_access.cache_dir,
            &pg_access.zip_file_path,
            &pg_access.verified_package_marker(),
            &pg_access.init_db_exe,
            &pg_access.pg_ctl_exe,
            &pg_access.postgres_executable_path(),
            src_path,
            &expected_archive_sha256,
            expected_executables,
        )
        .unwrap();

        assert!(
            pg_access.cache_dir.join("lib/myvec.so").exists(),
            "lib/myvec.so missing"
        );
        assert!(
            pg_access.cache_dir.join("lib/myvec.dylib").exists(),
            "lib/myvec.dylib missing"
        );
        // No existing share dir → falls back to share/postgresql/extension
        assert!(
            pg_access
                .cache_dir
                .join("share/postgresql/extension/myvec.control")
                .exists(),
            "share/postgresql/extension/myvec.control missing"
        );
        assert!(
            pg_access
                .cache_dir
                .join("share/postgresql/extension/myvec--1.0.sql")
                .exists(),
            "share/postgresql/extension/myvec--1.0.sql missing"
        );
        assert!(
            !pg_access.cache_dir.join("lib/README.txt").exists(),
            "README.txt should not be in lib/"
        );
        assert!(
            !pg_access
                .cache_dir
                .join("share/postgresql/extension/README.txt")
                .exists(),
            "README.txt should not be in share/postgresql/extension/"
        );
        verify_authenticated_cache_sync(
            &pg_access.cache_dir,
            &pg_access.zip_file_path,
            &pg_access.verified_package_marker(),
            &pg_access.init_db_exe,
            &pg_access.pg_ctl_exe,
            &pg_access.postgres_executable_path(),
            &expected_archive_sha256,
            expected_executables,
        )
        .unwrap();
        make_cache_removable(&pg_access.cache_dir).unwrap();
    }

    #[tokio::test]
    async fn failed_extension_transaction_preserves_original_cache() {
        let cache_dir = tempfile::TempDir::new().unwrap();
        let pg_access = cache_fixture(cache_dir.path());
        let (expected_archive_sha256, expected_executables) =
            prepare_authenticated_test_cache(&pg_access).await;
        let missing_source = cache_dir.path().join("missing-extension-source");

        assert!(
            install_extension_transaction(
                &pg_access.cache_root,
                &pg_access.cache_dir,
                &pg_access.zip_file_path,
                &pg_access.verified_package_marker(),
                &pg_access.init_db_exe,
                &pg_access.pg_ctl_exe,
                &pg_access.postgres_executable_path(),
                &missing_source,
                &expected_archive_sha256,
                expected_executables,
            )
            .is_err()
        );
        verify_authenticated_cache_sync(
            &pg_access.cache_dir,
            &pg_access.zip_file_path,
            &pg_access.verified_package_marker(),
            &pg_access.init_db_exe,
            &pg_access.pg_ctl_exe,
            &pg_access.postgres_executable_path(),
            &expected_archive_sha256,
            expected_executables,
        )
        .unwrap();
        for entry in std::fs::read_dir(&pg_access.cache_root).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.contains(".extension-stage-") && !name.contains(".extension-backup-"),
                "failed transaction left publication artifact {name}"
            );
        }
        make_cache_removable(&pg_access.cache_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_async_wait_cannot_interrupt_extension_publication() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("cancel-safe.sql"), b"SELECT 1;").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let pg_access = cache_fixture(directory.path());
        let (expected_archive_sha256, expected_executables) =
            prepare_authenticated_test_cache(&pg_access).await;
        let hook = Arc::new((std::sync::Barrier::new(2), std::sync::Barrier::new(2)));
        *EXTENSION_TRANSACTION_TEST_HOOK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((pg_access.cache_dir.clone(), hook.clone()));

        let cache_root = pg_access.cache_root.clone();
        let cache_dir = pg_access.cache_dir.clone();
        let archive_path = pg_access.zip_file_path.clone();
        let marker_path = pg_access.verified_package_marker();
        let initdb_path = pg_access.init_db_exe.clone();
        let pg_ctl_path = pg_access.pg_ctl_exe.clone();
        let postgres_path = pg_access.postgres_executable_path();
        let source_path = source.path().to_path_buf();
        let expected_for_task = expected_archive_sha256.clone();
        let task = tokio::task::spawn_blocking(move || {
            install_extension_transaction(
                &cache_root,
                &cache_dir,
                &archive_path,
                &marker_path,
                &initdb_path,
                &pg_ctl_path,
                &postgres_path,
                &source_path,
                &expected_for_task,
                expected_executables,
            )
        });
        hook.0.wait();
        task.abort();
        drop(task);
        hook.1.wait();

        let installed = pg_access
            .cache_dir
            .join("share/postgresql/extension/cancel-safe.sql");
        let started = std::time::Instant::now();
        while !installed.exists() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "detached blocking transaction did not finish publication"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        verify_authenticated_cache_sync(
            &pg_access.cache_dir,
            &pg_access.zip_file_path,
            &pg_access.verified_package_marker(),
            &pg_access.init_db_exe,
            &pg_access.pg_ctl_exe,
            &pg_access.postgres_executable_path(),
            &expected_archive_sha256,
            expected_executables,
        )
        .unwrap();
        make_cache_removable(&pg_access.cache_dir).unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_reparse_directory_is_rejected_before_acl_mutation() {
        use std::os::windows::fs::symlink_dir;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let reparse = directory.path().join("reparse");
        std::fs::create_dir(&target).unwrap();
        if let Err(error) = symlink_dir(&target, &reparse) {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                // Symlink creation requires Developer Mode or the symlink
                // privilege on older Windows hosts.
                return;
            }
            panic!("create test reparse point: {error}");
        }
        assert!(ensure_private_directory(&reparse).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn retained_windows_cache_lock_cannot_be_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let cache_root = directory.path().join("cache-root");
        let cache_dir = cache_root.join("version");
        ensure_private_directory(&cache_dir).unwrap();
        let lease =
            acquire_cache_lease_sync(&cache_root, &cache_dir, false, CACHE_LEASE_TIMEOUT).unwrap();
        let cache_key = hex::encode(Sha256::digest(
            cache_dir.as_os_str().to_string_lossy().as_bytes(),
        ));
        let lock_path = cache_root.join(".locks").join(format!("{cache_key}.lock"));
        let replacement = lock_path.with_extension("replacement");
        assert!(
            std::fs::rename(&lock_path, &replacement).is_err(),
            "a retained no-delete-share lock must not be replaceable"
        );
        assert!(lock_path.exists());

        let root_replacement = directory.path().join("cache-root-replacement");
        assert!(
            std::fs::rename(&cache_root, &root_replacement).is_err(),
            "retained ancestor handles must prevent lock-namespace replacement"
        );
        drop(lease);
    }

    #[test]
    fn exclusive_cache_lease_wait_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let cache_root = directory.path().join("cache-root");
        let cache_dir = cache_root.join("version");
        ensure_private_directory(&cache_dir).unwrap();
        let lease =
            acquire_cache_lease_sync(&cache_root, &cache_dir, false, CACHE_LEASE_TIMEOUT).unwrap();
        let started = Instant::now();
        let result =
            acquire_cache_lease_sync(&cache_root, &cache_dir, false, Duration::from_millis(25));
        assert_eq!(result.unwrap_err(), Error::PgCacheLeaseTimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(lease);
    }
}
