// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use sysinfo::{Pid, Process, System};

use pg_embed::process::PostgresProcess;

const MAX_POSTMASTER_PID_BYTES: u64 = 4 * 1024;

#[derive(Clone, Debug)]
pub(super) struct ExpectedPostgres {
    data_dir: PathBuf,
    executable: PathBuf,
    executable_digest: [u8; 32],
    port: u16,
}

impl ExpectedPostgres {
    pub(super) fn new(
        data_dir: &Path,
        executable: &Path,
        executable_digest: [u8; 32],
        port: u16,
    ) -> io::Result<Self> {
        let data_dir = std::fs::canonicalize(data_dir)?;
        Ok(Self {
            data_dir,
            executable: executable.to_path_buf(),
            executable_digest,
            port,
        })
    }

    pub(super) fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PostmasterIdentity {
    pid: u32,
    data_dir: PathBuf,
    start_time: u64,
    port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedProcess {
    pid: u32,
    start_time: Option<u64>,
    executable: Option<PathBuf>,
    executable_digest: Option<[u8; 32]>,
    data_dir: Option<PathBuf>,
    port: Option<u16>,
    owner_matches_current: Option<bool>,
}

#[derive(Debug)]
struct PidFileSnapshot {
    content: String,
}

/// A process identity captured and verified immediately after Olympus starts
/// its embedded postmaster. Windows/Linux retain the OS process object itself,
/// rather than granting a later numeric PID lookup termination authority.
pub(super) struct ArmedPostgres {
    expected: ExpectedPostgres,
    postmaster: PostmasterIdentity,
    process: ProcessAuthority,
}

enum ProcessAuthority {
    /// Whole-tree capability created before the first post-spawn await.
    Owned(PostgresProcess),
}

impl ArmedPostgres {
    pub(super) fn data_dir(&self) -> &Path {
        self.expected.data_dir()
    }

    pub(super) fn has_exited(&self) -> Result<bool, VerificationFailure> {
        match &self.process {
            ProcessAuthority::Owned(process) => process
                .has_exited()
                .map_err(|_| VerificationFailure::UnverifiableProcess),
        }
    }

    pub(super) fn terminate(&self) -> TerminationOutcome {
        let terminated = match &self.process {
            ProcessAuthority::Owned(process) => process.terminate_force().is_ok(),
        };
        if terminated {
            TerminationOutcome::Terminated(self.postmaster.pid)
        } else {
            TerminationOutcome::TerminationFailed(self.postmaster.pid)
        }
    }
}

#[cfg(target_os = "linux")]
struct RetainedProcess {
    handle: std::os::fd::OwnedFd,
    start_ticks: u64,
}

#[cfg(target_os = "windows")]
struct RetainedProcess {
    handle: std::os::windows::io::OwnedHandle,
    creation_ticks: u64,
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
struct RetainedProcess;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VerificationFailure {
    PidFileMissing,
    UnreadablePidFile,
    MalformedPidFile,
    PidFileChanged,
    PidFileDataDirMismatch,
    PidFilePortMismatch,
    PidMismatch,
    ReusedPid,
    UnverifiableProcess,
    UnverifiableProcessTree,
    ProcessAccessDenied,
    ProcessOwnerMismatch,
    ExecutableMismatch,
    ExecutableDigestMismatch,
    CommandDataDirMismatch,
    CommandPortMismatch,
}

impl VerificationFailure {
    pub(super) const fn message(self) -> &'static str {
        match self {
            Self::PidFileMissing => "postmaster.pid is not present",
            Self::UnreadablePidFile => "postmaster.pid is unreadable or exceeds the size limit",
            Self::MalformedPidFile => "postmaster.pid is structurally invalid",
            Self::PidFileChanged => "postmaster.pid changed while being read; it was preserved",
            Self::PidFileDataDirMismatch => {
                "postmaster.pid names a different PostgreSQL data directory"
            }
            Self::PidFilePortMismatch => "postmaster.pid names a different PostgreSQL port",
            Self::PidMismatch => "the observed process PID does not match postmaster.pid",
            Self::ReusedPid => "the PID was reused by a process with a different start time",
            Self::UnverifiableProcess => {
                "the operating system did not expose complete process identity"
            }
            Self::UnverifiableProcessTree => {
                "the verified postmaster has no retained whole-process-tree authority"
            }
            Self::ProcessAccessDenied => "the operating system denied access to the named process",
            Self::ProcessOwnerMismatch => {
                "the postmaster is owned by a different operating-system principal"
            }
            Self::ExecutableMismatch => {
                "the process executable is not the pg_embed PostgreSQL binary"
            }
            Self::ExecutableDigestMismatch => {
                "the process executable digest does not match the verified pg_embed binary"
            }
            Self::CommandDataDirMismatch => {
                "the process command line names a different PostgreSQL data directory"
            }
            Self::CommandPortMismatch => {
                "the process command line names a different PostgreSQL port"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TerminationOutcome {
    NoPidFile,
    ProcessNotRunning(u32),
    Terminated(u32),
    Refused {
        pid: Option<u32>,
        failure: VerificationFailure,
    },
    TerminationFailed(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PidPresence {
    NoPidFile,
    Absent(u32),
    Live(u32),
    Refused {
        pid: Option<u32>,
        failure: VerificationFailure,
    },
}

impl PidPresence {
    pub(super) fn safe_message(self) -> String {
        match self {
            Self::NoPidFile => "no postmaster.pid was present".to_owned(),
            Self::Absent(pid) => {
                format!("confirmed pid={pid} is absent; PostgreSQL will resolve its pidfile")
            }
            Self::Live(pid) => format!("pid={pid} is live and requires full authentication"),
            Self::Refused { pid, failure } => format!(
                "refused PostgreSQL PID observation{}: {}",
                pid.map(|pid| format!(" for pid={pid}")).unwrap_or_default(),
                failure.message()
            ),
        }
    }
}

impl TerminationOutcome {
    pub(super) fn safe_message(self) -> String {
        match self {
            Self::NoPidFile => "no postmaster.pid was present".to_owned(),
            Self::ProcessNotRunning(pid) => {
                format!("confirmed pid={pid} is absent; preserved postmaster.pid for PostgreSQL")
            }
            Self::Terminated(pid) => {
                format!(
                    "terminated verified embedded PostgreSQL pid={pid}; preserved postmaster.pid"
                )
            }
            Self::Refused { pid, failure } => match pid {
                Some(pid) => format!(
                    "refused to terminate or clean up unverified postmaster pid={pid}: {}",
                    failure.message()
                ),
                None => format!(
                    "refused to terminate or clean up an unverified postmaster: {}",
                    failure.message()
                ),
            },
            Self::TerminationFailed(pid) => {
                format!("verified embedded PostgreSQL pid={pid} did not terminate")
            }
        }
    }
}

/// Determine only whether a pidfile's process is absent.
///
/// This deliberately does not require the executable cache. It can therefore
/// recover a genuinely stale pidfile after cache eviction without weakening
/// the live-process path, which still requires complete executable/owner/argv
/// authentication before any termination.
pub(super) fn probe_postmaster_presence(
    pidfile: &Path,
    expected_data_dir: &Path,
    expected_port: u16,
) -> PidPresence {
    let snapshot = match read_pidfile_snapshot(pidfile) {
        Ok(snapshot) => snapshot,
        Err(VerificationFailure::PidFileMissing) => return PidPresence::NoPidFile,
        Err(failure) => return PidPresence::Refused { pid: None, failure },
    };
    let postmaster = match parse_postmaster_identity(&snapshot.content) {
        Ok(postmaster) => postmaster,
        Err(failure) => return PidPresence::Refused { pid: None, failure },
    };
    let expected_data_dir = match std::fs::canonicalize(expected_data_dir) {
        Ok(path) => path,
        Err(_) => {
            return PidPresence::Refused {
                pid: Some(postmaster.pid),
                failure: VerificationFailure::PidFileDataDirMismatch,
            };
        }
    };
    if !paths_equal(&postmaster.data_dir, &expected_data_dir) {
        return PidPresence::Refused {
            pid: Some(postmaster.pid),
            failure: VerificationFailure::PidFileDataDirMismatch,
        };
    }
    if postmaster.port != expected_port {
        return PidPresence::Refused {
            pid: Some(postmaster.pid),
            failure: VerificationFailure::PidFilePortMismatch,
        };
    }
    match probe_pid_presence(postmaster.pid) {
        Ok(true) => PidPresence::Live(postmaster.pid),
        Ok(false) => PidPresence::Absent(postmaster.pid),
        Err(failure) => PidPresence::Refused {
            pid: Some(postmaster.pid),
            failure,
        },
    }
}

/// Capture the exact postmaster Olympus just started and retain an OS process
/// object for panic cleanup. A later replacement process cannot inherit this
/// authority merely by writing a matching `postmaster.pid`.
pub(super) fn arm_verified_postgres(
    pidfile: &Path,
    expected: ExpectedPostgres,
    process: PostgresProcess,
) -> Result<ArmedPostgres, VerificationFailure> {
    let snapshot = read_pidfile_snapshot(pidfile)?;
    let postmaster = parse_postmaster_identity(&snapshot.content)?;
    verify_pidfile_expectations(&postmaster, &expected)?;
    verify_owned_process(&postmaster, &expected, &process)?;
    Ok(ArmedPostgres {
        expected,
        postmaster,
        process: ProcessAuthority::Owned(process),
    })
}

/// Inspect a stale postmaster, but never reconstruct termination authority
/// from its pidfile.
///
/// This function intentionally never removes `postmaster.pid`. PostgreSQL
/// owns its lock-file lifecycle and can safely resolve a stale file during its
/// next start. A retained leader handle or pidfd is insufficient to prove or
/// terminate the complete PostgreSQL descendant tree, so a live stale process
/// always fails closed. New launches cannot reach this state: their
/// parent-tied supervisor/Job capability tears down the whole tree when the
/// embedding process disappears.
pub(super) fn cleanup_verified_postgres(
    pidfile: &Path,
    expected: &ExpectedPostgres,
) -> (TerminationOutcome, Option<ArmedPostgres>) {
    let snapshot = match read_pidfile_snapshot(pidfile) {
        Ok(snapshot) => snapshot,
        Err(VerificationFailure::PidFileMissing) => {
            return (TerminationOutcome::NoPidFile, None);
        }
        Err(failure) => {
            return (TerminationOutcome::Refused { pid: None, failure }, None);
        }
    };

    let postmaster = match parse_postmaster_identity(&snapshot.content) {
        Ok(identity) => identity,
        Err(failure) => {
            return (TerminationOutcome::Refused { pid: None, failure }, None);
        }
    };
    if let Err(failure) = verify_pidfile_expectations(&postmaster, expected) {
        return (
            TerminationOutcome::Refused {
                pid: Some(postmaster.pid),
                failure,
            },
            None,
        );
    }

    let process = match open_verified_process(&postmaster, expected) {
        Ok(process) => process,
        Err(failure) => {
            return (
                TerminationOutcome::Refused {
                    pid: Some(postmaster.pid),
                    failure,
                },
                None,
            );
        }
    };
    match process {
        None => (TerminationOutcome::ProcessNotRunning(postmaster.pid), None),
        Some(process) => {
            drop(process);
            (
                TerminationOutcome::Refused {
                    pid: Some(postmaster.pid),
                    failure: VerificationFailure::UnverifiableProcessTree,
                },
                None,
            )
        }
    }
}

fn verify_owned_process(
    postmaster: &PostmasterIdentity,
    expected: &ExpectedPostgres,
    process: &PostgresProcess,
) -> Result<(), VerificationFailure> {
    if process.pid() != postmaster.pid {
        return Err(VerificationFailure::PidMismatch);
    }
    if process
        .has_exited()
        .map_err(|_| VerificationFailure::UnverifiableProcess)?
    {
        return Err(VerificationFailure::UnverifiableProcess);
    }

    let system = System::new_all();
    let Some(observed) = system.process(Pid::from_u32(postmaster.pid)) else {
        return Err(VerificationFailure::UnverifiableProcess);
    };
    let mut observed = observe_process(&system, observed);
    #[cfg(target_os = "linux")]
    {
        observed.owner_matches_current = linux_process_owner_matches_current(postmaster.pid);
    }
    #[cfg(target_os = "windows")]
    {
        // The child was created by this principal and the retained Child
        // HANDLE is non-forgeable. The stale-process path performs an
        // independent token-SID comparison on its separately opened handle.
        observed.owner_matches_current = Some(true);
    }
    #[cfg(target_os = "macos")]
    {
        // The supervised payload inherits this process's effective
        // credentials. PostgresProcess retains its private tree and unreaped
        // leader identity, preventing PID reuse through verification.
        observed.owner_matches_current = Some(true);
    }
    verify_identity(postmaster, &observed, expected)?;
    if process
        .has_exited()
        .map_err(|_| VerificationFailure::UnverifiableProcess)?
    {
        return Err(VerificationFailure::UnverifiableProcess);
    }
    Ok(())
}

fn read_pidfile_snapshot(pidfile: &Path) -> Result<PidFileSnapshot, VerificationFailure> {
    let mut file = open_pidfile_no_follow(pidfile).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            VerificationFailure::PidFileMissing
        } else {
            VerificationFailure::UnreadablePidFile
        }
    })?;
    reject_unsafe_pidfile_handle(&file)?;

    // Read twice through the same no-follow file handle. A pathname swap is
    // irrelevant after open, while in-place mutation during observation fails
    // closed instead of producing a mixed identity.
    let first = read_bounded_pidfile(&mut file)?;
    let second = read_bounded_pidfile(&mut file)?;
    if first != second {
        return Err(VerificationFailure::PidFileChanged);
    }
    let content = String::from_utf8(first).map_err(|_| VerificationFailure::MalformedPidFile)?;
    Ok(PidFileSnapshot { content })
}

fn open_pidfile_no_follow(pidfile: &Path) -> io::Result<File> {
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
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(pidfile)
}

fn reject_unsafe_pidfile_handle(file: &File) -> Result<(), VerificationFailure> {
    let metadata = file
        .metadata()
        .map_err(|_| VerificationFailure::UnreadablePidFile)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_POSTMASTER_PID_BYTES
    {
        return Err(VerificationFailure::UnreadablePidFile);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(VerificationFailure::UnreadablePidFile);
        }
    }
    Ok(())
}

fn read_bounded_pidfile(file: &mut File) -> Result<Vec<u8>, VerificationFailure> {
    reject_unsafe_pidfile_handle(file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| VerificationFailure::UnreadablePidFile)?;
    let mut bytes = Vec::with_capacity(MAX_POSTMASTER_PID_BYTES as usize);
    file.by_ref()
        .take(MAX_POSTMASTER_PID_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VerificationFailure::UnreadablePidFile)?;
    reject_unsafe_pidfile_handle(file)?;
    if bytes.len() as u64 > MAX_POSTMASTER_PID_BYTES {
        return Err(VerificationFailure::UnreadablePidFile);
    }
    Ok(bytes)
}

fn verify_pidfile_expectations(
    postmaster: &PostmasterIdentity,
    expected: &ExpectedPostgres,
) -> Result<(), VerificationFailure> {
    if !paths_equal(&postmaster.data_dir, &expected.data_dir) {
        return Err(VerificationFailure::PidFileDataDirMismatch);
    }
    if postmaster.port != expected.port {
        return Err(VerificationFailure::PidFilePortMismatch);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn probe_pid_presence(pid: u32) -> Result<bool, VerificationFailure> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: pidfd_open is a read-only existence/capability probe with zero
    // flags. It does not signal the numeric PID.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0_u32) };
    if raw < 0 {
        return match io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EACCES) | Some(libc::EPERM) => Err(VerificationFailure::ProcessAccessDenied),
            _ => Err(VerificationFailure::UnverifiableProcess),
        };
    }
    // SAFETY: `raw` is a fresh pidfd returned by the kernel.
    let handle = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let process = RetainedProcess {
        handle,
        start_ticks: linux_process_start_ticks(pid).unwrap_or_default(),
    };
    retained_process_exited(&process).map(|exited| !exited)
}

#[cfg(target_os = "windows")]
fn probe_pid_presence(pid: u32) -> Result<bool, VerificationFailure> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, WAIT_FAILED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    // SAFETY: the access mask and parsed PID are plain values. No terminate
    // permission is requested by this absence-only probe.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        return match unsafe { GetLastError() } {
            ERROR_INVALID_PARAMETER => Ok(false),
            ERROR_ACCESS_DENIED => Err(VerificationFailure::ProcessAccessDenied),
            _ => Err(VerificationFailure::UnverifiableProcess),
        };
    }
    // SAFETY: OpenProcess returned a new owned handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    match unsafe { WaitForSingleObject(handle.as_raw_handle().cast(), 0) } {
        WAIT_OBJECT_0 => Ok(false),
        WAIT_TIMEOUT => Ok(true),
        WAIT_FAILED => Err(VerificationFailure::UnverifiableProcess),
        _ => Err(VerificationFailure::UnverifiableProcess),
    }
}

#[cfg(target_os = "macos")]
fn probe_pid_presence(pid: u32) -> Result<bool, VerificationFailure> {
    // Signal zero performs an existence/permission probe without delivering a
    // signal. Unlike a process-list snapshot, it distinguishes confirmed
    // absence from an observation denied by the kernel.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return Ok(true);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Err(VerificationFailure::ProcessAccessDenied),
        _ => Err(VerificationFailure::UnverifiableProcess),
    }
}

#[cfg(target_os = "linux")]
fn open_verified_process(
    postmaster: &PostmasterIdentity,
    expected: &ExpectedPostgres,
) -> Result<Option<RetainedProcess>, VerificationFailure> {
    use std::os::fd::FromRawFd;

    // SAFETY: pidfd_open receives only a parsed PID and zero flags. The owned
    // descriptor below closes the successful result on every return path.
    let raw_fd =
        unsafe { libc::syscall(libc::SYS_pidfd_open, postmaster.pid as libc::pid_t, 0_u32) };
    if raw_fd < 0 {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            Ok(None)
        } else {
            Err(VerificationFailure::UnverifiableProcess)
        };
    }
    // SAFETY: `raw_fd` is a new descriptor returned by pidfd_open.
    let handle = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd as i32) };
    let Some(start_ticks) = linux_process_start_ticks(postmaster.pid) else {
        return Err(VerificationFailure::UnverifiableProcess);
    };
    let process = RetainedProcess {
        handle,
        start_ticks,
    };
    if !retained_process_still_same(postmaster.pid, &process)? {
        return Err(VerificationFailure::UnverifiableProcess);
    }

    let system = System::new_all();
    let Some(observed) = system.process(Pid::from_u32(postmaster.pid)) else {
        return if retained_process_exited(&process)? {
            Ok(None)
        } else {
            Err(VerificationFailure::UnverifiableProcess)
        };
    };
    let mut observed = observe_process(&system, observed);
    observed.owner_matches_current = linux_process_owner_matches_current(postmaster.pid);
    verify_identity(postmaster, &observed, expected)?;
    if !retained_process_still_same(postmaster.pid, &process)? {
        return Err(VerificationFailure::UnverifiableProcess);
    }
    Ok(Some(process))
}

#[cfg(target_os = "windows")]
fn open_verified_process(
    postmaster: &PostmasterIdentity,
    expected: &ExpectedPostgres,
) -> Result<Option<RetainedProcess>, VerificationFailure> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };

    // SAFETY: the access mask and parsed numeric PID are plain values.
    let raw_handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            postmaster.pid,
        )
    };
    if raw_handle.is_null() {
        // SAFETY: GetLastError has no preconditions and is read immediately
        // after the failed OpenProcess call.
        return match unsafe { GetLastError() } {
            ERROR_INVALID_PARAMETER => Ok(None),
            ERROR_ACCESS_DENIED => Err(VerificationFailure::ProcessAccessDenied),
            _ => Err(VerificationFailure::UnverifiableProcess),
        };
    }
    // SAFETY: OpenProcess returned a new owned handle.
    let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw_handle.cast()) };

    let Some(creation_ticks) = windows_process_creation_ticks(handle.as_raw_handle().cast()) else {
        return Err(VerificationFailure::UnverifiableProcess);
    };
    let process = RetainedProcess {
        handle,
        creation_ticks,
    };
    let handle = retained_windows_handle(&process);
    let Some(handle_start_time) = windows_creation_time_unix_seconds(creation_ticks) else {
        return Err(VerificationFailure::UnverifiableProcess);
    };
    if handle_start_time != postmaster.start_time {
        return Err(VerificationFailure::ReusedPid);
    }
    if !retained_process_still_same(postmaster.pid, &process)? {
        return Err(VerificationFailure::UnverifiableProcess);
    }

    let mut executable_buffer = vec![0_u16; 32_768];
    let mut executable_len = executable_buffer.len() as u32;
    // SAFETY: the buffer is writable for `executable_len` UTF-16 elements.
    let queried = unsafe {
        QueryFullProcessImageNameW(
            handle,
            0,
            executable_buffer.as_mut_ptr(),
            &mut executable_len,
        )
    };
    if queried == 0 || executable_len == 0 {
        return Err(VerificationFailure::UnverifiableProcess);
    }
    let handle_executable = PathBuf::from(OsString::from_wide(
        &executable_buffer[..executable_len as usize],
    ));
    let handle_executable = std::fs::canonicalize(handle_executable)
        .map_err(|_| VerificationFailure::UnverifiableProcess)?;
    if !paths_equal(&handle_executable, &expected.executable) {
        return Err(VerificationFailure::ExecutableMismatch);
    }
    if digest_file(&handle_executable).ok() != Some(expected.executable_digest) {
        return Err(VerificationFailure::ExecutableDigestMismatch);
    }

    // The process handle is already retained. Re-read the PID-indexed command
    // metadata now and require it to describe the same creation second and
    // exact pg_embed invocation before granting termination authority.
    let system = System::new_all();
    let Some(observed) = system.process(Pid::from_u32(postmaster.pid)) else {
        return if retained_process_exited(&process)? {
            Ok(None)
        } else {
            Err(VerificationFailure::UnverifiableProcess)
        };
    };
    let mut observed = observe_process(&system, observed);
    observed.owner_matches_current = windows_process_owner_matches_current(handle);
    verify_identity(postmaster, &observed, expected)?;
    if !retained_process_still_same(postmaster.pid, &process)? {
        return Err(VerificationFailure::UnverifiableProcess);
    }
    Ok(Some(process))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn open_verified_process(
    postmaster: &PostmasterIdentity,
    expected: &ExpectedPostgres,
) -> Result<Option<RetainedProcess>, VerificationFailure> {
    let system = System::new_all();
    if system.process(Pid::from_u32(postmaster.pid)).is_none() {
        return Ok(None);
    }
    let _ = expected;
    // Platforms without an OS process-object primitive are inspection-only.
    // A numeric PID never becomes termination authority.
    Err(VerificationFailure::UnverifiableProcess)
}

#[cfg(target_os = "linux")]
fn retained_process_exited(process: &RetainedProcess) -> Result<bool, VerificationFailure> {
    use std::os::fd::AsRawFd;

    let mut descriptor = libc::pollfd {
        fd: process.handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `descriptor` is valid for one pollfd and timeout zero does not
    // block. A readable pidfd denotes process exit.
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if result < 0 {
        return Err(VerificationFailure::UnverifiableProcess);
    }
    if result == 0 {
        return Ok(false);
    }
    if descriptor.revents & libc::POLLIN != 0 {
        Ok(true)
    } else {
        Err(VerificationFailure::UnverifiableProcess)
    }
}

#[cfg(target_os = "linux")]
fn retained_process_still_same(
    pid: u32,
    process: &RetainedProcess,
) -> Result<bool, VerificationFailure> {
    Ok(retained_observation_matches(
        retained_process_exited(process)?,
        process.start_ticks,
        linux_process_start_ticks(pid),
    ))
}

#[cfg(target_os = "linux")]
fn linux_process_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is parenthesized and may itself contain `)`, so split
    // at the final delimiter. Field 22 (`starttime`) is index 19 after fields
    // 1 and 2 have been removed.
    stat.rsplit_once(") ")?
        .1
        .split_ascii_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn linux_process_owner_matches_current(pid: u32) -> Option<bool> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let effective_uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_ascii_whitespace()
        .nth(2)?
        .parse::<libc::uid_t>()
        .ok()?;
    // SAFETY: geteuid has no preconditions or side effects.
    Some(effective_uid == unsafe { libc::geteuid() })
}

#[cfg(target_os = "windows")]
fn retained_windows_handle(process: &RetainedProcess) -> windows_sys::Win32::Foundation::HANDLE {
    use std::os::windows::io::AsRawHandle;

    process.handle.as_raw_handle().cast()
}

#[cfg(target_os = "windows")]
fn retained_process_exited(process: &RetainedProcess) -> Result<bool, VerificationFailure> {
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    // SAFETY: the owned handle remains valid for the call.
    match unsafe { WaitForSingleObject(retained_windows_handle(process), 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(VerificationFailure::UnverifiableProcess),
        _ => Err(VerificationFailure::UnverifiableProcess),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn retained_process_exited(_process: &RetainedProcess) -> Result<bool, VerificationFailure> {
    Err(VerificationFailure::UnverifiableProcess)
}

#[cfg(target_os = "windows")]
fn retained_process_still_same(
    _pid: u32,
    process: &RetainedProcess,
) -> Result<bool, VerificationFailure> {
    Ok(retained_observation_matches(
        retained_process_exited(process)?,
        process.creation_ticks,
        windows_process_creation_ticks(retained_windows_handle(process)),
    ))
}

fn retained_observation_matches(
    retained_object_exited: bool,
    captured_fingerprint: u64,
    observed_fingerprint: Option<u64>,
) -> bool {
    !retained_object_exited && observed_fingerprint == Some(captured_fingerprint)
}

#[cfg(target_os = "windows")]
fn windows_process_creation_ticks(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    // SAFETY: all output pointers reference initialized writable FILETIME
    // values and `handle` was opened with query permission.
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return None;
    }

    Some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

#[cfg(target_os = "windows")]
fn windows_creation_time_unix_seconds(creation_ticks: u64) -> Option<u64> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    creation_ticks
        .checked_sub(WINDOWS_TO_UNIX_EPOCH_100NS)
        .map(|unix_ticks| unix_ticks / 10_000_000)
}

#[cfg(target_os = "windows")]
fn windows_process_owner_matches_current(
    process_handle: windows_sys::Win32::Foundation::HANDLE,
) -> Option<bool> {
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{EqualSid, GetTokenInformation, TokenUser, TOKEN_USER};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    fn open_token(process: HANDLE) -> Option<OwnedHandle> {
        use std::os::windows::io::FromRawHandle;

        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Security::TOKEN_QUERY;
        use windows_sys::Win32::System::Threading::OpenProcessToken;

        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `token` is a writable out pointer and the process handle is
        // either retained or the documented current-process pseudo-handle.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
            return None;
        }
        // SAFETY: OpenProcessToken returned a new owned kernel handle.
        Some(unsafe { OwnedHandle::from_raw_handle(token.cast()) })
    }

    fn token_user_buffer(token: HANDLE) -> Option<Vec<usize>> {
        let mut required = 0_u32;
        // SAFETY: a null buffer with zero length requests the required size.
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
        }
        if (required as usize) < size_of::<TOKEN_USER>() {
            return None;
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        // SAFETY: the usize-backed allocation is suitably aligned and large
        // enough for TOKEN_USER plus its variable-length SID.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return None;
        }
        Some(buffer)
    }

    let process_token = open_token(process_handle)?;
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle for this process.
    let current_token = open_token(unsafe { GetCurrentProcess() })?;
    let process_user = token_user_buffer(process_token.as_raw_handle().cast())?;
    let current_user = token_user_buffer(current_token.as_raw_handle().cast())?;
    // SAFETY: both buffers remain alive and contain validated TOKEN_USER
    // layouts returned by GetTokenInformation.
    let process_sid = unsafe { (*(process_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let current_sid = unsafe { (*(current_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    if process_sid.is_null() || current_sid.is_null() {
        return None;
    }
    // SAFETY: both SID pointers are owned by the live token-information
    // buffers for the duration of the call.
    Some(unsafe { EqualSid(process_sid, current_sid) } != 0)
}

fn parse_postmaster_identity(content: &str) -> Result<PostmasterIdentity, VerificationFailure> {
    let mut lines = content.lines();
    let pid = lines
        .next()
        .and_then(|line| line.trim().parse::<u32>().ok())
        .filter(|pid| *pid != 0)
        .ok_or(VerificationFailure::MalformedPidFile)?;
    let data_dir = lines
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .and_then(|path| std::fs::canonicalize(path).ok())
        .ok_or(VerificationFailure::MalformedPidFile)?;
    let start_time = lines
        .next()
        .and_then(|line| line.trim().parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or(VerificationFailure::MalformedPidFile)?;
    let port = lines
        .next()
        .and_then(|line| line.trim().parse::<u16>().ok())
        .filter(|value| *value != 0)
        .ok_or(VerificationFailure::MalformedPidFile)?;

    // PostgreSQL 15 writes four additional lines after the port: socket
    // directory, listen address, shared-memory identifier, and status.
    lines.next().ok_or(VerificationFailure::MalformedPidFile)?;
    lines.next().ok_or(VerificationFailure::MalformedPidFile)?;
    lines.next().ok_or(VerificationFailure::MalformedPidFile)?;
    let status = lines
        .next()
        .map(str::trim)
        .ok_or(VerificationFailure::MalformedPidFile)?;
    if status != "ready" || lines.next().is_some() {
        return Err(VerificationFailure::MalformedPidFile);
    }

    Ok(PostmasterIdentity {
        pid,
        data_dir,
        start_time,
        port,
    })
}

fn observe_process(system: &System, process: &Process) -> ObservedProcess {
    let (executable, executable_digest) = observe_process_executable(process);
    let (data_dir, port) = observe_postgres_arguments(process.cmd());
    let start_time = (process.start_time() != 0).then_some(process.start_time());
    let owner_matches_current = system
        .process(Pid::from_u32(std::process::id()))
        .and_then(|current| current.user_id())
        .zip(process.user_id())
        .map(|(current, observed)| current == observed);

    ObservedProcess {
        pid: process.pid().as_u32(),
        start_time,
        executable,
        executable_digest,
        data_dir,
        port,
        owner_matches_current,
    }
}

#[cfg(target_os = "linux")]
fn observe_process_executable(process: &Process) -> (Option<PathBuf>, Option<[u8; 32]>) {
    let proc_executable = PathBuf::from(format!("/proc/{}/exe", process.pid().as_u32()));
    let executable = std::fs::read_link(&proc_executable)
        .ok()
        .and_then(|path| std::fs::canonicalize(path).ok());
    // Opening /proc/<pid>/exe hashes the image inode actually mapped by the
    // retained process, not mutable bytes later placed at the same pathname.
    let executable_digest = digest_file(&proc_executable).ok();
    (executable, executable_digest)
}

#[cfg(not(target_os = "linux"))]
fn observe_process_executable(process: &Process) -> (Option<PathBuf>, Option<[u8; 32]>) {
    let executable = process
        .exe()
        .and_then(|path| std::fs::canonicalize(path).ok());
    let executable_digest = executable
        .as_deref()
        .and_then(|path| digest_file(path).ok());
    (executable, executable_digest)
}

fn observe_postgres_arguments(arguments: &[OsString]) -> (Option<PathBuf>, Option<u16>) {
    let Some((data_dir, port)) = normalize_pg_embed_postgres_arguments(arguments) else {
        return (None, None);
    };
    (Some(data_dir), Some(port))
}

fn normalize_pg_embed_postgres_arguments(arguments: &[OsString]) -> Option<(PathBuf, u16)> {
    // sysinfo includes argv[0]. Its resolved image is verified independently,
    // so only the remaining exact pg_embed server options are normalized here.
    if arguments.len() < 2 || arguments[0].is_empty() {
        return None;
    }

    let mut data_dir = None;
    let mut port = None;
    let mut no_fsync = false;
    let mut index = 1;
    while index < arguments.len() {
        let argument = &arguments[index];
        let text = argument.to_str()?;
        match text {
            "-F" => {
                if no_fsync {
                    return None;
                }
                no_fsync = true;
                index += 1;
            }
            "-D" | "--data-directory" => {
                if data_dir.is_some() {
                    return None;
                }
                let value = arguments.get(index + 1)?;
                if value.is_empty() {
                    return None;
                }
                data_dir = Some(PathBuf::from(value));
                index += 2;
            }
            "-p" | "--port" => {
                if port.is_some() {
                    return None;
                }
                port = Some(arguments.get(index + 1)?.to_str()?.parse::<u16>().ok()?);
                index += 2;
            }
            _ => {
                if let Some(value) = text.strip_prefix("--data-directory=") {
                    if data_dir.is_some() || value.is_empty() {
                        return None;
                    }
                    data_dir = Some(PathBuf::from(value));
                } else if let Some(value) = text.strip_prefix("--port=") {
                    if port.is_some() || value.is_empty() {
                        return None;
                    }
                    port = Some(value.parse::<u16>().ok()?);
                } else if let Some(value) = text.strip_prefix("-D") {
                    if data_dir.is_some() || value.is_empty() {
                        return None;
                    }
                    data_dir = Some(PathBuf::from(value.strip_prefix('=').unwrap_or(value)));
                } else if let Some(value) = text.strip_prefix("-p") {
                    if port.is_some() || value.is_empty() {
                        return None;
                    }
                    port = Some(
                        value
                            .strip_prefix('=')
                            .unwrap_or(value)
                            .parse::<u16>()
                            .ok()?,
                    );
                } else {
                    // This is an allowlist, not a blacklist. It rejects `-c`,
                    // `--config-file`, underscore spellings, duplicate
                    // identity options, single-user mode, and future options
                    // until they are explicitly reviewed.
                    return None;
                }
                index += 1;
            }
        }
    }
    let data_dir = std::fs::canonicalize(data_dir?).ok()?;
    let port = port.filter(|port| *port != 0)?;
    no_fsync.then_some((data_dir, port))
}

fn verify_identity(
    postmaster: &PostmasterIdentity,
    observed: &ObservedProcess,
    expected: &ExpectedPostgres,
) -> Result<(), VerificationFailure> {
    verify_pidfile_expectations(postmaster, expected)?;
    if postmaster.pid != observed.pid {
        return Err(VerificationFailure::PidMismatch);
    }
    match observed.owner_matches_current {
        Some(true) => {}
        Some(false) => return Err(VerificationFailure::ProcessOwnerMismatch),
        None => return Err(VerificationFailure::UnverifiableProcess),
    }

    let Some(start_time) = observed.start_time else {
        return Err(VerificationFailure::UnverifiableProcess);
    };
    if start_time != postmaster.start_time {
        return Err(VerificationFailure::ReusedPid);
    }
    let Some(executable) = observed.executable.as_deref() else {
        return Err(VerificationFailure::UnverifiableProcess);
    };
    if !paths_equal(executable, &expected.executable) {
        return Err(VerificationFailure::ExecutableMismatch);
    }
    let Some(executable_digest) = observed.executable_digest else {
        return Err(VerificationFailure::UnverifiableProcess);
    };
    if executable_digest != expected.executable_digest {
        return Err(VerificationFailure::ExecutableDigestMismatch);
    }
    let Some(data_dir) = observed.data_dir.as_deref() else {
        return Err(VerificationFailure::UnverifiableProcess);
    };
    if !paths_equal(data_dir, &expected.data_dir) {
        return Err(VerificationFailure::CommandDataDirMismatch);
    }
    let Some(port) = observed.port else {
        return Err(VerificationFailure::UnverifiableProcess);
    };
    if port != expected.port {
        return Err(VerificationFailure::CommandPortMismatch);
    }
    Ok(())
}

fn digest_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(target_os = "windows")]
fn paths_equal(left: &Path, right: &Path) -> bool {
    left.as_os_str().eq_ignore_ascii_case(right.as_os_str())
}

#[cfg(not(target_os = "windows"))]
fn paths_equal(left: &Path, right: &Path) -> bool {
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (ExpectedPostgres, PostmasterIdentity, ObservedProcess) {
        let data_dir = PathBuf::from("/olympus/app-data/olympus-pg");
        let executable = PathBuf::from("/cache/pg-embed/bin/postgres");
        let expected = ExpectedPostgres {
            data_dir: data_dir.clone(),
            executable: executable.clone(),
            executable_digest: [0x5a; 32],
            port: 5433,
        };
        let postmaster = PostmasterIdentity {
            pid: 42,
            data_dir: data_dir.clone(),
            start_time: 1_800_000_000,
            port: 5433,
        };
        let observed = ObservedProcess {
            pid: 42,
            start_time: Some(1_800_000_000),
            executable: Some(executable),
            executable_digest: Some([0x5a; 32]),
            data_dir: Some(data_dir),
            port: Some(5433),
            owner_matches_current: Some(true),
        };
        (expected, postmaster, observed)
    }

    fn temp_expected(temp: &tempfile::TempDir) -> (PathBuf, ExpectedPostgres) {
        let data_dir = temp.path().join("cluster");
        std::fs::create_dir(&data_dir).expect("cluster dir");
        let executable = temp.path().join(if cfg!(windows) {
            "postgres.exe"
        } else {
            "postgres"
        });
        std::fs::write(&executable, b"test postgres").expect("test executable");
        let expected = ExpectedPostgres::new(
            &data_dir,
            &executable,
            Sha256::digest(b"test postgres").into(),
            5433,
        )
        .expect("expected identity");
        (data_dir, expected)
    }

    #[test]
    fn mismatched_pid_is_never_verified_for_termination() {
        let (expected, postmaster, mut observed) = fixture();
        observed.pid = 43;
        assert_eq!(
            verify_identity(&postmaster, &observed, &expected),
            Err(VerificationFailure::PidMismatch)
        );
    }

    #[test]
    fn reused_pid_with_new_start_time_is_never_verified_for_termination() {
        let (expected, postmaster, mut observed) = fixture();
        observed.start_time = Some(postmaster.start_time + 1);
        assert_eq!(
            verify_identity(&postmaster, &observed, &expected),
            Err(VerificationFailure::ReusedPid)
        );
    }

    #[test]
    fn unverifiable_process_metadata_is_never_accepted_for_termination() {
        let (expected, postmaster, mut observed) = fixture();
        observed.executable = None;
        observed.executable_digest = None;
        assert_eq!(
            verify_identity(&postmaster, &observed, &expected),
            Err(VerificationFailure::UnverifiableProcess)
        );
    }

    #[test]
    fn exact_structural_and_cryptographic_identity_is_verified() {
        let (expected, postmaster, observed) = fixture();
        assert_eq!(verify_identity(&postmaster, &observed, &expected), Ok(()));
    }

    #[test]
    fn owner_mismatch_is_never_verified_for_termination() {
        let (expected, postmaster, mut observed) = fixture();
        observed.owner_matches_current = Some(false);
        assert_eq!(
            verify_identity(&postmaster, &observed, &expected),
            Err(VerificationFailure::ProcessOwnerMismatch)
        );
    }

    #[test]
    fn exited_or_reused_retained_process_fails_observation() {
        assert!(retained_observation_matches(false, 99, Some(99)));
        assert!(!retained_observation_matches(true, 99, Some(99)));
        assert!(!retained_observation_matches(false, 99, Some(100)));
        assert!(!retained_observation_matches(false, 99, None));
    }

    #[test]
    fn exact_pg_embed_arguments_and_real_hyphenated_long_forms_are_normalized() {
        let temp = tempfile::tempdir().expect("temp dir");
        let data_dir = std::fs::canonicalize(temp.path()).expect("canonical data dir");
        let short = vec![
            OsString::from("postgres"),
            OsString::from("-D"),
            data_dir.as_os_str().to_owned(),
            OsString::from("-F"),
            OsString::from("-p"),
            OsString::from("5433"),
        ];
        assert_eq!(
            normalize_pg_embed_postgres_arguments(&short),
            Some((data_dir.clone(), 5433))
        );

        let long = vec![
            OsString::from("postgres"),
            OsString::from(format!("--data-directory={}", data_dir.to_string_lossy())),
            OsString::from("-F"),
            OsString::from("--port=5433"),
        ];
        assert_eq!(
            normalize_pg_embed_postgres_arguments(&long),
            Some((data_dir.clone(), 5433))
        );

        let separated_long = vec![
            OsString::from("postgres"),
            OsString::from("--data-directory"),
            data_dir.as_os_str().to_owned(),
            OsString::from("-F"),
            OsString::from("--port"),
            OsString::from("5433"),
        ];
        assert_eq!(
            normalize_pg_embed_postgres_arguments(&separated_long),
            Some((data_dir.clone(), 5433))
        );

        let attached_short = vec![
            OsString::from("postgres"),
            OsString::from(format!("-D={}", data_dir.to_string_lossy())),
            OsString::from("-F"),
            OsString::from("-p5433"),
        ];
        assert_eq!(
            normalize_pg_embed_postgres_arguments(&attached_short),
            Some((data_dir, 5433))
        );
    }

    #[test]
    fn duplicate_unknown_and_override_arguments_fail_closed() {
        let temp = tempfile::tempdir().expect("temp dir");
        let data_dir = temp.path().as_os_str().to_owned();
        for arguments in [
            vec![
                OsString::from("postgres"),
                OsString::from("-D"),
                data_dir.clone(),
                OsString::from("-D"),
                data_dir.clone(),
                OsString::from("-F"),
                OsString::from("-p"),
                OsString::from("5433"),
            ],
            vec![
                OsString::from("postgres"),
                OsString::from("-D"),
                data_dir.clone(),
                OsString::from("-F"),
                OsString::from("-p"),
                OsString::from("5433"),
                OsString::from("-c"),
                OsString::from("port=9999"),
            ],
            vec![
                OsString::from("postgres"),
                OsString::from("--data_directory"),
                data_dir.clone(),
                OsString::from("-F"),
                OsString::from("--port=5433"),
            ],
            vec![
                OsString::from("postgres"),
                OsString::from("-D"),
                data_dir.clone(),
                OsString::from("-F"),
                OsString::from("-p"),
                OsString::from("5433"),
                OsString::from("--config-file=attacker.conf"),
            ],
            vec![
                OsString::from("postgres"),
                OsString::from("-D"),
                data_dir.clone(),
                OsString::from("-p"),
                OsString::from("5433"),
            ],
            vec![
                OsString::from("postgres"),
                OsString::from("-D"),
                data_dir.clone(),
                OsString::from("-F"),
                OsString::from("-F"),
                OsString::from("-p"),
                OsString::from("5433"),
            ],
            vec![
                OsString::from("postgres"),
                OsString::from("-D"),
                data_dir.clone(),
                OsString::from("-F"),
                OsString::from("-p"),
                OsString::from("5433"),
                OsString::from("--port=5434"),
            ],
        ] {
            assert_eq!(observe_postgres_arguments(&arguments), (None, None));
        }
    }

    #[test]
    fn cleanup_preserves_postgres_owned_pidfile_for_absent_process() {
        let temp = tempfile::tempdir().expect("temp dir");
        let (data_dir, expected) = temp_expected(&temp);
        let pidfile = data_dir.join("postmaster.pid");
        let content = format!(
            "2147483647\n{}\n1800000000\n5433\n\n127.0.0.1\n0\nready\n",
            data_dir.display()
        );
        std::fs::write(&pidfile, &content).expect("pidfile");

        let _ = cleanup_verified_postgres(&pidfile, &expected);
        assert_eq!(
            std::fs::read_to_string(&pidfile).expect("pidfile remains"),
            content
        );
    }

    #[test]
    fn replacement_pidfile_path_is_preserved() {
        let temp = tempfile::tempdir().expect("temp dir");
        let (data_dir, expected) = temp_expected(&temp);
        let pidfile = data_dir.join("postmaster.pid");
        let original = format!(
            "2147483647\n{}\n1800000000\n5433\n\n127.0.0.1\n0\nready\n",
            data_dir.display()
        );
        std::fs::write(&pidfile, original).expect("original pidfile");
        read_pidfile_snapshot(&pidfile).expect("original snapshot");
        std::fs::rename(&pidfile, data_dir.join("postmaster.pid.old"))
            .expect("move original pathname");
        std::fs::write(&pidfile, "replacement identity").expect("replacement pidfile");

        let (outcome, retained) = cleanup_verified_postgres(&pidfile, &expected);
        assert!(retained.is_none());
        assert!(matches!(
            outcome,
            TerminationOutcome::Refused {
                failure: VerificationFailure::MalformedPidFile,
                ..
            }
        ));
        assert_eq!(
            std::fs::read_to_string(&pidfile).expect("replacement remains"),
            "replacement identity"
        );
    }

    #[test]
    fn oversized_pidfile_is_rejected_before_parsing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let pidfile = temp.path().join("postmaster.pid");
        std::fs::write(
            &pidfile,
            vec![b'0'; (MAX_POSTMASTER_PID_BYTES + 1) as usize],
        )
        .expect("write oversized pidfile");
        assert!(matches!(
            read_pidfile_snapshot(&pidfile),
            Err(VerificationFailure::UnreadablePidFile)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn pidfile_symlink_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp dir");
        let target = temp.path().join("target");
        let pidfile = temp.path().join("postmaster.pid");
        std::fs::write(&target, b"attacker-controlled").expect("target");
        symlink(&target, &pidfile).expect("symlink");
        assert!(matches!(
            read_pidfile_snapshot(&pidfile),
            Err(VerificationFailure::UnreadablePidFile)
        ));
        assert_eq!(
            std::fs::read(&target).expect("target remains"),
            b"attacker-controlled"
        );
    }
}
