//! Exact process-tree capability for PostgreSQL and its bundled utilities.
//!
//! Every launch retains the executable image, the direct supervisor/process
//! identity, and an OS-enforced tree boundary. Termination authority is never
//! reconstructed from `postmaster.pid` or from a later numeric-PID lookup.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::pg_access::VerifiedExecutable;
use crate::pg_errors::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessKind {
    Postgres,
    Utility,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessExit {
    code: Option<i32>,
    success: bool,
}

impl ProcessExit {
    pub(crate) const fn success(self) -> bool {
        self.success
    }

    pub(crate) const fn code(self) -> Option<i32> {
        self.code
    }
}

#[derive(Debug)]
enum LaunchImage {
    Verified(VerifiedExecutable),
    AdHoc { path: PathBuf, handle: Arc<File> },
}

impl LaunchImage {
    fn verified(executable: VerifiedExecutable) -> Self {
        Self::Verified(executable)
    }

    fn open(path: &Path) -> Result<Self> {
        use std::fs::OpenOptions;

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
        let handle = options
            .open(path)
            .map_err(|error| process_error("opening process image", error))?;
        let metadata = handle
            .metadata()
            .map_err(|error| process_error("inspecting process image", error))?;
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
        let path = std::fs::canonicalize(path)
            .map_err(|error| process_error("resolving process image", error))?;
        Ok(Self::AdHoc {
            path,
            handle: Arc::new(handle),
        })
    }

    fn path(&self) -> &Path {
        match self {
            Self::Verified(executable) => executable.path(),
            Self::AdHoc { path, .. } => path,
        }
    }

    fn handle(&self) -> Arc<File> {
        match self {
            Self::Verified(executable) => executable.retained_file(),
            Self::AdHoc { handle, .. } => handle.clone(),
        }
    }

    fn verify_before_launch(&self) -> Result<()> {
        match self {
            Self::Verified(executable) => executable.verify_for_launch(),
            Self::AdHoc { path, handle } => verify_ad_hoc_path(path, handle),
        }
    }
}

fn verify_ad_hoc_path(path: &Path, retained: &File) -> Result<()> {
    let current = LaunchImage::open(path)?;
    let current_handle = current.handle();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let retained = retained
            .metadata()
            .map_err(|error| process_error("inspecting retained process image", error))?;
        let current = current_handle
            .metadata()
            .map_err(|error| process_error("inspecting current process image", error))?;
        if retained.dev() != current.dev() || retained.ino() != current.ino() {
            return Err(Error::InvalidPgPackage);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if windows_file_identity(retained)? != windows_file_identity(&current_handle)? {
            return Err(Error::InvalidPgPackage);
        }
    }
    Ok(())
}

/// A sealed, clonable capability for one exact process tree.
///
/// Unix launches a tiny supervisor in a private session. The supervisor
/// forwards a graceful signal only to its direct payload and has a
/// parent-liveness pipe that force-terminates the private group if the
/// embedding process disappears. Windows retains `PROCESS_INFORMATION`'s
/// process and primary-thread handles and assigns the still-suspended child to
/// a private kill-on-close Job Object before resuming that retained thread.
#[derive(Clone)]
pub struct PostgresProcess {
    payload_pid: Arc<std::sync::atomic::AtomicU32>,
    inner: Arc<Mutex<ProcessInner>>,
}

struct ProcessInner {
    kind: ProcessKind,
    exit: Option<ProcessExit>,
    _image: LaunchImage,
    #[cfg(unix)]
    supervisor: std::process::Child,
    #[cfg(unix)]
    supervisor_pid: u32,
    #[cfg(unix)]
    watchdog_pid: u32,
    #[cfg(unix)]
    payload_exit: Option<ProcessExit>,
    #[cfg(unix)]
    payload_status_report: File,
    #[cfg(unix)]
    payload_status_bytes: Vec<u8>,
    #[cfg(unix)]
    _parent_watch: std::os::fd::OwnedFd,
    #[cfg(target_os = "linux")]
    supervisor_pidfd: std::os::fd::OwnedFd,
    #[cfg(target_os = "windows")]
    process: std::os::windows::io::OwnedHandle,
    #[cfg(target_os = "windows")]
    _primary_thread: std::os::windows::io::OwnedHandle,
    #[cfg(target_os = "windows")]
    job: std::os::windows::io::OwnedHandle,
}

impl Drop for ProcessInner {
    fn drop(&mut self) {
        if matches!(refresh_tree_exit(self), Ok(true)) {
            return;
        }

        // Drop is the last exact authority. Attempt a bounded graceful
        // postmaster/utility shutdown, then retain the capability and wait
        // without a deadline after forcing the whole private tree.
        let _ = signal_graceful(self);
        if matches!(
            wait_for_tree_exit(self, Some(Duration::from_secs(2))),
            Ok(true)
        ) {
            return;
        }

        loop {
            if let Err(error) = signal_force_tree(self) {
                log::error!("exact process-tree force termination failed during drop: {error}");
            }
            match wait_for_tree_exit(self, None) {
                Ok(true) => return,
                Ok(false) => unreachable!("an unbounded process-tree wait cannot time out"),
                Err(error) => {
                    log::error!("exact process-tree observation failed during drop: {error}");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

impl std::fmt::Debug for PostgresProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresProcess")
            .field("payload_pid", &self.pid())
            .finish_non_exhaustive()
    }
}

impl PostgresProcess {
    pub(crate) fn spawn_verified<I, A>(
        executable: VerifiedExecutable,
        args: I,
        stdin: Option<File>,
        kind: ProcessKind,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
    {
        Self::spawn_image(
            LaunchImage::verified(executable),
            args.into_iter()
                .map(|argument| argument.as_ref().to_os_string())
                .collect(),
            stdin,
            kind,
        )
    }

    pub(crate) fn spawn_path<I, A>(
        executable: &Path,
        args: I,
        stdin: Option<File>,
        kind: ProcessKind,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
    {
        Self::spawn_image(
            LaunchImage::open(executable)?,
            args.into_iter()
                .map(|argument| argument.as_ref().to_os_string())
                .collect(),
            stdin,
            kind,
        )
    }

    fn spawn_image(
        image: LaunchImage,
        args: Vec<OsString>,
        stdin: Option<File>,
        kind: ProcessKind,
    ) -> Result<Self> {
        image.verify_before_launch()?;
        #[cfg(unix)]
        {
            spawn_unix(image, args, stdin, kind)
        }
        #[cfg(target_os = "windows")]
        {
            spawn_windows(image, args, stdin, kind)
        }
    }

    /// Numeric identifier of the payload for diagnostics and comparison only.
    ///
    /// This value is never standalone termination authority.
    pub fn pid(&self) -> u32 {
        self.payload_pid.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Observe whether every live process in the retained tree has exited.
    pub fn has_exited(&self) -> Result<bool> {
        let mut inner = self.lock_inner()?;
        refresh_tree_exit(&mut inner)
    }

    /// Wait for whole-tree exit without signalling it.
    pub(crate) fn wait(&self, timeout: Option<Duration>) -> Result<Option<ProcessExit>> {
        let mut inner = self.lock_inner()?;
        if wait_for_tree_exit(&mut inner, timeout)? {
            Ok(inner.exit)
        } else {
            Ok(None)
        }
    }

    /// Request graceful shutdown of the retained payload, then force the
    /// entire retained tree if the grace period expires.
    pub fn terminate(&self, grace: Option<Duration>) -> Result<()> {
        let mut inner = self.lock_inner()?;
        if refresh_tree_exit(&mut inner)? {
            return Ok(());
        }

        if let Err(error) = signal_graceful(&mut inner) {
            log::warn!("graceful retained-process shutdown was unavailable: {error}");
            signal_force_tree(&mut inner)?;
            wait_for_tree_exit(&mut inner, None)?;
            return Ok(());
        }
        // `None` historically meant no caller-supplied command timeout. It
        // must not turn graceful shutdown into an unbounded wait that prevents
        // the required whole-tree force fallback.
        let graceful_wait = grace.unwrap_or(Duration::from_secs(5));
        if wait_for_tree_exit(&mut inner, Some(graceful_wait))? {
            return Ok(());
        }

        signal_force_tree(&mut inner)?;
        wait_for_tree_exit(&mut inner, None)?;
        Ok(())
    }

    /// Force-terminate the whole retained tree and wait without releasing its
    /// authority until every live member is gone.
    pub fn terminate_force(&self) -> Result<()> {
        let mut inner = self.lock_inner()?;
        if refresh_tree_exit(&mut inner)? {
            return Ok(());
        }
        signal_force_tree(&mut inner)?;
        wait_for_tree_exit(&mut inner, None)?;
        Ok(())
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, ProcessInner>> {
        self.inner.lock().map_err(|_| {
            Error::PgError(
                "retained process-tree mutex was poisoned".to_owned(),
                String::new(),
            )
        })
    }
}

fn process_error(context: &str, error: io::Error) -> Error {
    Error::PgError(error.to_string(), context.to_owned())
}

fn wait_for_tree_exit(inner: &mut ProcessInner, timeout: Option<Duration>) -> Result<bool> {
    let started = Instant::now();
    loop {
        if refresh_tree_exit(inner)? {
            return Ok(true);
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn spawn_unix(
    image: LaunchImage,
    args: Vec<OsString>,
    stdin: Option<File>,
    kind: ProcessKind,
) -> Result<PostgresProcess> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    const SUPERVISOR: &str = r#"
supervisor_pid=$$
shutdown_signal=$1
shift
payload_pid=0
payload_status=125
forward_shutdown() {
    if [ "$payload_pid" -gt 0 ] 2>/dev/null; then
        kill -"$shutdown_signal" "$payload_pid" 2>/dev/null || true
    fi
}
parent_lost() {
    trap '' USR1 TERM HUP INT
    forward_shutdown
    sleep 2
    kill -KILL "-$supervisor_pid" 2>/dev/null || true
    exit 125
}
normal_finish() {
    trap '' USR1 USR2 TERM HUP INT
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    exit "$payload_status"
}
trap forward_shutdown USR1
trap normal_finish USR2
trap parent_lost TERM HUP
(
    IFS= read -r _ <&@WATCH_FD@
    kill -TERM "$supervisor_pid" 2>/dev/null || true
    sleep 2
    kill -KILL "-$supervisor_pid" 2>/dev/null || true
) @REPORT_FD@>&- @IMAGE_FD@>&- @STATUS_FD@>&- &
watchdog_pid=$!
"$@" @WATCH_FD@>&- @REPORT_FD@>&- @STATUS_FD@>&- &
payload_pid=$!
printf '%s %s\n' "$watchdog_pid" "$payload_pid" >&@REPORT_FD@
while :; do
    wait "$payload_pid"
    observed_status=$?
    if kill -0 "$payload_pid" 2>/dev/null; then
        continue
    fi
    payload_status=$observed_status
    break
done
printf '%s\n' "$payload_status" >&@STATUS_FD@
wait "$watchdog_pid" 2>/dev/null || true
exit "$payload_status"
"#;

    let (watch_read, watch_write) =
        unix_pipe().map_err(|error| process_error("creating supervisor watch pipe", error))?;
    let (report_read, report_write) =
        unix_pipe().map_err(|error| process_error("creating supervisor report pipe", error))?;
    let (status_read, status_write) =
        unix_pipe().map_err(|error| process_error("creating supervisor status pipe", error))?;
    let retained_image = image.handle();
    // Reserve the inherited descriptors in the parent before Command::spawn
    // allocates its private exec-error pipe. Fixed child-only destinations can
    // collide with that pipe under descriptor-heavy test runners and prevent
    // the supervisor from reporting its payload PID.
    let inherited_watch_read = duplicate_unix_fd(watch_read.as_raw_fd(), 198)
        .map_err(|error| process_error("reserving supervisor watch descriptor", error))?;
    let inherited_report_write = duplicate_unix_fd(
        report_write.as_raw_fd(),
        inherited_watch_read.as_raw_fd() + 1,
    )
    .map_err(|error| process_error("reserving supervisor report descriptor", error))?;
    let inherited_image = duplicate_unix_fd(
        retained_image.as_raw_fd(),
        inherited_report_write.as_raw_fd() + 1,
    )
    .map_err(|error| process_error("reserving retained image descriptor", error))?;
    let inherited_status_write =
        duplicate_unix_fd(status_write.as_raw_fd(), inherited_image.as_raw_fd() + 1)
            .map_err(|error| process_error("reserving supervisor status descriptor", error))?;
    let watch_fd = inherited_watch_read.as_raw_fd();
    let report_fd = inherited_report_write.as_raw_fd();
    let image_fd = inherited_image.as_raw_fd();
    let status_fd = inherited_status_write.as_raw_fd();
    let supervisor_script = SUPERVISOR
        .replace("@WATCH_FD@", &watch_fd.to_string())
        .replace("@REPORT_FD@", &report_fd.to_string())
        .replace("@IMAGE_FD@", &image_fd.to_string())
        .replace("@STATUS_FD@", &status_fd.to_string());
    #[cfg(target_os = "linux")]
    let expected_parent = unsafe { libc::getpid() };

    let mut command = Command::new("/bin/sh");
    let shutdown_signal = match kind {
        ProcessKind::Postgres => libc::SIGINT,
        ProcessKind::Utility => libc::SIGTERM,
    };
    let executable_fd_path = if cfg!(target_os = "linux") {
        format!("/proc/self/fd/{image_fd}")
    } else {
        format!("/dev/fd/{image_fd}")
    };
    command
        .arg("-c")
        .arg(supervisor_script)
        .arg("pg-embed-supervisor")
        .arg(shutdown_signal.to_string())
        .arg(executable_fd_path)
        .args(args)
        .stdin(stdin.map_or_else(Stdio::null, Stdio::from))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != expected_parent {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "embedding process exited before supervisor launch completed",
                    ));
                }
            }
            for descriptor in [watch_fd, report_fd, image_fd, status_fd] {
                if libc::fcntl(descriptor, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let mut supervisor = command
        .spawn()
        .map_err(|error| process_error("spawning exact process-tree supervisor", error))?;
    drop(inherited_watch_read);
    drop(inherited_report_write);
    drop(inherited_image);
    drop(inherited_status_write);
    let supervisor_pid = supervisor.id();
    drop(watch_read);
    drop(report_write);
    drop(status_write);

    #[cfg(target_os = "linux")]
    let supervisor_pidfd = match open_pidfd(supervisor_pid) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
            return Err(error);
        }
    };

    // The report pipe is trusted: it is inherited only by the private
    // supervisor before any payload exists. Make it nonblocking so a broken
    // supervisor cannot wedge launch.
    let report_raw = report_read.as_raw_fd();
    let flags = unsafe { libc::fcntl(report_raw, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(report_raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        let error = io::Error::last_os_error();
        terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
        return Err(process_error("configuring supervisor PID report", error));
    }
    let mut report = File::from(report_read);
    let started = Instant::now();
    let mut bytes = Vec::with_capacity(16);
    let (watchdog_pid, reported_payload_pid) = loop {
        let mut buffer = [0_u8; 16];
        match report.read(&mut buffer) {
            Ok(0) => {
                terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
                return Err(Error::PgStartFailure);
            }
            Ok(read) => {
                bytes.extend_from_slice(&buffer[..read]);
                if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
                    let Some(mut reported) = std::str::from_utf8(&bytes[..newline])
                        .ok()
                        .map(str::split_whitespace)
                    else {
                        terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
                        return Err(Error::PgStartFailure);
                    };
                    let Some(watchdog_pid) = reported
                        .next()
                        .and_then(|value| value.parse::<u32>().ok())
                        .filter(|pid| *pid > 0)
                    else {
                        terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
                        return Err(Error::PgStartFailure);
                    };
                    let Some(reported_payload_pid) = reported
                        .next()
                        .and_then(|value| value.parse::<u32>().ok())
                        .filter(|pid| *pid > 0)
                    else {
                        terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
                        return Err(Error::PgStartFailure);
                    };
                    if reported.next().is_some() {
                        terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
                        return Err(Error::PgStartFailure);
                    }
                    break (watchdog_pid, reported_payload_pid);
                }
                if bytes.len() > 32 {
                    terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
                    return Err(Error::PgStartFailure);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => {
                terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
                return Err(process_error("reading supervisor payload PID", error));
            }
        }
        if unix_child_has_exited(&mut supervisor) || started.elapsed() >= Duration::from_secs(5) {
            terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
            return Err(Error::PgStartFailure);
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    let status_raw = status_read.as_raw_fd();
    let status_flags = unsafe { libc::fcntl(status_raw, libc::F_GETFL) };
    if status_flags < 0
        || unsafe { libc::fcntl(status_raw, libc::F_SETFL, status_flags | libc::O_NONBLOCK) } < 0
    {
        let error = io::Error::last_os_error();
        terminate_unowned_unix_tree(&mut supervisor, supervisor_pid);
        return Err(process_error("configuring supervisor status report", error));
    }

    Ok(PostgresProcess {
        payload_pid: Arc::new(std::sync::atomic::AtomicU32::new(reported_payload_pid)),
        inner: Arc::new(Mutex::new(ProcessInner {
            kind,
            exit: None,
            _image: image,
            supervisor,
            supervisor_pid,
            watchdog_pid,
            payload_exit: None,
            payload_status_report: File::from(status_read),
            payload_status_bytes: Vec::with_capacity(16),
            _parent_watch: watch_write,
            #[cfg(target_os = "linux")]
            supervisor_pidfd,
        })),
    })
}

#[cfg(unix)]
fn unix_pid_exited(pid: u32) -> Result<bool> {
    let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut information,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(process_error(
            "observing unreaped process-tree leader",
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { information.si_pid() } != 0)
}

#[cfg(unix)]
fn unix_child_has_exited(child: &mut std::process::Child) -> bool {
    unix_pid_exited(child.id()).unwrap_or(true)
}

#[cfg(unix)]
fn terminate_unowned_unix_tree(child: &mut std::process::Child, group: u32) {
    let Ok(group_signal) = i32::try_from(group) else {
        let _ = child.wait();
        return;
    };
    loop {
        let result = unsafe { libc::kill(-group_signal, libc::SIGKILL) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            log::error!(
                "pre-capability process-tree force termination failed: {}",
                io::Error::last_os_error()
            );
        }
        match unix_live_group_members_for(group, &[group]) {
            Ok(members) if members.is_empty() => break,
            Ok(_) | Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let _ = child.wait();
}

#[cfg(unix)]
fn unix_pipe() -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;

    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for descriptor in descriptors {
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
            }
            return Err(io::Error::last_os_error());
        }
    }
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(descriptors[0]),
            std::os::fd::OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

#[cfg(unix)]
fn duplicate_unix_fd(
    source: std::os::fd::RawFd,
    minimum: std::os::fd::RawFd,
) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    let duplicate = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, minimum) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) })
}

#[cfg(unix)]
fn unix_leader_exited(inner: &ProcessInner) -> Result<bool> {
    unix_pid_exited(inner.supervisor_pid)
}

#[cfg(target_os = "linux")]
fn unix_live_group_members_for(group: u32, excluded: &[u32]) -> Result<Vec<u32>> {
    let mut members = Vec::new();
    let entries = std::fs::read_dir("/proc")
        .map_err(|error| process_error("enumerating Linux process group", error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| process_error("enumerating Linux process group", error))?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if excluded.contains(&pid) {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(after_name) = stat.rsplit_once(')').map(|(_, suffix)| suffix.trim()) else {
            continue;
        };
        let mut fields = after_name.split_whitespace();
        let state = fields.next();
        let _parent = fields.next();
        let process_group = fields.next().and_then(|value| value.parse::<u32>().ok());
        if process_group == Some(group) && state != Some("Z") {
            members.push(pid);
        }
    }
    Ok(members)
}

#[cfg(target_os = "macos")]
fn unix_live_group_members_for(group: u32, excluded: &[u32]) -> Result<Vec<u32>> {
    const PROC_PGRP_ONLY: u32 = 2;

    unsafe extern "C" {
        fn proc_listpids(
            process_type: u32,
            type_info: u32,
            buffer: *mut libc::c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
    }

    let required = unsafe { proc_listpids(PROC_PGRP_ONLY, group, std::ptr::null_mut(), 0) };
    if required < 0 {
        return Err(process_error(
            "sizing macOS process-group observation",
            io::Error::last_os_error(),
        ));
    }
    let capacity = (required as usize)
        .saturating_add(32 * std::mem::size_of::<libc::pid_t>())
        .max(std::mem::size_of::<libc::pid_t>());
    let mut buffer = vec![0_u8; capacity];
    let written = unsafe {
        proc_listpids(
            PROC_PGRP_ONLY,
            group,
            buffer.as_mut_ptr().cast(),
            buffer.len() as libc::c_int,
        )
    };
    if written < 0 {
        return Err(process_error(
            "enumerating macOS process group",
            io::Error::last_os_error(),
        ));
    }
    let count = written as usize / std::mem::size_of::<libc::pid_t>();
    let pids = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<libc::pid_t>(), count) };
    Ok(pids
        .iter()
        .copied()
        .filter(|pid| *pid > 0 && !excluded.contains(&(*pid as u32)))
        .map(|pid| pid as u32)
        .collect())
}

#[cfg(unix)]
fn unix_live_group_members(inner: &ProcessInner) -> Result<Vec<u32>> {
    unix_live_group_members_for(
        inner.supervisor_pid,
        &[inner.supervisor_pid, inner.watchdog_pid],
    )
}

#[cfg(unix)]
fn refresh_payload_exit(inner: &mut ProcessInner) -> Result<()> {
    use std::io::Read;

    if inner.payload_exit.is_some() {
        return Ok(());
    }

    loop {
        let mut buffer = [0_u8; 16];
        match inner.payload_status_report.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                inner
                    .payload_status_bytes
                    .extend_from_slice(&buffer[..read]);
                if inner.payload_status_bytes.len() > 16 {
                    return Err(Error::PgError(
                        "invalid retained payload exit-status report".to_owned(),
                        String::new(),
                    ));
                }
                let Some(newline) = inner
                    .payload_status_bytes
                    .iter()
                    .position(|byte| *byte == b'\n')
                else {
                    continue;
                };
                if inner.payload_status_bytes[newline + 1..]
                    .iter()
                    .any(|byte| !byte.is_ascii_whitespace())
                {
                    return Err(Error::PgError(
                        "invalid retained payload exit-status report".to_owned(),
                        String::new(),
                    ));
                }
                let status = std::str::from_utf8(&inner.payload_status_bytes[..newline])
                    .ok()
                    .and_then(|value| value.parse::<u8>().ok())
                    .ok_or_else(|| {
                        Error::PgError(
                            "invalid retained payload exit-status report".to_owned(),
                            String::new(),
                        )
                    })?;
                inner.payload_exit = Some(ProcessExit {
                    code: Some(i32::from(status)),
                    success: status == 0,
                });
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => {
                return Err(process_error(
                    "reading retained payload exit-status report",
                    error,
                ));
            }
        }
    }
}

#[cfg(unix)]
fn refresh_tree_exit(inner: &mut ProcessInner) -> Result<bool> {
    if inner.exit.is_some() {
        return Ok(true);
    }

    refresh_payload_exit(inner)?;
    let leader_exited = unix_leader_exited(inner)?;
    let live_payload_members = unix_live_group_members(inner)?;
    if !leader_exited {
        // Keep the supervisor (and therefore its parent-loss watchdog) alive
        // after the direct payload exits while any descendant remains. Once
        // the payload status is known and its whole subtree is empty, ask the
        // exact retained supervisor to reap its watchdog and exit normally.
        if inner.payload_exit.is_some() && live_payload_members.is_empty() {
            signal_unix_supervisor(inner, libc::SIGUSR2)?;
        }
        return Ok(false);
    }
    if !live_payload_members.is_empty() {
        return Ok(false);
    }

    let status = inner
        .supervisor
        .wait()
        .map_err(|error| process_error("reaping process-tree supervisor", error))?;
    let supervisor_exit = ProcessExit {
        code: status.code(),
        success: status.success(),
    };
    inner.exit = Some(inner.payload_exit.unwrap_or(supervisor_exit));
    Ok(true)
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0_u32) };
    if raw < 0 {
        return Err(process_error(
            "opening retained Linux supervisor pidfd",
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) })
}

#[cfg(target_os = "linux")]
fn signal_linux_supervisor(inner: &ProcessInner, signal: libc::c_int) -> Result<()> {
    use std::os::fd::AsRawFd;

    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            inner.supervisor_pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    };
    if result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(process_error(
            "signalling retained Linux supervisor pidfd",
            io::Error::last_os_error(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn signal_macos_supervisor(inner: &ProcessInner, signal: libc::c_int) -> Result<()> {
    let result = unsafe { libc::kill(inner.supervisor_pid as libc::pid_t, signal) };
    if result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(process_error(
            "signalling retained macOS direct-child supervisor",
            io::Error::last_os_error(),
        ))
    }
}

#[cfg(unix)]
fn signal_unix_supervisor(inner: &ProcessInner, signal: libc::c_int) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        signal_linux_supervisor(inner, signal)
    }
    #[cfg(target_os = "macos")]
    {
        signal_macos_supervisor(inner, signal)
    }
}

#[cfg(unix)]
fn signal_graceful(inner: &mut ProcessInner) -> Result<()> {
    signal_unix_supervisor(inner, libc::SIGUSR1)
}

#[cfg(unix)]
fn signal_force_tree(inner: &mut ProcessInner) -> Result<()> {
    let group = i32::try_from(inner.supervisor_pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            Error::PgError(
                "invalid retained process-group identifier".to_owned(),
                String::new(),
            )
        })?;
    let result = unsafe { libc::kill(-group, libc::SIGKILL) };
    if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err(process_error(
            "force-terminating retained private process group",
            io::Error::last_os_error(),
        ));
    }
    #[cfg(target_os = "linux")]
    signal_linux_supervisor(inner, libc::SIGKILL)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn spawn_windows(
    image: LaunchImage,
    args: Vec<OsString>,
    stdin: Option<File>,
    kind: ProcessKind,
) -> Result<PostgresProcess> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, TRUE,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
    };

    fn inherited_null(access: u32, security: &mut SECURITY_ATTRIBUTES) -> io::Result<OwnedHandle> {
        use std::os::windows::io::FromRawHandle;

        let name: Vec<u16> = OsStr::new("NUL").encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                security,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedHandle::from_raw_handle(handle.cast()) })
        }
    }

    let mut security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: TRUE,
    };
    let null_input = inherited_null(GENERIC_READ, &mut security)
        .map_err(|error| process_error("opening inherited Windows null input", error))?;
    let null_output = inherited_null(GENERIC_WRITE, &mut security)
        .map_err(|error| process_error("opening inherited Windows null output", error))?;
    let mut duplicated_input: HANDLE = std::ptr::null_mut();
    let input_handle = if let Some(file) = stdin.as_ref() {
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                file.as_raw_handle().cast(),
                GetCurrentProcess(),
                &mut duplicated_input,
                0,
                TRUE,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(process_error(
                "duplicating inherited Windows process input",
                io::Error::last_os_error(),
            ));
        }
        duplicated_input
    } else {
        null_input.as_raw_handle().cast()
    };
    let duplicated_input = if duplicated_input.is_null() {
        None
    } else {
        Some(unsafe { OwnedHandle::from_raw_handle(duplicated_input.cast()) })
    };

    let mut inherited = [input_handle, null_output.as_raw_handle().cast()];
    let mut attributes_size = 0_usize;
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attributes_size);
    }
    if attributes_size == 0 {
        return Err(process_error(
            "sizing Windows process attribute list",
            io::Error::last_os_error(),
        ));
    }
    let mut attributes = vec![0_usize; attributes_size.div_ceil(std::mem::size_of::<usize>())];
    let attribute_list = attributes.as_mut_ptr().cast();
    if unsafe { InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut attributes_size) } == 0
    {
        return Err(process_error(
            "initializing Windows process attribute list",
            io::Error::last_os_error(),
        ));
    }
    struct AttributeListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for AttributeListGuard {
        fn drop(&mut self) {
            unsafe {
                DeleteProcThreadAttributeList(self.0);
            }
        }
    }
    let _attributes_guard = AttributeListGuard(attribute_list);
    if unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited.as_mut_ptr().cast(),
            inherited.len() * size_of::<HANDLE>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(process_error(
            "restricting inherited Windows process handles",
            io::Error::last_os_error(),
        ));
    }

    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input_handle;
    startup.StartupInfo.hStdOutput = null_output.as_raw_handle().cast();
    startup.StartupInfo.hStdError = null_output.as_raw_handle().cast();
    startup.lpAttributeList = attribute_list;

    let application: Vec<u16> = image
        .path()
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut command_line = windows_command_line(image.path().as_os_str(), &args);
    let mut process_information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            std::ptr::null(),
            &startup.StartupInfo,
            &mut process_information,
        )
    };
    drop(duplicated_input);
    if created == 0 {
        return Err(process_error(
            "creating suspended authenticated Windows process",
            io::Error::last_os_error(),
        ));
    }
    if process_information.hProcess.is_null() || process_information.hThread.is_null() {
        if !process_information.hProcess.is_null() {
            let partial_process =
                unsafe { OwnedHandle::from_raw_handle(process_information.hProcess.cast()) };
            terminate_unassigned_windows_process(&partial_process);
        }
        if !process_information.hThread.is_null() {
            drop(unsafe { OwnedHandle::from_raw_handle(process_information.hThread.cast()) });
        }
        return Err(Error::PgStartFailure);
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process_information.hProcess.cast()) };
    let primary_thread =
        unsafe { OwnedHandle::from_raw_handle(process_information.hThread.cast()) };
    let job = match create_kill_on_close_job(&process) {
        Ok(job) => job,
        Err(error) => {
            terminate_unassigned_windows_process(&process);
            return Err(process_error(
                "assigning suspended process to private Windows job",
                error,
            ));
        }
    };
    if unsafe {
        windows_sys::Win32::System::Threading::ResumeThread(primary_thread.as_raw_handle().cast())
    } == u32::MAX
    {
        let error = io::Error::last_os_error();
        let _ = terminate_windows_job_handle(&job);
        wait_windows_job_empty_handle(&job);
        return Err(process_error(
            "resuming retained Windows primary thread",
            error,
        ));
    }

    let pid = process_information.dwProcessId;
    Ok(PostgresProcess {
        payload_pid: Arc::new(std::sync::atomic::AtomicU32::new(pid)),
        inner: Arc::new(Mutex::new(ProcessInner {
            kind,
            exit: None,
            _image: image,
            process,
            _primary_thread: primary_thread,
            job,
        })),
    })
}

#[cfg(target_os = "windows")]
fn windows_command_line(program: &OsStr, args: &[OsString]) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    fn append_quoted(output: &mut Vec<u16>, value: &OsStr) {
        let units: Vec<u16> = value.encode_wide().collect();
        let requires_quotes = units.is_empty()
            || units
                .iter()
                .any(|unit| *unit == b' ' as u16 || *unit == b'\t' as u16 || *unit == b'"' as u16);
        if !requires_quotes {
            output.extend(units);
            return;
        }
        output.push(b'"' as u16);
        let mut backslashes = 0_usize;
        for unit in units {
            if unit == b'\\' as u16 {
                backslashes += 1;
                continue;
            }
            if unit == b'"' as u16 {
                output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
                output.push(unit);
                backslashes = 0;
                continue;
            }
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            backslashes = 0;
            output.push(unit);
        }
        output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
        output.push(b'"' as u16);
    }

    let mut command_line = Vec::new();
    append_quoted(&mut command_line, program);
    for argument in args {
        command_line.push(b' ' as u16);
        append_quoted(&mut command_line, argument);
    }
    command_line.push(0);
    command_line
}

#[cfg(target_os = "windows")]
fn create_kill_on_close_job(
    process: &std::os::windows::io::OwnedHandle,
) -> io::Result<std::os::windows::io::OwnedHandle> {
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };

    let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw_job.is_null() {
        return Err(io::Error::last_os_error());
    }
    let job = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw_job.cast()) };
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            raw_job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { AssignProcessToJobObject(raw_job, process.as_raw_handle().cast()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

#[cfg(target_os = "windows")]
fn terminate_unassigned_windows_process(process: &std::os::windows::io::OwnedHandle) {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::System::Threading::{INFINITE, TerminateProcess, WaitForSingleObject};

    unsafe {
        TerminateProcess(process.as_raw_handle().cast(), 1);
        WaitForSingleObject(process.as_raw_handle().cast(), INFINITE);
    }
}

#[cfg(target_os = "windows")]
fn terminate_windows_job_handle(job: &std::os::windows::io::OwnedHandle) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    if unsafe {
        windows_sys::Win32::System::JobObjects::TerminateJobObject(job.as_raw_handle().cast(), 1)
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn windows_job_active_processes(job: &std::os::windows::io::OwnedHandle) -> io::Result<u32> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::System::JobObjects::{
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
        QueryInformationJobObject,
    };

    let mut information: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        QueryInformationJobObject(
            job.as_raw_handle().cast(),
            JobObjectBasicAccountingInformation,
            (&mut information as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(information.ActiveProcesses)
    }
}

#[cfg(target_os = "windows")]
fn wait_windows_job_empty_handle(job: &std::os::windows::io::OwnedHandle) {
    while !matches!(windows_job_active_processes(job), Ok(0)) {
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "windows")]
fn refresh_tree_exit(inner: &mut ProcessInner) -> Result<bool> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::STILL_ACTIVE;
    use windows_sys::Win32::System::Threading::GetExitCodeProcess;

    if inner.exit.is_some() {
        return Ok(true);
    }
    let active = windows_job_active_processes(&inner.job)
        .map_err(|error| process_error("observing retained Windows job", error))?;
    if active != 0 {
        return Ok(false);
    }
    let mut code = STILL_ACTIVE as u32;
    if unsafe { GetExitCodeProcess(inner.process.as_raw_handle().cast(), &mut code) } == 0 {
        return Err(process_error(
            "reading retained Windows process exit code",
            io::Error::last_os_error(),
        ));
    }
    // An empty retained Job is terminal even if the leader handle briefly
    // reports STILL_ACTIVE. Preserve the observed code for diagnostics, but
    // never turn the authoritative zero-process observation back into live.
    inner.exit = Some(ProcessExit {
        code: i32::try_from(code).ok(),
        success: code == 0,
    });
    Ok(true)
}

#[cfg(target_os = "windows")]
fn send_windows_postgres_signal(inner: &ProcessInner, signal: u8) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_FILE_NOT_FOUND, ERROR_IO_INCOMPLETE,
        ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT, FALSE, GENERIC_READ, GENERIC_WRITE,
        HANDLE, INVALID_HANDLE_VALUE, TRUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, INFINITE, WaitForSingleObject,
    };

    const SIGNAL_PIPE_DEADLINE: Duration = Duration::from_secs(1);

    fn remaining_milliseconds(deadline: Instant) -> Option<u32> {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        let milliseconds = remaining.as_nanos().saturating_add(999_999) / 1_000_000;
        Some(u32::try_from(milliseconds).unwrap_or(u32::MAX).max(1))
    }

    fn timeout_error(context: &str) -> Error {
        process_error(
            context,
            io::Error::new(
                io::ErrorKind::TimedOut,
                "authenticated PostgreSQL signal-pipe operation timed out",
            ),
        )
    }

    struct PendingPipeIo {
        pipe: OwnedHandle,
        event: OwnedHandle,
        overlapped: Box<OVERLAPPED>,
        byte: Box<u8>,
    }

    struct PendingPipeIoPointer(*mut PendingPipeIo);

    // SAFETY: this pointer is created from `Box::into_raw` and has exactly one
    // Rust owner. The cleanup thread reads only the stable event handle while
    // the kernel may access the separately boxed OVERLAPPED and byte; it frees
    // the complete state only after the event reports I/O completion.
    unsafe impl Send for PendingPipeIoPointer {}

    impl PendingPipeIoPointer {
        fn collect_after_completion(self) {
            let pending = unsafe { Box::from_raw(self.0) };
            if unsafe { WaitForSingleObject(pending.event.as_raw_handle().cast(), INFINITE) }
                != WAIT_OBJECT_0
            {
                // The event is retained and valid, so this is an OS failure.
                // Leak the tiny state instead of risking kernel use-after-free.
                Box::leak(pending);
            }
        }
    }

    fn defer_cancelled_io_cleanup(pending: PendingPipeIo) {
        let raw = Box::into_raw(Box::new(pending));
        let pointer = PendingPipeIoPointer(raw);
        if std::thread::Builder::new()
            .name("pg-embed-pipe-cleanup".to_owned())
            .spawn(move || pointer.collect_after_completion())
            .is_err()
        {
            // `raw` remains intentionally allocated if a cleanup thread cannot
            // be created. The caller still reaches Job termination on time,
            // and no kernel-visible OVERLAPPED or buffer is freed too early.
            log::error!(
                "could not start detached PostgreSQL signal-pipe cancellation cleanup thread"
            );
        }
    }

    fn transfer_one_byte(
        authenticated_pipe: &OwnedHandle,
        byte: &mut u8,
        write: bool,
        deadline: Instant,
        context: &str,
    ) -> Result<()> {
        let mut duplicated_pipe: HANDLE = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                authenticated_pipe.as_raw_handle().cast(),
                GetCurrentProcess(),
                &mut duplicated_pipe,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
            || duplicated_pipe.is_null()
        {
            return Err(process_error(
                "duplicating authenticated PostgreSQL signal pipe",
                io::Error::last_os_error(),
            ));
        }
        let duplicated_pipe = unsafe { OwnedHandle::from_raw_handle(duplicated_pipe.cast()) };
        let raw_event = unsafe { CreateEventW(std::ptr::null(), TRUE, FALSE, std::ptr::null()) };
        if raw_event.is_null() {
            return Err(process_error(
                "creating PostgreSQL signal-pipe completion event",
                io::Error::last_os_error(),
            ));
        }
        let event = unsafe { OwnedHandle::from_raw_handle(raw_event.cast()) };
        let mut pending = PendingPipeIo {
            pipe: duplicated_pipe,
            event,
            overlapped: Box::new(unsafe { std::mem::zeroed() }),
            byte: Box::new(*byte),
        };
        pending.overlapped.hEvent = pending.event.as_raw_handle().cast();
        let mut immediate_bytes = 0_u32;
        let call_result = if write {
            unsafe {
                WriteFile(
                    pending.pipe.as_raw_handle().cast(),
                    (&*pending.byte as *const u8).cast(),
                    1,
                    &mut immediate_bytes,
                    &mut *pending.overlapped,
                )
            }
        } else {
            unsafe {
                ReadFile(
                    pending.pipe.as_raw_handle().cast(),
                    (&mut *pending.byte as *mut u8).cast(),
                    1,
                    &mut immediate_bytes,
                    &mut *pending.overlapped,
                )
            }
        };
        let call_error = (call_result == 0).then(io::Error::last_os_error);
        let transferred = if call_result != 0 {
            immediate_bytes
        } else {
            let call_error = call_error.expect("failed overlapped call records its OS error");
            if call_error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(process_error(context, call_error));
            }
            let mut transferred = 0_u32;
            let remaining = remaining_milliseconds(deadline);
            let completed = remaining.is_some_and(|milliseconds| unsafe {
                GetOverlappedResultEx(
                    pending.pipe.as_raw_handle().cast(),
                    &*pending.overlapped,
                    &mut transferred,
                    milliseconds,
                    FALSE,
                ) != 0
            });
            if completed {
                transferred
            } else {
                let completion_error = remaining
                    .map(|_| io::Error::last_os_error())
                    .unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "authenticated PostgreSQL signal-pipe deadline expired",
                        )
                    });
                let still_pending = completion_error.raw_os_error() == Some(WAIT_TIMEOUT as i32)
                    || completion_error.raw_os_error() == Some(ERROR_IO_INCOMPLETE as i32)
                    || completion_error.kind() == io::ErrorKind::TimedOut
                    || remaining_milliseconds(deadline).is_none();
                if still_pending {
                    unsafe {
                        CancelIoEx(pending.pipe.as_raw_handle().cast(), &*pending.overlapped);
                    }
                    defer_cancelled_io_cleanup(pending);
                    return Err(timeout_error(context));
                }
                return Err(process_error(context, completion_error));
            }
        };
        if transferred != 1 {
            return Err(Error::PgError(
                format!("{context}: expected one transferred byte, got {transferred}"),
                String::new(),
            ));
        }
        if !write {
            *byte = *pending.byte;
        }
        Ok(())
    }

    match unsafe { WaitForSingleObject(inner.process.as_raw_handle().cast(), 0) } {
        WAIT_OBJECT_0 => return Ok(()),
        WAIT_TIMEOUT => {}
        _ => {
            return Err(process_error(
                "observing retained PostgreSQL process before graceful shutdown",
                io::Error::last_os_error(),
            ));
        }
    }
    let process_id = windows_process_id(&inner.process)?;
    let pipe_name = format!(r"\\.\pipe\pgsignal_{process_id}");
    let pipe_name: Vec<u16> = OsStr::new(&pipe_name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let deadline = Instant::now() + SIGNAL_PIPE_DEADLINE;
    let raw_pipe = loop {
        let Some(wait_milliseconds) = remaining_milliseconds(deadline) else {
            return Err(timeout_error("connecting retained PostgreSQL signal pipe"));
        };
        if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), wait_milliseconds) } == 0 {
            let error = io::Error::last_os_error();
            if remaining_milliseconds(deadline).is_none() {
                return Err(timeout_error("connecting retained PostgreSQL signal pipe"));
            }
            if matches!(
                error.raw_os_error().map(|code| code as u32),
                Some(ERROR_FILE_NOT_FOUND) | Some(ERROR_PIPE_BUSY) | Some(ERROR_SEM_TIMEOUT)
            ) {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(process_error(
                "waiting for retained PostgreSQL signal pipe",
                error,
            ));
        }
        let pipe = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if pipe != INVALID_HANDLE_VALUE && !pipe.is_null() {
            break pipe;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(process_error(
                "opening retained PostgreSQL signal pipe",
                error,
            ));
        }
    };
    let pipe = unsafe { OwnedHandle::from_raw_handle(raw_pipe.cast()) };
    let mut server_pid = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut server_pid) } == 0
        || server_pid != process_id
    {
        return Err(Error::PgError(
            "PostgreSQL signal pipe did not belong to the retained process".to_owned(),
            String::new(),
        ));
    }
    let mut outbound = signal;
    transfer_one_byte(
        &pipe,
        &mut outbound,
        true,
        deadline,
        "writing retained PostgreSQL signal pipe",
    )?;
    let mut acknowledgement = 0_u8;
    transfer_one_byte(
        &pipe,
        &mut acknowledgement,
        false,
        deadline,
        "reading retained PostgreSQL signal acknowledgement",
    )?;
    if acknowledgement != signal {
        return Err(Error::PgError(
            "retained PostgreSQL signal pipe returned an invalid acknowledgement".to_owned(),
            String::new(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_process_id(process: &std::os::windows::io::OwnedHandle) -> Result<u32> {
    use std::os::windows::io::AsRawHandle;

    let pid = unsafe {
        windows_sys::Win32::System::Threading::GetProcessId(process.as_raw_handle().cast())
    };
    if pid == 0 {
        Err(process_error(
            "reading retained Windows process identifier",
            io::Error::last_os_error(),
        ))
    } else {
        Ok(pid)
    }
}

#[cfg(target_os = "windows")]
fn signal_graceful(inner: &mut ProcessInner) -> Result<()> {
    match inner.kind {
        // PostgreSQL's Windows port accepts the same fast-shutdown SIGINT used
        // by pg_ctl through a per-process named pipe. We authenticate the pipe
        // server against the retained hProcess before sending one byte.
        ProcessKind::Postgres => send_windows_postgres_signal(inner, 2),
        ProcessKind::Utility => signal_force_tree(inner),
    }
}

#[cfg(target_os = "windows")]
fn signal_force_tree(inner: &mut ProcessInner) -> Result<()> {
    terminate_windows_job_handle(&inner.job)
        .map_err(|error| process_error("force-terminating retained Windows job", error))
}

#[cfg(target_os = "windows")]
fn windows_file_identity(file: &File) -> Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0 {
        return Err(process_error(
            "reading retained Windows file identity",
            io::Error::last_os_error(),
        ));
    }
    Ok((
        information.dwVolumeSerialNumber,
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("pg-embed exact process-tree lifecycle supports Linux, macOS, and Windows only");

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn wait_for_report(path: &Path) -> Vec<u32> {
        let started = Instant::now();
        loop {
            if let Ok(content) = std::fs::read_to_string(path) {
                let pids: Vec<u32> = content
                    .lines()
                    .filter_map(|line| line.trim().parse().ok())
                    .collect();
                if pids.len() == 2 {
                    return pids;
                }
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "process-tree helper did not report its PIDs"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    fn pid_is_absent(pid: u32) -> bool {
        if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
            return false;
        }
        io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    #[cfg(unix)]
    fn assert_pids_disappear(pids: &[u32]) {
        let started = Instant::now();
        while pids.iter().any(|pid| !pid_is_absent(*pid)) {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "retained process-tree member survived termination: {pids:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    fn spawn_shell_tree(report: &Path) -> PostgresProcess {
        PostgresProcess::spawn_path(
            Path::new("/bin/sh"),
            [
                OsString::from("-c"),
                OsString::from(
                    "printf '%s\\n' \"$$\" > \"$1\"; sleep 60 & \
                     printf '%s\\n' \"$!\" >> \"$1\"; wait",
                ),
                OsString::from("pg-embed-tree-test"),
                report.as_os_str().to_os_string(),
            ],
            None,
            ProcessKind::Utility,
        )
        .expect("spawn retained shell tree")
    }

    #[cfg(unix)]
    fn spawn_shell_with_orphaned_descendant(report: &Path) -> PostgresProcess {
        PostgresProcess::spawn_path(
            Path::new("/bin/sh"),
            [
                OsString::from("-c"),
                OsString::from(
                    "printf '%s\\n' \"$$\" > \"$1\"; sleep 60 & \
                     printf '%s\\n' \"$!\" >> \"$1\"; exit 0",
                ),
                OsString::from("pg-embed-orphan-tree-test"),
                report.as_os_str().to_os_string(),
            ],
            None,
            ProcessKind::Utility,
        )
        .expect("spawn retained shell with orphaned descendant")
    }

    #[cfg(unix)]
    fn wait_for_payload_exit(process: &PostgresProcess) {
        let started = Instant::now();
        loop {
            let mut inner = process.inner.lock().expect("process mutex");
            refresh_payload_exit(&mut inner).expect("observe direct payload exit");
            let payload_exited = inner.payload_exit.is_some();
            drop(inner);
            if payload_exited {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "direct payload did not exit"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_terminates_descendants_not_only_the_leader() {
        let directory = tempfile::tempdir().expect("temp dir");
        let report = directory.path().join("pids");
        let process = spawn_shell_tree(&report);
        let pids = wait_for_report(&report);
        process
            .terminate(Some(Duration::from_millis(100)))
            .expect("terminate complete retained tree");
        assert_pids_disappear(&pids);
    }

    #[cfg(unix)]
    #[test]
    fn payload_leader_exit_does_not_release_descendant_tree() {
        let directory = tempfile::tempdir().expect("temp dir");
        let report = directory.path().join("pids");
        let process = spawn_shell_with_orphaned_descendant(&report);
        let pids = wait_for_report(&report);
        wait_for_payload_exit(&process);
        assert!(
            !process
                .has_exited()
                .expect("observe descendant-containing tree"),
            "payload leader exit released a live descendant"
        );
        process
            .terminate_force()
            .expect("terminate descendant after payload leader exit");
        assert_pids_disappear(&pids);
    }

    #[cfg(unix)]
    #[test]
    fn parent_death_helper() {
        let Some(report) = std::env::var_os("PG_EMBED_PARENT_DEATH_REPORT") else {
            return;
        };
        let process = spawn_shell_tree(Path::new(&report));
        let _ = wait_for_report(Path::new(&report));
        std::mem::forget(process);
        // Model abrupt host loss: no Rust destructor or atexit handler runs.
        unsafe {
            libc::_exit(0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn abrupt_embedding_process_death_terminates_the_tree() {
        let directory = tempfile::tempdir().expect("temp dir");
        let report = directory.path().join("pids");
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("parent_death_helper")
            .arg("--nocapture")
            .env("PG_EMBED_PARENT_DEATH_REPORT", &report)
            .status()
            .expect("run abrupt-parent helper");
        assert!(status.success());
        assert_pids_disappear(&wait_for_report(&report));
    }

    #[cfg(unix)]
    #[test]
    fn parent_death_after_payload_exit_helper() {
        let Some(report) = std::env::var_os("PG_EMBED_PARENT_DEATH_AFTER_PAYLOAD_REPORT") else {
            return;
        };
        let process = spawn_shell_with_orphaned_descendant(Path::new(&report));
        let _ = wait_for_report(Path::new(&report));
        wait_for_payload_exit(&process);
        std::mem::forget(process);
        unsafe {
            libc::_exit(0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn abrupt_parent_death_after_payload_exit_terminates_descendants() {
        let directory = tempfile::tempdir().expect("temp dir");
        let report = directory.path().join("pids");
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("parent_death_after_payload_exit_helper")
            .arg("--nocapture")
            .env("PG_EMBED_PARENT_DEATH_AFTER_PAYLOAD_REPORT", &report)
            .status()
            .expect("run post-payload abrupt-parent helper");
        assert!(status.success());
        assert_pids_disappear(&wait_for_report(&report));
    }

    #[cfg(target_os = "windows")]
    fn windows_command_processor() -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join("cmd.exe")
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_hanging_postgres_pipe_helper() {
        const HELPER_NAME: &str = "pg-embed-hanging-pipe-helper.exe";

        let executable = std::env::current_exe().expect("helper executable path");
        let is_helper_copy = executable
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(HELPER_NAME));
        if !is_helper_copy {
            return;
        }
        let report = executable
            .parent()
            .expect("helper executable parent")
            .join("pipe-state");

        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

        use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{PIPE_ACCESS_DUPLEX, ReadFile};
        use windows_sys::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;

        let pid = unsafe { GetCurrentProcessId() };
        let pipe_name = format!(r"\\.\pipe\pgsignal_{pid}");
        let pipe_name: Vec<u16> = OsStr::new(&pipe_name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let raw_pipe = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                1,
                1,
                0,
                std::ptr::null(),
            )
        };
        assert!(
            raw_pipe != INVALID_HANDLE_VALUE && !raw_pipe.is_null(),
            "create same-PID PostgreSQL signal pipe: {}",
            io::Error::last_os_error()
        );
        let pipe = unsafe { OwnedHandle::from_raw_handle(raw_pipe.cast()) };
        std::fs::write(&report, format!("ready:{pid}")).expect("report hanging pipe readiness");

        let connected =
            unsafe { ConnectNamedPipe(pipe.as_raw_handle().cast(), std::ptr::null_mut()) };
        if connected == 0 {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(ERROR_PIPE_CONNECTED as i32),
                "connect same-PID PostgreSQL signal pipe"
            );
        }
        let mut signal = 0_u8;
        let mut read = 0_u32;
        assert_ne!(
            unsafe {
                ReadFile(
                    pipe.as_raw_handle().cast(),
                    (&mut signal as *mut u8).cast(),
                    1,
                    &mut read,
                    std::ptr::null_mut(),
                )
            },
            0,
            "read PostgreSQL signal byte: {}",
            io::Error::last_os_error()
        );
        assert_eq!(read, 1);
        std::fs::write(&report, format!("received:{pid}"))
            .expect("report received PostgreSQL signal");

        // Deliberately never acknowledge the signal. The parent must time out
        // this authenticated pipe read and force the retained Job.
        std::thread::sleep(Duration::from_secs(60));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn unresponsive_authenticated_postgres_pipe_cannot_block_job_fallback() {
        const HELPER_NAME: &str = "pg-embed-hanging-pipe-helper.exe";

        let directory = tempfile::tempdir().expect("temp dir");
        let report = directory.path().join("pipe-state");
        let executable = directory.path().join(HELPER_NAME);
        std::fs::copy(
            std::env::current_exe().expect("test executable"),
            &executable,
        )
        .expect("copy isolated hanging-pipe test executable");
        let process = PostgresProcess::spawn_path(
            &executable,
            [
                "process::tests::windows_hanging_postgres_pipe_helper",
                "--exact",
                "--nocapture",
            ],
            None,
            ProcessKind::Postgres,
        )
        .expect("spawn same-PID hanging-pipe helper in retained Job");
        let expected_ready = format!("ready:{}", process.pid());
        let started = Instant::now();
        loop {
            if std::fs::read_to_string(&report).is_ok_and(|state| state == expected_ready) {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "same-PID hanging-pipe helper did not become ready"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        let terminate_started = Instant::now();
        process
            .terminate(Some(Duration::from_secs(10)))
            .expect("bounded pipe timeout must reach Job force-fallback");
        assert!(
            terminate_started.elapsed() < Duration::from_secs(3),
            "the one-second authenticated-pipe deadline did not reach Job force-fallback"
        );
        let expected_received = format!("received:{}", process.pid());
        assert_eq!(
            std::fs::read_to_string(&report).expect("read final hanging-pipe helper state"),
            expected_received
        );
        assert!(process.has_exited().expect("confirm empty retained Job"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn suspended_windows_launch_is_job_assigned_then_resumed() {
        let process = PostgresProcess::spawn_path(
            &windows_command_processor(),
            ["/D", "/C", "exit", "0"],
            None,
            ProcessKind::Utility,
        )
        .expect("create suspended process, assign its Job, and resume retained hThread");
        let exit = process
            .wait(Some(Duration::from_secs(5)))
            .expect("wait for retained Windows Job")
            .expect("process tree exited");
        assert!(exit.success());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_leader_exit_does_not_release_descendant_job() {
        use std::os::windows::io::AsRawHandle;

        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        let process = PostgresProcess::spawn_path(
            &windows_command_processor(),
            ["/D", "/S", "/C", r#"start "" /B ping -t 127.0.0.1"#],
            None,
            ProcessKind::Utility,
        )
        .expect("spawn leader with descendant");
        let started = Instant::now();
        loop {
            let inner = process.inner.lock().expect("process mutex");
            let leader_exited =
                unsafe { WaitForSingleObject(inner.process.as_raw_handle().cast(), 0) }
                    == WAIT_OBJECT_0;
            let active = windows_job_active_processes(&inner.job).expect("query Job");
            drop(inner);
            if leader_exited && active > 0 {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "cmd leader did not leave a live descendant in its retained Job"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!process.has_exited().expect("observe complete Job"));
        process
            .terminate_force()
            .expect("terminate descendant-containing Job");
        assert!(process.has_exited().expect("confirm empty Job"));
    }
}
