//! Generic async facade over the exact process-tree runner.
//!
//! The public traits and types remain source-compatible with pg-embed 1.0,
//! while every spawned utility is now owned by the same cancellation-safe tree
//! capability used for PostgreSQL itself.

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::marker;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::pg_access::VerifiedExecutable;
use crate::process::{PostgresProcess, ProcessKind};

/// Indicates whether a log line came from stdout or stderr.
#[derive(Debug)]
pub enum LogType {
    /// Standard output line.
    Info,
    /// Standard error line.
    Error,
}

/// Maps a process type to the status values and errors it should produce.
pub trait ProcessStatus<T, E>
where
    E: Error + Send,
    Self: Send,
{
    fn status_entry(&self) -> T;
    fn status_exit(&self) -> T;
    fn error_type(&self) -> E;

    fn timeout_error(&self) -> E {
        self.error_type()
    }

    fn wrap_error<F: Error + Sync + Send + 'static>(&self, error: F, message: Option<String>) -> E;
}

/// A retained public compatibility type for consumers that format captured
/// output. Exact-tree utilities intentionally inherit no writable output
/// stream from the embedding application.
#[derive(Debug)]
#[allow(dead_code)]
pub struct LogOutputData {
    line: String,
    log_type: LogType,
}

/// Trait for types that can spawn and execute an OS process asynchronously.
#[allow(async_fn_in_trait)]
pub trait AsyncCommand<S, E, P>
where
    E: Error + Send,
    P: ProcessStatus<S, E> + Send,
    Self: Sized,
{
    fn new<A, B>(executable_path: &OsStr, args: A, process_type: P) -> Result<Self, E>
    where
        A: IntoIterator<Item = B>,
        B: AsRef<OsStr>;

    async fn execute(&mut self, timeout: Option<Duration>) -> Result<S, E>;
}

/// A one-shot process executor backed by an exact whole-tree capability.
pub struct AsyncCommandExecutor<S, E, P>
where
    S: Send,
    E: Error + Send,
    P: ProcessStatus<S, E>,
    Self: Send,
{
    process: PostgresProcess,
    process_type: P,
    _marker_s: marker::PhantomData<S>,
    _marker_e: marker::PhantomData<E>,
}

impl<S, E, P> AsyncCommandExecutor<S, E, P>
where
    S: Send,
    E: Error + Send,
    P: ProcessStatus<S, E> + Send,
{
    pub(crate) fn from_verified<A, B>(
        executable: VerifiedExecutable,
        args: A,
        process_type: P,
    ) -> Result<Self, E>
    where
        A: IntoIterator<Item = B>,
        B: AsRef<OsStr>,
    {
        let arguments: Vec<OsString> = args
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string())
            .collect();
        let process =
            PostgresProcess::spawn_verified(executable, &arguments, None, ProcessKind::Utility)
                .map_err(|error| {
                    process_type
                        .wrap_error(error, Some("spawning retained verified utility".to_owned()))
                })?;
        Ok(Self {
            process,
            process_type,
            _marker_s: Default::default(),
            _marker_e: Default::default(),
        })
    }

    async fn wait_for_completion(&mut self, timeout: Option<Duration>) -> Result<S, E> {
        let started = Instant::now();
        loop {
            if self
                .process
                .has_exited()
                .map_err(|error| self.process_type.wrap_error(error, None))?
            {
                let exit = self
                    .process
                    .wait(Some(Duration::ZERO))
                    .map_err(|error| self.process_type.wrap_error(error, None))?
                    .ok_or_else(|| {
                        self.process_type.wrap_error(
                            std::io::Error::other(
                                "process tree reported exit without a retained status",
                            ),
                            None,
                        )
                    })?;
                return if exit.success() {
                    Ok(self.process_type.status_exit())
                } else {
                    Err(self.process_type.wrap_error(
                        std::io::Error::other(format!(
                            "retained utility exited unsuccessfully with code {:?}",
                            exit.code()
                        )),
                        Some("waiting for exact utility tree".to_owned()),
                    ))
                };
            }

            if timeout.is_some_and(|limit| started.elapsed() >= limit) {
                let process = self.process.clone();
                tokio::task::spawn_blocking(move || process.terminate(Some(Duration::ZERO)))
                    .await
                    .map_err(|error| {
                        self.process_type
                            .wrap_error(error, Some("joining exact utility termination".to_owned()))
                    })?
                    .map_err(|error| self.process_type.wrap_error(error, None))?;
                return Err(self.process_type.timeout_error());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl<S, E, P> AsyncCommand<S, E, P> for AsyncCommandExecutor<S, E, P>
where
    S: Send,
    E: Error + Send,
    P: ProcessStatus<S, E> + Send,
{
    fn new<A, B>(executable_path: &OsStr, args: A, process_type: P) -> Result<Self, E>
    where
        A: IntoIterator<Item = B>,
        B: AsRef<OsStr>,
    {
        let arguments: Vec<OsString> = args
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string())
            .collect();
        let process = PostgresProcess::spawn_path(
            Path::new(executable_path),
            &arguments,
            None,
            ProcessKind::Utility,
        )
        .map_err(|error| {
            process_type.wrap_error(error, Some("spawning exact utility tree".to_owned()))
        })?;
        Ok(Self {
            process,
            process_type,
            _marker_s: Default::default(),
            _marker_e: Default::default(),
        })
    }

    async fn execute(&mut self, timeout: Option<Duration>) -> Result<S, E> {
        self.wait_for_completion(timeout).await
    }
}
