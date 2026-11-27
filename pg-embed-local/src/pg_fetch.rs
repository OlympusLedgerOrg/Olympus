//! Download PostgreSQL binaries from Maven Central.
//!
//! The [`PgFetchSettings`] struct describes *which* binary to fetch (OS,
//! architecture, version) and exposes [`PgFetchSettings::fetch_postgres`] to
//! perform the actual HTTP download.  The downloaded bytes are a JAR file
//! (ZIP) that is later unpacked by [`crate::pg_unpack`].

use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::pg_enums::{Architecture, OperationSystem};
use crate::pg_errors::Error;
use crate::pg_errors::Result;

/// A PostgreSQL version string in `MAJOR.MINOR.PATCH` form.
///
/// Olympus's verified acquisition path currently accepts [`PG_V15`]. Other
/// constants remain for API compatibility but fail closed until their target
/// archives have source-pinned digests.
#[derive(Debug, Copy, Clone)]
pub struct PostgresVersion(pub &'static str);

/// PostgreSQL 18.2.0 binaries.
pub const PG_V18: PostgresVersion = PostgresVersion("18.2.0");
/// PostgreSQL 17.8.0 binaries.
pub const PG_V17: PostgresVersion = PostgresVersion("17.8.0");
/// PostgreSQL 16.12.0 binaries.
pub const PG_V16: PostgresVersion = PostgresVersion("16.12.0");
/// PostgreSQL 15.16.0 binaries.
pub const PG_V15: PostgresVersion = PostgresVersion("15.16.0");
/// PostgreSQL 14.21.0 binaries.
pub const PG_V14: PostgresVersion = PostgresVersion("14.21.0");
/// PostgreSQL 13.23.0 binaries.
pub const PG_V13: PostgresVersion = PostgresVersion("13.23.0");
/// PostgreSQL 12.22.0 binaries.
pub const PG_V12: PostgresVersion = PostgresVersion("12.22.0");
/// PostgreSQL 11.22.1 binaries.
pub const PG_V11: PostgresVersion = PostgresVersion("11.22.1");
/// PostgreSQL 10.23.0 binaries.
pub const PG_V10: PostgresVersion = PostgresVersion("10.23.0");

// Maven Central SHA-256 sidecars for the exact PostgreSQL package shipped by
// Olympus. Adding a version or release target is a reviewable source change:
// fetch its immutable `.jar.sha256`, independently hash the JAR, and extend
// this table in the same commit.
const PG_V15_LINUX_AMD64_SHA256: &str =
    "ebc352db047343fe4b0d5182beec1e49bad3239cb30eb4c896d7a785d77c325c";
const PG_V15_WINDOWS_AMD64_SHA256: &str =
    "66ca2635edbbbe798a6c514b9a8a23e01b2cb6ca26ad87052c05f3dd4741e2e8";
const PG_V15_DARWIN_AMD64_SHA256: &str =
    "600b3c07a268d8f5b24b175cc4bd0dbdc875ac9d9dbff8740f86164923f402e3";
const PG_V15_DARWIN_ARM64V8_SHA256: &str =
    "e26068293bdd21dcee5771c813248deee8271c7b6eb01768647d40b85c7c95c5";

/// HTTP statuses worth retrying: rate limiting, request timeout, the transient
/// 5xx family, and `404 Not Found`.
///
/// A 404 is normally permanent — the requested release has no build for this
/// platform — but `repo1.maven.org` also serves spurious 404s for paths it
/// answers with 200 minutes later: the `vendored pg_embed unit tests` job lost a
/// run to exactly that on 2026-11-27, and the same URL downloaded fine on a
/// rerun. Retrying it is bounded by [`DOWNLOAD_ATTEMPTS`], so a release that is
/// genuinely absent still fails in about a minute instead of hanging.
///
/// 401/403 stay permanent: the mirror rejected the request and will keep
/// rejecting it, so those fail on the first response instead of spending the
/// retry budget.
///
/// Retries also exist because a cold binary cache is fetched from Maven Central,
/// which answers a burst of CI runners with `429 Too Many Requests`: the
/// `api_db` job lost a run to exactly that on 2026-11-27 while the package
/// itself was fine, and the embedded-Postgres cache only hides the download
/// until its key changes.
fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 404 | 408 | 429 | 500 | 502 | 503 | 504)
}

/// Attempts per download, including the first one.
///
/// Six attempts at the backoff below wait at most ~60 s in total, which is
/// noise beside the 20-minute cap the `api_db` job puts on the whole step.
const DOWNLOAD_ATTEMPTS: u32 = 6;

/// First retry delay; doubles per failure.
const RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

/// Ceiling for a single wait, including a server-supplied `Retry-After`.
const RETRY_MAX_DELAY: Duration = Duration::from_secs(60);

/// Delay before the next attempt after `attempt` failures.
///
/// `Retry-After` wins when present in its delta-seconds form (the HTTP-date
/// form falls back to backoff — parsing dates for a retry hint is not worth a
/// dependency). Either way the wait is capped by [`RETRY_MAX_DELAY`], so a
/// mirror asking for an hour cannot stall the caller.
fn retry_delay(attempt: u32, retry_after: Option<&reqwest::header::HeaderValue>) -> Duration {
    let server_hint = retry_after
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    if let Some(hint) = server_hint {
        return hint.min(RETRY_MAX_DELAY);
    }
    RETRY_BASE_DELAY
        .saturating_mul(1 << attempt.saturating_sub(1))
        .min(RETRY_MAX_DELAY)
}

/// Settings that determine which PostgreSQL binary package to download.
///
/// Construct with [`Default::default`] and override individual fields as
/// needed:
///
/// ```rust
/// use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
///
/// let settings = PgFetchSettings {
///     version: PG_V15,
///     ..Default::default()
/// };
/// ```
///
/// The default target OS and architecture are detected at compile time via
/// `#[cfg(target_os)]` / `#[cfg(target_arch)]`.
#[derive(Debug, Clone)]
pub struct PgFetchSettings {
    /// Base URL of the Maven repository hosting the binaries.
    ///
    /// Defaults to `https://repo1.maven.org`.  Override to point at a local
    /// mirror or artifact proxy.
    pub host: String,
    /// Target operating system.  Determines the package classifier used in the
    /// Maven artifact name.
    pub operating_system: OperationSystem,
    /// Target CPU architecture.  Combined with [`Self::operating_system`] to
    /// form the Maven classifier.
    pub architecture: Architecture,
    /// PostgreSQL version to download.  Use one of the `PG_Vxx` constants.
    pub version: PostgresVersion,
}

impl Default for PgFetchSettings {
    fn default() -> Self {
        PgFetchSettings {
            host: "https://repo1.maven.org".to_string(),
            operating_system: OperationSystem::default(),
            architecture: Architecture::default(),
            version: PG_V15,
        }
    }
}

impl PgFetchSettings {
    /// Returns the Maven classifier string for this OS/architecture
    /// combination.
    ///
    /// The classifier is the middle segment of the artifact name, e.g.
    /// `linux-amd64` or `darwin-amd64`.  For Alpine Linux the architecture
    /// gets an `-alpine` suffix instead of a separate OS segment.
    ///
    /// # Returns
    ///
    /// A `String` of the form `{os}-{arch}` (or `{os}-{arch}-alpine` for
    /// [`OperationSystem::AlpineLinux`]).
    pub fn platform(&self) -> String {
        let os = self.operating_system.to_string();
        let arch = if self.operating_system == OperationSystem::AlpineLinux {
            format!("{}-alpine", self.architecture)
        } else {
            self.architecture.to_string()
        };
        format!("{}-{}", os, arch)
    }

    /// Return the repository-pinned SHA-256 for this exact package.
    ///
    /// Unknown versions and platform combinations fail closed before any
    /// network request. Olympus currently releases PG 15.16.0 packages for
    /// Windows x64, Linux x64, macOS Intel, and macOS Apple Silicon.
    pub(crate) fn expected_sha256(&self) -> Result<&'static str> {
        let digest = match (self.version.0, self.operating_system, self.architecture) {
            ("15.16.0", OperationSystem::Linux, Architecture::Amd64) => PG_V15_LINUX_AMD64_SHA256,
            ("15.16.0", OperationSystem::Windows, Architecture::Amd64) => {
                PG_V15_WINDOWS_AMD64_SHA256
            }
            ("15.16.0", OperationSystem::Darwin, Architecture::Amd64) => PG_V15_DARWIN_AMD64_SHA256,
            ("15.16.0", OperationSystem::Darwin, Architecture::Arm64v8) => {
                PG_V15_DARWIN_ARM64V8_SHA256
            }
            _ => {
                return Err(Error::UnpinnedPgPackage(format!(
                    "PostgreSQL {} for {}",
                    self.version.0,
                    self.platform()
                )));
            }
        };
        Ok(digest)
    }

    fn verify_digest(&self, digest: &[u8]) -> Result<()> {
        let expected = self.expected_sha256()?;
        let actual = hex::encode(digest);
        if actual != expected {
            return Err(Error::PgPackageDigestMismatch {
                expected: expected.to_owned(),
                actual,
            });
        }
        Ok(())
    }

    /// Initiates an HTTP GET for the Maven artifact and checks the response
    /// status.
    ///
    /// Constructs the full artifact URL from [`Self::host`],
    /// [`Self::platform`], and [`Self::version`] and issues the request.
    /// The caller streams the response body.
    ///
    /// # Retries
    ///
    /// Transient failures are retried — see [`is_retryable_status`] and
    /// [`retry_delay`] — so a rate-limited or briefly unavailable mirror does
    /// not fail an otherwise healthy build. The final attempt's error is what
    /// the caller sees, and every attempt after the first logs a warning with
    /// the status and the wait, so a retried run leaves a trace in CI.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DownloadFailure`] if every attempt fails, or on the
    /// first response whose status is permanent (e.g. 410 when the requested
    /// PostgreSQL version was removed from the mirror).
    async fn start_download(&self) -> Result<reqwest::Response> {
        let platform = self.platform();
        let version = self.version.0;
        let download_url = format!(
            "{}/maven2/io/zonky/test/postgres/embedded-postgres-binaries-{}/{}/\
             embedded-postgres-binaries-{}-{}.jar",
            &self.host, &platform, version, &platform, version
        );

        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match reqwest::get(&download_url).await {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let status = response.status();
                    let failure = Error::DownloadFailure(format!(
                        "HTTP {status} fetching PostgreSQL {version} for platform '{platform}'. This \
                         version may not be available for the current OS/architecture. Note: \
                         darwin-arm64v8 (Apple Silicon) only has binaries for PG 14 and newer.",
                    ));
                    if !is_retryable_status(status) || attempt >= DOWNLOAD_ATTEMPTS {
                        return Err(failure);
                    }
                    let delay = retry_delay(
                        attempt,
                        response.headers().get(reqwest::header::RETRY_AFTER),
                    );
                    log::warn!(
                        "PostgreSQL download attempt {attempt}/{DOWNLOAD_ATTEMPTS} failed with \
                         HTTP {status}; retrying in {delay:?}"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(err) => {
                    let failure = Error::DownloadFailure(err.to_string());
                    if attempt >= DOWNLOAD_ATTEMPTS {
                        return Err(failure);
                    }
                    let delay = retry_delay(attempt, None);
                    log::warn!(
                        "PostgreSQL download attempt {attempt}/{DOWNLOAD_ATTEMPTS} failed \
                         ({err}); retrying in {delay:?}"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Downloads the PostgreSQL binaries JAR from Maven Central.
    ///
    /// Constructs the full artifact URL from [`Self::host`],
    /// [`Self::platform`], and [`Self::version`], performs an HTTP GET, and
    /// returns the raw bytes of the JAR file.  The caller is responsible
    /// for persisting and unpacking the
    /// data (see [`crate::pg_unpack::unpack_postgres`]).
    ///
    /// Prefer [`Self::fetch_postgres_to_file`] when the bytes will be written
    /// to disk — it streams directly without buffering the entire archive in
    /// memory.
    ///
    /// # Returns
    ///
    /// The raw bytes of the downloaded JAR on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DownloadFailure`] if the HTTP request fails or the
    /// server returns a non-2xx status after the bounded retries (e.g. 404
    /// when the requested PostgreSQL version is not available for the current
    /// platform).
    /// Returns [`Error::ConversionFailure`] if reading the response body fails.
    pub async fn fetch_postgres(&self) -> Result<Vec<u8>> {
        self.expected_sha256()?;
        let response = self.start_download().await?;
        let content = response
            .bytes()
            .await
            .map_err(|e| Error::ConversionFailure(e.to_string()))?;

        log::debug!("Downloaded {} bytes", content.len());
        log::trace!(
            "First 1024 bytes: {:?}",
            &String::from_utf8_lossy(&content[..content.len().min(1024)])
        );

        self.verify_digest(&Sha256::digest(&content))?;

        Ok(content.to_vec())
    }

    /// Downloads the PostgreSQL binaries JAR and streams it directly to
    /// `zip_path`.
    ///
    /// Unlike [`Self::fetch_postgres`], this method never loads the full
    /// archive into memory — each HTTP chunk is written to the file as it
    /// arrives. Use this method when you intend to write the JAR to disk
    /// (as [`crate::pg_access::PgAccess`] does), since it avoids a 100–200
    /// MB in-memory buffer.
    ///
    /// # Arguments
    ///
    /// * `zip_path` — Destination file path for the downloaded JAR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DownloadFailure`] if the HTTP request fails or the
    /// server returns a non-2xx status.
    /// Returns [`Error::WriteFileError`] if the file cannot be created or a
    /// chunk cannot be written.
    /// Returns [`Error::ConversionFailure`] if reading a response chunk fails.
    pub(crate) async fn fetch_postgres_to_file(&self, zip_path: &Path) -> Result<()> {
        self.expected_sha256()?;
        let mut response = self.start_download().await?;
        let mut file = tokio::fs::File::create(zip_path)
            .await
            .map_err(|e| Error::WriteFileError(e.to_string()))?;
        let mut total = 0u64;
        let mut hasher = Sha256::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::ConversionFailure(e.to_string()))?
        {
            file.write_all(&chunk)
                .await
                .map_err(|e| Error::WriteFileError(e.to_string()))?;
            hasher.update(&chunk);
            total += chunk.len() as u64;
        }
        file.sync_data()
            .await
            .map_err(|e| Error::WriteFileError(e.to_string()))?;
        drop(file);

        if let Err(err) = self.verify_digest(&hasher.finalize()) {
            let _ = tokio::fs::remove_file(zip_path).await;
            return Err(err);
        }
        log::debug!("Downloaded and wrote {} bytes to disk", total);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_postgres() -> Result<()> {
        let pg_settings = PgFetchSettings::default();
        let content = pg_settings.fetch_postgres().await?;
        assert!(
            !content.is_empty(),
            "downloaded content should not be empty"
        );
        Ok(())
    }

    #[test]
    fn release_package_digests_are_pinned_per_target() {
        let cases = [
            (
                OperationSystem::Linux,
                Architecture::Amd64,
                PG_V15_LINUX_AMD64_SHA256,
            ),
            (
                OperationSystem::Windows,
                Architecture::Amd64,
                PG_V15_WINDOWS_AMD64_SHA256,
            ),
            (
                OperationSystem::Darwin,
                Architecture::Amd64,
                PG_V15_DARWIN_AMD64_SHA256,
            ),
            (
                OperationSystem::Darwin,
                Architecture::Arm64v8,
                PG_V15_DARWIN_ARM64V8_SHA256,
            ),
        ];

        for (operating_system, architecture, expected) in cases {
            let settings = PgFetchSettings {
                operating_system,
                architecture,
                version: PG_V15,
                ..Default::default()
            };
            assert_eq!(settings.expected_sha256().unwrap(), expected);
        }
    }

    #[test]
    fn transient_download_statuses_are_retried_and_permanent_ones_are_not() {
        // 404 is retried because Maven Central serves spurious 404s for
        // artifacts it answers with 200 moments later; the attempt cap, not the
        // status class, bounds a genuinely missing release.
        for status in [404, 408, 429, 500, 502, 503, 504] {
            let status = reqwest::StatusCode::from_u16(status).unwrap();
            assert!(is_retryable_status(status), "{status} must be retried");
        }
        // Rejections and definitive removals are permanent.
        for status in [400, 401, 403, 410, 501] {
            let status = reqwest::StatusCode::from_u16(status).unwrap();
            assert!(!is_retryable_status(status), "{status} must fail fast");
        }
    }

    #[test]
    fn retry_delay_backs_off_caps_and_honours_retry_after() {
        assert_eq!(retry_delay(1, None), Duration::from_secs(2));
        assert_eq!(retry_delay(2, None), Duration::from_secs(4));
        assert_eq!(retry_delay(3, None), Duration::from_secs(8));
        assert_eq!(retry_delay(4, None), Duration::from_secs(16));
        assert_eq!(retry_delay(5, None), Duration::from_secs(32));
        // Doubling would reach 64 s here; the ceiling wins.
        assert_eq!(retry_delay(6, None), RETRY_MAX_DELAY);

        let hint = reqwest::header::HeaderValue::from_static("7");
        assert_eq!(retry_delay(1, Some(&hint)), Duration::from_secs(7));

        // A mirror asking for a day must not stall the caller.
        let huge = reqwest::header::HeaderValue::from_static("86400");
        assert_eq!(retry_delay(1, Some(&huge)), RETRY_MAX_DELAY);

        // The HTTP-date form is not parsed; the backoff applies instead.
        let date = reqwest::header::HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT");
        assert_eq!(retry_delay(2, Some(&date)), Duration::from_secs(4));
    }

    #[test]
    fn unpinned_version_and_platform_fail_closed() {
        let unpinned_version = PgFetchSettings {
            version: PG_V17,
            ..Default::default()
        };
        assert!(matches!(
            unpinned_version.expected_sha256(),
            Err(Error::UnpinnedPgPackage(_))
        ));

        let unpinned_platform = PgFetchSettings {
            operating_system: OperationSystem::Linux,
            architecture: Architecture::Arm64v8,
            version: PG_V15,
            ..Default::default()
        };
        assert!(matches!(
            unpinned_platform.expected_sha256(),
            Err(Error::UnpinnedPgPackage(_))
        ));
    }

    #[test]
    fn package_digest_mismatch_is_rejected() {
        let settings = PgFetchSettings {
            operating_system: OperationSystem::Linux,
            architecture: Architecture::Amd64,
            version: PG_V15,
            ..Default::default()
        };
        let err = settings
            .verify_digest(&Sha256::digest(b"attacker-controlled archive"))
            .unwrap_err();
        assert!(matches!(err, Error::PgPackageDigestMismatch { .. }));
    }

    /// Verify that every Olympus release-target package can actually be
    /// downloaded and matches the source-pinned SHA-256.
    ///
    /// Each target is fetched in full and the byte count is printed. This test
    /// is marked `#[ignore]` because it performs network downloads.
    ///
    /// ```text
    /// cargo test --features rt_tokio -- --ignored pinned_targets_downloadable --nocapture
    /// ```
    #[tokio::test]
    #[ignore]
    async fn pinned_targets_downloadable() -> Result<()> {
        let targets = [
            ("linux-amd64", OperationSystem::Linux, Architecture::Amd64),
            (
                "windows-amd64",
                OperationSystem::Windows,
                Architecture::Amd64,
            ),
            ("darwin-amd64", OperationSystem::Darwin, Architecture::Amd64),
            (
                "darwin-arm64v8",
                OperationSystem::Darwin,
                Architecture::Arm64v8,
            ),
        ];

        for (name, operating_system, architecture) in targets {
            let settings = PgFetchSettings {
                operating_system,
                architecture,
                version: PG_V15,
                ..Default::default()
            };
            let bytes = settings.fetch_postgres().await?;
            println!("{name}: {} bytes (SHA-256 verified)", bytes.len());
        }
        Ok(())
    }
}
