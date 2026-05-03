package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	pb "github.com/OlympusLedgerOrg/Olympus/services/sequencer/proto"

	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/api"
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/client"
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/config"
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/metrics"
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/storage"
)

func main() {
	// Self-probe mode for container healthchecks. The distroless/static
	// runtime image has no shell, curl, or wget, so the only reliable way
	// to express a Docker/K8s healthcheck is to exec the binary itself with
	// a flag and exit non-zero on failure.
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		os.Exit(runHealthcheck())
	}

	ctx := context.Background()

	dbCfg, err := config.LoadDBConfig()
	if err != nil {
		log.Fatalf("DB config: %v", err)
	}
	// Don't log dbCfg.Source directly: even though it is a categorical
	// constant ("file" / "env" / "embedded") that cannot itself carry the
	// password, CodeQL's clear-text-logging analyzer conservatively taints
	// any value computed in the same branch that read SEQUENCER_DB_PASSWORD_FILE.
	// The presence/absence of the warning below is enough to tell operators
	// which source is in use.
	if dbCfg.Source == config.SourceEmbedded || dbCfg.Source == config.SourceEnv {
		log.Printf("WARNING: DB password is supplied via environment variable; " +
			"prefer SEQUENCER_DB_PASSWORD_FILE pointing at a 0600 secret file " +
			"(env vars are visible via /proc/<pid>/environ and `docker inspect`).")
	} else {
		log.Printf("DB password loaded from file-backed secret.")
	}

	httpAddr := os.Getenv("SEQUENCER_HTTP_ADDR")
	// OLYMPUS_SEQUENCER_TOKEN is the canonical environment variable name.
	// SEQUENCER_API_TOKEN is retained as a deprecated alias for one release;
	// operators should migrate to OLYMPUS_SEQUENCER_TOKEN.
	apiToken := os.Getenv("OLYMPUS_SEQUENCER_TOKEN")
	if apiToken == "" {
		apiToken = os.Getenv("SEQUENCER_API_TOKEN")
		if apiToken != "" {
			log.Printf("WARNING: SEQUENCER_API_TOKEN is deprecated; " +
				"rename to OLYMPUS_SEQUENCER_TOKEN. " +
				"SEQUENCER_API_TOKEN will be removed in the next release.")
		}
	}
	if apiToken == "" {
		log.Fatalf("OLYMPUS_SEQUENCER_TOKEN (or deprecated SEQUENCER_API_TOKEN) is required")
	}
	if len(apiToken) < 32 {
		log.Fatalf("OLYMPUS_SEQUENCER_TOKEN must be at least 32 bytes")
	}
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	// Initialize CD-HS-ST Rust service client
	smtClient, err := client.NewCdhsSmfClient()
	if err != nil {
		log.Fatalf("Failed to create SMT client: %v", err)
	}
	defer smtClient.Close()

	// Initialize storage (Postgres). Use redactedErr when logging because
	// dbCfg.URL embeds the database password; even though the storage
	// layer's current errors never include the URL, redactedErr is a
	// defense-in-depth scrubber that prevents any future regression from
	// leaking credentials via log lines.
	store, err := storage.NewPostgresStorage(ctx, dbCfg.URL)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %s", redactedErr(err, dbCfg.URL))
	}
	defer store.Close()

	// Create sequencer service. Wire metrics + an explicit
	// storage-commit timeout (H-2). The storage-commit timeout MUST stay
	// strictly less than the Rust prepared-LRU TTL (default 30s); see
	// api.DefaultStorageCommitTimeout for the rationale.
	mreg := metrics.New().WithConstLabels(map[string]string{"service": "sequencer"})
	storageCommitTimeout := api.DefaultStorageCommitTimeout
	if v := os.Getenv("OLYMPUS_SEQUENCER_STORAGE_COMMIT_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("Invalid OLYMPUS_SEQUENCER_STORAGE_COMMIT_TIMEOUT=%q: %v", v, err)
		}
		if d <= 0 {
			log.Fatalf("OLYMPUS_SEQUENCER_STORAGE_COMMIT_TIMEOUT must be positive, got %s", d)
		}
		// Defence in depth: even if an operator overrides the LRU TTL on
		// the Rust side, the Go-side commit budget must still be
		// strictly shorter than the documented default (30s) to maintain
		// the H-2 ordering guarantee. Operators that need to push the
		// LRU TTL higher must coordinate both knobs together.
		const minLRUTTLGuard = 30 * time.Second
		if d >= minLRUTTLGuard {
			log.Fatalf("OLYMPUS_SEQUENCER_STORAGE_COMMIT_TIMEOUT (%s) must be strictly less than the Rust LRU TTL (%s) to ensure Go aborts before the LRU prunes; see services/cdhs-smf-rust/src/prepared.rs::DEFAULT_PREPARED_TTL",
				d, minLRUTTLGuard)
		}
		storageCommitTimeout = d
	}
	sequencer := api.NewSequencer(smtClient, store, apiToken,
		api.WithMetrics(mreg),
		api.WithStorageCommitTimeout(storageCommitTimeout),
	)
	log.Printf("H-2 storage-commit timeout: %s (Rust LRU TTL: 30s)", storageCommitTimeout)

	// Startup replay: restore in-memory SMT from persisted leaves before
	// accepting traffic, so proof and root queries are consistent from the
	// first request.
	leaves, err := store.GetLeaves(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrLegacyLeaves) {
			log.Fatalf("FATAL: %v", err)
		}
		log.Fatalf("Failed to load leaves for startup replay: %v", err)
	}
	pbLeaves := make([]*pb.LeafEntry, len(leaves))
	for i, l := range leaves {
		pbLeaves[i] = &pb.LeafEntry{
			Key:                    l.Key,
			ValueHash:              l.ValueHash,
			ParserId:               l.ParserID,
			CanonicalParserVersion: l.CanonicalParserVersion,
		}
	}
	replayResp, err := smtClient.ReplayLeaves(ctx, pbLeaves)
	if err != nil {
		log.Fatalf("Startup replay failed: %v", err)
	}
	log.Printf("Startup replay complete: replayed %d leaves, root_hash=%s",
		len(leaves), hex.EncodeToString(replayResp.RootHash))

	// H-2 crash-recovery convergence assertion.
	//
	// If the Go process previously crashed *between* a successful
	// Postgres COMMIT (step b) and a successful CommitPreparedUpdate
	// (step c), the prepared transaction expires from the Rust LRU and
	// the live SMT lags durable Postgres state. The deterministic
	// startup-replay above is the recovery mechanism: it re-applies
	// every persisted leaf into the Rust SMT, including any leaves that
	// were durable-but-uncommitted at the prior crash time.
	//
	// To prove that the recovery was complete (and to fail loudly on
	// any silent replay bug or Postgres tampering), we assert that the
	// resulting live root equals the latest signed root in Postgres. If
	// they differ, the live SMT is *not* the same tree the service
	// previously signed, and serving any subsequent proof would be
	// unsafe — abort the boot.
	expectedRoot, expectedSize, latestErr := store.GetLatestRoot(ctx)
	if latestErr != nil {
		log.Fatalf("Startup convergence: failed to query latest signed root: %v", latestErr)
	}
	if expectedSize == 0 {
		// No signed roots durably persisted yet. The replayed tree
		// must therefore also be empty; anything else means leaves
		// exist without their corresponding signed roots, which is a
		// torn-write the operator must investigate.
		if len(leaves) != 0 {
			log.Fatalf("Startup convergence FAILED: replayed %d leaves but cdhs_smf_roots is empty. "+
				"Durable state is inconsistent — refusing to serve.", len(leaves))
		}
		log.Printf("Startup convergence OK: empty database, empty tree")
	} else {
		if uint64(len(leaves)) != expectedSize {
			log.Fatalf("Startup convergence FAILED: replayed %d leaves but latest signed tree_size is %d. "+
				"Durable state is inconsistent — refusing to serve.",
				len(leaves), expectedSize)
		}
		if !bytes.Equal(replayResp.RootHash, expectedRoot) {
			log.Fatalf("Startup convergence FAILED: replayed root_hash=%s but latest signed root_hash=%s. "+
				"The live SMT is not the same tree the service previously signed — refusing to serve.",
				hex.EncodeToString(replayResp.RootHash), hex.EncodeToString(expectedRoot))
		}
		log.Printf("Startup convergence OK: replayed root matches latest signed root at tree_size=%d", expectedSize)
	}

	// Start HTTP/gRPC server
	listener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	tlsCert := os.Getenv("SEQUENCER_TLS_CERT")
	tlsKey := os.Getenv("SEQUENCER_TLS_KEY")

	// Fail fast if exactly one of cert/key is set — this is a dangerous
	// misconfiguration that would silently fall back to plaintext HTTP.
	if (tlsCert == "") != (tlsKey == "") {
		log.Fatalf("Misconfigured TLS: both SEQUENCER_TLS_CERT and SEQUENCER_TLS_KEY must be set, or neither. Got cert=%q, key=%q", tlsCert, tlsKey)
	}

	log.Printf("Sequencer service starting on %s", httpAddr)

	// Build an explicit http.Server with conservative timeouts so a
	// misbehaving or malicious client cannot hold a connection open
	// indefinitely (classic Slowloris). The bare http.Serve / http.ServeTLS
	// helpers leave every timeout at zero, which is unsafe for a
	// public-facing cryptographic state service.
	srv := &http.Server{
		Handler:           sequencer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if tlsCert != "" && tlsKey != "" {
		if err := srv.ServeTLS(listener, tlsCert, tlsKey); err != nil {
			log.Fatalf("TLS server failed: %v", err)
		}
	} else {
		log.Printf("WARNING: TLS is not configured (SEQUENCER_TLS_CERT / SEQUENCER_TLS_KEY not set). " +
			"The X-Sequencer-Token will be transmitted in plaintext. " +
			"Configure TLS or use a TLS-terminating reverse proxy in production.")
		if err := srv.Serve(listener); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}

// insecureLocalTLSConfig returns a TLS config that skips verification.
// Used only by the in-container healthcheck probe against 127.0.0.1; do
// not use for any outbound connection.
func insecureLocalTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // local-loopback healthcheck only
}

// runHealthcheck performs an HTTP GET against /v1/healthz on the local
// listener and returns 0 on a 2xx response, 1 otherwise. Honors
// SEQUENCER_HTTP_ADDR so the probe reaches the same address the server is
// listening on. Defaults to 127.0.0.1:8081 (matches the published port in
// docker-compose.yml).
func runHealthcheck() int {
	addr := os.Getenv("SEQUENCER_HTTP_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: invalid SEQUENCER_HTTP_ADDR %q: %v\n", addr, err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	scheme := "http"
	if os.Getenv("SEQUENCER_TLS_CERT") != "" && os.Getenv("SEQUENCER_TLS_KEY") != "" {
		scheme = "https"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	if scheme == "https" {
		// The server cert is operator-issued; the probe runs inside the
		// container so we trust the loopback target. Skipping verification
		// here is intentional and scoped to the local probe only.
		client.Transport = &http.Transport{
			TLSClientConfig: insecureLocalTLSConfig(),
		}
	}

	url := fmt.Sprintf("%s://%s/v1/healthz", scheme, net.JoinHostPort(host, port))
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: GET %s: %v\n", url, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "healthcheck: GET %s -> %d\n", url, resp.StatusCode)
		return 1
	}
	return 0
}

// redactedErr returns err.Error() with the supplied secret string (and any
// percent-encoded form of its userinfo segment) removed. Used when logging
// errors that may have flowed downstream from a connection string
// containing a password.
func redactedErr(err error, secret string) string {
	msg := err.Error()
	if secret == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, secret, "[REDACTED-DB-URL]")
	// Some libraries log just the userinfo portion (`user:password@host`).
	// Try to match and redact that fragment as well.
	if u, perr := url.Parse(secret); perr == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			msg = strings.ReplaceAll(msg, pw, "[REDACTED]")
		}
	}
	return msg
}
