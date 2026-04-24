package main

import (
	"context"
	"encoding/hex"
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
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/storage"
)

func main() {
	ctx := context.Background()

	dbCfg, err := config.LoadDBConfig()
	if err != nil {
		log.Fatalf("DB config: %v", err)
	}
	// dbCfg.Source is a categorical SourceKind constant ("file", "env",
	// "embedded") — never an operator-controlled string — so logging it
	// cannot leak the password or the secret-file path.
	log.Printf("DB password source: %s", dbCfg.Source)
	if dbCfg.Source == config.SourceEmbedded || dbCfg.Source == config.SourceEnv {
		log.Printf("WARNING: DB password is supplied via environment variable; " +
			"prefer SEQUENCER_DB_PASSWORD_FILE pointing at a 0600 secret file " +
			"(env vars are visible via /proc/<pid>/environ and `docker inspect`).")
	}

	httpAddr := os.Getenv("SEQUENCER_HTTP_ADDR")
	apiToken := os.Getenv("SEQUENCER_API_TOKEN")
	if apiToken == "" {
		log.Fatalf("SEQUENCER_API_TOKEN is required")
	}
	if len(apiToken) < 32 {
		log.Fatalf("SEQUENCER_API_TOKEN must be at least 32 bytes")
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

	// Create sequencer service
	sequencer := api.NewSequencer(smtClient, store, apiToken)

	// Startup replay: restore in-memory SMT from persisted leaves before
	// accepting traffic, so proof and root queries are consistent from the
	// first request.
	leaves, err := store.GetLeaves(ctx)
	if err != nil {
		log.Fatalf("Failed to load leaves for startup replay: %v", err)
	}
	pbLeaves := make([]*pb.LeafEntry, len(leaves))
	for i, l := range leaves {
		pbLeaves[i] = &pb.LeafEntry{
			Key:       l.Key,
			ValueHash: l.ValueHash,
		}
	}
	replayResp, err := smtClient.ReplayLeaves(ctx, pbLeaves)
	if err != nil {
		log.Fatalf("Startup replay failed: %v", err)
	}
	log.Printf("Startup replay complete: replayed %d leaves, root_hash=%s",
		len(leaves), hex.EncodeToString(replayResp.RootHash))

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
