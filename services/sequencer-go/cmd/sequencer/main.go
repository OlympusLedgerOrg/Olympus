package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/api"
	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/client"
	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/storage"
)

func main() {
	ctx := context.Background()

	dbURL := os.Getenv("SEQUENCER_DB_URL")
	httpAddr := os.Getenv("SEQUENCER_HTTP_ADDR")
	apiToken := os.Getenv("SEQUENCER_API_TOKEN")
	if dbURL == "" {
		log.Fatalf("SEQUENCER_DB_URL is required")
	}
	if apiToken == "" {
		log.Fatalf("SEQUENCER_API_TOKEN is required")
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

	// Initialize storage (Postgres)
	store, err := storage.NewPostgresStorage(ctx, dbURL)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// Create sequencer service
	sequencer := api.NewSequencer(smtClient, store, apiToken)

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

	if tlsCert != "" && tlsKey != "" {
		if err := http.ServeTLS(listener, sequencer.Handler(), tlsCert, tlsKey); err != nil {
			log.Fatalf("TLS server failed: %v", err)
		}
	} else {
		log.Printf("WARNING: TLS is not configured (SEQUENCER_TLS_CERT / SEQUENCER_TLS_KEY not set). " +
			"The X-Sequencer-Token will be transmitted in plaintext. " +
			"Configure TLS or use a TLS-terminating reverse proxy in production.")
		if err := http.Serve(listener, sequencer.Handler()); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}
