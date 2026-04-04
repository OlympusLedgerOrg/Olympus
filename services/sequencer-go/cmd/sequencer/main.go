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
	smtAddr := os.Getenv("SEQUENCER_SMT_ADDR")
	httpAddr := os.Getenv("SEQUENCER_HTTP_ADDR")
	apiToken := os.Getenv("SEQUENCER_API_TOKEN")
	if dbURL == "" {
		log.Fatalf("SEQUENCER_DB_URL is required")
	}
	if smtAddr == "" {
		log.Fatalf("SEQUENCER_SMT_ADDR is required")
	}
	if apiToken == "" {
		log.Fatalf("SEQUENCER_API_TOKEN is required")
	}
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	// Initialize CD-HS-ST Rust service client
	smtClient, err := client.NewCdhsSmfClient(smtAddr)
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

	log.Printf("Sequencer service starting on %s", httpAddr)
	if err := http.Serve(listener, sequencer.Handler()); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
