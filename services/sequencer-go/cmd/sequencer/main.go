package main

import (
	"context"
	"log"
	"net"
	"net/http"

	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/api"
	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/client"
	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/storage"
)

func main() {
	ctx := context.Background()

	// Initialize CD-HS-SMF Rust service client
	smtClient, err := client.NewCdhsSmfClient("localhost:50051")
	if err != nil {
		log.Fatalf("Failed to create SMT client: %v", err)
	}
	defer smtClient.Close()

	// Initialize storage (Postgres)
	store, err := storage.NewPostgresStorage(ctx, "postgresql://olympus:olympus@localhost:5432/olympus")
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// Create sequencer service
	sequencer := api.NewSequencer(smtClient, store)

	// Start HTTP/gRPC server
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("Sequencer service starting on :8080")
	if err := http.Serve(listener, sequencer.Handler()); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
