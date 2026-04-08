package client

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/local"

	pb "github.com/wombatvagina69-crypto/olympus/services/sequencer/proto"
)

type testCdhsSmfService struct {
	pb.UnimplementedCdhsSmfServiceServer
}

func (testCdhsSmfService) GetRoot(context.Context, *pb.GetRootRequest) (*pb.GetRootResponse, error) {
	return &pb.GetRootResponse{
		Root:     []byte{1, 2, 3, 4},
		TreeSize: 7,
	}, nil
}

func TestNewCdhsSmfClientConnectsOverUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "cdhs-smf.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	server := grpc.NewServer(grpc.Creds(local.NewCredentials()))
	pb.RegisterCdhsSmfServiceServer(server, testCdhsSmfService{})
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		select {
		case err := <-serverErr:
			if err != nil && err != grpc.ErrServerStopped {
				t.Fatalf("serve unix socket: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for gRPC server shutdown")
		}
	})

	t.Setenv("CDHS_SMF_SOCKET", socketPath)

	client, err := NewCdhsSmfClient()
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetRoot(ctx)
	if err != nil {
		t.Fatalf("get root over unix socket: %v", err)
	}
	if want := []byte{1, 2, 3, 4}; !slices.Equal(resp.Root, want) {
		t.Fatalf("root = %v, want %v", resp.Root, []byte{1, 2, 3, 4})
	}
	if resp.TreeSize != 7 {
		t.Fatalf("tree_size = %d, want 7", resp.TreeSize)
	}
}
