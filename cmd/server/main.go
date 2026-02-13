package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/rcoop/dns-exfil/server"
)

func main() {
	domain := flag.String("domain", "", "Base domain for DNS queries (required)")
	encKey := flag.String("encryption-key", "", "Encryption passphrase (required)")
	outputDir := flag.String("output-dir", ".", "Directory to write received files")
	listen := flag.String("listen", ":53", "Address to listen on (e.g. :53, 127.0.0.1:5353)")
	sessionTimeout := flag.Duration("session-timeout", 5*time.Minute, "Session inactivity timeout")
	flag.Parse()

	if *domain == "" || *encKey == "" {
		fmt.Fprintln(os.Stderr, "Usage: server --domain <domain> --encryption-key <key> --output-dir <dir>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("creating output dir: %v", err)
	}

	store := server.NewSessionStore(*sessionTimeout)
	done := make(chan struct{})
	store.StartCleanup(30*time.Second, done)

	handler := &server.Handler{
		BaseDomain: *domain,
		Store:      store,
		Assembler: &server.Assembler{
			EncryptionKey: *encKey,
			OutputDir:     *outputDir,
		},
	}

	srv := &dns.Server{
		Addr:    *listen,
		Net:     "udp",
		Handler: handler,
	}

	go func() {
		log.Printf("DNS server listening on %s (domain: %s)", *listen, *domain)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	close(done)
	srv.Shutdown()
}
