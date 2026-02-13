package server

import (
	//nolint:gosec // MD5 used as a non-security checksum for file integrity
	"crypto/md5"
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/rcoop/dns-exfil/internal/crypto"
)

// Assembler handles the final reassembly, decryption, and writing of a file.
type Assembler struct {
	EncryptionKey string
	OutputDir     string
}

// Assemble concatenates chunks, decrypts, verifies MD5, and writes the file.
func (a *Assembler) Assemble(session *Session, expectedMD5 []byte) error {
	ciphertext := session.Reassemble()

	key := crypto.DeriveKey(a.EncryptionKey, session.Salt)

	plaintext, err := crypto.Decrypt(key, ciphertext)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	//nolint:gosec // MD5 used as a non-security checksum
	hash := md5.Sum(plaintext)
	if !bytes.Equal(hash[:], expectedMD5) {
		return fmt.Errorf("MD5 mismatch: got %x, expected %x", hash[:], expectedMD5)
	}

	// Sanitize filename to prevent path traversal.
	safeName := filepath.Base(session.Filename)
	outPath := filepath.Join(a.OutputDir, safeName)

	if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}

	log.Printf("[%s] File written: %s (%d bytes)", session.ID, outPath, len(plaintext))
	return nil
}
