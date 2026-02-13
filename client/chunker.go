package client

import (
	//nolint:gosec // MD5 used as a non-security checksum for file integrity
	"crypto/md5"
	"fmt"
	"os"

	"github.com/rcoop/dns-exfil/internal/crypto"
	"github.com/rcoop/dns-exfil/internal/protocol"
)

// ChunkedFile holds the results of reading, encrypting, and chunking a file.
type ChunkedFile struct {
	Filename  string
	Salt      []byte
	MD5       []byte // MD5 of the original plaintext
	Chunks    [][]byte
	ChunkSize int
}

// ChunkFile reads a file, computes its MD5, encrypts it, and splits the
// ciphertext into chunks sized for the given base domain.
func ChunkFile(path, encryptionKey, baseDomain string) (*ChunkedFile, error) {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	//nolint:gosec // MD5 used as a non-security checksum
	hash := md5.Sum(plaintext)

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	key := crypto.DeriveKey(encryptionKey, salt)

	ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	chunkSize := protocol.CalcChunkSize(baseDomain)
	if chunkSize <= 0 {
		return nil, fmt.Errorf("base domain too long, no room for data")
	}

	chunks := splitBytes(ciphertext, chunkSize)

	return &ChunkedFile{
		Filename:  fileBaseName(path),
		Salt:      salt,
		MD5:       hash[:],
		Chunks:    chunks,
		ChunkSize: chunkSize,
	}, nil
}

func splitBytes(data []byte, size int) [][]byte {
	var chunks [][]byte
	for len(data) > 0 {
		end := size
		if end > len(data) {
			end = len(data)
		}
		chunk := make([]byte, end)
		copy(chunk, data[:end])
		chunks = append(chunks, chunk)
		data = data[end:]
	}
	return chunks
}

func fileBaseName(path string) string {
	// Use simple approach: find last separator.
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}
