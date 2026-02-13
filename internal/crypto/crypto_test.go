package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	passphrase := "test-passphrase-123"
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}

	if len(salt) != SaltLen {
		t.Fatalf("salt length: got %d, want %d", len(salt), SaltLen)
	}

	key := DeriveKey(passphrase, salt)
	if len(key) != KeyLen {
		t.Fatalf("key length: got %d, want %d", len(key), KeyLen)
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Ciphertext should be nonce + plaintext + GCM tag.
	if len(ciphertext) <= len(plaintext) {
		t.Fatalf("ciphertext too short: %d bytes", len(ciphertext))
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed:\n  original:  %x\n  decrypted: %x", plaintext, decrypted)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	salt, _ := GenerateSalt()
	key1 := DeriveKey("password1", salt)
	key2 := DeriveKey("password2", salt)

	ciphertext, err := Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(key2, ciphertext)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt := []byte("1234567890123456") // 16 bytes
	key1 := DeriveKey("passphrase", salt)
	key2 := DeriveKey("passphrase", salt)

	if !bytes.Equal(key1, key2) {
		t.Error("same passphrase+salt should produce same key")
	}
}
