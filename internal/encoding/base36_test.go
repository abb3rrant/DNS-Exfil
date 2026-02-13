package encoding

import (
	"bytes"
	"testing"
)

func TestBase36RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty-ish", []byte{0}},
		{"single byte", []byte{0x42}},
		{"hello", []byte("Hello, World!")},
		{"leading zeros", []byte{0, 0, 0, 1, 2, 3}},
		{"all zeros", []byte{0, 0, 0}},
		{"binary", []byte{0xff, 0x00, 0xab, 0xcd, 0xef}},
		{"256 bytes", make([]byte, 256)},
	}

	// Fill the 256-byte test case with interesting data.
	for i := range tests[len(tests)-1].data {
		tests[len(tests)-1].data[i] = byte(i)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Base36Encode(tt.data)

			// Verify only valid base36 chars.
			for _, c := range encoded {
				if (c < '0' || c > '9') && (c < 'a' || c > 'z') {
					t.Errorf("invalid char in encoded string: %c", c)
				}
			}

			decoded, err := Base36Decode(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}

			if !bytes.Equal(decoded, tt.data) {
				t.Errorf("round-trip failed:\n  original: %x\n  decoded:  %x\n  encoded:  %s",
					tt.data, decoded, encoded)
			}
		})
	}
}

func TestBase36DecodeInvalid(t *testing.T) {
	_, err := Base36Decode("")
	if err == nil {
		t.Error("expected error for empty string")
	}

	_, err = Base36Decode("HELLO")
	if err == nil {
		t.Error("expected error for uppercase chars")
	}
}

func TestSplitIntoLabels(t *testing.T) {
	s := "abcdefghij"
	labels := SplitIntoLabels(s, 3)
	expected := []string{"abc", "def", "ghi", "j"}
	if len(labels) != len(expected) {
		t.Fatalf("expected %d labels, got %d", len(expected), len(labels))
	}
	for i, l := range labels {
		if l != expected[i] {
			t.Errorf("label[%d]: expected %q, got %q", i, expected[i], l)
		}
	}

	// Verify JoinLabels is the inverse.
	joined := JoinLabels(labels)
	if joined != s {
		t.Errorf("JoinLabels: expected %q, got %q", s, joined)
	}
}
