package encoding

import (
	"fmt"
	"math/big"
	"strings"
)

const base36Chars = "0123456789abcdefghijklmnopqrstuvwxyz"

// MaxLabelLen is the maximum length of a single DNS label per RFC 1035.
const MaxLabelLen = 63

// Base36Encode encodes arbitrary bytes into a base36 string.
// Leading zero bytes are preserved as leading '0' characters.
func Base36Encode(data []byte) string {
	if len(data) == 0 {
		return "0"
	}

	// Count leading zero bytes — each maps to a '0' prefix.
	var leadingZeros int
	for _, b := range data {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Convert the whole byte slice to a big.Int and encode.
	n := new(big.Int).SetBytes(data)
	if n.Sign() == 0 {
		return strings.Repeat("0", leadingZeros)
	}

	var result []byte
	base := big.NewInt(36)
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		result = append(result, base36Chars[mod.Int64()])
	}

	// Reverse the result (it was built LSB-first).
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return strings.Repeat("0", leadingZeros) + string(result)
}

// Base36Decode decodes a base36 string back to the original bytes.
// Leading '0' characters are restored as leading zero bytes.
func Base36Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("empty base36 string")
	}

	// Count leading '0' chars.
	var leadingZeros int
	for _, c := range s {
		if c != '0' {
			break
		}
		leadingZeros++
	}

	// All zeros → return that many zero bytes.
	if leadingZeros == len(s) {
		return make([]byte, leadingZeros), nil
	}

	n := new(big.Int)
	base := big.NewInt(36)
	for _, c := range s {
		idx := strings.IndexRune(base36Chars, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base36 character: %c", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}

	decoded := n.Bytes() // big-endian, no leading zeros
	result := make([]byte, leadingZeros+len(decoded))
	copy(result[leadingZeros:], decoded)
	return result, nil
}

// SplitIntoLabels splits a string into DNS labels of at most maxLen characters.
func SplitIntoLabels(s string, maxLen int) []string {
	if maxLen <= 0 {
		maxLen = MaxLabelLen
	}
	var labels []string
	for len(s) > 0 {
		end := maxLen
		if end > len(s) {
			end = len(s)
		}
		labels = append(labels, s[:end])
		s = s[end:]
	}
	return labels
}

// JoinLabels joins DNS labels back into a single string.
func JoinLabels(labels []string) string {
	return strings.Join(labels, "")
}
