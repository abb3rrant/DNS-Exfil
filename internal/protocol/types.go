package protocol

import "net"

// Message types — the first label of each DNS query.
const (
	TypeInit = "i"
	TypeData = "d"
	TypeFin  = "f"
)

// Response IPs returned as A record answers.
var (
	IPAck        = net.IPv4(1, 0, 0, 1) // ACK
	IPNack       = net.IPv4(1, 0, 0, 2) // NACK
	IPComplete   = net.IPv4(1, 0, 0, 3) // COMPLETE
	IPIncomplete = net.IPv4(1, 0, 0, 4) // INCOMPLETE
)

// MaxDomainLen is the maximum total domain name length per RFC 1035.
const MaxDomainLen = 253

// MetaOverhead is the byte count consumed by the type, session ID, seq, and
// total labels plus their dots:  "d.SSSSSSSS.NNNNN.NNNNN."
// type(1) + dot(1) + sid(8) + dot(1) + seq(≤5) + dot(1) + total(≤5) + dot(1) = 23
// We round up to 24 for safety.
const MetaOverhead = 24

// InitMessage represents a parsed init query.
type InitMessage struct {
	SessionID string
	Total     int
	Salt      []byte
	Filename  string
}

// DataMessage represents a parsed data query.
type DataMessage struct {
	SessionID string
	Seq       int
	Total     int
	Data      []byte
}

// FinMessage represents a parsed fin query.
type FinMessage struct {
	SessionID string
	Total     int
	MD5       []byte
}
