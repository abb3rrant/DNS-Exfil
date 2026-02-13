package protocol

import (
	"bytes"
	"testing"
)

func TestCalcChunkSize(t *testing.T) {
	// A reasonable base domain should yield a positive chunk size.
	size := CalcChunkSize("exfil.example.com")
	if size <= 0 {
		t.Fatalf("expected positive chunk size, got %d", size)
	}
	t.Logf("chunk size for exfil.example.com: %d bytes", size)

	// A very long domain should yield 0.
	longDomain := "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z." +
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z." +
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z." +
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z"
	size = CalcChunkSize(longDomain)
	if size != 0 {
		t.Fatalf("expected 0 for very long domain, got %d", size)
	}
}

func TestBuildParseInit(t *testing.T) {
	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	filename := "secret.txt"
	baseDomain := "exfil.example.com"

	query := BuildInitQuery("abcd1234", 42, salt, filename, baseDomain)
	t.Logf("init query: %s", query)

	msg, err := ParseQuery(query, baseDomain)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	init, ok := msg.(*InitMessage)
	if !ok {
		t.Fatalf("expected *InitMessage, got %T", msg)
	}

	if init.SessionID != "abcd1234" {
		t.Errorf("session ID: got %q, want %q", init.SessionID, "abcd1234")
	}
	if init.Total != 42 {
		t.Errorf("total: got %d, want %d", init.Total, 42)
	}
	if !bytes.Equal(init.Salt, salt) {
		t.Errorf("salt: got %x, want %x", init.Salt, salt)
	}
	if init.Filename != filename {
		t.Errorf("filename: got %q, want %q", init.Filename, filename)
	}
}

func TestBuildParseData(t *testing.T) {
	data := []byte("hello world, this is some test data for chunking!")
	baseDomain := "exfil.example.com"

	query := BuildDataQuery("abcd1234", 5, 10, data, baseDomain)
	t.Logf("data query: %s (len=%d)", query, len(query))

	// Verify total length is within DNS limits.
	if len(query) > MaxDomainLen {
		t.Errorf("query too long: %d > %d", len(query), MaxDomainLen)
	}

	msg, err := ParseQuery(query, baseDomain)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	d, ok := msg.(*DataMessage)
	if !ok {
		t.Fatalf("expected *DataMessage, got %T", msg)
	}

	if d.SessionID != "abcd1234" {
		t.Errorf("session ID: got %q", d.SessionID)
	}
	if d.Seq != 5 {
		t.Errorf("seq: got %d, want 5", d.Seq)
	}
	if d.Total != 10 {
		t.Errorf("total: got %d, want 10", d.Total)
	}
	if !bytes.Equal(d.Data, data) {
		t.Errorf("data round-trip failed:\n  original: %x\n  decoded:  %x", data, d.Data)
	}
}

func TestBuildParseFin(t *testing.T) {
	md5 := []byte{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
		0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e}
	baseDomain := "exfil.example.com"

	query := BuildFinQuery("abcd1234", 42, md5, baseDomain)
	t.Logf("fin query: %s", query)

	msg, err := ParseQuery(query, baseDomain)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	fin, ok := msg.(*FinMessage)
	if !ok {
		t.Fatalf("expected *FinMessage, got %T", msg)
	}

	if fin.SessionID != "abcd1234" {
		t.Errorf("session ID: got %q", fin.SessionID)
	}
	if fin.Total != 42 {
		t.Errorf("total: got %d, want 42", fin.Total)
	}
	if !bytes.Equal(fin.MD5, md5) {
		t.Errorf("md5: got %x, want %x", fin.MD5, md5)
	}
}

func TestParseQueryBadDomain(t *testing.T) {
	_, err := ParseQuery("i.abc.0.1.data.wrong.com", "exfil.example.com")
	if err == nil {
		t.Error("expected error for mismatched domain")
	}
}
