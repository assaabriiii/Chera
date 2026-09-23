// Package dnswire encodes and decodes the small subset of the DNS wire
// format chera needs: single-question A/AAAA queries and their answers.
// Keeping this in-tree avoids a dependency for a few hundred bytes of
// parsing.
package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Record types and response codes used by chera.
const (
	TypeA    uint16 = 1
	TypeAAAA uint16 = 28
	ClassIN  uint16 = 1

	RCodeSuccess  = 0
	RCodeServFail = 2
	RCodeNXDomain = 3
	RCodeRefused  = 5
)

// ErrMalformed is returned for messages that cannot be parsed.
var ErrMalformed = errors.New("malformed DNS message")

// Query builds a recursive query for name.
func Query(id uint16, name string, qtype uint16) ([]byte, error) {
	msg := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:], 1)      // QDCOUNT
	var err error
	msg, err = appendName(msg, name)
	if err != nil {
		return nil, err
	}
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, ClassIN)
	return msg, nil
}

func appendName(msg []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return nil, fmt.Errorf("invalid DNS name %q", name)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS name %q", name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	return append(msg, 0), nil
}

// Question is the first question of a message.
type Question struct {
	ID    uint16
	Name  string
	Type  uint16
	Class uint16
}

// Response is the decoded part of an answer that chera uses.
type Response struct {
	ID        uint16
	RCode     int
	Truncated bool
	Question  Question
	Addrs     []netip.Addr
}

// Parse decodes a response message.
func Parse(msg []byte) (*Response, error) {
	if len(msg) < 12 {
		return nil, ErrMalformed
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	r := &Response{
		ID:        binary.BigEndian.Uint16(msg[0:]),
		RCode:     int(flags & 0x000f),
		Truncated: flags&0x0200 != 0,
	}
	if flags&0x8000 == 0 {
		return nil, fmt.Errorf("%w: not a response", ErrMalformed)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+4 > len(msg) {
			return nil, ErrMalformed
		}
		if i == 0 {
			r.Question = Question{
				ID:    r.ID,
				Name:  name,
				Type:  binary.BigEndian.Uint16(msg[off:]),
				Class: binary.BigEndian.Uint16(msg[off+2:]),
			}
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		_, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+10 > len(msg) {
			return nil, ErrMalformed
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		class := binary.BigEndian.Uint16(msg[off+2:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, ErrMalformed
		}
		rdata := msg[off : off+rdlen]
		off += rdlen
		if class != ClassIN {
			continue
		}
		switch {
		case typ == TypeA && rdlen == 4:
			r.Addrs = append(r.Addrs, netip.AddrFrom4([4]byte(rdata)))
		case typ == TypeAAAA && rdlen == 16:
			r.Addrs = append(r.Addrs, netip.AddrFrom16([16]byte(rdata)))
		}
	}
	return r, nil
}

// ParseQuestion decodes the header and first question of a query; used by
// the fake servers in tests.
func ParseQuestion(msg []byte) (Question, error) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:]) < 1 {
		return Question{}, ErrMalformed
	}
	name, off, err := readName(msg, 12)
	if err != nil {
		return Question{}, err
	}
	if off+4 > len(msg) {
		return Question{}, ErrMalformed
	}
	return Question{
		ID:    binary.BigEndian.Uint16(msg[0:]),
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[off:]),
		Class: binary.BigEndian.Uint16(msg[off+2:]),
	}, nil
}

// Answer builds a response to q containing addrs that match the question
// type. It is used by fake DNS servers in tests.
func Answer(q Question, rcode int, addrs []netip.Addr) ([]byte, error) {
	msg := make([]byte, 12, 128)
	binary.BigEndian.PutUint16(msg[0:], q.ID)
	binary.BigEndian.PutUint16(msg[2:], 0x8180|uint16(rcode&0xf)) // QR, RD, RA
	binary.BigEndian.PutUint16(msg[4:], 1)
	var err error
	msg, err = appendName(msg, q.Name)
	if err != nil {
		return nil, err
	}
	msg = binary.BigEndian.AppendUint16(msg, q.Type)
	msg = binary.BigEndian.AppendUint16(msg, ClassIN)
	var count uint16
	for _, a := range addrs {
		var rdata []byte
		switch {
		case q.Type == TypeA && a.Is4():
			b := a.As4()
			rdata = b[:]
		case q.Type == TypeAAAA && a.Is6():
			b := a.As16()
			rdata = b[:]
		default:
			continue
		}
		msg = append(msg, 0xc0, 12) // pointer to the question name
		msg = binary.BigEndian.AppendUint16(msg, q.Type)
		msg = binary.BigEndian.AppendUint16(msg, ClassIN)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
		msg = append(msg, rdata...)
		count++
	}
	binary.BigEndian.PutUint16(msg[6:], count)
	return msg, nil
}

// readName reads a possibly compressed name at off and returns it with the
// offset just past it.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for hops := 0; ; hops++ {
		if hops > 64 || off >= len(msg) {
			return "", 0, ErrMalformed
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, ErrMalformed
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
		case l&0xc0 != 0:
			return "", 0, ErrMalformed
		default:
			if off+1+l > len(msg) {
				return "", 0, ErrMalformed
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}
