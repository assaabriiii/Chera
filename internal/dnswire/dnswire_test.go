package dnswire

import (
	"errors"
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		qtype uint16
		rcode int
		addrs []string
		want  []string
	}{
		{"a", TypeA, RCodeSuccess, []string{"140.82.121.4", "140.82.121.3"}, []string{"140.82.121.4", "140.82.121.3"}},
		{"aaaa filters v4", TypeAAAA, RCodeSuccess, []string{"1.2.3.4", "2606:4700::1"}, []string{"2606:4700::1"}},
		{"nxdomain", TypeA, RCodeNXDomain, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := Query(0x1234, "github.com.", tt.qtype)
			if err != nil {
				t.Fatal(err)
			}
			question, err := ParseQuestion(q)
			if err != nil {
				t.Fatal(err)
			}
			if question.Name != "github.com" || question.Type != tt.qtype || question.ID != 0x1234 {
				t.Fatalf("question = %+v", question)
			}
			var addrs []netip.Addr
			for _, a := range tt.addrs {
				addrs = append(addrs, netip.MustParseAddr(a))
			}
			ans, err := Answer(question, tt.rcode, addrs)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := Parse(ans)
			if err != nil {
				t.Fatal(err)
			}
			if resp.ID != 0x1234 || resp.RCode != tt.rcode || resp.Question.Name != "github.com" {
				t.Fatalf("resp = %+v", resp)
			}
			if len(resp.Addrs) != len(tt.want) {
				t.Fatalf("addrs = %v, want %v", resp.Addrs, tt.want)
			}
			for i, w := range tt.want {
				if resp.Addrs[i].String() != w {
					t.Fatalf("addr %d = %s, want %s", i, resp.Addrs[i], w)
				}
			}
		})
	}
}

func TestQueryErrors(t *testing.T) {
	for _, name := range []string{"", "a..b", string(make([]byte, 64)) + ".com"} {
		if _, err := Query(1, name, TypeA); err == nil {
			t.Errorf("Query(%q) should fail", name)
		}
	}
}

func TestParseMalformed(t *testing.T) {
	good, _ := Answer(Question{ID: 1, Name: "a.com", Type: TypeA}, 0, []netip.Addr{netip.MustParseAddr("1.2.3.4")})
	tests := map[string][]byte{
		"short":     {0, 1, 2},
		"truncated": good[:len(good)-2],
		"query":     mustQuery(t),
		"loop":      append([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}, 0xc0, 12),
	}
	for name, msg := range tests {
		if _, err := Parse(msg); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func mustQuery(t *testing.T) []byte {
	q, err := Query(1, "a.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func FuzzParse(f *testing.F) {
	good, _ := Answer(Question{ID: 1, Name: "a.com", Type: TypeA}, 0, []netip.Addr{netip.MustParseAddr("1.2.3.4")})
	f.Add(good)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Parse(b)
		_, _ = ParseQuestion(b)
	})
}
