package commands

import "testing"

func TestNormaliseDomain(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain apex", "example.com", "example.com", false},
		{"subdomain", "api.example.com", "api.example.com", false},
		{"uppercase", "EXAMPLE.com", "example.com", false},
		{"surrounding space", "  example.com  ", "example.com", false},
		{"trailing dot", "example.com.", "example.com", false},
		{"https scheme", "https://example.com", "example.com", false},
		{"http scheme", "http://example.com", "example.com", false},
		{"scheme + path", "https://example.com/foo/bar", "example.com", false},
		{"scheme + path + query", "https://example.com/foo?x=1", "example.com", false},
		{"host with port", "example.com:8443", "example.com", false},
		{"scheme + port", "https://example.com:8443", "example.com", false},
		{"multi-label tld", "example.co.uk", "example.co.uk", false},
		{"long subdomain chain", "a.b.c.d.example.com", "a.b.c.d.example.com", false},
		{"hyphen in label", "my-site.example.com", "my-site.example.com", false},

		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"single label", "localhost", "", true},
		{"ipv4", "192.168.1.1", "", true},
		{"underscore", "foo_bar.example.com", "", true},
		{"leading dot", ".example.com", "", true},
		{"trailing hyphen in label", "foo-.example.com", "", true},
		{"label too long", longLabel(70) + ".example.com", "", true},
		{"label exactly 63 ok", longLabel(63) + ".example.com", longLabel(63) + ".example.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normaliseDomain(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normaliseDomain(%q) returned %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normaliseDomain(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("normaliseDomain(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func longLabel(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
