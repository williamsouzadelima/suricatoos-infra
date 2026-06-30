package correlation

import (
	"reflect"
	"testing"
)

func TestUpstreamVersion(t *testing.T) {
	cases := map[string]string{
		"1:3.0.2-0ubuntu1.10": "3.0.2",  // epoch + debian revision
		"8.9p1-3":             "8.9p1",  // openssh upstream keeps pN
		"3.0.7-18.el9":        "3.0.7",  // rpm release
		"2.38-3ubuntu1":       "2.38",   // glibc
		"1.1.1f-1ubuntu2.22":  "1.1.1f", // openssl letter suffix
		"2.4.52+dfsg1-1":      "2.4.52", // debian +dfsg
		"5.15.0-117.127":      "5.15.0", // kernel
		"9.16.1~beta-1":       "9.16.1", // tilde pre-release
		"":                    "",
	}
	for in, want := range cases {
		if got := upstreamVersion(in); got != want {
			t.Errorf("upstreamVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLookupCPEProduct(t *testing.T) {
	cases := map[string]string{
		"openssl":                        "openssl:openssl",
		"OpenSSL":                        "openssl:openssl", // case-insensitive
		"openssh-server":                 "openbsd:openssh",
		"libssl3":                        "openssl:openssl",
		"linux-image-5.15.0-117-generic": "linux:linux_kernel", // prefix rule
		"python3.11":                     "python:python",      // prefix rule
		"some-random-lib":                "",                   // unmapped
	}
	for in, want := range cases {
		if got := lookupCPEProduct(in); got != want {
			t.Errorf("lookupCPEProduct(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGenerateCPEs(t *testing.T) {
	inv := Inventory{
		Packages: []Package{
			{Name: "openssl", Version: "1:3.0.2-0ubuntu1.10"},
			{Name: "libssl3", Version: "3.0.2-0ubuntu1.10"}, // same CPE as openssl -> dedup
			{Name: "openssh-server", Version: "8.9p1-3"},
			{Name: "linux-image-5.15.0-117-generic", Version: "5.15.0-117.127"},
			{Name: "some-random-lib", Version: "1.0"}, // skipped (unmapped)
		},
	}
	got := GenerateCPEs(inv)
	want := []string{
		"cpe:/a:openbsd:openssh:8.9p1",
		"cpe:/a:openssl:openssl:3.0.2",
		"cpe:/o:linux:linux_kernel:5.15.0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GenerateCPEs() = %v, want %v", got, want)
	}
}
