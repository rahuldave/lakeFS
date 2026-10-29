package api

import "testing"

func TestHasDotSegment(t *testing.T) {
	cases := map[string]bool{
		"local://acme-data":                           false,
		"local://acme-data/data/abc/def":              false,
		"local:///var/lakefs/data/acme-x/data/a/b":    false,
		"s3://bucket/acme..x/file":                    false,
		"local://acme-x/../globex-y":                  true,
		"local://acme-x/data/../../globex-y/data/a/b": true,
		"local://acme-x/./data":                       true,
		"local://acme-x/%2e%2e/globex-y":              true,
		"local://acme-x/%2E%2e/globex-y":              true,
		"local://acme-x/..":                           true,
		"local://acme-x\\..\\globex-y":                true,
		"local://acme-x/%zz":                          true,
		"s3://bucket/a/%2e/b":                         true,
	}
	for uri, want := range cases {
		if got := hasDotSegment(uri); got != want {
			t.Errorf("hasDotSegment(%q) = %v, want %v", uri, got, want)
		}
	}
}
