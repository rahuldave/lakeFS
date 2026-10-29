package pyramid

import "testing"

func TestValidateFilenameRefusesTraversal(t *testing.T) {
	for _, name := range []string{
		"..", ".", "../x", "a/../../b", "a/./b", "a/..", "/etc/hosts", `a\..\b`, "",
		"../../../../../../../../../../etc/hosts",
	} {
		if validateFilename(name) == nil {
			t.Errorf("validateFilename(%q) accepted a name that leaves the namespace", name)
		}
	}
	for _, name := range []string{"1/2/file1.txt", "file1", "abc123def", "a..b", "x/..y/z"} {
		if err := validateFilename(name); err != nil {
			t.Errorf("validateFilename(%q) = %v, want nil", name, err)
		}
	}
}
