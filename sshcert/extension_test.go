package sshcert

import "testing"

func TestAddCustomExtensions(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name string
		exts map[string]string
	}{
		{
			"nil map",
			nil,
		},
		{
			"empty map",
			make(map[string]string),
		},
		{
			"map with some entries",
			map[string]string{
				"permit-pty":              "",
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-user-rc":          "",
			},
		},
	}

	requiredKeys := []string{ExtensionCAHost, ExtensionCreationTime}
	for _, tt := range testCases {
		tt := tt // capture range variable - see https://blog.golang.org/subtests
		t.Run(tt.name, func(t *testing.T) {
			exts, err := AddCustomExtensions(tt.exts)
			if err != nil {
				t.Logf("fail to add custom extensions: %v", err)
				return
			}
			for _, k := range requiredKeys {
				if _, ok := exts[k]; !ok {
					t.Fatalf("custom extension not added: %s", k)
				}
			}
		})
	}
}
