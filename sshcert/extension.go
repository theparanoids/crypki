// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package sshcert

import (
	"fmt"
	"os"
	"time"
)

// The name of custom extensions
const (
	ExtensionCAHost       = "ca-host@verizonmedia.com"
	ExtensionCreationTime = "creation-time@verizonmedia.com"
)

const timeLayout = "20060102T150405"

// AddCustomExtensions add custom extensions with names having suffix "verizonmedia.com"
func AddCustomExtensions(extensions map[string]string) error {
	if extensions == nil {
		extensions = make(map[string]string)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("unable to extract hostname: %v", err)
	}
	extensions[ExtensionCAHost] = hostname
	extensions[ExtensionCreationTime] = time.Now().Format(timeLayout)
	return nil
}
