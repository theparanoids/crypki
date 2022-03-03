// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package api

import (
	"fmt"
	"time"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/server/scheduler"
)

// SigningService implements proto.SigningServer interface.
type SigningService struct {
	crypki.CertSign
	KeyUsages      map[string]map[string]bool
	MaxValidity    map[string]uint64
	RequestChan    map[string]chan scheduler.Request
	RequestTimeout map[string]uint
	proto.UnimplementedSigningServer
}

// timeElapsedSince returns time elapsed since start time in microseconds.
func timeElapsedSince(start time.Time) int64 {
	return time.Since(start).Nanoseconds() / time.Microsecond.Nanoseconds()
}

// checkValidity checks whether the requested `validity` is less than
// maximum allowed validity.
// Note that validity and maxValidity values are in seconds.
func checkValidity(validity uint64, maxValidity uint64) error {
	if validity <= 0 {
		return fmt.Errorf("missing or bad validity: %d", validity)
	}
	if maxValidity != 0 && maxValidity < validity {
		return fmt.Errorf("requested validity %v is greater than maximum allowed validity %v", validity, maxValidity)
	}
	return nil
}
