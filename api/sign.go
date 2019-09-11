// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package api

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/yahoo/crypki"
)

// SigningService implements proto.SigningServer interface.
type SigningService struct {
	crypki.CertSign
	KeyUsages   map[string]map[string]bool
	MaxValidity map[string]uint64
}

// recoverIfPanicked recovers from panic and logs the error.
func recoverIfPanicked(method string) {
	if r := recover(); r != nil {
		log.Printf("%s: recovered from panic", method)
		var err error
		if _, ok := r.(error); ok {
			err = r.(error)
		} else if _, ok := r.(string); ok {
			err = errors.New(r.(string))
		} else {
			panic(r)
		}
		log.Printf("%s: error recovered was: %v", method, err)
	}
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
