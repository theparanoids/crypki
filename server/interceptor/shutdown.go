// Copyright 2021 Yahoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package interceptor

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
)

// ShutdownCounterConfig configures the behavior of ShutdownCounter.
type ShutdownCounterConfig struct {
	ReportOnly            bool
	ConsecutiveCountLimit int32
	TimeRangeCountLimit   int32
	TickerDuration        time.Duration

	// The function is provided by users to shutdown the server. This function is
	// guaranteed to run only once.
	ShutdownFn func()
}

// ShutdownCounter provides an interceptor function that can be used with
// StatusInterceptor to shutdown the server when the criteria meet.
type ShutdownCounter struct {
	config ShutdownCounterConfig

	// consecutiveCounter keeps track of the number of consecutive failures with
	// Internal grpc code.
	consecutiveCounter int32

	// timeRangeCounter counts the number of failures with Internal grpc code in
	// the most recent 1 minutes.
	timeRangeCounter int32

	// once ensures that the shutdown function only runs once.
	once sync.Once
}

func (c *ShutdownCounter) shutdown() {
	c.once.Do(func() {
		if c.config.ShutdownFn != nil {
			c.config.ShutdownFn()
		}
	})
}

func (c *ShutdownCounter) startTicker(ctx context.Context) {
	timer := time.NewTicker(c.config.TickerDuration)
	for {
		select {
		case <-ctx.Done():
			timer.Stop()
			return

		case <-timer.C:
			if c.timeRangeCounter >= c.config.TimeRangeCountLimit {
				log.Printf("the number of internal failures %d reaches configured limit %d in %s",
					c.timeRangeCounter, c.config.TimeRangeCountLimit, c.config.TickerDuration)

				if c.config.ReportOnly {
					log.Printf("ShutdownCounter: report only")
				} else {
					log.Printf("ShutdownCounter: shutting down server")
					go c.shutdown()
					timer.Stop()
					return
				}
			}
			// reset counter
			atomic.StoreInt32(&c.timeRangeCounter, 0)
		}
	}
}

// InterceptorFn is intended to be used to create a StatusInterceptor to
// monitor service status and shutdown the server when the criteria meet.
//
// 		shutdownCounterConfig := interceptor.ShutdownCounterConfig{
//			ReportOnly:            true,
//			ConsecutiveCountLimit: 4,
//			TimeRangeCountLimit:   10,
//			TickerDuration:        60 * time.Second,
//			ShutdownFn: func() {
//				grpcServer.GracefulStop()
//				if err := server.Shutdown(ctx); err != nil {
//					log.Fatalf("failed to shutdown server: %v", err)
//				}
//			},
//		}
//		interceptors = []grpc.UnaryServerInterceptor{
//			interceptor.StatusInterceptor((interceptor.NewShutdownCounter(ctx, shutdownCounterConfig)).InterceptorFn),
//		}
func (c *ShutdownCounter) InterceptorFn(code codes.Code) {
	if code == codes.Internal {
		atomic.AddInt32(&c.consecutiveCounter, 1)
		atomic.AddInt32(&c.timeRangeCounter, 1)
	} else {
		// reset counter
		atomic.StoreInt32(&c.consecutiveCounter, 0)
	}
	if c.consecutiveCounter >= c.config.ConsecutiveCountLimit {
		log.Printf("the number of consecutive internal failures %d reaches configured limit %d",
			c.consecutiveCounter, c.config.ConsecutiveCountLimit)

		if c.config.ReportOnly {
			log.Printf("ShutdownCounter: report only")
		} else {
			log.Printf("ShutdownCounter: shutting down server")
			go c.shutdown()
		}
	}
}

// NewShutdownCounter returns a ShutdownCounter.
func NewShutdownCounter(ctx context.Context, config ShutdownCounterConfig) *ShutdownCounter {
	counter := &ShutdownCounter{
		config: config,
	}
	go counter.startTicker(ctx)
	return counter
}
