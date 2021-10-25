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
package scheduler

import (
	"fmt"
	"sync"
	"testing"
)

func TestCounter(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		count     Counter
		operation func(count Counter) uint32
		want      uint32
	}{
		"get empty counter": {
			operation: func(count Counter) uint32 {
				return count.Get()
			},
			want: 0,
		},
		"inc counter": {
			operation: func(count Counter) uint32 {
				count.Inc()
				count.Inc()
				return count.Get()
			},
			want: 2,
		},
		"inc & reset counter": {
			operation: func(count Counter) uint32 {
				count.Inc()
				count.Inc()
				count.Reset()
				count.Inc()
				return count.Get()
			},
			want: 1,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := tt.operation(tt.count)
			if got != tt.want {
				t.Errorf("%s: expected %d, got %d", name, tt.want, got)
			}
		})
	}
}

func TestCounterMultipleGoRoutines(t *testing.T) {
	t.Parallel()
	var totalCount Counter
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		totalCount.Inc()
		totalCount.Reset()
		totalCount.Inc()
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		for i := 1; i < 100; i++ {
			totalCount.Inc()
		}
		wg.Done()
	}()
	wg.Wait()
	fmt.Printf("count: %d\n", totalCount.Get())
	if totalCount.Get() == 0 {
		t.Errorf("count not incremented correctly, got 0")
	}
}
