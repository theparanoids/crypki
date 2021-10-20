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
package priority

import (
	"context"
	"testing"
)

func TestPool_Initialize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := map[string]struct {
		nworkers int
		endpoint string
		qSize    int
	}{
		"2 workers": {
			nworkers: 2,
			endpoint: "dummy",
			qSize:    10,
		},
		"10 workers": {
			nworkers: 10,
			endpoint: "/v1/x509-cert",
			qSize:    10,
		},
	}

	for label, tt := range tests {
		tt := tt
		t.Run(label, func(t *testing.T) {
			workerQ := make(chan Worker, tt.nworkers)
			p := &pool{name: tt.endpoint, size: tt.nworkers, queueSize: tt.qSize}
			p.initialize(workerQ)
			p.start(ctx)
			p.stop(ctx)
		})
	}
}
