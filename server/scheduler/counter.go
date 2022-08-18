// Copyright 2021 Yahoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package scheduler

import "sync/atomic"

type Counter uint32

func (c *Counter) Get() uint32 {
	return atomic.LoadUint32((*uint32)(c))
}
func (c *Counter) Inc() uint32 {
	return atomic.AddUint32((*uint32)(c), 1)
}
func (c *Counter) Reset() uint32 {
	return atomic.SwapUint32((*uint32)(c), 0)
}
