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

import "sync/atomic"

type Counter int32

func (c *Counter) Get() int32 {
	return atomic.LoadInt32((*int32)(c))
}
func (c *Counter) Inc() int32 {
	return atomic.AddInt32((*int32)(c), 1)
}
func (c *Counter) Reset() int32 {
	return atomic.SwapInt32((*int32)(c), 0)
}
