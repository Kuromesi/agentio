// Copyright 2026 The Kruise Authors
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
package tokentransform

import "github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"

// Fixed replies, including their bodies, are read-only across requests.
var (
	connectUnsupportedReply = filter.Reply{
		Status: 403, Body: []byte("tokentransform: unsupported for CONNECT"),
	}
	credentialUnavailableReply = filter.Reply{
		Status: 403, Body: []byte("tokentransform: credential unavailable"),
	}
)
