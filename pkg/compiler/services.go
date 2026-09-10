// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compiler

import (
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func newServiceResources(inputs Inputs, gateways krt.Collection[model.Gateway], failures *failureRecorder, options collectionOptions) krt.Collection[model.Resource] {
	clearFailureOnSourceDelete(inputs.Services, failures, "Service")
	return krt.NewCollection(inputs.Services,
		func(ctx krt.HandlerContext, service model.Service) *model.Resource {
			gatewayKey := service.Namespace + "/" + service.Name
			if krt.FetchOne(ctx, gateways, krt.FilterKey(gatewayKey)) == nil {
				gatewayKey = ""
			}
			resource, err := buildWDSService(service, gatewayKey)
			if err != nil {
				failures.record("Service", service.ResourceName(), err)
				return nil
			}
			failures.clear("Service", service.ResourceName())
			return &resource
		}, options("service-resources")...)
}
