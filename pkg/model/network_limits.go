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

package model

import (
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

// ValidateBandwidthLimit validates module configuration at both ingestion and compilation.
func ValidateBandwidthLimit(config *configv1.BandwidthLimitSettings) error {
	if config == nil {
		return nil
	}
	if len(config.GetRateLimits()) == 0 || len(config.GetDescriptors()) == 0 {
		return fmt.Errorf("bandwidthLimit requires rateLimits and descriptors")
	}
	for _, limit := range []*uint32{config.MaxDynamicBuckets, config.BufferLimitBytes} {
		if limit != nil && *limit == 0 {
			return fmt.Errorf("bandwidthLimit capacity and buffer limit must be positive")
		}
	}
	entries := make([][]*configv1.BandwidthDescriptorEntry, 0, len(config.GetDescriptors()))
	for i, descriptor := range config.GetDescriptors() {
		rates := descriptor.GetBandwidthLimit()
		if rates.GetUploadBytesPerSecond() == 0 && rates.GetDownloadBytesPerSecond() == 0 {
			return fmt.Errorf(
				"bandwidthLimit.descriptors[%d] requires positive byte rates in at least one direction",
				i,
			)
		}
		for _, rate := range []*uint64{rates.UploadBytesPerSecond, rates.DownloadBytesPerSecond} {
			if rate != nil && *rate == 0 {
				return fmt.Errorf("bandwidthLimit.descriptors[%d] byte rates must be positive when set", i)
			}
		}
		entries = append(entries, descriptor.GetEntries())
	}
	return validateDescriptorLayout("bandwidthLimit", config.GetRateLimits(), entries)
}

// ValidateConnectConcurrencyLimit validates admission configuration at ingestion and compilation.
func ValidateConnectConcurrencyLimit(config *configv1.ConnectConcurrencyLimitSettings) error {
	if config == nil {
		return nil
	}
	if config.MaxDynamicBuckets != nil && *config.MaxDynamicBuckets == 0 {
		return fmt.Errorf("connectConcurrencyLimit.maxDynamicBuckets must be positive")
	}
	entries := make([][]*configv1.BandwidthDescriptorEntry, 0, len(config.GetDescriptors()))
	for i, descriptor := range config.GetDescriptors() {
		if descriptor.GetMaxConcurrentStreams() == 0 {
			return fmt.Errorf("connectConcurrencyLimit.descriptors[%d].maxConcurrentStreams must be positive", i)
		}
		entries = append(entries, descriptor.GetEntries())
	}
	return validateDescriptorLayout("connectConcurrencyLimit", config.GetRateLimits(), entries)
}

func validateDescriptorLayout(
	name string,
	rules []*configv1.BandwidthRateLimit,
	descriptors [][]*configv1.BandwidthDescriptorEntry,
) error {
	if len(rules) == 0 || len(descriptors) == 0 {
		return fmt.Errorf("%s requires rateLimits and descriptors", name)
	}
	groups := make([][]string, 0, len(rules))
	for i, rule := range rules {
		keys, err := bandwidthActionKeys(rule)
		if err != nil {
			return fmt.Errorf("%s.rateLimits[%d]: %w", name, i, err)
		}
		groups = append(groups, keys)
	}
	for i, entries := range descriptors {
		keys := make([]string, 0, len(entries))
		for _, entry := range entries {
			keys = append(keys, entry.GetKey())
		}
		if !slices.ContainsFunc(groups, func(group []string) bool { return slices.Equal(group, keys) }) {
			return fmt.Errorf("%s.descriptors[%d].entries must match an action group's keys in order", name, i)
		}
		for _, previous := range descriptors[:i] {
			if slices.EqualFunc(
				previous,
				entries,
				func(a, b *configv1.BandwidthDescriptorEntry) bool { return proto.Equal(a, b) },
			) {
				return fmt.Errorf("%s.descriptors[%d] duplicates earlier entries", name, i)
			}
		}
	}
	return nil
}

func bandwidthActionKeys(rule *configv1.BandwidthRateLimit) ([]string, error) {
	if len(rule.GetActions()) == 0 {
		return nil, fmt.Errorf("actions must not be empty")
	}
	keys := make([]string, 0, len(rule.GetActions()))
	for i, action := range rule.GetActions() {
		state, fixed := action.GetFilterState(), action.GetGenericKey()
		var key string
		switch {
		case state != nil && fixed == nil && state.GetKey() != "":
			key = state.GetDescriptorKey()
		case fixed != nil && state == nil && fixed.GetDescriptorValue() != "":
			key = fixed.GetDescriptorKey()
		default:
			return nil, fmt.Errorf("actions[%d] requires exactly one nonempty source", i)
		}
		if key == "" || slices.Contains(keys, key) {
			return nil, fmt.Errorf("descriptor keys must be nonempty and unique")
		}
		keys = append(keys, key)
	}
	return keys, nil
}
