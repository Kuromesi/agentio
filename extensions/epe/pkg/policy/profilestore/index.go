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
package profilestore

import (
	"slices"
	"sort"

	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

// maxIndexedInValues bounds per-profile bucket fan-out. Requirements above
// the limit remain correct by falling back to a full selector check.
const maxIndexedInValues = 16

type labelBucket struct {
	key   string
	value string
}

type indexRequirement struct {
	key    string
	values []string
}

type profileIndex struct {
	buckets  map[labelBucket][]*securityprofile.Profile
	fallback []*securityprofile.Profile
}

// eligibleRequirements returns positive equality requirements that can safely
// anchor a profile. A match for one of these requirements proves the Pod has
// the indexed key and one of the indexed values. Other operators can match an
// absent key or an unbounded value and must use the fallback scan.
func eligibleRequirements(selector labels.Selector) []indexRequirement {
	requirements, _ := selector.Requirements()
	var eligible []indexRequirement
	for _, requirement := range requirements {
		if requirement.Operator() != selection.Equals &&
			requirement.Operator() != selection.DoubleEquals &&
			requirement.Operator() != selection.In {
			continue
		}
		values := requirement.Values().List()
		if len(values) == 0 || len(values) > maxIndexedInValues {
			continue
		}
		eligible = append(eligible, indexRequirement{key: requirement.Key(), values: values})
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].key != eligible[j].key {
			return eligible[i].key < eligible[j].key
		}
		return slices.Compare(eligible[i].values, eligible[j].values) < 0
	})
	return eligible
}

func buildProfileIndex(sortedProfiles []*securityprofile.Profile) profileIndex {
	requirementsByProfile := make([][]indexRequirement, len(sortedProfiles))
	bucketCounts := make(map[labelBucket]int)
	for i, profile := range sortedProfiles {
		requirements := eligibleRequirements(profile.Selector)
		requirementsByProfile[i] = requirements
		seen := make(map[labelBucket]struct{})
		for _, requirement := range requirements {
			for _, value := range requirement.values {
				seen[labelBucket{key: requirement.key, value: value}] = struct{}{}
			}
		}
		for bucket := range seen {
			bucketCounts[bucket]++
		}
	}

	index := profileIndex{buckets: make(map[labelBucket][]*securityprofile.Profile)}
	for i, profile := range sortedProfiles {
		anchor, ok := selectAnchor(requirementsByProfile[i], bucketCounts)
		if !ok {
			index.fallback = append(index.fallback, profile)
			continue
		}
		for _, value := range anchor.values {
			bucket := labelBucket{key: anchor.key, value: value}
			index.buckets[bucket] = append(index.buckets[bucket], profile)
		}
	}
	return index
}

func selectAnchor(requirements []indexRequirement, bucketCounts map[labelBucket]int) (indexRequirement, bool) {
	if len(requirements) == 0 {
		return indexRequirement{}, false
	}
	anchor := requirements[0]
	for _, requirement := range requirements[1:] {
		if anchorLess(requirement, anchor, bucketCounts) {
			anchor = requirement
		}
	}
	return anchor, true
}

func anchorLess(left, right indexRequirement, bucketCounts map[labelBucket]int) bool {
	leftMax, rightMax := maxBucketCount(left, bucketCounts), maxBucketCount(right, bucketCounts)
	if leftMax != rightMax {
		return leftMax < rightMax
	}
	if len(left.values) != len(right.values) {
		return len(left.values) < len(right.values)
	}
	if left.key != right.key {
		return left.key < right.key
	}
	return slices.Compare(left.values, right.values) < 0
}

func maxBucketCount(requirement indexRequirement, bucketCounts map[labelBucket]int) int {
	maxCount := 0
	for _, value := range requirement.values {
		if count := bucketCounts[labelBucket{key: requirement.key, value: value}]; count > maxCount {
			maxCount = count
		}
	}
	return maxCount
}

// appendMatches filters fallback entries and every bucket hit by podLabels
// with the complete selector before appending them. Each profile has exactly
// one anchor requirement, so a Pod can encounter it in at most one bucket.
func (index profileIndex) appendMatches(
	podLabels map[string]string,
	ls labels.Set,
	matched []*securityprofile.Profile,
) []*securityprofile.Profile {
	for _, profile := range index.fallback {
		if profile.Selector.Matches(ls) {
			matched = append(matched, profile)
		}
	}
	for key, value := range podLabels {
		for _, profile := range index.buckets[labelBucket{key: key, value: value}] {
			if profile.Selector.Matches(ls) {
				matched = append(matched, profile)
			}
		}
	}
	return matched
}
