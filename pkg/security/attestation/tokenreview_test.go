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

package attestation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"google.golang.org/grpc/metadata"

	"github.com/openkruise/agentio/pkg/model"
)

// countingReviewer builds a TokenReviewer over a fake client that records how many
// TokenReviews reached the API server and answers them from a script.
type countingReviewer struct {
	reviewer *TokenReviewer

	mu    sync.Mutex
	calls int
}

func newCountingReviewer(t *testing.T, authenticate func(token string) authenticationv1.TokenReviewStatus) *countingReviewer {
	t.Helper()
	counter := &countingReviewer{}
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review, ok := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		if !ok {
			return false, nil, nil
		}
		counter.mu.Lock()
		counter.calls++
		counter.mu.Unlock()
		return true, &authenticationv1.TokenReview{Status: authenticate(review.Spec.Token)}, nil
	})
	reviewer, err := NewTokenReviewer(client, "cluster.local", []string{"istio-ca"})
	if err != nil {
		t.Fatal(err)
	}
	counter.reviewer = reviewer
	return counter
}

func (c *countingReviewer) reviews() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func bearerContext(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
}

func authenticatedAs(username string) authenticationv1.TokenReviewStatus {
	return authenticationv1.TokenReviewStatus{
		Authenticated: true,
		User: authenticationv1.UserInfo{
			Username: username,
			Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			Extra: map[string]authenticationv1.ExtraValue{
				podNameExtra: {"client-pod"},
				podUIDExtra:  {"pod-uid"},
			},
		},
	}
}

func TestAuthenticateMissingBearerIsUnsupported(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		t.Fatal("TokenReview called without a Kubernetes Bearer credential")
		return authenticationv1.TokenReviewStatus{}
	})

	_, err := counter.reviewer.Authenticate(context.Background())
	if !errors.Is(err, ErrUnsupportedCredentials) {
		t.Fatalf("Authenticate() error = %v, want ErrUnsupportedCredentials", err)
	}
	if got := counter.reviews(); got != 0 {
		t.Fatalf("TokenReviews = %d, want 0", got)
	}
}

func TestAuthenticateRejectedBearerIsHardFailure(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticationv1.TokenReviewStatus{Authenticated: false, Error: "rejected"}
	})

	_, err := counter.reviewer.Authenticate(bearerContext("not-a-kubernetes-token"))
	if err == nil {
		t.Fatal("Authenticate() accepted a rejected Kubernetes Bearer credential")
	}
	if errors.Is(err, ErrUnsupportedCredentials) {
		t.Fatalf("Authenticate() error = %v, want a hard rejection", err)
	}
	if got := counter.reviews(); got != 1 {
		t.Fatalf("TokenReviews = %d, want 1", got)
	}
}

func TestAuthenticateRejectsUsernameWithoutServiceAccountGroup(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1.UserInfo{
				Username: "system:serviceaccount:demo:app",
				Groups:   []string{"system:authenticated", "system:serviceaccounts:demo"},
			},
		}
	})

	if _, err := counter.reviewer.Authenticate(bearerContext("not-a-service-account-token")); err == nil {
		t.Fatal("Authenticate accepted a TokenReview without system:serviceaccounts group")
	}
	if got := counter.reviews(); got != 1 {
		t.Fatalf("TokenReviews = %d, want 1", got)
	}
	if _, err := counter.reviewer.Authenticate(bearerContext("not-a-service-account-token")); err == nil {
		t.Fatal("Authenticate cached a TokenReview without system:serviceaccounts group")
	}
	if got := counter.reviews(); got != 2 {
		t.Fatalf("TokenReviews after retry = %d, want 2", got)
	}
}

// A repeated token presentation is answered from cache.
func TestAuthenticateCachesSuccessfulReviews(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("system:serviceaccount:demo:app")
	})

	for range 5 {
		caller, err := counter.reviewer.Authenticate(bearerContext("a-token"))
		if err != nil {
			t.Fatal(err)
		}
		if caller.Principal.ServiceAccount.Namespace != "demo" || caller.Principal.ServiceAccount.ServiceAccount != "app" {
			t.Fatalf("principal = %+v", caller.Principal)
		}
		if caller.AttestedBy != model.AttestationKubernetes || caller.Kubernetes.WorkloadName != "client-pod" || caller.Kubernetes.WorkloadUID != "pod-uid" {
			t.Fatalf("bound pod identity lost through the cache: %+v", caller)
		}
	}
	if got := counter.reviews(); got != 1 {
		t.Fatalf("TokenReviews = %d, want 1", got)
	}
}

// Distinct tokens are distinct cache entries: one client's review must never
// answer for another's token.
func TestAuthenticateDoesNotShareEntriesBetweenTokens(t *testing.T) {
	counter := newCountingReviewer(t, func(token string) authenticationv1.TokenReviewStatus {
		if token == "token-a" {
			return authenticatedAs("system:serviceaccount:demo:a")
		}
		return authenticatedAs("system:serviceaccount:demo:b")
	})

	first, err := counter.reviewer.Authenticate(bearerContext("token-a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := counter.reviewer.Authenticate(bearerContext("token-b"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Principal.ServiceAccount.ServiceAccount == second.Principal.ServiceAccount.ServiceAccount {
		t.Fatalf("two tokens resolved to the same identity: %s", first.Principal)
	}
	if got := counter.reviews(); got != 2 {
		t.Fatalf("TokenReviews = %d, want 2", got)
	}
}

// A cache entry expires, which bounds how long a revoked token stays usable.
func TestAuthenticateReReviewsAfterTTL(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("system:serviceaccount:demo:app")
	})
	counter.reviewer.ttl = 10 * time.Millisecond

	if _, err := counter.reviewer.Authenticate(bearerContext("a-token")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := counter.reviewer.Authenticate(bearerContext("a-token")); err != nil {
		t.Fatal(err)
	}
	if got := counter.reviews(); got != 2 {
		t.Fatalf("TokenReviews = %d, want 2 after expiry", got)
	}
}

// Rejections are never cached.
func TestAuthenticateDoesNotCacheRejections(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticationv1.TokenReviewStatus{Authenticated: false, Error: "nope"}
	})

	for range 3 {
		if _, err := counter.reviewer.Authenticate(bearerContext("a-token")); err == nil {
			t.Fatal("an unauthenticated token was accepted")
		}
	}
	if got := counter.reviews(); got != 3 {
		t.Fatalf("TokenReviews = %d, want one per attempt", got)
	}
}

// A username that is not a service account is refused, and not cached.
func TestAuthenticateRejectsNonServiceAccountUsers(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("kubernetes-admin")
	})
	if _, err := counter.reviewer.Authenticate(bearerContext("a-token")); err == nil {
		t.Fatal("a non-service-account user was accepted")
	}
	if _, err := counter.reviewer.Authenticate(bearerContext("a-token")); err == nil {
		t.Fatal("the rejection was cached")
	}
	if got := counter.reviews(); got != 2 {
		t.Fatalf("TokenReviews = %d, want one per attempt", got)
	}
}

// The cache never exceeds tokenReviewCacheEntries.
func TestTokenReviewCacheIsBounded(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("system:serviceaccount:demo:app")
	})
	now := time.Now()
	for index := range tokenReviewCacheEntries + 500 {
		counter.reviewer.remember(string(rune(index))+"-token", model.PeerIdentity{}, now)
	}
	counter.reviewer.mu.Lock()
	size := len(counter.reviewer.cache)
	counter.reviewer.mu.Unlock()
	if size > tokenReviewCacheEntries {
		t.Fatalf("cache grew to %d entries, cap is %d", size, tokenReviewCacheEntries)
	}
}

func TestAuthenticateRequiresBearerToken(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("system:serviceaccount:demo:app")
	})
	for _, ctx := range []context.Context{
		context.Background(),
		metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic abc")),
		metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer ")),
	} {
		if _, err := counter.reviewer.Authenticate(ctx); err == nil {
			t.Fatal("a request without a bearer token was accepted")
		}
	}
	if got := counter.reviews(); got != 0 {
		t.Fatalf("TokenReviews = %d, want none for malformed credentials", got)
	}
}
