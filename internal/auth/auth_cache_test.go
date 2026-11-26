// Copyright the regclient contributors.
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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/regclient/regclient/types/errs"
)

// newTestBearer builds a bearer handler backed by a discard logger.
func newTestBearer(host string, credsFn CredsFn) *bearerHandler {
	return NewBearerHandler(
		&http.Client{}, "regclient/test", host, credsFn,
		slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{})),
	).(*bearerHandler)
}

func bearerChallenge(realm, service, scope string) challenge {
	return challenge{
		authType: "bearer",
		params: map[string]string{
			"realm":   realm,
			"service": service,
			"scope":   scope,
		},
	}
}

func mustRequest(t *testing.T, u string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	return req
}

// tokenResp is a token server response body.
func tokenResp(token string) []byte {
	b, _ := json.Marshal(bearerToken{Token: token, ExpiresIn: 900, IssuedAt: time.Now()})
	return b
}

// TestBearerMirrorIsolation verifies the same handler does not reuse a token
// when the realm, service, or scopes differ, which can happen when an image is
// reached through different mirrors.
func TestBearerMirrorIsolation(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	tokens := map[string]string{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		key := req.URL.Query().Get("service") + "|" + strings.Join(req.URL.Query()["scope"], ",")
		mu.Lock()
		tok := tokens[key]
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(tokenResp(tok))
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)
	host := tsURL.Host

	mu.Lock()
	tokens["svc-a|repository:repo:pull"] = "token-mirror-a"
	tokens["svc-b|repository:repo:pull"] = "token-mirror-b"
	tokens["svc-a|repository:repo:pull,push"] = "token-mirror-a-push"
	mu.Unlock()

	b := newTestBearer(host, DefaultCredsFn)
	req := mustRequest(t, tsURL.String()+"/v2/repo/manifests/latest")

	// first mirror: realm A, service A, pull scope
	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc-a", "repository:repo:pull")); err != nil {
		t.Fatalf("challenge A failed: %v", err)
	}
	if err := b.UpdateRequest(req); err != nil {
		t.Fatalf("update A failed: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer token-mirror-a" {
		t.Fatalf("expected token-mirror-a, got %q", got)
	}
	entryA := b.cur

	// second mirror: different realm and service, same registry host
	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/other-token", "svc-b", "repository:repo:pull")); err != nil {
		t.Fatalf("challenge B failed: %v", err)
	}
	if b.cur == entryA {
		t.Fatalf("expected a new token generation for the changed realm/service")
	}
	if err := b.UpdateRequest(req); err != nil {
		t.Fatalf("update B failed: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer token-mirror-b" {
		t.Fatalf("expected token-mirror-b, got %q", got)
	}

	// the previous generation's token must remain usable for an in-flight request
	entryA.refreshMu.Lock()
	tokA := entryA.token.Token
	entryA.refreshMu.Unlock()
	if tokA != "token-mirror-a" {
		t.Fatalf("previous generation token was overwritten: %q", tokA)
	}

	// switching back to the first realm reuses its cached entry, no refetch
	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc-a", "repository:repo:pull")); err != nil {
		t.Fatalf("challenge A again failed: %v", err)
	}
	if b.cur != entryA {
		t.Fatalf("expected to return to the cached entry for realm A")
	}
	if err := b.UpdateRequest(req); err != nil {
		t.Fatalf("update A again failed: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer token-mirror-a" {
		t.Fatalf("expected cached token-mirror-a, got %q", got)
	}

	// different scopes on the same realm get a distinct entry
	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc-a", "repository:repo:push")); err != nil {
		t.Fatalf("challenge push failed: %v", err)
	}
	if b.cur == entryA {
		t.Fatalf("expected a distinct entry for the push scope")
	}
	if err := b.UpdateRequest(req); err != nil {
		t.Fatalf("update push failed: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer token-mirror-a-push" {
		t.Fatalf("expected token-mirror-a-push, got %q", got)
	}

	// all four identities remain cached independently
	if len(b.entries) != 3 {
		t.Fatalf("expected 3 cached identities, got %d", len(b.entries))
	}
}

// TestBearerScopeOrderKey verifies the cache key is insensitive to scope order.
func TestBearerScopeOrderKey(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(tokenResp("ordered-token"))
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)
	b := newTestBearer(tsURL.Host, DefaultCredsFn)

	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc", "repository:repo:pull")); err != nil {
		t.Fatalf("challenge 1 failed: %v", err)
	}
	if err := b.AddScope("repository:other:pull"); err != nil {
		t.Fatalf("add scope failed: %v", err)
	}
	key1 := b.bearerKeyLocked()

	// rebuild the handler with the scopes added in the reverse order
	b2 := newTestBearer(tsURL.Host, DefaultCredsFn)
	if err := b2.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc", "repository:other:pull")); err != nil {
		t.Fatalf("challenge 2 failed: %v", err)
	}
	if err := b2.AddScope("repository:repo:pull"); err != nil {
		t.Fatalf("add scope 2 failed: %v", err)
	}
	key2 := b2.bearerKeyLocked()

	if key1 != key2 {
		t.Fatalf("scope order changed the cache key:\n%#v\n%#v", key1, key2)
	}
}

// TestBearerExpiryRefresh verifies an expired token is refetched and that the
// attempt state does not block later refreshes.
func TestBearerExpiryRefresh(t *testing.T) {
	t.Parallel()
	var gets atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gets.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(tokenResp("expiry-" + strconv.Itoa(int(gets.Load()))))
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)
	b := newTestBearer(tsURL.Host, DefaultCredsFn)
	req := mustRequest(t, tsURL.String()+"/v2/repo/manifests/latest")

	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc", "repository:repo:pull")); err != nil {
		t.Fatalf("challenge failed: %v", err)
	}
	if err := b.UpdateRequest(req); err != nil {
		t.Fatalf("first update failed: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer expiry-1" {
		t.Fatalf("expected expiry-1, got %q", got)
	}

	// force expiry, the next request must refetch
	b.cur.token.IssuedAt = time.Now().Add(-time.Hour)
	if !b.isExpired() {
		t.Fatalf("expected token to be expired")
	}
	if err := b.UpdateRequest(req); err != nil {
		t.Fatalf("refresh after expiry failed: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer expiry-2" {
		t.Fatalf("expected expiry-2 after refresh, got %q", got)
	}
	if gets.Load() != 2 {
		t.Fatalf("expected 2 token fetches, got %d", gets.Load())
	}
}

// TestBearerRefreshCoalesce verifies concurrent refreshes merge into a single
// outbound request and a canceled caller does not affect the shared result.
func TestBearerRefreshCoalesce(t *testing.T) {
	t.Parallel()
	var fetches atomic.Int32
	entering := make(chan struct{})
	gate := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fetches.Add(1)
		select {
		case entering <- struct{}{}:
		default:
		}
		<-gate
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(tokenResp("shared-token"))
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)
	b := newTestBearer(tsURL.Host, DefaultCredsFn)

	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc", "repository:repo:pull")); err != nil {
		t.Fatalf("challenge failed: %v", err)
	}
	e := b.cur

	// leader starts a refresh and blocks on the server gate
	leaderReq := mustRequest(t, tsURL.String()+"/v2/repo/manifests/latest")
	leaderDone := make(chan error, 1)
	go func() { leaderDone <- b.UpdateRequest(leaderReq) }()
	<-entering

	// two waiters join the same in-flight refresh
	ctx0, cancel0 := context.WithCancel(context.Background())
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	waiterReady := make(chan struct{}, 2)
	waiter0Done := make(chan error, 1)
	waiter1Done := make(chan error, 1)
	startWaiter := func(ctx context.Context, done chan error) {
		go func() {
			r := mustRequest(t, tsURL.String()+"/v2/repo/manifests/latest").WithContext(ctx)
			waiterReady <- struct{}{}
			done <- b.UpdateRequest(r)
		}()
	}
	startWaiter(ctx0, waiter0Done)
	startWaiter(ctx1, waiter1Done)
	<-waiterReady
	<-waiterReady

	// cancel one waiter: its own request fails but the shared refresh continues
	cancel0()
	select {
	case err := <-waiter0Done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected canceled waiter to return context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("canceled waiter did not return")
	}

	// the shared refresh is still in flight, single outbound fetch so far
	select {
	case <-leaderDone:
		t.Fatalf("leader refresh should still be blocked on the gate")
	case <-waiter1Done:
		t.Fatalf("surviving waiter should still be blocked on the gate")
	default:
	}

	// release the shared refresh; the leader and surviving waiter succeed
	close(gate)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader refresh failed: %v", err)
	}
	if err := <-waiter1Done; err != nil {
		t.Fatalf("surviving waiter refresh failed: %v", err)
	}
	if got := leaderReq.Header.Get("Authorization"); got != "Bearer shared-token" {
		t.Fatalf("expected shared-token, got %q", got)
	}
	if fetches.Load() != 1 {
		t.Fatalf("expected a single coalesced fetch, got %d", fetches.Load())
	}
	if e.token.Token != "shared-token" {
		t.Fatalf("shared entry did not retain the token: %q", e.token.Token)
	}
}

// TestBearerMethodPriority verifies Bearer POST is tried before an
// authenticated GET, and anonymous GET is used without credentials, each only
// once per round.
func TestBearerMethodPriority(t *testing.T) {
	t.Parallel()
	var posts, gets atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodPost:
			posts.Add(1)
			w.WriteHeader(http.StatusNotFound)
		case http.MethodGet:
			gets.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(tokenResp("get-token"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)

	// credentialed: POST (refresh) fails, then GET with basic auth succeeds once
	b := newTestBearer(tsURL.Host, func(string) Cred {
		return Cred{User: "user", Password: "pass", Token: "refresh-token"}
	})
	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc", "repository:repo:pull")); err != nil {
		t.Fatalf("challenge failed: %v", err)
	}
	req := mustRequest(t, tsURL.String()+"/v2/repo/manifests/latest")
	if err := b.UpdateRequest(req); err != nil {
		t.Fatalf("credentialed update failed: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer get-token" {
		t.Fatalf("expected get-token, got %q", got)
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("expected 1 post and 1 get, got posts=%d gets=%d", posts.Load(), gets.Load())
	}

	// anonymous handler: no POST, a single anonymous GET
	bAnon := newTestBearer(tsURL.Host, DefaultCredsFn)
	if err := bAnon.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc", "repository:repo:pull")); err != nil {
		t.Fatalf("anonymous challenge failed: %v", err)
	}
	reqAnon := mustRequest(t, tsURL.String()+"/v2/repo/manifests/latest")
	if err := bAnon.UpdateRequest(reqAnon); err != nil {
		t.Fatalf("anonymous update failed: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("anonymous flow must not POST, got posts=%d", posts.Load())
	}
	if gets.Load() != 2 {
		t.Fatalf("expected a second GET for the anonymous flow, got gets=%d", gets.Load())
	}
}

// TestBearerFailureRetriedOnce verifies a round that exhausts every method
// returns unauthorized without looping, and subsequent expiry allows a retry.
func TestBearerFailureRetriedOnce(t *testing.T) {
	t.Parallel()
	var posts, gets atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			posts.Add(1)
		} else {
			gets.Add(1)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)
	b := newTestBearer(tsURL.Host, func(string) Cred {
		return Cred{User: "user", Password: "pass", Token: "refresh-token"}
	})
	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/token", "svc", "repository:repo:pull")); err != nil {
		t.Fatalf("challenge failed: %v", err)
	}
	req := mustRequest(t, tsURL.String()+"/v2/repo/manifests/latest")
	err := b.UpdateRequest(req)
	if !errors.Is(err, errs.ErrHTTPUnauthorized) {
		t.Fatalf("expected ErrHTTPUnauthorized, got %v", err)
	}
	// POST then GET, each attempted exactly once
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("expected 1 post and 1 get, got posts=%d gets=%d", posts.Load(), gets.Load())
	}

	// a new refresh round after the entry is marked expired may retry again
	b.cur.token.IssuedAt = time.Now().Add(-time.Hour)
	_ = b.UpdateRequest(req)
	if posts.Load() != 2 || gets.Load() != 2 {
		t.Fatalf("expected a second round after expiry, got posts=%d gets=%d", posts.Load(), gets.Load())
	}
}

// TestBasicRetryOnce verifies a basic challenge is processed once and an
// identical repeated challenge reports no new challenge, which is what makes
// the HTTP layer stop retrying after the single allowed retry. The basic
// header itself is stateless and re-attached on redirects.
func TestBasicRetryOnce(t *testing.T) {
	t.Parallel()
	credsFn := func(string) Cred {
		return Cred{User: "user", Password: "pass"}
	}
	a := NewAuth(WithCreds(credsFn))
	tsURL, _ := url.Parse("http://registry.example.org")
	resp := &http.Response{
		Request:    &http.Request{URL: tsURL, Header: http.Header{}},
		StatusCode: http.StatusUnauthorized,
		Header:     http.Header{"Www-Authenticate": {`Basic realm="test"`}},
	}
	if err := a.HandleResponse(resp); err != nil {
		t.Fatalf("handle response failed: %v", err)
	}
	req := mustRequest(t, tsURL.String())
	if err := a.UpdateRequest(req); err != nil {
		t.Fatalf("first basic attempt failed: %v", err)
	}
	if req.Header.Get("Authorization") == "" {
		t.Fatalf("expected a basic authorization header")
	}
	// the same challenge again means there is nothing new to try at the
	// handler level: the HTTP layer treats this as a terminal failure
	// instead of looping
	basic := a.hs[tsURL.Host]["basic"].(*basicHandler)
	if err := basic.ProcessChallenge(challenge{
		authType: "basic",
		params:   map[string]string{"realm": "test"},
	}); !errors.Is(err, errs.ErrNoNewChallenge) {
		t.Fatalf("expected ErrNoNewChallenge on repeated challenge, got %v", err)
	}
	// a changed realm is a new challenge and re-enables the attempt
	resp2 := &http.Response{
		Request:    &http.Request{URL: tsURL, Header: http.Header{}},
		StatusCode: http.StatusUnauthorized,
		Header:     http.Header{"Www-Authenticate": {`Basic realm="other"`}},
	}
	if err := a.HandleResponse(resp2); err != nil {
		t.Fatalf("second challenge failed: %v", err)
	}
	req3 := mustRequest(t, tsURL.String())
	if err := a.UpdateRequest(req3); err != nil {
		t.Fatalf("basic attempt after new challenge failed: %v", err)
	}
	if req3.Header.Get("Authorization") == "" {
		t.Fatalf("expected basic auth to be retried after a new challenge")
	}
}

// TestRedactURL verifies host credentials never appear in log-ready URLs.
func TestRedactURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		bad  []string
	}{
		{
			name: "basic account parameter",
			in:   "https://auth.example.org/token?account=secretuser&service=reg",
			bad:  []string{"secretuser"},
		},
		{
			name: "password parameter",
			in:   "https://auth.example.org/token?password=hunter2",
			bad:  []string{"hunter2"},
		},
		{
			name: "embedded userinfo",
			in:   "https://user:hunter2@auth.example.org/token",
			bad:  []string{"hunter2", "user:"},
		},
		{
			name: "mixed case parameter name",
			in:   "https://auth.example.org/token?ACCOUNT=secretuser",
			bad:  []string{"secretuser"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := redactURL(tt.in)
			for _, fragment := range tt.bad {
				if strings.Contains(out, fragment) {
					t.Fatalf("redacted URL %q still contains %q", out, fragment)
				}
			}
			if !strings.Contains(out, redactedValue) && !strings.Contains(out, url.QueryEscape(redactedValue)) {
				t.Fatalf("expected redaction marker in %q", out)
			}
		})
	}
}

// captureHandler collects log records for assertions on logged attributes.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// failingRoundTripper simulates the *url.Error that http.Client.Do returns
// on a transport failure, which embeds the full request URL including the
// account query parameter.
type failingRoundTripper struct {
	u string
}

func (f *failingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, &url.Error{Op: req.Method + " " + req.URL.Path, URL: f.u, Err: errors.New("connection refused")}
}

// TestNoCredentialsInLogs drives a failing token fetch and asserts the logger
// never receives the host password or the account query parameter.
func TestNoCredentialsInLogs(t *testing.T) {
	t.Parallel()
	const password = "super-secret-pass"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)
	leakURL := tsURL.String() + "/token?account=theuser&client_id=regclient"

	capture := &captureHandler{}
	logger := slog.New(capture)
	b := NewBearerHandler(
		&http.Client{Transport: &failingRoundTripper{u: leakURL}},
		"regclient/test", tsURL.Host,
		func(string) Cred { return Cred{User: "theuser", Password: password} },
		logger,
	).(*bearerHandler)
	// the realm itself carries an account parameter that must be redacted in logs
	if err := b.ProcessChallenge(bearerChallenge(tsURL.String()+"/token?account=theuser", "svc", "repository:repo:pull")); err != nil {
		t.Fatalf("challenge failed: %v", err)
	}
	req := mustRequest(t, tsURL.String()+"/v2/repo/manifests/latest")
	_ = b.UpdateRequest(req)

	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.records) == 0 {
		t.Fatalf("expected failure log records")
	}
	for _, r := range capture.records {
		var bld strings.Builder
		r.Attrs(func(a slog.Attr) bool {
			bld.WriteString(a.String())
			bld.WriteString(" ")
			return true
		})
		dumped := r.Message + " " + bld.String()
		if strings.Contains(dumped, password) {
			t.Fatalf("log record leaked password: %q", dumped)
		}
		if strings.Contains(dumped, "theuser") {
			t.Fatalf("log record leaked account name: %q", dumped)
		}
	}
}
