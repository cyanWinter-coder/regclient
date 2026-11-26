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

package regclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/scheme/reg"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/mediatype"
	v1 "github.com/regclient/regclient/types/oci/v1"
	"github.com/regclient/regclient/types/platform"
	"github.com/regclient/regclient/types/ref"
)

type resTxEntry struct {
	body        []byte
	contentType string
}

type resTxRegistry struct {
	mu        sync.Mutex
	tags      map[string]string
	manifests map[string]resTxEntry
	requests  []string
}

type resTxIndexEntry struct {
	platform platform.Platform
	digest   string
}

func newResTxRegistry() *resTxRegistry {
	return &resTxRegistry{
		tags:      map[string]string{},
		manifests: map[string]resTxEntry{},
	}
}

func (r *resTxRegistry) add(mt string, body []byte) string {
	dig := digest.FromBytes(body).String()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[dig] = resTxEntry{body: body, contentType: mt}
	return dig
}

func (r *resTxRegistry) addImage(name string) string {
	body, err := json.Marshal(v1.Manifest{
		Versioned: v1.ManifestSchemaVersion,
		MediaType: mediatype.OCI1Manifest,
		Config: descriptor.Descriptor{
			MediaType: mediatype.OCI1ImageConfig,
			Size:      int64(len(name)),
			Digest:    digest.FromString("config-" + name),
		},
		Layers: []descriptor.Descriptor{{
			MediaType: mediatype.OCI1Layer,
			Size:      int64(len(name)),
			Digest:    digest.FromString("layer-" + name),
		}},
	})
	if err != nil {
		panic(err)
	}
	return r.add(mediatype.OCI1Manifest, body)
}

func (r *resTxRegistry) addIndex(generation string, entries ...resTxIndexEntry) string {
	descs := make([]descriptor.Descriptor, 0, len(entries))
	for _, entry := range entries {
		p := entry.platform
		descs = append(descs, descriptor.Descriptor{
			MediaType: mediatype.OCI1Manifest,
			Digest:    digest.Digest(entry.digest),
			Size:      128,
			Platform:  &p,
		})
	}
	body, err := json.Marshal(v1.Index{
		Versioned:   v1.IndexSchemaVersion,
		MediaType:   mediatype.OCI1ManifestList,
		Manifests:   descs,
		Annotations: map[string]string{"generation": generation},
	})
	if err != nil {
		panic(err)
	}
	return r.add(mediatype.OCI1ManifestList, body)
}

func (r *resTxRegistry) setTag(tag, dig string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tags[tag] = dig
}

func (r *resTxRegistry) tamper(dig string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.manifests[dig]
	entry.body = body
	r.manifests[dig] = entry
}

func (r *resTxRegistry) requestCount(fragment string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, request := range r.requests {
		if strings.Contains(request, fragment) {
			count++
		}
	}
	return count
}

func (r *resTxRegistry) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, req.Method+" "+req.URL.Path)
	r.mu.Unlock()

	if req.URL.Path == "/v2/" {
		rw.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		rw.WriteHeader(http.StatusOK)
		return
	}
	_, reference, found := strings.Cut(req.URL.Path, "/manifests/")
	if !found {
		http.NotFound(rw, req)
		return
	}

	r.mu.Lock()
	dig, isTag := r.tags[reference]
	if !isTag {
		dig = reference
	}
	entry, ok := r.manifests[dig]
	r.mu.Unlock()
	if !ok {
		http.NotFound(rw, req)
		return
	}

	rw.Header().Set("Content-Type", entry.contentType)
	rw.Header().Set("Docker-Content-Digest", dig)
	rw.Header().Set("Content-Length", fmt.Sprintf("%d", len(entry.body)))
	rw.WriteHeader(http.StatusOK)
	if req.Method != http.MethodHead {
		_, _ = io.Copy(rw, bytes.NewReader(entry.body))
	}
}

func newResTxClient(t *testing.T, host string) *regclient.RegClient {
	t.Helper()
	hostConfig := config.Host{Name: host, Hostname: host, TLS: config.TLSDisabled}
	return regclient.New(
		regclient.WithConfigHost(hostConfig),
		regclient.WithRegOpts(
			reg.WithConfigHosts([]*config.Host{&hostConfig}),
			reg.WithCache(time.Minute, 100),
		),
	)
}

func resTxRef(t *testing.T, host, location string) ref.Ref {
	t.Helper()
	reference := host + "/repo:" + location
	if strings.HasPrefix(location, "sha256:") {
		reference = host + "/repo@" + location
	}
	r, err := ref.New(reference)
	if err != nil {
		t.Fatalf("create ref %s: %v", reference, err)
	}
	return r
}

func TestResolutionTxTagMovePinsSelection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	registry := newResTxRegistry()
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	serverURL, _ := url.Parse(server.URL)
	host := serverURL.Host
	client := newResTxClient(t, host)

	amd64V1 := registry.addImage("amd64-v1")
	arm64V1 := registry.addImage("arm64-v1")
	amd64V2 := registry.addImage("amd64-v2")
	arm64V2 := registry.addImage("arm64-v2")
	indexV1 := registry.addIndex("v1",
		resTxIndexEntry{platform: platform.Platform{OS: "linux", Architecture: "amd64"}, digest: amd64V1},
		resTxIndexEntry{platform: platform.Platform{OS: "linux", Architecture: "arm64"}, digest: arm64V1},
	)
	indexV2 := registry.addIndex("v2",
		resTxIndexEntry{platform: platform.Platform{OS: "linux", Architecture: "amd64"}, digest: amd64V2},
		resTxIndexEntry{platform: platform.Platform{OS: "linux", Architecture: "arm64"}, digest: arm64V2},
	)
	registry.setTag("moving", indexV1)
	p := platform.Platform{OS: "linux", Architecture: "amd64"}

	m, err := client.ManifestGet(ctx, resTxRef(t, host, "moving"), regclient.WithManifestPlatform(p))
	if err != nil {
		t.Fatalf("first ManifestGet: %v", err)
	}
	if got := m.GetDescriptor().Digest.String(); got != amd64V1 {
		t.Fatalf("first digest = %s, want %s", got, amd64V1)
	}

	registry.setTag("moving", indexV2)
	m, err = client.ManifestGet(ctx, resTxRef(t, host, "moving"), regclient.WithManifestPlatform(p))
	if err != nil {
		t.Fatalf("ManifestGet after tag move: %v", err)
	}
	if got := m.GetDescriptor().Digest.String(); got != amd64V2 {
		t.Fatalf("moved tag mixed generations: got %s, want %s", got, amd64V2)
	}

	m, err = client.ManifestGet(ctx, resTxRef(t, host, indexV1), regclient.WithManifestPlatform(p))
	if err != nil {
		t.Fatalf("pinned old index ManifestGet: %v", err)
	}
	if got := m.GetDescriptor().Digest.String(); got != amd64V1 {
		t.Fatalf("old index digest = %s, want %s", got, amd64V1)
	}
}

func TestResolutionTxSelectionPriority(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, reverse := range []bool{false, true} {
		registry := newResTxRegistry()
		server := httptest.NewServer(registry)
		t.Cleanup(server.Close)
		serverURL, _ := url.Parse(server.URL)
		host := serverURL.Host
		client := newResTxClient(t, host)

		armV5 := registry.addImage("arm-v5")
		armV7 := registry.addImage("arm-v7")
		entries := []resTxIndexEntry{
			{platform: platform.Platform{OS: "linux", Architecture: "arm", Variant: "v5"}, digest: armV5},
			{platform: platform.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}, digest: armV7},
		}
		if reverse {
			entries[0], entries[1] = entries[1], entries[0]
		}
		indexDig := registry.addIndex("priority", entries...)
		registry.setTag("priority", indexDig)

		p := platform.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}
		m, err := client.ManifestGet(ctx, resTxRef(t, host, "priority"), regclient.WithManifestPlatform(p))
		if err != nil {
			t.Fatalf("reverse=%v ManifestGet: %v", reverse, err)
		}
		if got := m.GetDescriptor().Digest.String(); got != armV7 {
			t.Fatalf("reverse=%v selected %s, want exact v7 %s", reverse, got, armV7)
		}
	}
}

func TestResolutionTxStableNoSelectablePlatform(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	registry := newResTxRegistry()
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	serverURL, _ := url.Parse(server.URL)
	host := serverURL.Host
	client := newResTxClient(t, host)

	amd64 := registry.addImage("amd64")
	armV7 := registry.addImage("arm-v7")
	generic := registry.addImage("generic-features")
	indexDig := registry.addIndex("platforms",
		resTxIndexEntry{platform: platform.Platform{OS: "linux", Architecture: "amd64"}, digest: amd64},
		resTxIndexEntry{platform: platform.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}, digest: armV7},
		resTxIndexEntry{platform: platform.Platform{
			OS: "restxos", Architecture: "amd64", OSVersion: "1.0", Features: []string{"aes"},
		}, digest: generic},
	)
	windows := registry.addImage("windows")
	windowsIndex := registry.addIndex("windows", resTxIndexEntry{
		platform: platform.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.14393"},
		digest:   windows,
	})
	registry.setTag("platforms", indexDig)
	registry.setTag("windows", windowsIndex)

	tests := []struct {
		name string
		tag  string
		p    platform.Platform
	}{
		{name: "variant", tag: "platforms", p: platform.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}},
		{name: "os version", tag: "windows", p: platform.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.17763"}},
		{name: "features", tag: "platforms", p: platform.Platform{
			OS: "restxos", Architecture: "amd64", OSVersion: "1.0", Features: []string{"sse4"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resTxRef(t, host, tt.tag)
			_, err := client.ManifestGet(ctx, r, regclient.WithManifestPlatform(tt.p))
			if !errors.Is(err, errs.ErrNotFound) {
				t.Fatalf("Get error = %v, want %v", err, errs.ErrNotFound)
			}
			_, err = client.ManifestHead(ctx, r, regclient.WithManifestPlatform(tt.p))
			if !errors.Is(err, errs.ErrNotFound) {
				t.Fatalf("Head error = %v, want %v", err, errs.ErrNotFound)
			}
		})
	}
}

func TestResolutionTxSingleManifestCompatibility(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	registry := newResTxRegistry()
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	serverURL, _ := url.Parse(server.URL)
	host := serverURL.Host
	client := newResTxClient(t, host)

	singleV1 := registry.addImage("single-v1")
	singleV2 := registry.addImage("single-v2")
	registry.setTag("single", singleV1)
	p := platform.Platform{OS: "linux", Architecture: "amd64"}
	r := resTxRef(t, host, "single")

	m, err := client.ManifestGet(ctx, r, regclient.WithManifestPlatform(p))
	if err != nil {
		t.Fatalf("ManifestGet: %v", err)
	}
	if m.IsList() || m.GetDescriptor().Digest.String() != singleV1 {
		t.Fatalf("unexpected initial manifest %s list=%v", m.GetDescriptor().Digest, m.IsList())
	}
	if _, err := client.ManifestHead(ctx, r, regclient.WithManifestPlatform(p)); err != nil {
		t.Fatalf("ManifestHead: %v", err)
	}

	registry.setTag("single", singleV2)
	m, err = client.ManifestGet(ctx, r)
	if err != nil {
		t.Fatalf("ManifestGet after move: %v", err)
	}
	if got := m.GetDescriptor().Digest.String(); got != singleV2 {
		t.Fatalf("tag move not visible: got %s, want %s", got, singleV2)
	}
}

func TestResolutionTxChildCacheBoundToParent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	registry := newResTxRegistry()
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	serverURL, _ := url.Parse(server.URL)
	host := serverURL.Host
	client := newResTxClient(t, host)

	child := registry.addImage("shared-child")
	indexV1 := registry.addIndex("parent-v1", resTxIndexEntry{
		platform: platform.Platform{OS: "linux", Architecture: "amd64"},
		digest:   child,
	})
	indexV2 := registry.addIndex("parent-v2", resTxIndexEntry{
		platform: platform.Platform{OS: "linux", Architecture: "amd64"},
		digest:   child,
	})
	p := platform.Platform{OS: "linux", Architecture: "amd64"}

	if _, err := client.ManifestGet(ctx, resTxRef(t, host, indexV1), regclient.WithManifestPlatform(p)); err != nil {
		t.Fatalf("prime parent one: %v", err)
	}
	childRequests := registry.requestCount("/manifests/" + child)
	if _, err := client.ManifestGet(ctx, resTxRef(t, host, indexV1), regclient.WithManifestPlatform(p)); err != nil {
		t.Fatalf("repeat parent one: %v", err)
	}
	if got := registry.requestCount("/manifests/" + child); got != childRequests {
		t.Fatalf("same parent cache not reused: requests %d to %d", childRequests, got)
	}

	if _, err := client.ManifestGet(ctx, resTxRef(t, host, indexV2), regclient.WithManifestPlatform(p)); err != nil {
		t.Fatalf("parent two: %v", err)
	}
	if got := registry.requestCount("/manifests/" + child); got <= childRequests {
		t.Fatalf("child was reused across parent generations without rebinding")
	}
}

func TestResolutionTxDigestMismatchEvictsOnlyRelevant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	registry := newResTxRegistry()
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	serverURL, _ := url.Parse(server.URL)
	host := serverURL.Host
	client := newResTxClient(t, host)

	good := registry.addImage("good")
	other := registry.addImage("other")
	tampered, err := json.Marshal(v1.Manifest{
		Versioned: v1.ManifestSchemaVersion,
		MediaType: mediatype.OCI1Manifest,
		Config: descriptor.Descriptor{
			MediaType: mediatype.OCI1ImageConfig,
			Size:      8,
			Digest:    digest.FromString("config-tampered"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry.tamper(good, tampered)
	rGood := resTxRef(t, host, good)
	rOther := resTxRef(t, host, other)

	if _, err := client.ManifestGet(ctx, rOther); err != nil {
		t.Fatalf("seed other cache: %v", err)
	}
	if _, err := client.ManifestGet(ctx, rGood); !errors.Is(err, errs.ErrDigestMismatch) {
		t.Fatalf("tampered manifest error = %v, want %v", err, errs.ErrDigestMismatch)
	}
	if got := registry.requestCount("/manifests/" + good); got != 1 {
		t.Fatalf("good requests = %d, want 1", got)
	}
	if _, err := client.ManifestGet(ctx, rGood); !errors.Is(err, errs.ErrDigestMismatch) {
		t.Fatalf("retry error = %v, want %v", err, errs.ErrDigestMismatch)
	}
	if got := registry.requestCount("/manifests/" + good); got != 2 {
		t.Fatalf("good requests after retry = %d, want 2", got)
	}

	before := registry.requestCount("")
	if _, err := client.ManifestGet(ctx, rOther); err != nil {
		t.Fatalf("other cache entry lost: %v", err)
	}
	if got := registry.requestCount(""); got != before {
		t.Fatalf("unrelated cache entry was not reused")
	}
}
