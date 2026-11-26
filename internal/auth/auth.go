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

// Package auth is used for HTTP authentication
package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/regclient/regclient/internal/regnet"
	"github.com/regclient/regclient/types/errs"
)

// redactedQueryParams are query parameters that may carry host credentials.
// They are replaced with redactedValue in logs.
var redactedQueryParams = map[string]bool{
	"account":  true,
	"password": true,
	"token":    true,
}

const redactedValue = "[redacted]"

// redactURL returns a copy of the URL string with credential-bearing query
// parameters and any user info removed. It is safe to log the result.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redactedValue
	}
	if u.User != nil {
		u.User = url.User(redactedValue)
	}
	q := u.Query()
	changed := false
	for k := range q {
		if redactedQueryParams[strings.ToLower(k)] {
			q.Set(k, redactedValue)
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// redactError returns an error safe to log, replacing any URL embedded in a
// [url.Error] with a redacted copy. Nested url.Error values are redacted too.
// Network errors otherwise do not carry request credentials, but the token
// endpoint URL may include an account.
func redactError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	return &url.Error{
		Op:  ue.Op,
		URL: redactURL(ue.URL),
		Err: redactError(ue.Err),
	}
}

type charLU byte

var charLUs [256]charLU

var defaultClientID = "regclient"

// minTokenLife tokens are required to last at least 60 seconds to support older docker clients
var minTokenLife = 60

// tokenBuffer is used to renew a token before it expires to account for time to process requests on the server
var tokenBuffer = time.Second * 5

const (
	isSpace charLU = 1 << iota
	isToken
)

func init() {
	for c := range 256 {
		charLUs[c] = 0
		if strings.ContainsRune(" \t\r\n", rune(c)) {
			charLUs[c] |= isSpace
		}
		if (rune('a') <= rune(c) && rune(c) <= rune('z')) || (rune('A') <= rune(c) && rune(c) <= rune('Z') || (rune('0') <= rune(c) && rune(c) <= rune('9')) || strings.ContainsRune("-._~+/", rune(c))) {
			charLUs[c] |= isToken
		}
	}
}

// CredsFn is passed to lookup credentials for a given hostname, response is a username and password or empty strings
type CredsFn func(host string) Cred

// Cred is returned by the CredsFn.
// If Token is provided and auth method is bearer, it will attempt to use it as a refresh token.
// Else if user and password are provided, they are attempted with all auth methods.
// Else if neither are provided and auth method is bearer, an anonymous login is attempted.
type Cred struct {
	//#nosec G117 exported struct intentionally holds secrets
	User, Password string // clear text username and password
	Token          string // refresh token only used for bearer auth
}

// challenge is the extracted contents of the WWW-Authenticate header.
type challenge struct {
	authType string
	params   map[string]string
}

// handler handles a challenge for a host to return an auth header
type handler interface {
	AddScope(scope string) error
	ProcessChallenge(challenge) error
	UpdateRequest(*http.Request) error
}

// asyncHandler is implemented by handlers that must not run under the Auth
// mutex, typically because their UpdateRequest makes HTTP calls.
// The handler is expected to provide its own internal synchronization.
type asyncHandler interface {
	UpdateRequestAsync(*http.Request) error
}

// handlerBuild is used to make a new handler for a specific authType and URL
type handlerBuild func(client *http.Client, clientID, host string, credFn CredsFn, slog *slog.Logger) handler

// Opts configures options for NewAuth
type Opts func(*Auth)

// Auth is used to handle authentication requests.
type Auth struct {
	httpClient *http.Client
	clientID   string
	credsFn    CredsFn
	hbs        map[string]handlerBuild       // handler builders based on authType
	hs         map[string]map[string]handler // handlers based on url and authType
	authTypes  []string
	slog       *slog.Logger
	mu         sync.Mutex
}

// NewAuth creates a new Auth
func NewAuth(opts ...Opts) *Auth {
	a := &Auth{
		httpClient: &http.Client{},
		clientID:   defaultClientID,
		credsFn:    DefaultCredsFn,
		hbs:        map[string]handlerBuild{},
		hs:         map[string]map[string]handler{},
		authTypes:  []string{},
		slog:       slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{})),
	}

	for _, opt := range opts {
		opt(a)
	}

	if len(a.authTypes) == 0 {
		a.addDefaultHandlers()
	}

	return a
}

// WithCreds provides a user/pass lookup for a url
func WithCreds(f CredsFn) Opts {
	return func(a *Auth) {
		if f != nil {
			a.credsFn = f
		}
	}
}

// WithHTTPClient uses a specific http client with requests
func WithHTTPClient(h *http.Client) Opts {
	return func(a *Auth) {
		if h != nil {
			a.httpClient = h
		}
	}
}

// WithClientID uses a client ID with request headers
func WithClientID(clientID string) Opts {
	return func(a *Auth) {
		a.clientID = clientID
	}
}

// WithHandler includes a handler for a specific auth type
func WithHandler(authType string, hb handlerBuild) Opts {
	return func(a *Auth) {
		lcat := strings.ToLower(authType)
		a.hbs[lcat] = hb
		a.authTypes = append(a.authTypes, lcat)
	}
}

// WithDefaultHandlers includes a Basic and Bearer handler, this is automatically added with "WithHandler" is not called
func WithDefaultHandlers() Opts {
	return func(a *Auth) {
		a.addDefaultHandlers()
	}
}

// WithLog injects a Logger
func WithLog(slog *slog.Logger) Opts {
	return func(a *Auth) {
		a.slog = slog
	}
}

// AddScope extends an existing auth with additional scopes.
// This is used to pre-populate scopes with the Docker convention rather than
// depend on the registry to respond with the correct http status and headers.
func (a *Auth) AddScope(host, scope string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	success := false
	if a.hs[host] == nil {
		return errs.ErrNoNewChallenge
	}
	for _, at := range a.authTypes {
		if a.hs[host][at] != nil {
			err := a.hs[host][at].AddScope(scope)
			if err == nil {
				success = true
			} else if err != errs.ErrNoNewChallenge {
				return err
			}
		}
	}
	if !success {
		return errs.ErrNoNewChallenge
	}
	a.slog.Debug("Auth scope added",
		slog.String("host", host),
		slog.String("scope", scope))
	return nil
}

// HandleResponse parses the 401 response, extracting the WWW-Authenticate
// header and verifying the requirement is different from what was included in
// the last request
func (a *Auth) HandleResponse(resp *http.Response) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// verify response is an access denied
	if resp.StatusCode != http.StatusUnauthorized {
		return errs.ErrUnsupported
	}

	// extract host and auth header
	host := resp.Request.URL.Host
	cl, err := ParseAuthHeaders(resp.Header.Values("WWW-Authenticate"))
	if err != nil {
		return err
	}
	if len(cl) > 0 {
		authTypes := make([]string, 0, len(cl))
		for _, c := range cl {
			authTypes = append(authTypes, c.authType)
		}
		a.slog.Debug("Auth request parsed",
			slog.String("host", host),
			slog.Any("authtypes", authTypes))
	}
	if len(cl) < 1 {
		return errs.ErrEmptyChallenge
	}
	goodChallenge := false
	// loop over the received challenge(s)
	for _, c := range cl {
		if _, ok := a.hbs[c.authType]; !ok {
			a.slog.Warn("Unsupported auth type",
				slog.String("authtype", c.authType))
			continue
		}
		// setup a handler for the host and auth type
		if _, ok := a.hs[host]; !ok {
			a.hs[host] = map[string]handler{}
		}
		if _, ok := a.hs[host][c.authType]; !ok {
			h := a.hbs[c.authType](a.httpClient, a.clientID, host, a.credsFn, a.slog)
			if h == nil {
				continue
			}
			a.hs[host][c.authType] = h
		}
		// process the challenge with that handler
		err := a.hs[host][c.authType].ProcessChallenge(c)
		if err == nil {
			goodChallenge = true
		} else if err == errs.ErrNoNewChallenge {
			// handle race condition when another request updates the challenge
			// detect that by seeing the current auth header is different
			prevAH := resp.Request.Header.Get("Authorization")
			err := a.hs[host][c.authType].UpdateRequest(resp.Request)
			if err == nil && prevAH != resp.Request.Header.Get("Authorization") {
				goodChallenge = true
			}
		} else {
			return err
		}
	}
	if !goodChallenge {
		return errs.ErrHTTPUnauthorized
	}

	return nil
}

// UpdateRequest adds Authorization headers to a request
func (a *Auth) UpdateRequest(req *http.Request) error {
	a.mu.Lock()
	host := req.URL.Host
	if a.hs[host] == nil {
		a.mu.Unlock()
		return nil
	}
	var h handler
	for _, at := range a.authTypes {
		if a.hs[host][at] != nil {
			h = a.hs[host][at]
			break
		}
	}
	// handlers making outbound calls run without the Auth mutex so concurrent
	// token refreshes coalesce instead of serializing every request
	async, isAsync := h.(asyncHandler)
	if isAsync {
		a.mu.Unlock()
		return async.UpdateRequestAsync(req)
	}
	defer a.mu.Unlock()
	if h == nil {
		return nil
	}
	err := h.UpdateRequest(req)
	if err != nil {
		a.slog.Debug("Failed to generate auth",
			slog.String("err", err.Error()),
			slog.String("host", host))
	}
	return err
}

func (a *Auth) addDefaultHandlers() {
	if _, ok := a.hbs["basic"]; !ok {
		a.hbs["basic"] = NewBasicHandler
		a.authTypes = append(a.authTypes, "basic")
	}
	if _, ok := a.hbs["bearer"]; !ok {
		a.hbs["bearer"] = NewBearerHandler
		a.authTypes = append(a.authTypes, "bearer")
	}
}

// DefaultCredsFn is used to return no credentials when auth is not configured with a CredsFn
// This avoids the need to check for nil pointers
func DefaultCredsFn(h string) Cred {
	return Cred{}
}

// ParseAuthHeaders extracts the scheme and realm from WWW-Authenticate headers
func ParseAuthHeaders(ahl []string) ([]challenge, error) {
	var cl []challenge
	for _, ah := range ahl {
		c, err := parseAuthHeader(ah)
		if err != nil {
			return nil, fmt.Errorf("failed to parse challenge header: %s, %w", ah, err)
		}
		cl = append(cl, c...)
	}
	return cl, nil
}

// parseAuthHeader parses a single header line for WWW-Authenticate
// Example values:
// Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:samalba/my-app:pull,push"
// Basic realm="GitHub Package Registry"
func parseAuthHeader(ah string) ([]challenge, error) {
	var cl []challenge
	var c *challenge
	curElement := []byte{}
	curKey := ""
	stateElement := "string"
	stateSyntax := "start"

	for _, b := range []byte(ah) {
		switch stateElement {
		case "string":
			// string: ignore leading space, enter quote only if first character, handle escapes, handle valid tokens, else end
			if charLUs[b]&isToken != 0 {
				// add valid tokens to element
				curElement = append(curElement, b)
			} else if charLUs[b]&isSpace != 0 && len(curElement) == 0 {
				// ignore leading spaces
			} else if b == '"' && len(curElement) == 0 {
				stateElement = "quote"
			} else if b == '\\' {
				stateElement = "escape_string"
			} else {
				stateElement = "end"
			}
		case "quote":
			// quote: handle escapes, handle closing quote (quote_end to read next character), all other tokens are valid
			if b == '\\' {
				stateElement = "escape_quote"
			} else if b == '"' {
				stateElement = "quote_end"
			} else {
				curElement = append(curElement, b)
			}
		case "quote_end":
			// any character after the close quote is the end of the element
			stateElement = "end"
		case "escape_string":
			// escape_string: handle any character and return to string state
			curElement = append(curElement, b)
			stateElement = "string"
		case "escape_quote":
			// escape_quote: handle any character and return to quote state
			curElement = append(curElement, b)
			stateElement = "quote"
		case "end":
			// finished parsing element, continue to processing element according to the current state
		default:
			return nil, fmt.Errorf("unhandled element case: %w", errs.ErrParsingFailed)
		}
		if stateElement != "end" {
			// continue parsing the element until it ends
			continue
		}

		// syntax looks at each string within the overall challenge syntax
		switch stateSyntax {
		case "start":
			// start: (start of auth_type) read auth_type and space (end_auth_type) or auth_type and comma (start)
			if charLUs[b]&isSpace != 0 && len(curElement) > 0 {
				stateSyntax = "end_auth_type"
			} else if b == ',' && len(curElement) > 0 {
				// state remains at start
			} else {
				return nil, fmt.Errorf("start element did not end with a space or comma: %w", errs.ErrParsingFailed)
			}
			c = &challenge{authType: strings.ToLower(string(curElement)), params: map[string]string{}}
			cl = append(cl, *c)
		case "start_or_param":
			// start_or_param: (after param_value) read auth_type and space (end_auth_type) or param_key and equals (param_value)
			if charLUs[b]&isSpace != 0 && len(curElement) > 0 {
				c = &challenge{authType: strings.ToLower(string(curElement)), params: map[string]string{}}
				cl = append(cl, *c)
				stateSyntax = "end_auth_type"
			} else if b == '=' && len(curElement) > 0 {
				curKey = strings.ToLower(string(curElement))
				stateSyntax = "param_value"
			} else {
				return nil, fmt.Errorf("expected auth type or param: %w", errs.ErrParsingFailed)
			}
		case "end_auth_type":
			// end_auth_type: (after reading auth_type) read param_key and equals (param_value) or just a comma (start)
			if b == '=' && len(curElement) > 0 {
				curKey = strings.ToLower(string(curElement))
				stateSyntax = "param_value"
			} else if b == ',' && len(curElement) == 0 {
				// ignore white space between end of auth_type and comma
				stateSyntax = "start"
			} else {
				return nil, fmt.Errorf("expected param or comma: %w", errs.ErrParsingFailed)
			}
		case "param_value":
			// param_value: (after param_key) read param_value and comma (start_or_param)
			if b == ',' {
				c.params[curKey] = string(curElement)
				stateSyntax = "start_or_param"
				curKey = ""
			} else {
				return nil, fmt.Errorf("expected param value: %w", errs.ErrParsingFailed)
			}
		default:
			return nil, fmt.Errorf("unhandled syntax case: %w", errs.ErrParsingFailed)
		}
		// reset element state
		stateElement = "string"
		curElement = []byte{}
	}
	// at end of parsing, if the element is not empty, process according to syntax state:
	if len(curElement) > 0 {
		// ensure this is not within an unclosed quote or partial escape
		if stateElement != "string" && stateElement != "quote_end" {
			return nil, fmt.Errorf("eol element in state %s: %w", stateElement, errs.ErrParsingFailed)
		}
		switch stateSyntax {
		case "start", "start_or_param":
			// add a new auth type if a string is seen at the start, before any equals
			c = &challenge{authType: strings.ToLower(string(curElement)), params: map[string]string{}}
			cl = append(cl, *c)
		case "param_value":
			// add the last param key=val
			c.params[curKey] = string(curElement)
		case "end_auth_type":
			// missing equals for param
			return nil, fmt.Errorf("eol at param without value: %w", errs.ErrParsingFailed)
		}
	}

	return cl, nil
}

// basicHandler supports Basic auth type requests
type basicHandler struct {
	realm   string
	host    string
	credsFn CredsFn
}

// NewBasicHandler creates a new BasicHandler
func NewBasicHandler(client *http.Client, clientID, host string, credsFn CredsFn, slog *slog.Logger) handler {
	return &basicHandler{
		realm:   "",
		host:    host,
		credsFn: credsFn,
	}
}

// AddScope is not valid for BasicHandler
func (b *basicHandler) AddScope(scope string) error {
	return errs.ErrNoNewChallenge
}

// ProcessChallenge for BasicHandler is a noop
func (b *basicHandler) ProcessChallenge(c challenge) error {
	if _, ok := c.params["realm"]; !ok {
		return errs.ErrInvalidChallenge
	}
	if b.realm != c.params["realm"] {
		b.realm = c.params["realm"]
		return nil
	}
	return errs.ErrNoNewChallenge
}

// UpdateRequest for BasicHandler generates base64 encoded user/pass for a host.
// Basic credentials are stateless and re-attached on redirects; the caller is
// responsible for bounding retries after a rejected challenge.
func (b *basicHandler) UpdateRequest(req *http.Request) error {
	cred := b.credsFn(b.host)
	if cred.User == "" || cred.Password == "" {
		return fmt.Errorf("no credentials available: %w", errs.ErrHTTPUnauthorized)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s",
		base64.StdEncoding.EncodeToString([]byte(cred.User+":"+cred.Password))))
	return nil
}

// bearerToken is the json response to the Bearer request
type bearerToken struct {
	Token        string    `json:"token"`
	AccessToken  string    `json:"access_token"` //#nosec G117 exported struct intentionally holds secrets
	ExpiresIn    int       `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
	RefreshToken string    `json:"refresh_token"` //#nosec G117 exported struct intentionally holds secrets
	Scope        string    `json:"scope"`
}

// bearerHandler supports Bearer auth type requests.
//
// Tokens are cached per (registry host, realm, service, sorted scopes)
// identity so that mirrors sharing a host but presenting different
// challenges never reuse a token scoped for another realm or scope set.
// Each challenge change starts a new generation: the previous entry stays
// available for requests already in flight while new requests resolve
// against the new generation.
type bearerHandler struct {
	client   *http.Client
	clientID string
	host     string
	credsFn  CredsFn
	slog     *slog.Logger

	mu         sync.Mutex
	realm      string
	service    string
	scopes     []string // scopes accumulated before a realm/service is known
	generation uint64
	cur        *bearerEntry
	entries    map[bearerKey]*bearerEntry
}

// bearerKey is the cache identity of a token. It includes the registry,
// realm, service, and the sorted, non-empty scopes.
type bearerKey struct {
	host    string
	realm   string
	service string
	scopes  string // scopes joined with a space after sorting
}

// bearerEntry is one cached token identity.
type bearerEntry struct {
	key      bearerKey
	scopes   []string
	tokenURL *url.URL
	token    bearerToken

	// refresh coalescing: at most one outbound token request per entry,
	// other callers wait on done and share the leader's result
	refreshMu sync.Mutex
	done      chan struct{}
	err       error
}

// NewBearerHandler creates a new BearerHandler
func NewBearerHandler(client *http.Client, clientID, host string, credsFn CredsFn, slog *slog.Logger) handler {
	return &bearerHandler{
		client:   client,
		clientID: clientID,
		host:     host,
		credsFn:  credsFn,
		scopes:   []string{},
		entries:  map[bearerKey]*bearerEntry{},
		slog:     slog,
	}
}

// AddScope appends a new scope if it doesn't already exist
func (b *bearerHandler) AddScope(scope string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.scopeExists(scope) {
		if b.cur == nil || b.cur.usable() {
			return errs.ErrNoNewChallenge
		}
		// scope exists but the cached token is gone or expired: let the
		// caller trigger a refresh for the current identity
		return nil
	}
	b.addScope(scope)
	if b.realm == "" {
		return nil
	}
	// resolve the new identity, starting a new generation when it changes
	b.resolveLocked()
	return nil
}

// addScope appends a scope, extending an existing repository scope when
// possible. It does not mutate any cached token.
func (b *bearerHandler) addScope(scope string) {
	if !b.tryExtendExistingScope(scope) {
		b.scopes = append(b.scopes, scope)
	}
}

var knownActions = []string{"pull", "push", "delete"}

// tryExtendExistingScope extends an existing scope if both the new scope and the current scope contain only knownActions.
// It returns true if actions are added or are already present. Otherwise, it returns false,
// indicating that the new scope should be appended to b.scopes instead.
func (b *bearerHandler) tryExtendExistingScope(scope string) bool {
	repo, actions, ok := parseScope(scope)
	if !ok {
		return false
	}
	scopePrefix := "repository:" + repo + ":"
	for i, cur := range b.scopes {
		if !strings.HasPrefix(cur, scopePrefix) {
			continue
		}
		_, curActions, curOk := parseScope(cur)
		if !curOk {
			continue
		}

		for _, a := range actions {
			if !slices.Contains(curActions, a) {
				curActions = append(curActions, a)
			}
		}
		b.scopes[i] = scopePrefix + strings.Join(curActions, ",")
		return true
	}
	return false
}

// parseScope splits a scope into the repo and slice of actions.
// Unknown actions in the scope will set bool to false.
func parseScope(scope string) (string, []string, bool) {
	scopeSplit := strings.SplitN(scope, ":", 3)
	if scopeSplit[0] != "repository" || len(scopeSplit) < 3 {
		return "", nil, false
	}
	actionSplit := strings.Split(scopeSplit[2], ",")
	for _, a := range actionSplit {
		if !slices.Contains(knownActions, a) {
			return "", nil, false
		}
	}
	return scopeSplit[1], actionSplit, true
}

// bearerKeyLocked builds the cache key for the current realm, service, and scopes
func (b *bearerHandler) bearerKeyLocked() bearerKey {
	scopes := slices.Clone(b.scopes)
	slices.Sort(scopes)
	scopes = slices.DeleteFunc(scopes, func(s string) bool { return s == "" })
	return bearerKey{
		host:    b.host,
		realm:   b.realm,
		service: b.service,
		scopes:  strings.Join(scopes, " "),
	}
}

// resolveLocked looks up or creates the entry for the current identity,
// carrying over the refresh token from the previous entry. A changed
// identity starts a new generation. The caller must hold b.mu.
func (b *bearerHandler) resolveLocked() *bearerEntry {
	key := b.bearerKeyLocked()
	if e, ok := b.entries[key]; ok {
		if b.cur != e {
			b.cur = e
			b.generation++
		}
		return e
	}
	e := &bearerEntry{
		key:    key,
		scopes: slices.Clone(b.scopes),
	}
	// refresh tokens may be reused across scope sets within a realm
	if b.cur != nil {
		if rt := b.cur.refreshTokenLocked(); rt != "" {
			e.token.RefreshToken = rt
		}
	}
	b.entries[key] = e
	b.cur = e
	b.generation++
	return e
}

// ProcessChallenge handles WWW-Authenticate header for bearer tokens
// Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:samalba/my-app:pull,push"
func (b *bearerHandler) ProcessChallenge(c challenge) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := c.params["realm"]; !ok {
		return errs.ErrInvalidChallenge
	}
	if _, ok := c.params["service"]; !ok {
		c.params["service"] = ""
	}
	if _, ok := c.params["scope"]; !ok {
		c.params["scope"] = ""
	}

	// a changed realm or service is a distinct token identity, e.g. the
	// same image reached through mirrors fronting different auth servers
	realmChanged := b.realm != "" && b.realm != c.params["realm"]
	serviceChanged := b.service != "" && b.service != c.params["service"]
	if realmChanged || serviceChanged {
		b.realm = c.params["realm"]
		b.service = c.params["service"]
		b.scopes = []string{}
		if c.params["scope"] != "" {
			b.addScope(c.params["scope"])
		}
		// previous entries stay cached for requests already in flight
		b.resolveLocked()
		return nil
	}

	existingScope := b.scopeExists(c.params["scope"])
	sameIdentity := b.realm == c.params["realm"] &&
		b.service == c.params["service"] &&
		existingScope &&
		b.cur != nil &&
		b.cur.usable()
	if sameIdentity {
		return errs.ErrNoNewChallenge
	}

	if b.realm == "" {
		b.realm = c.params["realm"]
	}
	if b.service == "" {
		b.service = c.params["service"]
	}
	if !existingScope {
		b.addScope(c.params["scope"])
	}
	// new or expired identity: start the next generation, previous entries
	// remain cached for requests already in flight
	b.resolveLocked()
	return nil
}

// UpdateRequest satisfies the handler interface; the bearer handler makes
// outbound calls and is always invoked through UpdateRequestAsync.
func (b *bearerHandler) UpdateRequest(req *http.Request) error {
	return b.UpdateRequestAsync(req)
}

// UpdateRequestAsync adds a bearer token to the request, coalescing
// concurrent refreshes for the same identity. It runs without the Auth
// mutex and uses its own locking.
func (b *bearerHandler) UpdateRequestAsync(req *http.Request) error {
	b.mu.Lock()
	if b.realm == "" || b.cur == nil {
		b.mu.Unlock()
		return errs.ErrHTTPUnauthorized
	}
	e := b.cur
	realm := b.realm
	b.mu.Unlock()

	// resolve the token URL once per identity, under the entry lock
	e.refreshMu.Lock()
	if e.tokenURL == nil {
		u, err := req.URL.Parse(realm)
		if err != nil {
			e.refreshMu.Unlock()
			return err
		}
		e.tokenURL = u
	}
	tokenURL := e.tokenURL
	e.refreshMu.Unlock()

	// verify tokenURL is allowed for request URL
	if err := regnet.AllowRedirect(*req.URL, *tokenURL); err != nil {
		return err
	}

	if err := e.ensureToken(b, req); err != nil {
		return err
	}
	e.refreshMu.Lock()
	token := e.token.Token
	e.refreshMu.Unlock()
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	return nil
}

// ensureToken returns a usable token for the entry, merging concurrent
// refresh calls into a single outbound request. A caller canceling its own
// request does not cancel the shared refresh. All reads and writes of the
// cached token are guarded by refreshMu.
func (e *bearerEntry) ensureToken(b *bearerHandler, req *http.Request) error {
	e.refreshMu.Lock()
	if e.token.Token != "" && !e.isExpiredLocked() {
		e.refreshMu.Unlock()
		return nil
	}
	if e.done != nil {
		// another caller is already refreshing this identity
		done := e.done
		e.refreshMu.Unlock()
		select {
		case <-done:
		case <-req.Context().Done():
			return req.Context().Err()
		}
		e.refreshMu.Lock()
		err := e.err
		usable := e.token.Token != "" && !e.isExpiredLocked()
		e.refreshMu.Unlock()
		if err != nil {
			return err
		}
		if !usable {
			return errs.ErrHTTPUnauthorized
		}
		return nil
	}
	// leader: run the refresh without the entry lock so waiters can join
	done := make(chan struct{})
	e.done = done
	e.refreshMu.Unlock()

	// detach from the leader's request context: the shared result must
	// survive an individual caller canceling
	ctx := context.WithoutCancel(req.Context())
	err := e.fetchToken(b, ctx)

	e.refreshMu.Lock()
	e.err = err
	e.done = nil
	close(done)
	e.refreshMu.Unlock()
	if err != nil {
		return err
	}
	return nil
}

// isExpired returns true when token issue date is either 0, token has expired,
// or will expire within buffer time. Caller must hold refreshMu.
func (e *bearerEntry) isExpiredLocked() bool {
	if e.token.IssuedAt.IsZero() {
		return true
	}
	expireSec := e.token.IssuedAt.Add(time.Duration(e.token.ExpiresIn) * time.Second)
	expireSec = expireSec.Add(tokenBuffer * -1)
	return time.Now().After(expireSec)
}

// isExpired locks the entry before evaluating expiry.
func (e *bearerEntry) isExpired() bool {
	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	return e.isExpiredLocked()
}

// usable reports whether the entry holds a non-empty, unexpired token.
func (e *bearerEntry) usable() bool {
	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	return e.token.Token != "" && !e.isExpiredLocked()
}

// refreshTokenLocked returns the current refresh token under the entry lock.
func (e *bearerEntry) refreshTokenLocked() string {
	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	return e.token.RefreshToken
}

// isExpired helper retained on the handler for the cached current entry
func (b *bearerHandler) isExpired() bool {
	if b.cur == nil {
		return true
	}
	return b.cur.isExpired()
}

// fetchToken performs one refresh round for the entry, trying methods in a
// fixed priority: authenticated POST (refresh/password), then authenticated
// GET (basic), then an anonymous GET. Each method is attempted at most once
// within the round, so a failed authentication is retried once rather than
// hammered; a later expiry triggers a fresh round.
func (e *bearerEntry) fetchToken(b *bearerHandler, ctx context.Context) error {
	cred := b.credsFn(b.host)
	e.refreshMu.Lock()
	refreshToken := e.token.RefreshToken
	e.refreshMu.Unlock()
	hasCred := cred.User != "" && cred.Password != ""
	canPost := refreshToken != "" || cred.Token != ""
	canAuthGet := hasCred
	canAnon := !hasCred && cred.Token == ""

	if canPost {
		if err := e.tryPost(b, ctx, cred, refreshToken); err == nil {
			return nil
		} else if err != errs.ErrHTTPUnauthorized {
			return fmt.Errorf("failed to request auth token (post): %w%.0w", err, errs.ErrHTTPUnauthorized)
		}
	}
	if canAuthGet {
		if err := e.tryGet(b, ctx, cred); err == nil {
			return nil
		} else if err != errs.ErrHTTPUnauthorized {
			return fmt.Errorf("failed to request auth token (get): %w%.0w", err, errs.ErrHTTPUnauthorized)
		}
	}
	if canAnon {
		if err := e.tryGet(b, ctx, Cred{}); err == nil {
			return nil
		} else if err != errs.ErrHTTPUnauthorized {
			return fmt.Errorf("failed to request auth token (anonymous get): %w%.0w", err, errs.ErrHTTPUnauthorized)
		}
	}
	return errs.ErrHTTPUnauthorized
}

// tryGet requests a new token with a GET request
func (e *bearerEntry) tryGet(b *bearerHandler, ctx context.Context, cred Cred) error {
	//#nosec G704 inputs follow specification
	req, err := http.NewRequestWithContext(ctx, "GET", e.tokenURL.String(), nil)
	if err != nil {
		return err
	}

	reqParams := req.URL.Query()
	reqParams.Add("client_id", b.clientID)
	// Note, an offline_token should not be requested by default due to broken OAuth2 implementations returning an invalid token
	if b.service != "" {
		reqParams.Add("service", b.service)
	}

	for _, s := range e.scopes {
		reqParams.Add("scope", s)
	}

	if cred.User != "" && cred.Password != "" {
		reqParams.Add("account", cred.User)
		req.SetBasicAuth(cred.User, cred.Password)
	}

	req.Header.Add("User-Agent", b.clientID)
	req.URL.RawQuery = reqParams.Encode()

	//#nosec G704 inputs follow specification
	resp, err := b.client.Do(req)
	if err != nil {
		b.slog.Debug("Auth token GET failed",
			slog.String("host", b.host),
			slog.String("url", redactURL(e.tokenURL.String())),
			slog.String("err", redactError(err).Error()))
		return err
	}
	defer resp.Body.Close()

	return e.validateResponse(b, resp)
}

// tryPost requests a new token via a POST request
func (e *bearerEntry) tryPost(b *bearerHandler, ctx context.Context, cred Cred, refreshToken string) error {
	form := url.Values{}
	if len(e.scopes) > 0 {
		form.Set("scope", strings.Join(e.scopes, " "))
	}
	if b.service != "" {
		form.Set("service", b.service)
	}
	form.Set("client_id", b.clientID)
	if refreshToken != "" {
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)
	} else if cred.Token != "" {
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", cred.Token)
	} else if cred.User != "" && cred.Password != "" {
		form.Set("grant_type", "password")
		form.Set("username", cred.User)
		form.Set("password", cred.Password)
	}

	//#nosec G704 inputs are user controlled or follow specification
	req, err := http.NewRequestWithContext(ctx, "POST", e.tokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Add("User-Agent", b.clientID)

	//#nosec G704 inputs are user controlled or follow specification
	resp, err := b.client.Do(req)
	if err != nil {
		b.slog.Debug("Auth token POST failed",
			slog.String("host", b.host),
			slog.String("url", redactURL(e.tokenURL.String())),
			slog.String("err", redactError(err).Error()))
		return err
	}
	defer resp.Body.Close()

	return e.validateResponse(b, resp)
}

// scopeExists check if the scope already exists within the list of scopes
func (b *bearerHandler) scopeExists(search string) bool {
	if search == "" {
		return true
	}
	searchRepo, searchActions, searchOk := parseScope(search)
	if !searchOk {
		return slices.Contains(b.scopes, search)
	}
	scopePrefix := "repository:" + searchRepo + ":"
	for _, scope := range b.scopes {
		if scope == search {
			return true
		}
		if !strings.HasPrefix(scope, scopePrefix) {
			continue
		}
		_, actions, ok := parseScope(scope)
		if !ok {
			continue
		}

		for _, sa := range searchActions {
			if !slices.Contains(actions, sa) {
				return false
			}
		}
		return true

	}
	return false
}

// validateResponse extracts the returned token
func (e *bearerEntry) validateResponse(b *bearerHandler, resp *http.Response) error {
	if resp.StatusCode != 200 {
		return errs.ErrHTTPUnauthorized
	}

	// decode response before taking the entry lock
	decoder := json.NewDecoder(resp.Body)
	decoded := bearerToken{}
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}

	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	if decoded.RefreshToken == "" {
		// preserve a previously issued refresh token when the response omits one
		decoded.RefreshToken = e.token.RefreshToken
	}
	e.token = decoded

	if e.token.ExpiresIn < minTokenLife {
		e.token.ExpiresIn = minTokenLife
	}

	// If token is already expired, it was sent with a zero value or
	// there may be a clock skew between the client and auth server.
	// Also handle cases of remote time in the future.
	// But if remote time is slightly in the past, leave as is so token
	// expires here before the server.
	if e.isExpiredLocked() || e.token.IssuedAt.After(time.Now()) {
		e.token.IssuedAt = time.Now().UTC()
	}

	// AccessToken and Token should be the same and we use Token elsewhere
	if e.token.AccessToken != "" {
		e.token.Token = e.token.AccessToken
	}

	b.slog.Debug("Auth token received",
		slog.String("host", b.host),
		slog.String("realm", e.key.realm),
		slog.String("service", e.key.service),
		slog.Uint64("generation", b.generation))

	return nil
}

// jwtHubHandler supports JWT auth type requests.
type jwtHubHandler struct {
	client   *http.Client
	clientID string
	realm    string
	host     string
	credsFn  CredsFn
	jwt      string
}

type jwtHubPost struct {
	User string `json:"username"`
	Pass string `json:"password"` //#nosec G117 exported struct intentionally holds secrets
}
type jwtHubResp struct {
	Detail       string `json:"detail"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"` //#nosec G117 exported struct intentionally holds secrets
}

// NewJWTHubHandler creates a new JWTHandler for Docker Hub.
func NewJWTHubHandler(client *http.Client, clientID, host string, credsFn CredsFn, slog *slog.Logger) handler {
	// JWT handler is only tested against Hub, and the API is Hub specific
	if host == "hub.docker.com" {
		return &jwtHubHandler{
			client:   client,
			clientID: clientID,
			host:     host,
			credsFn:  credsFn,
			realm:    "https://hub.docker.com/v2/users/login",
		}
	}
	return nil
}

// AddScope is not valid for JWTHubHandler
func (j *jwtHubHandler) AddScope(scope string) error {
	return errs.ErrNoNewChallenge
}

// ProcessChallenge handles WWW-Authenticate header for JWT auth on Docker Hub
func (j *jwtHubHandler) ProcessChallenge(c challenge) error {
	cred := j.credsFn(j.host)
	// use token if provided
	if cred.Token != "" {
		j.jwt = cred.Token
		return nil
	}

	// send a login request to hub
	bodyBytes, err := json.Marshal(jwtHubPost{
		User: cred.User,
		Pass: cred.Password, //#nosec G117 field name follows spec
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", j.realm, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", j.clientID)

	//#nosec G704 inputs are user controlled or follow specification requirements
	resp, err := j.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.StatusCode >= 300 {
		return errs.ErrHTTPUnauthorized
	}

	var bodyParsed jwtHubResp
	err = json.NewDecoder(resp.Body).Decode(&bodyParsed)
	if err != nil {
		return err
	}
	j.jwt = bodyParsed.Token

	return nil
}

// UpdateRequest for JWTHubHandler adds JWT header
func (j *jwtHubHandler) UpdateRequest(req *http.Request) error {
	if len(j.jwt) > 0 {
		req.Header.Set("Authorization", fmt.Sprintf("JWT %s", j.jwt))
		return nil
	}
	return errs.ErrHTTPUnauthorized
}
