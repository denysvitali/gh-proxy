// Package policy models the authorization policy loaded from Kubernetes
// ConfigMaps. Policy is evaluated at request time to decide whether a consumer
// may perform an operation on a given repository via a given endpoint class.
package policy

import (
	"fmt"
	"strings"
	"sync"
)

// Access is a repo-level access level.
type Access string

// Repo-level access levels.
const (
	AccessNone  Access = "none"
	AccessRead  Access = "read"
	AccessWrite Access = "write"
)

// EndpointClass names a coarse-grained GitHub capability rather than a
// specific URL. The proxy maps concrete requests to one of these classes
// before checking policy.
type EndpointClass string

// Known endpoint classes recognised by the proxy.
const (
	EndpointGitRead     EndpointClass = "git.read"
	EndpointGitWrite    EndpointClass = "git.write"
	EndpointWorkflows   EndpointClass = "actions.workflows"
	EndpointRefs        EndpointClass = "api.refs"
	EndpointPullRequest EndpointClass = "api.pulls"
)

// Document is the on-disk policy schema (one YAML file).
type Document struct {
	Version   int        `yaml:"version"`
	Tenants   []Tenant   `yaml:"tenants"`
	Consumers []Consumer `yaml:"consumers"`
}

// Tenant groups a GitHub App installation with its repo rules.
type Tenant struct {
	Name           string `yaml:"name"`
	InstallationID int64  `yaml:"installation_id"`
	Org            string `yaml:"org"`
	Repos          []Repo `yaml:"repos"`
}

// Repo describes per-repo access. Name may be "*" to match any repo in the org.
type Repo struct {
	Name      string          `yaml:"name"`
	Access    Access          `yaml:"access"`
	Endpoints []EndpointClass `yaml:"endpoints"`
}

// Consumer is an identity that authenticates with a static bearer token.
// Consumers are bound to a single tenant and carry one or more bcrypt hashes
// of the secret part of their token. The on-the-wire token has the form
// "<id>.<secret>"; the proxy looks up the consumer by id and bcrypt-compares
// the secret against TokenHashes.
type Consumer struct {
	ID          string   `yaml:"id"`
	Tenant      string   `yaml:"tenant"`
	TokenHashes []string `yaml:"token_hashes"`
}

// Validate checks the document is internally consistent.
func (d *Document) Validate() error {
	if d.Version == 0 {
		return fmt.Errorf("policy: version is required")
	}
	names := make(map[string]struct{}, len(d.Tenants))
	for _, t := range d.Tenants {
		if t.Name == "" {
			return fmt.Errorf("policy: tenant missing name")
		}
		if _, dup := names[t.Name]; dup {
			return fmt.Errorf("policy: duplicate tenant %q", t.Name)
		}
		names[t.Name] = struct{}{}
		if t.InstallationID == 0 {
			return fmt.Errorf("policy: tenant %q missing installation_id", t.Name)
		}
		for _, r := range t.Repos {
			switch r.Access {
			case AccessNone, AccessRead, AccessWrite:
			default:
				return fmt.Errorf("policy: tenant %q repo %q has invalid access %q", t.Name, r.Name, r.Access)
			}
		}
	}
	ids := make(map[string]struct{}, len(d.Consumers))
	for _, c := range d.Consumers {
		if c.ID == "" {
			return fmt.Errorf("policy: consumer missing id")
		}
		if strings.Contains(c.ID, ".") {
			return fmt.Errorf("policy: consumer id %q must not contain '.'", c.ID)
		}
		if _, dup := ids[c.ID]; dup {
			return fmt.Errorf("policy: duplicate consumer %q", c.ID)
		}
		ids[c.ID] = struct{}{}
		if _, ok := names[c.Tenant]; !ok {
			return fmt.Errorf("policy: consumer %q references unknown tenant %q", c.ID, c.Tenant)
		}
		if len(c.TokenHashes) == 0 {
			return fmt.Errorf("policy: consumer %q has no token_hashes", c.ID)
		}
	}
	return nil
}

// Snapshot returns a shallow copy of the current document for read-only use
// (e.g. startup logging). Returns nil if no document is loaded.
func (e *Engine) Snapshot() *Document {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.doc
}

// Consumer looks up a consumer by ID.
func (e *Engine) Consumer(id string) (*Consumer, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.doc == nil {
		return nil, false
	}
	for i := range e.doc.Consumers {
		if e.doc.Consumers[i].ID == id {
			return &e.doc.Consumers[i], true
		}
	}
	return nil, false
}

// Decision is the result of an authorization check.
type Decision struct {
	Allowed bool
	Reason  string
}

// Request describes what the caller wants to do.
type Request struct {
	Tenant   string
	Org      string
	Repo     string
	Write    bool
	Endpoint EndpointClass
}

// Engine evaluates Requests against a Document. It is safe for concurrent use;
// swap the underlying document via Replace.
type Engine struct {
	mu  sync.RWMutex
	doc *Document
}

// NewEngine constructs an Engine seeded with doc (may be nil).
func NewEngine(doc *Document) *Engine {
	return &Engine{doc: doc}
}

// Replace atomically swaps the policy document.
func (e *Engine) Replace(doc *Document) {
	e.mu.Lock()
	e.doc = doc
	e.mu.Unlock()
}

// Tenant looks up a tenant by name.
func (e *Engine) Tenant(name string) (*Tenant, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.doc == nil {
		return nil, false
	}
	for i := range e.doc.Tenants {
		if e.doc.Tenants[i].Name == name {
			return &e.doc.Tenants[i], true
		}
	}
	return nil, false
}

// Evaluate decides a request.
func (e *Engine) Evaluate(req Request) Decision {
	t, ok := e.Tenant(req.Tenant)
	if !ok {
		return Decision{false, "unknown tenant"}
	}
	if req.Org != "" && !strings.EqualFold(req.Org, t.Org) {
		return Decision{false, "org mismatch for tenant"}
	}
	repo := findRepo(t.Repos, req.Repo)
	if repo == nil {
		return Decision{false, "repo not in policy"}
	}
	if req.Write && repo.Access != AccessWrite {
		return Decision{false, "write not allowed"}
	}
	if !req.Write && repo.Access == AccessNone {
		return Decision{false, "read not allowed"}
	}
	if req.Endpoint != "" && !hasEndpoint(repo.Endpoints, req.Endpoint) {
		return Decision{false, fmt.Sprintf("endpoint %q not allowed", req.Endpoint)}
	}
	return Decision{true, ""}
}

func findRepo(repos []Repo, name string) *Repo {
	var wildcard *Repo
	for i := range repos {
		if repos[i].Name == name {
			return &repos[i]
		}
		if repos[i].Name == "*" {
			wildcard = &repos[i]
		}
	}
	return wildcard
}

func hasEndpoint(list []EndpointClass, want EndpointClass) bool {
	for _, e := range list {
		if e == want || e == "*" {
			return true
		}
	}
	return false
}
