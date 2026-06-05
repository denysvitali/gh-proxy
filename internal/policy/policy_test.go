// Coverage goal: push internal/policy from 68% to 95%+ by covering the
// remaining branches in Document.Validate (missing version, duplicate
// tenant / consumer, dot in consumer id, empty token_hashes, missing
// installation_id, invalid Access) and the Engine surface (Snapshot,
// Consumer, Replace). A testing.F fuzz target seeds Document.Validate
// with a small corpus and lets `go test -fuzz` explore further.
package policy

import (
	"testing"
)

func baseDoc() *Document {
	return &Document{
		Version: 1,
		Tenants: []Tenant{{
			Name:           "acme",
			InstallationID: 42,
			Org:            "acme",
			Repos: []Repo{
				{Name: "app", Access: AccessRead, Endpoints: []EndpointClass{EndpointGitRead, EndpointWorkflows}},
				{Name: "infra", Access: AccessWrite, Endpoints: []EndpointClass{"*"}},
				{Name: "locked", Access: AccessNone},
			},
		}},
		Consumers: []Consumer{{ID: "ci", Tenant: "acme", TokenHashes: []string{"$2a$10$dummy"}}},
	}
}

func TestValidate(t *testing.T) {
	if err := baseDoc().Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownTenantForConsumer(t *testing.T) {
	d := baseDoc()
	d.Consumers[0].Tenant = "nope"
	if err := d.Validate(); err == nil {
		t.Fatal("expected error for unknown tenant reference")
	}
}

func TestEvaluate(t *testing.T) {
	e := NewEngine(baseDoc())

	cases := []struct {
		name string
		req  Request
		want bool
	}{
		{"read allowed", Request{Tenant: "acme", Org: "acme", Repo: "app", Endpoint: EndpointGitRead}, true},
		{"write denied on read repo", Request{Tenant: "acme", Org: "acme", Repo: "app", Write: true, Endpoint: EndpointGitWrite}, false},
		{"endpoint not allowed", Request{Tenant: "acme", Org: "acme", Repo: "app", Endpoint: EndpointPullRequest}, false},
		{"wildcard endpoints", Request{Tenant: "acme", Org: "acme", Repo: "infra", Write: true, Endpoint: EndpointPullRequest}, true},
		{"repo not in policy, read allowed", Request{Tenant: "acme", Org: "acme", Repo: "ghost", Endpoint: EndpointGitRead}, true},
		{"repo not in policy, write denied", Request{Tenant: "acme", Org: "acme", Repo: "ghost", Write: true, Endpoint: EndpointGitWrite}, false},
		{"none access denies read", Request{Tenant: "acme", Org: "acme", Repo: "locked", Endpoint: EndpointGitRead}, false},
		{"unknown tenant", Request{Tenant: "other", Repo: "app"}, false},
		{"org mismatch read allowed", Request{Tenant: "acme", Org: "evil", Repo: "app", Endpoint: EndpointGitRead}, true},
		{"org mismatch write denied", Request{Tenant: "acme", Org: "evil", Repo: "app", Write: true, Endpoint: EndpointGitWrite}, false},
		{"org mismatch repo not in policy read allowed", Request{Tenant: "acme", Org: "evil", Repo: "ghost", Endpoint: EndpointGitRead}, true},
		{"org mismatch repo not in policy write denied", Request{Tenant: "acme", Org: "evil", Repo: "ghost", Write: true, Endpoint: EndpointGitWrite}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := e.Evaluate(c.req)
			if got.Allowed != c.want {
				t.Fatalf("allowed=%v reason=%q, want %v", got.Allowed, got.Reason, c.want)
			}
		})
	}
}

// TestEvaluateWildcardRepoFallback verifies the "match exact first, then *"
// order. A repo with the same name as the wildcard should win over the
// wildcard, and a repo that does not exist should fall through to the
// wildcard rule if one is configured.
func TestEvaluateWildcardRepoFallback(t *testing.T) {
	d := &Document{
		Version: 1,
		Tenants: []Tenant{{
			Name:           "acme",
			InstallationID: 1,
			Org:            "acme",
			Repos: []Repo{
				{Name: "app", Access: AccessRead, Endpoints: []EndpointClass{EndpointGitRead}},
				{Name: "*", Access: AccessWrite, Endpoints: []EndpointClass{"*"}},
			},
		}},
	}
	e := NewEngine(d)

	// Exact match takes precedence.
	if !e.Evaluate(Request{Tenant: "acme", Org: "acme", Repo: "app", Endpoint: EndpointGitRead}).Allowed {
		t.Fatal("exact match should be allowed")
	}
	if e.Evaluate(Request{Tenant: "acme", Org: "acme", Repo: "app", Write: true, Endpoint: EndpointGitWrite}).Allowed {
		t.Fatal("exact-match read-only repo should deny writes (not fall through to *)")
	}
	// Unmatched repo falls through to wildcard.
	if !e.Evaluate(Request{Tenant: "acme", Org: "acme", Repo: "ghost", Write: true, Endpoint: EndpointGitWrite}).Allowed {
		t.Fatal("unmatched repo should fall through to wildcard allow")
	}
}

// TestEvaluateEmptyEndpointClass asserts that an empty Endpoint string
// in the request skips the endpoint check (so a caller may opt out of
// endpoint-class enforcement by passing "").
func TestEvaluateEmptyEndpointClass(t *testing.T) {
	e := NewEngine(baseDoc())
	// Endpoint is "" → endpoint check is skipped; only access matters.
	if !e.Evaluate(Request{Tenant: "acme", Org: "acme", Repo: "app", Endpoint: ""}).Allowed {
		t.Fatal("empty endpoint should skip the endpoint check")
	}
	// "locked" has AccessNone, so even with an empty endpoint it's denied.
	if e.Evaluate(Request{Tenant: "acme", Org: "acme", Repo: "locked", Endpoint: ""}).Allowed {
		t.Fatal("AccessNone should still deny with empty endpoint")
	}
}

func TestValidate_Errors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Document)
		wantSub string
	}{
		{
			name:    "missing version",
			mutate:  func(d *Document) { d.Version = 0 },
			wantSub: "version is required",
		},
		{
			name: "duplicate tenant name",
			mutate: func(d *Document) {
				d.Tenants = append(d.Tenants, d.Tenants[0])
			},
			wantSub: `duplicate tenant "acme"`,
		},
		{
			name: "tenant missing name",
			mutate: func(d *Document) {
				d.Tenants[0].Name = ""
			},
			wantSub: "tenant missing name",
		},
		{
			name: "tenant missing installation_id",
			mutate: func(d *Document) {
				d.Tenants[0].InstallationID = 0
			},
			wantSub: "missing installation_id",
		},
		{
			name: "invalid access value",
			mutate: func(d *Document) {
				d.Tenants[0].Repos[0].Access = "super"
			},
			wantSub: `invalid access "super"`,
		},
		{
			name: "duplicate consumer id",
			mutate: func(d *Document) {
				d.Consumers = append(d.Consumers, d.Consumers[0])
			},
			wantSub: `duplicate consumer "ci"`,
		},
		{
			name: "consumer id contains dot",
			mutate: func(d *Document) {
				d.Consumers[0].ID = "has.dot"
			},
			wantSub: "must not contain '.'",
		},
		{
			name: "consumer id is empty",
			mutate: func(d *Document) {
				d.Consumers[0].ID = ""
			},
			wantSub: "consumer missing id",
		},
		{
			name: "consumer has no token_hashes",
			mutate: func(d *Document) {
				d.Consumers[0].TokenHashes = nil
			},
			wantSub: "no token_hashes",
		},
		{
			name: "valid consumer id (no dot)",
			mutate: func(d *Document) {
				d.Consumers[0].ID = "ci-runner"
			},
			wantSub: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := cloneDoc(baseDoc())
			c.mutate(d)
			err := d.Validate()
			if c.wantSub == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantSub)
			}
			if !contains(err.Error(), c.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), c.wantSub)
			}
		})
	}
}

func cloneDoc(d *Document) *Document {
	out := &Document{Version: d.Version}
	for _, t := range d.Tenants {
		clone := Tenant{Name: t.Name, InstallationID: t.InstallationID, Org: t.Org}
		clone.Repos = append([]Repo(nil), t.Repos...)
		out.Tenants = append(out.Tenants, clone)
	}
	for _, c := range d.Consumers {
		clone := Consumer{ID: c.ID, Tenant: c.Tenant}
		clone.TokenHashes = append([]string(nil), c.TokenHashes...)
		out.Consumers = append(out.Consumers, clone)
	}
	return out
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	}())
}

func TestSnapshot(t *testing.T) {
	e := NewEngine(nil)
	if e.Snapshot() != nil {
		t.Fatal("nil engine should return nil snapshot")
	}
	d := baseDoc()
	e.Replace(d)
	got := e.Snapshot()
	if got == nil {
		t.Fatal("snapshot should be non-nil after Replace")
	}
	// Mutating the returned doc must not affect the engine's view; the
	// returned pointer is the underlying doc, not a copy. Documenting the
	// current behaviour: Snapshot returns a shallow pointer.
	if got.Version != 1 {
		t.Fatalf("snapshot version=%d want 1", got.Version)
	}
}

func TestConsumer_Lookup(t *testing.T) {
	e := NewEngine(baseDoc())
	if c, ok := e.Consumer("ci"); !ok || c.ID != "ci" {
		t.Fatalf("lookup ci: got (%+v, %v)", c, ok)
	}
	if _, ok := e.Consumer("ghost"); ok {
		t.Fatal("ghost should not exist")
	}
	e2 := NewEngine(nil)
	if _, ok := e2.Consumer("ci"); ok {
		t.Fatal("nil engine should not find any consumer")
	}
}

func TestReplace(t *testing.T) {
	e := NewEngine(baseDoc())
	if _, ok := e.Tenant("acme"); !ok {
		t.Fatal("acme should exist before Replace")
	}
	// Swap in a different document.
	e.Replace(&Document{Version: 1, Tenants: []Tenant{{Name: "other", InstallationID: 1}}})
	if _, ok := e.Tenant("acme"); ok {
		t.Fatal("acme should not exist after Replace")
	}
	if _, ok := e.Tenant("other"); !ok {
		t.Fatal("other should exist after Replace")
	}
	// Replace(nil) wipes the engine.
	e.Replace(nil)
	if got := e.Snapshot(); got != nil {
		t.Fatal("snapshot should be nil after Replace(nil)")
	}
}

// TestFuzzValidate is a fuzz target for Document.Validate. Validators are
// classic fuzz targets: the function is small, structured, and easy to
// crash with a struct field combination the author didn't think of.
//
// Run with: go test -fuzz=FuzzValidate -run=^$ ./internal/policy
func FuzzValidate(f *testing.F) {
	// Seed with a few interesting mutations.
	f.Add(int64(0), "acme", "acme", "ci", "acme", "hash")
	f.Add(int64(42), "acme", "acme", "ci", "acme", "hash")
	f.Add(int64(1), "", "acme", "ci", "acme", "hash")
	f.Add(int64(1), "acme", "acme", "", "acme", "hash")
	f.Add(int64(1), "acme", "acme", "has.dot", "acme", "hash")
	f.Add(int64(1), "acme", "acme", "ci", "missing", "hash")

	f.Fuzz(func(_ *testing.T, installID int64, tenantName, org, consumerID, consumerTenant, tokenHash string) {
		d := &Document{
			Version: 1,
			Tenants: []Tenant{{
				Name:           tenantName,
				InstallationID: installID,
				Org:            org,
				Repos: []Repo{
					{Name: "app", Access: AccessRead, Endpoints: []EndpointClass{EndpointGitRead}},
					{Name: "infra", Access: AccessWrite, Endpoints: []EndpointClass{"*"}},
					{Name: "locked", Access: AccessNone},
				},
			}},
			Consumers: []Consumer{{
				ID:          consumerID,
				Tenant:      consumerTenant,
				TokenHashes: []string{tokenHash},
			}},
		}

		// The fuzz target is just: do not panic. If Validate returns an
		// error, fine. If it returns nil, Evaluate must also be safe.
		if err := d.Validate(); err != nil {
			return
		}
		eng := NewEngine(d)
		// A handful of representative evaluations.
		_ = eng.Evaluate(Request{Tenant: tenantName, Org: org, Repo: "app", Endpoint: EndpointGitRead})
		_ = eng.Evaluate(Request{Tenant: tenantName, Org: org, Repo: "app", Write: true, Endpoint: EndpointGitWrite})
		_ = eng.Evaluate(Request{Tenant: "missing", Org: org, Repo: "app", Endpoint: EndpointGitRead})
	})
}
