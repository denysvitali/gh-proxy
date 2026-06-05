package policy

import "testing"

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

// TestEvaluatePRSubclasses covers the api.pulls.* split. The legacy
// `api.pulls` class is preserved as a backwards-compatible umbrella for
// reads, creates, and reviews; `api.pulls.merge` is opt-in only.
func TestEvaluatePRSubclasses(t *testing.T) {
	doc := &Document{
		Version: 1,
		Tenants: []Tenant{{
			Name:           "acme",
			InstallationID: 1,
			Org:            "acme",
			Repos: []Repo{
				// Legacy: only lists api.pulls. Should still allow reads,
				// creates, and reviews — but NOT merge.
				{Name: "legacy", Access: AccessWrite, Endpoints: []EndpointClass{EndpointPullRequest}},
				// New style: explicit per-class. Should allow merge.
				{Name: "modern", Access: AccessWrite, Endpoints: []EndpointClass{EndpointPullsMerge}},
				// Strict: only review class — no read, no create, no merge.
				{Name: "reviewers", Access: AccessWrite, Endpoints: []EndpointClass{EndpointPullsReview}},
				// Wildcard tenant — gets everything, including merge.
				{Name: "wild", Access: AccessWrite, Endpoints: []EndpointClass{"*"}},
			},
		}},
		Consumers: []Consumer{{ID: "ci", Tenant: "acme", TokenHashes: []string{"x"}}},
	}
	e := NewEngine(doc)

	cases := []struct {
		repo string
		req  Request
		want bool
		why  string
	}{
		{"legacy", Request{Tenant: "acme", Repo: "legacy", Endpoint: EndpointPullRequest}, true, "read allowed via api.pulls"},
		{"legacy", Request{Tenant: "acme", Repo: "legacy", Write: true, Endpoint: EndpointPullsCreate}, true, "create allowed via api.pulls umbrella"},
		{"legacy", Request{Tenant: "acme", Repo: "legacy", Write: true, Endpoint: EndpointPullsReview}, true, "review allowed via api.pulls umbrella"},
		{"legacy", Request{Tenant: "acme", Repo: "legacy", Write: true, Endpoint: EndpointPullsMerge}, false, "merge NOT allowed via api.pulls umbrella"},

		{"modern", Request{Tenant: "acme", Repo: "modern", Write: true, Endpoint: EndpointPullsMerge}, true, "explicit merge allowed"},
		{"modern", Request{Tenant: "acme", Repo: "modern", Endpoint: EndpointPullRequest}, false, "read NOT implied by merge class"},
		{"modern", Request{Tenant: "acme", Repo: "modern", Write: true, Endpoint: EndpointPullsCreate}, false, "create NOT implied by merge class"},

		{"reviewers", Request{Tenant: "acme", Repo: "reviewers", Write: true, Endpoint: EndpointPullsReview}, true, "explicit review allowed"},
		{"reviewers", Request{Tenant: "acme", Repo: "reviewers", Write: true, Endpoint: EndpointPullsCreate}, false, "create NOT implied by review class"},
		{"reviewers", Request{Tenant: "acme", Repo: "reviewers", Write: true, Endpoint: EndpointPullsMerge}, false, "merge NOT implied by review class"},

		// Wildcard still grants everything, including merge.
		{"wild", Request{Tenant: "acme", Repo: "wild", Write: true, Endpoint: EndpointPullsMerge}, true, "* includes merge"},
		{"wild", Request{Tenant: "acme", Repo: "wild", Write: true, Endpoint: EndpointPullsReview}, true, "* includes review"},
	}
	for _, c := range cases {
		got := e.Evaluate(c.req)
		if got.Allowed != c.want {
			t.Errorf("%s: %s: allowed=%v reason=%q, want %v", c.repo, c.why, got.Allowed, got.Reason, c.want)
		}
	}
}
