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
		{"repo not in policy", Request{Tenant: "acme", Org: "acme", Repo: "ghost", Endpoint: EndpointGitRead}, false},
		{"none access denies read", Request{Tenant: "acme", Org: "acme", Repo: "locked", Endpoint: EndpointGitRead}, false},
		{"unknown tenant", Request{Tenant: "other", Repo: "app"}, false},
		{"org mismatch", Request{Tenant: "acme", Org: "evil", Repo: "app", Endpoint: EndpointGitRead}, false},
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
