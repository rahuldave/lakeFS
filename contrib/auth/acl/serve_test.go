package acl_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/treeverse/lakefs/contrib/auth/acl"
	authtestutil "github.com/treeverse/lakefs/contrib/auth/acl/testutil"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/logging"
)

var adminStatement = map[string]any{"effect": "allow", "resource": "*",
	"action": []string{"fs:*", "auth:*", "ci:*", "retention:*", "branches:*", "pr:*"}}

func newServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	svc, _ := authtestutil.SetupService(t, t.Context(), []byte("some secret"))
	srv := httptest.NewServer(acl.Serve(svc, logging.Dummy(), token))
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, srv *httptest.Server, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestServeRequiresTheAPIToken(t *testing.T) {
	srv := newServer(t, "right-token")
	for _, token := range []string{"", "wrong-token", "right-tokenX", "right"} {
		if code, _ := call(t, srv, token, http.MethodGet, "/api/v1/auth/users", nil); code != http.StatusUnauthorized {
			t.Errorf("token %q: got %d, want 401", token, code)
		}
		if code, _ := call(t, srv, token, http.MethodPost, "/api/v1/auth/users", map[string]any{"username": "intruder"}); code != http.StatusUnauthorized {
			t.Errorf("token %q: making a user got %d, want 401", token, code)
		}
	}
	if code, _ := call(t, srv, "right-token", http.MethodGet, "/api/v1/auth/users", nil); code != http.StatusOK {
		t.Errorf("right token: got %d, want 200", code)
	}
	if code, _ := call(t, srv, "", http.MethodGet, "/_health", nil); code != http.StatusOK && code != http.StatusNoContent {
		t.Errorf("health check without a token: got %d", code)
	}
}

func TestServeWithoutATokenAcceptsEveryCaller(t *testing.T) {
	srv := newServer(t, "")
	if code, _ := call(t, srv, "", http.MethodGet, "/api/v1/auth/users", nil); code != http.StatusOK {
		t.Errorf("got %d, want 200", code)
	}
}

func TestServePolicyLifecycle(t *testing.T) {
	const tok = "tok"
	srv := newServer(t, tok)
	must := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		code, out := call(t, srv, tok, method, path, body)
		if code != want {
			t.Fatalf("%s %s: got %d (%v), want %d", method, path, code, out, want)
		}
		return out
	}
	names := func(out map[string]any) []string {
		var got []string
		for _, p := range out["results"].([]any) {
			got = append(got, p.(map[string]any)["name"].(string))
		}
		return got
	}
	has := func(list []string, name string) bool {
		for _, n := range list {
			if n == name {
				return true
			}
		}
		return false
	}
	policy := map[string]any{"name": "acme-repos", "statement": []any{map[string]any{
		"effect": "allow", "action": []string{"fs:*"}, "resource": "arn:lakefs:fs:::repository/acme-*"}}}
	must(http.MethodPost, "/api/v1/auth/policies", policy, http.StatusCreated)
	must(http.MethodPost, "/api/v1/auth/groups", map[string]any{"id": "acme"}, http.StatusCreated)
	must(http.MethodPost, "/api/v1/auth/users", map[string]any{"username": "acme-user"}, http.StatusCreated)

	if !has(names(must(http.MethodGet, "/api/v1/auth/policies", nil, http.StatusOK)), "acme-repos") {
		t.Fatal("ListPolicies does not show acme-repos")
	}
	if got := names(must(http.MethodGet, "/api/v1/auth/policies?prefix=zzz", nil, http.StatusOK)); len(got) != 0 {
		t.Fatalf("ListPolicies with prefix zzz = %v", got)
	}

	must(http.MethodPut, "/api/v1/auth/groups/acme/policies/acme-repos", nil, http.StatusCreated)
	must(http.MethodDelete, "/api/v1/auth/groups/acme/policies/acme-repos", nil, http.StatusNoContent)
	if got := names(must(http.MethodGet, "/api/v1/auth/groups/acme/policies", nil, http.StatusOK)); len(got) != 0 {
		t.Fatalf("group policies after detach = %v", got)
	}

	must(http.MethodPut, "/api/v1/auth/users/acme-user/policies/acme-repos", nil, http.StatusCreated)
	if !has(names(must(http.MethodGet, "/api/v1/auth/users/acme-user/policies", nil, http.StatusOK)), "acme-repos") {
		t.Fatal("user policies do not show acme-repos after attach")
	}
	must(http.MethodDelete, "/api/v1/auth/users/acme-user/policies/acme-repos", nil, http.StatusNoContent)
	if got := names(must(http.MethodGet, "/api/v1/auth/users/acme-user/policies", nil, http.StatusOK)); len(got) != 0 {
		t.Fatalf("user policies after detach = %v", got)
	}

	// Deleting a policy also removes it from the groups and users it was attached to.
	must(http.MethodPut, "/api/v1/auth/groups/acme/policies/acme-repos", nil, http.StatusCreated)
	must(http.MethodPut, "/api/v1/auth/users/acme-user/policies/acme-repos", nil, http.StatusCreated)
	must(http.MethodDelete, "/api/v1/auth/policies/acme-repos", nil, http.StatusNoContent)
	must(http.MethodGet, "/api/v1/auth/policies/acme-repos", nil, http.StatusNotFound)
	must(http.MethodDelete, "/api/v1/auth/policies/acme-repos", nil, http.StatusNotFound)
	if got := names(must(http.MethodGet, "/api/v1/auth/groups/acme/policies", nil, http.StatusOK)); len(got) != 0 {
		t.Fatalf("group policies after delete = %v", got)
	}
	if got := names(must(http.MethodGet, "/api/v1/auth/users/acme-user/policies", nil, http.StatusOK)); len(got) != 0 {
		t.Fatalf("user policies after delete = %v", got)
	}
}

func TestServeGuardsTheBuiltInPolicies(t *testing.T) {
	// Review 5, finding 1: deleting the Admins ACL policy locked the admin out.
	const tok = "tok"
	srv := newServer(t, tok)
	code := func(method, path string, body any) int {
		t.Helper()
		c, _ := call(t, srv, tok, method, path, body)
		return c
	}
	admins := "/api/v1/auth/policies/" + acl.PolicyName(acl.AdminsGroup)
	for _, g := range []string{acl.AdminsGroup, "Readers"} {
		if c := code(http.MethodPost, "/api/v1/auth/groups", map[string]any{"id": g}); c != http.StatusCreated {
			t.Fatalf("make group %s: %d", g, c)
		}
	}
	// Review 7, finding 6: an ACL policy name must name a group, or it could
	// become a policy that nothing can delete.
	orphan := map[string]any{"name": acl.PolicyName("NoSuchGroup"), "statement": []any{map[string]any{
		"effect": "deny", "action": []string{"fs:*"}, "resource": "*"}}}
	if c := code(http.MethodPost, "/api/v1/auth/policies", orphan); c != http.StatusBadRequest {
		t.Errorf("an ACL policy for no group: got %d, want 400", c)
	}
	// The Admins policy may be made, and written, only with the Admin statements.
	wrong := map[string]any{"name": acl.PolicyName(acl.AdminsGroup), "statement": []any{map[string]any{
		"effect": "allow", "action": []string{"fs:*"}, "resource": "*"}}}
	if c := code(http.MethodPost, "/api/v1/auth/policies", wrong); c != http.StatusBadRequest {
		t.Fatalf("make the Admins policy with other statements: got %d, want 400", c)
	}
	right := map[string]any{"name": acl.PolicyName(acl.AdminsGroup), "statement": []any{adminStatement}}
	if c := code(http.MethodPost, "/api/v1/auth/policies", right); c != http.StatusCreated {
		t.Fatalf("make the Admins policy: got %d, want 201", c)
	}
	if c := code(http.MethodPut, admins, map[string]any{"name": acl.PolicyName(acl.AdminsGroup), "statement": []any{adminStatement}}); c != http.StatusOK {
		t.Fatalf("restore the Admins policy: got %d, want 200", c)
	}
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodDelete, admins, nil},
		{http.MethodPut, admins, map[string]any{"name": acl.PolicyName(acl.AdminsGroup), "statement": []any{map[string]any{
			"effect": "allow", "action": []string{"fs:ReadRepository"}, "resource": "*"}}}},
		{http.MethodDelete, "/api/v1/auth/groups/Admins/policies/" + acl.PolicyName(acl.AdminsGroup), nil},
		{http.MethodDelete, "/api/v1/auth/policies/" + acl.PolicyName("Readers"), nil},
		{http.MethodDelete, "/api/v1/auth/groups/Readers/policies/" + acl.PolicyName("Readers"), nil},
		// Review 8: deleting Admins, or planting other statements in its policy.
		{http.MethodDelete, "/api/v1/auth/groups/Admins", nil},
		{http.MethodPut, admins, map[string]any{"name": acl.PolicyName(acl.AdminsGroup), "statement": []any{map[string]any{
			"effect": "deny", "action": []string{"fs:*"}, "resource": "*"}}}},
	} {
		if c := code(tc.method, tc.path, tc.body); c != http.StatusBadRequest {
			t.Errorf("%s %s: got %d, want 400", tc.method, tc.path, c)
		}
	}
}

func TestDeletedPolicyLeavesNoAttachmentForANewPolicyOfTheSameName(t *testing.T) {
	// Review 5, finding 2: an attachment left behind came back with a new
	// policy of the same name.
	const tok = "tok"
	srv := newServer(t, tok)
	must := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		c, out := call(t, srv, tok, method, path, body)
		if c != want {
			t.Fatalf("%s %s: got %d, want %d", method, path, c, want)
		}
		return out
	}
	p := map[string]any{"name": "p", "statement": []any{map[string]any{
		"effect": "allow", "action": []string{"fs:*"}, "resource": "*"}}}
	must(http.MethodPost, "/api/v1/auth/groups", map[string]any{"id": "g"}, http.StatusCreated)
	must(http.MethodPost, "/api/v1/auth/users", map[string]any{"username": "u"}, http.StatusCreated)
	must(http.MethodPost, "/api/v1/auth/policies", p, http.StatusCreated)
	must(http.MethodPut, "/api/v1/auth/groups/g/policies/p", nil, http.StatusCreated)
	must(http.MethodPut, "/api/v1/auth/users/u/policies/p", nil, http.StatusCreated)
	must(http.MethodDelete, "/api/v1/auth/policies/p", nil, http.StatusNoContent)
	must(http.MethodPost, "/api/v1/auth/policies", p, http.StatusCreated)
	if got := must(http.MethodGet, "/api/v1/auth/groups/g/policies", nil, http.StatusOK)["results"].([]any); len(got) != 0 {
		t.Fatalf("group g got the new policy p back: %v", got)
	}
	if got := must(http.MethodGet, "/api/v1/auth/users/u/policies", nil, http.StatusOK)["results"].([]any); len(got) != 0 {
		t.Fatalf("user u got the new policy p back: %v", got)
	}
	// Attaching a policy that does not exist fails, and leaves nothing.
	must(http.MethodPut, "/api/v1/auth/groups/g/policies/gone", nil, http.StatusNotFound)
}

func TestRetriedDeleteRemovesLinksLeftBehind(t *testing.T) {
	// Review 6, finding A2: a delete that failed after removing the policy
	// record left links that nothing could remove.
	ctx := t.Context()
	svc, store := authtestutil.SetupService(t, ctx, []byte("some secret"))
	if _, err := svc.CreateGroup(ctx, &model.Group{DisplayName: "g"}); err != nil {
		t.Fatal(err)
	}
	p := &model.Policy{DisplayName: "p", Statement: model.Statements{{Effect: "allow", Action: []string{"fs:*"}, Resource: "*"}}}
	if err := svc.WritePolicy(ctx, p, false); err != nil {
		t.Fatal(err)
	}
	if err := svc.AttachPolicyToGroup(ctx, "p", "g"); err != nil {
		t.Fatal(err)
	}
	// The record goes, as in a delete that stopped before the links.
	if err := store.Delete(ctx, []byte(model.PartitionKey), model.PolicyPath("p")); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeletePolicy(ctx, "p"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("retried delete = %v, want not found", err)
	}
	if err := svc.WritePolicy(ctx, p, false); err != nil {
		t.Fatal(err)
	}
	got, _, err := svc.ListGroupPolicies(ctx, "g", &model.PaginationParams{Amount: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("group g got the new policy p from a link left behind: %v", got)
	}
}

func TestDeletedUserTakesItsKeys(t *testing.T) {
	// Review 7, finding 3: a new user of the same name got the old user's keys.
	ctx := t.Context()
	svc, _ := authtestutil.SetupService(t, ctx, []byte("some secret"))
	if _, err := svc.CreateUser(ctx, &model.User{Username: "u"}); err != nil {
		t.Fatal(err)
	}
	cred, err := svc.CreateCredentials(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteUser(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUser(ctx, &model.User{Username: "u"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetCredentials(ctx, cred.AccessKeyID); err == nil {
		t.Fatal("the old key works for the new user u")
	}
	got, _, err := svc.ListUserCredentials(ctx, "u", &model.PaginationParams{Amount: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("new user u has %d old keys", len(got))
	}
}

func TestAdminsPolicyCanBeDetachedFromAUser(t *testing.T) {
	// Review 7, finding 4: it could be attached to a user but never detached.
	const tok = "tok"
	srv := newServer(t, tok)
	policy := map[string]any{"name": acl.PolicyName(acl.AdminsGroup), "statement": []any{adminStatement}}
	for _, step := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPost, "/api/v1/auth/groups", map[string]any{"id": acl.AdminsGroup}, http.StatusCreated},
		{http.MethodPost, "/api/v1/auth/policies", policy, http.StatusCreated},
		{http.MethodPost, "/api/v1/auth/users", map[string]any{"username": "u"}, http.StatusCreated},
		{http.MethodPut, "/api/v1/auth/users/u/policies/" + acl.PolicyName(acl.AdminsGroup), nil, http.StatusCreated},
		{http.MethodDelete, "/api/v1/auth/users/u/policies/" + acl.PolicyName(acl.AdminsGroup), nil, http.StatusNoContent},
	} {
		if c, out := call(t, srv, tok, step.method, step.path, step.body); c != step.want {
			t.Fatalf("%s %s: got %d (%v), want %d", step.method, step.path, c, out, step.want)
		}
	}
}

func TestDeletedGroupTakesItsACLPolicy(t *testing.T) {
	// Review 8, finding 2: a deleted group's ACL policy stayed, unguarded.
	ctx := t.Context()
	svc, _ := authtestutil.SetupService(t, ctx, []byte("some secret"))
	if err := acl.SetupACLServer(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteGroup(ctx, acl.ReadersGroup); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetPolicy(ctx, acl.PolicyName(acl.ReadersGroup)); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("the Readers ACL policy outlived its group: %v", err)
	}
}
