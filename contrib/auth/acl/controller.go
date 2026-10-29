//nolint:stylecheck
package acl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-openapi/swag"
	"github.com/treeverse/lakefs/contrib/auth/apigen"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/logging"
)

// DefaultMaxPerPage is the maximum amount of results returned for paginated queries to the API
const DefaultMaxPerPage int = 1000

type Controller struct {
	Auth auth.Service
}

func NewController(authService auth.Service) *Controller {
	return &Controller{
		Auth: authService,
	}
}

func (c *Controller) GetCredentials(w http.ResponseWriter, r *http.Request, accessKeyId string) {
	ctx := r.Context()
	credentials, err := c.Auth.GetCredentials(ctx, accessKeyId)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "credentials not found")
		return
	}
	if c.handleAPIError(w, err) {
		return
	}
	response := apigen.CredentialsWithSecret{
		UserName:        swag.String(credentials.Username),
		AccessKeyId:     credentials.AccessKeyID,
		SecretAccessKey: credentials.SecretAccessKey,
		CreationDate:    credentials.IssuedDate.Unix(),
	}
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) GetExternalPrincipal(w http.ResponseWriter, _ *http.Request, _ apigen.GetExternalPrincipalParams) {
	writeError(w, http.StatusNotImplemented, "Not implemented")
}

func (c *Controller) ListGroups(w http.ResponseWriter, r *http.Request, params apigen.ListGroupsParams) {
	ctx := r.Context()
	groups, paginator, err := c.Auth.ListGroups(ctx, &model.PaginationParams{
		After:  swag.StringValue((*string)(params.After)),
		Prefix: swag.StringValue((*string)(params.Prefix)),
		Amount: paginationAmount(params.Amount),
	})
	if c.handleAPIError(w, err) {
		return
	}

	response := apigen.GroupList{
		Results: make([]apigen.Group, 0, len(groups)),
		Pagination: apigen.Pagination{
			HasMore:    paginator.NextPageToken != "",
			NextOffset: paginator.NextPageToken,
			Results:    paginator.Amount,
		},
	}

	for _, g := range groups {
		response.Results = append(response.Results, apigen.Group{
			Name:         g.DisplayName,
			Description:  g.Description,
			CreationDate: g.CreatedAt.Unix(),
		})
	}
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) CreateGroup(w http.ResponseWriter, r *http.Request, body apigen.CreateGroupJSONRequestBody) {
	ctx := r.Context()
	g, err := c.Auth.CreateGroup(ctx, &model.Group{
		CreatedAt:   time.Now().UTC(),
		DisplayName: body.Id,
		Description: body.Description,
	})
	if c.handleAPIError(w, err) {
		return
	}
	response := apigen.Group{
		CreationDate: g.CreatedAt.Unix(),
		Name:         g.DisplayName,
		Description:  g.Description,
	}
	writeResponse(w, http.StatusCreated, response)
}

func (c *Controller) DeleteGroup(w http.ResponseWriter, r *http.Request, groupID string) {
	if refuseBuiltInPolicy(w, groupID == AdminsGroup) {
		return
	}
	ctx := r.Context()
	err := c.Auth.DeleteGroup(ctx, groupID)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusNoContent, nil)
}

func (c *Controller) GetGroup(w http.ResponseWriter, r *http.Request, groupID string) {
	ctx := r.Context()
	g, err := c.Auth.GetGroup(ctx, groupID)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	if c.handleAPIError(w, err) {
		return
	}

	response := apigen.Group{
		Name:         g.DisplayName,
		CreationDate: g.CreatedAt.Unix(),
		Description:  g.Description,
	}
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) ListGroupMembers(w http.ResponseWriter, r *http.Request, groupID string, params apigen.ListGroupMembersParams) {
	ctx := r.Context()
	users, paginator, err := c.Auth.ListGroupUsers(ctx, groupID, &model.PaginationParams{
		After:  swag.StringValue((*string)(params.After)),
		Prefix: swag.StringValue((*string)(params.Prefix)),
		Amount: paginationAmount(params.Amount),
	})
	if c.handleAPIError(w, err) {
		return
	}
	response := apigen.UserList{
		Results: make([]apigen.User, 0, len(users)),
		Pagination: apigen.Pagination{
			HasMore:    paginator.NextPageToken != "",
			NextOffset: paginator.NextPageToken,
			Results:    paginator.Amount,
		},
	}
	for _, u := range users {
		response.Results = append(response.Results, apigen.User{
			Username:     u.Username,
			CreationDate: u.CreatedAt.Unix(),
			Email:        u.Email,
			FriendlyName: u.FriendlyName,
		})
	}
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) DeleteGroupMembership(w http.ResponseWriter, r *http.Request, groupID, userID string) {
	ctx := r.Context()
	err := c.Auth.RemoveUserFromGroup(ctx, userID, groupID)
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusNoContent, nil)
}

func (c *Controller) AddGroupMembership(w http.ResponseWriter, r *http.Request, groupID, userID string) {
	ctx := r.Context()
	err := c.Auth.AddUserToGroup(ctx, userID, groupID)
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusCreated, nil)
}

func (c *Controller) ListGroupPolicies(w http.ResponseWriter, r *http.Request, groupID string, params apigen.ListGroupPoliciesParams) {
	ctx := r.Context()
	policies, paginator, err := c.Auth.ListGroupPolicies(ctx, groupID, &model.PaginationParams{
		After:  swag.StringValue((*string)(params.After)),
		Prefix: swag.StringValue((*string)(params.Prefix)),
		Amount: paginationAmount(params.Amount),
	})
	if c.handleAPIError(w, err) {
		return
	}

	response := apigen.PolicyList{
		Results: make([]apigen.Policy, 0, len(policies)),
		Pagination: apigen.Pagination{
			HasMore:    paginator.NextPageToken != "",
			NextOffset: paginator.NextPageToken,
			Results:    paginator.Amount,
		},
	}
	for _, p := range policies {
		response.Results = append(response.Results, serializePolicy(p))
	}

	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) DetachPolicyFromGroup(w http.ResponseWriter, r *http.Request, groupID, policyID string) {
	if refuseBuiltInPolicy(w, policyID == PolicyName(groupID)) {
		return
	}
	ctx := r.Context()
	err := c.Auth.DetachPolicyFromGroup(ctx, policyID, groupID)
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusNoContent, nil)
}

func (c *Controller) AttachPolicyToGroup(w http.ResponseWriter, r *http.Request, groupID, policyID string) {
	ctx := r.Context()
	err := c.Auth.AttachPolicyToGroup(ctx, policyID, groupID)
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusCreated, nil)
}

// isGroupACLPolicy reports whether policyID is the ACL policy of a group
// that exists, ACL(_-_)<group>.
func (c *Controller) isGroupACLPolicy(ctx context.Context, policyID string) bool {
	if !IsPolicyName(policyID) {
		return false
	}
	_, err := c.Auth.GetGroup(ctx, strings.TrimPrefix(policyID, PolicyPrefix))
	return !errors.Is(err, auth.ErrNotFound) // an error reading the group still guards it
}

// isAdminsPolicy reports whether a body for ACL(_-_)Admins holds exactly the
// Admin ACL's statements. Only then may it be written, so the repair can
// always restore it and nothing else can be planted in it.
func isAdminsPolicy(stmts []apigen.Statement) bool {
	want, err := ACLToStatement(model.ACL{Permission: AdminPermission})
	if err != nil || len(stmts) != len(want) {
		return false
	}
	for i, s := range stmts {
		if s.Effect != want[i].Effect || s.Resource != want[i].Resource || !slices.Equal(s.Action, want[i].Action) {
			return false
		}
	}
	return true
}

// refuseBuiltInPolicy answers 400 when refuse is true. It guards the
// ACL policies of groups, ACL(_-_)<group>: deleting one of a group that
// exists, detaching a group's own one, or writing over the Admins one would
// leave groups, and the admin among them, unable to do anything.
// WriteGroupACL never does these; it writes and attaches the others. Making
// an ACL policy for an existing group is allowed, since it never
// overwrites, so a lost one can be made again.
func refuseBuiltInPolicy(w http.ResponseWriter, refuse bool) bool {
	if !refuse {
		return false
	}
	writeError(w, http.StatusBadRequest, "built-in ACL policies cannot be changed this way")
	return true
}

func (c *Controller) ListPolicies(w http.ResponseWriter, r *http.Request, params apigen.ListPoliciesParams) {
	ctx := r.Context()
	policies, paginator, err := c.Auth.ListPolicies(ctx, &model.PaginationParams{
		After:  swag.StringValue((*string)(params.After)),
		Prefix: swag.StringValue((*string)(params.Prefix)),
		Amount: paginationAmount(params.Amount),
	})
	if c.handleAPIError(w, err) {
		return
	}

	response := apigen.PolicyList{
		Results: make([]apigen.Policy, 0, len(policies)),
		Pagination: apigen.Pagination{
			HasMore:    paginator.NextPageToken != "",
			NextOffset: paginator.NextPageToken,
			Results:    paginator.Amount,
		},
	}
	for _, p := range policies {
		response.Results = append(response.Results, serializePolicy(p))
	}

	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) CreatePolicy(w http.ResponseWriter, r *http.Request, body apigen.CreatePolicyJSONRequestBody) {
	ctx := r.Context()
	if body.Name == PolicyName(AdminsGroup) && !isAdminsPolicy(body.Statement) {
		writeError(w, http.StatusBadRequest, "the Admins ACL policy must hold exactly the Admin statements")
		return
	}
	if IsPolicyName(body.Name) && !c.isGroupACLPolicy(ctx, body.Name) {
		// An ACL policy name belongs to a group; one for no group could
		// never be deleted once that group appeared.
		writeError(w, http.StatusBadRequest, "an ACL policy name must name an existing group")
		return
	}

	stmts := make(model.Statements, len(body.Statement))
	for i, apiStatement := range body.Statement {
		stmts[i] = model.Statement{
			Effect:   apiStatement.Effect,
			Action:   apiStatement.Action,
			Resource: apiStatement.Resource,
		}
	}

	p := &model.Policy{
		CreatedAt:   time.Now().UTC(),
		DisplayName: body.Name,
		Statement:   stmts,
		ACL: model.ACL{
			Permission: model.ACLPermission(swag.StringValue(body.Acl)),
		},
	}

	err := c.Auth.WritePolicy(ctx, p, false)
	if c.handleAPIError(w, err) {
		return
	}

	writeResponse(w, http.StatusCreated, serializePolicy(p))
}

func (c *Controller) DeletePolicy(w http.ResponseWriter, r *http.Request, policyID string) {
	if refuseBuiltInPolicy(w, c.isGroupACLPolicy(r.Context(), policyID)) {
		return
	}
	ctx := r.Context()
	err := c.Auth.DeletePolicy(ctx, policyID)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusNoContent, nil)
}

func (c *Controller) GetPolicy(w http.ResponseWriter, r *http.Request, policyID string) {
	ctx := r.Context()
	p, err := c.Auth.GetPolicy(ctx, policyID)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	if c.handleAPIError(w, err) {
		return
	}

	response := serializePolicy(p)
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) UpdatePolicy(w http.ResponseWriter, r *http.Request, body apigen.UpdatePolicyJSONRequestBody, policyID string) {
	if refuseBuiltInPolicy(w, policyID == PolicyName(AdminsGroup) && !isAdminsPolicy(body.Statement)) {
		return
	}
	ctx := r.Context()

	stmts := make(model.Statements, len(body.Statement))
	for i, apiStatement := range body.Statement {
		stmts[i] = model.Statement{
			Effect:   apiStatement.Effect,
			Action:   apiStatement.Action,
			Resource: apiStatement.Resource,
		}
	}

	p := &model.Policy{
		CreatedAt:   time.Now().UTC(),
		DisplayName: policyID,
		Statement:   stmts,
		ACL: model.ACL{
			Permission: model.ACLPermission(swag.StringValue(body.Acl)),
		},
	}
	err := c.Auth.WritePolicy(ctx, p, true)
	if c.handleAPIError(w, err) {
		return
	}
	response := serializePolicy(p)
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) ClaimTokenId(w http.ResponseWriter, _ *http.Request, _ apigen.ClaimTokenIdJSONRequestBody) {
	writeError(w, http.StatusNotImplemented, "Not implemented")
}

func (c *Controller) ListUsers(w http.ResponseWriter, r *http.Request, params apigen.ListUsersParams) {
	// make sure email is lower
	// TODO(Guys): This workaround was added in order to skip in case of filter by email. filter by email is only used in lakeFS email authenticator which isn't supported.
	if params.Email != nil {
		writeResponse(w, http.StatusOK, apigen.UserList{
			Results:    make([]apigen.User, 0),
			Pagination: apigen.Pagination{},
		})
		return
	}

	ctx := r.Context()
	users, paginator, err := c.Auth.ListUsers(ctx,
		&model.PaginationParams{
			After:  swag.StringValue((*string)(params.After)),
			Prefix: swag.StringValue((*string)(params.Prefix)),
			Amount: paginationAmount(params.Amount),
		})
	if c.handleAPIError(w, err) {
		return
	}

	response := apigen.UserList{
		Results: make([]apigen.User, 0, len(users)),
		Pagination: apigen.Pagination{
			HasMore:    paginator.NextPageToken != "",
			NextOffset: paginator.NextPageToken,
			Results:    paginator.Amount,
		},
	}
	for _, u := range users {
		response.Results = append(response.Results, apigen.User{
			Username:          u.Username,
			CreationDate:      u.CreatedAt.Unix(),
			Email:             u.Email,
			EncryptedPassword: u.EncryptedPassword,
			FriendlyName:      u.FriendlyName,
		})
	}
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) CreateUser(w http.ResponseWriter, r *http.Request, body apigen.CreateUserJSONRequestBody) {
	ctx := r.Context()
	u := &model.User{
		CreatedAt:    time.Now().UTC(),
		Username:     body.Username,
		FriendlyName: body.FriendlyName,
		Email:        body.Email,
		Source:       swag.StringValue(body.Source),
	}
	_, err := c.Auth.CreateUser(ctx, u)
	if c.handleAPIError(w, err) {
		return
	}
	response := apigen.User{
		CreationDate: u.CreatedAt.Unix(),
		Email:        u.Email,
		FriendlyName: u.FriendlyName,
		Username:     u.Username,
		Source:       &u.Source,
	}
	writeResponse(w, http.StatusCreated, response)
}

func (c *Controller) DeleteUser(w http.ResponseWriter, r *http.Request, username string) {
	ctx := r.Context()
	err := c.Auth.DeleteUser(ctx, username)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusNoContent, nil)
}

func (c *Controller) GetUser(w http.ResponseWriter, r *http.Request, username string) {
	ctx := r.Context()
	u, err := c.Auth.GetUser(ctx, username)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if c.handleAPIError(w, err) {
		return
	}
	response := apigen.User{
		CreationDate:      u.CreatedAt.Unix(),
		Email:             u.Email,
		EncryptedPassword: u.EncryptedPassword,
		Username:          u.Username,
		FriendlyName:      u.FriendlyName,
		Source:            swag.String(u.Source),
	}
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) ListUserCredentials(w http.ResponseWriter, r *http.Request, userID string, params apigen.ListUserCredentialsParams) {
	ctx := r.Context()
	credentials, paginator, err := c.Auth.ListUserCredentials(ctx, userID, &model.PaginationParams{
		After:  swag.StringValue((*string)(params.After)),
		Prefix: swag.StringValue((*string)(params.Prefix)),
		Amount: paginationAmount(params.Amount),
	})
	if c.handleAPIError(w, err) {
		return
	}

	response := apigen.CredentialsList{
		Results: make([]apigen.Credentials, 0, len(credentials)),
		Pagination: apigen.Pagination{
			HasMore:    paginator.NextPageToken != "",
			NextOffset: paginator.NextPageToken,
			Results:    paginator.Amount,
		},
	}
	for _, c := range credentials {
		response.Results = append(response.Results, apigen.Credentials{
			AccessKeyId:  c.AccessKeyID,
			CreationDate: c.IssuedDate.Unix(),
		})
	}
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) CreateCredentials(w http.ResponseWriter, r *http.Request, userID string, params apigen.CreateCredentialsParams) {
	ctx := r.Context()
	var (
		credentials *model.Credential
		err         error
	)
	if params.AccessKey != nil && params.SecretKey != nil {
		credentials, err = c.Auth.AddCredentials(ctx, userID, *params.AccessKey, *params.SecretKey)
	} else {
		credentials, err = c.Auth.CreateCredentials(ctx, userID)
	}
	if c.handleAPIError(w, err) {
		return
	}

	response := apigen.CredentialsWithSecret{
		UserName:        swag.String(credentials.Username),
		AccessKeyId:     credentials.AccessKeyID,
		SecretAccessKey: credentials.SecretAccessKey,
		CreationDate:    credentials.IssuedDate.Unix(),
	}
	writeResponse(w, http.StatusCreated, response)
}

func (c *Controller) DeleteCredentials(w http.ResponseWriter, r *http.Request, userID string, accessKeyID string) {
	ctx := r.Context()
	err := c.Auth.DeleteCredentials(ctx, userID, accessKeyID)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "credentials not found")
		return
	}
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusNoContent, nil)
}

func (c *Controller) GetCredentialsForUser(w http.ResponseWriter, r *http.Request, userId string, accessKeyId string) {
	ctx := r.Context()
	credentials, err := c.Auth.GetCredentialsForUser(ctx, userId, accessKeyId)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "credentials not found")
		return
	}
	if c.handleAPIError(w, err) {
		return
	}
	response := apigen.Credentials{
		AccessKeyId:  credentials.AccessKeyID,
		CreationDate: credentials.IssuedDate.Unix(),
	}
	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) CreateUserExternalPrincipal(w http.ResponseWriter, _ *http.Request, _ string, _ apigen.CreateUserExternalPrincipalParams) {
	writeError(w, http.StatusNotImplemented, "Not implemented")
}

func (c *Controller) DeleteUserExternalPrincipal(w http.ResponseWriter, _ *http.Request, _ string, _ apigen.DeleteUserExternalPrincipalParams) {
	writeError(w, http.StatusNotImplemented, "Not implemented")
}

func (c *Controller) ListUserExternalPrincipals(w http.ResponseWriter, _ *http.Request, _ string, _ apigen.ListUserExternalPrincipalsParams) {
	writeError(w, http.StatusNotImplemented, "Not implemented")
}

func (c *Controller) UpdateUserFriendlyName(w http.ResponseWriter, r *http.Request, body apigen.UpdateUserFriendlyNameJSONRequestBody, username string) {
	ctx := r.Context()

	err := c.Auth.UpdateUserFriendlyName(ctx, username, body.FriendlyName)
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusNoContent, nil)
}

func (c *Controller) ListUserGroups(w http.ResponseWriter, r *http.Request, userID string, params apigen.ListUserGroupsParams) {
	ctx := r.Context()
	groups, paginator, err := c.Auth.ListUserGroups(ctx, userID, &model.PaginationParams{
		After:  swag.StringValue((*string)(params.After)),
		Prefix: swag.StringValue((*string)(params.Prefix)),
		Amount: paginationAmount(params.Amount),
	})
	if c.handleAPIError(w, err) {
		return
	}

	response := apigen.GroupList{
		Results: make([]apigen.Group, 0, len(groups)),
		Pagination: apigen.Pagination{
			HasMore:    paginator.NextPageToken != "",
			NextOffset: paginator.NextPageToken,
			Results:    paginator.Amount,
		},
	}
	for _, g := range groups {
		response.Results = append(response.Results, apigen.Group{
			Name:         g.DisplayName,
			CreationDate: g.CreatedAt.Unix(),
		})
	}

	writeResponse(w, http.StatusOK, response)
}

func (c *Controller) UpdatePassword(w http.ResponseWriter, _ *http.Request, _ apigen.UpdatePasswordJSONRequestBody, _ string) {
	writeError(w, http.StatusNotImplemented, "Not implemented")
}

func (c *Controller) ListUserPolicies(w http.ResponseWriter, r *http.Request, userID string, params apigen.ListUserPoliciesParams) {
	ctx := r.Context()
	var listPolicies func(ctx context.Context, username string, params *model.PaginationParams) ([]*model.Policy, *model.Paginator, error)
	if swag.BoolValue(params.Effective) {
		listPolicies = c.Auth.ListEffectivePolicies
	} else {
		listPolicies = c.Auth.ListUserPolicies
	}
	policies, paginator, err := listPolicies(ctx, userID, &model.PaginationParams{
		After:  swag.StringValue((*string)(params.After)),
		Prefix: swag.StringValue((*string)(params.Prefix)),
		Amount: paginationAmount(params.Amount),
	})
	if c.handleAPIError(w, err) {
		return
	}

	response := apigen.PolicyList{
		Pagination: apigen.Pagination{
			HasMore:    paginator.NextPageToken != "",
			NextOffset: paginator.NextPageToken,
			Results:    paginator.Amount,
		},
		Results: make([]apigen.Policy, 0, len(policies)),
	}
	for _, p := range policies {
		response.Results = append(response.Results, serializePolicy(p))
	}
	writeResponse(w, http.StatusOK, response)
}

func serializePolicy(p *model.Policy) apigen.Policy {
	stmts := make([]apigen.Statement, 0, len(p.Statement))
	for _, s := range p.Statement {
		stmts = append(stmts, apigen.Statement{
			Action:   s.Action,
			Effect:   s.Effect,
			Resource: s.Resource,
		})
	}
	createdAt := p.CreatedAt.Unix()
	var acl *string
	if p.ACL.Permission != "" {
		acl = (*string)(&p.ACL.Permission)
	}
	return apigen.Policy{
		Name:         p.DisplayName,
		CreationDate: &createdAt,
		Statement:    stmts,
		Acl:          acl,
	}
}

func (c *Controller) DetachPolicyFromUser(w http.ResponseWriter, r *http.Request, userID, policyID string) {
	ctx := r.Context()
	err := c.Auth.DetachPolicyFromUser(ctx, policyID, userID)
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusNoContent, nil)
}

func (c *Controller) AttachPolicyToUser(w http.ResponseWriter, r *http.Request, userID, policyID string) {
	ctx := r.Context()
	err := c.Auth.AttachPolicyToUser(ctx, policyID, userID)
	if c.handleAPIError(w, err) {
		return
	}
	writeResponse(w, http.StatusCreated, nil)
}

func (c *Controller) GetVersion(w http.ResponseWriter, _ *http.Request) {
	writeResponse(w, http.StatusOK, apigen.VersionConfig{
		Version: "dev",
	})
}

func (c *Controller) HealthCheck(w http.ResponseWriter, _ *http.Request) {
	writeResponse(w, http.StatusNoContent, nil)
}

func (c *Controller) handleAPIError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, err)

	case errors.Is(err, model.ErrValidationError):
		writeError(w, http.StatusBadRequest, err)

	case errors.Is(err, auth.ErrAlreadyExists):
		writeError(w, http.StatusConflict, "Already exists")

	case err != nil:
		writeError(w, http.StatusInternalServerError, err)

	default:
		return false
	}

	return true
}

func writeError(w http.ResponseWriter, code int, v any) {
	apiErr := apigen.Error{
		Message: fmt.Sprint(v),
	}
	writeResponse(w, code, apiErr)
}

func writeResponse(w http.ResponseWriter, code int, response any) {
	log := logging.ContextUnavailable()
	if response == nil {
		w.WriteHeader(code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		log.WithError(err).WithField("code", code).Debug("Failed to write encoded json response")
	}
}

func paginationAmount(v *apigen.PaginationAmount) int {
	if v == nil {
		return DefaultMaxPerPage
	}
	i := int(*v)
	if i > DefaultMaxPerPage {
		return DefaultMaxPerPage
	}
	if i <= 0 {
		return DefaultMaxPerPage
	}
	return i
}
