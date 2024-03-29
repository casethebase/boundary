package apptokens

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	requestauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/apptokens"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete", "add-principals", "set-principals", "remove-principals", "add-grants", "set-grants", "remove-grants", "add-grant-scopes", "set-grant-scopes", "remove-grant-scopes"}

// func TestNewService(t *testing.T) {
// 	ctx := context.TODO()

// 	repoFn := func() apptoken.Repository {
// 		return &mockRepository{}
// 	}

// 	iamRepoFn := func() common.IamRepository {
// 		return &mockIamRepository{}
// 	}

// 	service, err := NewService(ctx, repoFn, iamRepoFn)
// 	if err != nil {
// 		t.Errorf("unexpected error: %v", err)
// 	}

// 	if service.repoFn == nil {
// 		t.Error("expected non-nil apptoken repository")
// 	}

// 	if service.iamRepoFn == nil {
// 		t.Error("expected non-nil iam repository")
// 	}
// }

func TestService_CreateAppToken(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)

	tokenRepo, _ := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	iamRepo := iam.TestRepo(t, conn, wrap)
	repo := apptoken.TestRepo(t, conn, wrap, iamRepo)

	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func(opts ...apptoken.Option) (*apptoken.Repository, error) {
		return repo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}

	service, err := NewService(ctx, repoFn, iamRepoFn)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	org, proj := iam.TestScopes(t, iamRepo)
	authMethod := password.TestAuthMethods(t, conn, "global", 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test_user")
	user := iam.TestUser(t, iamRepo, "global", iam.WithAccountIds(acct.PublicId))
	userHistoryId, err := repo.ResolveUserHistoryId(ctx, user.GetPublicId())

	privProjRole := iam.TestRole(t, conn, proj.GetPublicId())
	iam.TestRoleGrant(t, conn, privProjRole.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, privProjRole.GetPublicId(), user.GetPublicId())
	privOrgRole := iam.TestRole(t, conn, org.GetPublicId())
	iam.TestRoleGrant(t, conn, privOrgRole.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, privOrgRole.GetPublicId(), user.GetPublicId())

	at, _ := tokenRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(requestauth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsCache)
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = requestauth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsCache, &requestInfo)

	appTokenMutatorFn := func(mod func(*apptokens.AppToken)) *services.CreateAppTokenRequest {
		token := &apptokens.AppToken{
			Scope:           &scopes.ScopeInfo{Id: proj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: proj.GetParentId()},
			Name:            wrapperspb.String("test-app-token"),
			Description:     wrapperspb.String("test-app-token-description"),
			ExpirationTime:  timestamppb.New(time.Now().Add(365 * 24 * time.Minute)),
			CreatedByUserId: userHistoryId,
			GrantStrings: []string{
				"id=*;type=*;actions=read",
			},
			Grants: []*apptokens.Grant{
				&apptokens.Grant{
					Canonical: "id=*;type=*;actions=read",
					Raw:       "id=*;type=*;actions=read",
				},
			},
			ExpirationInterval: 60,
			ScopeId:            org.GetPublicId(),
			AuthorizedActions:  testAuthorizedActions,
		}
		if mod != nil {
			mod(token)
		}
		return &services.CreateAppTokenRequest{
			Item: token,
		}
	}

	tests := []struct {
		name     string
		request  *services.CreateAppTokenRequest
		expected *services.CreateAppTokenResponse
		err      error
	}{
		{
			name:     "ValidRequest",
			request:  appTokenMutatorFn(nil),
			expected: &services.CreateAppTokenResponse{},
			err:      nil,
		},
		{
			name: "valid-request-with-no-name",
			request: appTokenMutatorFn(func(token *apptokens.AppToken) {
				token.Name = nil
			}),
		},
		{
			name: "valid-request-with-no-description",
			request: appTokenMutatorFn(func(token *apptokens.AppToken) {
				token.Description = nil
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := service.CreateAppToken(ctx, tt.request)

			// assert.Equal(t, tt.expected, response)
			assert.Equal(t, tt.err, err)
			assert.NotNil(t, response)
		})
	}
}
