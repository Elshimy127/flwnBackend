package member

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/platform/httpx"
)

// Service holds the member rules (docs/AUTH.md §5, §8, §14):
//   - adding, changing or removing members needs admin+ with identity:write (route policy);
//   - granting the owner role, or changing or removing an owner, needs the caller to be owner;
//   - a member's email is their login identity and changes only through /auth/email;
//   - the engine keeps at least one active human owner (409 last_owner) and refuses AI owners;
//   - after a role or status change the cached membership is dropped; suspension or removal
//     also revokes every session of that member, so access ends on the next request.
type Service struct {
	engine *dataengine.Client
	auth   *auth.Service
}

func NewService(engine *dataengine.Client, authSvc *auth.Service) *Service {
	return &Service{engine: engine, auth: authSvc}
}

func forbidden(code string) error  { return httpx.Forbidden(code) }
func badRequest(code string) error { return httpx.BadRequest(code) }

// Create adds a member. For HUMAN members the engine finds or creates the user by email; that
// person signs in after registering and verifying the same email.
func (s *Service) Create(ctx context.Context, p auth.Principal, ws uuid.UUID, in Create) (*Member, error) {
	if in.Role != nil && *in.Role == string(auth.RoleOwner) && p.Role != auth.RoleOwner {
		return nil, forbidden("owner_required_to_add_owner")
	}
	if email, err := in.Email.Get(); err == nil && email != "" {
		canon, err := auth.CanonicalEmail(email)
		if err != nil {
			return nil, badRequest("invalid_email")
		}
		in.Email.Set(canon)
	}
	return dataengine.Decode[Member](s.engine.CreateMemberWorkspacesWorkspaceIdMembersPost(ctx, ws, nil, in))
}

func (s *Service) List(ctx context.Context, ws uuid.UUID, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListMembersWorkspacesWorkspaceIdMembersGetParams{Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListMembersWorkspacesWorkspaceIdMembersGet(ctx, ws, params))
}

func (s *Service) Get(ctx context.Context, ws, id uuid.UUID) (*Member, error) {
	return dataengine.Decode[Member](s.engine.GetMemberWorkspacesWorkspaceIdMembersMemberIdGet(ctx, ws, id, nil))
}

func (s *Service) Update(ctx context.Context, p auth.Principal, ws, id uuid.UUID, in Update) (*Member, error) {
	if in.Email.IsSpecified() {
		return nil, badRequest("email_changes_use_auth_email")
	}
	target, err := s.Get(ctx, ws, id)
	if err != nil {
		return nil, err
	}
	newRole, _ := in.Role.Get()
	touchesOwner := target.Role == string(auth.RoleOwner) || (in.Role.IsSpecified() && newRole == string(auth.RoleOwner))
	if touchesOwner && p.Role != auth.RoleOwner {
		return nil, forbidden("owner_required_for_owner_role")
	}
	out, err := dataengine.Decode[Member](s.engine.UpdateMemberWorkspacesWorkspaceIdMembersMemberIdPatch(ctx, ws, id, nil, in))
	if err != nil {
		return nil, err
	}
	s.auth.InvalidateMember(ws, id)
	if out.Status != string(StatusActive) {
		if err := s.auth.RevokeMemberSessions(ctx, ws, id, "member_suspended"); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (s *Service) Delete(ctx context.Context, p auth.Principal, ws, id uuid.UUID) error {
	target, err := s.Get(ctx, ws, id)
	if err != nil {
		return err
	}
	if target.Role == string(auth.RoleOwner) && p.Role != auth.RoleOwner {
		return forbidden("owner_required_to_remove_owner")
	}
	if err := dataengine.NoContent(s.engine.DeleteMemberWorkspacesWorkspaceIdMembersMemberIdDelete(ctx, ws, id, nil)); err != nil {
		return err
	}
	return s.auth.RevokeMemberSessions(ctx, ws, id, "member_removed")
}
