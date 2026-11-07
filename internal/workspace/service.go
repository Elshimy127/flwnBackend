package workspace

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/platform/httpx"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

// Service holds the workspace rules (docs/AUTH.md §5, §8):
//   - creating a workspace makes the caller its owner, atomically in the engine;
//   - List returns only the caller's memberships;
//   - update needs admin+, delete and ownership transfer need owner + recent auth (routes);
//   - the engine keeps at least one owner per workspace (409 last_owner).
type Service struct {
	engine *dataengine.Client
	system auth.Engine
	auth   *auth.Service
}

func NewService(engine *dataengine.Client, system auth.Engine, authSvc *auth.Service) *Service {
	return &Service{engine: engine, system: system, auth: authSvc}
}

// Transfer is the ownership-transfer request.
type Transfer struct {
	ToMemberID   uuid.UUID `json:"to_member_id" binding:"required"`
	DemoteSelfTo *string   `json:"demote_self_to"`
}

func (s *Service) Create(ctx context.Context, p auth.Principal, in Create) (auth.Workspace, error) {
	return s.system.CreateWorkspace(ctx, in.Name, in.Slug, p.UserID)
}

func (s *Service) List(ctx context.Context, p auth.Principal) ([]auth.Membership, error) {
	return s.auth.Memberships(ctx, p.UserID)
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Workspace, error) {
	return dataengine.Decode[Workspace](s.engine.GetWorkspaceWorkspacesWorkspaceIdGet(ctx, id, nil))
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, in Update) (*Workspace, error) {
	return dataengine.Decode[Workspace](s.engine.UpdateWorkspaceWorkspacesWorkspaceIdPatch(ctx, id, nil, in))
}

// Delete soft-deletes the workspace and ends every session bound to it at once.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	if err := dataengine.NoContent(s.engine.DeleteWorkspaceWorkspacesWorkspaceIdDelete(ctx, id, nil)); err != nil {
		return err
	}
	return s.auth.RevokeWorkspaceSessions(ctx, id, "workspace_deleted")
}

// Transfer hands ownership to another active human member in one engine transaction. Role
// changes take effect on the next request: both members' cached views are dropped.
func (s *Service) Transfer(ctx context.Context, p auth.Principal, in Transfer) (*map[string]any, error) {
	if in.DemoteSelfTo != nil && *in.DemoteSelfTo != string(auth.RoleAdmin) && *in.DemoteSelfTo != string(auth.RoleMember) {
		return nil, httpx.BadRequest("demote_self_to_must_be_admin_or_member")
	}
	out, err := dataengine.Decode[map[string]any](s.engine.JSON(ctx, http.MethodPost,
		"/workspaces/"+p.WorkspaceID.String()+"/ownership/transfer",
		map[string]any{"to_member_id": in.ToMemberID, "demote_self_to": in.DemoteSelfTo}))
	s.auth.InvalidateMember(p.WorkspaceID, p.MemberID)
	s.auth.InvalidateMember(p.WorkspaceID, in.ToMemberID)
	return out, err
}

func (s *Service) writeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, auth.ErrEngineConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "slug_taken"})
	case errors.Is(err, auth.ErrEngineUnavailable), errors.Is(err, auth.ErrUnavailable):
		c.JSON(http.StatusBadGateway, gin.H{"error": "data_engine_unavailable"})
	default:
		secure.Abort(c, err)
	}
}
