package workspace

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Service is where workspace rules belong.
//
// TODO: creating a workspace doesn't create its first member; the onboarding flow must also add
// the creator as owner. Only owners should update or delete a workspace, and List should only
// return workspaces the caller belongs to (the service key sees all of them).
type Service struct {
	engine *dataengine.Client
}

func NewService(engine *dataengine.Client) *Service {
	return &Service{engine: engine}
}

func (s *Service) Create(ctx context.Context, in Create) (*Workspace, error) {
	return dataengine.Decode[Workspace](s.engine.CreateWorkspaceWorkspacesPost(ctx, nil, in))
}

func (s *Service) List(ctx context.Context, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListWorkspacesWorkspacesGetParams{Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListWorkspacesWorkspacesGet(ctx, params))
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Workspace, error) {
	return dataengine.Decode[Workspace](s.engine.GetWorkspaceWorkspacesWorkspaceIdGet(ctx, id, nil))
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, in Update) (*Workspace, error) {
	return dataengine.Decode[Workspace](s.engine.UpdateWorkspaceWorkspacesWorkspaceIdPatch(ctx, id, nil, in))
}

// Delete soft-deletes the workspace.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	return dataengine.NoContent(s.engine.DeleteWorkspaceWorkspacesWorkspaceIdDelete(ctx, id, nil))
}
