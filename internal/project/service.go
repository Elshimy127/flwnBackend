package project

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Service is where project rules belong.
//
// TODO: viewers can't create or change projects; only the lead or an admin may delete one;
// max projects per plan.
type Service struct {
	engine *dataengine.Client
}

func NewService(engine *dataengine.Client) *Service {
	return &Service{engine: engine}
}

func (s *Service) Create(ctx context.Context, ws uuid.UUID, in Create) (*Project, error) {
	return dataengine.Decode[Project](s.engine.CreateProjectWorkspacesWorkspaceIdProjectsPost(ctx, ws, nil, in))
}

func (s *Service) List(ctx context.Context, ws uuid.UUID, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListProjectsWorkspacesWorkspaceIdProjectsGetParams{Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListProjectsWorkspacesWorkspaceIdProjectsGet(ctx, ws, params))
}

func (s *Service) Get(ctx context.Context, ws, id uuid.UUID) (*Project, error) {
	return dataengine.Decode[Project](s.engine.GetProjectWorkspacesWorkspaceIdProjectsProjectIdGet(ctx, ws, id, nil))
}

func (s *Service) Update(ctx context.Context, ws, id uuid.UUID, in Update) (*Project, error) {
	return dataengine.Decode[Project](s.engine.UpdateProjectWorkspacesWorkspaceIdProjectsProjectIdPatch(ctx, ws, id, nil, in))
}

func (s *Service) Delete(ctx context.Context, ws, id uuid.UUID) error {
	return dataengine.NoContent(s.engine.DeleteProjectWorkspacesWorkspaceIdProjectsProjectIdDelete(ctx, ws, id, nil))
}

// ListForMember returns the projects the member leads, or whose team they belong to.
func (s *Service) ListForMember(ctx context.Context, ws, member uuid.UUID, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListMemberProjectsWorkspacesWorkspaceIdMembersMemberIdProjectsGetParams{Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListMemberProjectsWorkspacesWorkspaceIdMembersMemberIdProjectsGet(ctx, ws, member, params))
}
