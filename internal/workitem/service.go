package workitem

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Service is where work item rules belong.
//
// TODO: viewers can't create or change work items; allowed status transitions.
type Service struct {
	engine *dataengine.Client
}

func NewService(engine *dataengine.Client) *Service {
	return &Service{engine: engine}
}

func (s *Service) Create(ctx context.Context, ws, project uuid.UUID, in Create) (*WorkItem, error) {
	return dataengine.Decode[WorkItem](s.engine.CreateWorkItemWorkspacesWorkspaceIdProjectsProjectIdWorkItemsPost(ctx, ws, project, nil, in))
}

func (s *Service) List(ctx context.Context, ws, project uuid.UUID, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListWorkItemsWorkspacesWorkspaceIdProjectsProjectIdWorkItemsGetParams{Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListWorkItemsWorkspacesWorkspaceIdProjectsProjectIdWorkItemsGet(ctx, ws, project, params))
}

func (s *Service) Get(ctx context.Context, ws, project, id uuid.UUID) (*WorkItem, error) {
	return dataengine.Decode[WorkItem](s.engine.GetWorkItemWorkspacesWorkspaceIdProjectsProjectIdWorkItemsWorkItemIdGet(ctx, ws, project, id, nil))
}

func (s *Service) Update(ctx context.Context, ws, project, id uuid.UUID, in Update) (*WorkItem, error) {
	return dataengine.Decode[WorkItem](s.engine.UpdateWorkItemWorkspacesWorkspaceIdProjectsProjectIdWorkItemsWorkItemIdPatch(ctx, ws, project, id, nil, in))
}

func (s *Service) Delete(ctx context.Context, ws, project, id uuid.UUID) error {
	return dataengine.NoContent(s.engine.DeleteWorkItemWorkspacesWorkspaceIdProjectsProjectIdWorkItemsWorkItemIdDelete(ctx, ws, project, id, nil))
}
