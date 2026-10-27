package sprint

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Service is where sprint rules belong.
//
// TODO: one active sprint per project; can't reopen a completed sprint; "estimate needed before
// a task enters a sprint" if the product wants it.
type Service struct {
	engine *dataengine.Client
}

func NewService(engine *dataengine.Client) *Service {
	return &Service{engine: engine}
}

func (s *Service) Create(ctx context.Context, ws, project uuid.UUID, in Create) (*Sprint, error) {
	return dataengine.Decode[Sprint](s.engine.CreateSprintWorkspacesWorkspaceIdProjectsProjectIdSprintsPost(ctx, ws, project, nil, in))
}

func (s *Service) List(ctx context.Context, ws, project uuid.UUID, status *string, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListSprintsWorkspacesWorkspaceIdProjectsProjectIdSprintsGetParams{Status: status, Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListSprintsWorkspacesWorkspaceIdProjectsProjectIdSprintsGet(ctx, ws, project, params))
}

func (s *Service) Get(ctx context.Context, ws, project, id uuid.UUID) (*Sprint, error) {
	return dataengine.Decode[Sprint](s.engine.GetSprintWorkspacesWorkspaceIdProjectsProjectIdSprintsSprintIdGet(ctx, ws, project, id, nil))
}

func (s *Service) Update(ctx context.Context, ws, project, id uuid.UUID, in Update) (*Sprint, error) {
	return dataengine.Decode[Sprint](s.engine.UpdateSprintWorkspacesWorkspaceIdProjectsProjectIdSprintsSprintIdPatch(ctx, ws, project, id, nil, in))
}

// Delete removes the sprint; the engine sends its tasks back to the backlog.
func (s *Service) Delete(ctx context.Context, ws, project, id uuid.UUID) error {
	return dataengine.NoContent(s.engine.DeleteSprintWorkspacesWorkspaceIdProjectsProjectIdSprintsSprintIdDelete(ctx, ws, project, id, nil))
}
