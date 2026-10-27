package task

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Service is where task authorization and product rules belong. The engine only checks that data
// is valid (ids exist, sprint is in the same project); deciding what a user may do is ours.
//
// TODO rules from the integration guide:
//   - only members allowed to edit the project can create/update/delete tasks
//   - allowed status transitions ("can't close a blocked task")
//   - only active members can be assigned (the engine enforces this today but will stop)
type Service struct {
	engine *dataengine.Client
}

func NewService(engine *dataengine.Client) *Service {
	return &Service{engine: engine}
}

func (s *Service) Create(ctx context.Context, ws, project uuid.UUID, in Create) (*Task, error) {
	return dataengine.Decode[Task](s.engine.CreateTaskWorkspacesWorkspaceIdProjectsProjectIdTasksPost(ctx, ws, project, nil, in))
}

func (s *Service) List(ctx context.Context, ws, project uuid.UUID, f Filter, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListTasksWorkspacesWorkspaceIdProjectsProjectIdTasksGetParams{
		AssigneeId: f.AssigneeID,
		Status:     f.Status,
		SprintId:   f.SprintID,
		Backlog:    f.Backlog,
		Limit:      page.Limit,
		Offset:     page.Offset,
	}
	return dataengine.Decode[Page](s.engine.ListTasksWorkspacesWorkspaceIdProjectsProjectIdTasksGet(ctx, ws, project, params))
}

func (s *Service) Get(ctx context.Context, ws, project, id uuid.UUID) (*Task, error) {
	return dataengine.Decode[Task](s.engine.GetTaskWorkspacesWorkspaceIdProjectsProjectIdTasksTaskIdGet(ctx, ws, project, id, nil))
}

func (s *Service) Update(ctx context.Context, ws, project, id uuid.UUID, in Update) (*Task, error) {
	return dataengine.Decode[Task](s.engine.UpdateTaskWorkspacesWorkspaceIdProjectsProjectIdTasksTaskIdPatch(ctx, ws, project, id, nil, in))
}

func (s *Service) Delete(ctx context.Context, ws, project, id uuid.UUID) error {
	return dataengine.NoContent(s.engine.DeleteTaskWorkspacesWorkspaceIdProjectsProjectIdTasksTaskIdDelete(ctx, ws, project, id, nil))
}

// GetByKey looks a task up by its readable key, such as DATA-12.
func (s *Service) GetByKey(ctx context.Context, ws uuid.UUID, key string) (*Task, error) {
	return dataengine.Decode[Task](s.engine.GetTaskByKeyWorkspacesWorkspaceIdTasksByKeyKeyGet(ctx, ws, key, nil))
}

// ListForMember returns every task assigned to the member, across all projects.
func (s *Service) ListForMember(ctx context.Context, ws, member uuid.UUID, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListMemberTasksWorkspacesWorkspaceIdMembersMemberIdTasksGetParams{Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListMemberTasksWorkspacesWorkspaceIdMembersMemberIdTasksGet(ctx, ws, member, params))
}
