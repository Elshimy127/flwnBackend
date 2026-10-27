package member

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Service is where member rules belong.
//
// TODO: only owners/admins may add, change or remove members; an admin can't promote someone to
// owner; a workspace must keep at least one owner; seat limits per plan.
type Service struct {
	engine *dataengine.Client
}

func NewService(engine *dataengine.Client) *Service {
	return &Service{engine: engine}
}

// Create adds a member. For HUMAN members the engine finds or creates the user by email,
// so there's no need to create the user first. Adding the same person twice is a 409.
func (s *Service) Create(ctx context.Context, ws uuid.UUID, in Create) (*Member, error) {
	return dataengine.Decode[Member](s.engine.CreateMemberWorkspacesWorkspaceIdMembersPost(ctx, ws, nil, in))
}

func (s *Service) List(ctx context.Context, ws uuid.UUID, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListMembersWorkspacesWorkspaceIdMembersGetParams{Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListMembersWorkspacesWorkspaceIdMembersGet(ctx, ws, params))
}

func (s *Service) Get(ctx context.Context, ws, id uuid.UUID) (*Member, error) {
	return dataengine.Decode[Member](s.engine.GetMemberWorkspacesWorkspaceIdMembersMemberIdGet(ctx, ws, id, nil))
}

func (s *Service) Update(ctx context.Context, ws, id uuid.UUID, in Update) (*Member, error) {
	return dataengine.Decode[Member](s.engine.UpdateMemberWorkspacesWorkspaceIdMembersMemberIdPatch(ctx, ws, id, nil, in))
}

func (s *Service) Delete(ctx context.Context, ws, id uuid.UUID) error {
	return dataengine.NoContent(s.engine.DeleteMemberWorkspacesWorkspaceIdMembersMemberIdDelete(ctx, ws, id, nil))
}
