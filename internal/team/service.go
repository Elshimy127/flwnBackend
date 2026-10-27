package team

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Service is where team rules belong.
//
// TODO: the service key sees private teams too, so List/Get must hide private teams from callers
// who are neither members of the team nor workspace admins. Only admins manage teams.
type Service struct {
	engine *dataengine.Client
}

func NewService(engine *dataengine.Client) *Service {
	return &Service{engine: engine}
}

func (s *Service) Create(ctx context.Context, ws uuid.UUID, in Create) (*Team, error) {
	return dataengine.Decode[Team](s.engine.CreateTeamWorkspacesWorkspaceIdTeamsPost(ctx, ws, nil, in))
}

func (s *Service) List(ctx context.Context, ws uuid.UUID, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListTeamsWorkspacesWorkspaceIdTeamsGetParams{Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListTeamsWorkspacesWorkspaceIdTeamsGet(ctx, ws, params))
}

func (s *Service) Get(ctx context.Context, ws, id uuid.UUID) (*Team, error) {
	return dataengine.Decode[Team](s.engine.GetTeamWorkspacesWorkspaceIdTeamsTeamIdGet(ctx, ws, id, nil))
}

func (s *Service) Update(ctx context.Context, ws, id uuid.UUID, in Update) (*Team, error) {
	return dataengine.Decode[Team](s.engine.UpdateTeamWorkspacesWorkspaceIdTeamsTeamIdPatch(ctx, ws, id, nil, in))
}

func (s *Service) Delete(ctx context.Context, ws, id uuid.UUID) error {
	return dataengine.NoContent(s.engine.DeleteTeamWorkspacesWorkspaceIdTeamsTeamIdDelete(ctx, ws, id, nil))
}

// ReplaceMembers sets the team's full member list. Anyone not in it is removed from the team.
func (s *Service) ReplaceMembers(ctx context.Context, ws, id uuid.UUID, in MembersUpdate) (*Team, error) {
	return dataengine.Decode[Team](s.engine.ReplaceTeamMembersWorkspacesWorkspaceIdTeamsTeamIdMembersPut(ctx, ws, id, nil, in))
}
