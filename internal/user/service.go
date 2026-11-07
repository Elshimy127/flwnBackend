package user

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Service reads and updates the caller's own profile. Who may call it is decided by the route
// (self only); account creation, email change and deletion live in the auth service.
type Service struct {
	engine *dataengine.Client
}

func NewService(engine *dataengine.Client) *Service {
	return &Service{engine: engine}
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	return dataengine.Decode[User](s.engine.GetUserUsersUserIdGet(ctx, id, nil))
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, in Update) (*User, error) {
	return dataengine.Decode[User](s.engine.UpdateUserUsersUserIdPatch(ctx, id, nil, in))
}
