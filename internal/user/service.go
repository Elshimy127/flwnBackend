package user

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Service is where user rules belong.
//
// TODO: users are global, so only the user themself (or a platform admin) should read or change
// one. Deleting a user doesn't remove their workspace memberships; remove those here if needed.
type Service struct {
	engine *dataengine.Client
}

func NewService(engine *dataengine.Client) *Service {
	return &Service{engine: engine}
}

func (s *Service) Create(ctx context.Context, in Create) (*User, error) {
	return dataengine.Decode[User](s.engine.CreateUserUsersPost(ctx, nil, in))
}

// List returns users, optionally only the one with this email.
func (s *Service) List(ctx context.Context, email *string, page dataengine.Page) (*Page, error) {
	params := &dataengine.ListUsersUsersGetParams{Email: email, Limit: page.Limit, Offset: page.Offset}
	return dataengine.Decode[Page](s.engine.ListUsersUsersGet(ctx, params))
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	return dataengine.Decode[User](s.engine.GetUserUsersUserIdGet(ctx, id, nil))
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, in Update) (*User, error) {
	return dataengine.Decode[User](s.engine.UpdateUserUsersUserIdPatch(ctx, id, nil, in))
}

// Delete soft-deletes the user.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	return dataengine.NoContent(s.engine.DeleteUserUsersUserIdDelete(ctx, id, nil))
}
