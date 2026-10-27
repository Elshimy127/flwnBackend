// Package user is the user domain: global accounts, not tied to a workspace.
package user

import "github.com/Hesham127/flwnBackend/internal/platform/dataengine"

type (
	User   = dataengine.UserOut
	Create = dataengine.UserCreate
	Update = dataengine.UserUpdate
	Page   = dataengine.UserPage
)
