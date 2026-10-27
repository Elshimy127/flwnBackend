// Package sprint is the sprint domain.
package sprint

import "github.com/Hesham127/flwnBackend/internal/platform/dataengine"

type (
	Sprint = dataengine.SprintOut
	Create = dataengine.SprintCreate
	Update = dataengine.SprintUpdate
	Page   = dataengine.SprintPage
)

type Status string

const (
	StatusPlanned   Status = "planned"
	StatusActive    Status = "active"
	StatusCompleted Status = "completed"
)
