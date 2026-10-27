// Package project is the project domain.
package project

import "github.com/Hesham127/flwnBackend/internal/platform/dataengine"

type (
	Project = dataengine.ProjectOut
	Create  = dataengine.ProjectCreate
	Update  = dataengine.ProjectUpdate
	Page    = dataengine.ProjectPage
)

type Status string

const (
	StatusBacklog    Status = "backlog"
	StatusPlanned    Status = "planned"
	StatusInProgress Status = "in_progress"
	StatusPaused     Status = "paused"
	StatusCompleted  Status = "completed"
	StatusCanceled   Status = "canceled"
)
