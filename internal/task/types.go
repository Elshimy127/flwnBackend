// Package task is the task domain: routes, handlers and the rules for tasks.
package task

import (
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

type (
	Task   = dataengine.TaskOut
	Create = dataengine.TaskCreate
	Update = dataengine.TaskUpdate
	Page   = dataengine.TaskPage
)

// Filter narrows a project's task list. Nil fields are not applied.
type Filter struct {
	AssigneeID *uuid.UUID
	Status     *string
	SprintID   *uuid.UUID
	Backlog    *bool // true: only tasks with no sprint
}

type Status string

const (
	StatusBacklog    Status = "backlog"
	StatusTodo       Status = "todo"
	StatusInProgress Status = "in_progress"
	StatusInReview   Status = "in_review"
	StatusDone       Status = "done"
	StatusCanceled   Status = "canceled"
)

type Priority string

const (
	PriorityNone   Priority = "none"
	PriorityLow    Priority = "low"
	PriorityMedium Priority = "medium"
	PriorityHigh   Priority = "high"
	PriorityUrgent Priority = "urgent"
)
