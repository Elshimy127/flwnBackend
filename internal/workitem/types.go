// Package workitem is the work item domain: features, stories and bugs that tasks belong to.
package workitem

import "github.com/Hesham127/flwnBackend/internal/platform/dataengine"

type (
	WorkItem = dataengine.WorkItemOut
	Create   = dataengine.WorkItemCreate
	Update   = dataengine.WorkItemUpdate
	Page     = dataengine.WorkItemPage
)

type Type string

const (
	TypeFeature Type = "FEATURE"
	TypeStory   Type = "STORY"
	TypeBug     Type = "BUG"
)

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
