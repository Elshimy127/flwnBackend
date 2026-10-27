// Package team is the team domain: groups of members inside a workspace.
package team

import "github.com/Hesham127/flwnBackend/internal/platform/dataengine"

type (
	Team          = dataengine.TeamOut
	Create        = dataengine.TeamCreate
	Update        = dataengine.TeamUpdate
	Page          = dataengine.TeamPage
	MembersUpdate = dataengine.TeamMembersUpdate
)

type Visibility string

const (
	VisibilityWorkspace Visibility = "workspace" // everyone in the workspace can see it
	VisibilityPrivate   Visibility = "private"   // only its members and admins
)
