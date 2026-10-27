// Package workspace is the workspace domain.
package workspace

import "github.com/Hesham127/flwnBackend/internal/platform/dataengine"

type (
	Workspace = dataengine.WorkspaceOut
	Create    = dataengine.WorkspaceCreate
	Update    = dataengine.WorkspaceUpdate
	Page      = dataengine.WorkspacePage
)
