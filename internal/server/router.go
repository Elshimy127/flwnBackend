// Package server wires every domain's routes into one Gin engine.
package server

import (
	"github.com/gin-gonic/gin"

	"github.com/Hesham127/flwnBackend/internal/member"
	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/platform/httpx"
	"github.com/Hesham127/flwnBackend/internal/project"
	"github.com/Hesham127/flwnBackend/internal/sprint"
	"github.com/Hesham127/flwnBackend/internal/task"
	"github.com/Hesham127/flwnBackend/internal/team"
	"github.com/Hesham127/flwnBackend/internal/user"
	"github.com/Hesham127/flwnBackend/internal/workitem"
	"github.com/Hesham127/flwnBackend/internal/workspace"
)

func NewRouter(engine *dataengine.Client) *gin.Engine {
	r := gin.Default()

	v1 := r.Group("/api/v1", httpx.Actor())
	user.RegisterRoutes(v1, user.NewService(engine))
	workspace.RegisterRoutes(v1, workspace.NewService(engine))
	member.RegisterRoutes(v1, member.NewService(engine))
	team.RegisterRoutes(v1, team.NewService(engine))
	project.RegisterRoutes(v1, project.NewService(engine))
	workitem.RegisterRoutes(v1, workitem.NewService(engine))
	sprint.RegisterRoutes(v1, sprint.NewService(engine))
	task.RegisterRoutes(v1, task.NewService(engine))

	return r
}
