package sprint

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Hesham127/flwnBackend/internal/platform/httpx"
)

type handler struct {
	svc *Service
}

func (h *handler) create(c *gin.Context) {
	ws, ok := httpx.PathUUID(c, "workspace_id")
	if !ok {
		return
	}
	project, ok := httpx.PathUUID(c, "project_id")
	if !ok {
		return
	}
	var in Create
	if !httpx.BindJSON(c, &in) {
		return
	}
	out, err := h.svc.Create(c.Request.Context(), ws, project, in)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	c.JSON(http.StatusCreated, out)
}

func (h *handler) list(c *gin.Context) {
	ws, ok := httpx.PathUUID(c, "workspace_id")
	if !ok {
		return
	}
	project, ok := httpx.PathUUID(c, "project_id")
	if !ok {
		return
	}
	page, ok := httpx.QueryPage(c)
	if !ok {
		return
	}
	out, err := h.svc.List(c.Request.Context(), ws, project, httpx.QueryString(c, "status"), page)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *handler) get(c *gin.Context) {
	ws, ok := httpx.PathUUID(c, "workspace_id")
	if !ok {
		return
	}
	project, ok := httpx.PathUUID(c, "project_id")
	if !ok {
		return
	}
	id, ok := httpx.PathUUID(c, "sprint_id")
	if !ok {
		return
	}
	out, err := h.svc.Get(c.Request.Context(), ws, project, id)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *handler) update(c *gin.Context) {
	ws, ok := httpx.PathUUID(c, "workspace_id")
	if !ok {
		return
	}
	project, ok := httpx.PathUUID(c, "project_id")
	if !ok {
		return
	}
	id, ok := httpx.PathUUID(c, "sprint_id")
	if !ok {
		return
	}
	var in Update
	if !httpx.BindJSON(c, &in) {
		return
	}
	out, err := h.svc.Update(c.Request.Context(), ws, project, id, in)
	if err != nil {
		httpx.Error(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *handler) delete(c *gin.Context) {
	ws, ok := httpx.PathUUID(c, "workspace_id")
	if !ok {
		return
	}
	project, ok := httpx.PathUUID(c, "project_id")
	if !ok {
		return
	}
	id, ok := httpx.PathUUID(c, "sprint_id")
	if !ok {
		return
	}
	if err := h.svc.Delete(c.Request.Context(), ws, project, id); err != nil {
		httpx.Error(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
