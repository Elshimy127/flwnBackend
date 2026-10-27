package member

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
	var in Create
	if !httpx.BindJSON(c, &in) {
		return
	}
	out, err := h.svc.Create(c.Request.Context(), ws, in)
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
	page, ok := httpx.QueryPage(c)
	if !ok {
		return
	}
	out, err := h.svc.List(c.Request.Context(), ws, page)
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
	id, ok := httpx.PathUUID(c, "member_id")
	if !ok {
		return
	}
	out, err := h.svc.Get(c.Request.Context(), ws, id)
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
	id, ok := httpx.PathUUID(c, "member_id")
	if !ok {
		return
	}
	var in Update
	if !httpx.BindJSON(c, &in) {
		return
	}
	out, err := h.svc.Update(c.Request.Context(), ws, id, in)
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
	id, ok := httpx.PathUUID(c, "member_id")
	if !ok {
		return
	}
	if err := h.svc.Delete(c.Request.Context(), ws, id); err != nil {
		httpx.Error(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
