package httpx

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Actor puts the calling member into the request context, so engine writes are attributed to them.
//
// TODO: this trusts a dev header. Replace it with real authentication (session/JWT → member id)
// before anything is exposed outside local development.
func Actor() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader("X-Member-Id")
		if raw == "" {
			c.Next()
			return
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			badRequest(c, "X-Member-Id must be a UUID")
			return
		}
		c.Request = c.Request.WithContext(dataengine.WithActingMember(c.Request.Context(), id))
		c.Next()
	}
}
