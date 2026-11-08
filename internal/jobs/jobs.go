// Package jobs runs the backend's background work: provisioning reconciliation and cleanup of
// expired auth rows. Jobs use the system engine identity, never a request's acting member.
package jobs

import (
	"context"
	"log"
	"time"

	"github.com/Hesham127/flwnBackend/internal/auth"
)

// Run starts the jobs and stops when ctx ends.
func Run(ctx context.Context, svc *auth.Service) {
	go every(ctx, time.Minute, "reconcile_provisioning", func(ctx context.Context) error {
		return svc.ReconcileProvisioning(ctx)
	})
	go every(ctx, time.Hour, "auth_cleanup", func(ctx context.Context) error {
		n, err := svc.Store().Cleanup(ctx, time.Now().UTC())
		if n > 0 {
			log.Printf("job auth_cleanup deleted %d rows", n)
		}
		return err
	})
}

func every(ctx context.Context, d time.Duration, name string, fn func(context.Context) error) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		runCtx, cancel := context.WithTimeout(ctx, d/2)
		if err := fn(runCtx); err != nil {
			log.Printf("job %s actor=system:%s: %v", name, name, err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
