//go:build !windows

package login

import (
	"context"

	"github.com/sosecure/insite-agent/internal/scan"
	"github.com/sosecure/insite-agent/internal/settings"
)

type Monitor struct{}

func New(_ *scan.Manager, _ *settings.Store) *Monitor { return &Monitor{} }

func (m *Monitor) Run(ctx context.Context) { <-ctx.Done() }
