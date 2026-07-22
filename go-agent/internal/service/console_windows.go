//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sosecure/insite-agent/internal/app"
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/ipc"
	"github.com/sosecure/insite-agent/internal/ui"
)

func runConsole() error {
	baseDir := config.DataBaseDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	host, client, err := ensureHost(ctx, baseDir)
	if err != nil {
		return err
	}
	if host != nil {
		defer cancel()
	}

	return ui.Run(ctx, client, host != nil)
}

func ensureHost(ctx context.Context, baseDir string) (*app.Host, *ipc.Client, error) {
	client := ipc.NewClient(ipc.DefaultAddr)
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	err := client.Health(pingCtx)
	cancel()
	if err == nil {
		return nil, client, nil
	}

	host, err := app.NewHost(baseDir)
	if err != nil {
		return nil, nil, err
	}
	go func() { _ = host.Start(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		pingCtx, cancel := context.WithTimeout(ctx, time.Second)
		err := client.Health(pingCtx)
		cancel()
		if err == nil {
			return host, client, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return host, client, fmt.Errorf("ipc server did not start")
}

func RunUI() error {
	baseDir := config.DataBaseDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()

	host, client, err := ensureHost(ctx, baseDir)
	if err != nil {
		return err
	}
	_ = host
	return ui.Run(ctx, client, host != nil)
}

// RunConfirmStopUI opens the credential gate used when stopping protection.
func RunConfirmStopUI() error {
	baseDir := config.DataBaseDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()

	_, client, err := ensureHost(ctx, baseDir)
	if err != nil {
		return err
	}
	return ui.RunConfirmStop(ctx, client, StopProtectionAuthorized)
}

// RunConfirmExitUI opens the credential gate used when exiting the tray UI.
func RunConfirmExitUI() error {
	baseDir := config.DataBaseDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()

	_, client, err := ensureHost(ctx, baseDir)
	if err != nil {
		return err
	}
	return ui.RunConfirmExit(ctx, client)
}
