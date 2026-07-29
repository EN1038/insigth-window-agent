package ipc

import (
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/history"
	"github.com/sosecure/insite-agent/internal/runtime"
	"github.com/sosecure/insite-agent/internal/settings"
)

// Service is implemented by app.Host for the local IPC API.
type Service interface {
	GetConfig() *config.AgentConfig
	GetSettings() *settings.Store
	GetHistory() *history.Store
	ReloadConfig(cfg *config.AgentConfig) error
	IsLoggedIn() bool
	Logout()
	Login(email, password string) (ok bool, msg, agentID string)
	TestConnection() bool
	ScanRuntime() *runtime.ScanRuntime
	PushSettingsToServer()
	SyncThreatIntel() (rulesN, ssdeepN int, err error)
	CheckAgentUpdate(autoInstall bool) error
	InstallAssignedAgentUpdate() error
	RulesInfo() RulesInfoResponse
	QuarantineList() []QuarantineItem
}
