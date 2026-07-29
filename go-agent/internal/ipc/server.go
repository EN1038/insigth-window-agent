package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/install"
	"github.com/sosecure/insite-agent/internal/settings"
)

type Server struct {
	svc Service
	srv *http.Server
}

func NewServer(svc Service) *Server {
	return &Server{svc: svc}
}

func (s *Server) Listen(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/config", s.handleConfig)
	mux.HandleFunc("/v1/connection/test", s.handleConnectionTest)
	mux.HandleFunc("/v1/login", s.handleLogin)
	mux.HandleFunc("/v1/logout", s.handleLogout)
	mux.HandleFunc("/v1/settings", s.handleSettings)
	mux.HandleFunc("/v1/scan/start", s.handleScanStart)
	mux.HandleFunc("/v1/scan/stop", s.handleScanStop)
	mux.HandleFunc("/v1/scan/status", s.handleScanStatus)
	mux.HandleFunc("/v1/rules/sync", s.handleRulesSync)
	mux.HandleFunc("/v1/rules/info", s.handleRulesInfo)
	mux.HandleFunc("/v1/quarantine", s.handleQuarantine)
	mux.HandleFunc("/v1/history", s.handleHistory)
	mux.HandleFunc("/v1/service/install", s.handleServiceInstall)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
	}()
	return s.srv.Serve(ln)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, OKResponse{OK: true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.svc.GetSettings()
	resp := StatusResponse{
		HasConfig:        s.svc.GetConfig() != nil,
		Approved:         st.GetBool("approved"),
		ThreatIntelReady: st.GetBool(settings.KeyTIBootstrapDone),
		SyncBusy:         st.GetBool(settings.KeyTISyncBusy),
		DownloadMessage:  st.Get(settings.KeyTIDownloadMessage, ""),
		LoggedIn:         s.svc.IsLoggedIn(),
		Online:           false, // use POST /v1/connection/test for server reachability (avoid blocking status)
		AgentID:          st.Get("agent_id", ""),
	}
	if p := strings.TrimSpace(st.Get(settings.KeyTIDownloadPercent, "0")); p != "" {
		fmt.Sscanf(p, "%f", &resp.DownloadPercent)
	}
	if sr := s.svc.ScanRuntime(); sr != nil && sr.Manager != nil {
		resp.Scanning = sr.Manager.IsScanning()
	}
	writeJSON(w, resp)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, ConfigToPublicView(s.svc.GetConfig()))
	case http.MethodPost:
		var req SaveConfigRequest
		if !readJSON(r, &req) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		cfg := &config.AgentConfig{
			SiteIP:  strings.TrimSpace(req.SiteIP),
			SiteID:  strings.TrimSpace(req.SiteID),
			SiteKey: strings.TrimSpace(req.SiteKey),
		}
		// Require all three fields every time (no silent reuse of a stored site key).
		if cfg.SiteIP == "" || cfg.SiteID == "" || cfg.SiteKey == "" {
			writeJSON(w, OKResponse{OK: false, Message: "Please fill Server IP, Site Code, and Site Key"})
			return
		}
		if prev := s.svc.GetConfig(); prev != nil {
			cfg.ClientCertPath = prev.ClientCertPath
			cfg.ClientCertPass = prev.ClientCertPass
			cfg.TLSInsecureSkipVerify = prev.TLSInsecureSkipVerify
			// Keep crypto salts only when connecting to the same site key.
			if prev.SiteKey == cfg.SiteKey && prev.SiteID == cfg.SiteID {
				cfg.SiteIPKey = prev.SiteIPKey
				cfg.SiteMacKey = prev.SiteMacKey
			}
		}
		if err := s.svc.ReloadConfig(cfg); err != nil {
			writeJSON(w, OKResponse{OK: false, Message: err.Error()})
			return
		}
		writeJSON(w, OKResponse{OK: true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleConnectionTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, OKResponse{OK: s.svc.TestConnection()})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req LoginRequest
	if !readJSON(r, &req) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ok, msg, agentID := s.svc.Login(req.Email, req.Password)
	writeJSON(w, LoginResponse{OK: ok, Message: msg, AgentID: agentID})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.svc.Logout()
	writeJSON(w, OKResponse{OK: true})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	st := s.svc.GetSettings()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, settingsView(st))
	case http.MethodPost:
		var req UpdateSettingsRequest
		if !readJSON(r, &req) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		applySettings(st, req)
		_ = st.Save()
		s.svc.PushSettingsToServer()
		writeJSON(w, OKResponse{OK: true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sr := s.svc.ScanRuntime()
	if sr == nil || sr.Manager == nil {
		writeJSON(w, OKResponse{OK: false, Message: "scan engine not ready (await approval)"})
		return
	}
	// Preflight rules so the UI can show an immediate actionable error instead of
	// failing asynchronously after returning OK.
	if err := sr.Manager.EnsureRulesReady(); err != nil {
		writeJSON(w, OKResponse{OK: false, Message: "rules not ready: " + err.Error() + " (sync rules first)"})
		return
	}
	var req ScanStartRequest
	if !readJSON(r, &req) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	mgr := sr.Manager
	switch strings.ToLower(req.Type) {
	case "quick":
		mgr.StartQuickScan()
	case "full":
		mgr.StartFullScan()
	case "auto":
		mgr.StartAutoScan()
	case "custom":
		if strings.TrimSpace(req.Path) == "" {
			writeJSON(w, OKResponse{OK: false, Message: "path required"})
			return
		}
		mgr.StartCustomScan(req.Path)
	default:
		writeJSON(w, OKResponse{OK: false, Message: "unknown scan type"})
		return
	}
	writeJSON(w, OKResponse{OK: true})
}

func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if sr := s.svc.ScanRuntime(); sr != nil && sr.Manager != nil {
		sr.Manager.StopScan()
	}
	writeJSON(w, OKResponse{OK: true})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if sr := s.svc.ScanRuntime(); sr != nil && sr.Manager != nil {
		st := sr.Manager.Status()
		writeJSON(w, ScanStatusResponse{
			Scanning: st.Scanning,
			ScanType: st.ScanType,
			Scanned:  st.Scanned,
			Total:    st.Total,
			Skipped:  st.Skipped,
			Threats:  st.Threats,
			Status:   st.Status,
		})
		return
	}
	writeJSON(w, ScanStatusResponse{})
}

func (s *Server) handleRulesSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.svc.GetSettings()
	if st != nil && st.GetBool(settings.KeyTISyncBusy) {
		writeJSON(w, OKResponse{OK: true, Message: "Sync already in progress"})
		return
	}
	if st != nil {
		st.Set(settings.KeyTISyncBusy, "true")
		st.Set(settings.KeyTIDownloadPercent, "0")
		st.Set(settings.KeyTIDownloadMessage, "Starting sync…")
		_ = st.Save()
	}
	go func() {
		defer func() {
			if st := s.svc.GetSettings(); st != nil {
				st.Set(settings.KeyTISyncBusy, "false")
				_ = st.Save()
			}
		}()
		rulesN, ssdeepN, err := s.svc.SyncThreatIntel()
		if err != nil {
			if st := s.svc.GetSettings(); st != nil {
				st.Set(settings.KeyTIDownloadMessage, "Sync failed: "+err.Error())
				_ = st.Save()
			}
			return
		}
		if sr := s.svc.ScanRuntime(); sr != nil {
			sr.RefreshRules()
		}
		if st := s.svc.GetSettings(); st != nil {
			st.Set(settings.KeyTIDownloadPercent, "100")
			st.Set(settings.KeyTIDownloadMessage, fmt.Sprintf("Sync done (rules=%d ssdeep=%d)", rulesN, ssdeepN))
			_ = st.Save()
		}
	}()
	writeJSON(w, OKResponse{OK: true, Message: "Sync started"})
}

func (s *Server) handleRulesInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.svc.RulesInfo())
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items := s.svc.QuarantineList()
	if items == nil {
		items = []QuarantineItem{}
	}
	writeJSON(w, items)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	events, err := s.svc.GetHistory().ReadRecent(7, limit)
	if err != nil {
		writeJSON(w, []HistoryEvent{})
		return
	}
	out := make([]HistoryEvent, 0, len(events))
	for _, ev := range events {
		out = append(out, HistoryEvent{
			Time:    ev.TimeRFC3339,
			Kind:    ev.Kind,
			Message: ev.Message,
		})
	}
	writeJSON(w, out)
}

func (s *Server) handleServiceInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var err error
	if install.LegacyServicesPresent() {
		err = install.UpgradeFromLegacy()
	} else {
		err = install.Install()
	}
	if err != nil {
		writeJSON(w, OKResponse{OK: false, Message: err.Error()})
		return
	}
	writeJSON(w, OKResponse{OK: true, Message: install.ServiceName + " installed"})
}

func settingsView(st *settings.Store) SettingsView {
	return SettingsView{
		RealtimeShield:      st.GetBool(settings.KeyRealtimeShield),
		USBProtection:       st.GetBool(settings.KeyUSBProtection),
		AutoScanOnLogin:     st.GetBool(settings.KeyAutoScanOnLogin),
		BatchJobEveryDay:    st.Get(settings.KeyBatchJobEveryDay, "02:00"),
		TISyncEveryDay:      st.Get(settings.KeyTISyncEveryDay, "03:00"),
		ExclusionPaths:      strings.ReplaceAll(st.Get(settings.KeyExclusionPaths, ""), ";", "\n"),
		ScanExtensions:      st.Get(settings.KeyScanExtensions, ""),
		QuickScanPaths:      strings.ReplaceAll(st.Get(settings.KeyQuickScanPaths, ""), ";", "\n"),
		SsdeepEnabled:       st.GetBool(settings.KeySsdeepEnabled),
		SsdeepThreshold:     st.Get(settings.KeySsdeepThreshold, "85"),
		SsdeepReportAPI:     st.GetBool(settings.KeySsdeepReportAPI),
		QuarantineOnDetect:  st.GetBool(settings.KeyQuarantineOnDetect),
		SendSsdeepCandidate: st.GetBool(settings.KeySendSsdeepCandidate),
		LogLevel:            st.Get(settings.KeyLogLevel, "info"),
		CacheExpiryHours:    st.Get(settings.KeyCacheExpiryHours, "168"),
		RulesVersion:        st.Get(settings.KeyRulesVersion, ""),
	}
}

func applySettings(st *settings.Store, req UpdateSettingsRequest) {
	if req.RealtimeShield != nil {
		st.Set(settings.KeyRealtimeShield, boolStr(*req.RealtimeShield))
	}
	if req.USBProtection != nil {
		st.Set(settings.KeyUSBProtection, boolStr(*req.USBProtection))
	}
	if req.AutoScanOnLogin != nil {
		st.Set(settings.KeyAutoScanOnLogin, boolStr(*req.AutoScanOnLogin))
	}
	if req.BatchJobEveryDay != "" {
		st.Set(settings.KeyBatchJobEveryDay, req.BatchJobEveryDay)
	}
	if req.TISyncEveryDay != "" {
		st.Set(settings.KeyTISyncEveryDay, req.TISyncEveryDay)
	}
	// UI always sends these; allow empty to clear exclusions.
	{
		normalized := strings.ReplaceAll(req.ExclusionPaths, "\r\n", ";")
		normalized = strings.ReplaceAll(normalized, "\n", ";")
		st.Set(settings.KeyExclusionPaths, normalized)
	}
	if strings.TrimSpace(req.ScanExtensions) != "" {
		normalized := strings.ReplaceAll(req.ScanExtensions, "\r\n", ",")
		normalized = strings.ReplaceAll(normalized, "\n", ",")
		normalized = strings.ReplaceAll(normalized, ";", ",")
		st.Set(settings.KeyScanExtensions, normalized)
		_ = st.MergeDefaultScanExtensions()
	}
	{
		normalized := strings.ReplaceAll(req.QuickScanPaths, "\r\n", ";")
		normalized = strings.ReplaceAll(normalized, "\n", ";")
		st.Set(settings.KeyQuickScanPaths, normalized)
	}
	if req.SsdeepEnabled != nil {
		st.Set(settings.KeySsdeepEnabled, boolStr(*req.SsdeepEnabled))
	}
	if req.SsdeepThreshold != "" {
		st.Set(settings.KeySsdeepThreshold, strings.TrimSpace(req.SsdeepThreshold))
	}
	if req.SsdeepReportAPI != nil {
		st.Set(settings.KeySsdeepReportAPI, boolStr(*req.SsdeepReportAPI))
	}
	if req.QuarantineOnDetect != nil {
		st.Set(settings.KeyQuarantineOnDetect, boolStr(*req.QuarantineOnDetect))
	}
	if req.SendSsdeepCandidate != nil {
		st.Set(settings.KeySendSsdeepCandidate, boolStr(*req.SendSsdeepCandidate))
	}
	if req.LogLevel != "" {
		st.Set(settings.KeyLogLevel, strings.ToLower(strings.TrimSpace(req.LogLevel)))
	}
	if req.CacheExpiryHours != "" {
		st.Set(settings.KeyCacheExpiryHours, strings.TrimSpace(req.CacheExpiryHours))
	}
	// Local Settings save wins until a newer Center edit arrives.
	st.Set(settings.KeyConfigUpdatedAt, strconv.FormatInt(time.Now().Unix(), 10))
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func readJSON(r *http.Request, out any) bool {
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return false
	}
	return json.Unmarshal(b, out) == nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
