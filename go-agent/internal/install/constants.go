package install

const (
	// ServiceName is the primary Windows service for the Go agent.
	ServiceName        = "SOSECURE Threat inSight"
	ServiceDisplayName = "SOSECURE Threat inSight Agent"
	ServiceDescription = "SOSECURE Threat inSight — endpoint protection agent (heartbeat, scan, realtime, USB)."

	// WatchdogServiceName restarts the main service if stopped without authorization.
	WatchdogServiceName        = "SOSECURE Threat inSight Watchdog"
	WatchdogServiceDisplayName = "SOSECURE Threat inSight Watchdog"
	WatchdogServiceDescription = "Keeps the Threat inSight agent running; prompts for credentials if protection is stopped."

	legacyServiceMain     = "SOSECURE Threat inSights Service"
	legacyServiceWatchdog = "SOSECURE Threat inSights Agent Service"
	// Older installer registrations on some deployments
	legacyServiceMainAlt     = "SOSECURE_INSINTS_AGENT"
	legacyServiceWatchdogAlt = "SOSECURE_WATCHDOG_AGENT"
)
