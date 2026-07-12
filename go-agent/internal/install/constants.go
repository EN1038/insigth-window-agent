package install

const (
	// ServiceName is the single Windows service for the Go agent.
	ServiceName        = "SOSECURE Threat inSight"
	ServiceDisplayName = "SOSECURE Threat inSight Agent"
	ServiceDescription = "SOSECURE Threat inSight — endpoint protection agent (heartbeat, scan, realtime, USB)."

	legacyServiceMain     = "SOSECURE Threat inSights Service"
	legacyServiceWatchdog = "SOSECURE Threat inSights Agent Service"
	// Older installer registrations on some deployments
	legacyServiceMainAlt     = "SOSECURE_INSINTS_AGENT"
	legacyServiceWatchdogAlt = "SOSECURE_WATCHDOG_AGENT"
)
