package scan

import "testing"

func TestRealtimeSessionAccumulatesUntilOnDemandReset(t *testing.T) {
	m := &Manager{}

	m.rtBaseScanned.Store(0)
	m.rtBaseThreats.Store(0)
	m.rtAccumulating.Store(true)

	m.commitRealtimeSession(1, 1)
	m.commitRealtimeSession(1, 0)
	sc, th := m.realtimeSession()
	if sc != 2 || th != 1 {
		t.Fatalf("session after two silent files: scanned=%d threats=%d", sc, th)
	}

	m.rtBaseScanned.Store(int64(sc))
	m.rtBaseThreats.Store(int64(th))
	var st StatusInfo
	m.paintCounts(&st, 1, 1, 1) // third file in progress
	if st.Scanned != 3 || st.Threats != 2 || st.Total != 3 {
		t.Fatalf("paint during silent: %+v", st)
	}

	m.resetRealtimeSession()
	sc, th = m.realtimeSession()
	if sc != 0 || th != 0 {
		t.Fatalf("session after FULL reset: scanned=%d threats=%d", sc, th)
	}
	m.paintCounts(&st, 10, 100, 2)
	if st.Scanned != 10 || st.Total != 100 || st.Threats != 2 {
		t.Fatalf("paint after reset (on-demand): %+v", st)
	}
}
