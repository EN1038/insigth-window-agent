package reportq

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sosecure/insite-agent/internal/api"
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/storage"
)

const (
	KindYara            = "sendLogYara"
	KindHash            = "sendHash"
	KindSsdeep          = "sendLogSsdeep"
	KindSsdeepCandidate = "sendSsdeepCandidate"
	KindScanLog         = "sendAgentScanLog"
	KindScanFile        = "sendScanFileLog"

	maxItems    = 200
	maxAttempts = 12
)

// Item is one durable outbound API payload awaiting retry.
type Item struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	Attempts  int             `json:"attempts"`
	LastError string          `json:"last_error,omitempty"`
	CreatedAt int64           `json:"created_at"`
}

type Queue struct {
	mu   sync.Mutex
	enc  storage.EncryptedJSON
	path string
}

func New(baseDir string) *Queue {
	p := config.ResolvePaths(baseDir)
	return &Queue{
		path: filepath.Join(p.DataDir, "report_queue.enc"),
		enc: storage.EncryptedJSON{
			VaultPath: p.VaultPath,
			Path:      filepath.Join(p.DataDir, "report_queue.enc"),
			Purpose:   "report-queue",
			AAD:       "report-queue|v1",
		},
	}
}

type filePayload struct {
	Items []Item `json:"items"`
}

func (q *Queue) loadLocked() []Item {
	var p filePayload
	if err := q.enc.Load(&p); err != nil {
		if !os.IsNotExist(err) {
			return nil
		}
		return nil
	}
	return p.Items
}

func (q *Queue) saveLocked(items []Item) error {
	if len(items) > maxItems {
		items = items[len(items)-maxItems:]
	}
	return q.enc.Save(filePayload{Items: items})
}

// Enqueue stores a failed API payload for later retry.
func (q *Queue) Enqueue(kind string, payload any) error {
	if q == nil {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	items := q.loadLocked()
	items = append(items, Item{
		ID:        fmt.Sprintf("%d-%d", time.Now().UnixNano(), len(items)+1),
		Kind:      kind,
		Payload:   raw,
		CreatedAt: time.Now().Unix(),
	})
	return q.saveLocked(items)
}

// Flush retries queued items against the Center API. Returns number sent.
func (q *Queue) Flush(client *api.Client) (sent int, err error) {
	if q == nil || client == nil {
		return 0, nil
	}
	q.mu.Lock()
	items := q.loadLocked()
	q.mu.Unlock()
	if len(items) == 0 {
		return 0, nil
	}

	var remain []Item
	for _, it := range items {
		if it.Attempts >= maxAttempts {
			continue // drop permanently failed
		}
		ok, sendErr := dispatch(client, it)
		if ok {
			sent++
			continue
		}
		it.Attempts++
		if sendErr != nil {
			it.LastError = sendErr.Error()
		}
		remain = append(remain, it)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if saveErr := q.saveLocked(remain); saveErr != nil {
		return sent, saveErr
	}
	return sent, nil
}

func dispatch(client *api.Client, it Item) (bool, error) {
	switch it.Kind {
	case KindYara:
		var items []api.YaraLogItem
		if err := json.Unmarshal(it.Payload, &items); err != nil {
			return false, err
		}
		resp, _, err := client.SendLogYara(items)
		return apiOK(resp, err), err
	case KindHash:
		var items []api.HashItem
		if err := json.Unmarshal(it.Payload, &items); err != nil {
			return false, err
		}
		resp, _, err := client.SendHash(items)
		return apiOK(resp, err), err
	case KindSsdeep:
		var items []api.SsdeepLogItem
		if err := json.Unmarshal(it.Payload, &items); err != nil {
			return false, err
		}
		resp, _, err := client.SendLogSsdeep(items)
		return apiOK(resp, err), err
	case KindSsdeepCandidate:
		var items []api.SsdeepCandidateItem
		if err := json.Unmarshal(it.Payload, &items); err != nil {
			return false, err
		}
		resp, _, err := client.SendSsdeepCandidate(items)
		return apiOK(resp, err), err
	case KindScanLog:
		var items []api.ScanLogItem
		if err := json.Unmarshal(it.Payload, &items); err != nil {
			return false, err
		}
		resp, _, err := client.SendAgentScanLog(items)
		return apiOK(resp, err), err
	case KindScanFile:
		var items []api.ScanFileItem
		if err := json.Unmarshal(it.Payload, &items); err != nil {
			return false, err
		}
		resp, _, err := client.SendScanFileLog(items)
		return apiOK(resp, err), err
	default:
		return false, fmt.Errorf("unknown kind %s", it.Kind)
	}
}

func apiOK(resp *api.Response, err error) bool {
	if err != nil {
		return false
	}
	if resp == nil {
		return false
	}
	return resp.StatusCode > 0 && resp.StatusCode < 400
}
