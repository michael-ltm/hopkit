package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Entry is one audit record. Reason is masked before being written.
type Entry struct {
	Time   string `json:"time"`
	Tool   string `json:"tool"`
	Alias  string `json:"alias,omitempty"`
	Reason string `json:"reason,omitempty"`
	Result string `json:"result,omitempty"`
}

// AuditLog appends JSON-lines records to a file with mode 0600.
type AuditLog struct {
	path string
}

// NewAuditLog returns an AuditLog that appends to path.
func NewAuditLog(path string) *AuditLog { return &AuditLog{path: path} }

// Append writes one masked record. The file and its parent directory are
// created on first use. Each record is one JSON object on its own line.
func (a *AuditLog) Append(e Entry) error {
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return fmt.Errorf("mkdir audit dir: %w", err)
	}
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.Reason = MaskSecrets(e.Reason)
	e.Result = MaskSecrets(e.Result)

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return nil
}
