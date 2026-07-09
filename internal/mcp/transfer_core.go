package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type transferFileOptions struct {
	Resume         bool
	ExpectedSHA256 string
	Progress       func(done, total int64)
}

type transferResult struct {
	BytesCopied int64  `json:"bytes_copied"`
	BytesTotal  int64  `json:"bytes_total"`
	ResumedFrom int64  `json:"resumed_from,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
}

func copySeekableToAtomicFile(ctx context.Context, src io.ReadSeeker, srcSize int64, dstPath string, opts transferFileOptions) (transferResult, error) {
	partPath := dstPath + ".part"
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o700); err != nil {
		return transferResult{}, err
	}

	var offset int64
	if opts.Resume {
		if st, err := os.Stat(partPath); err == nil {
			offset = st.Size()
			if offset > srcSize {
				offset = 0
			}
		}
	}
	if _, err := src.Seek(offset, io.SeekStart); err != nil {
		return transferResult{}, err
	}

	flags := os.O_CREATE | os.O_WRONLY
	if offset > 0 {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	dst, err := os.OpenFile(partPath, flags, 0o600)
	if err != nil {
		return transferResult{}, err
	}

	buf := make([]byte, 1024*1024)
	var copied int64
	for {
		if err := ctx.Err(); err != nil {
			_ = dst.Close()
			return transferResult{}, err
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				copied += int64(nw)
				if opts.Progress != nil {
					opts.Progress(offset+copied, srcSize)
				}
			}
			if ew != nil {
				_ = dst.Close()
				return transferResult{}, ew
			}
			if nr != nw {
				_ = dst.Close()
				return transferResult{}, io.ErrShortWrite
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			_ = dst.Close()
			return transferResult{}, er
		}
	}
	if err := dst.Close(); err != nil {
		return transferResult{}, err
	}

	sum, err := sha256File(partPath)
	if err != nil {
		return transferResult{}, err
	}
	if want := strings.TrimSpace(strings.ToLower(opts.ExpectedSHA256)); want != "" && sum != want {
		return transferResult{}, fmt.Errorf("sha256 mismatch: got %s want %s (left partial at %s)", sum, want, partPath)
	}
	if err := os.Rename(partPath, dstPath); err != nil {
		return transferResult{}, err
	}
	return transferResult{BytesCopied: copied, BytesTotal: srcSize, ResumedFrom: offset, SHA256: sum}, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type transferJob struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Alias       string `json:"alias"`
	RemotePath  string `json:"remote_path,omitempty"`
	LocalPath   string `json:"local_path,omitempty"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	BytesDone   int64  `json:"bytes_done"`
	BytesTotal  int64  `json:"bytes_total"`
	ResumedFrom int64  `json:"resumed_from,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at,omitempty"`
}

type transferManager struct {
	mu      sync.Mutex
	next    int64
	jobs    map[string]*transferJob
	nowFunc func() time.Time
}

var defaultTransferManager = newTransferManager()

func newTransferManager() *transferManager {
	return &transferManager{jobs: map[string]*transferJob{}, nowFunc: time.Now}
}

func (m *transferManager) start(kind, alias, remotePath, localPath string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	id := fmt.Sprintf("tx-%d-%d", m.nowFunc().UnixNano(), m.next)
	m.jobs[id] = &transferJob{
		ID: id, Kind: kind, Alias: alias, RemotePath: remotePath, LocalPath: localPath,
		Status: "running", StartedAt: m.nowFunc().Format(time.RFC3339),
	}
	return id
}

func (m *transferManager) update(id string, fn func(job *transferJob)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job, ok := m.jobs[id]; ok {
		fn(job)
	}
}

func (m *transferManager) finish(id string, res transferResult, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return
	}
	job.FinishedAt = m.nowFunc().Format(time.RFC3339)
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		return
	}
	job.Status = "completed"
	job.BytesDone = res.BytesTotal
	job.BytesTotal = res.BytesTotal
	job.ResumedFrom = res.ResumedFrom
	job.SHA256 = res.SHA256
}

func (m *transferManager) snapshot(id string) (transferJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return transferJob{}, false
	}
	return *job, true
}
