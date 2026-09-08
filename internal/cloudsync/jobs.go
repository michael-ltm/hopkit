package cloudsync

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"
)

type Job struct {
	ID        string `json:"id"`
	Device    string `json:"device"`
	Action    string `json:"action"`
	Version   string `json:"version"`
	Expires   int64  `json:"expires"`
	Signature string `json:"signature"`
	Status    string `json:"status"`
}
type JobResult struct {
	Claim   string `json:"claim"`
	Status  string `json:"status"`
	Code    string `json:"code"`
	Count   int    `json:"count"`
	Receipt string `json:"receipt"`
}
type jobRecord struct {
	Result  JobResult `json:"result"`
	Expires int64     `json:"expires"`
}

var jobID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)
var jobVersion = regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,80}$`)

func (j Job) Message(user string) string {
	return fmt.Sprintf("sshm-job-v1\n%s\n%s\n%s\n%s\n%s\n%d", user, j.ID, j.Device, j.Action, j.Version, j.Expires)
}
func (v *Vault) VerifyJob(j Job, user, device string) bool {
	if !jobID.MatchString(j.ID) || j.Device != device || !jobID.MatchString(device) || j.Expires <= time.Now().UnixMilli() || j.Expires > time.Now().Add(24*time.Hour).UnixMilli() {
		return false
	}
	switch j.Action {
	case "sync", "inspect":
		if j.Version != "" {
			return false
		}
	case "update":
		if !jobVersion.MatchString(j.Version) {
			return false
		}
	default:
		return false
	}
	pub, _ := encoding.DecodeString(v.Public())
	sig, e := encoding.DecodeString(j.Signature)
	return e == nil && ed25519.Verify(pub, []byte(j.Message(user)), sig)
}
func (r JobResult) Message(user string, j Job) string {
	return fmt.Sprintf("sshm-job-result-v1\n%s\n%s\n%s\n%s\n%s\n%d", user, j.ID, j.Device, r.Status, r.Code, r.Count)
}
func (v *Vault) SignJobResult(user string, j Job, r *JobResult) {
	p := v.private()
	defer Wipe(p)
	r.Receipt = encoding.EncodeToString(ed25519.Sign(p, []byte(r.Message(user, j))))
}

// The private receipt journal is written before claiming or executing. A crash
// never silently reruns an installation; unfinished work is reported interrupted.
// Only bounded status codes and counts enter the server or local journal.
func (s *State) ProcessJobs(ctx context.Context, v *Vault, path string, execute func(context.Context, Job) JobResult) error {
	var list struct {
		Jobs []Job `json:"jobs"`
	}
	if e := s.Request(ctx, "POST", "/v1/jobs/poll", nil, &list); e != nil {
		return e
	}
	if len(list.Jobs) > 4 {
		return errors.New("invalid job queue")
	}
	if len(list.Jobs) == 0 {
		return nil
	}
	journal := map[string]jobRecord{}
	file := path + ".jobs.json"
	if b, e := os.ReadFile(file); e == nil {
		if len(b) > 2*1024*1024 || json.Unmarshal(b, &journal) != nil || journal == nil {
			return errors.New("invalid job journal")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	for k, r := range journal {
		if r.Expires < time.Now().Add(-7*24*time.Hour).UnixMilli() {
			delete(journal, k)
		}
	}
	save := func() error {
		b, e := json.Marshal(journal)
		if e != nil {
			return e
		}
		return WritePrivate(file, b)
	}
	for _, j := range list.Jobs {
		if !v.VerifyJob(j, s.Username, s.DeviceID) {
			continue
		}
		key := Digest([]string{s.Username, s.DeviceID, j.Signature})
		record, exists := journal[key]
		if !exists {
			record = jobRecord{Result: JobResult{Claim: RandomID(), Status: "failed", Code: "interrupted"}, Expires: j.Expires}
			journal[key] = record
			if e := save(); e != nil {
				return e
			}
		}
		// A running job without our receipt belongs to another process; never steal it.
		if j.Status == "running" && !exists {
			continue
		}
		jobCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		e := s.Request(jobCtx, "POST", "/v1/jobs/"+j.ID+"/claim", map[string]string{"claim": record.Result.Claim}, nil)
		if e != nil {
			cancel()
			return e
		}
		if !exists {
			result := execute(jobCtx, j)
			result.Claim = record.Result.Claim
			record.Result = result
		}
		v.SignJobResult(s.Username, j, &record.Result)
		journal[key] = record
		if e = save(); e != nil {
			cancel()
			return e
		}
		cancel()
		// Reporting gets its own short deadline even when the operation timed out.
		reportCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		e = s.Request(reportCtx, "POST", "/v1/jobs/"+j.ID+"/result", record.Result, nil)
		stop()
		if e != nil {
			return e
		}
	}
	return nil
}
