package mcp

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/safety"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/pkg/sftp"
)

// expandLocalHome expands a leading ~ in a local path to the user's home dir.
func expandLocalHome(p string) (string, error) {
	if !strings.HasPrefix(p, "~") {
		return p, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand path %q: %w", p, err)
	}
	return filepath.Join(h, p[1:]), nil
}

func handleUpload(deps Deps, args map[string]any) (any, error) {
	return handleUploadCtx(context.Background(), deps, args, nil)
}

func Upload(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	return handleUploadCtx(ctx, deps, args, nil)
}

// handleUploadCtx copies a LOCAL file to a remote server over SFTP. It returns
// a byte-count summary only — never the file content (which would blow the
// model's context window).
func handleUploadCtx(ctx context.Context, deps Deps, args map[string]any, progress func(done, total int64)) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	if alias == "" {
		return errResult("bad_request", "alias is required"), nil
	}
	localPath := strArg(args, "local_path")
	if localPath == "" {
		return errResult("bad_request", "local_path is required"), nil
	}
	remotePath := strArg(args, "remote_path")
	if remotePath == "" {
		return errResult("bad_request", "remote_path is required"), nil
	}

	expanded, err := expandLocalHome(localPath)
	if err != nil {
		return errResult("path", err.Error()), nil
	}
	if _, err := os.Stat(expanded); err != nil {
		return errResult("bad_request", fmt.Sprintf("open local file %s: %v", expanded, err)), nil
	}
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}

	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{ConfigPath: deps.ConfigPath})
	if err != nil {
		return errResult("ssh", safety.MaskSecrets(err.Error())), nil
	}
	defer cli.Close()

	sc, err := cli.NewSFTP()
	if err != nil {
		return errResult("sftp", safety.MaskSecrets(err.Error())), nil
	}
	defer sc.Close()

	res, err := uploadLocalFile(ctx, sc, expanded, remotePath, transferFileOptions{
		Resume:         boolArg(args, "resume"),
		ExpectedSHA256: strArg(args, "sha256"),
		Progress:       progress,
	})
	if err != nil {
		return errResult("sftp", safety.MaskSecrets(err.Error())), nil
	}

	audit(deps, safety.Entry{Tool: "upload", Alias: alias, Reason: reason,
		Result: fmt.Sprintf("uploaded %d bytes to %s", res.BytesCopied, remotePath)})
	return map[string]any{
		"alias": alias, "uploaded": true, "remote_path": remotePath,
		"bytes": res.BytesCopied, "bytes_total": res.BytesTotal,
		"resumed_from": res.ResumedFrom, "sha256": res.SHA256,
	}, nil
}

func handleDownload(deps Deps, args map[string]any) (any, error) {
	return handleDownloadCtx(context.Background(), deps, args, nil)
}

func Download(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	return handleDownloadCtx(ctx, deps, args, nil)
}

// handleDownloadCtx copies a remote file to the LOCAL machine over SFTP. It
// returns a byte-count summary only — never the file content.
func handleDownloadCtx(ctx context.Context, deps Deps, args map[string]any, progress func(done, total int64)) (any, error) {
	reason, err := requireReason(args)
	if err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	alias := strArg(args, "alias")
	if alias == "" {
		return errResult("bad_request", "alias is required"), nil
	}
	remotePath := strArg(args, "remote_path")
	if remotePath == "" {
		return errResult("bad_request", "remote_path is required"), nil
	}
	localPath := strArg(args, "local_path")
	if localPath == "" {
		return errResult("bad_request", "local_path is required"), nil
	}

	expanded, err := expandLocalHome(localPath)
	if err != nil {
		return errResult("path", err.Error()), nil
	}

	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return errResult("config", err.Error()), nil
	}
	s, ok := cfg.Servers[alias]
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown server %q", alias)), nil
	}

	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{ConfigPath: deps.ConfigPath})
	if err != nil {
		return errResult("ssh", safety.MaskSecrets(err.Error())), nil
	}
	defer cli.Close()

	sc, err := cli.NewSFTP()
	if err != nil {
		return errResult("sftp", safety.MaskSecrets(err.Error())), nil
	}
	defer sc.Close()

	res, err := downloadRemoteFile(ctx, sc, remotePath, expanded, transferFileOptions{
		Resume:         boolArg(args, "resume"),
		ExpectedSHA256: strArg(args, "sha256"),
		Progress:       progress,
	})
	if err != nil {
		return errResult("sftp", safety.MaskSecrets(err.Error())), nil
	}

	audit(deps, safety.Entry{Tool: "download", Alias: alias, Reason: reason,
		Result: fmt.Sprintf("downloaded %d bytes to %s", res.BytesCopied, expanded)})
	return map[string]any{
		"alias": alias, "downloaded": true, "local_path": expanded,
		"bytes": res.BytesCopied, "bytes_total": res.BytesTotal,
		"resumed_from": res.ResumedFrom, "sha256": res.SHA256,
	}, nil
}

func boolArg(args map[string]any, key string) bool {
	v, _ := args[key].(bool)
	return v
}

type sftpClient interface {
	Open(path string) (*sftp.File, error)
	OpenFile(path string, f int) (*sftp.File, error)
	Stat(path string) (os.FileInfo, error)
	Rename(oldname, newname string) error
	Remove(path string) error
}

func downloadRemoteFile(ctx context.Context, sc sftpClient, remotePath, localPath string, opts transferFileOptions) (transferResult, error) {
	st, err := sc.Stat(remotePath)
	if err != nil {
		return transferResult{}, fmt.Errorf("stat remote file %s: %w", remotePath, err)
	}
	src, err := sc.Open(remotePath)
	if err != nil {
		return transferResult{}, fmt.Errorf("open remote file %s: %w", remotePath, err)
	}
	defer src.Close()
	return copySeekableToAtomicFile(ctx, src, st.Size(), localPath, opts)
}

func uploadLocalFile(ctx context.Context, sc sftpClient, localPath, remotePath string, opts transferFileOptions) (transferResult, error) {
	src, err := os.Open(localPath)
	if err != nil {
		return transferResult{}, fmt.Errorf("open local file %s: %w", localPath, err)
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return transferResult{}, err
	}
	sum, err := sha256File(localPath)
	if err != nil {
		return transferResult{}, err
	}
	if want := strings.TrimSpace(strings.ToLower(opts.ExpectedSHA256)); want != "" && sum != want {
		return transferResult{}, fmt.Errorf("sha256 mismatch: got %s want %s", sum, want)
	}

	partPath := remotePath + ".part"
	var offset int64
	if opts.Resume {
		if partInfo, err := sc.Stat(partPath); err == nil {
			offset = partInfo.Size()
			if offset > st.Size() {
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
	dst, err := sc.OpenFile(partPath, flags)
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
					opts.Progress(offset+copied, st.Size())
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
	if err := sc.Rename(partPath, remotePath); err != nil {
		_ = sc.Remove(remotePath)
		if err2 := sc.Rename(partPath, remotePath); err2 != nil {
			return transferResult{}, err
		}
	}
	return transferResult{BytesCopied: copied, BytesTotal: st.Size(), ResumedFrom: offset, SHA256: sum}, nil
}

func transferManagerFromDeps(deps Deps) *transferManager {
	if deps.TransferManager != nil {
		return deps.TransferManager
	}
	return defaultTransferManager
}

func handleTransferStart(ctx context.Context, deps Deps, args map[string]any) (any, error) {
	if _, err := requireReason(args); err != nil {
		return errResult("bad_request", err.Error()), nil
	}
	kind := strings.ToLower(strings.TrimSpace(strArg(args, "direction")))
	if kind == "" {
		kind = strings.ToLower(strings.TrimSpace(strArg(args, "kind")))
	}
	if kind != "download" && kind != "upload" {
		return errResult("bad_request", "direction must be download or upload"), nil
	}
	alias := strArg(args, "alias")
	remotePath := strArg(args, "remote_path")
	localPath := strArg(args, "local_path")
	if alias == "" || remotePath == "" || localPath == "" {
		return errResult("bad_request", "alias, remote_path, and local_path are required"), nil
	}

	mgr := transferManagerFromDeps(deps)
	id := mgr.start(kind, alias, remotePath, localPath)
	jobArgs := map[string]any{}
	for k, v := range args {
		jobArgs[k] = v
	}
	go func() {
		progress := func(done, total int64) {
			mgr.update(id, func(job *transferJob) {
				job.BytesDone = done
				job.BytesTotal = total
			})
		}
		var out any
		var err error
		if kind == "download" {
			out, err = handleDownloadCtx(context.Background(), deps, jobArgs, progress)
		} else {
			out, err = handleUploadCtx(context.Background(), deps, jobArgs, progress)
		}
		res := transferResult{}
		if m, ok := out.(map[string]any); ok {
			if e, ok := m["error"]; ok {
				err = fmt.Errorf("%v", e)
			} else {
				if n, ok := m["bytes_total"].(int64); ok {
					res.BytesTotal = n
				}
				if n, ok := m["bytes"].(int64); ok {
					res.BytesCopied = n
				}
				if n, ok := m["resumed_from"].(int64); ok {
					res.ResumedFrom = n
				}
				if s, ok := m["sha256"].(string); ok {
					res.SHA256 = s
				}
			}
		}
		mgr.finish(id, res, err)
	}()
	audit(deps, safety.Entry{Tool: "transfer_start", Alias: alias, Reason: strArg(args, "reason"),
		Result: fmt.Sprintf("started %s transfer %s", kind, id)})
	snap, _ := mgr.snapshot(id)
	return snap, nil
}

func handleTransferStatus(_ context.Context, deps Deps, args map[string]any) (any, error) {
	id := strArg(args, "transfer_id")
	if id == "" {
		id = strArg(args, "id")
	}
	if id == "" {
		return errResult("bad_request", "transfer_id is required"), nil
	}
	snap, ok := transferManagerFromDeps(deps).snapshot(id)
	if !ok {
		return errResult("not_found", fmt.Sprintf("unknown transfer %q", id)), nil
	}
	return snap, nil
}

// registerTransferTools registers upload and download. These move files
// between the local machine and a remote server over the existing SSH
// connection (no shelling out to scp) and never return file content.
func registerTransferTools(s *server.MCPServer, deps Deps, names []string) []string {
	reg := func(name, desc string, fn func(context.Context, Deps, map[string]any) (any, error), extra ...mcp.ToolOption) {
		opts := append([]mcp.ToolOption{
			mcp.WithDescription(desc),
			mcp.WithString("alias", mcp.Description("server alias")),
			mcp.WithString("reason", mcp.Description("why (required, audited)")),
		}, extra...)
		tool := mcp.NewTool(name, opts...)
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := fn(ctx, deps, req.GetArguments())
			if err != nil {
				return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
			}
			js, err := maskedJSONResult(out)
			if err != nil {
				return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
			}
			return mcp.NewToolResultText(js), nil
		})
		names = append(names, name)
	}
	reg("upload", "Upload a local file to a remote server over SFTP (returns a byte-count summary, never content). Supports resume, .part temp files, and sha256 verification.",
		func(ctx context.Context, deps Deps, args map[string]any) (any, error) {
			return handleUploadCtx(ctx, deps, args, nil)
		},
		mcp.WithString("local_path", mcp.Description("local source file path")),
		mcp.WithString("remote_path", mcp.Description("remote destination file path")),
		mcp.WithBoolean("resume", mcp.Description("resume from an existing .part file when possible")),
		mcp.WithString("sha256", mcp.Description("expected SHA-256 checksum")))
	reg("download", "Download a remote file to the local machine over SFTP (returns a byte-count summary, never content). Supports resume, .part temp files, and sha256 verification.",
		func(ctx context.Context, deps Deps, args map[string]any) (any, error) {
			return handleDownloadCtx(ctx, deps, args, nil)
		},
		mcp.WithString("remote_path", mcp.Description("remote source file path")),
		mcp.WithString("local_path", mcp.Description("local destination file path")),
		mcp.WithBoolean("resume", mcp.Description("resume from an existing .part file when possible")),
		mcp.WithString("sha256", mcp.Description("expected SHA-256 checksum")))
	reg("transfer_start", "Start a background upload/download so large files can be polled with transfer_status instead of blocking one MCP call.", handleTransferStart,
		mcp.WithString("direction", mcp.Description("download or upload")),
		mcp.WithString("remote_path", mcp.Description("remote file path")),
		mcp.WithString("local_path", mcp.Description("local file path")),
		mcp.WithBoolean("resume", mcp.Description("resume from an existing .part file when possible")),
		mcp.WithString("sha256", mcp.Description("expected SHA-256 checksum")))
	statusTool := mcp.NewTool("transfer_status",
		mcp.WithDescription("Get the current status of a background file transfer."),
		mcp.WithString("transfer_id", mcp.Description("transfer id returned by transfer_start")))
	s.AddTool(statusTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, err := handleTransferStatus(ctx, deps, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
		}
		js, err := maskedJSONResult(out)
		if err != nil {
			return mcp.NewToolResultError(safety.MaskSecrets(err.Error())), nil
		}
		return mcp.NewToolResultText(js), nil
	})
	names = append(names, "transfer_status")
	return names
}
