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

// handleUpload copies a LOCAL file to a remote server over SFTP. It returns a
// byte-count summary only — never the file content (which would blow the
// model's context window).
func handleUpload(deps Deps, args map[string]any) (any, error) {
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
	src, err := os.Open(expanded)
	if err != nil {
		return errResult("bad_request", fmt.Sprintf("open local file %s: %v", expanded, err)), nil
	}
	defer src.Close()

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

	dst, err := sc.Create(remotePath)
	if err != nil {
		return errResult("sftp", safety.MaskSecrets(err.Error())), nil
	}
	n, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return errResult("sftp", safety.MaskSecrets(copyErr.Error())), nil
	}
	if closeErr != nil {
		return errResult("sftp", safety.MaskSecrets(closeErr.Error())), nil
	}

	audit(deps, safety.Entry{Tool: "upload", Alias: alias, Reason: reason,
		Result: fmt.Sprintf("uploaded %d bytes to %s", n, remotePath)})
	return map[string]any{"alias": alias, "uploaded": true, "remote_path": remotePath, "bytes": n}, nil
}

// handleDownload copies a remote file to the LOCAL machine over SFTP. It
// returns a byte-count summary only — never the file content.
func handleDownload(deps Deps, args map[string]any) (any, error) {
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

	src, err := sc.Open(remotePath)
	if err != nil {
		return errResult("bad_request", fmt.Sprintf("open remote file %s: %v", remotePath, safety.MaskSecrets(err.Error()))), nil
	}
	defer src.Close()

	if err := os.MkdirAll(filepath.Dir(expanded), 0o700); err != nil {
		return errResult("path", safety.MaskSecrets(err.Error())), nil
	}
	dst, err := os.Create(expanded)
	if err != nil {
		return errResult("path", safety.MaskSecrets(err.Error())), nil
	}
	n, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return errResult("sftp", safety.MaskSecrets(copyErr.Error())), nil
	}
	if closeErr != nil {
		return errResult("path", safety.MaskSecrets(closeErr.Error())), nil
	}

	audit(deps, safety.Entry{Tool: "download", Alias: alias, Reason: reason,
		Result: fmt.Sprintf("downloaded %d bytes to %s", n, expanded)})
	return map[string]any{"alias": alias, "downloaded": true, "local_path": expanded, "bytes": n}, nil
}

// registerTransferTools registers upload and download. These move files
// between the local machine and a remote server over the existing SSH
// connection (no shelling out to scp) and never return file content.
func registerTransferTools(s *server.MCPServer, deps Deps, names []string) []string {
	reg := func(name, desc string, fn func(Deps, map[string]any) (any, error), extra ...mcp.ToolOption) {
		opts := append([]mcp.ToolOption{
			mcp.WithDescription(desc),
			mcp.WithString("alias", mcp.Description("server alias")),
			mcp.WithString("reason", mcp.Description("why (required, audited)")),
		}, extra...)
		tool := mcp.NewTool(name, opts...)
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := fn(deps, req.GetArguments())
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			js, _ := jsonResult(out)
			return mcp.NewToolResultText(safety.MaskSecrets(js)), nil
		})
		names = append(names, name)
	}
	reg("upload", "Upload a local file to a remote server over SFTP (returns a byte-count summary, never content).", handleUpload,
		mcp.WithString("local_path", mcp.Description("local source file path")),
		mcp.WithString("remote_path", mcp.Description("remote destination file path")))
	reg("download", "Download a remote file to the local machine over SFTP (returns a byte-count summary, never content).", handleDownload,
		mcp.WithString("remote_path", mcp.Description("remote source file path")),
		mcp.WithString("local_path", mcp.Description("local destination file path")))
	return names
}
