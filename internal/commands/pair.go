package commands

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/michael-ltm/sshm/internal/keystore"
	"github.com/michael-ltm/sshm/internal/pair"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/michael-ltm/sshm/internal/wizard"
	"github.com/spf13/cobra"
)

const defaultPairTimeout = 30 * time.Minute
const pairCallbackRetryGrace = 25 * time.Second
const maxPrintedPairCommandBytes = 8190

type pairOptions struct {
	host           string
	port           int
	user           string
	description    string
	tags           string
	group          string
	keyPath        string
	scriptDir      string
	callbackHost   string
	listen         string
	target         string
	timeout        time.Duration
	noEncrypt      bool
	connectTimeout time.Duration
	hostSet        bool
	portSet        bool
	descriptionSet bool
	tagsSet        bool
	groupSet       bool
}

func newPairCmd() *cobra.Command {
	opts := defaultPairOptions()
	c := &cobra.Command{
		Use:   "pair [alias]",
		Short: "Pair a Windows, Linux, or macOS host with one target-side command",
		Long: `With no arguments, opens a guided form for address, description, and target system.

With an alias, creates a one-time local pairing session and prints self-contained commands.

Run the Windows command in Administrator PowerShell, or the POSIX command in
the target user's Linux/macOS shell. The target installs/starts OpenSSH when
needed, appends the generated public key, reports its actual username, and is
saved only after sshm verifies a real key-authenticated SSH session.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if flagJSON {
				return fmt.Errorf("--json is not supported by the streaming pair command")
			}
			if len(args) == 0 {
				if cmd.LocalNonPersistentFlags().NFlag() > 0 {
					return fmt.Errorf("pair flags require an alias; run plain `sshm pair` for the guided form")
				}
				if !commandHasTerminal(cmd) {
					return fmt.Errorf("guided pairing requires a terminal; use `sshm pair <alias> --host <host>`")
				}
				cfg, _, err := loadConfig()
				if err != nil {
					return err
				}
				return runPairWizard(cmd, cfg)
			}
			opts.hostSet = cmd.Flags().Changed("host")
			opts.portSet = cmd.Flags().Changed("port")
			opts.descriptionSet = cmd.Flags().Changed("description")
			opts.tagsSet = cmd.Flags().Changed("tags")
			opts.groupSet = cmd.Flags().Changed("group")
			if !cmd.Flags().Changed("target") && commandHasTerminal(cmd) {
				currentPlatform := config.PlatformWindows
				cfg, _, err := loadConfig()
				if err != nil {
					return err
				}
				if existing := cfg.Servers[args[0]]; existing != nil && existing.Platform != "" {
					currentPlatform = existing.Platform
				}
				platform, err := wizard.RunPairPlatform(currentPlatform, cmd.InOrStdin(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				opts.target = pairTargetForPlatform(platform)
			}
			return runPairCommand(cmd, args[0], opts)
		},
	}
	c.Flags().StringVar(&opts.host, "host", "", "host/IP (required when pairing a new alias)")
	c.Flags().IntVar(&opts.port, "port", 22, "SSH port")
	c.Flags().StringVar(&opts.user, "user", "", "fallback username until the target reports its actual user")
	c.Flags().StringVarP(&opts.description, "description", "d", "", "server purpose/description")
	c.Flags().StringVar(&opts.tags, "tags", "", "comma-separated discovery tags")
	c.Flags().StringVar(&opts.group, "group", "", "server group")
	c.Flags().StringVarP(&opts.keyPath, "identity", "i", "", "key path (default ~/.ssh/id_ed25519_<alias>)")
	c.Flags().StringVar(&opts.scriptDir, "script-dir", "", "write private target command files here instead of printing them")
	c.Flags().StringVar(&opts.callbackHost, "callback-host", "", "Tailscale/LAN address the target can reach (auto-detected)")
	c.Flags().StringVar(&opts.listen, "listen", "", "local callback listen address (default matches callback address family)")
	c.Flags().StringVar(&opts.target, "target", "all", "command to print: windows, posix, or all")
	c.Flags().DurationVar(&opts.timeout, "timeout", defaultPairTimeout, "time to wait for the target command")
	c.Flags().DurationVar(&opts.connectTimeout, "connect-timeout", 45*time.Second, "time to retry verified SSH after callback")
	c.Flags().BoolVar(&opts.noEncrypt, "no-encrypt", false, "generate an unencrypted private key (not recommended)")
	return c
}

func defaultPairOptions() pairOptions {
	return pairOptions{
		port:           22,
		target:         "all",
		timeout:        defaultPairTimeout,
		connectTimeout: 45 * time.Second,
	}
}

func runPairWizard(cmd *cobra.Command, cfg *config.Config) error {
	existing := make([]string, 0, len(cfg.Servers))
	for alias := range cfg.Servers {
		existing = append(existing, alias)
	}
	input, err := wizard.RunPair(existing, cmd.InOrStdin(), cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(input.Port)
	if err != nil {
		return err
	}
	opts := defaultPairOptions()
	opts.host = input.Host
	opts.port = port
	opts.description = input.Description
	opts.tags = input.Tags
	opts.group = input.Group
	opts.target = pairTargetForPlatform(input.Platform)
	return runPairCommand(cmd, input.Alias, opts)
}

func pairTargetForPlatform(platform string) string {
	switch platform {
	case config.PlatformWindows:
		return "windows"
	case config.PlatformLinux, config.PlatformMacOS:
		return "posix"
	default:
		return "all"
	}
}

func runPairCommand(cmd *cobra.Command, alias string, opts pairOptions) error {
	if err := wizard.ValidateAlias(alias); err != nil {
		return err
	}
	if opts.timeout <= 0 || opts.connectTimeout <= 0 {
		return fmt.Errorf("timeouts must be positive")
	}
	switch opts.target {
	case "all", "windows", "posix":
	default:
		return fmt.Errorf("--target must be windows, posix, or all")
	}

	cfg, path, err := loadConfig()
	if err != nil {
		return err
	}
	existing, exists := cfg.Servers[alias]
	if exists && existing == nil {
		return fmt.Errorf("server %q has an empty config entry", alias)
	}
	server, err := pairCandidate(existing, exists, opts)
	if err != nil {
		return err
	}
	callbackHost := strings.TrimSpace(strings.Trim(opts.callbackHost, "[]"))
	if callbackHost == "" {
		callbackHost, err = pair.DiscoverCallbackHost(server.Host, server.Port)
		if err != nil {
			if !commandHasTerminal(cmd) {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Automatic callback route could not be used: %v\n", err)
			callbackHost, err = wizard.RunCallbackHost(cmd.InOrStdin(), cmd.ErrOrStderr(), pair.ValidateCallbackHost)
			if err != nil {
				return err
			}
		}
	} else if err := pair.ValidateCallbackHost(callbackHost); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", pairListenAddress(callbackHost, opts.listen))
	if err != nil {
		return fmt.Errorf("open pair callback listener: %w", err)
	}
	defer listener.Close()
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("pair callback listener is not TCP")
	}

	keyPath := opts.keyPath
	if keyPath == "" && server.KeyPath != "" {
		keyPath = server.KeyPath
	}
	if keyPath == "" {
		keyPath = filepath.Join("~", ".ssh", "id_ed25519_"+alias)
	}
	expandedKey, err := sshpkg.ExpandHome(keyPath)
	if err != nil {
		return err
	}
	publicKey, generated, err := preparePairKey(cmd, alias, expandedKey, opts.noEncrypt)
	if err != nil {
		return err
	}
	server.Auth = config.AuthKey
	server.KeyPath = keyPath

	token, err := pair.NewToken()
	if err != nil {
		if generated {
			keys.RemoveGenerated(expandedKey)
		}
		return err
	}
	callbackURL := pair.CallbackURL(callbackHost, tcpAddr.Port, token)
	scripts, err := pair.BuildScripts(publicKey, callbackURL, server.Port)
	if err != nil {
		return err
	}
	if opts.scriptDir == "" {
		if err := validatePrintedPairCommandLengths(opts.target, scripts); err != nil {
			return err
		}
	}

	reports := make(chan pair.Report, 1)
	retryAcknowledged := make(chan struct{}, 1)
	httpServer := &http.Server{
		Handler:           pair.HandlerWithRetrySignal(token, reports, retryAcknowledged),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Pairing %q at %s (callback %s)\n", alias, sshpkg.Address(server), pair.RedactedURL(callbackURL))
	if generated {
		fmt.Fprintf(out, "Generated key: %s\n", expandedKey)
	}
	if opts.scriptDir != "" {
		paths, err := writePairCommandFiles(opts.scriptDir, alias, opts.target, scripts)
		if err != nil {
			return err
		}
		for _, path := range paths {
			fmt.Fprintf(out, "Target command file: %s\n", path)
		}
	} else {
		if opts.target == "all" || opts.target == "windows" {
			fmt.Fprintln(out, "\nWindows (run in Administrator PowerShell):")
			fmt.Fprintln(out, scripts.Windows)
		}
		if opts.target == "all" || opts.target == "posix" {
			fmt.Fprintln(out, "\nLinux/macOS (run as the target login user; sudo may prompt):")
			fmt.Fprintln(out, scripts.POSIX)
		}
	}
	fmt.Fprintf(out, "\nWaiting up to %s for the target...\n", opts.timeout)

	waitCtx, cancel := context.WithTimeout(cmd.Context(), opts.timeout)
	defer cancel()
	var report pair.Report
	select {
	case report = <-reports:
		fmt.Fprintf(out, "Target reported %s@%s (%s); verifying key login...\n", report.User, report.Hostname, report.Platform)
	case err := <-serveErr:
		return fmt.Errorf("pair callback server: %w; %s", err, pairRetryInstruction(alias, exists, opts.keyPath, keyPath))
	case <-waitCtx.Done():
		return fmt.Errorf("pairing timed out waiting for the target; keep the generated key and %s", pairRetryInstruction(alias, exists, opts.keyPath, keyPath))
	}

	server.User = report.User
	verifyCtx, verifyCancel := context.WithTimeout(cmd.Context(), opts.connectTimeout)
	defer verifyCancel()
	verifiedUser, verifiedHost, err := verifyPairedServer(verifyCtx, server)
	if err != nil {
		return fmt.Errorf("target callback received but SSH verification failed: %w; %s", err, pairRetryInstruction(alias, exists, opts.keyPath, keyPath))
	}
	if !sameReportedUser(report, verifiedUser) {
		return fmt.Errorf("SSH identity mismatch: target reported user %q but whoami returned %q", report.User, verifiedUser)
	}
	server.Platform = platformFromPairReport(report.Platform)

	if err := config.Update(path, func(latest *config.Config) error {
		current, currentExists := latest.Servers[alias]
		saved := server
		if exists {
			if !currentExists || current == nil {
				return fmt.Errorf("server %q changed while pairing", alias)
			}
			if current.Host != existing.Host || current.Port != existing.Port {
				return fmt.Errorf("server %q connection changed while pairing", alias)
			}
			// Pairing may wait for many minutes. Preserve unrelated edits that
			// landed meanwhile and update only the fields this operation proved
			// or the caller explicitly requested.
			saved = current
			saved.User = server.User
			saved.Auth = config.AuthKey
			saved.KeyPath = server.KeyPath
			saved.Platform = server.Platform
			if opts.descriptionSet {
				saved.Description = server.Description
			}
			if opts.tagsSet {
				saved.Tags = server.Tags
			}
			if opts.groupSet {
				saved.Group = server.Group
			}
		} else if currentExists {
			return fmt.Errorf("server %q was added by another process while pairing", alias)
		}
		now := time.Now().UTC()
		if !exists && saved.CreatedAt.IsZero() {
			saved.CreatedAt = now
		}
		saved.LastUsed = now
		saved.LastChecked = now
		saved.LastSeen = now
		saved.LastStatus = config.StatusOnline
		latest.Servers[alias] = saved
		if latest.Default == "" {
			latest.Default = alias
		}
		return nil
	}); err != nil {
		return fmt.Errorf("SSH pairing was verified but the config could not be saved: %w; %s", err, pairRetryInstruction(alias, exists, opts.keyPath, keyPath))
	}

	fmt.Fprintf(out, "paired %q: verified %s on %s via key-authenticated SSH\n", alias, strings.TrimSpace(verifiedUser), strings.TrimSpace(verifiedHost))
	// The target sends one identical confirmation after its first successful
	// callback. Keep the listener available for a bounded grace period in case
	// the first 202 response was lost on the return path.
	waitForPairCallbackRetry(cmd.Context(), retryAcknowledged, pairCallbackRetryGrace)
	return nil
}

func waitForPairCallbackRetry(ctx context.Context, retryAcknowledged <-chan struct{}, grace time.Duration) {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-retryAcknowledged:
	case <-timer.C:
	case <-ctx.Done():
	}
}

func pairRetryInstruction(alias string, existing bool, explicitIdentity, actualIdentity string) string {
	if strings.TrimSpace(explicitIdentity) != "" {
		return fmt.Sprintf("rerun the same pair command with `--identity` pointing to the kept key %q; do not generate or install a second key", actualIdentity)
	}
	if existing {
		return fmt.Sprintf("rerun `sshm pair %s`; the guided platform choice and existing key will be reused", alias)
	}
	return fmt.Sprintf("rerun plain `sshm pair`, enter alias %q and the same address; the existing generated key will be reused", alias)
}

func pairListenAddress(callbackHost, configured string) string {
	if configured = strings.TrimSpace(configured); configured != "" {
		return configured
	}
	if ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(callbackHost), "[]")); err == nil {
		if ip.Is6() {
			return "[::]:0"
		}
		return "0.0.0.0:0"
	}
	// A hostname may resolve to either family. Go uses a dual-stack listener
	// where supported and otherwise falls back to the available family.
	return ":0"
}

func platformFromPairReport(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "windows":
		return config.PlatformWindows
	case "linux":
		return config.PlatformLinux
	case "darwin":
		return config.PlatformMacOS
	default:
		return ""
	}
}

func writePairCommandFiles(dir, alias, target string, scripts pair.Scripts) ([]string, error) {
	if strings.ContainsAny(dir, "\x00\r\n") {
		return nil, fmt.Errorf("script directory is invalid")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create script directory: %w", err)
	}
	var paths []string
	write := func(suffix, content string) error {
		path := filepath.Join(dir, alias+suffix)
		if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
			return fmt.Errorf("write target command %s: %w", path, err)
		}
		if err := protectPrivateFile(path); err != nil {
			_ = os.Remove(path)
			return fmt.Errorf("secure target command %s: %w", path, err)
		}
		paths = append(paths, path)
		return nil
	}
	if target == "all" || target == "windows" {
		if err := write(".windows.ps1", scripts.Windows); err != nil {
			return nil, err
		}
	}
	if target == "all" || target == "posix" {
		if err := write(".posix.sh", scripts.POSIX); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func validatePrintedPairCommandLengths(target string, scripts pair.Scripts) error {
	commands := []struct {
		platform string
		enabled  bool
		command  string
	}{
		{platform: "Windows", enabled: target == "all" || target == "windows", command: scripts.Windows},
		{platform: "Linux/macOS", enabled: target == "all" || target == "posix", command: scripts.POSIX},
	}
	for _, candidate := range commands {
		if candidate.enabled && len(candidate.command) > maxPrintedPairCommandBytes {
			return fmt.Errorf("%s target command is %d bytes and exceeds the safe %d-byte copy limit; rerun with --script-dir <private-directory> and transfer the generated command file", candidate.platform, len(candidate.command), maxPrintedPairCommandBytes)
		}
	}
	return nil
}

func pairCandidate(existing *config.Server, exists bool, opts pairOptions) (*config.Server, error) {
	if exists {
		candidate := *existing
		if opts.hostSet && opts.host != candidate.Host {
			return nil, fmt.Errorf("server host differs from --host; use `sshm edit` explicitly before pairing")
		}
		if opts.portSet && opts.port != candidate.Port {
			return nil, fmt.Errorf("server port differs from --port; use `sshm edit` explicitly before pairing")
		}
		if opts.descriptionSet {
			candidate.Description = opts.description
		}
		if opts.tagsSet {
			candidate.Tags = splitTags(opts.tags)
		}
		if opts.groupSet {
			candidate.Group = opts.group
		}
		if opts.user != "" {
			candidate.User = opts.user
		}
		if candidate.Port == 0 {
			candidate.Port = 22
		}
		if err := validateMetadataFields(candidate.Label, candidate.Description, candidate.Tags, candidate.Group, candidate.Notes); err != nil {
			return nil, err
		}
		return &candidate, nil
	}

	if err := wizard.ValidateHost(opts.host); err != nil {
		return nil, fmt.Errorf("--host is required for a new alias: %w", err)
	}
	if opts.port < 1 || opts.port > 65535 {
		return nil, fmt.Errorf("port must be in 1..65535")
	}
	tags := splitTags(opts.tags)
	if err := validateMetadataFields("", opts.description, tags, opts.group, ""); err != nil {
		return nil, err
	}
	if strings.ContainsAny(opts.user, "\x00\r\n") {
		return nil, fmt.Errorf("user must be a single line")
	}
	return &config.Server{
		Host:        opts.host,
		Port:        opts.port,
		User:        opts.user,
		Description: opts.description,
		Tags:        tags,
		Group:       opts.group,
	}, nil
}

var (
	storeAndLoadPairKey = keystore.StoreAndLoad
	checkPairKeyUsable  = sshpkg.CheckKeyPairUsable
)

func preparePairKey(cmd *cobra.Command, alias, expandedPath string, noEncrypt bool) (publicKey string, generated bool, err error) {
	if _, readErr := os.Stat(expandedPath + ".pub"); readErr == nil {
		if _, statErr := os.Stat(expandedPath); statErr != nil {
			return "", false, fmt.Errorf("public key exists but private key is missing at %s", expandedPath)
		}
		checkedPublicKey, err := checkPairKeyUsable(expandedPath)
		if err != nil {
			return "", false, fmt.Errorf(
				"pairing key %q is not ready for SSH signing: %w; fix the private/public key pair or load and unlock this key with ssh-add, then retry",
				expandedPath, err,
			)
		}
		return checkedPublicKey, false, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", false, fmt.Errorf("read public key: %w", readErr)
	}
	if _, statErr := os.Stat(expandedPath); statErr == nil {
		return "", false, fmt.Errorf("private key exists but %s.pub is missing; restore or derive the public key before pairing", expandedPath)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", false, statErr
	}
	if err := os.MkdirAll(filepath.Dir(expandedPath), 0o700); err != nil {
		return "", false, fmt.Errorf("create key directory: %w", err)
	}

	if noEncrypt {
		publicKey, err = keys.GenerateED25519(expandedPath, alias+"@sshm-pair")
		if err != nil {
			return "", false, err
		}
		checkedPublicKey, err := checkPairKeyUsable(expandedPath)
		if err != nil {
			keys.RemoveGenerated(expandedPath)
			return "", false, fmt.Errorf("generated pairing key failed its SSH signing preflight: %w", err)
		}
		return checkedPublicKey, true, nil
	}
	passphrase, err := keys.RandomPassphrase()
	if err != nil {
		return "", false, err
	}
	publicKey, err = keys.GenerateED25519Encrypted(expandedPath, alias+"@sshm-pair", passphrase)
	if err != nil {
		return "", false, err
	}
	generated = true
	recoveryPath, err := keys.WriteRecovery(expandedPath, passphrase)
	if err != nil {
		keys.RemoveGenerated(expandedPath)
		return "", false, err
	}
	store, err := storeAndLoadPairKey(expandedPath, passphrase)
	if err != nil {
		return "", false, fmt.Errorf(
			"generated encrypted pairing key could not be loaded for SSH signing: %w; the key was kept at %q with its recovery passphrase at %q; start or unlock ssh-agent/OpenSSH Authentication Agent, load this key with ssh-add, then retry pairing; after pairing, move the passphrase to your password manager and delete the recovery file",
			err, expandedPath, recoveryPath,
		)
	}
	checkedPublicKey, err := checkPairKeyUsable(expandedPath)
	if err != nil {
		return "", false, fmt.Errorf(
			"generated encrypted pairing key failed its SSH signing preflight: %w; the key was kept at %q with its recovery passphrase at %q; ensure ssh-agent/OpenSSH Authentication Agent is running and unlocked, load this key with ssh-add, then retry pairing; after pairing, move the passphrase to your password manager and delete the recovery file",
			err, expandedPath, recoveryPath,
		)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Encrypted key recovery file: %s (move the passphrase to your password manager, then delete it)\n", recoveryPath)
	if store.Note != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Key agent note: %s\n", store.Note)
	}
	return checkedPublicKey, true, nil
}

func verifyPairedServer(ctx context.Context, server *config.Server) (user, hostname string, err error) {
	var lastErr error
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		user, hostname, lastErr = verifyPairAttempt(attemptCtx, server)
		cancel()
		if lastErr == nil {
			return user, hostname, nil
		}
		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("%w (last error: %v)", ctx.Err(), lastErr)
		case <-ticker.C:
		}
	}
}

func verifyPairAttempt(ctx context.Context, server *config.Server) (string, string, error) {
	client, err := sshpkg.Dial(server, sshpkg.BuildOpts{Timeout: 8 * time.Second, ConfigPath: configPath()})
	if err != nil {
		return "", "", err
	}
	defer client.Close()
	who, err := client.Exec(ctx, "whoami")
	if err != nil {
		return "", "", fmt.Errorf("whoami failed: %w", err)
	}
	if who == nil || who.ExitCode != 0 {
		if who == nil {
			return "", "", fmt.Errorf("whoami returned no result")
		}
		return "", "", fmt.Errorf("whoami failed: exit=%d err=%v stderr=%s", who.ExitCode, err, strings.TrimSpace(who.Stderr))
	}
	host, err := client.Exec(ctx, "hostname")
	if err != nil {
		return "", "", fmt.Errorf("hostname failed: %w", err)
	}
	if host == nil || host.ExitCode != 0 {
		if host == nil {
			return "", "", fmt.Errorf("hostname returned no result")
		}
		return "", "", fmt.Errorf("hostname failed: exit=%d err=%v stderr=%s", host.ExitCode, err, strings.TrimSpace(host.Stderr))
	}
	return strings.TrimSpace(who.Stdout), strings.TrimSpace(host.Stdout), nil
}

func sameReportedUser(report pair.Report, verified string) bool {
	reported := strings.ToLower(strings.TrimSpace(report.User))
	verified = strings.ToLower(strings.TrimSpace(verified))
	if verified == reported {
		return true
	}
	if report.Platform == "windows" {
		return strings.HasSuffix(verified, `\`+reported) || strings.HasSuffix(verified, "/"+reported)
	}
	return false
}
