package commands

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/ui"
	"github.com/muesli/cancelreader"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newCloudAddDeviceCmd(enable bool) *cobra.Command {
	var name, description string
	use, short := "add-device [device-name-or-id]", "Add this or another account device to the encrypted connection list"
	if enable {
		use, short = "enable", "Add this device and allow encrypted client/web terminals until Ctrl-C"
	}
	c := &cobra.Command{Use: use, Short: short, Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if enable && len(args) > 0 {
			return errors.New("enable runs on the target device; it cannot enable another computer remotely")
		}
		s, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		defer func() {
			if close != nil {
				close()
			}
		}()
		path := cloudsync.StatePath(configPath())
		if err = s.Sync(cmd.Context(), v, path); err != nil {
			return err
		}
		var response struct {
			Devices []cloudsync.Device `json:"devices"`
		}
		if err = s.Request(cmd.Context(), "GET", "/v1/devices", nil, &response); err != nil {
			return err
		}
		selected := s.DeviceID
		if len(args) > 0 {
			selected = args[0]
		}
		var matches []cloudsync.Device
		for _, d := range response.Devices {
			if d.Kind != "browser" && (d.ID == selected || d.Label == selected) {
				matches = append(matches, d)
			}
		}
		if len(matches) != 1 {
			return errors.New("device name is missing or ambiguous; use an exact ID from sshm cloud devices")
		}
		d := matches[0]
		if d.Platform == "darwin" {
			d.Platform = "macos"
		}
		if name == "" {
			name = d.Label
		}
		if description == "" {
			description = d.Note
		}
		if commandHasTerminal(cmd) && !cmd.Flags().Changed("name") {
			if err = huh.NewForm(huh.NewGroup(huh.NewInput().Title("Device connection name").Value(&name), huh.NewInput().Title("Description (optional)").Value(&description))).WithInput(cmd.InOrStdin()).WithOutput(cmd.ErrOrStderr()).WithTheme(ui.FormTheme()).Run(); err != nil {
				return err
			}
		}
		if enable && (len(name) > 80 || len(description) > 500 || strings.ContainsAny(name+description, "\x00\r\n\x1b")) {
			return errors.New("device name must be at most 80 characters and description at most 500")
		}
		entry, err := v.Data.AddDevice(d, name, description)
		if err != nil {
			return err
		}
		if err = s.SaveDraft(v, path); err != nil {
			return err
		}
		if err = s.Sync(cmd.Context(), v, path); err != nil {
			return err
		}
		if err = publishCloudInventory(cmd, s, v); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Device %q added to cloud list. Repeated additions update the same device. Other clients: sshm cloud sync, then sshm connect %q.\n", entry.Aliases[0], entry.Aliases[0])
		if !enable {
			fmt.Fprintln(cmd.OutOrStdout(), "To accept connections, run sshm cloud enable on that device. No SSH port or password login is required.")
			return nil
		}
		if err = s.Request(cmd.Context(), "POST", "/v1/devices/"+s.DeviceID, map[string]any{"label": name, "group": d.Group, "tags": append([]string{}, d.Tags...), "note": description}, nil); err != nil {
			return err
		}
		agentVault, err := cloudsync.UnlockMaster(s.Username, s.Draft, v.Master)
		if err != nil {
			return err
		}
		close()
		close = nil
		defer agentVault.Close()
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer stop()
		fmt.Fprintln(cmd.OutOrStdout(), "Encrypted connections enabled for this OS user. Keep this process running; Ctrl-C disables access. Restart requires unlocking again.")
		return runCloudAgent(ctx, cmd, s, agentVault, true)
	}}
	c.Flags().StringVar(&name, "name", "", "connection name (defaults to device name)")
	c.Flags().StringVar(&description, "description", "", "connection description")
	return c
}

func attachDeviceTerminal(cmd *cobra.Command, s *cloudsync.State, v *cloudsync.Vault, entry cloudsync.Entry) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("device terminal requires an interactive terminal; run sshm connect <device-name>")
	}
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	client, err := cloudsync.OpenDeviceTerminal(ctx, s, v, cloudsync.DeviceServerID(entry.Server))
	if err != nil {
		return err
	}
	defer client.Close()
	if cfg, e := config.Load(configPath()); e == nil {
		for alias, local := range cfg.Servers {
			if local != nil && local.CloudEntry == entry.ID && local.CloudVault == cloudsync.InventoryIdentity(s) {
				_ = config.RecordSSHUse(configPath(), alias, &entry.Server, time.Now())
			}
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Encrypted device connection · %s · no fixed session time limit\n", entry.Aliases[0])
	old, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer term.Restore(int(os.Stdin.Fd()), old)
	reader, err := cancelreader.NewReader(os.Stdin)
	if err != nil {
		return err
	}
	defer reader.Close()
	defer reader.Cancel()
	go func() {
		buf := make([]byte, 8192)
		defer cloudsync.Wipe(buf)
		for {
			n, e := reader.Read(buf)
			if n > 0 {
				e = client.Send(cloudsync.ShellPayload{Type: "input", Data: base64.RawURLEncoding.EncodeToString(buf[:n])})
			}
			if e != nil {
				cancel()
				return
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		lastCols, lastRows := 0, 0
		for {
			cols, rows, e := term.GetSize(int(os.Stdout.Fd()))
			if e == nil {
				cols = max(20, min(300, cols))
				rows = max(5, min(150, rows))
				if cols != lastCols || rows != lastRows {
					if client.Send(cloudsync.ShellPayload{Type: "resize", Cols: cols, Rows: rows}) != nil {
						cancel()
						return
					}
					lastCols, lastRows = cols, rows
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	for {
		p, e := client.Receive(ctx)
		if e != nil {
			return fmt.Errorf("encrypted device session ended: %w", e)
		}
		switch p.Type {
		case "closed":
			return nil
		case "output":
			raw, e := base64.RawURLEncoding.DecodeString(p.Data)
			if e != nil {
				return errors.New("invalid device output")
			}
			_, e = cmd.OutOrStdout().Write(raw)
			cloudsync.Wipe(raw)
			if e != nil {
				return e
			}
		default:
			return errors.New("unexpected encrypted terminal message: " + strings.TrimSpace(p.Type))
		}
	}
}
