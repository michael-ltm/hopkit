# Windows pairing

SSHM includes its SSH client. A Windows computer accepting incoming SSH still
needs an SSH server service. The pairing installer uses the Windows OpenSSH
feature first, with the existing SHA-256-pinned, Microsoft-signature-verified
Win32-OpenSSH ZIP fallback when needed. It does not bundle an additional server
binary into every SSHM download. The pinned fallback is currently the official
`10.0.0.0p2-Preview` release; installing it is reported explicitly.

Installing a second embedded server would still require administrator rights,
service registration, firewall access and port-conflict handling. A functioning
existing sshd installation is reused. Its custom port is checked rather than
silently changed. Port 22 is the default on Windows, Linux and macOS; select
Advanced settings only if a server uses a different SSH port.

## Guided setup

1. Run `sshm`, press `a`, select Set up this server, then enter name, address
   and target system. Leave Advanced settings off for the default port.
2. For Windows, copy the generated `.windows.cmd` and `.windows.ps1` files into
   the **same folder** on the target computer while the controller keeps waiting.
3. Right-click `.windows.cmd` and choose **Run as administrator**, using the
   Windows account you want to pair. The launcher uses the OS PowerShell with
   no user profile and a process-only execution policy. It preserves the exit
   code and keeps the window open so errors remain readable.
4. The controller saves the server only after actual key-authenticated SSH
   succeeds. Remove the copied files afterwards. They contain the public key
   and a one-time callback, never the SSH private key or vault password.

Guided controller files are temporary and are removed when that pairing command
ends. An expired session needs freshly generated files using the same alias/key.
For files kept in a chosen private directory, run:

```sh
sshm pair office-pc --host 100.x.y.z --target windows --script-dir ./pair-office
```

The existing explicit CLI without `--script-dir` still prints the self-contained
PowerShell one-liner. Use Administrator PowerShell to paste that command; it is
not cmd.exe syntax. File mode avoids long clipboard lines and shell ambiguity.

## Read-only checks and errors

From either PowerShell or cmd.exe in the target folder, run:

```text
.\office-pc.windows.cmd check
```

This checks PowerShell, elevation, service presence, executable existence,
configuration validity and configured listening ports. It exits **before**
installing packages, writing keys, changing services/firewall or sending a
callback. An unelevated check reports that configuration validation requires
an administrator. Missing OpenSSH is an actionable finding, not a failed test.

Installation files label the current step: login identity, installation,
configuration, service startup, key permissions, firewall or controller callback.
They report errors without dumping source lines containing the callback.
PowerShell 5.1+ and administrator access are required. Organizational restrictions
such as Constrained Language or Group Policy still need the administrator's help;
the launcher does not bypass those policies.

For a disconnected target, set `SSHM_OPENSSH_ZIP` to the matching official pinned
ZIP before running the script from an elevated terminal. The existing installer
skips the online Windows feature attempt and verifies the ZIP hash and executable
signature. A downloaded ZIP of a different version is rejected. This is an
existing offline-install path, not a newly shipped offline bundle.

Microsoft references:
- [OpenSSH installation and prerequisites](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
- [Official Win32-OpenSSH installation](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH)

## Validation of preview.7

Go tests and vet passed. On att-dev, native Windows PowerShell 5.1 parsed the
generated script, a simulated missing-service check returned before installation,
and the generated launcher completed its real read-only check: sshd running,
configuration valid, port 22 listening. Before/after hashes of the live SSH
configuration and both authorized-key files matched. Windows ConPTY tests
passed at 120x30, 80x24 and 40x12, including a real loopback TCP probe.

A fresh Windows OpenSSH installation was not exercised on a disposable VM in
this run. Existing healthy production SSH was not reinstalled for that test.
The installer payload and its pinned package versions remain the existing ones;
this change adds file delivery, environment checks and readable stage errors.
