package ssh

import "net"

// Keep platform discovery separate from dialing so tests can restrict agent
// candidates to their own sockets instead of contacting a user's live agent.
var agentPaths = platformAgentPaths

// DialAgent connects to the running ssh-agent using the platform-appropriate
// transport (unix socket via SSH_AUTH_SOCK, or the Windows OpenSSH agent
// named pipe). Callers own the returned connection and must Close it.
func DialAgent() (net.Conn, error) { return dialAgent() }
