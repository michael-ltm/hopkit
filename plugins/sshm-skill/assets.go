// Package sshmassets bundles the same skill documents shipped by the plugin.
package sshmassets

import "embed"

//go:embed skills/sshm-server-ops/*.md
var Skills embed.FS
