// Package hopkitassets bundles the same skill documents shipped by the plugin.
package hopkitassets

import "embed"

//go:embed skills/hopkit-server-ops/*.md
var Skills embed.FS
