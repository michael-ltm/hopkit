package mcp

import (
	"encoding/base64"
	"encoding/binary"
	"unicode/utf16"
)

func utf16LE(s string) []byte {
	words := utf16.Encode([]rune(s))
	out := make([]byte, len(words)*2)
	for i, word := range words {
		binary.LittleEndian.PutUint16(out[i*2:], word)
	}
	return out
}

func powershellEncodedCommand(script string) string {
	encoded := base64.StdEncoding.EncodeToString(utf16LE(script))
	return "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encoded
}
