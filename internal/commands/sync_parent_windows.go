//go:build windows

package commands

// On Windows, FlushFileBuffers on the backup file (os.File.Sync) persists the
// file and its metadata; directory handles do not support the POSIX fsync
// contract. The protected NTFS DACL is set before that flush.
func syncParentDir(string) error { return nil }
