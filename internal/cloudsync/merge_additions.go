package cloudsync

import "reflect"

func compatibleEntries(a, b *Entry) bool {
	return a != nil && b != nil && a.ID == b.ID && reflect.DeepEqual(cleanServer(a.Server), cleanServer(b.Server))
}
func mergeAdditions(a, b Entry) Entry {
	out := b
	out.Aliases = union(a.Aliases, b.Aliases)
	out.CredentialIDs = union(a.CredentialIDs, b.CredentialIDs)
	out.Sources = map[string]Source{}
	for k, v := range b.Sources {
		out.Sources[k] = v
	}
	for k, v := range a.Sources {
		if existing, ok := out.Sources[k]; ok && !reflect.DeepEqual(existing, v) {
			out.Sources[Digest([]string{k, Digest(v)})] = v
		} else {
			out.Sources[k] = v
		}
	}
	return out
}

// RepairCompatibleConflicts only combines additive credentials, aliases and
// provenance when connection settings agree. Deletions and edits stay explicit.
func (d *Data) RepairCompatibleConflicts() int {
	repaired := 0
	for id, c := range d.Conflicts {
		current, exists := d.Entries[id]
		if !exists || d.Deleted[id] || !compatibleEntries(c.Local, c.Remote) || !compatibleEntries(c.Local, &current) {
			continue
		}
		d.Entries[id] = mergeAdditions(mergeAdditions(*c.Local, *c.Remote), current)
		delete(d.Conflicts, id)
		repaired++
	}
	return repaired
}
