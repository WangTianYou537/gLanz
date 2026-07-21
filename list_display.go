package lanzou

import (
	"fmt"
	"sort"
	"strings"
)

// DisplayEntry is a list row after optional split-unescape grouping.
type DisplayEntry struct {
	// Kind: "DIR", "FILE", "SPLIT"
	Kind string
	// ID is folder/file id, or first-part id for SPLIT groups.
	ID string
	// Name is the display name (original name for SPLIT).
	Name string
	// Size is human size string when available.
	Size string
	// Extra is description / part summary.
	Extra string
	// Parts holds members when Kind=="SPLIT".
	Parts []ListEntry
	// Meta is filled for SPLIT from notes.
	Meta *PartMeta
	// Raw is the underlying list entry for non-grouped rows.
	Raw *ListEntry
}

// UnescapeList groups split parts (via file description notes) into virtual rows.
// Folders and non-part files pass through unchanged. When list_unescape is false,
// returns a flat mapping of list entries.
//
// noteByID is optional: map fileID → description. If nil / missing, only
// filename-based heuristics are NOT applied — notes are authoritative.
func UnescapeList(list []ListEntry, noteByID map[string]string, enabled bool) []DisplayEntry {
	if !enabled {
		out := make([]DisplayEntry, 0, len(list))
		for i := range list {
			e := list[i]
			out = append(out, flatEntry(e))
		}
		return applyConvertNotes(out, noteByID)
	}
	if noteByID == nil {
		noteByID = map[string]string{}
	}

	type group struct {
		meta  PartMeta
		parts []ListEntry
	}
	groups := map[string]*group{}
	var order []string
	var plain []ListEntry

	for _, e := range list {
		if e.Type == EntryFolder {
			plain = append(plain, e)
			continue
		}
		note := noteByID[e.ID]
		// also allow Description field if list API ever fills it
		if note == "" {
			note = e.Description
		}
		meta, ok := ParsePartNote(note)
		if !ok {
			plain = append(plain, e)
			continue
		}
		g, exists := groups[meta.GroupID]
		if !exists {
			g = &group{meta: meta}
			groups[meta.GroupID] = g
			order = append(order, meta.GroupID)
		}
		// keep richest name
		if g.meta.Name == "" && meta.Name != "" {
			g.meta.Name = meta.Name
		}
		if meta.Total > g.meta.Total {
			g.meta.Total = meta.Total
		}
		g.parts = append(g.parts, e)
		// stash index on a copy via Description if empty — we sort by parsed index
		// re-parse each part's note for index when sorting
	}

	out := make([]DisplayEntry, 0, len(plain)+len(order))
	for _, e := range plain {
		out = append(out, flatEntry(e))
	}
	out = applyConvertNotes(out, noteByID)
	for _, gid := range order {
		g := groups[gid]
		sort.SliceStable(g.parts, func(i, j int) bool {
			mi, _ := ParsePartNote(firstNote(noteByID, g.parts[i]))
			mj, _ := ParsePartNote(firstNote(noteByID, g.parts[j]))
			return mi.Index < mj.Index
		})
		name := g.meta.Name
		if name == "" {
			name = g.parts[0].Name
		}
		var totalSize int64
		for _, p := range g.parts {
			if m, ok := ParsePartNote(firstNote(noteByID, p)); ok && m.Size > 0 {
				totalSize += m.Size
			}
		}
		firstID := ""
		if len(g.parts) > 0 {
			firstID = g.parts[0].ID
		}
		metaCopy := g.meta
		out = append(out, DisplayEntry{
			Kind:  "SPLIT",
			ID:    firstID,
			Name:  name,
			Size:  humanSize(totalSize),
			Extra: fmt.Sprintf("parts=%d/%d group=%s", len(g.parts), g.meta.Total, gid),
			Parts: g.parts,
			Meta:  &metaCopy,
		})
	}
	return out
}

func flatEntry(e ListEntry) DisplayEntry {
	kind := "FILE"
	extra := e.Size
	name := e.Name
	if e.Type == EntryFolder {
		kind = "DIR"
		extra = e.Description
	}
	ee := e
	return DisplayEntry{
		Kind:  kind,
		ID:    e.ID,
		Name:  name,
		Size:  e.Size,
		Extra: extra,
		Raw:   &ee,
	}
}

// applyConvertNotes rewrites FILE display names using [lanzou-convert] notes.
func applyConvertNotes(rows []DisplayEntry, notes map[string]string) []DisplayEntry {
	if notes == nil {
		return rows
	}
	for i := range rows {
		if rows[i].Kind != "FILE" {
			continue
		}
		note := notes[rows[i].ID]
		if note == "" && rows[i].Raw != nil {
			note = rows[i].Raw.Description
		}
		cm, ok := ParseConvertNote(note)
		if !ok || cm.Name == "" {
			continue
		}
		// Show original name; keep uploaded name in extra when converted.
		as := cm.As
		if as == "" {
			as = rows[i].Name
		}
		rows[i].Name = cm.Name
		if cm.Raw {
			// raw: name already original; no extra hint needed
			continue
		}
		hint := fmt.Sprintf("as=%s mode=%s", as, cm.Mode)
		if rows[i].Extra != "" {
			rows[i].Extra = rows[i].Extra + "  " + hint
		} else {
			rows[i].Extra = hint
		}
	}
	return rows
}

func firstNote(notes map[string]string, e ListEntry) string {
	if n := notes[e.ID]; n != "" {
		return n
	}
	return e.Description
}

func humanSize(n int64) string {
	if n <= 0 {
		return ""
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// FetchNotes loads descriptions for file entries (best-effort).
func (a *Account) FetchNotes(list []ListEntry) map[string]string {
	out := map[string]string{}
	for _, e := range list {
		if e.Type != EntryFile {
			continue
		}
		// Prefer existing description
		if strings.Contains(e.Description, "[lanzou-part]") {
			out[e.ID] = e.Description
			continue
		}
		desc, err := a.GetFileDescribe(e.ID)
		if err != nil {
			continue
		}
		if desc != "" {
			out[e.ID] = desc
		}
	}
	return out
}
