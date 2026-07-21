package lanzou

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// FileNote is the unified JSON metadata stored in Lanzou file descriptions.
//
//	{"v":1,"kind":"convert","name":"a.dex","as":"a.dex.zip","mode":"zip","suffix":"zip","size":20}
//	{"v":1,"kind":"part","id":"...","name":"big.bin","index":1,"total":3,"size":1048576}
//
// Legacy plain-text notes ([lanzou-convert] / [lanzou-part]) are still parsed.
type FileNote struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"` // convert | part
	Name   string `json:"name,omitempty"`
	As     string `json:"as,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Suffix string `json:"suffix,omitempty"`
	ID     string `json:"id,omitempty"`
	Index  int    `json:"index,omitempty"`
	Total  int    `json:"total,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

// FormatPartNote builds a JSON part note.
func FormatPartNote(groupID, origName string, index, total int, size int64) string {
	b, _ := json.Marshal(FileNote{
		V: 1, Kind: "part",
		ID: groupID, Name: origName,
		Index: index, Total: total, Size: size,
	})
	return string(b)
}

// FormatConvertNote builds a JSON convert note.
func FormatConvertNote(origName, uploadName, mode, suffix string, size int64) string {
	b, _ := json.Marshal(FileNote{
		V: 1, Kind: "convert",
		Name: origName, As: uploadName,
		Mode: mode, Suffix: suffix, Size: size,
	})
	return string(b)
}

// PartMeta is parsed from a file description.
type PartMeta struct {
	GroupID string
	Name    string
	Index   int
	Total   int
	Size    int64
}

// ConvertMeta is parsed from a convert description.
type ConvertMeta struct {
	Name   string // original basename
	As     string // uploaded basename
	Mode   string // zip | rename
	Suffix string
	Size   int64
}

// ParseFileNote tries JSON first, then legacy text markers.
func ParseFileNote(desc string) (FileNote, bool) {
	desc = htmlUnescape(strings.TrimSpace(desc))
	if desc == "" {
		return FileNote{}, false
	}
	// JSON object (possibly with surrounding noise)
	if i := strings.Index(desc, "{"); i >= 0 {
		if j := strings.LastIndex(desc, "}"); j > i {
			var n FileNote
			if err := json.Unmarshal([]byte(desc[i:j+1]), &n); err == nil && n.Kind != "" {
				if n.V == 0 {
					n.V = 1
				}
				return n, true
			}
		}
	}
	// legacy convert
	if cm, ok := parseLegacyConvert(desc); ok {
		return FileNote{
			V: 1, Kind: "convert",
			Name: cm.Name, As: cm.As, Mode: cm.Mode, Suffix: cm.Suffix, Size: cm.Size,
		}, true
	}
	// legacy part
	if pm, ok := parseLegacyPart(desc); ok {
		return FileNote{
			V: 1, Kind: "part",
			ID: pm.GroupID, Name: pm.Name, Index: pm.Index, Total: pm.Total, Size: pm.Size,
		}, true
	}
	return FileNote{}, false
}

// htmlUnescape decodes common entities Lanzou injects into descriptions.
func htmlUnescape(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	r := strings.NewReplacer(
		"&quot;", `"`,
		"&#34;", `"`,
		"&apos;", `'`,
		"&#39;", `'`,
		"&lt;", "<",
		"&gt;", ">",
		"&amp;", "&",
	)
	// amp last would break others if done first; NewReplacer applies left-to-right
	// so put amp last... actually we put amp last in list but Replacer is simultaneous
	// on non-overlapping. Safer multi-pass for amp after quotes.
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = strings.ReplaceAll(s, "&#34;", `"`)
	s = strings.ReplaceAll(s, "&apos;", `'`)
	s = strings.ReplaceAll(s, "&#39;", `'`)
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	_ = r
	return s
}

// ParsePartNote extracts PartMeta (JSON or legacy).
func ParsePartNote(desc string) (PartMeta, bool) {
	n, ok := ParseFileNote(desc)
	if !ok || n.Kind != "part" {
		return PartMeta{}, false
	}
	if n.ID == "" || n.Total < 1 || n.Index < 1 {
		return PartMeta{}, false
	}
	return PartMeta{GroupID: n.ID, Name: n.Name, Index: n.Index, Total: n.Total, Size: n.Size}, true
}

// ParseConvertNote extracts ConvertMeta (JSON or legacy).
func ParseConvertNote(desc string) (ConvertMeta, bool) {
	n, ok := ParseFileNote(desc)
	if !ok || n.Kind != "convert" {
		return ConvertMeta{}, false
	}
	if n.Name == "" {
		return ConvertMeta{}, false
	}
	return ConvertMeta{Name: n.Name, As: n.As, Mode: n.Mode, Suffix: n.Suffix, Size: n.Size}, true
}

func parseLegacyPart(desc string) (PartMeta, bool) {
	const mark = "[lanzou-part]"
	i := strings.Index(desc, mark)
	if i < 0 {
		return PartMeta{}, false
	}
	rest := strings.TrimSpace(desc[i+len(mark):])
	if j := strings.IndexAny(rest, "\r\n"); j >= 0 {
		rest = rest[:j]
	}
	m := PartMeta{}
	for _, field := range strings.Fields(rest) {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch k {
		case "id":
			m.GroupID = v
		case "name":
			m.Name = v
		case "index":
			m.Index, _ = strconv.Atoi(v)
		case "total":
			m.Total, _ = strconv.Atoi(v)
		case "size":
			m.Size, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if m.GroupID == "" || m.Total < 1 || m.Index < 1 {
		return PartMeta{}, false
	}
	return m, true
}

func parseLegacyConvert(desc string) (ConvertMeta, bool) {
	const mark = "[lanzou-convert]"
	i := strings.Index(desc, mark)
	if i < 0 {
		return ConvertMeta{}, false
	}
	rest := strings.TrimSpace(desc[i+len(mark):])
	if j := strings.IndexAny(rest, "\r\n"); j >= 0 {
		rest = rest[:j]
	}
	m := ConvertMeta{}
	for _, field := range strings.Fields(rest) {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch k {
		case "name":
			m.Name = v
		case "as":
			m.As = v
		case "mode":
			m.Mode = v
		case "suffix":
			m.Suffix = v
		case "size":
			m.Size, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if m.Name == "" {
		return ConvertMeta{}, false
	}
	return m, true
}

// NoteKind returns "convert", "part", or "".
func NoteKind(desc string) string {
	n, ok := ParseFileNote(desc)
	if !ok {
		return ""
	}
	return n.Kind
}

// FormatNoteDebug is a short human summary for logs.
func FormatNoteDebug(desc string) string {
	n, ok := ParseFileNote(desc)
	if !ok {
		return ""
	}
	switch n.Kind {
	case "convert":
		return fmt.Sprintf("convert name=%s as=%s", n.Name, n.As)
	case "part":
		return fmt.Sprintf("part name=%s %d/%d id=%s", n.Name, n.Index, n.Total, n.ID)
	default:
		return n.Kind
	}
}
