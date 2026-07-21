package lanzou

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FileNote is the unified JSON metadata stored in Lanzou file descriptions.
// Schema v1 only (no legacy text markers):
//
//	{"v":1,"kind":"raw","name":"a.txt","as":"a.txt","size":12}
//	{"v":1,"kind":"convert","name":"a.dex","as":"a.dex.zip","mode":"zip","suffix":"zip","size":20}
//	{"v":1,"kind":"part","id":"...","name":"big.bin","as":"big_part001.zip","index":1,"total":3,"size":1048576}
type FileNote struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"` // raw | convert | part
	Name   string `json:"name,omitempty"`
	As     string `json:"as,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Suffix string `json:"suffix,omitempty"`
	ID     string `json:"id,omitempty"`
	Index  int    `json:"index,omitempty"`
	Total  int    `json:"total,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

// Note schema version.
const NoteVersion = 1

// FormatRawNote builds a JSON note for an upload that did not convert the suffix.
func FormatRawNote(origName, uploadName string, size int64) string {
	if uploadName == "" {
		uploadName = origName
	}
	b, _ := json.Marshal(FileNote{
		V: NoteVersion, Kind: "raw",
		Name: origName, As: uploadName, Size: size,
	})
	return string(b)
}

// FormatConvertNote builds a JSON convert note.
func FormatConvertNote(origName, uploadName, mode, suffix string, size int64) string {
	b, _ := json.Marshal(FileNote{
		V: NoteVersion, Kind: "convert",
		Name: origName, As: uploadName,
		Mode: mode, Suffix: suffix, Size: size,
	})
	return string(b)
}

// FormatPartNote builds a JSON part note.
func FormatPartNote(groupID, origName, uploadName string, index, total int, size int64) string {
	b, _ := json.Marshal(FileNote{
		V: NoteVersion, Kind: "part",
		ID: groupID, Name: origName, As: uploadName,
		Index: index, Total: total, Size: size,
	})
	return string(b)
}

// PartMeta is parsed from a part note.
type PartMeta struct {
	GroupID string
	Name    string
	As      string
	Index   int
	Total   int
	Size    int64
}

// ConvertMeta is parsed from a convert (or raw) note.
type ConvertMeta struct {
	Name   string // original basename
	As     string // uploaded basename
	Mode   string // zip | rename (convert only)
	Suffix string
	Size   int64
	Raw    bool // true when kind=raw
}

// ParseFileNote parses a v1 JSON note only (after HTML unescape).
func ParseFileNote(desc string) (FileNote, bool) {
	desc = htmlUnescape(strings.TrimSpace(desc))
	if desc == "" {
		return FileNote{}, false
	}
	i := strings.Index(desc, "{")
	if i < 0 {
		return FileNote{}, false
	}
	j := strings.LastIndex(desc, "}")
	if j <= i {
		return FileNote{}, false
	}
	var n FileNote
	if err := json.Unmarshal([]byte(desc[i:j+1]), &n); err != nil || n.Kind == "" {
		return FileNote{}, false
	}
	switch n.Kind {
	case "raw", "convert", "part":
	default:
		return FileNote{}, false
	}
	if n.V == 0 {
		n.V = NoteVersion
	}
	return n, true
}

// htmlUnescape decodes common entities Lanzou injects into descriptions.
func htmlUnescape(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = strings.ReplaceAll(s, "&#34;", `"`)
	s = strings.ReplaceAll(s, "&apos;", `'`)
	s = strings.ReplaceAll(s, "&#39;", `'`)
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	return s
}

// ParsePartNote extracts PartMeta from a JSON part note.
func ParsePartNote(desc string) (PartMeta, bool) {
	n, ok := ParseFileNote(desc)
	if !ok || n.Kind != "part" {
		return PartMeta{}, false
	}
	if n.ID == "" || n.Total < 1 || n.Index < 1 {
		return PartMeta{}, false
	}
	return PartMeta{GroupID: n.ID, Name: n.Name, As: n.As, Index: n.Index, Total: n.Total, Size: n.Size}, true
}

// ParseConvertNote extracts ConvertMeta from convert or raw notes.
// raw is treated as a convert-with-same-name for resolution/display.
func ParseConvertNote(desc string) (ConvertMeta, bool) {
	n, ok := ParseFileNote(desc)
	if !ok {
		return ConvertMeta{}, false
	}
	switch n.Kind {
	case "convert":
		if n.Name == "" {
			return ConvertMeta{}, false
		}
		return ConvertMeta{Name: n.Name, As: n.As, Mode: n.Mode, Suffix: n.Suffix, Size: n.Size}, true
	case "raw":
		if n.Name == "" {
			return ConvertMeta{}, false
		}
		as := n.As
		if as == "" {
			as = n.Name
		}
		return ConvertMeta{Name: n.Name, As: as, Size: n.Size, Raw: true}, true
	default:
		return ConvertMeta{}, false
	}
}

// NoteKind returns "raw", "convert", "part", or "".
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
	case "raw":
		return fmt.Sprintf("raw name=%s", n.Name)
	case "convert":
		return fmt.Sprintf("convert name=%s as=%s", n.Name, n.As)
	case "part":
		return fmt.Sprintf("part name=%s %d/%d id=%s", n.Name, n.Index, n.Total, n.ID)
	default:
		return n.Kind
	}
}
