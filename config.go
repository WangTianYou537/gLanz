package lanzou

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Config holds user preferences for upload conversion / splitting / list display.
// Stored as JSON at ~/.lanzou/config.json by default.
type Config struct {
	// SuffixAutoConvert: when true, unsupported suffixes are converted before upload.
	SuffixAutoConvert bool `json:"suffix_auto_convert"`
	// SuffixName: target extension without leading dot (default "zip").
	SuffixName string `json:"suffix_name"`
	// SuffixMode: "zip" = real compress; "rename" = only change/append extension.
	SuffixMode string `json:"suffix_mode"`
	// SplitEnable: split files larger than SplitSizeMB into chunks.
	SplitEnable bool `json:"split_enable"`
	// SplitSizeMB: max size of each chunk (must be 1..100, default 90).
	SplitSizeMB int `json:"split_size_mb"`
	// SplitNameFormat placeholders:
	//   {name}  original basename without final ext
	//   {ext}   original extension (no dot)
	//   {index} 1-based part index (zero-padded to 3 by default via {index:03d})
	//   {total} total parts
	//   {suffix} configured SuffixName
	// Default: "{name}_part{index:03d}.{suffix}"
	// Note: names like "x.part001.zip" are rejected by Lanzou (error 7071);
	// use underscore form instead.
	SplitNameFormat string `json:"split_name_format"`
	// SplitNote: write part metadata into file description after upload.
	SplitNote bool `json:"split_note"`
	// ListUnescape: group split parts when listing.
	ListUnescape bool `json:"list_unescape"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		SuffixAutoConvert: true,
		SuffixName:        "zip",
		SuffixMode:        "zip", // zip | rename
		SplitEnable:       true,
		SplitSizeMB:       90,
		SplitNameFormat:   "{name}_part{index:03d}.{suffix}",
		SplitNote:         true,
		ListUnescape:      true,
	}
}

var (
	cfgMu       sync.RWMutex
	cfgCached   *Config
	cfgPathUsed string
)

// DefaultConfigPath returns ~/.lanzou/config.json (or ./lanzou.config.json).
func DefaultConfigPath() string {
	if v := os.Getenv("LANZOU_CONFIG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "./lanzou.config.json"
	}
	return filepath.Join(home, ".lanzou", "config.json")
}

// LoadConfig reads config from path (empty = default path). Missing file → defaults.
func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	cfg := DefaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return DefaultConfig(), fmt.Errorf("config json: %w", err)
	}
	cfg.normalize()
	return cfg, nil
}

// SaveConfig writes cfg to path (empty = default path), creating parent dirs.
func SaveConfig(path string, cfg Config) error {
	if path == "" {
		path = DefaultConfigPath()
	}
	cfg.normalize()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	cfgMu.Lock()
	c := cfg
	cfgCached = &c
	cfgPathUsed = path
	cfgMu.Unlock()
	return nil
}

// GetConfig returns the process-wide cached config (loads once).
func GetConfig() Config {
	cfgMu.RLock()
	if cfgCached != nil {
		c := *cfgCached
		cfgMu.RUnlock()
		return c
	}
	cfgMu.RUnlock()

	cfgMu.Lock()
	defer cfgMu.Unlock()
	if cfgCached != nil {
		return *cfgCached
	}
	path := DefaultConfigPath()
	cfg, _ := LoadConfig(path)
	cfgCached = &cfg
	cfgPathUsed = path
	return cfg
}

// SetConfigCache replaces the in-memory config (does not write disk).
func SetConfigCache(cfg Config) {
	cfg.normalize()
	cfgMu.Lock()
	c := cfg
	cfgCached = &c
	cfgMu.Unlock()
}

// ConfigPathUsed returns the path last used by GetConfig/SaveConfig.
func ConfigPathUsed() string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfgPathUsed != "" {
		return cfgPathUsed
	}
	return DefaultConfigPath()
}

// ConfigKeys lists settable keys with short descriptions.
func ConfigKeys() [][2]string {
	return [][2]string{
		{"suffix_auto_convert", "bool  auto convert unsupported suffix (default true)"},
		{"suffix_name", "string target extension, no dot (default zip)"},
		{"suffix_mode", "zip|rename  zip=compress, rename=only change suffix"},
		{"split_enable", "bool  split large files (default true)"},
		{"split_size_mb", "int   chunk size in MB, 1..100 (default 90)"},
		{"split_name_format", "string part name template"},
		{"split_note", "bool  write part metadata to file description"},
		{"list_unescape", "bool  group split parts in ls (default true)"},
	}
}

// SetConfigValue sets one key on cfg and returns the updated config.
func SetConfigValue(cfg Config, key, value string) (Config, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	switch key {
	case "suffix_auto_convert":
		b, err := parseBool(value)
		if err != nil {
			return cfg, err
		}
		cfg.SuffixAutoConvert = b
	case "suffix_name":
		v := strings.TrimPrefix(strings.ToLower(value), ".")
		if v == "" {
			return cfg, fmt.Errorf("suffix_name cannot be empty")
		}
		cfg.SuffixName = v
	case "suffix_mode":
		v := strings.ToLower(value)
		if v != "zip" && v != "rename" {
			return cfg, fmt.Errorf("suffix_mode must be zip or rename")
		}
		cfg.SuffixMode = v
	case "split_enable":
		b, err := parseBool(value)
		if err != nil {
			return cfg, err
		}
		cfg.SplitEnable = b
	case "split_size_mb":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 100 {
			return cfg, fmt.Errorf("split_size_mb must be integer 1..100")
		}
		cfg.SplitSizeMB = n
	case "split_name_format":
		if value == "" {
			return cfg, fmt.Errorf("split_name_format cannot be empty")
		}
		cfg.SplitNameFormat = value
	case "split_note":
		b, err := parseBool(value)
		if err != nil {
			return cfg, err
		}
		cfg.SplitNote = b
	case "list_unescape":
		b, err := parseBool(value)
		if err != nil {
			return cfg, err
		}
		cfg.ListUnescape = b
	default:
		return cfg, fmt.Errorf("unknown config key: %s", key)
	}
	cfg.normalize()
	return cfg, nil
}

// GetConfigValue returns string form of one key.
func GetConfigValue(cfg Config, key string) (string, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "suffix_auto_convert":
		return strconv.FormatBool(cfg.SuffixAutoConvert), nil
	case "suffix_name":
		return cfg.SuffixName, nil
	case "suffix_mode":
		return cfg.SuffixMode, nil
	case "split_enable":
		return strconv.FormatBool(cfg.SplitEnable), nil
	case "split_size_mb":
		return strconv.Itoa(cfg.SplitSizeMB), nil
	case "split_name_format":
		return cfg.SplitNameFormat, nil
	case "split_note":
		return strconv.FormatBool(cfg.SplitNote), nil
	case "list_unescape":
		return strconv.FormatBool(cfg.ListUnescape), nil
	default:
		return "", fmt.Errorf("unknown config key: %s", key)
	}
}

func (c *Config) normalize() {
	if c.SuffixName == "" {
		c.SuffixName = "zip"
	}
	c.SuffixName = strings.TrimPrefix(strings.ToLower(c.SuffixName), ".")
	if c.SuffixMode != "zip" && c.SuffixMode != "rename" {
		c.SuffixMode = "zip"
	}
	if c.SplitSizeMB < 1 {
		c.SplitSizeMB = 90
	}
	if c.SplitSizeMB > 100 {
		c.SplitSizeMB = 100
	}
	if c.SplitNameFormat == "" {
		c.SplitNameFormat = "{name}_part{index:03d}.{suffix}"
	}
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "1", "true", "t", "yes", "y", "on":
		return true, nil
	case "0", "false", "f", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool: %s (use true/false)", s)
	}
}

// FormatSplitName builds a part filename from template.
func FormatSplitName(format, origBase string, index, total int, suffix string) string {
	ext := fileExt(origBase)
	name := strings.TrimSuffix(origBase, filepath.Ext(origBase))
	if name == "" {
		name = origBase
	}
	out := format
	// {index:03d} style
	out = replaceIndexToken(out, "{index", index)
	out = strings.ReplaceAll(out, "{total}", strconv.Itoa(total))
	out = strings.ReplaceAll(out, "{name}", name)
	out = strings.ReplaceAll(out, "{ext}", ext)
	out = strings.ReplaceAll(out, "{suffix}", suffix)
	return out
}

func replaceIndexToken(s, prefix string, index int) string {
	// handle {index} and {index:03d}
	for {
		i := strings.Index(s, prefix)
		if i < 0 {
			return s
		}
		rest := s[i+len(prefix):]
		if strings.HasPrefix(rest, "}") {
			s = s[:i] + fmt.Sprintf("%d", index) + rest[1:]
			continue
		}
		if strings.HasPrefix(rest, ":") {
			j := strings.Index(rest, "}")
			if j < 0 {
				return s
			}
			spec := rest[1:j] // e.g. 03d
			var rendered string
			if strings.HasSuffix(spec, "d") {
				// width from leading zeros like 03d
				width := 0
				for _, ch := range spec[:len(spec)-1] {
					if ch >= '0' && ch <= '9' {
						width = width*10 + int(ch-'0')
					}
				}
				if width > 0 {
					rendered = fmt.Sprintf("%0*d", width, index)
				} else {
					rendered = fmt.Sprintf("%d", index)
				}
			} else {
				rendered = fmt.Sprintf("%d", index)
			}
			s = s[:i] + rendered + rest[j+1:]
			continue
		}
		return s
	}
}

// Part note helpers ---------------------------------------------------------

// FormatPartNote builds the description written to each uploaded part.
func FormatPartNote(groupID, origName string, index, total int, size int64) string {
	return fmt.Sprintf(
		"[lanzou-part] id=%s name=%s index=%d total=%d size=%d",
		groupID, origName, index, total, size,
	)
}

// FormatConvertNote builds the description written when a suffix was converted.
// Example: [lanzou-convert] name=classes2.dex as=classes2.dex.zip mode=zip suffix=zip size=20
func FormatConvertNote(origName, uploadName, mode, suffix string, size int64) string {
	return fmt.Sprintf(
		"[lanzou-convert] name=%s as=%s mode=%s suffix=%s size=%d",
		origName, uploadName, mode, suffix, size,
	)
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

// ParsePartNote extracts PartMeta from a description, if present.
func ParsePartNote(desc string) (PartMeta, bool) {
	const mark = "[lanzou-part]"
	i := strings.Index(desc, mark)
	if i < 0 {
		return PartMeta{}, false
	}
	rest := strings.TrimSpace(desc[i+len(mark):])
	// stop at newline if multi-line
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

// ParseConvertNote extracts ConvertMeta from a description, if present.
func ParseConvertNote(desc string) (ConvertMeta, bool) {
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
