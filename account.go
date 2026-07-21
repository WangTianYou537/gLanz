// Account / file-manager APIs against https://up.woozooo.com/
// Ported from lanzou.class.php (login, folder/file CRUD, passwords).
// Credentials are never hard-coded; pass them to NewAccount / Login.

package lanzou

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAccountBase = "https://pc.woozooo.com/"
	// Lanzou HTML5 upload limit (server-side).
	maxUploadBytes = 100 * 1024 * 1024
)

// uploadAllowedExts is the server-side suffix whitelist for html5up.php.
// Source: Lanzou web upload policy (cannot upload e.g. .dex directly).
var uploadAllowedExts = map[string]struct{}{
	"doc": {}, "docx": {}, "zip": {}, "rar": {}, "apk": {}, "txt": {}, "exe": {},
	"7z": {}, "e": {}, "z": {}, "ct": {}, "ke": {}, "cetrainer": {}, "db": {},
	"tar": {}, "pdf": {}, "w3x": {}, "epub": {}, "mobi": {}, "azw": {}, "azw3": {},
	"osk": {}, "osz": {}, "xpa": {}, "cpk": {}, "lua": {}, "jar": {}, "dmg": {},
	"ppt": {}, "pptx": {}, "xls": {}, "xlsx": {}, "mp3": {}, "ipa": {}, "iso": {},
	"img": {}, "gho": {}, "ttf": {}, "ttc": {}, "txf": {}, "dwg": {}, "bat": {},
	"imazingapp": {}, "dll": {}, "crx": {}, "xapk": {}, "conf": {}, "deb": {},
	"rp": {}, "rpm": {}, "rplib": {}, "mobileconfig": {}, "appimage": {},
	"lolgezi": {}, "flac": {}, "cad": {}, "hwt": {}, "accdb": {}, "ce": {},
	"xmind": {}, "enc": {}, "bds": {}, "bdi": {}, "ssf": {}, "it": {},
	"pkg": {}, "cfg": {}, "mp4": {}, "avi": {}, "png": {}, "jpeg": {}, "jpg": {},
	"gif": {}, "webp": {}, "brushset": {},
}

// fileExt returns lower-case extension without the leading dot.
func fileExt(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	return strings.TrimPrefix(ext, ".")
}

// IsUploadAllowedExt reports whether ext (with or without leading dot) is
// accepted by Lanzou html5up.php.
func IsUploadAllowedExt(ext string) bool {
	ext = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ext), "."))
	if ext == "" {
		return false
	}
	_, ok := uploadAllowedExts[ext]
	return ok
}

// zipSingleFile packs src into a temporary .zip containing one entry (basename).
//
// IMPORTANT: archive/zip.Writer always emits local headers with bit 3 (data
// descriptor) and zero sizes. Lanzou CDN rejects large files built that way
// with offline ERROR:102. We write a Store zip with full sizes/CRC in the
// local header (same layout the official web upload / Python zipfile produce).
func zipSingleFile(src, suffixName string) (zipPath string, uploadName string, err error) {
	base := filepath.Base(src)
	if suffixName == "" {
		suffixName = "zip"
	}
	tmp, err := os.CreateTemp("", "lanzou-up-*.zip")
	if err != nil {
		return "", "", err
	}
	zipPath = tmp.Name()
	if err := writeStoreZip(src, base, tmp); err != nil {
		tmp.Close()
		os.Remove(zipPath)
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(zipPath)
		return "", "", err
	}
	uploadName = base + "." + suffixName
	return zipPath, uploadName, nil
}

// writeStoreZip writes a single-entry ZIP using the Store method and complete
// local-header sizes (no data descriptor bit).
func writeStoreZip(src, entryName string, out *os.File) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	if size < 0 {
		return fmt.Errorf("invalid size")
	}
	// CRC32 of whole file
	h := crc32.NewIEEE()
	if _, err := io.Copy(h, in); err != nil {
		return err
	}
	crc := h.Sum32()
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return err
	}

	name := []byte(entryName)
	if len(name) == 0 || len(name) > 0xffff {
		return fmt.Errorf("invalid zip entry name")
	}
	// DOS time = 0 is fine for CDN.
	var (
		modTime uint16
		modDate uint16
	)
	// Local file header (30 bytes + name)
	// signature, ver, flag, method, time, date, crc, csize, usize, nlen, elen
	local := make([]byte, 30)
	// little-endian helpers
	putU16 := func(b []byte, v uint16) { b[0] = byte(v); b[1] = byte(v >> 8) }
	putU32 := func(b []byte, v uint32) {
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
	}
	putU32(local[0:], 0x04034b50)
	putU16(local[4:], 20) // version needed
	putU16(local[6:], 0)  // flags: no data descriptor
	putU16(local[8:], 0)  // method Store
	putU16(local[10:], modTime)
	putU16(local[12:], modDate)
	putU32(local[14:], crc)
	putU32(local[18:], uint32(size))
	putU32(local[22:], uint32(size))
	putU16(local[26:], uint16(len(name)))
	putU16(local[28:], 0)
	if _, err := out.Write(local); err != nil {
		return err
	}
	if _, err := out.Write(name); err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	// Central directory
	cdStart, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	cd := make([]byte, 46)
	putU32(cd[0:], 0x02014b50)
	putU16(cd[4:], 20)  // version made by
	putU16(cd[6:], 20)  // version needed
	putU16(cd[8:], 0)   // flags
	putU16(cd[10:], 0)  // method Store
	putU16(cd[12:], modTime)
	putU16(cd[14:], modDate)
	putU32(cd[16:], crc)
	putU32(cd[20:], uint32(size))
	putU32(cd[24:], uint32(size))
	putU16(cd[28:], uint16(len(name)))
	putU16(cd[30:], 0) // extra
	putU16(cd[32:], 0) // comment
	putU16(cd[34:], 0) // disk start
	putU16(cd[36:], 0) // int attr
	putU32(cd[38:], 0) // ext attr
	putU32(cd[42:], 0) // relative offset of local header
	if _, err := out.Write(cd); err != nil {
		return err
	}
	if _, err := out.Write(name); err != nil {
		return err
	}
	cdEnd, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	// End of central directory
	eocd := make([]byte, 22)
	putU32(eocd[0:], 0x06054b50)
	putU16(eocd[4:], 0)
	putU16(eocd[6:], 0)
	putU16(eocd[8:], 1)
	putU16(eocd[10:], 1)
	putU32(eocd[12:], uint32(cdEnd-cdStart))
	putU32(eocd[16:], uint32(cdStart))
	putU16(eocd[20:], 0)
	_, err = out.Write(eocd)
	return err
}

// renameCopy creates a temp copy of src (no compression). Remote name is separate.
func renameCopy(src string) (path string, err error) {
	tmp, err := os.CreateTemp("", "lanzou-up-*")
	if err != nil {
		return "", err
	}
	path = tmp.Name()
	f, err := os.Open(src)
	if err != nil {
		tmp.Close()
		os.Remove(path)
		return "", err
	}
	if _, err := io.Copy(tmp, f); err != nil {
		f.Close()
		tmp.Close()
		os.Remove(path)
		return "", err
	}
	f.Close()
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// convertSuffix applies suffix_auto_convert policy to a single file that is
// already ≤ max upload size. Returns path + remote name + cleanup.
func convertSuffix(localPath string, cfg Config) (uploadPath, uploadName string, cleanup func(), err error) {
	cleanup = func() {}
	name := filepath.Base(localPath)
	if IsUploadAllowedExt(fileExt(name)) {
		return localPath, name, cleanup, nil
	}
	if !cfg.SuffixAutoConvert {
		return "", "", cleanup, fmt.Errorf(
			"suffix .%s not allowed by server (set suffix_auto_convert=true or rename)",
			fileExt(name),
		)
	}
	suffix := cfg.SuffixName
	if suffix == "" {
		suffix = "zip"
	}
	if !IsUploadAllowedExt(suffix) {
		return "", "", cleanup, fmt.Errorf("configured suffix_name .%s is not on server whitelist", suffix)
	}
	switch cfg.SuffixMode {
	case "rename":
		uploadName = name + "." + suffix
		p, err := renameCopy(localPath)
		if err != nil {
			return "", "", cleanup, err
		}
		cleanup = func() { _ = os.Remove(p) }
		return p, uploadName, cleanup, nil
	default: // zip
		zp, zn, err := zipSingleFile(localPath, suffix)
		if err != nil {
			return "", "", cleanup, fmt.Errorf("zip unsupported ext .%s: %w", fileExt(name), err)
		}
		cleanup = func() { _ = os.Remove(zp) }
		return zp, zn, cleanup, nil
	}
}

// splitFile writes raw chunks of localPath into temp files of at most chunkBytes.
func splitFile(localPath string, chunkBytes int64) (paths []string, sizes []int64, cleanup func(), err error) {
	cleanup = func() {
		for _, p := range paths {
			_ = os.Remove(p)
		}
	}
	f, err := os.Open(localPath)
	if err != nil {
		return nil, nil, cleanup, err
	}
	defer f.Close()
	buf := make([]byte, 1024*1024)
	var idx int
	for {
		tmp, err := os.CreateTemp("", fmt.Sprintf("lanzou-part-%d-*.bin", idx))
		if err != nil {
			cleanup()
			return nil, nil, func() {}, err
		}
		var written int64
		for written < chunkBytes {
			toRead := int64(len(buf))
			if left := chunkBytes - written; left < toRead {
				toRead = left
			}
			n, rerr := f.Read(buf[:toRead])
			if n > 0 {
				if _, werr := tmp.Write(buf[:n]); werr != nil {
					tmp.Close()
					cleanup()
					return nil, nil, func() {}, werr
				}
				written += int64(n)
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				tmp.Close()
				cleanup()
				return nil, nil, func() {}, rerr
			}
		}
		if err := tmp.Close(); err != nil {
			cleanup()
			return nil, nil, func() {}, err
		}
		if written == 0 {
			_ = os.Remove(tmp.Name())
			break
		}
		paths = append(paths, tmp.Name())
		sizes = append(sizes, written)
		idx++
		// peek: if EOF already drained, next loop will write 0
		// check remaining by attempting non-destructive? just continue; zero write breaks
		if written < chunkBytes {
			// last partial chunk
			break
		}
	}
	if len(paths) == 0 {
		return nil, nil, cleanup, fmt.Errorf("empty file, nothing to split")
	}
	return paths, sizes, cleanup, nil
}

// isArchiveSuffix reports suffixes the server may content-validate as archives.
func isArchiveSuffix(ext string) bool {
	switch strings.ToLower(strings.TrimPrefix(ext, ".")) {
	case "zip", "rar", "7z", "tar":
		return true
	default:
		return false
	}
}

// newPartGroupID builds a short unique group id for split notes.
func newPartGroupID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// Account is a logged-in Lanzou control-panel client.
type Account struct {
	http     *http.Client
	base     string
	cookie   string
	cookieFile string
	account  string
	password string
}

// AccountOption configures Account.
type AccountOption func(*Account)

// WithCookieFile sets a path to load/save session cookies.
func WithCookieFile(path string) AccountOption {
	return func(a *Account) { a.cookieFile = path }
}

// WithAccountBase overrides the control-panel origin (default up.woozooo.com).
func WithAccountBase(base string) AccountOption {
	return func(a *Account) {
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		a.base = base
	}
}

// NewAccount creates an account client. Call Login or LoadCookie before API use.
func NewAccount(username, password string, opts ...AccountOption) *Account {
	a := &Account{
		http: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		base:     defaultAccountBase,
		account:  username,
		password: password,
	}
	for _, o := range opts {
		o(a)
	}
	if a.cookieFile != "" {
		if b, err := os.ReadFile(a.cookieFile); err == nil {
			a.cookie = strings.TrimSpace(string(b))
		}
	}
	return a
}

// Login POSTs task/uid/pwd to mlogin.php (same as browser/curl simple login).
func (a *Account) Login() error {
	form := url.Values{}
	form.Set("task", "3")
	form.Set("uid", a.account)
	form.Set("pwd", a.password)

	req, err := http.NewRequest(http.MethodPost, a.base+"mlogin.php", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defaultUA)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Referer", a.base+"mlogin.php")
	req.Header.Set("Origin", strings.TrimRight(a.base, "/"))

	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	a.mergeSetCookie(resp.Header)

	var js map[string]any
	if err := json.Unmarshal(body, &js); err != nil {
		return fmt.Errorf("login non-json: %w body=%s", err, truncate(string(body), 200))
	}
	if anyString(js["zt"]) != "1" {
		info := anyString(js["info"])
		if info == "" {
			info = truncate(string(body), 200)
		}
		return fmt.Errorf("login failed: %s", info)
	}
	if a.cookie == "" {
		return fmt.Errorf("login ok but no Set-Cookie received")
	}
	if a.cookieFile != "" {
		if err := os.WriteFile(a.cookieFile, []byte(a.cookie), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (a *Account) mergeSetCookie(h http.Header) {
	mapc := map[string]string{}
	for _, pair := range strings.Split(a.cookie, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if k, v, ok := strings.Cut(pair, "="); ok {
			mapc[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	for _, sc := range h.Values("Set-Cookie") {
		part, _, _ := strings.Cut(sc, ";")
		if k, v, ok := strings.Cut(part, "="); ok {
			mapc[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	parts := make([]string, 0, len(mapc))
	for k, v := range mapc {
		parts = append(parts, k+"="+v)
	}
	a.cookie = strings.Join(parts, "; ")
}


// EnsureLogin logs in if Verification fails.
func (a *Account) EnsureLogin() error {
	if a.Verification() {
		return nil
	}
	return a.Login()
}

// Verification checks whether the current cookie session is valid.
func (a *Account) Verification() bool {
	if a.cookie == "" {
		return false
	}
	// soft check via doupload task=5
	raw, err := a.postTask("task=5&folder_id=-1")
	if err == nil {
		var js map[string]any
		if json.Unmarshal([]byte(raw), &js) == nil {
			zt := anyString(js["zt"])
			if zt != "" && zt != "9" {
				return true
			}
		}
	}
	// fallback: account.php should not show login page
	html, err := a.getHTML("account.php")
	if err != nil {
		return false
	}
	return !strings.Contains(html, "网盘用户登录")
}

// Cookie returns the raw cookie string.
func (a *Account) Cookie() string { return a.cookie }

// SetCookie sets session cookie manually.
func (a *Account) SetCookie(cookie string) {
	a.cookie = cookie
	if a.cookieFile != "" {
		_ = os.WriteFile(a.cookieFile, []byte(cookie), 0o600)
	}
}

func (a *Account) postTask(param string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, a.base+"doupload.php", strings.NewReader(param))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", defaultUA)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if a.cookie != "" {
		req.Header.Set("Cookie", a.cookie)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("doupload status %s body=%s", resp.Status, truncate(string(b), 200))
	}
	return string(b), nil
}

func (a *Account) getHTML(pathOrURL string) (string, error) {
	u := pathOrURL
	if !strings.HasPrefix(u, "http") {
		u = a.base + strings.TrimPrefix(pathOrURL, "/")
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", defaultUA)
	if a.cookie != "" {
		req.Header.Set("Cookie", a.cookie)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// EntryType: 0 folder, 1 file.
const (
	EntryFolder = 0
	EntryFile   = 1
)

// ListEntry is a folder or file row.
type ListEntry struct {
	Type        int    `json:"type"` // 0 folder, 1 file
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url,omitempty"`
	Size        string `json:"size,omitempty"`
	Time        string `json:"time,omitempty"`
	Description string `json:"description,omitempty"`
}

// List returns folders + files under folderID ("-1" is root).
// Folders via task=47, files via task=5 (JSON APIs).
func (a *Account) List(folderID string) ([]ListEntry, error) {
	if folderID == "" {
		folderID = "-1"
	}
	var out []ListEntry

	// folders
	rawDir, err := a.postTask("task=47&folder_id=" + url.QueryEscape(folderID))
	if err != nil {
		return nil, err
	}
	var dirJS struct {
		ZT   any `json:"zt"`
		Text []struct {
			Name      string `json:"name"`
			FolID     any    `json:"fol_id"`
			FolderDes string `json:"folder_des"`
		} `json:"text"`
	}
	if err := json.Unmarshal([]byte(rawDir), &dirJS); err != nil {
		return nil, fmt.Errorf("list folders json: %w body=%s", err, truncate(rawDir, 200))
	}
	for _, it := range dirJS.Text {
		id := anyString(it.FolID)
		if id == "" {
			continue
		}
		out = append(out, ListEntry{
			Type: EntryFolder, ID: id, Name: it.Name, Description: it.FolderDes,
		})
	}

	// files
	raw, err := a.postTask("task=5&folder_id=" + url.QueryEscape(folderID))
	if err != nil {
		return out, err
	}
	var js struct {
		ZT   any `json:"zt"`
		Text []struct {
			ID      any    `json:"id"`
			NameAll string `json:"name_all"`
			Size    string `json:"size"`
			Time    string `json:"time"`
		} `json:"text"`
	}
	if err := json.Unmarshal([]byte(raw), &js); err != nil {
		return out, fmt.Errorf("list files json: %w body=%s", err, truncate(raw, 200))
	}
	for _, it := range js.Text {
		id := anyString(it.ID)
		out = append(out, ListEntry{
			Type: EntryFile, ID: id, Name: it.NameAll, Size: it.Size, Time: it.Time,
		})
	}
	return out, nil
}

// GetFolderIDByName finds a child folder id by name under fatherID.
func (a *Account) GetFolderIDByName(name, fatherID string) (string, error) {
	list, err := a.List(fatherID)
	if err != nil {
		return "", err
	}
	for _, e := range list {
		if e.Type == EntryFolder && e.Name == name {
			return e.ID, nil
		}
	}
	return "", fmt.Errorf("folder %q not found", name)
}

// CreateFolder creates a folder. Returns raw JSON response body.
func (a *Account) CreateFolder(name, parentID, describe string) (string, error) {
	if parentID == "" {
		parentID = "-1"
	}
	// PHP inverted the existence check; we only create if not found.
	if id, err := a.GetFolderIDByName(name, parentID); err == nil && id != "" {
		return "", fmt.Errorf("folder already exists: id=%s", id)
	}
	form := url.Values{}
	form.Set("task", "2")
	form.Set("folder_name", name)
	form.Set("folder_description", describe)
	form.Set("parent_id", parentID)
	return a.postTask(form.Encode())
}

// SetFolderNameAndDescribe renames a folder and sets description.
func (a *Account) SetFolderNameAndDescribe(folderID, name, describe string) (string, error) {
	form := url.Values{}
	form.Set("task", "4")
	form.Set("folder_id", folderID)
	form.Set("folder_name", name)
	form.Set("folder_description", describe)
	return a.postTask(form.Encode())
}

// SetFolderPassword enables password on a folder.
func (a *Account) SetFolderPassword(folderID, pwd string) (string, error) {
	form := url.Values{}
	form.Set("task", "16")
	form.Set("shows", "1")
	form.Set("shownames", pwd)
	form.Set("folder_id", folderID)
	return a.postTask(form.Encode())
}

// DeleteFolder deletes a folder by id.
func (a *Account) DeleteFolder(folderID string) (string, error) {
	return a.postTask("task=3&folder_id=" + url.QueryEscape(folderID))
}

// DeleteFolderByName deletes a child folder by name.
func (a *Account) DeleteFolderByName(name, fatherID string) (string, error) {
	id, err := a.GetFolderIDByName(name, fatherID)
	if err != nil {
		return "", err
	}
	return a.DeleteFolder(id)
}

// FolderInfo holds scraped folder metadata.
type FolderInfo struct {
	Name        string
	Description string
	URL         string
	Password    string
	FileCount   string
	FileSize    string
}

// GetFolderInfo scrapes folder info page.
func (a *Account) GetFolderInfo(folderID string) (*FolderInfo, error) {
	html, err := a.getHTML(fmt.Sprintf("myfile.php?item=3&folder_id=%s&v2", url.QueryEscape(folderID)))
	if err != nil {
		return nil, err
	}
	info := &FolderInfo{
		Name:        strIntercept(html, `<input class="input" type="text" id="foldertxt" name="foldertxt" value="`, `">`),
		Description: strIntercept(html, `<input class="input" type="text" id="folderinfo" name="folderinfo" value="`, `">`),
		URL:         strIntercept(html, fmt.Sprintf(`<div class="folsha8"><div class="f_pwdurl" onclick="ucopy(%s);">`, folderID), `<br>`),
		Password:    strIntercept(html, `<span class="shapwd">密码:`, `</span></div>`),
		FileCount:   strIntercept(html, `<div class="folsha2">文件数<div class="folsha3">`, `</div></div>`),
		FileSize:    strIntercept(html, `<div class="folsha2">大小<div class="folsha3">`, `</div></div>`),
	}
	return info, nil
}

// GetFileInfoRaw returns raw JSON for task=22.
func (a *Account) GetFileInfoRaw(fileID string) (string, error) {
	return a.postTask("task=22&file_id=" + url.QueryEscape(fileID))
}

// FileInfo is a decoded task=22 payload.
type FileInfo struct {
	Raw map[string]any
	ID  string
	Pwd string
	// ShareURL is is_newd + "/" + f_id when available.
	ShareURL string
}

// GetFileInfo returns parsed file info.
func (a *Account) GetFileInfo(fileID string) (*FileInfo, error) {
	raw, err := a.GetFileInfoRaw(fileID)
	if err != nil {
		return nil, err
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(raw), &js); err != nil {
		return nil, err
	}
	info, _ := js["info"].(map[string]any)
	fi := &FileInfo{Raw: js, ID: fileID}
	if info != nil {
		fi.Pwd = anyString(info["pwd"])
		newd := anyString(info["is_newd"])
		fid := anyString(info["f_id"])
		if newd != "" && fid != "" {
			fi.ShareURL = strings.TrimRight(newd, "/") + "/" + fid
		}
	}
	return fi, nil
}

// GetFilePassword returns share password for a file.
func (a *Account) GetFilePassword(fileID string) (string, error) {
	fi, err := a.GetFileInfo(fileID)
	if err != nil {
		return "", err
	}
	return fi.Pwd, nil
}

// GetFileDownloadInfo returns share URL + password for a managed file.
func (a *Account) GetFileDownloadInfo(fileID string) (shareURL, pwd string, err error) {
	fi, err := a.GetFileInfo(fileID)
	if err != nil {
		return "", "", err
	}
	return fi.ShareURL, fi.Pwd, nil
}

// SetFilePassword sets a file share password.
func (a *Account) SetFilePassword(fileID, pwd string) (string, error) {
	form := url.Values{}
	form.Set("task", "23")
	form.Set("file_id", fileID)
	form.Set("shows", "1")
	form.Set("shownames", pwd)
	return a.postTask(form.Encode())
}

// GetFileDescribe returns file description.
func (a *Account) GetFileDescribe(fileID string) (string, error) {
	raw, err := a.postTask("task=12&file_id=" + url.QueryEscape(fileID))
	if err != nil {
		return "", err
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(raw), &js); err != nil {
		return "", err
	}
	return anyString(js["info"]), nil
}

// SetFileDescribe sets file description.
func (a *Account) SetFileDescribe(fileID, describe string) (string, error) {
	form := url.Values{}
	form.Set("task", "11")
	form.Set("file_id", fileID)
	form.Set("desc", describe)
	return a.postTask(form.Encode())
}

// MoveFile moves a file into folderID.
func (a *Account) MoveFile(fileID, folderID string) (string, error) {
	form := url.Values{}
	form.Set("task", "20")
	form.Set("folder_id", folderID)
	form.Set("file_id", fileID)
	return a.postTask(form.Encode())
}

// DeleteFile deletes a file by id.
func (a *Account) DeleteFile(fileID string) (string, error) {
	return a.postTask("task=6&file_id=" + url.QueryEscape(fileID))
}

// UploadResult is the outcome of a successful Upload (single or multi-part).
type UploadResult struct {
	FileID   string // first / only file id
	Name     string // first / only remote name
	RawJSON  string
	FolderID string
	// Parts is non-empty when the file was split.
	Parts []UploadPart `json:"parts,omitempty"`
	// OrigName is the original local basename.
	OrigName string `json:"orig_name,omitempty"`
	// GroupID links split parts via file description.
	GroupID string `json:"group_id,omitempty"`
}

// UploadPart is one chunk of a split upload.
type UploadPart struct {
	FileID string
	Name   string
	Index  int
	Total  int
	Size   int64
}

// Upload uploads a local file to folderID ("-1" = root) via html5up.php.
//
// Behaviour is controlled by GetConfig():
//   - suffix_auto_convert / suffix_name / suffix_mode for blocked extensions
//   - split_enable / split_size_mb / split_name_format / split_note for large files
//
// Server hard limit remains 100MB per request.
func (a *Account) Upload(localPath, folderID string) (*UploadResult, error) {
	if folderID == "" {
		folderID = "-1"
	}
	cfg := GetConfig()
	st, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("path is a directory: %s", localPath)
	}
	origName := filepath.Base(localPath)
	size := st.Size()
	chunkBytes := int64(cfg.SplitSizeMB) * 1024 * 1024
	if chunkBytes < 1 {
		chunkBytes = 90 * 1024 * 1024
	}
	if chunkBytes > maxUploadBytes {
		chunkBytes = maxUploadBytes
	}

	// Decide whether to split.
	needSplit := cfg.SplitEnable && size > chunkBytes
	if !cfg.SplitEnable && size > maxUploadBytes {
		return nil, fmt.Errorf(
			"file too large: %d bytes (max %d MB; enable split_enable or shrink file)",
			size, maxUploadBytes/(1024*1024),
		)
	}

	if !needSplit {
		// Single-file path: convert suffix if needed, then upload once.
		upPath, upName, cleanup, err := convertSuffix(localPath, cfg)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		// After convert, size may grow (zip); enforce limit.
		ust, err := os.Stat(upPath)
		if err != nil {
			return nil, err
		}
		if ust.Size() > maxUploadBytes {
			if !cfg.SplitEnable {
				return nil, fmt.Errorf(
					"converted file too large: %d bytes (max %d MB)",
					ust.Size(), maxUploadBytes/(1024*1024),
				)
			}
			// Fall through to split the converted file.
			needSplit = true
			localPath = upPath
			// keep cleanup for later — restructure
			return a.uploadSplit(upPath, origName, folderID, cfg, chunkBytes, cleanup)
		}
		if upName != origName {
			fmt.Fprintf(os.Stderr, "[upload] convert %s -> %s  size=%s\n",
				origName, upName, humanBytes(ust.Size()))
		} else {
			fmt.Fprintf(os.Stderr, "[upload] single %s  size=%s\n",
				upName, humanBytes(ust.Size()))
		}
		res, err := a.uploadOne(upPath, upName, folderID)
		if err != nil {
			return nil, err
		}
		res.OrigName = origName
		// Always write JSON note (raw or convert).
		if res.FileID != "" {
			origSize := st.Size()
			var note string
			if upName != origName {
				note = FormatConvertNote(origName, upName, cfg.SuffixMode, cfg.SuffixName, origSize)
			} else {
				note = FormatRawNote(origName, upName, origSize)
			}
			if _, nerr := a.SetFileDescribe(res.FileID, note); nerr != nil {
				fmt.Fprintf(os.Stderr, "[warn] set note: %v\n", nerr)
			}
		}
		return res, nil
	}

	return a.uploadSplit(localPath, origName, folderID, cfg, chunkBytes, func() {})
}

// uploadSplit splits localPath into chunks, converts each, uploads, writes notes.
// Notes form a linked list via "next" (file id of the following part).
func (a *Account) uploadSplit(
	localPath, origName, folderID string,
	cfg Config, chunkBytes int64, parentCleanup func(),
) (*UploadResult, error) {
	defer parentCleanup()
	st, _ := os.Stat(localPath)
	var totalSize int64
	if st != nil {
		totalSize = st.Size()
	}
	fmt.Fprintf(os.Stderr, "[upload] split %s  size=%s  chunk=%s  ...\n",
		origName, humanBytes(totalSize), humanBytes(chunkBytes))
	paths, sizes, cleanup, err := splitFile(localPath, chunkBytes)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	total := len(paths)
	groupID := newPartGroupID()
	suffix := cfg.SuffixName
	if suffix == "" {
		suffix = "zip"
	}
	fmt.Fprintf(os.Stderr, "[upload] split ready  parts=%d  group=%s\n", total, groupID)

	// Phase 1: upload all parts (notes written in phase 2 once next ids known).
	type staged struct {
		fileID string
		name   string
		size   int64
		index  int
	}
	stagedParts := make([]staged, 0, total)

	for i, p := range paths {
		index := i + 1
		partName := FormatSplitName(cfg.SplitNameFormat, origName, index, total, suffix)
		if !IsUploadAllowedExt(fileExt(partName)) {
			partName = partName + "." + suffix
		}

		var upPath, upName string
		var partCleanup func()
		needRealZip := cfg.SuffixMode == "zip" && isArchiveSuffix(suffix)
		if needRealZip {
			zp, zn, err := zipSingleFile(p, suffix)
			if err != nil {
				return nil, err
			}
			upPath = zp
			upName = partName
			if fileExt(upName) != suffix {
				upName = strings.TrimSuffix(upName, filepath.Ext(upName)) + "." + suffix
			}
			_ = zn
			partCleanup = func() { _ = os.Remove(zp) }
		} else {
			upName = partName
			if !IsUploadAllowedExt(fileExt(upName)) {
				upName = upName + "." + suffix
			}
			cp, err := renameCopy(p)
			if err != nil {
				return nil, err
			}
			upPath = cp
			partCleanup = func() { _ = os.Remove(cp) }
		}
		ust, err := os.Stat(upPath)
		if err != nil {
			partCleanup()
			return nil, err
		}
		if ust.Size() > maxUploadBytes {
			partCleanup()
			return nil, fmt.Errorf("part %d too large after convert: %d bytes", index, ust.Size())
		}
		fmt.Fprintf(os.Stderr, "[upload] part %d/%d  name=%s  payload=%s  raw=%s\n",
			index, total, upName, humanBytes(ust.Size()), humanBytes(sizes[i]))
		res, err := a.uploadOne(upPath, upName, folderID)
		partCleanup()
		if err != nil {
			return nil, fmt.Errorf("upload part %d/%d: %w", index, total, err)
		}
		fmt.Fprintf(os.Stderr, "[ok %d/%d] part %d id=%s name=%s\n",
			index, total, index, res.FileID, res.Name)
		stagedParts = append(stagedParts, staged{
			fileID: res.FileID,
			name:   res.Name,
			size:   sizes[i],
			index:  index,
		})
	}

	// Phase 2: write part notes with next → following file id.
	fmt.Fprintf(os.Stderr, "[upload] writing part notes (%d)...\n", total)
	parts := make([]UploadPart, 0, total)
	for i, sp := range stagedParts {
		nextID := ""
		if i+1 < len(stagedParts) {
			nextID = stagedParts[i+1].fileID
		}
		if sp.fileID != "" {
			note := FormatPartNote(groupID, origName, sp.name, sp.index, total, sp.size, nextID)
			if _, nerr := a.SetFileDescribe(sp.fileID, note); nerr != nil {
				fmt.Fprintf(os.Stderr, "[warn] set part note %d: %v\n", sp.index, nerr)
			}
		}
		parts = append(parts, UploadPart{
			FileID: sp.fileID,
			Name:   sp.name,
			Index:  sp.index,
			Total:  total,
			Size:   sp.size,
		})
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("split upload produced no parts")
	}
	fmt.Fprintf(os.Stderr, "[upload] split done  parts=%d  group=%s  orig=%s\n",
		total, groupID, origName)
	return &UploadResult{
		FileID:   parts[0].FileID,
		Name:     parts[0].Name,
		FolderID: folderID,
		Parts:    parts,
		OrigName: origName,
		GroupID:  groupID,
	}, nil
}

// uploadOne POSTs a single local file with the given remote filename.
// Streams the multipart body so large files do not need a full in-memory buffer,
// and reports byte progress for the file part.
func (a *Account) uploadOne(localPath, filename, folderID string) (*UploadResult, error) {
	st, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}
	fileSize := st.Size()

	tryURLs := []string{a.base + "html5up.php"}
	if u, err := url.Parse(a.base); err == nil {
		alt := "https://pc.woozooo.com/"
		if u.Host == "pc.woozooo.com" {
			alt = "https://up.woozooo.com/"
		} else if u.Host == "up.woozooo.com" {
			alt = "https://pc.woozooo.com/"
		}
		if alt != a.base {
			tryURLs = append(tryURLs, alt+"html5up.php")
		}
	}

	client := *a.http
	client.Timeout = 60 * time.Minute

	var lastErr error
	var raw string
	for _, upURL := range tryURLs {
		f, err := os.Open(localPath)
		if err != nil {
			return nil, err
		}

		pr, pw := io.Pipe()
		w := multipart.NewWriter(pw)
		ct := w.FormDataContentType()
		prog := &progressReader{r: f, total: fileSize, label: filename, kind: "upload"}

		go func() {
			var copyErr error
			defer func() {
				_ = w.Close()
				_ = f.Close()
				if copyErr != nil {
					_ = pw.CloseWithError(copyErr)
				} else {
					_ = pw.Close()
				}
			}()
			if err := w.WriteField("task", "1"); err != nil {
				copyErr = err
				return
			}
			if err := w.WriteField("folder_id", folderID); err != nil {
				copyErr = err
				return
			}
			part, err := w.CreateFormFile("upload_file", filename)
			if err != nil {
				copyErr = err
				return
			}
			if _, err := io.Copy(part, prog); err != nil {
				copyErr = err
				return
			}
			prog.finishLine()
		}()

		req, err := http.NewRequest(http.MethodPost, upURL, pr)
		if err != nil {
			_ = pw.CloseWithError(err)
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", ct)
		req.Header.Set("User-Agent", defaultUA)
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		req.Header.Set("Referer", a.base+"mydisk.php")
		req.Header.Set("Origin", strings.TrimRight(a.base, "/"))
		if a.cookie != "" {
			req.Header.Set("Cookie", a.cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		rawB, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		raw = string(rawB)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("upload status %s body=%s", resp.Status, truncate(raw, 300))
			continue
		}
		var js map[string]any
		if err := json.Unmarshal(rawB, &js); err != nil {
			lastErr = fmt.Errorf("upload non-json: %w body=%s", err, truncate(raw, 300))
			continue
		}
		if anyString(js["zt"]) != "1" {
			lastErr = fmt.Errorf("upload failed: %s", truncate(raw, 300))
			continue
		}
		fileID := ""
		name := filename
		switch text := js["text"].(type) {
		case []any:
			if len(text) > 0 {
				if row, ok := text[0].(map[string]any); ok {
					fileID = anyString(row["id"])
					if n := anyString(row["name"]); n != "" {
						name = n
					} else if n := anyString(row["name_all"]); n != "" {
						name = n
					}
				}
			}
		case map[string]any:
			fileID = anyString(text["id"])
			if n := anyString(text["name"]); n != "" {
				name = n
			} else if n := anyString(text["name_all"]); n != "" {
				name = n
			}
		}
		if fileID == "" {
			fileID = anyString(js["id"])
			if fileID == "" {
				if info, ok := js["info"].(map[string]any); ok {
					fileID = anyString(info["id"])
				} else {
					fileID = anyString(js["info"])
				}
			}
		}
		return &UploadResult{
			FileID:   fileID,
			Name:     name,
			RawJSON:  raw,
			FolderID: folderID,
		}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("upload failed")
	}
	return nil, lastErr
}

// --- string helpers (PHP strIntercept port) ---

func strIntercept(str, start, end string) string {
	if start == "" {
		if end == "" {
			return str
		}
		i := strings.Index(str, end)
		if i < 0 {
			return ""
		}
		return str[:i]
	}
	i := strings.Index(str, start)
	if i < 0 {
		return ""
	}
	i += len(start)
	if end == "" {
		return str[i:]
	}
	j := strings.Index(str[i:], end)
	if j < 0 {
		return ""
	}
	return str[i : i+j]
}

// silence unused import if strconv used elsewhere - keep for ID parsing convenience
var _ = strconv.Itoa


