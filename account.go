// Account / file-manager APIs against https://up.woozooo.com/
// Ported from lanzou.class.php (login, folder/file CRUD, passwords).
// Credentials are never hard-coded; pass them to NewAccount / Login.

package lanzou

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
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
// Caller must remove the returned path when done.
func zipSingleFile(src string) (zipPath string, zipName string, err error) {
	base := filepath.Base(src)
	tmp, err := os.CreateTemp("", "lanzou-up-*.zip")
	if err != nil {
		return "", "", err
	}
	zipPath = tmp.Name()
	zw := zip.NewWriter(tmp)
	w, err := zw.Create(base)
	if err != nil {
		zw.Close()
		tmp.Close()
		os.Remove(zipPath)
		return "", "", err
	}
	f, err := os.Open(src)
	if err != nil {
		zw.Close()
		tmp.Close()
		os.Remove(zipPath)
		return "", "", err
	}
	if _, err := io.Copy(w, f); err != nil {
		f.Close()
		zw.Close()
		tmp.Close()
		os.Remove(zipPath)
		return "", "", err
	}
	f.Close()
	if err := zw.Close(); err != nil {
		tmp.Close()
		os.Remove(zipPath)
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(zipPath)
		return "", "", err
	}
	// e.g. classes2.dex -> classes2.dex.zip
	zipName = base + ".zip"
	return zipPath, zipName, nil
}

// prepareUploadPath validates size/ext. Unsupported suffixes are auto-zipped.
// cleanup removes a temp zip if one was created (no-op otherwise).
func prepareUploadPath(localPath string) (uploadPath, uploadName string, cleanup func(), err error) {
	cleanup = func() {}
	st, err := os.Stat(localPath)
	if err != nil {
		return "", "", cleanup, err
	}
	if st.IsDir() {
		return "", "", cleanup, fmt.Errorf("path is a directory: %s", localPath)
	}
	if st.Size() > maxUploadBytes {
		return "", "", cleanup, fmt.Errorf(
			"file too large: %d bytes (max %d MB)", st.Size(), maxUploadBytes/(1024*1024),
		)
	}
	name := filepath.Base(localPath)
	if IsUploadAllowedExt(fileExt(name)) {
		return localPath, name, cleanup, nil
	}
	// Auto wrap unsupported suffix (e.g. .dex) into .zip
	zp, zn, err := zipSingleFile(localPath)
	if err != nil {
		return "", "", cleanup, fmt.Errorf("zip unsupported ext .%s: %w", fileExt(name), err)
	}
	// re-check zipped size
	zst, err := os.Stat(zp)
	if err != nil {
		os.Remove(zp)
		return "", "", cleanup, err
	}
	if zst.Size() > maxUploadBytes {
		os.Remove(zp)
		return "", "", cleanup, fmt.Errorf(
			"zipped file too large: %d bytes (max %d MB)", zst.Size(), maxUploadBytes/(1024*1024),
		)
	}
	cleanup = func() { _ = os.Remove(zp) }
	return zp, zn, cleanup, nil
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

// UploadResult is the outcome of a successful Upload.
type UploadResult struct {
	FileID   string
	Name     string
	RawJSON  string
	FolderID string
}

// Upload uploads a local file to folderID ("-1" = root) via html5up.php.
// Matches browser HTML5 upload:
//
//	POST https://pc.woozooo.com/html5up.php
//	multipart: task=1, folder_id=<id>, upload_file=@file
//
// Server limits: max 100MB; restricted suffix whitelist. Unsupported suffixes
// (e.g. .dex) are automatically packed into a .zip before upload.
func (a *Account) Upload(localPath, folderID string) (*UploadResult, error) {
	if folderID == "" {
		folderID = "-1"
	}
	uploadPath, filename, cleanup, err := prepareUploadPath(localPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	f, err := os.Open(uploadPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("task", "1")
	_ = w.WriteField("folder_id", folderID)
	part, err := w.CreateFormFile("upload_file", filename)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, f); err != nil {
		return nil, err
	}
	ct := w.FormDataContentType()
	if err := w.Close(); err != nil {
		return nil, err
	}
	payload := body.Bytes()

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
		req, err := http.NewRequest(http.MethodPost, upURL, bytes.NewReader(payload))
		if err != nil {
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
		// html5up may return text as object or array
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
		// some responses put id at top-level
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


