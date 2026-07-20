// Account / file-manager APIs against https://up.woozooo.com/
// Ported from lanzou.class.php (login, folder/file CRUD, passwords).
// Credentials are never hard-coded; pass them to NewAccount / Login.

package lanzou

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAccountBase = "https://pc.woozooo.com/"
	mobileUA           = "Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4051.0 Mobile Safari/537.36"
)

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

// Login authenticates via account.php formhash + mydisk.php (current web flow).
// Old mlogin.php endpoint is no longer reliable.
func (a *Account) Login() error {
	// 1) GET account.php for formhash (+ any pre-cookies)
	req1, err := http.NewRequest(http.MethodGet, a.base+"mlogin.php", nil)
	if err != nil {
		return err
	}
	req1.Header.Set("User-Agent", mobileUA)
	req1.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req1.Header.Set("Referer", a.base+"mydisk.php")
	resp1, err := a.http.Do(req1)
	if err != nil {
		return err
	}
	body1, err := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if err != nil {
		return err
	}
	a.mergeSetCookie(resp1.Header)

	formhash := extractFormhash(string(body1))
	if formhash == "" {
		// fallback: try mobile login page
		reqM, _ := http.NewRequest(http.MethodGet, a.base+"mlogin.php", nil)
		if reqM != nil {
			reqM.Header.Set("User-Agent", mobileUA)
			respM, errM := a.http.Do(reqM)
			if errM == nil {
				bM, _ := io.ReadAll(respM.Body)
				respM.Body.Close()
				a.mergeSetCookie(respM.Header)
				formhash = extractFormhash(string(bM))
			}
		}
	}

	// 2) POST mydisk.php with full login fields (reference LanZouCloud-API)
	form := url.Values{}
	form.Set("task", "3")
	form.Set("setSessionId", "")
	form.Set("setToken", "")
	form.Set("setSig", "")
	form.Set("setScene", "")
	form.Set("uid", a.account)
	form.Set("pwd", a.password)
	if formhash != "" {
		form.Set("formhash", formhash)
	}

	tryURLs := []string{a.base + "mlogin.php?istoken=3", a.base + "mlogin.php", a.base + "mydisk.php"}
	var lastErr error
	for _, postURL := range tryURLs {
		req, err := http.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// mobile UA is required by some deployments
		req.Header.Set("User-Agent", mobileUA)
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		req.Header.Set("Referer", a.base+"account.php")
		req.Header.Set("Origin", strings.TrimRight(a.base, "/"))
		if a.cookie != "" {
			req.Header.Set("Cookie", a.cookie)
		}
		resp, err := a.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		a.mergeSetCookie(resp.Header)
		raw := string(body)
		var js map[string]any
		_ = json.Unmarshal(body, &js)
		info := anyString(js["info"])
		zt := anyString(js["zt"])
		ok := zt == "1" || strings.Contains(info, "成功") || strings.Contains(raw, "成功")
		if !ok {
			lastErr = fmt.Errorf("login failed via %s: zt=%v info=%s body=%s", postURL, js["zt"], info, truncate(raw, 200))
			continue
		}
		if a.cookie == "" {
			lastErr = fmt.Errorf("login response ok but no cookies set")
			continue
		}
		// verify session
		if !a.Verification() {
			// still save cookie; some checks are soft
			lastErr = fmt.Errorf("login cookie not accepted by verification; body=%s", truncate(raw, 200))
			// try next endpoint
			continue
		}
		if a.cookieFile != "" {
			if err := os.WriteFile(a.cookieFile, []byte(a.cookie), 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("login failed")
	}
	return lastErr
}

func extractFormhash(html string) string {
	re := regexp.MustCompile(`name=["']formhash["']\s+value=["']([^"']+)["']`)
	if m := re.FindStringSubmatch(html); len(m) == 2 {
		return m[1]
	}
	re2 := regexp.MustCompile(`value=["']([^"']+)["']\s+name=["']formhash["']`)
	if m := re2.FindStringSubmatch(html); len(m) == 2 {
		return m[1]
	}
	re3 := regexp.MustCompile(`formhash['"]?\s*[:=]\s*['"]([^'"]+)['"]`)
	if m := re3.FindStringSubmatch(html); len(m) == 2 {
		return m[1]
	}
	return "03e22cb9"
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
func (a *Account) List(folderID string) ([]ListEntry, error) {
	if folderID == "" {
		folderID = "-1"
	}
	html, err := a.getHTML("myfile.php?folder_id=" + url.QueryEscape(folderID))
	if err != nil {
		return nil, err
	}
	var out []ListEntry
	// folders between markers
	section := strIntercept(html, "<!--folder list index-->", "<!--file list index-->")
	marker := `<div class="folder">
	<div class="folders">
		<div class="folm" onclick="modify(`
	if section == "" {
		// tolerate whitespace variants
		reFolder := regexp.MustCompile(`onclick="modify\((\d+)\)"[\s\S]*?<span>([^<]*)</span>[\s\S]*?<a href="([^"]*)"[\s\S]*?<div class="folders1">([^<]*)</div>`)
		for _, m := range reFolder.FindAllStringSubmatch(html, -1) {
			out = append(out, ListEntry{
				Type: EntryFolder, ID: m[1], Name: m[2], URL: m[3], Description: strings.TrimSpace(m[4]),
			})
		}
	} else {
		parts := strings.Split(section, marker)
		for _, item := range parts {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			id := strIntercept(item, "", ")")
			name := strIntercept(item, "<span>", "</span>")
			u := strIntercept(item, `<a href="`, `"`)
			desc := strIntercept(item, `<div class="folders1">`, `</div>`)
			if id == "" && name == "" {
				continue
			}
			out = append(out, ListEntry{Type: EntryFolder, ID: id, Name: name, URL: u, Description: desc})
		}
	}

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
		desc, _ := a.GetFileDescribe(id)
		out = append(out, ListEntry{
			Type: EntryFile, ID: id, Name: it.NameAll, Size: it.Size, Time: it.Time, Description: desc,
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

// Upload uploads a local file to folderID ("-1" = root) via fileup.php.
// Protocol mirrors common Lanzou web clients (task=1 multipart to fileup.php).
// See: https://github.com/zaxtyson/LanZouCloud-API
func (a *Account) Upload(localPath, folderID string) (*UploadResult, error) {
	if folderID == "" {
		folderID = "-1"
	}
	f, err := os.Open(localPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("path is a directory: %s", localPath)
	}
	filename := filepath.Base(localPath)

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("task", "1")
	_ = w.WriteField("vie", "2")
	_ = w.WriteField("ve", "2")
	_ = w.WriteField("id", "WU_FILE_0")
	_ = w.WriteField("folder_id_bb_n", folderID)
	_ = w.WriteField("name", filename)
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

	tryURLs := []string{a.base + "fileup.php"}
	// also try pc.woozooo.com host (common web endpoint)
	if u, err := url.Parse(a.base); err == nil {
		host := u.Host
		if host == "up.woozooo.com" {
			tryURLs = append(tryURLs, "https://pc.woozooo.com/fileup.php")
		} else if host == "pc.woozooo.com" {
			tryURLs = append(tryURLs, "https://up.woozooo.com/fileup.php")
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
		req.Header.Set("Referer", a.base)
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
		if text, ok := js["text"].([]any); ok && len(text) > 0 {
			if row, ok := text[0].(map[string]any); ok {
				fileID = anyString(row["id"])
				if n := anyString(row["name"]); n != "" {
					name = n
				} else if n := anyString(row["name_all"]); n != "" {
					name = n
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


func looksLikeCaptchaError(s string) bool {
	s = strings.ToLower(s)
	for _, k := range []string{"验证", "captcha", "nvc", "token", "滑动", "智能验证", "sig"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}
