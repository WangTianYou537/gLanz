// Account / file-manager APIs against https://up.woozooo.com/
// Ported from lanzou.class.php (login, folder/file CRUD, passwords).
// Credentials are never hard-coded; pass them to NewAccount / Login.

package lanzou

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultAccountBase = "https://up.woozooo.com/"

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

// Login authenticates and stores cookies (optionally to cookie file).
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

	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// response may include headers if we don't separate; use Header for cookies
	var cookieParts []string
	for _, sc := range resp.Header.Values("Set-Cookie") {
		part := strings.SplitN(sc, ";", 2)[0]
		if part != "" {
			cookieParts = append(cookieParts, part)
		}
	}
	// Some endpoints return Set-Cookie only; also parse body JSON
	var js map[string]any
	_ = json.Unmarshal(body, &js)
	zt := anyString(js["zt"])
	if zt != "1" {
		return fmt.Errorf("login failed: zt=%v body=%s", js["zt"], truncate(string(body), 200))
	}
	if len(cookieParts) == 0 {
		// fallback: parse raw if client stripped cookies (unlikely)
		return fmt.Errorf("login ok but no Set-Cookie received")
	}
	a.cookie = strings.Join(cookieParts, "; ")
	if a.cookieFile != "" {
		if err := os.WriteFile(a.cookieFile, []byte(a.cookie), 0o600); err != nil {
			return err
		}
	}
	return nil
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
	raw, err := a.postTask("task=5&folder_id=-1")
	if err != nil {
		return false
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(raw), &js); err != nil {
		return false
	}
	return anyString(js["zt"]) != "9"
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

// Upload is not implemented in the original PHP class (no multipart endpoint there).
// Kept as a clear stub so callers know the gap.
func (a *Account) Upload(localPath, folderID string) error {
	return fmt.Errorf("upload not implemented: original PHP class has no upload API; use web doupload flow separately")
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
