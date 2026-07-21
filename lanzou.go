// Package lanzou resolves Lanzou (蓝奏云) public and password share links.
//
// Features:
//   - public / password shares
//   - Alibaba WAF/ESA acw_sc__v2 cookie
//   - CDN pseudo-link resolution and risk-page fallback
//   - optional local download
package lanzou

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	// MASK / PERM recovered from acw challenge script (stable for current site family).
	acwMask = "3000176000856006061501533003690027800375"
	cdnRiskWait = 2200 * time.Millisecond
)

// Fixed 1-based permutation for acw_sc__v2.
var acwPerm = []int{
	0x0F, 0x23, 0x1D, 0x18, 0x21, 0x10, 0x01, 0x26, 0x0A, 0x09, 0x13, 0x1F, 0x28, 0x1B, 0x16,
	0x17, 0x19, 0x0D, 0x06, 0x0B, 0x27, 0x12, 0x14, 0x08, 0x0E, 0x15, 0x20, 0x1A, 0x02, 0x1E,
	0x07, 0x04, 0x11, 0x05, 0x03, 0x1C, 0x22, 0x25, 0x0C, 0x24,
}

// Sentinel errors.
var (
	ErrPasswordRequired = errors.New("password required for this share link")
)

var (
	reArg1     = regexp.MustCompile(`var\s+arg1\s*=\s*'([0-9A-Fa-f]+)'`)
	reSign     = regexp.MustCompile(`'sign'\s*:\s*'([^']+)'`)
	reAjaxmFid = regexp.MustCompile(`ajaxm\.php\?file=(\d+)`)
	reFidVar   = regexp.MustCompile(`var\s+fid\s*=\s*(\d+)\s*;`)
	reFidData  = regexp.MustCompile(`data-id="(\d+)"`)
	reFidQuote = regexp.MustCompile(`fid\s*=\s*'(\d+)'`)
	reFnIframe = regexp.MustCompile(`iframe[^>]*src="(/fn\?[^"]*)"`)
	reFnSrc    = regexp.MustCompile(`src='(/fn\?[^']*)'`)
	reTitle    = regexp.MustCompile(`(?is)<title>(.*?)(?:\s*-\s*蓝奏云)?</title>`)
	reWpSign   = regexp.MustCompile(`var\s+wp_sign\s*=\s*'([^']*)'`)
	reAjaxdata = regexp.MustCompile(`var\s+ajaxdata\s*=\s*'([^']*)'`)
	reKdns     = regexp.MustCompile(`var\s+kdns\s*=\s*(\d+)`)
	reKilldns  = regexp.MustCompile(`var\s+killdns\s*=\s*(\d+)`)
	reFileTok  = regexp.MustCompile(`'file'\s*:\s*'([^']+)'`)
	reFReport  = regexp.MustCompile(`[?&]f=(\d+)`)
)

// Options for Parse.
type Options struct {
	Password      string
	ResolveDirect bool
}

// Result of a successful Parse.
type Result struct {
	FID                 string
	Filename            string
	PasswordProtected   bool
	CDNDomain           string
	Telecom             string
	Unicom              string
	Normal              string
	Direct              string
	SavedPath           string
}

// Client holds HTTP state (cookies) for a lanzou session.
type Client struct {
	http     *http.Client
	cookies  map[string]string
	origin   string
	filename string
}

// New creates a Client with browser-like headers and cookie jar map.
func New() *Client {
	return &Client{
		http: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		cookies: map[string]string{},
	}
}

// IsAcwChallenge reports whether HTML is an acw challenge page.
func IsAcwChallenge(html string) bool {
	return strings.Contains(html, "var arg1=") && strings.Contains(html, "acw_sc__v2")
}

// ExtractArg1 extracts arg1 from challenge HTML.
func ExtractArg1(html string) (string, bool) {
	m := reArg1.FindStringSubmatch(html)
	if len(m) < 2 {
		return "", false
	}
	return m[1], true
}

// CalcAcwScV2 computes cookie value from arg1.
func CalcAcwScV2(arg1 string) (string, error) {
	return CalcAcwScV2With(arg1, acwMask, acwPerm)
}

// CalcAcwScV2With allows custom mask/perm.
func CalcAcwScV2With(arg1, mask string, perm []int) (string, error) {
	if len(arg1) != len(perm) {
		return "", fmt.Errorf("arg1 length %d != perm length %d", len(arg1), len(perm))
	}
	q := make([]byte, len(perm))
	for x := 0; x < len(arg1); x++ {
		pos := x + 1
		for z, p := range perm {
			if p == pos {
				q[z] = arg1[x]
			}
		}
	}
	u := string(q)
	var b strings.Builder
	limit := len(u)
	if len(mask) < limit {
		limit = len(mask)
	}
	for i := 0; i+1 < limit; i += 2 {
		left, err := strconv.ParseUint(u[i:i+2], 16, 8)
		if err != nil {
			return "", err
		}
		right, err := strconv.ParseUint(mask[i:i+2], 16, 8)
		if err != nil {
			return "", err
		}
		b.WriteString(fmt.Sprintf("%02x", uint8(left)^uint8(right)))
	}
	return b.String(), nil
}

// IsPasswordProtected detects password share HTML.
func IsPasswordProtected(html string) bool {
	markers := []string{
		`id="passwddiv"`,
		`id='passwddiv'`,
		`id="pwd"`,
		`function down_p(`,
		`passwddiv-input`,
		`输入密码`,
	}
	for _, m := range markers {
		if strings.Contains(html, m) {
			return true
		}
	}
	return false
}

func (c *Client) storeCookies(h http.Header) {
	for _, sc := range h.Values("Set-Cookie") {
		part := strings.SplitN(sc, ";", 2)[0]
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
			c.cookies[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
}

func (c *Client) cookieHeader() string {
	if len(c.cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(c.cookies))
	for k, v := range c.cookies {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUA)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	}
	if ch := c.cookieHeader(); ch != "" {
		req.Header.Set("Cookie", ch)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	c.storeCookies(resp.Header)
	return resp, nil
}

func (c *Client) getHTML(rawURL, referer string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GET %s -> %s", rawURL, resp.Status)
	}
	text := string(body)
	if !IsAcwChallenge(text) {
		return text, nil
	}
	arg1, ok := ExtractArg1(text)
	if !ok {
		return "", errors.New("acw challenge without arg1")
	}
	token, err := CalcAcwScV2(arg1)
	if err != nil {
		return "", err
	}
	c.cookies["acw_sc__v2"] = token

	req2, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	if referer != "" {
		req2.Header.Set("Referer", referer)
	}
	resp2, err := c.do(req2)
	if err != nil {
		return "", err
	}
	defer resp2.Body.Close()
	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		return "", err
	}
	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		return "", fmt.Errorf("GET %s after acw -> %s", rawURL, resp2.Status)
	}
	text2 := string(body2)
	if IsAcwChallenge(text2) {
		return "", errors.New("still on acw challenge after cookie")
	}
	return text2, nil
}

func originOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

func lastMatch(re *regexp.Regexp, s string) string {
	all := re.FindAllStringSubmatch(s, -1)
	if len(all) == 0 || len(all[len(all)-1]) < 2 {
		return ""
	}
	return all[len(all)-1][1]
}

func extractPwdSign(html string) string {
	all := reSign.FindAllStringSubmatch(html, -1)
	var valid []string
	for _, m := range all {
		if len(m) < 2 {
			continue
		}
		s := m[1]
		if len(s) > 20 && !strings.ContainsAny(s, "<>") {
			valid = append(valid, s)
		}
	}
	if len(valid) == 0 {
		return ""
	}
	return valid[len(valid)-1]
}

func extractPwdFID(html string) string {
	if s := lastMatch(reAjaxmFid, html); s != "" {
		return s
	}
	return lastMatch(reFReport, html)
}

type ajaxmResp struct {
	ZT  any `json:"zt"`
	Dom any `json:"dom"`
	URL any `json:"url"`
	Inf any `json:"inf"`
}

func anyString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		// JSON numbers decode as float64
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(v)
	}
}

func ztString(v any) string { return anyString(v) }

type linkSet struct {
	dom, telecom, unicom, normal string
}

func (c *Client) postAjaxm(api string, form url.Values, referer, kdns string) (*linkSet, error) {
	req, err := http.NewRequest(http.MethodPost, api, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", c.origin)
	req.Header.Set("Referer", referer)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ajaxm %s -> %s body=%s", api, resp.Status, truncate(string(body), 200))
	}
	var data ajaxmResp
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("ajaxm non-json: %w body=%s", err, truncate(string(body), 200))
	}
	if ztString(data.ZT) != "1" {
		return nil, fmt.Errorf("ajaxm failed zt=%v info=%s", data.ZT, anyString(data.Inf))
	}
	dom := anyString(data.Dom)
	fileURL := anyString(data.URL)
	if dom == "" || fileURL == "" {
		return nil, fmt.Errorf("ajaxm missing dom/url")
	}
	if kdns == "0" {
		dom = "https://slssctm.dmpdmp.com"
	}
	if inf := strings.TrimSpace(anyString(data.Inf)); inf != "" && inf != "文件" {
		// public shares sometimes return numeric/noise inf; keep only filename-like values
		if strings.Contains(inf, ".") || strings.ContainsAny(inf, "._- ") || !isAllDigits(inf) {
			c.filename = inf
		}
	}
	base := dom + "/file/" + fileURL
	normal := base
	if strings.Contains(base, "?") {
		normal += "&toolsdown"
	} else {
		normal += "?toolsdown"
	}
	return &linkSet{dom: dom, telecom: base, unicom: base, normal: normal}, nil
}

// Parse resolves a share URL.
func (c *Client) Parse(shareURL string, opt Options) (*Result, error) {
	if opt == (Options{}) {
		opt.ResolveDirect = true
	}
	// default ResolveDirect true when zero value used with password only
	if !opt.ResolveDirect && opt.Password == "" {
		// leave as-is; callers should set explicitly. For convenience when only Password set:
	}
	// Force default true unless caller constructs Options with ResolveDirect false intentionally.
	// Zero value has ResolveDirect=false; match Python default by treating unset via helper.
	// We document that ResolveDirect defaults to true when using DefaultOptions().
	c.filename = ""
	origin, err := originOf(shareURL)
	if err != nil {
		return nil, err
	}
	c.origin = origin

	html, err := c.getHTML(shareURL, "")
	if err != nil {
		return nil, err
	}

	var (
		fid  string
		ls   *linkSet
		pwdP bool
	)

	if IsPasswordProtected(html) {
		if strings.TrimSpace(opt.Password) == "" {
			return nil, ErrPasswordRequired
		}
		pwdP = true
		fid = extractPwdFID(html)
		sign := extractPwdSign(html)
		if fid == "" || sign == "" {
			return nil, fmt.Errorf("password page parse failed: fid=%q sign=%v", fid, sign != "")
		}
		kdns := "1"
		if m := reKdns.FindStringSubmatch(html); len(m) == 2 {
			kdns = m[1]
		}
		if m := reKilldns.FindStringSubmatch(html); len(m) == 2 {
			kdns = m[1]
		}
		form := url.Values{}
		form.Set("action", "downprocess")
		form.Set("sign", sign)
		form.Set("kd", kdns)
		form.Set("p", opt.Password)
		api := c.origin + "/ajaxm.php?file=" + fid
		ls, err = c.postAjaxm(api, form, shareURL, kdns)
		if err != nil {
			return nil, err
		}
	} else {
		fid = firstNonEmpty(
			sub1(reFidVar, html),
			sub1(reFidData, html),
			sub1(reFidQuote, html),
		)
		fnPath := firstNonEmpty(sub1(reFnIframe, html), sub1(reFnSrc, html))
		if fid == "" || fnPath == "" {
			return nil, fmt.Errorf("public page missing fid/fn: fid=%q fn=%q", fid, fnPath)
		}
		if m := reTitle.FindStringSubmatch(html); len(m) == 2 {
			name := strings.TrimSpace(m[1])
			if name != "" && name != "文件" && name != "蓝奏云" {
				c.filename = name
			}
		}
		fnURL := c.origin + fnPath
		fnHTML, err := c.getHTML(fnURL, c.origin+"/")
		if err != nil {
			return nil, err
		}
		wpSign := sub1(reWpSign, fnHTML)
		ajaxdata := sub1(reAjaxdata, fnHTML)
		kdns := "1"
		if m := reKdns.FindStringSubmatch(fnHTML); len(m) == 2 {
			kdns = m[1]
		}
		if m := reKilldns.FindStringSubmatch(fnHTML); len(m) == 2 {
			kdns = m[1]
		}
		if wpSign == "" || ajaxdata == "" {
			return nil, fmt.Errorf("fn page missing sign/ajaxdata")
		}
		form := url.Values{}
		form.Set("action", "downprocess")
		form.Set("websignkey", ajaxdata)
		form.Set("signs", ajaxdata)
		form.Set("sign", wpSign)
		form.Set("websign", "")
		form.Set("kd", kdns)
		form.Set("ves", "1")
		api := c.origin + "/ajaxm.php?file=" + fid
		ls, err = c.postAjaxm(api, form, c.origin+fnPath, kdns)
		if err != nil {
			return nil, err
		}
	}

	res := &Result{
		FID:               fid,
		Filename:          c.filename,
		PasswordProtected: pwdP,
		CDNDomain:         ls.dom,
		Telecom:           ls.telecom,
		Unicom:            ls.unicom,
		Normal:            ls.normal,
	}

	// Default resolve direct to true for Options{} used carefully:
	// If caller only sets Password, ResolveDirect is false; fix by DefaultOptions.
	if opt.ResolveDirect {
		direct, err := c.ResolveDirectURL(ls.telecom)
		if err != nil {
			direct, err = c.ResolveDirectURL(ls.normal)
			if err != nil {
				return nil, err
			}
		}
		res.Direct = direct
	}
	return res, nil
}

// DefaultOptions returns options with ResolveDirect enabled.
func DefaultOptions() Options {
	return Options{ResolveDirect: true}
}

// ResolveDirectURL turns a CDN pseudo link into a downloadable URL.
func (c *Client) ResolveDirectURL(cdnURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, cdnURL, nil)
	if err != nil {
		return "", err
	}
	if c.origin != "" {
		req.Header.Set("Referer", c.origin+"/")
	} else {
		req.Header.Set("Referer", "https://www.lanzou.com/")
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("cdn status %s", resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	buf := make([]byte, 256)
	n, _ := io.ReadFull(resp.Body, buf)
	head := buf[:n]
	if looksLikeFile(head, ct) {
		io.Copy(io.Discard, resp.Body)
		return cdnURL, nil
	}
	rest, _ := io.ReadAll(resp.Body)
	body := append(head, rest...)
	text := string(body)
	if isCDNRiskPage(text) {
		return c.resolveViaAjax(cdnURL, text)
	}
	return "", fmt.Errorf("unknown CDN response ct=%s head=%q", ct, truncate(string(head), 60))
}

type riskResp struct {
	ZT  any    `json:"zt"`
	URL string `json:"url"`
}

func (c *Client) resolveViaAjax(cdnURL, riskHTML string) (string, error) {
	fileTok := sub1(reFileTok, riskHTML)
	sign := ""
	if all := reSign.FindAllStringSubmatch(riskHTML, -1); len(all) > 0 {
		sign = all[0][1]
	}
	if fileTok == "" || sign == "" {
		return "", errors.New("risk page missing file/sign")
	}
	u, err := url.Parse(cdnURL)
	if err != nil {
		return "", err
	}
	ajax, err := u.Parse("ajax.php")
	if err != nil {
		return "", err
	}
	origin, _ := originOf(cdnURL)
	var lastErr error
	for i := 0; i < 2; i++ {
		time.Sleep(cdnRiskWait)
		form := url.Values{}
		form.Set("file", fileTok)
		form.Set("el", "2")
		form.Set("sign", sign)
		req, err := http.NewRequest(http.MethodPost, ajax.String(), strings.NewReader(form.Encode()))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		req.Header.Set("Referer", cdnURL)
		req.Header.Set("Origin", origin)
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
		resp, err := c.do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var data riskResp
		if err := json.Unmarshal(b, &data); err != nil {
			lastErr = fmt.Errorf("non-json: %w", err)
			continue
		}
		final := data.URL
		if ztString(data.ZT) == "1" && final != "" && !strings.HasPrefix(final, "?") {
			if strings.HasPrefix(final, "//") {
				final = "https:" + final
			} else if strings.HasPrefix(final, "/") {
				final = origin + final
			}
			return final, nil
		}
		lastErr = fmt.Errorf("zt=%v url=%s", data.ZT, final)
	}
	return "", fmt.Errorf("cdn ajax failed: %v", lastErr)
}

// Download saves url into destDir and returns the path.
// Progress is printed to stderr when Content-Length is known.
func (c *Client) Download(rawURL, destDir, filename, referer string) (string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	if referer == "" {
		if c.origin != "" {
			referer = c.origin + "/"
		} else {
			referer = "https://www.lanzou.com/"
		}
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Referer", referer)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	c.http.Timeout = 120 * time.Minute
	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download status %s", resp.Status)
	}

	name := filename
	if name == "" {
		name = filenameFromCD(resp.Header.Get("Content-Disposition"))
	}
	if name == "" {
		name = filenameFromURL(rawURL)
	}
	if name == "" {
		name = c.filename
	}
	if name == "" {
		name = fmt.Sprintf("lanzou_%d.bin", time.Now().Unix())
	}
	name = filepath.Base(name)
	out := filepath.Join(destDir, name)
	if _, err := os.Stat(out); err == nil {
		ext := filepath.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		for i := 1; ; i++ {
			cand := filepath.Join(destDir, fmt.Sprintf("%s(%d)%s", stem, i, ext))
			if _, err := os.Stat(cand); os.IsNotExist(err) {
				out = cand
				break
			}
		}
	}
	f, err := os.Create(out)
	if err != nil {
		return "", err
	}
	defer f.Close()

	total := resp.ContentLength
	src := io.Reader(resp.Body)
	if total > 0 {
		src = &progressReader{
			r:     resp.Body,
			total: total,
			label: name,
		}
	} else {
		fmt.Fprintf(os.Stderr, "\r[download] %s  ...", name)
	}
	if _, err := io.Copy(f, src); err != nil {
		return "", err
	}
	if total > 0 {
		fmt.Fprintf(os.Stderr, "\r[download] %s  100.0%%  %s/%s          \n",
			name, humanBytes(total), humanBytes(total))
	} else {
		fmt.Fprintf(os.Stderr, "\r[download] %s  done                    \n", name)
	}
	return out, nil
}

// progressReader prints download progress to stderr.
type progressReader struct {
	r       io.Reader
	total   int64
	read    int64
	label   string
	lastPct int
	lastAt  time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.read += int64(n)
		now := time.Now()
		pct := int(p.read * 1000 / p.total) // 0.1% units
		if p.lastAt.IsZero() || now.Sub(p.lastAt) >= 200*time.Millisecond || pct != p.lastPct || p.read >= p.total {
			p.lastAt = now
			p.lastPct = pct
			fmt.Fprintf(os.Stderr, "\r[download] %s  %5.1f%%  %s/%s  ",
				p.label, float64(p.read)*100/float64(p.total),
				humanBytes(p.read), humanBytes(p.total))
		}
	}
	return n, err
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	}
	f := float64(n)
	units := []string{"KB", "MB", "GB", "TB"}
	for _, u := range units {
		f /= 1024
		if f < 1024 {
			return fmt.Sprintf("%.1f%s", f, u)
		}
	}
	return fmt.Sprintf("%.1fPB", f/1024)
}

func isCDNRiskPage(html string) bool {
	return (strings.Contains(html, "ajax.php") && strings.Contains(html, "down_r")) ||
		(strings.Contains(html, "系统发现您的网络异常") && strings.Contains(html, "ajax.php"))
}

func looksLikeFile(chunk []byte, ct string) bool {
	lct := strings.ToLower(ct)
	if strings.Contains(lct, "octet-stream") || strings.Contains(lct, "zip") ||
		strings.Contains(lct, "msword") || strings.Contains(lct, "excel") {
		return true
	}
	if strings.Contains(lct, "application/") && !strings.Contains(lct, "html") && !strings.Contains(lct, "json") {
		return true
	}
	if len(chunk) >= 2 && chunk[0] == 'P' && chunk[1] == 'K' {
		return true
	}
	if len(chunk) >= 2 && chunk[0] == 0x1f && chunk[1] == 0x8b {
		return true
	}
	if len(chunk) >= 4 && chunk[0] == 0xd0 && chunk[1] == 0xcf && chunk[2] == 0x11 && chunk[3] == 0xe0 {
		return true
	}
	if len(chunk) >= 4 && string(chunk[:4]) == "%PDF" {
		return true
	}
	s := strings.ToLower(strings.TrimSpace(string(chunk)))
	if strings.HasPrefix(s, "<!doctype") || strings.HasPrefix(s, "<html") || strings.HasPrefix(s, "<script") {
		return false
	}
	return false
}

func filenameFromCD(cd string) string {
	if cd == "" {
		return ""
	}
	if i := strings.Index(strings.ToLower(cd), "filename*=utf-8''"); i >= 0 {
		v := cd[i+len("filename*=utf-8''"):]
		v = strings.Split(v, ";")[0]
		v, _ = url.QueryUnescape(strings.Trim(v, `"`))
		return v
	}
	if i := strings.Index(strings.ToLower(cd), "filename="); i >= 0 {
		v := cd[i+len("filename="):]
		v = strings.Split(v, ";")[0]
		return strings.Trim(v, `"`)
	}
	return ""
}

func filenameFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	for _, k := range []string{"fileName", "filename", "fn", "name"} {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	base := path.Base(u.Path)
	if base == "" || base == "." || base == "file" || base == "ajax.php" {
		return ""
	}
	return base
}

func sub1(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
