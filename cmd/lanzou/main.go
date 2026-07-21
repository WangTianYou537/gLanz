package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/spf13/pflag"
	"github.com/WangTianYou537/gLanz"
)

func defaultCookiePath() string {
	if v := os.Getenv("LANZOU_COOKIE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "./lanzou.cookie"
	}
	return filepath.Join(home, ".lanzou", "cookie")
}

func ensureCookieDir(path string) {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
}

func main() {
	// Global -i / --interactive before subcommand routing
	if hasFlag(os.Args[1:], "-i") || hasFlag(os.Args[1:], "--interactive") {
		runInteractive(stripFlag(os.Args[1:], "-i", "--interactive"))
		return
	}

	if len(os.Args) < 2 {
		printRootHelp()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "parse", "get":
		runParse(os.Args[2:])
	case "login":
		runLogin(os.Args[2:])
	case "logout":
		runLogout(os.Args[2:])
	case "list", "ls":
		runList(os.Args[2:])
	case "upload", "up":
		runUpload(os.Args[2:])
	case "mkdir":
		runMkdir(os.Args[2:])
	case "rm", "delete":
		runDelete(os.Args[2:])
	case "info":
		runInfo(os.Args[2:])
	case "passwd", "password":
		runPasswd(os.Args[2:])
	case "download", "dl":
		runDownload(os.Args[2:])
	case "interactive", "i", "shell":
		runInteractive(os.Args[2:])
	case "help", "-h", "--help":
		printRootHelp()
	default:
		// bare share URL or share flags (legacy): lanzou <url> / lanzou -p xxx <url>
		if strings.HasPrefix(cmd, "http://") || strings.HasPrefix(cmd, "https://") || strings.HasPrefix(cmd, "-") {
			runParse(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printRootHelp()
		os.Exit(1)
	}
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func stripFlag(args []string, names ...string) []string {
	set := map[string]struct{}{}
	for _, n := range names {
		set[n] = struct{}{}
	}
	out := make([]string, 0, len(args))
	for _, a := range args {
		if _, ok := set[a]; ok {
			continue
		}
		out = append(out, a)
	}
	return out
}

func printRootHelp() {
	fmt.Fprintf(os.Stderr, `lanzou — Lanzou share resolve + account CLI

Usage:
  lanzou -i                              # interactive shell
  lanzou <share-url> [flags]             # parse share (legacy)
  lanzou parse <share-url> [flags]
  lanzou login --user U --pass P
  lanzou login --cookie-str "PHPSESSID=...; phpdisk_info=..."
  lanzou logout
  lanzou list [--folder ID]
  lanzou upload <file> [--folder ID]
  lanzou download <id|name> [--folder ID] [-o DIR] [-j N]
  lanzou mkdir <name> [--folder parentID]
  lanzou rm --file ID | --folder ID
  lanzou info --file ID | --folder ID
  lanzou passwd --file ID --pwd XXX

Default cookie file: ~/.lanzou/cookie
(override with --cookie / -c or env LANZOU_COOKIE)

Interactive (-i) commands:
  ls / ll                 list current folder
  cd <id|name|/|..>       enter folder
  pwd                     show current folder id
  download <id|name> [-j N] [-o DIR]
  info <id|name>
  upload <local-path>
  mkdir <name>
  rm <id|name>
  login / logout
  help / exit / quit

Share flags:
  -p, --pwd string         share password
      --down               download after resolve
  -o, --output-dir string  download directory (default ".")
  -f, --filename string    save filename
      --no-resolve         skip CDN direct resolve

Account flags:
  -u, --user string        account username/phone
      --pass string        account password
  -c, --cookie string      cookie file (default ~/.lanzou/cookie)
  -j, --jobs int           download concurrency (default 3)
`)
}

func runParse(args []string) {
	fs := pflag.NewFlagSet("parse", pflag.ExitOnError)
	pwd := fs.StringP("pwd", "p", "", "share password")
	down := fs.Bool("down", false, "download after resolve")
	outDir := fs.StringP("output-dir", "o", ".", "download directory")
	filename := fs.StringP("filename", "f", "", "save filename")
	noResolve := fs.Bool("no-resolve", false, "skip CDN direct resolve")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: lanzou parse <share-url> [flags]")
		fs.PrintDefaults()
		os.Exit(1)
	}
	shareURL := fs.Arg(0)

	c := lanzou.New()
	opt := lanzou.Options{Password: *pwd, ResolveDirect: !*noResolve}
	res, err := c.Parse(shareURL, opt)
	if err != nil {
		if errors.Is(err, lanzou.ErrPasswordRequired) {
			fmt.Fprintln(os.Stderr, "[error]", err)
			fmt.Fprintln(os.Stderr, "example: lanzou parse --pwd 5grc https://wwbss.lanzouu.com/ioHpR10k7d4b")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}

	fmt.Println("============================================================")
	fmt.Println("  fid:     ", res.FID)
	fmt.Println("  filename:", empty(res.Filename, "?"))
	fmt.Println("  password:", yn(res.PasswordProtected))
	fmt.Println("  cdn:     ", res.CDNDomain)
	fmt.Println("  telecom: ", res.Telecom)
	fmt.Println("  normal:  ", res.Normal)
	if res.Direct != "" {
		fmt.Println("  direct:  ", res.Direct)
	}
	fmt.Println("============================================================")

	if *down {
		u := res.Direct
		if u == "" {
			u = res.Telecom
		}
		path, err := c.Download(u, *outDir, first(*filename, res.Filename), "")
		if err != nil {
			fmt.Fprintln(os.Stderr, "[error] download:", err)
			os.Exit(1)
		}
		fmt.Println("[done] saved:", path)
	}
}

func accountFlags(fs *pflag.FlagSet) (user, pass, cookie *string) {
	user = fs.StringP("user", "u", envOr("LANZOU_USER", ""), "account username/phone")
	pass = fs.String("pass", envOr("LANZOU_PASS", ""), "account password")
	cookie = fs.StringP("cookie", "c", defaultCookiePath(), "cookie file path")
	return
}

func openAccount(user, pass, cookie string, needLogin bool) *lanzou.Account {
	ensureCookieDir(cookie)
	acc := lanzou.NewAccount(user, pass, lanzou.WithCookieFile(cookie))
	if needLogin {
		if user == "" || pass == "" {
			if !acc.Verification() {
				fmt.Fprintln(os.Stderr, "[error] not logged in; run: lanzou login --user U --pass P")
				os.Exit(2)
			}
			return acc
		}
		if err := acc.EnsureLogin(); err != nil {
			fmt.Fprintln(os.Stderr, "[error] login:", err)
			os.Exit(1)
		}
	}
	return acc
}

func runLogin(args []string) {
	fs := pflag.NewFlagSet("login", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	cookieStr := fs.String("cookie-str", "", "paste browser cookie string")
	_ = fs.Parse(args)
	ensureCookieDir(*cookie)

	if *cookieStr != "" {
		acc := lanzou.NewAccount("", "", lanzou.WithCookieFile(*cookie))
		acc.SetCookie(*cookieStr)
		if !acc.Verification() {
			fmt.Fprintln(os.Stderr, "[error] cookie invalid or expired")
			os.Exit(1)
		}
		fmt.Println("[ok] cookie imported ->", *cookie)
		return
	}
	if *user == "" || *pass == "" {
		fmt.Fprintln(os.Stderr, "usage: lanzou login --user U --pass P")
		fmt.Fprintln(os.Stderr, "   or: lanzou login --cookie-str 'PHPSESSID=...; phpdisk_info=...'")
		fs.PrintDefaults()
		os.Exit(1)
	}
	acc := lanzou.NewAccount(*user, *pass, lanzou.WithCookieFile(*cookie))
	if err := acc.Login(); err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	fmt.Println("[ok] logged in, cookie saved to", *cookie)
}

func runLogout(args []string) {
	fs := pflag.NewFlagSet("logout", pflag.ExitOnError)
	cookie := fs.StringP("cookie", "c", defaultCookiePath(), "cookie file path")
	_ = fs.Parse(args)
	if err := os.Remove(*cookie); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	fmt.Println("[ok] cookie removed:", *cookie)
}

func runList(args []string) {
	fs := pflag.NewFlagSet("list", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	folder := fs.String("folder", "-1", "folder id (-1 = root)")
	_ = fs.Parse(args)
	acc := openAccount(*user, *pass, *cookie, true)
	list, err := acc.List(*folder)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	printList(*folder, list)
}

func printList(folder string, list []lanzou.ListEntry) {
	fmt.Printf("folder=%s  entries=%d\n", folder, len(list))
	for _, e := range list {
		kind := "FILE"
		if e.Type == lanzou.EntryFolder {
			kind = "DIR "
		}
		extra := e.Size
		if e.Type == lanzou.EntryFolder {
			extra = e.Description
		}
		fmt.Printf("  [%s] id=%-12s  %s  %s\n", kind, e.ID, e.Name, extra)
	}
}

func runUpload(args []string) {
	fs := pflag.NewFlagSet("upload", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	folder := fs.String("folder", "-1", "target folder id")
	setPwd := fs.String("set-pwd", "", "set share password after upload")
	setDesc := fs.String("set-desc", "", "set description after upload")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: lanzou upload <local-file> [--folder ID]")
		os.Exit(1)
	}
	local := fs.Arg(0)
	acc := openAccount(*user, *pass, *cookie, true)
	// Hint when suffix is not on server whitelist (library will auto-zip).
	if ext := filepath.Ext(local); ext != "" && !lanzou.IsUploadAllowedExt(ext) {
		fmt.Printf("[upload] suffix %s not allowed by server, will pack as .zip\n", strings.ToLower(ext))
	}
	fmt.Println("[upload]", local, "-> folder", *folder)
	res, err := acc.Upload(local, *folder)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	fmt.Println("[ok] uploaded id=", res.FileID, "name=", res.Name)
	if *setPwd != "" && res.FileID != "" {
		if _, err := acc.SetFilePassword(res.FileID, *setPwd); err != nil {
			fmt.Fprintln(os.Stderr, "[warn] set password:", err)
		}
	}
	if *setDesc != "" && res.FileID != "" {
		if _, err := acc.SetFileDescribe(res.FileID, *setDesc); err != nil {
			fmt.Fprintln(os.Stderr, "[warn] set desc:", err)
		}
	}
	if res.FileID != "" {
		if share, pwd, err := acc.GetFileDownloadInfo(res.FileID); err == nil {
			fmt.Println("  share:", share)
			if pwd != "" {
				fmt.Println("  share_pwd:", pwd)
			}
		}
	}
}

func runMkdir(args []string) {
	fs := pflag.NewFlagSet("mkdir", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	parent := fs.String("folder", "-1", "parent folder id")
	desc := fs.String("desc", "", "folder description")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: lanzou mkdir <name> [--folder parentID]")
		os.Exit(1)
	}
	acc := openAccount(*user, *pass, *cookie, true)
	raw, err := acc.CreateFolder(fs.Arg(0), *parent, *desc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	fmt.Println("[ok] mkdir", fs.Arg(0))
	fmt.Println(raw)
}

func runDelete(args []string) {
	fs := pflag.NewFlagSet("rm", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	fileID := fs.String("file", "", "file id")
	folderID := fs.String("folder", "", "folder id")
	_ = fs.Parse(args)
	if *fileID == "" && *folderID == "" {
		fmt.Fprintln(os.Stderr, "usage: lanzou rm --file ID | --folder ID")
		os.Exit(1)
	}
	acc := openAccount(*user, *pass, *cookie, true)
	var raw string
	var err error
	if *fileID != "" {
		raw, err = acc.DeleteFile(*fileID)
	} else {
		raw, err = acc.DeleteFolder(*folderID)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	fmt.Println("[ok] deleted")
	fmt.Println(raw)
}

func runInfo(args []string) {
	fs := pflag.NewFlagSet("info", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	fileID := fs.String("file", "", "file id")
	folderID := fs.String("folder", "", "folder id")
	_ = fs.Parse(args)
	if *fileID == "" && *folderID == "" {
		fmt.Fprintln(os.Stderr, "usage: lanzou info --file ID | --folder ID")
		os.Exit(1)
	}
	acc := openAccount(*user, *pass, *cookie, true)
	if *fileID != "" {
		fi, err := acc.GetFileInfo(*fileID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[error]", err)
			os.Exit(1)
		}
		fmt.Println("file_id:  ", fi.ID)
		fmt.Println("share:    ", fi.ShareURL)
		fmt.Println("password: ", fi.Pwd)
		return
	}
	info, err := acc.GetFolderInfo(*folderID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	fmt.Println("name:     ", info.Name)
	fmt.Println("desc:     ", info.Description)
	fmt.Println("url:      ", info.URL)
	fmt.Println("password: ", info.Password)
	fmt.Println("files:    ", info.FileCount)
	fmt.Println("size:     ", info.FileSize)
}

func runPasswd(args []string) {
	fs := pflag.NewFlagSet("passwd", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	fileID := fs.String("file", "", "file id")
	folderID := fs.String("folder", "", "folder id")
	pwd := fs.StringP("pwd", "p", "", "new password")
	_ = fs.Parse(args)
	if *pwd == "" || (*fileID == "" && *folderID == "") {
		fmt.Fprintln(os.Stderr, "usage: lanzou passwd --file ID --pwd XXX | --folder ID --pwd XXX")
		os.Exit(1)
	}
	acc := openAccount(*user, *pass, *cookie, true)
	var raw string
	var err error
	if *fileID != "" {
		raw, err = acc.SetFilePassword(*fileID, *pwd)
	} else {
		raw, err = acc.SetFolderPassword(*folderID, *pwd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	fmt.Println("[ok] password updated")
	fmt.Println(raw)
}

func runDownload(args []string) {
	fs := pflag.NewFlagSet("download", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	folder := fs.String("folder", "-1", "current folder id for name lookup")
	outDir := fs.StringP("output-dir", "o", ".", "output directory")
	jobs := fs.IntP("jobs", "j", 3, "concurrency")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: lanzou download <id|name> [--folder ID] [-o DIR] [-j N]")
		os.Exit(1)
	}
	target := fs.Arg(0)
	acc := openAccount(*user, *pass, *cookie, true)
	if err := downloadTarget(acc, *folder, target, *outDir, *jobs); err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
}

// ---------- download helpers ----------

type dlJob struct {
	fileID   string
	name     string
	destDir  string
	shareURL string
	pwd      string
}

func downloadTarget(acc *lanzou.Account, curFolder, target, outDir string, jobs int) error {
	if jobs < 1 {
		jobs = 3
	}
	list, err := acc.List(curFolder)
	if err != nil {
		return err
	}
	e, ok := resolveEntry(list, target)
	if !ok {
		// maybe raw id not in current listing: treat as file first
		if isDigits(target) {
			return downloadFileByID(acc, target, "", outDir)
		}
		return fmt.Errorf("not found in folder %s: %s", curFolder, target)
	}
	if e.Type == lanzou.EntryFile {
		return downloadFileByID(acc, e.ID, e.Name, outDir)
	}
	// folder recursive
	dest := filepath.Join(outDir, sanitizeName(e.Name))
	fmt.Printf("[download] folder %s (%s) -> %s  jobs=%d\n", e.Name, e.ID, dest, jobs)
	return downloadFolderRecursive(acc, e.ID, dest, jobs)
}

func downloadFileByID(acc *lanzou.Account, fileID, name, outDir string) error {
	share, pwd, err := acc.GetFileDownloadInfo(fileID)
	if err != nil {
		return err
	}
	if share == "" {
		return fmt.Errorf("empty share url for file %s", fileID)
	}
	fmt.Printf("[download] file id=%s name=%s\n", fileID, name)
	return downloadShare(share, pwd, outDir, name)
}

func downloadFolderRecursive(acc *lanzou.Account, folderID, destDir string, jobs int) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	// collect all files first
	var files []dlJob
	var walk func(fid, dir string) error
	walk = func(fid, dir string) error {
		list, err := acc.List(fid)
		if err != nil {
			return err
		}
		for _, e := range list {
			if e.Type == lanzou.EntryFolder {
				sub := filepath.Join(dir, sanitizeName(e.Name))
				if err := os.MkdirAll(sub, 0o755); err != nil {
					return err
				}
				if err := walk(e.ID, sub); err != nil {
					return err
				}
				continue
			}
			share, pwd, err := acc.GetFileDownloadInfo(e.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[warn] skip %s: %v\n", e.Name, err)
				continue
			}
			files = append(files, dlJob{fileID: e.ID, name: e.Name, destDir: dir, shareURL: share, pwd: pwd})
		}
		return nil
	}
	if err := walk(folderID, destDir); err != nil {
		return err
	}
	fmt.Printf("[download] %d files queued\n", len(files))
	return downloadJobs(files, jobs)
}

func downloadJobs(jobs []dlJob, concurrency int) error {
	if len(jobs) == 0 {
		return nil
	}
	ch := make(chan dlJob)
	var wg sync.WaitGroup
	var fail atomic.Int32
	var done atomic.Int32
	total := len(jobs)

	worker := func() {
		defer wg.Done()
		for j := range ch {
			err := downloadShare(j.shareURL, j.pwd, j.destDir, j.name)
			n := done.Add(1)
			if err != nil {
				fail.Add(1)
				fmt.Fprintf(os.Stderr, "[fail %d/%d] %s: %v\n", n, total, j.name, err)
			} else {
				fmt.Printf("[ok %d/%d] %s\n", n, total, j.name)
			}
		}
	}
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go worker()
	}
	for _, j := range jobs {
		ch <- j
	}
	close(ch)
	wg.Wait()
	if fail.Load() > 0 {
		return fmt.Errorf("%d/%d downloads failed", fail.Load(), total)
	}
	return nil
}

func downloadShare(shareURL, pwd, outDir, filename string) error {
	c := lanzou.New()
	res, err := c.Parse(shareURL, lanzou.Options{Password: pwd, ResolveDirect: true})
	if err != nil {
		return err
	}
	u := res.Direct
	if u == "" {
		u = res.Telecom
	}
	name := filename
	if name == "" {
		name = res.Filename
	}
	_, err = c.Download(u, outDir, name, "")
	return err
}

func resolveEntry(list []lanzou.ListEntry, target string) (lanzou.ListEntry, bool) {
	// exact id
	for _, e := range list {
		if e.ID == target {
			return e, true
		}
	}
	// exact name
	for _, e := range list {
		if e.Name == target {
			return e, true
		}
	}
	// case-insensitive name
	lt := strings.ToLower(target)
	for _, e := range list {
		if strings.ToLower(e.Name) == lt {
			return e, true
		}
	}
	return lanzou.ListEntry{}, false
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "unnamed"
	}
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return repl.Replace(name)
}

func isDigits(s string) bool {
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

// ---------- interactive shell ----------

type shell struct {
	acc     *lanzou.Account
	folder  string
	stack   []string // parent ids for cd ..
	cookie  string
	outDir  string
	jobs    int
	user    string
	pass    string
}

func runInteractive(args []string) {
	fs := pflag.NewFlagSet("interactive", pflag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	user, pass, cookie := accountFlags(fs)
	outDir := fs.StringP("output-dir", "o", ".", "default download directory")
	jobs := fs.IntP("jobs", "j", 3, "download concurrency")
	_ = fs.Parse(args)

	ensureCookieDir(*cookie)
	acc := lanzou.NewAccount(*user, *pass, lanzou.WithCookieFile(*cookie))
	if *user != "" && *pass != "" {
		if err := acc.EnsureLogin(); err != nil {
			fmt.Fprintln(os.Stderr, "[warn] login:", err)
		}
	} else if !acc.Verification() {
		fmt.Fprintln(os.Stderr, "[warn] not logged in. Use: login --user U --pass P")
	}

	sh := &shell{
		acc:    acc,
		folder: "-1",
		stack:  nil,
		cookie: *cookie,
		outDir: *outDir,
		jobs:   *jobs,
		user:   *user,
		pass:   *pass,
	}

	fmt.Println("lanzou interactive shell. type 'help', 'exit' to quit.")
	in := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("lanzou:%s> ", sh.folder)
		if !in.Scan() {
			fmt.Println()
			if err := in.Err(); err != nil {
				fmt.Fprintln(os.Stderr, "[error]", err)
			}
			return
		}
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		if err := sh.exec(line); err != nil {
			if errors.Is(err, errExit) {
				return
			}
			fmt.Fprintln(os.Stderr, "[error]", err)
		}
	}
}

var errExit = errors.New("exit")

func (sh *shell) exec(line string) error {
	parts := splitArgs(line)
	if len(parts) == 0 {
		return nil
	}
	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "help", "?":
		fmt.Println("ls | cd <id|name|/|..> | pwd | download <id|name> [-j N] [-o DIR]")
		fmt.Println("info <id|name> | upload <path> | mkdir <name> | rm <id|name>")
		fmt.Println("login [--user U --pass P] | logout | exit")
		return nil
	case "exit", "quit", "q":
		return errExit
	case "pwd":
		fmt.Println(sh.folder)
		return nil
	case "ls", "ll", "list":
		list, err := sh.acc.List(sh.folder)
		if err != nil {
			return err
		}
		printList(sh.folder, list)
		return nil
	case "cd":
		if len(args) < 1 {
			return fmt.Errorf("usage: cd <id|name|/|..>")
		}
		return sh.cd(args[0])
	case "download", "dl", "get":
		return sh.cmdDownload(args)
	case "info":
		if len(args) < 1 {
			return fmt.Errorf("usage: info <id|name>")
		}
		return sh.cmdInfo(args[0])
	case "upload", "up":
		if len(args) < 1 {
			return fmt.Errorf("usage: upload <local-path>")
		}
		res, err := sh.acc.Upload(args[0], sh.folder)
		if err != nil {
			return err
		}
		fmt.Println("[ok] uploaded", res.FileID, res.Name)
		return nil
	case "mkdir":
		if len(args) < 1 {
			return fmt.Errorf("usage: mkdir <name>")
		}
		_, err := sh.acc.CreateFolder(args[0], sh.folder, "")
		if err != nil {
			return err
		}
		fmt.Println("[ok] mkdir", args[0])
		return nil
	case "rm", "delete":
		if len(args) < 1 {
			return fmt.Errorf("usage: rm <id|name>")
		}
		return sh.cmdRm(args[0])
	case "login":
		return sh.cmdLogin(args)
	case "logout":
		_ = os.Remove(sh.cookie)
		sh.acc.SetCookie("")
		fmt.Println("[ok] logged out")
		return nil
	default:
		return fmt.Errorf("unknown command: %s (help for list)", cmd)
	}
}

func (sh *shell) cd(target string) error {
	if target == "/" || target == "~" || target == "root" {
		sh.folder = "-1"
		sh.stack = nil
		return nil
	}
	if target == ".." {
		if len(sh.stack) == 0 {
			sh.folder = "-1"
			return nil
		}
		sh.folder = sh.stack[len(sh.stack)-1]
		sh.stack = sh.stack[:len(sh.stack)-1]
		return nil
	}
	list, err := sh.acc.List(sh.folder)
	if err != nil {
		return err
	}
	e, ok := resolveEntry(list, target)
	if !ok {
		// allow raw folder id
		if isDigits(target) {
			sh.stack = append(sh.stack, sh.folder)
			sh.folder = target
			return nil
		}
		return fmt.Errorf("folder not found: %s", target)
	}
	if e.Type != lanzou.EntryFolder {
		return fmt.Errorf("%s is a file, not a folder", e.Name)
	}
	sh.stack = append(sh.stack, sh.folder)
	sh.folder = e.ID
	fmt.Println("cd ->", e.Name, "("+e.ID+")")
	return nil
}

func (sh *shell) cmdDownload(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: download <id|name> [-j N] [-o DIR]")
	}
	target := args[0]
	jobs := sh.jobs
	outDir := sh.outDir
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-j", "--jobs":
			if i+1 < len(args) {
				i++
				if n, err := strconv.Atoi(args[i]); err == nil && n > 0 {
					jobs = n
				}
			}
		case "-o", "--output-dir":
			if i+1 < len(args) {
				i++
				outDir = args[i]
			}
		}
	}
	return downloadTarget(sh.acc, sh.folder, target, outDir, jobs)
}

func (sh *shell) cmdInfo(target string) error {
	list, err := sh.acc.List(sh.folder)
	if err != nil {
		return err
	}
	e, ok := resolveEntry(list, target)
	if !ok {
		if isDigits(target) {
			// try as file id
			fi, err := sh.acc.GetFileInfo(target)
			if err != nil {
				return err
			}
			fmt.Println("file_id: ", fi.ID)
			fmt.Println("share:   ", fi.ShareURL)
			fmt.Println("password:", fi.Pwd)
			return nil
		}
		return fmt.Errorf("not found: %s", target)
	}
	if e.Type == lanzou.EntryFile {
		fi, err := sh.acc.GetFileInfo(e.ID)
		if err != nil {
			return err
		}
		fmt.Println("type:    FILE")
		fmt.Println("id:      ", e.ID)
		fmt.Println("name:    ", e.Name)
		fmt.Println("size:    ", e.Size)
		fmt.Println("share:   ", fi.ShareURL)
		fmt.Println("password:", fi.Pwd)
		return nil
	}
	info, err := sh.acc.GetFolderInfo(e.ID)
	if err != nil {
		return err
	}
	fmt.Println("type:    DIR")
	fmt.Println("id:      ", e.ID)
	fmt.Println("name:    ", e.Name)
	fmt.Println("url:     ", info.URL)
	fmt.Println("password:", info.Password)
	fmt.Println("files:   ", info.FileCount)
	fmt.Println("size:    ", info.FileSize)
	return nil
}

func (sh *shell) cmdRm(target string) error {
	list, err := sh.acc.List(sh.folder)
	if err != nil {
		return err
	}
	e, ok := resolveEntry(list, target)
	if !ok {
		return fmt.Errorf("not found: %s", target)
	}
	if e.Type == lanzou.EntryFile {
		_, err = sh.acc.DeleteFile(e.ID)
	} else {
		_, err = sh.acc.DeleteFolder(e.ID)
	}
	if err != nil {
		return err
	}
	fmt.Println("[ok] deleted", e.Name, e.ID)
	return nil
}

func (sh *shell) cmdLogin(args []string) error {
	user := sh.user
	pass := sh.pass
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user", "-u":
			if i+1 < len(args) {
				i++
				user = args[i]
			}
		case "--pass":
			if i+1 < len(args) {
				i++
				pass = args[i]
			}
		case "--cookie-str":
			if i+1 < len(args) {
				i++
				sh.acc.SetCookie(args[i])
				if !sh.acc.Verification() {
					return fmt.Errorf("cookie invalid")
				}
				fmt.Println("[ok] cookie imported")
				return nil
			}
		}
	}
	if user == "" || pass == "" {
		return fmt.Errorf("usage: login --user U --pass P")
	}
	sh.user, sh.pass = user, pass
	sh.acc = lanzou.NewAccount(user, pass, lanzou.WithCookieFile(sh.cookie))
	if err := sh.acc.Login(); err != nil {
		return err
	}
	fmt.Println("[ok] logged in")
	return nil
}

// splitArgs: simple whitespace split with "quoted" support
func splitArgs(line string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQ = !inQ
		case (c == ' ' || c == '\t') && !inQ:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func empty(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
