package main

import (
	"archive/zip"
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/WangTianYou537/gLanz"
	"github.com/spf13/pflag"
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
	if hasFlag(os.Args[1:], "-V") || hasFlag(os.Args[1:], "--version") || hasFlag(os.Args[1:], "version") {
		fmt.Println("lanzou", lanzou.Version)
		return
	}

	if len(os.Args) < 2 {
		printRootHelp()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "parse", "get", "p":
		runParse(os.Args[2:])
	case "login", "signin", "auth":
		runLogin(os.Args[2:])
	case "logout", "signout":
		runLogout(os.Args[2:])
	case "list", "ls", "ll", "dir":
		runList(os.Args[2:])
	case "upload", "up", "put":
		runUpload(os.Args[2:])
	case "mkdir", "md":
		runMkdir(os.Args[2:])
	case "rm", "delete", "del", "remove", "unlink":
		runDelete(os.Args[2:])
	case "info", "show", "stat":
		runInfo(os.Args[2:])
	case "passwd", "password", "pwdset":
		runPasswd(os.Args[2:])
	case "download", "dl", "down", "fetch":
		runDownload(os.Args[2:])
	case "config", "conf", "cfg", "settings":
		runConfig(os.Args[2:])
	case "interactive", "i", "shell", "sh", "repl":
		runInteractive(os.Args[2:])
	case "version", "ver":
		fmt.Println("lanzou", lanzou.Version)
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
  lanzou --version / -V / version
  lanzou <share-url> [flags]             # parse share (legacy)
  lanzou parse|get|p <share-url> [flags]
  lanzou login|signin|auth --user U --pass P
  lanzou login --cookie-str "PHPSESSID=...; phpdisk_info=..."
  lanzou logout|signout
  lanzou list|ls|ll|dir [--folder ID]
  lanzou upload|up|put <file> [--folder ID]
  lanzou download|dl|down|fetch <id|name> [--folder ID] [-o DIR] [-j N]
  lanzou mkdir|md <name> [--folder parentID]
  lanzou rm|delete|del|remove --file ID | --folder ID
  lanzou info|show|stat --file ID | --folder ID
  lanzou passwd|password|pwdset --file ID --pwd XXX
  lanzou config|conf|cfg [list|get KEY|set KEY VALUE|path|reset]

Default cookie file: ~/.lanzou/cookie
Default config file: ~/.lanzou/config.json
(override with --cookie / -c or env LANZOU_COOKIE / LANZOU_CONFIG)

Config keys:
  suffix_auto_convert  bool   auto convert blocked suffix (default true)
  suffix_name          string target ext, no dot (default zip)
  suffix_mode          zip|rename  compress vs rename-only
  split_enable         bool   split large files (default true)
  split_size_mb        int    chunk size MB 1..100 (default 90)
  split_name_format    string e.g. {name}_part{index:03d}.{suffix}
  split_note           bool   write part meta to file desc (default true)
  list_unescape        bool   group split parts in ls (default true)

Interactive (-i) commands:
  ls|ll|list|dir          list current folder
  cd <name|id|/abs/path|..|.>       enter folder
  pwd                     show current path (/ or /folder/...)
  download|dl|down|fetch <id|name> [-j N] [-o DIR]
  info|show|stat <id|name>
  upload|up|put <local-path>
  mkdir|md <name>
  rm|delete|del|remove <id|name>
  login|signin / logout|signout
  config|conf|cfg ...
  help / exit|quit|q

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
	raw := fs.Bool("raw", false, "disable list_unescape grouping")
	_ = fs.Parse(args)
	acc := openAccount(*user, *pass, *cookie, true)
	list, err := acc.List(*folder)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	printList(acc, *folder, list, !*raw)
}

func printList(acc *lanzou.Account, folder string, list []lanzou.ListEntry, unescape bool) {
	cfg := lanzou.GetConfig()
	doUnescape := unescape && cfg.ListUnescape
	var notes map[string]string
	if doUnescape {
		// only fetch notes when there might be parts (best-effort)
		notes = acc.FetchNotes(list)
	}
	rows := lanzou.UnescapeList(list, notes, doUnescape)
	fmt.Printf("folder=%s  entries=%d", folder, len(list))
	if doUnescape && len(rows) != len(list) {
		fmt.Printf("  display=%d", len(rows))
	}
	fmt.Println()
	for _, e := range rows {
		kind := e.Kind
		if kind == "DIR" {
			kind = "DIR "
		} else if kind == "FILE" {
			kind = "FILE"
		} else if kind == "SPLIT" {
			kind = "SPLIT"
		}
		extra := e.Extra
		if extra == "" {
			extra = e.Size
		}
		fmt.Printf("  [%s] id=%-12s  %s  %s\n", kind, e.ID, e.Name, extra)
		if e.Kind == "SPLIT" {
			for _, p := range e.Parts {
				fmt.Printf("           └─ id=%-12s  %s  %s\n", p.ID, p.Name, p.Size)
			}
		}
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
	cfg := lanzou.GetConfig()
	if ext := filepath.Ext(local); ext != "" && !lanzou.IsUploadAllowedExt(ext) {
		if cfg.SuffixAutoConvert {
			fmt.Printf("[upload] suffix %s not allowed; convert mode=%s -> .%s\n",
				strings.ToLower(ext), cfg.SuffixMode, cfg.SuffixName)
		} else {
			fmt.Printf("[upload] suffix %s not allowed (suffix_auto_convert=false)\n", strings.ToLower(ext))
		}
	}
	if st, err := os.Stat(local); err == nil {
		limit := int64(cfg.SplitSizeMB) * 1024 * 1024
		if cfg.SplitEnable && st.Size() > limit {
			fmt.Printf("[upload] size %d > %dMB, will split (format=%s)\n",
				st.Size(), cfg.SplitSizeMB, cfg.SplitNameFormat)
		}
	}
	fmt.Println("[upload]", local, "-> folder", *folder)
	res, err := acc.Upload(local, *folder)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	if len(res.Parts) > 0 {
		fmt.Printf("[ok] uploaded %d parts  group=%s  orig=%s\n", len(res.Parts), res.GroupID, res.OrigName)
		for _, p := range res.Parts {
			fmt.Printf("  part %d/%d id=%s name=%s size=%d\n", p.Index, p.Total, p.FileID, p.Name, p.Size)
		}
	} else {
		fmt.Println("[ok] uploaded id=", res.FileID, "name=", res.Name)
	}
	if *setPwd != "" && res.FileID != "" {
		if _, err := acc.SetFilePassword(res.FileID, *setPwd); err != nil {
			fmt.Fprintln(os.Stderr, "[warn] set password:", err)
		}
	}
	// set-desc only for non-split (split uses structured notes)
	if *setDesc != "" && res.FileID != "" && len(res.Parts) == 0 {
		if _, err := acc.SetFileDescribe(res.FileID, *setDesc); err != nil {
			fmt.Fprintln(os.Stderr, "[warn] set desc:", err)
		}
	}
	if res.FileID != "" && len(res.Parts) == 0 {
		if share, pwd, err := acc.GetFileDownloadInfo(res.FileID); err == nil {
			fmt.Println("  share:", share)
			if pwd != "" {
				fmt.Println("  share_pwd:", pwd)
			}
		}
	}
}

func runConfig(args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}
	sub := args[0]
	switch sub {
	case "list", "show", "ls":
		cfg := lanzou.GetConfig()
		fmt.Println("config:", lanzou.ConfigPathUsed())
		for _, kv := range lanzou.ConfigKeys() {
			v, _ := lanzou.GetConfigValue(cfg, kv[0])
			fmt.Printf("  %-20s = %-10s  # %s\n", kv[0], v, kv[1])
		}
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: lanzou config get <key>")
			os.Exit(1)
		}
		cfg := lanzou.GetConfig()
		v, err := lanzou.GetConfigValue(cfg, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "[error]", err)
			os.Exit(1)
		}
		fmt.Println(v)
	case "set":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: lanzou config set <key> <value>")
			os.Exit(1)
		}
		cfg := lanzou.GetConfig()
		cfg, err := lanzou.SetConfigValue(cfg, args[1], args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "[error]", err)
			os.Exit(1)
		}
		if err := lanzou.SaveConfig("", cfg); err != nil {
			fmt.Fprintln(os.Stderr, "[error] save:", err)
			os.Exit(1)
		}
		v, _ := lanzou.GetConfigValue(cfg, args[1])
		fmt.Printf("[ok] %s = %s\n  saved: %s\n", args[1], v, lanzou.ConfigPathUsed())
	case "path":
		fmt.Println(lanzou.ConfigPathUsed())
	case "reset":
		cfg := lanzou.DefaultConfig()
		if err := lanzou.SaveConfig("", cfg); err != nil {
			fmt.Fprintln(os.Stderr, "[error]", err)
			os.Exit(1)
		}
		fmt.Println("[ok] reset to defaults ->", lanzou.ConfigPathUsed())
	case "help", "-h", "--help":
		fmt.Println("lanzou config list")
		fmt.Println("lanzou config get <key>")
		fmt.Println("lanzou config set <key> <value>")
		fmt.Println("lanzou config path")
		fmt.Println("lanzou config reset")
		fmt.Println()
		for _, kv := range lanzou.ConfigKeys() {
			fmt.Printf("  %-20s  %s\n", kv[0], kv[1])
		}
	default:
		// allow: lanzou config suffix_auto_convert true
		if len(args) == 2 {
			cfg := lanzou.GetConfig()
			cfg, err := lanzou.SetConfigValue(cfg, args[0], args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "[error]", err)
				os.Exit(1)
			}
			if err := lanzou.SaveConfig("", cfg); err != nil {
				fmt.Fprintln(os.Stderr, "[error] save:", err)
				os.Exit(1)
			}
			v, _ := lanzou.GetConfigValue(cfg, args[0])
			fmt.Printf("[ok] %s = %s\n", args[0], v)
			return
		}
		fmt.Fprintf(os.Stderr, "unknown config subcommand: %s\n", sub)
		os.Exit(1)
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
	folderCtx := fs.String("in", "-1", "folder to resolve name (default root)")
	_ = fs.Parse(args)
	acc := openAccount(*user, *pass, *cookie, true)

	// Positional: lanzou rm <id|name>  (resolve via list + notes)
	if fs.NArg() >= 1 && *fileID == "" && *folderID == "" {
		target := fs.Arg(0)
		if err := deleteTarget(acc, *folderCtx, target); err != nil {
			fmt.Fprintln(os.Stderr, "[error]", err)
			os.Exit(1)
		}
		return
	}
	if *fileID == "" && *folderID == "" {
		fmt.Fprintln(os.Stderr, "usage: lanzou rm <id|name> [--in folderID]")
		fmt.Fprintln(os.Stderr, "   or: lanzou rm --file ID | --folder ID")
		os.Exit(1)
	}
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

// deleteTarget deletes a file/folder by id, remote name, or note original name.
// Convert files delete one; split groups delete all parts.
func deleteTarget(acc *lanzou.Account, curFolder, target string) error {
	list, err := acc.List(curFolder)
	if err != nil {
		return err
	}
	notes := acc.FetchNotes(list)

	// 1) note-based: convert or whole split group
	if r, ok := resolveByNotes(list, notes, target); ok {
		if r.Kind == "split" {
			fmt.Printf("[rm] split %s  parts=%d\n", r.OrigName, len(r.Parts))
			var failed int
			for _, p := range r.Parts {
				if _, err := acc.DeleteFile(p.FileID); err != nil {
					failed++
					fmt.Fprintf(os.Stderr, "[warn] delete part %d id=%s: %v\n", p.Index, p.FileID, err)
				} else {
					fmt.Printf("[ok] deleted part %d/%d id=%s %s\n", p.Index, p.Total, p.FileID, p.Name)
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d/%d parts failed to delete", failed, len(r.Parts))
			}
			return nil
		}
		if _, err := acc.DeleteFile(r.FileID); err != nil {
			return err
		}
		fmt.Printf("[ok] deleted %s (id=%s remote via convert note)\n", r.OrigName, r.FileID)
		return nil
	}

	// 2) normal list resolve
	e, ok := resolveEntry(list, target)
	if !ok {
		if isDigits(target) {
			if _, err := acc.DeleteFile(target); err != nil {
				// try as folder
				if _, err2 := acc.DeleteFolder(target); err2 != nil {
					return err
				}
				fmt.Println("[ok] deleted folder", target)
				return nil
			}
			fmt.Println("[ok] deleted file", target)
			return nil
		}
		return fmt.Errorf("not found in folder %s: %s", curFolder, target)
	}
	if e.Type == lanzou.EntryFile {
		// if this file is part of a split, delete whole group
		if note := notes[e.ID]; note != "" {
			if pm, ok := lanzou.ParsePartNote(note); ok {
				name := pm.Name
				if name == "" {
					name = pm.GroupID
				}
				if r, ok := resolveByNotes(list, notes, name); ok && r.Kind == "split" {
					return deleteTarget(acc, curFolder, name)
				}
			}
		}
		if _, err := acc.DeleteFile(e.ID); err != nil {
			return err
		}
		fmt.Printf("[ok] deleted file %s (%s)\n", e.Name, e.ID)
		return nil
	}
	if _, err := acc.DeleteFolder(e.ID); err != nil {
		return err
	}
	fmt.Printf("[ok] deleted folder %s (%s)\n", e.Name, e.ID)
	return nil
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
	// Prefer note-based resolution (convert / split) so original names work.
	notes := acc.FetchNotes(list)
	if resolved, ok := resolveByNotes(list, notes, target); ok {
		return downloadResolved(acc, resolved, outDir, jobs)
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
		// still check note for better local name
		if note := notes[e.ID]; note != "" {
			if cm, ok := lanzou.ParseConvertNote(note); ok && cm.Name != "" {
				return downloadFileByID(acc, e.ID, cm.Name, outDir)
			}
		}
		return downloadFileByID(acc, e.ID, e.Name, outDir)
	}
	// folder recursive
	dest := filepath.Join(outDir, sanitizeName(e.Name))
	fmt.Printf("[download] folder %s (%s) -> %s  jobs=%d\n", e.Name, e.ID, dest, jobs)
	return downloadFolderRecursive(acc, e.ID, dest, jobs)
}

// resolvedDownload is either a single converted file or a split group.
type resolvedDownload struct {
	Kind     string // "file" | "split"
	OrigName string
	// file
	FileID   string
	FileName string // remote name
	// split
	Parts []resolvedPart
}

type resolvedPart struct {
	FileID string
	Name   string
	Index  int
	Total  int
	Size   int64
}

func resolveByNotes(list []lanzou.ListEntry, notes map[string]string, target string) (resolvedDownload, bool) {
	lt := strings.ToLower(strings.TrimSpace(target))
	if lt == "" {
		return resolvedDownload{}, false
	}

	// 1) convert notes: exact original name match
	for _, e := range list {
		if e.Type != lanzou.EntryFile {
			continue
		}
		note := notes[e.ID]
		if note == "" {
			note = e.Description
		}
		cm, ok := lanzou.ParseConvertNote(note)
		if !ok {
			continue
		}
		if strings.EqualFold(cm.Name, target) {
			saveAs := cm.Name
			if saveAs == "" {
				saveAs = e.Name
			}
			return resolvedDownload{
				Kind:     "file",
				OrigName: cm.Name,
				FileID:   e.ID,
				FileName: saveAs,
			}, true
		}
	}

	// 2) split notes: group by original name
	type gparts struct {
		meta  lanzou.PartMeta
		parts []resolvedPart
	}
	groups := map[string]*gparts{} // key = lower(name) or group id
	for _, e := range list {
		if e.Type != lanzou.EntryFile {
			continue
		}
		note := notes[e.ID]
		if note == "" {
			note = e.Description
		}
		pm, ok := lanzou.ParsePartNote(note)
		if !ok {
			continue
		}
		key := strings.ToLower(pm.Name)
		if key == "" {
			key = pm.GroupID
		}
		g, exists := groups[key]
		if !exists {
			g = &gparts{meta: pm}
			groups[key] = g
		}
		if g.meta.Name == "" && pm.Name != "" {
			g.meta.Name = pm.Name
		}
		if pm.Total > g.meta.Total {
			g.meta.Total = pm.Total
		}
		g.parts = append(g.parts, resolvedPart{
			FileID: e.ID,
			Name:   e.Name,
			Index:  pm.Index,
			Total:  pm.Total,
			Size:   pm.Size,
		})
	}
	if g, ok := groups[lt]; ok && len(g.parts) > 0 {
		// also allow match by group id
		sort.SliceStable(g.parts, func(i, j int) bool { return g.parts[i].Index < g.parts[j].Index })
		name := g.meta.Name
		if name == "" {
			name = target
		}
		return resolvedDownload{Kind: "split", OrigName: name, Parts: g.parts}, true
	}
	// match group id exactly
	for _, g := range groups {
		if g.meta.GroupID == target && len(g.parts) > 0 {
			sort.SliceStable(g.parts, func(i, j int) bool { return g.parts[i].Index < g.parts[j].Index })
			name := g.meta.Name
			if name == "" {
				name = target
			}
			return resolvedDownload{Kind: "split", OrigName: name, Parts: g.parts}, true
		}
	}
	return resolvedDownload{}, false
}

func downloadResolved(acc *lanzou.Account, r resolvedDownload, outDir string, jobs int) error {
	if r.Kind == "split" {
		return downloadSplitGroup(acc, r, outDir, jobs)
	}
	return downloadFileByID(acc, r.FileID, r.FileName, outDir)
}

func downloadSplitGroup(acc *lanzou.Account, r resolvedDownload, outDir string, jobs int) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	// download each part to temp files, then concat
	type partFile struct {
		index int
		path  string
	}
	var (
		mu    sync.Mutex
		files []partFile
		fail  atomic.Int32
		done  atomic.Int32
	)
	total := len(r.Parts)
	fmt.Printf("[download] split %s  parts=%d  jobs=%d\n", r.OrigName, total, jobs)

	ch := make(chan resolvedPart)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for p := range ch {
			tmp, err := os.CreateTemp(outDir, fmt.Sprintf("part-%03d-*.bin", p.Index))
			if err != nil {
				fail.Add(1)
				fmt.Fprintf(os.Stderr, "[fail] part %d: %v\n", p.Index, err)
				continue
			}
			tmpPath := tmp.Name()
			tmp.Close()
			// download with remote name first into outDir, then move — simpler: use downloadShare with basename of tmp
			share, pwd, err := acc.GetFileDownloadInfo(p.FileID)
			if err != nil {
				os.Remove(tmpPath)
				fail.Add(1)
				fmt.Fprintf(os.Stderr, "[fail] part %d info: %v\n", p.Index, err)
				continue
			}
			// downloadShare writes filename into outDir; use unique name then rename
			partName := fmt.Sprintf(".%s.part%03d.download", sanitizeName(r.OrigName), p.Index)
			err = downloadShare(share, pwd, outDir, partName)
			n := done.Add(1)
			if err != nil {
				os.Remove(tmpPath)
				os.Remove(filepath.Join(outDir, partName))
				fail.Add(1)
				fmt.Fprintf(os.Stderr, "[fail %d/%d] part %d: %v\n", n, total, p.Index, err)
				continue
			}
			downloaded := filepath.Join(outDir, partName)
			// If suffix_mode=zip, the downloaded file is a zip containing the raw chunk.
			rawPath, cleanup, err := extractPartPayload(downloaded, tmpPath)
			if err != nil {
				os.Remove(downloaded)
				fail.Add(1)
				fmt.Fprintf(os.Stderr, "[fail %d/%d] part %d extract: %v\n", n, total, p.Index, err)
				continue
			}
			_ = cleanup
			os.Remove(downloaded)
			mu.Lock()
			files = append(files, partFile{index: p.Index, path: rawPath})
			mu.Unlock()
			fmt.Printf("[ok %d/%d] part %d\n", n, total, p.Index)
		}
	}
	if jobs < 1 {
		jobs = 3
	}
	wg.Add(jobs)
	for i := 0; i < jobs; i++ {
		go worker()
	}
	for _, p := range r.Parts {
		ch <- p
	}
	close(ch)
	wg.Wait()
	if fail.Load() > 0 {
		for _, f := range files {
			os.Remove(f.path)
		}
		return fmt.Errorf("%d/%d split parts failed", fail.Load(), total)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].index < files[j].index })
	outPath := filepath.Join(outDir, sanitizeName(r.OrigName))
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	for _, f := range files {
		in, err := os.Open(f.path)
		if err != nil {
			out.Close()
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			in.Close()
			out.Close()
			return err
		}
		in.Close()
		os.Remove(f.path)
	}
	if err := out.Close(); err != nil {
		return err
	}
	fmt.Println("[done] merged:", outPath)
	return nil
}

// extractPartPayload returns raw part bytes path.
// If downloaded is a zip with a single entry (suffix_mode=zip), extract it;
// otherwise treat the file itself as the raw payload (rename mode).
func extractPartPayload(downloaded, preferPath string) (rawPath string, cleanup func(), err error) {
	cleanup = func() {}
	// try zip
	zr, err := zip.OpenReader(downloaded)
	if err == nil {
		defer zr.Close()
		if len(zr.File) >= 1 {
			// use first entry
			rc, err := zr.File[0].Open()
			if err != nil {
				return "", cleanup, err
			}
			defer rc.Close()
			out, err := os.Create(preferPath)
			if err != nil {
				return "", cleanup, err
			}
			if _, err := io.Copy(out, rc); err != nil {
				out.Close()
				os.Remove(preferPath)
				return "", cleanup, err
			}
			if err := out.Close(); err != nil {
				os.Remove(preferPath)
				return "", cleanup, err
			}
			cleanup = func() { _ = os.Remove(preferPath) }
			return preferPath, cleanup, nil
		}
	}
	// not a zip / empty: move/copy downloaded to preferPath
	if err := os.Rename(downloaded, preferPath); err != nil {
		// cross-device fallback
		in, err := os.Open(downloaded)
		if err != nil {
			return "", cleanup, err
		}
		out, err := os.Create(preferPath)
		if err != nil {
			in.Close()
			return "", cleanup, err
		}
		if _, err := io.Copy(out, in); err != nil {
			in.Close()
			out.Close()
			os.Remove(preferPath)
			return "", cleanup, err
		}
		in.Close()
		out.Close()
		os.Remove(downloaded)
	}
	cleanup = func() { _ = os.Remove(preferPath) }
	return preferPath, cleanup, nil
}

func downloadFileByID(acc *lanzou.Account, fileID, name, outDir string) error {
	share, pwd, err := acc.GetFileDownloadInfo(fileID)
	if err != nil {
		return err
	}
	if share == "" {
		return fmt.Errorf("empty share url for file %s", fileID)
	}
	// If local name still looks converted, try note for original.
	saveName := name
	if desc, err := acc.GetFileDescribe(fileID); err == nil {
		if cm, ok := lanzou.ParseConvertNote(desc); ok && cm.Name != "" {
			saveName = cm.Name
		}
	}
	fmt.Printf("[download] file id=%s name=%s\n", fileID, saveName)
	if err := downloadShare(share, pwd, outDir, saveName); err != nil {
		return err
	}
	// If uploaded as real zip convert of a non-zip original, extract single entry
	// only when saveName differs from remote and remote was zip of original.
	// Keep simple: file already saved as saveName via multipart filename override.
	// For mode=zip, downloaded content is zip bytes but named saveName — extract if needed.
	saved := filepath.Join(outDir, saveName)
	if st, err := os.Stat(saved); err == nil && st.Size() > 0 {
		if needsUnzipConvert(saved, saveName) {
			if err := unzipSingleTo(saved, saved+".raw"); err == nil {
				_ = os.Remove(saved)
				_ = os.Rename(saved+".raw", saved)
				fmt.Println("[download] extracted original payload ->", saved)
			}
		}
	}
	return nil
}

func needsUnzipConvert(path, wantName string) bool {
	// Heuristic: file is a zip and first entry name equals wantName.
	zr, err := zip.OpenReader(path)
	if err != nil {
		return false
	}
	defer zr.Close()
	if len(zr.File) != 1 {
		return false
	}
	return zr.File[0].Name == wantName || filepath.Base(zr.File[0].Name) == filepath.Base(wantName)
}

func unzipSingleTo(zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) < 1 {
		return fmt.Errorf("empty zip")
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
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
		notes := acc.FetchNotes(list)
		// first expand split groups in this folder so we don't download parts separately
		seen := map[string]bool{}
		// handle splits by original name
		splitResolved := map[string]resolvedDownload{}
		for _, e := range list {
			if e.Type != lanzou.EntryFile {
				continue
			}
			note := notes[e.ID]
			if pm, ok := lanzou.ParsePartNote(note); ok {
				key := strings.ToLower(pm.Name)
				if key == "" {
					key = pm.GroupID
				}
				r := splitResolved[key]
				r.Kind = "split"
				r.OrigName = pm.Name
				r.Parts = append(r.Parts, resolvedPart{FileID: e.ID, Name: e.Name, Index: pm.Index, Total: pm.Total, Size: pm.Size})
				splitResolved[key] = r
				seen[e.ID] = true
			}
		}
		for _, r := range splitResolved {
			sort.SliceStable(r.Parts, func(i, j int) bool { return r.Parts[i].Index < r.Parts[j].Index })
			if err := downloadSplitGroup(acc, r, dir, jobs); err != nil {
				fmt.Fprintf(os.Stderr, "[warn] split %s: %v\n", r.OrigName, err)
			}
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
			if seen[e.ID] {
				continue
			}
			saveName := e.Name
			if note := notes[e.ID]; note != "" {
				if cm, ok := lanzou.ParseConvertNote(note); ok && cm.Name != "" {
					saveName = cm.Name
				}
			}
			share, pwd, err := acc.GetFileDownloadInfo(e.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[warn] skip %s: %v\n", e.Name, err)
				continue
			}
			files = append(files, dlJob{fileID: e.ID, name: saveName, destDir: dir, shareURL: share, pwd: pwd})
		}
		return nil
	}
	if err := walk(folderID, destDir); err != nil {
		return err
	}
	fmt.Printf("[download] %d files queued\n", len(files))
	// downloadJobs then post-extract converts
	if err := downloadJobs(files, jobs); err != nil {
		return err
	}
	for _, j := range files {
		saved := filepath.Join(j.destDir, j.name)
		if needsUnzipConvert(saved, j.name) {
			if err := unzipSingleTo(saved, saved+".raw"); err == nil {
				_ = os.Remove(saved)
				_ = os.Rename(saved+".raw", saved)
			}
		}
	}
	return nil
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

type pathSeg struct {
	ID   string
	Name string
}

type shell struct {
	acc    *lanzou.Account
	path   []pathSeg // root = empty; each segment is a folder under parent
	cookie string
	outDir string
	jobs   int
	user   string
	pass   string
}

func (sh *shell) folderID() string {
	if len(sh.path) == 0 {
		return "-1"
	}
	return sh.path[len(sh.path)-1].ID
}

// pathString returns display path: "/" or "/foo/bar"
func (sh *shell) pathString() string {
	if len(sh.path) == 0 {
		return "/"
	}
	var b strings.Builder
	for _, s := range sh.path {
		b.WriteByte('/')
		b.WriteString(s.Name)
	}
	return b.String()
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
		path:   nil,
		cookie: *cookie,
		outDir: *outDir,
		jobs:   *jobs,
		user:   *user,
		pass:   *pass,
	}

	fmt.Println("lanzou interactive shell. type 'help', 'exit' to quit.")
	in := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("lanzou:%s> ", sh.pathString())
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
		fmt.Println("ls|ll|list|dir | cd <name|id|/abs/path|..|.> | pwd")
		fmt.Println("download|dl|down|fetch <id|name> [-j N] [-o DIR]")
		fmt.Println("info|show|stat <id|name> | upload|up|put <path>")
		fmt.Println("mkdir|md <name> | rm|delete|del|remove <id|name>")
		fmt.Println("login|signin [--user U --pass P] | logout|signout")
		fmt.Println("config|conf|cfg [list|get|set ...] | exit|quit|q")
		return nil
	case "exit", "quit", "q":
		return errExit
	case "pwd":
		fmt.Println(sh.pathString())
		return nil
	case "ls", "ll", "list", "dir":
		list, err := sh.acc.List(sh.folderID())
		if err != nil {
			return err
		}
		printList(sh.acc, sh.pathString(), list, true)
		return nil
	case "cd":
		if len(args) < 1 {
			return fmt.Errorf("usage: cd <name|id|/abs/path|..|.>")
		}
		return sh.cd(args[0])
	case "download", "dl", "down", "fetch", "get":
		return sh.cmdDownload(args)
	case "info", "show", "stat":
		if len(args) < 1 {
			return fmt.Errorf("usage: info <id|name>")
		}
		return sh.cmdInfo(args[0])
	case "upload", "up", "put":
		if len(args) < 1 {
			return fmt.Errorf("usage: upload <local-path>")
		}
		res, err := sh.acc.Upload(args[0], sh.folderID())
		if err != nil {
			return err
		}
		fmt.Println("[ok] uploaded", res.FileID, res.Name)
		return nil
	case "mkdir", "md":
		if len(args) < 1 {
			return fmt.Errorf("usage: mkdir <name>")
		}
		_, err := sh.acc.CreateFolder(args[0], sh.folderID(), "")
		if err != nil {
			return err
		}
		fmt.Println("[ok] mkdir", args[0])
		return nil
	case "rm", "delete", "del", "remove", "unlink":
		if len(args) < 1 {
			return fmt.Errorf("usage: rm <id|name>")
		}
		return sh.cmdRm(args[0])
	case "login", "signin", "auth":
		return sh.cmdLogin(args)
	case "logout", "signout":
		_ = os.Remove(sh.cookie)
		sh.acc.SetCookie("")
		fmt.Println("[ok] logged out")
		return nil
	case "config", "conf", "cfg", "settings":
		runConfig(args)
		return nil
	default:
		return fmt.Errorf("unknown command: %s (help for list)", cmd)
	}
}

func (sh *shell) cd(target string) error {
	target = strings.TrimSpace(target)
	if target == "" || target == "." {
		return nil
	}
	// absolute path
	if strings.HasPrefix(target, "/") || target == "~" || target == "root" {
		sh.path = nil
		rest := strings.TrimPrefix(target, "/")
		if target == "~" || target == "root" {
			rest = ""
		}
		if rest == "" {
			return nil
		}
		return sh.cdRelative(rest)
	}
	return sh.cdRelative(target)
}

// cdRelative walks path components from current location (supports a/b, .., names, ids).
func (sh *shell) cdRelative(rel string) error {
	// normalize separators
	rel = strings.ReplaceAll(rel, "\\", "/")
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			if len(sh.path) > 0 {
				sh.path = sh.path[:len(sh.path)-1]
			}
			continue
		}
		cur := sh.folderID()
		list, err := sh.acc.List(cur)
		if err != nil {
			return err
		}
		e, ok := resolveEntry(list, p)
		if !ok {
			if isDigits(p) {
				// raw folder id: keep id as display name if unknown
				name := p
				if info, err := sh.acc.GetFolderInfo(p); err == nil && info.Name != "" {
					name = info.Name
				}
				sh.path = append(sh.path, pathSeg{ID: p, Name: name})
				continue
			}
			return fmt.Errorf("folder not found: %s (at %s)", p, sh.pathString())
		}
		if e.Type != lanzou.EntryFolder {
			return fmt.Errorf("%s is a file, not a folder", e.Name)
		}
		sh.path = append(sh.path, pathSeg{ID: e.ID, Name: e.Name})
	}
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
	return downloadTarget(sh.acc, sh.folderID(), target, outDir, jobs)
}

func (sh *shell) cmdInfo(target string) error {
	list, err := sh.acc.List(sh.folderID())
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
	return deleteTarget(sh.acc, sh.folderID(), target)
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
