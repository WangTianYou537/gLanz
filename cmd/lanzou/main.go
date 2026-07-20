package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
	"github.com/WangTianYou537/gLanz"
)

const defaultCookie = "./lanzou.cookie"

func main() {
	if len(os.Args) < 2 {
		printRootHelp()
		os.Exit(1)
	}

	// Backward compatible: first arg looks like URL => parse mode
	cmd := os.Args[1]
	if strings.HasPrefix(cmd, "http://") || strings.HasPrefix(cmd, "https://") || strings.HasPrefix(cmd, "-") {
		runParse(os.Args[1:])
		return
	}

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
	case "help", "-h", "--help":
		printRootHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printRootHelp()
		os.Exit(1)
	}
}

func printRootHelp() {
	fmt.Fprintf(os.Stderr, `lanzou — Lanzou share resolve + account CLI

Usage:
  lanzou <share-url> [flags]              # parse share (legacy)
  lanzou parse <share-url> [flags]
  lanzou login --user U --pass P [--cookie FILE]
  lanzou logout [--cookie FILE]
  lanzou list [--folder ID] [--cookie FILE]
  lanzou upload <file> [--folder ID] [--cookie FILE]
  lanzou mkdir <name> [--folder parentID] [--desc TEXT]
  lanzou rm --file ID | --folder ID
  lanzou info --file ID | --folder ID
  lanzou passwd --file ID --pwd XXX | --folder ID --pwd XXX

Share flags:
  -p, --pwd string         share password
      --down               download after resolve
  -o, --output-dir string  download directory (default ".")
  -f, --filename string    save filename
      --no-resolve         skip CDN direct resolve

Account flags (most commands):
  -u, --user string        account username/phone
      --pass string        account password
  -c, --cookie string      cookie file (default "./lanzou.cookie")
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
	opt := lanzou.Options{
		Password:      *pwd,
		ResolveDirect: !*noResolve,
	}
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
	user = fs.StringP("user", "u", envOr("LANZOU_USER", ""), "account username/phone (or env LANZOU_USER)")
	pass = fs.String("pass", envOr("LANZOU_PASS", ""), "account password (or env LANZOU_PASS)")
	cookie = fs.StringP("cookie", "c", envOr("LANZOU_COOKIE", defaultCookie), "cookie file path")
	return
}

func openAccount(user, pass, cookie string, needLogin bool) *lanzou.Account {
	acc := lanzou.NewAccount(user, pass, lanzou.WithCookieFile(cookie))
	if needLogin {
		if user == "" || pass == "" {
			// try cookie only
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
	_ = fs.Parse(args)
	if *user == "" || *pass == "" {
		fmt.Fprintln(os.Stderr, "usage: lanzou login --user U --pass P [--cookie FILE]")
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
	cookie := fs.StringP("cookie", "c", envOr("LANZOU_COOKIE", defaultCookie), "cookie file path")
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
	fmt.Printf("folder=%s  entries=%d\n", *folder, len(list))
	for _, e := range list {
		kind := "FILE"
		if e.Type == lanzou.EntryFolder {
			kind = "DIR "
		}
		extra := e.Size
		if e.Type == lanzou.EntryFolder {
			extra = e.URL
		}
		fmt.Printf("  [%s] id=%-12s  %s  %s\n", kind, e.ID, e.Name, extra)
	}
}

func runUpload(args []string) {
	fs := pflag.NewFlagSet("upload", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	folder := fs.String("folder", "-1", "target folder id (-1 = root)")
	setPwd := fs.String("set-pwd", "", "optional: set share password after upload")
	setDesc := fs.String("set-desc", "", "optional: set description after upload")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: lanzou upload <local-file> [--folder ID] [--cookie FILE]")
		fs.PrintDefaults()
		os.Exit(1)
	}
	local := fs.Arg(0)
	acc := openAccount(*user, *pass, *cookie, true)
	fmt.Println("[upload]", local, "-> folder", *folder)
	res, err := acc.Upload(local, *folder)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	fmt.Println("[ok] uploaded")
	fmt.Println("  file_id:", res.FileID)
	fmt.Println("  name:   ", res.Name)
	if *setPwd != "" && res.FileID != "" {
		if _, err := acc.SetFilePassword(res.FileID, *setPwd); err != nil {
			fmt.Fprintln(os.Stderr, "[warn] set password:", err)
		} else {
			fmt.Println("  password set")
		}
	}
	if *setDesc != "" && res.FileID != "" {
		if _, err := acc.SetFileDescribe(res.FileID, *setDesc); err != nil {
			fmt.Fprintln(os.Stderr, "[warn] set desc:", err)
		} else {
			fmt.Println("  description set")
		}
	}
	if res.FileID != "" {
		if share, pwd, err := acc.GetFileDownloadInfo(res.FileID); err == nil {
			fmt.Println("  share:  ", share)
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
		fmt.Fprintln(os.Stderr, "usage: lanzou mkdir <name> [--folder parentID] [--desc TEXT]")
		os.Exit(1)
	}
	name := fs.Arg(0)
	acc := openAccount(*user, *pass, *cookie, true)
	raw, err := acc.CreateFolder(name, *parent, *desc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[error]", err)
		os.Exit(1)
	}
	fmt.Println("[ok] mkdir", name)
	fmt.Println(raw)
}

func runDelete(args []string) {
	fs := pflag.NewFlagSet("rm", pflag.ExitOnError)
	user, pass, cookie := accountFlags(fs)
	fileID := fs.String("file", "", "file id to delete")
	folderID := fs.String("folder", "", "folder id to delete")
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

// silence unused import if any
var _ = filepath.Base
