package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"github.com/wantu/lanzou"
)

func main() {
	pwd := pflag.StringP("pwd", "p", "", "share password")
	down := pflag.Bool("down", false, "download after resolve")
	outDir := pflag.StringP("output-dir", "o", ".", "download directory")
	filename := pflag.StringP("filename", "f", "", "save filename")
	noResolve := pflag.Bool("no-resolve", false, "skip CDN direct resolve")
	pflag.Parse()

	if pflag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: lanzou [flags] <share-url>")
		pflag.PrintDefaults()
		os.Exit(1)
	}
	shareURL := pflag.Arg(0)

	c := lanzou.New()
	opt := lanzou.Options{
		Password:      *pwd,
		ResolveDirect: !*noResolve,
	}
	// When only password is needed, still default resolve true unless --no-resolve
	if !*noResolve {
		opt.ResolveDirect = true
	}

	res, err := c.Parse(shareURL, opt)
	if err != nil {
		if errors.Is(err, lanzou.ErrPasswordRequired) {
			fmt.Fprintln(os.Stderr, "[error]", err)
			fmt.Fprintln(os.Stderr, "example: lanzou --pwd 5grc https://wwbss.lanzouu.com/ioHpR10k7d4b")
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
