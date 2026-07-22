package lanzou

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DownloadShareOptions controls note-aware share download.
type DownloadShareOptions struct {
	Password string
	DestDir  string
	// Filename overrides the final save name. Empty = auto from note/remote.
	Filename string
	// Account enables walking part.next share URLs for multi-part notes.
	Account *Account
	// SkipNote disables convert/part restoration (plain download).
	SkipNote bool
}

// DownloadShareNote parses a share link, downloads, and applies convert/part notes:
//   - convert (zip): download then unzip single entry to original name
//   - convert (rename) / raw: save as original name
//   - part: download this part and follow next share URLs (+ npwd), merge to original name
//
// Without a note, behaves like DownloadShare.
func (c *Client) DownloadShareNote(shareURL string, opt DownloadShareOptions) (string, error) {
	if opt.DestDir == "" {
		opt.DestDir = "."
	}
	if err := os.MkdirAll(opt.DestDir, 0o755); err != nil {
		return "", err
	}

	res, err := c.Parse(shareURL, Options{Password: opt.Password, ResolveDirect: false})
	if err != nil {
		return "", err
	}

	if opt.SkipNote || res.Note == nil {
		name := firstNonEmpty(opt.Filename, res.Filename)
		return DownloadShareWithName(shareURL, opt.Password, opt.DestDir, name)
	}

	switch res.Note.Kind {
	case "convert", "raw":
		return downloadConvertShare(res, shareURL, opt)
	case "part":
		return downloadPartChain(res, shareURL, opt)
	default:
		name := firstNonEmpty(opt.Filename, res.Filename)
		return DownloadShareWithName(shareURL, opt.Password, opt.DestDir, name)
	}
}

// DownloadShareWithName is DownloadShare with an explicit save filename.
func DownloadShareWithName(shareURL, password, destDir, filename string) (string, error) {
	return New().DownloadShare(shareURL, password, destDir, filename)
}

func downloadConvertShare(res *Result, shareURL string, opt DownloadShareOptions) (string, error) {
	orig := res.OrigName
	if orig == "" && res.Note != nil {
		orig = res.Note.Name
	}
	remoteName := res.Filename
	if res.Note != nil && res.Note.As != "" {
		remoteName = res.Note.As
	}
	tmpName := ".dl-" + sanitizeFileName(firstNonEmpty(remoteName, res.Filename, "download.bin"))
	tmpPath, err := DownloadShareWithName(shareURL, opt.Password, opt.DestDir, tmpName)
	if err != nil {
		return "", err
	}

	finalName := sanitizeFileName(firstNonEmpty(opt.Filename, orig, remoteName, filepath.Base(tmpPath)))
	finalPath := uniquePath(filepath.Join(opt.DestDir, finalName))

	mode := ""
	if res.Note != nil {
		mode = res.Note.Mode
	}
	// zip convert: extract single entry as original payload
	if res.Note != nil && res.Note.Kind == "convert" && (mode == "zip" || mode == "") {
		if err := unzipSingleEntry(tmpPath, finalPath); err == nil {
			_ = os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "[download] restored convert -> %s\n", finalPath)
			return finalPath, nil
		}
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		if _, err2 := copyFileSimple(tmpPath, finalPath); err2 != nil {
			return "", err2
		}
		_ = os.Remove(tmpPath)
	}
	return finalPath, nil
}

func downloadPartChain(res *Result, shareURL string, opt DownloadShareOptions) (string, error) {
	if res.Note == nil {
		return "", fmt.Errorf("missing part note")
	}
	orig := sanitizeFileName(firstNonEmpty(opt.Filename, res.Note.Name, "merged.bin"))
	total := res.Note.Total
	if total < 1 {
		total = 1
	}

	type partJob struct {
		index    int
		shareURL string
		pwd      string
		size     int64
	}
	jobs := []partJob{{
		index:    res.Note.Index,
		shareURL: shareURL,
		pwd:      opt.Password,
		size:     res.Note.Size,
	}}

	// Walk next share URLs from notes (no account required).
	if res.Note.Next != "" {
		nextURL := normalizeShareURL(res.Note.Next)
		nextPwd := res.Note.NPwd
		seen := map[string]struct{}{shareURL: {}}
		if nextURL != "" {
			seen[nextURL] = struct{}{}
		}
		for guard := 0; nextURL != "" && guard < 256; guard++ {
			nc := New()
			nres, err := nc.Parse(nextURL, Options{Password: nextPwd, ResolveDirect: false})
			if err != nil {
				return "", fmt.Errorf("part next share: %w", err)
			}
			idx := len(jobs) + 1
			var size int64
			following, followingPwd := "", ""
			if nres.Note != nil && nres.Note.Kind == "part" {
				idx = nres.Note.Index
				size = nres.Note.Size
				following = nres.Note.Next
				followingPwd = nres.Note.NPwd
				if total < nres.Note.Total {
					total = nres.Note.Total
				}
			}
			jobs = append(jobs, partJob{index: idx, shareURL: nextURL, pwd: nextPwd, size: size})
			if following == "" {
				break
			}
			if _, ok := seen[following]; ok {
				break
			}
			seen[following] = struct{}{}
			nextURL = normalizeShareURL(following)
			nextPwd = followingPwd
		}
	}

	for i := 0; i < len(jobs); i++ {
		for j := i + 1; j < len(jobs); j++ {
			if jobs[j].index < jobs[i].index {
				jobs[i], jobs[j] = jobs[j], jobs[i]
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[download] split %s  parts=%d/%d  (serial, note chain)\n", orig, len(jobs), total)
	partFiles := make([]string, 0, len(jobs))
	for i, j := range jobs {
		fmt.Fprintf(os.Stderr, "[download] part %d/%d index=%d\n", i+1, len(jobs), j.index)
		tmpName := fmt.Sprintf(".%s.s%03d.download", orig, j.index)
		path, err := DownloadShareWithName(j.shareURL, j.pwd, opt.DestDir, tmpName)
		if err != nil {
			for _, f := range partFiles {
				_ = os.Remove(f)
			}
			return "", fmt.Errorf("part index=%d: %w", j.index, err)
		}
		raw := filepath.Join(opt.DestDir, fmt.Sprintf(".%s.s%03d.bin", orig, j.index))
		if err := extractZipOrRename(path, raw); err != nil {
			_ = os.Remove(path)
			for _, f := range partFiles {
				_ = os.Remove(f)
			}
			return "", fmt.Errorf("part index=%d extract: %w", j.index, err)
		}
		_ = os.Remove(path)
		partFiles = append(partFiles, raw)
		fmt.Fprintf(os.Stderr, "[ok %d/%d] part index=%d\n", i+1, len(jobs), j.index)
		if i+1 < len(jobs) {
			time.Sleep(400 * time.Millisecond)
		}
	}

	if len(partFiles) == 1 && (total > 1 || res.Note.Next != "") && opt.Account == nil {
		outPath := uniquePath(filepath.Join(opt.DestDir, fmt.Sprintf("%s.part%03d", orig, jobs[0].index)))
		if err := os.Rename(partFiles[0], outPath); err != nil {
			if _, err2 := copyFileSimple(partFiles[0], outPath); err2 != nil {
				return "", err2
			}
			_ = os.Remove(partFiles[0])
		}
		fmt.Fprintf(os.Stderr, "[done] partial part saved: %s (login to merge full set)\n", outPath)
		return outPath, nil
	}

	outPath := uniquePath(filepath.Join(opt.DestDir, orig))
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	for _, f := range partFiles {
		in, err := os.Open(f)
		if err != nil {
			out.Close()
			return "", err
		}
		_, err = io.Copy(out, in)
		in.Close()
		_ = os.Remove(f)
		if err != nil {
			out.Close()
			return "", err
		}
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "[done] merged: %s\n", outPath)
	return outPath, nil
}

func normalizeShareURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return u
	}
	if strings.HasPrefix(u, "//") {
		return "https:" + u
	}
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	// host/path without scheme
	if strings.Contains(u, ".") && strings.Contains(u, "/") {
		return "https://" + u
	}
	return u
}

func sanitizeFileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "unnamed"
	}
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return filepath.Base(repl.Replace(name))
}

func uniquePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	ext := filepath.Ext(path)
	stem := strings.TrimSuffix(path, ext)
	for i := 1; ; i++ {
		cand := fmt.Sprintf("%s(%d)%s", stem, i, ext)
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
}

func unzipSingleEntry(zipPath, dest string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	if len(r.File) == 0 {
		return fmt.Errorf("empty zip")
	}
	rc, err := r.File[0].Open()
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

func extractZipOrRename(downloaded, prefer string) error {
	if err := unzipSingleEntry(downloaded, prefer); err == nil {
		return nil
	}
	if err := os.Rename(downloaded, prefer); err == nil {
		return nil
	}
	_, err := copyFileSimple(downloaded, prefer)
	return err
}

func copyFileSimple(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, in)
}
