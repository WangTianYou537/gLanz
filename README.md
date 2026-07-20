# gLanz

Lanzou (蓝奏云) Go library: share-link resolve + account management.

Module: `github.com/WangTianYou537/gLanz`

## Install

```bash
go get github.com/WangTianYou537/gLanz@v0.1.3
go install github.com/WangTianYou537/gLanz/cmd/lanzou@v0.1.3
```

## Share resolve

```go
c := lanzou.New()
res, err := c.Parse(shareURL, lanzou.Options{
    Password:      "optional",
    ResolveDirect: true,
})
```

## Account (from lanzou.class.php)

```go
acc := lanzou.NewAccount("user", "password", lanzou.WithCookieFile("./cookie.txt"))
if err := acc.EnsureLogin(); err != nil { /* ... */ }
list, _ := acc.List("-1")                 // root
_ = acc.CreateFolder("demo", "-1", "desc")
_ = acc.SetFilePassword(fileID, "abcd")
share, pwd, _ := acc.GetFileDownloadInfo(fileID)
```

APIs: Login / Verification / List / CreateFolder / DeleteFolder /
SetFolderPassword / GetFolderInfo / GetFileInfo / SetFilePassword /
SetFileDescribe / MoveFile / DeleteFile.

## CLI

```bash
lanzou https://hya.lanzouu.com/xxx
lanzou --pwd 5grc --down https://wwbss.lanzouu.com/xxx
```

## License

MIT
