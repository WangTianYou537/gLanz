# gLanz

Lanzou (蓝奏云) Go library + CLI: share resolve **and** account ops (login / list / upload / download / interactive).

Module: `github.com/WangTianYou537/gLanz`

## Install CLI

```bash
go install github.com/WangTianYou537/gLanz/cmd/lanzou@latest
# 注意路径必须含 /cmd/lanzou
```

## CLI

```bash
# 分享解析（兼容旧用法）
lanzou https://hya.lanzouu.com/xxx
lanzou parse --pwd 5grc --down https://wwbss.lanzouu.com/xxx

# 登录（cookie 默认 ~/.lanzou/cookie，也可用环境变量 LANZOU_USER/LANZOU_PASS/LANZOU_COOKIE）
lanzou login --user 手机号 --pass 密码
lanzou logout

# 目录 / 上传
lanzou list
lanzou list --folder 123456
lanzou upload ./file.zip --folder -1
lanzou upload ./a.doc --folder 123 --set-pwd abcd --set-desc "说明"
lanzou mkdir demo --folder -1 --desc "新建"
lanzou info --file 111
lanzou passwd --file 111 --pwd ab12
lanzou rm --file 111

# 下载：文件走 info share 解析；文件夹递归并发（默认 -j 3）
lanzou download <id|name> [--folder ID] [-o DIR] [-j 3]

# 交互模式
lanzou -i
#   ls / cd <id|name|/|..> / pwd / download <id|name> / info / upload / mkdir / rm / login / exit
```

## Library

```go
import "github.com/WangTianYou537/gLanz"

// share
c := lanzou.New()
res, _ := c.Parse(url, lanzou.Options{ResolveDirect: true})

// account
acc := lanzou.NewAccount(user, pass, lanzou.WithCookieFile("~/.lanzou/cookie"))
_ = acc.EnsureLogin()
list, _ := acc.List("-1")
up, _ := acc.Upload("./a.zip", "-1")
```

Upload endpoint: `POST fileup.php` multipart (`task=1`, field `upload_file`), compatible with common Lanzou web clients.

## License

MIT
