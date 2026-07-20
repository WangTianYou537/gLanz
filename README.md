# lanzou (Go)

Lanzou (蓝奏云) share-link resolver library and CLI.

## Install

```bash
go install github.com/wantu/lanzou/cmd/lanzou@latest
```

## Library

```go
import "github.com/wantu/lanzou"

c := lanzou.New()
res, err := c.Parse(shareURL, lanzou.Options{
    Password: "5grc",       // optional
    ResolveDirect: true,
})
```

## CLI

```bash
lanzou https://hya.lanzouu.com/iUTg43ww9ich
lanzou --pwd 5grc --down https://wwbss.lanzouu.com/ioHpR10k7d4b
```

## License

MIT
