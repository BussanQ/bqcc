package cli

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/example/decentid/internal/app"
	webui "github.com/example/decentid/internal/web"
)

// RunWeb starts the localhost web console. args is the flag slice that follows
// the "web" subcommand (i.e. os.Args after the subcommand name).
func RunWeb(args []string) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	identityPath := fs.String("identity", app.DefaultIdentityPath, "本地私有身份文件")
	addr := fs.String("addr", "127.0.0.1:8080", "本地 Web 操作台地址")
	fs.Parse(args)

	if !isLoopbackBind(*addr) {
		fmt.Fprintln(os.Stderr, "拒绝绑定非 loopback 地址；本地私有操作台请使用 127.0.0.1")
		os.Exit(1)
	}

	service := app.NewService(*identityPath)
	server, err := webui.New(service)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("DecentID Web 操作台：http://%s\n", *addr)
	fmt.Printf("本地私有身份文件：%s\n", *identityPath)
	if err := server.ListenAndServe(*addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func isLoopbackBind(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
