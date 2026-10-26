// recon-mcp is the MCP server (stdio transport) that exposes the recon
// modules as tools. It holds no business logic: everything lives in internal/
// (shared with recon-cli); this binary only wires internal/mcp onto a stdio
// transport and runs until stdin closes or SIGINT/SIGTERM.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	reconmcp "github.com/Qtlas/BugBounty-recon/internal/mcp"
)

// version of the server, announced to the MCP client. Overridable at build
// time via -ldflags "-X main.version=...".
var version = "0.1.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := reconmcp.NewServer(version)
	if err := srv.Run(ctx, &sdk.StdioTransport{}); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "recon-mcp:", err)
		os.Exit(1)
	}
}
