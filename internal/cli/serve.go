package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/lucasngucii/argus/internal/store"
	"github.com/lucasngucii/argus/internal/web"
)

// Serve opens the decision store and runs the loopback control-plane until ctx
// is cancelled (the caller wires SIGINT/SIGTERM). It prints the real listen URL
// once bound, and always closes the store on return — the deferred Close runs
// after web.ListenAndServe's bounded graceful shutdown, so the DB handle is
// released cleanly even on Ctrl-C. A store-open, address-validation, or
// serve error returns non-zero; a clean shutdown returns 0.
func Serve(ctx context.Context, home, addr string, w io.Writer) int {
	dbPath := filepath.Join(home, ".argus", "argus.db")
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(w, "argus: serve: open store: %v\n", err)
		return 1
	}
	defer st.Close()

	policyPath := filepath.Join(home, ".argus", "policy.json")
	srv, err := web.New(st, policyPath, addr)
	if err != nil {
		fmt.Fprintf(w, "argus: serve: %v\n", err)
		return 1
	}

	err = srv.ListenAndServe(ctx, func(bound string) {
		fmt.Fprintf(w, "argus: serving on http://%s\n", bound)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(w, "argus: serve: %v\n", err)
		return 1
	}
	return 0
}
