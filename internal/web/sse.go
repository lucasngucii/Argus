package web

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// handleStream serves GET /api/stream as a per-connection Server-Sent Events
// feed of new decisions. There is deliberately no pub/sub hub: each connection
// runs its own short poll loop against the store. For a local single-user gate
// the connection count is tiny, and a hub would be state and shutdown
// complexity with nothing to buy it.
//
// The loop seeds its cursor from the current MaxID (so a client sees only
// decisions made after it connected), then on each tick emits every row past
// the cursor as an SSE `data:` frame and advances. It returns promptly when
// EITHER the request context is done (client disconnect) OR srv.shutdown is
// closed (server shutdown) — so an open stream can never block graceful
// shutdown. A store read error (including the "database is closed" shutdown
// race) is logged and ends the stream rather than panicking or spinning.
func (srv *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		serverError(w, "stream", errNotFlushable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	cursor, err := srv.store.MaxID()
	if err != nil {
		slog.Error("sse: seed cursor", "err", err)
		return
	}

	ticker := time.NewTicker(srv.sseInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-srv.shutdown:
			return
		case <-ticker.C:
			rows, err := srv.store.DecisionsAfter(cursor, 100)
			if err != nil {
				slog.Error("sse: read decisions", "err", err)
				return
			}
			for _, row := range rows {
				b, err := json.Marshal(row)
				if err != nil {
					slog.Error("sse: marshal row", "err", err)
					continue
				}
				fmt.Fprintf(w, "data: %s\n\n", b)
				cursor = row.ID
			}
			if len(rows) > 0 {
				flusher.Flush()
			}
		}
	}
}

// errNotFlushable is returned when the response writer cannot stream — SSE is
// impossible without flushing, so the handler fails with a 500 up front.
var errNotFlushable = fmt.Errorf("response writer does not support flushing")
