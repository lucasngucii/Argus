package web

import (
	"embed"
	"mime"
)

// init registers the JavaScript MIME type for .mjs. Go's built-in mime table
// does not map .mjs on every platform, and a browser refuses to evaluate an ES
// module served as application/octet-stream — so the FileServer must return a
// JavaScript content-type for the per-tab modules.
func init() {
	_ = mime.AddExtensionType(".mjs", "text/javascript")
}

// staticFS holds the hand-written, no-build frontend (HTML/CSS + per-tab ES
// modules), embedded at compile time so a single `go build` ships the whole
// control-plane — no npm, node, or bundler in the toolchain. Files live under
// the "static/" prefix; the Handler serves them at /static/*.
//
//go:embed static/*
var staticFS embed.FS
