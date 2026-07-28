package web

import "embed"

// staticFS holds the hand-written, no-build frontend (HTML/CSS + per-tab ES
// modules), embedded at compile time so a single `go build` ships the whole
// control-plane — no npm, node, or bundler in the toolchain. Files live under
// the "static/" prefix; the Handler serves them at /static/*.
//
//go:embed static/*
var staticFS embed.FS
