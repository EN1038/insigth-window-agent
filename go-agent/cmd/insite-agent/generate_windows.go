//go:build windows

package main

// Embed Windows application icon + version resources into insite-agent.exe.
// Generated file: resource.syso (linked automatically by `go build`).
//
//go:generate go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1 -64 -o resource.syso -platform-specific=false
