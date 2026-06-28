// Package linux implements the Linux inventory Collector. It reads the dpkg
// status database and /etc/os-release directly (no fragile shell-out) and is
// passive/local-only. rpm support is added incrementally. See agent/README.md.
package linux
