// Package windows implements the Windows inventory Collector: it reads the
// registry Uninstall keys (HKLM, both 64- and 32-bit views; never Win32_Product
// via WMI) and optionally winget. Passive and local-only. Implemented in Fase 3.
package windows
