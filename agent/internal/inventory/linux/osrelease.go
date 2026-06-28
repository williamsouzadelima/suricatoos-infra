package linux

import (
	"bufio"
	"io"
	"strings"
)

// parseOSRelease parses an os-release(5) stream (KEY=VALUE lines, values may be
// quoted) and returns the distro ID and version ID, e.g. ("debian", "12").
func parseOSRelease(r io.Reader) (distro, release string, err error) {
	vals := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vals[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	if err := sc.Err(); err != nil {
		return "", "", err
	}
	return vals["ID"], vals["VERSION_ID"], nil
}
