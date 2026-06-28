//go:build darwin

package darwin

import (
	"encoding/xml"
	"io"
	"strings"
)

// parsePlistDict parses an Apple XML plist <dict> into a key→string map.
// Non-string value types (integer, bool, date, array, nested dict) are skipped.
// The parser is intentionally lenient: malformed entries are silently ignored.
func parsePlistDict(r io.Reader) (map[string]string, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	out := make(map[string]string)
	var pending string // key awaiting its value
	var lastElem string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			lastElem = t.Name.Local
		case xml.EndElement:
			// Reset lastElem only on element types that are NOT key or string,
			// so that CharData following <key>…</key> still sees lastElem=="key"
			// until the next StartElement updates it.
			if t.Name.Local != "key" && t.Name.Local != "string" {
				lastElem = ""
			}
		case xml.CharData:
			s := strings.TrimSpace(string(t))
			if s == "" {
				continue
			}
			switch lastElem {
			case "key":
				pending = s
			case "string":
				if pending != "" {
					out[pending] = s
					pending = ""
				}
			}
		}
	}
	return out, nil
}
