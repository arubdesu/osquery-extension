package mcp_servers

// stripJSONC removes // line comments and /* */ block comments from a JSON-with-comments
// document. The stripper is string-aware: it does not touch sequences that appear inside
// double-quoted strings, so values like "https://example.com" or "// note" survive.
//
// It does not support single-quoted strings (JSONC doesn't either) and does not handle
// trailing commas (rare in MCP configs; if present, json.Unmarshal returns an error and
// the file is reported as malformed).
//
// Returns terminated=false when a block comment was opened and never closed. Such a file is
// malformed, and the stripped prefix in front of the opener can still be valid JSON on its own,
// so silently returning it would report a truncated file as a clean one. The caller turns a
// false here into a parse warning.
//
// One pass, one allocation.
func stripJSONC(in []byte) (out []byte, terminated bool) {
	out = make([]byte, 0, len(in))
	inString := false
	escape := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			out = append(out, c)
			switch {
			case escape:
				escape = false
			case c == '\\':
				escape = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(in) {
			next := in[i+1]
			if next == '/' {
				i += 2
				for i < len(in) && in[i] != '\n' {
					i++
				}
				if i < len(in) {
					out = append(out, '\n')
				}
				continue
			}
			if next == '*' {
				// Leave a separator behind, the same way the // branch above preserves its
				// newline. Valid JSON never places two value tokens adjacent with only a
				// comment between them, so this is hardening rather than a fix, but the
				// asymmetry with the line-comment branch is not worth keeping.
				out = append(out, ' ')
				i += 2
				closed := false
				// Scan forward to the closing */. Written as a positive break
				// rather than a negated conjunction: the condition is "have we
				// reached the terminator", which this states directly rather than as
				// either form of "not not at it".
				for i+1 < len(in) {
					if in[i] == '*' && in[i+1] == '/' {
						closed = true
						break
					}
					i++
				}
				if !closed {
					return out, false
				}
				i++
				continue
			}
		}
		out = append(out, c)
	}
	return out, true
}
