package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
)

// ANSI colour codes. We check for NO_COLOR and non-TTY so CI logs stay clean.
const (
	colReset  = "\033[0m"
	colBold   = "\033[1m"
	colDim    = "\033[2m"
	colCyan   = "\033[36m"
	colGreen  = "\033[32m"
	colYellow = "\033[33m"
	colRed    = "\033[31m"
	colGrey   = "\033[90m"
	colWhite  = "\033[97m"
)

const msgWidth = 36 // pad messages to this width so attrs line up

// PrettyHandler is a custom slog.Handler that produces human-readable,
// colourised log output for development and ops use.
// JSON mode is handled separately — this handler is only used for text mode.
type PrettyHandler struct {
	mu      sync.Mutex
	out     io.Writer
	level   slog.Level
	colour  bool
	preAttr []slog.Attr // attrs added via WithAttrs
	group   string      // current group prefix from WithGroup
}

// NewPrettyHandler constructs a PrettyHandler writing to out.
func NewPrettyHandler(out io.Writer, level slog.Level) *PrettyHandler {
	// Disable colour if NO_COLOR is set or if out is not a TTY.
	colour := os.Getenv("NO_COLOR") == ""
	if f, ok := out.(*os.File); ok {
		// Basic TTY detection — works on Linux/macOS.
		fi, err := f.Stat()
		if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
			colour = false
		}
	}
	return &PrettyHandler{out: out, level: level, colour: colour}
}

// Enabled implements slog.Handler.
func (h *PrettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle implements slog.Handler.
func (h *PrettyHandler) Handle(_ context.Context, r slog.Record) error {
	// Collect all attributes: pre-set ones first, then the record's.
	attrs := make([]slog.Attr, 0, len(h.preAttr)+r.NumAttrs())
	attrs = append(attrs, h.preAttr...)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	// Detect request log — emitted by the HTTP middleware with a known shape.
	if isRequestLog(r.Message, attrs) {
		return h.writeRequestLog(r, attrs)
	}

	return h.writeStandardLog(r, attrs)
}

// WithAttrs implements slog.Handler.
func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h2 := h.clone()
	h2.preAttr = append(h2.preAttr, attrs...)
	return h2
}

// WithGroup implements slog.Handler.
func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	h2 := h.clone()
	if h2.group != "" {
		h2.group += "." + name
	} else {
		h2.group = name
	}
	return h2
}

func (h *PrettyHandler) writeStandardLog(r slog.Record, attrs []slog.Attr) error {
	var buf bytes.Buffer

	// Time — HH:MM:SS only
	buf.WriteString(h.dim(r.Time.Format("15:04:05")))
	buf.WriteByte(' ')

	// Level — 3 chars, coloured
	buf.WriteString(h.levelStr(r.Level))
	buf.WriteByte(' ')

	// Message — padded, then attributes
	msg := r.Message
	specialKey := ""

	// Check if there is a single large JSON blob attr (e.g. startup config).
	// If so, print the message on its own line and the JSON pretty-printed below.
	var jsonBlob string
	var normalAttrs []slog.Attr
	for _, a := range attrs {
		if looksLikeJSON(a.Value.String()) {
			jsonBlob = a.Value.String()
			specialKey = a.Key
		} else {
			normalAttrs = append(normalAttrs, a)
		}
	}

	// Pad message
	buf.WriteString(h.bold(padRight(msg, msgWidth)))

	// Normal attrs inline
	for _, a := range normalAttrs {
		v := a.Value.String()
		if v == "" || v == `""` {
			continue // suppress empty values
		}
		buf.WriteByte(' ')
		buf.WriteString(h.dim(a.Key + "="))
		buf.WriteString(h.attrVal(v))
	}

	buf.WriteByte('\n')

	// If there was a JSON blob, pretty-print it indented below.
	if jsonBlob != "" {
		pretty, err := prettyJSON(jsonBlob)
		if err == nil {
			buf.WriteString(h.dim("         " + specialKey + ":\n"))
			for _, line := range strings.Split(pretty, "\n") {
				if line == "" {
					continue
				}
				buf.WriteString(h.dim("           " + line + "\n"))
			}
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.out.Write(buf.Bytes())
	return err
}

// isRequestLog identifies HTTP request records by their message and attrs.
func isRequestLog(msg string, attrs []slog.Attr) bool {
	if msg != "request" {
		return false
	}
	for _, a := range attrs {
		if a.Key == "method" {
			return true
		}
	}
	return false
}

func (h *PrettyHandler) writeRequestLog(r slog.Record, attrs []slog.Attr) error {
	var method, path, remote, requestID string
	var status, durationMS int64

	for _, a := range attrs {
		switch a.Key {
		case "method":
			method = a.Value.String()
		case "path":
			path = a.Value.String()
		case "status":
			status = a.Value.Int64()
		case "duration_ms":
			durationMS = a.Value.Int64()
		case "remote":
			remote = a.Value.String()
		case "request_id":
			requestID = a.Value.String()
		}
	}

	var buf bytes.Buffer

	buf.WriteString(h.dim(r.Time.Format("15:04:05")))
	buf.WriteByte(' ')
	buf.WriteString(h.levelStr(r.Level))
	buf.WriteByte(' ')

	// Arrow + method + path
	arrow := h.colourStatus(status, "→")
	buf.WriteString(arrow)
	buf.WriteByte(' ')
	buf.WriteString(h.bold(padRight(method, 5)))
	buf.WriteString(h.white(padRight(path, 28)))

	// Status code, coloured
	buf.WriteString(h.colourStatus(status, padRight(strconv.FormatInt(status, 10), 5)))

	// Duration
	dur := fmt.Sprintf("%dms", durationMS)
	buf.WriteString(h.dim(padRight(dur, 7)))

	// Remote addr — strip port for cleanliness if it's localhost
	if strings.HasPrefix(remote, "[::1]") || strings.HasPrefix(remote, "127.0.0.1") {
		remote = "localhost"
	}
	buf.WriteString(h.dim(remote))

	// Request ID only if non-empty
	if requestID != "" {
		buf.WriteString(h.dim("  id=" + requestID))
	}

	buf.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.out.Write(buf.Bytes())
	return err
}

func (h *PrettyHandler) levelStr(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return h.c(colRed+colBold, "ERR")
	case level >= slog.LevelWarn:
		return h.c(colYellow, "WRN")
	case level >= slog.LevelInfo:
		return h.c(colCyan, "INF")
	default:
		return h.c(colGrey, "DBG")
	}
}

func (h *PrettyHandler) colourStatus(status int64, s string) string {
	switch {
	case status >= 500:
		return h.c(colRed, s)
	case status >= 400:
		return h.c(colYellow, s)
	case status >= 200:
		return h.c(colGreen, s)
	default:
		return h.c(colGrey, s)
	}
}

func (h *PrettyHandler) attrVal(v string) string {
	if strings.ContainsAny(v, " \t\n") {
		return h.c(colWhite, `"`+v+`"`)
	}
	return h.c(colWhite, v)
}

func (h *PrettyHandler) c(code, s string) string {
	if !h.colour {
		return s
	}
	return code + s + colReset
}

func (h *PrettyHandler) bold(s string) string  { return h.c(colBold, s) }
func (h *PrettyHandler) dim(s string) string   { return h.c(colDim, s) }
func (h *PrettyHandler) white(s string) string { return h.c(colWhite, s) }

func (h *PrettyHandler) clone() *PrettyHandler {
	h2 := *h
	h2.preAttr = append([]slog.Attr(nil), h.preAttr...)
	return &h2
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s + " "
	}
	return s + strings.Repeat(" ", n-len(s))
}

func looksLikeJSON(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) > 2 && (s[0] == '{' || s[0] == '[')
}

func prettyJSON(s string) (string, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
