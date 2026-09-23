package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func browserUA(profile string) string {
	if profile == "chrome120" {
		return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	return "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
}

var startupGate struct {
	sync.Mutex
	next time.Time
}

func startupAllowed(now time.Time) bool {
	startupGate.Lock()
	defer startupGate.Unlock()
	if now.Before(startupGate.next) {
		return false
	}
	startupGate.next = now.Add(time.Minute)
	return true
}
func validStartupPaths(paths string) bool {
	if paths == "" {
		return true
	}
	parts := strings.Split(paths, ",")
	if len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		u, e := url.ParseRequestURI(p)
		if e != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || len(p) > 512 || strings.ContainsAny(p, "\r\n#") {
			return false
		}
	}
	return true
}

func startupRequests(ctx context.Context, c net.Conn, o options) error {
	if o.startupPaths == "" || !startupAllowed(time.Now()) {
		return nil
	}
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.SetDeadline(deadline); err != nil {
		return err
	}
	defer c.SetDeadline(time.Time{})
	br := bufio.NewReaderSize(c, 8192)
	remaining := int64(32768)
	for _, path := range strings.Split(o.startupPaths, ",") {
		req, e := http.NewRequest("GET", "https://"+o.name+path, nil)
		if e != nil {
			return e
		}
		req.Header.Set("User-Agent", browserUA(o.fingerprint))
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "identity")
		if e = req.Write(c); e != nil {
			return e
		}
		var header strings.Builder
		for {
			line, e := br.ReadSlice('\n')
			if e != nil {
				return e
			}
			header.Write(line)
			if header.Len() > 8192 {
				return errors.New("startup headers too large")
			}
			if string(line) == "\r\n" {
				break
			}
		}
		response, e := http.ReadResponse(bufio.NewReader(io.MultiReader(strings.NewReader(header.String()), br)), req)
		if e != nil {
			return e
		}
		if response.StatusCode != 200 || response.Close {
			return errors.New("startup requires persistent HTTP 200")
		}
		n, e := io.Copy(io.Discard, io.LimitReader(response.Body, remaining+1))
		remaining -= n
		if e != nil || remaining < 0 {
			return errors.New("startup body exceeds budget")
		}
		if e = response.Body.Close(); e != nil {
			return e
		}
		if br.Buffered() != 0 {
			return errors.New("unsolicited bytes after startup response")
		}
	}
	return nil
}
