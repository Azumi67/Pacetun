package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
)

func TestStreamErrorClassifications(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "eof"}, {io.EOF, "eof"}, {net.ErrClosed, "closed"},
		{context.Canceled, "closed"}, {errors.New("unexpected"), "io_error"},
	}
	for _, test := range cases {
		if got := classifyStreamError(test.err); got != test.want {
			t.Fatalf("got %q want %q", got, test.want)
		}
	}
}
