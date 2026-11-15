// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestFingerprintForUTLSAndClone(t *testing.T) {
	if got := FingerprintForName(""); got != nil {
		t.Fatalf("expected nil for empty profile name, got %#v", got)
	}
	if got := FingerprintForUTLS("", ""); got != nil {
		t.Fatalf("expected nil for empty uTLS client, got %#v", got)
	}
	if got := FingerprintForUTLS("firefox", "120"); got.Name != "firefox_120" {
		t.Fatalf("expected firefox_120, got %q", got.Name)
	}
	if got := FingerprintForUTLS("safari", "16.0"); got.Name != "safari_16" {
		t.Fatalf("expected safari_16, got %q", got.Name)
	}
	if got := FingerprintForName("iOS"); got.Name != "ios" {
		t.Fatalf("expected ios, got %q", got.Name)
	}

	orig := FingerprintChrome()
	cloned := orig.Clone()
	cloned.Settings[0].Val = 1234
	cloned.PseudoHeaderOrder[0] = ":path"
	cloned.HeaderOrder[0] = "x-other"
	if orig.Settings[0].Val == 1234 || orig.PseudoHeaderOrder[0] == ":path" || orig.HeaderOrder[0] == "x-other" {
		t.Fatal("Clone did not isolate slices")
	}

	// Oversized ConnectionFlow and InitialWindowSize clamp cleanly within RFC 9113 bounds.
	settings, streamWin, frameSize, tableSize, headerList, connFlow, sendWU := resolveFingerprintConnParams(
		&FingerprintProfile{
			Settings: []Setting{
				{ID: SettingInitialWindowSize, Val: math.MaxUint32},
				{ID: SettingMaxFrameSize, Val: 100},
				{ID: SettingMaxHeaderListSize, Val: 131072},
			},
			ConnectionFlow: math.MaxUint32,
		},
		configFromTransport(&Transport{}),
		0,
	)
	if !sendWU || uint64(connFlow)+initialWindowSize > math.MaxInt32 {
		t.Fatalf("connection flow overflowed int32 window: connFlow=%d", connFlow)
	}
	if settings[0].Val != math.MaxInt32 || streamWin != math.MaxInt32 {
		t.Fatalf("unexpected clamped initial window size: wire=%d state=%d", settings[0].Val, streamWin)
	}
	if settings[1].Val != minMaxFrameSize || frameSize != minMaxFrameSize {
		t.Fatalf("unexpected clamped frame size: wire=%d state=%d", settings[1].Val, frameSize)
	}
	if tableSize != initialHeaderTableSize || headerList != 131072 {
		t.Fatalf("unexpected RFC defaults/list size: tableSize=%d headerList=%d", tableSize, headerList)
	}
}

type capturedH2Request struct {
	Settings      []Setting
	HasConnWU     bool
	ConnWU        uint32
	Priorities    []PrioritySpec
	HeaderPrio    PriorityParam
	HasHeaderPrio bool
	PseudoOrder   []string
	HeaderOrder   []string
}

func captureWireFingerprint(
	t *testing.T,
	ctx context.Context,
	fp *FingerprintProfile,
	reqHeaders http.Header,
) capturedH2Request {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	resCh := make(chan capturedH2Request, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		preface := make([]byte, len(clientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			errCh <- err
			return
		}
		if string(preface) != ClientPreface {
			errCh <- fmt.Errorf("unexpected client preface %q", preface)
			return
		}

		fr := NewFramer(conn, conn)
		dec := hpack.NewDecoder(65536, nil)
		fr.ReadMetaHeaders = dec
		if err := fr.WriteSettings(); err != nil {
			errCh <- err
			return
		}

		var got capturedH2Request
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			switch f := f.(type) {
			case *SettingsFrame:
				if !f.IsAck() {
					f.ForeachSetting(func(s Setting) error {
						got.Settings = append(got.Settings, s)
						return nil
					})
					if err := fr.WriteSettingsAck(); err != nil {
						errCh <- err
						return
					}
				}
			case *WindowUpdateFrame:
				if f.StreamID == 0 {
					got.HasConnWU = true
					got.ConnWU = f.Increment
				}
			case *PriorityFrame:
				got.Priorities = append(got.Priorities, PrioritySpec{
					StreamID:      f.StreamID,
					PriorityParam: f.PriorityParam,
				})
			case *MetaHeadersFrame:
				got.HasHeaderPrio = f.HasPriority()
				got.HeaderPrio = f.Priority
				for _, hf := range f.Fields {
					if hf.IsPseudo() {
						got.PseudoOrder = append(got.PseudoOrder, hf.Name)
					} else {
						got.HeaderOrder = append(got.HeaderOrder, hf.Name)
					}
				}
				var hdrBuf bytes.Buffer
				enc := hpack.NewEncoder(&hdrBuf)
				_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				if err := fr.WriteHeaders(HeadersFrameParam{
					StreamID:      f.StreamID,
					BlockFragment: hdrBuf.Bytes(),
					EndStream:     true,
					EndHeaders:    true,
				}); err != nil {
					errCh <- err
					return
				}
				resCh <- got
				return
			}
		}
	}()

	tr := &Transport{
		AllowHTTP:   true,
		Fingerprint: fp,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()

	// Note: Transport.RoundTrip dispatches http:// over DialTLSContext when DialTLSContext is set
	// only for https://; use https scheme so DialTLSContext is always invoked with raw TCP conn.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ln.Addr().String()+"/test?a=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, vv := range reqHeaders {
		req.Header[k] = slices.Clone(vv)
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		select {
		case srvErr := <-errCh:
			t.Fatalf("RoundTrip error: %v (server err: %v)", err, srvErr)
		default:
			t.Fatalf("RoundTrip error: %v", err)
		}
	}
	resp.Body.Close()

	select {
	case srvErr := <-errCh:
		t.Fatalf("server error: %v", srvErr)
		return capturedH2Request{}
	case got := <-resCh:
		return got
	}
}

func TestFingerprintWireFrames(t *testing.T) {
	reqHdrs := http.Header{
		"Cache-Control":             {"max-age=0"},
		"Sec-Ch-Ua":                 {`"Chromium";v="134"`},
		"Sec-Ch-Ua-Mobile":          {"?0"},
		"Sec-Ch-Ua-Platform":        {`"Windows"`},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {"Mozilla/5.0"},
		"Accept":                    {"text/html"},
		"Sec-Fetch-Site":            {"none"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-Dest":            {"document"},
		"Accept-Encoding":           {"gzip, deflate, br"},
		"Accept-Language":           {"en-US,en;q=0.9"},
		"Cookie":                    {"b=2; a=1"},
		"Priority":                  {"u=0, i"},
		"Te":                        {"trailers"},
		"X-Custom-B":                {"2"},
		"X-Custom-A":                {"1"},
	}

	t.Run("chrome", func(t *testing.T) {
		fp := FingerprintChrome()
		got := captureWireFingerprint(t, context.Background(), fp, reqHdrs)
		if !slices.Equal(got.Settings, fp.Settings) {
			t.Fatalf("settings mismatch: got %+v, want %+v", got.Settings, fp.Settings)
		}
		if !got.HasConnWU || got.ConnWU != 15663105 {
			t.Fatalf("conn window update mismatch: got (%v, %d), want 15663105", got.HasConnWU, got.ConnWU)
		}
		if len(got.Priorities) != 0 {
			t.Fatalf("unexpected priority frames: %+v", got.Priorities)
		}
		wantPseudo := []string{":method", ":authority", ":scheme", ":path"}
		if !slices.Equal(got.PseudoOrder, wantPseudo) {
			t.Fatalf("pseudo-header order mismatch: got %v, want %v", got.PseudoOrder, wantPseudo)
		}
		wantHeaders := []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"accept-encoding",
			"accept-language",
			"cookie",
			"cookie",
			"priority",
			"te",
			"x-custom-a",
			"x-custom-b",
		}
		if !slices.Equal(got.HeaderOrder, wantHeaders) {
			t.Fatalf("header order mismatch:\n got: %v\nwant: %v", got.HeaderOrder, wantHeaders)
		}
	})

	t.Run("firefox", func(t *testing.T) {
		fp := FingerprintFirefox()
		got := captureWireFingerprint(t, context.Background(), fp, reqHdrs)
		if !slices.Equal(got.Settings, fp.Settings) {
			t.Fatalf("settings mismatch: got %+v, want %+v", got.Settings, fp.Settings)
		}
		if !got.HasConnWU || got.ConnWU != 12517377 {
			t.Fatalf("conn window update mismatch: got (%v, %d), want 12517377", got.HasConnWU, got.ConnWU)
		}
		wantPseudo := []string{":method", ":path", ":authority", ":scheme"}
		if !slices.Equal(got.PseudoOrder, wantPseudo) {
			t.Fatalf("pseudo-header order mismatch: got %v, want %v", got.PseudoOrder, wantPseudo)
		}
	})

	t.Run("safari", func(t *testing.T) {
		fp := FingerprintSafari()
		got := captureWireFingerprint(t, context.Background(), fp, reqHdrs)
		if !slices.Equal(got.Settings, fp.Settings) {
			t.Fatalf("settings mismatch: got %+v, want %+v", got.Settings, fp.Settings)
		}
		if !got.HasConnWU || got.ConnWU != 10420225 {
			t.Fatalf("conn window update mismatch: got (%v, %d), want 10420225", got.HasConnWU, got.ConnWU)
		}
		wantPseudo := []string{":method", ":scheme", ":path", ":authority"}
		if !slices.Equal(got.PseudoOrder, wantPseudo) {
			t.Fatalf("pseudo-header order mismatch: got %v, want %v", got.PseudoOrder, wantPseudo)
		}
	})

	t.Run("custom_priority_skip_wu_and_context_override", func(t *testing.T) {
		fp := &FingerprintProfile{
			Name: "custom",
			Settings: []Setting{
				{ID: SettingEnablePush, Val: 0},
				{ID: SettingInitialWindowSize, Val: 65536},
			},
			SkipConnectionFlow: true,
			Priorities: []PrioritySpec{
				{StreamID: 3, PriorityParam: PriorityParam{Weight: 200}},
			},
			HeaderPriority:    PriorityParam{Exclusive: true, StreamDep: 0, Weight: 255},
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
			HeaderOrder:       []string{"accept", "user-agent"},
		}
		ctx := ContextWithPseudoHeaderOrder(context.Background(), []string{":path", ":method", ":scheme", ":authority"})
		ctx = ContextWithHeaderOrder(ctx, []string{"x-custom-b", "user-agent"})

		got := captureWireFingerprint(t, ctx, fp, reqHdrs)
		if got.HasConnWU {
			t.Fatalf("expected skipped connection WINDOW_UPDATE, got %d", got.ConnWU)
		}
		if len(got.Priorities) != 1 || got.Priorities[0].StreamID != 3 || got.Priorities[0].PriorityParam.Weight != 200 {
			t.Fatalf("unexpected priority frames: %+v", got.Priorities)
		}
		if !got.HasHeaderPrio || !got.HeaderPrio.Exclusive || got.HeaderPrio.Weight != 255 {
			t.Fatalf("header priority mismatch: (%v, %+v)", got.HasHeaderPrio, got.HeaderPrio)
		}
		wantPseudo := []string{":path", ":method", ":scheme", ":authority"}
		if !slices.Equal(got.PseudoOrder, wantPseudo) {
			t.Fatalf("context pseudo-header override mismatch: got %v, want %v", got.PseudoOrder, wantPseudo)
		}
		if len(got.HeaderOrder) < 2 || got.HeaderOrder[0] != "x-custom-b" || got.HeaderOrder[1] != "user-agent" {
			t.Fatalf("context header order override mismatch: %v", got.HeaderOrder)
		}
	})
}

func TestFingerprintHeaderOrderDeterminism(t *testing.T) {
	reqHdrs := http.Header{
		"User-Agent":      {"Mozilla/5.0"},
		"Accept":          {"*/*"},
		"Accept-Language": {"en-US"},
		"X-Gamma":         {"3"},
		"X-Alpha":         {"1"},
		"X-Beta":          {"2"},
	}
	fp := FingerprintFirefox()
	var baselinePseudo, baselineHdrs []string
	for i := range 5 {
		got := captureWireFingerprint(t, context.Background(), fp, reqHdrs)
		if i == 0 {
			baselinePseudo = got.PseudoOrder
			baselineHdrs = got.HeaderOrder
			continue
		}
		if !slices.Equal(got.PseudoOrder, baselinePseudo) {
			t.Fatalf("iteration %d pseudo-header drift: %v vs %v", i, got.PseudoOrder, baselinePseudo)
		}
		if !slices.Equal(got.HeaderOrder, baselineHdrs) {
			t.Fatalf("iteration %d header drift: %v vs %v", i, got.HeaderOrder, baselineHdrs)
		}
	}
}

func TestFingerprintEndToEndServerTransfer(t *testing.T) {
	// Transfer a payload larger than Firefox's initial 128 KiB stream window to
	// verify ClientConn flow control stays synchronized with advertised SETTINGS.
	payload := make([]byte, 512*1024)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatal(err)
	}

	profiles := []*FingerprintProfile{
		FingerprintChrome(),
		FingerprintFirefox(),
		FingerprintSafari(),
		FingerprintIOS(),
	}

	for _, fp := range profiles {
		t.Run(strings.ToLower(fp.Name), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			srv := &Server{}
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				srv.ServeConn(conn, &ServeConnOpts{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, err := io.ReadAll(r.Body)
						if err != nil {
							http.Error(w, err.Error(), http.StatusBadRequest)
							return
						}
						if !bytes.Equal(body, payload) {
							http.Error(w, "request body mismatch", http.StatusBadRequest)
							return
						}
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write(payload)
					}),
				})
			}()

			tr := &Transport{
				AllowHTTP:   true,
				Fingerprint: fp,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				},
			}
			defer tr.CloseIdleConnections()

			req, err := http.NewRequest(http.MethodPost, "https://"+ln.Addr().String()+"/upload", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip failed: %v", err)
			}
			gotBody, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("ReadAll failed: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("unexpected status %d: %s", resp.StatusCode, string(gotBody))
			}
			if !bytes.Equal(gotBody, payload) {
				t.Fatalf("response payload mismatch (len=%d want=%d)", len(gotBody), len(payload))
			}

			ln.Close()
			tr.CloseIdleConnections()
			<-done
		})
	}
}
