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
	"sync"
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
	cloned.SensitiveHeaders[0] = "x-secret"
	if orig.Settings[0].Val == 1234 || orig.PseudoHeaderOrder[0] == ":path" || orig.HeaderOrder[0] == "x-other" || orig.SensitiveHeaders[0] == "x-secret" {
		t.Fatal("Clone did not isolate slices")
	}
	for _, fp := range []*FingerprintProfile{
		FingerprintChrome(),
		FingerprintEdge(),
		FingerprintAndroid(),
		FingerprintFirefox(),
		FingerprintFirefox120(),
		FingerprintSafari(),
		FingerprintSafari16(),
		FingerprintIOS(),
	} {
		if fp.DefaultUserAgent == "" || strings.Contains(fp.DefaultUserAgent, "Go-http-client") {
			t.Fatalf("%s profile has invalid DefaultUserAgent %q", fp.Name, fp.DefaultUserAgent)
		}
		if fp.ConnWindowRefreshRatio != 0.5 || fp.StreamWindowRefreshRatio != 0.5 {
			t.Fatalf("%s profile unexpected refresh ratios: conn=%v stream=%v", fp.Name, fp.ConnWindowRefreshRatio, fp.StreamWindowRefreshRatio)
		}
		if !slices.Contains(fp.SensitiveHeaders, "cookie") || !slices.Contains(fp.SensitiveHeaders, "authorization") {
			t.Fatalf("%s profile missing sensitive cookie/authorization headers: %v", fp.Name, fp.SensitiveHeaders)
		}
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
	Settings        []Setting
	HasConnWU       bool
	ConnWU          uint32
	Priorities      []PrioritySpec
	HeaderPrio      PriorityParam
	HasHeaderPrio   bool
	PseudoOrder     []string
	HeaderOrder     []string
	Fields          []hpack.HeaderField
	PriorityUpdates []PriorityUpdateFrame
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
				got.Fields = slices.Clone(f.Fields)
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

func TestFingerprintDefaultUserAgentFallback(t *testing.T) {
	chrome := FingerprintChrome()

	t.Run("omitted_uses_profile_default", func(t *testing.T) {
		got := captureWireFingerprint(t, context.Background(), chrome, http.Header{
			"Accept": {"*/*"},
		})
		var ua string
		for _, hf := range got.Fields {
			if hf.Name == "user-agent" {
				ua = hf.Value
			}
		}
		if ua != chrome.DefaultUserAgent {
			t.Fatalf("user-agent mismatch: got %q, want %q", ua, chrome.DefaultUserAgent)
		}
		if strings.Contains(ua, "Go-http-client") {
			t.Fatalf("leaked Go default user-agent: %q", ua)
		}
	})

	t.Run("explicit_nil_suppressed", func(t *testing.T) {
		got := captureWireFingerprint(t, context.Background(), chrome, http.Header{
			"User-Agent": nil,
		})
		for _, hf := range got.Fields {
			if hf.Name == "user-agent" {
				t.Fatalf("expected suppressed user-agent, got %q", hf.Value)
			}
		}
	})

	t.Run("explicit_value_preserved", func(t *testing.T) {
		got := captureWireFingerprint(t, context.Background(), chrome, http.Header{
			"User-Agent": {"custom-agent/9.9"},
		})
		var ua string
		for _, hf := range got.Fields {
			if hf.Name == "user-agent" {
				ua = hf.Value
			}
		}
		if ua != "custom-agent/9.9" {
			t.Fatalf("custom user-agent lost: got %q", ua)
		}
	})

	t.Run("nil_profile_preserves_go_default", func(t *testing.T) {
		got := captureWireFingerprint(t, context.Background(), nil, http.Header{})
		var ua string
		for _, hf := range got.Fields {
			if hf.Name == "user-agent" {
				ua = hf.Value
			}
		}
		if ua != defaultUserAgent {
			t.Fatalf("expected vanilla default %q, got %q", defaultUserAgent, ua)
		}
	})
}

func runDownloadCaptureWindowUpdates(
	t *testing.T,
	fp *FingerprintProfile,
	payload []byte,
	chunkSize int,
) []WindowUpdateFrame {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type serverResult struct {
		wus []WindowUpdateFrame
		err error
	}
	resCh := make(chan serverResult, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- serverResult{err: err}
			return
		}
		defer conn.Close()

		preface := make([]byte, len(clientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			resCh <- serverResult{err: err}
			return
		}
		if string(preface) != ClientPreface {
			resCh <- serverResult{err: fmt.Errorf("unexpected preface %q", preface)}
			return
		}

		fr := NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)

		var writeMu sync.Mutex
		writeHeaders := func(p HeadersFrameParam) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			return fr.WriteHeaders(p)
		}
		writeSettingsAck := func() error {
			writeMu.Lock()
			defer writeMu.Unlock()
			return fr.WriteSettingsAck()
		}
		writeData := func(streamID uint32, endStream bool, data []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			return fr.WriteData(streamID, endStream, data)
		}
		{
			writeMu.Lock()
			err = fr.WriteSettings()
			writeMu.Unlock()
			if err != nil {
				resCh <- serverResult{err: err}
				return
			}
		}

		var (
			winMu      sync.Mutex
			winCond    = sync.NewCond(&winMu)
			connWin    = int64(initialWindowSize)
			streamWin  = int64(initialWindowSize)
			closed     bool
			streamDone = make(chan error, 1)
			sawReq     bool
			postWUs    []WindowUpdateFrame
		)

		sendStream := func(sid uint32) {
			var hdrBuf bytes.Buffer
			enc := hpack.NewEncoder(&hdrBuf)
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			if err := writeHeaders(HeadersFrameParam{
				StreamID:      sid,
				BlockFragment: hdrBuf.Bytes(),
				EndStream:     false,
				EndHeaders:    true,
			}); err != nil {
				streamDone <- err
				return
			}
			for off := 0; off < len(payload); {
				end := off + chunkSize
				if end > len(payload) {
					end = len(payload)
				}
				n := int64(end - off)
				winMu.Lock()
				for !closed && (connWin < n || streamWin < n) {
					winCond.Wait()
				}
				if closed {
					winMu.Unlock()
					streamDone <- nil
					return
				}
				connWin -= n
				streamWin -= n
				winMu.Unlock()

				if err := writeData(sid, end == len(payload), payload[off:end]); err != nil {
					streamDone <- err
					return
				}
				off = end
			}
			streamDone <- nil
		}

		for {
			f, err := fr.ReadFrame()
			if err != nil {
				winMu.Lock()
				closed = true
				winCond.Broadcast()
				winMu.Unlock()
				if sawReq {
					<-streamDone
				}
				resCh <- serverResult{wus: postWUs}
				return
			}
			switch f := f.(type) {
			case *SettingsFrame:
				if !f.IsAck() {
					_ = f.ForeachSetting(func(s Setting) error {
						if s.ID == SettingInitialWindowSize {
							winMu.Lock()
							streamWin = int64(s.Val)
							winCond.Broadcast()
							winMu.Unlock()
						}
						return nil
					})
					if err := writeSettingsAck(); err != nil {
						resCh <- serverResult{err: err}
						return
					}
				}
			case *WindowUpdateFrame:
				if sawReq {
					postWUs = append(postWUs, *f)
				}
				winMu.Lock()
				if f.StreamID == 0 {
					connWin += int64(f.Increment)
				} else {
					streamWin += int64(f.Increment)
				}
				winCond.Broadcast()
				winMu.Unlock()
			case *MetaHeadersFrame:
				var reqPath string
				for _, hf := range f.Fields {
					if hf.Name == ":path" {
						reqPath = hf.Value
						break
					}
				}
				if reqPath == "/done" {
					if sawReq {
						if err := <-streamDone; err != nil {
							resCh <- serverResult{err: err}
							return
						}
					}
					var hdrBuf bytes.Buffer
					enc := hpack.NewEncoder(&hdrBuf)
					_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					_ = writeHeaders(HeadersFrameParam{
						StreamID:      f.StreamID,
						BlockFragment: hdrBuf.Bytes(),
						EndStream:     true,
						EndHeaders:    true,
					})
					winMu.Lock()
					closed = true
					winCond.Broadcast()
					winMu.Unlock()
					resCh <- serverResult{wus: postWUs}
					return
				}
				sawReq = true
				go sendStream(f.StreamID)
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

	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://" + ln.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("GET /stream failed: %v", err)
	}
	gotBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(/stream) failed: %v", err)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d bytes", len(gotBody), len(payload))
	}

	// Issue a follow-up request on the same HTTP/2 connection so the server frame
	// reader deterministically drains all post-read WINDOW_UPDATE frames before stopping.
	doneResp, err := client.Get("https://" + ln.Addr().String() + "/done")
	if err != nil {
		t.Fatalf("GET /done failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, doneResp.Body)
	doneResp.Body.Close()

	res := <-resCh
	if res.err != nil {
		t.Fatalf("server error: %v", res.err)
	}
	return res.wus
}

func TestFingerprintDynamicWindowRefresh(t *testing.T) {
	payload := make([]byte, 512<<10)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatal(err)
	}

	t.Run("chrome_suppresses_small_ticks", func(t *testing.T) {
		fp := FingerprintChrome()
		wus := runDownloadCaptureWindowUpdates(t, fp, payload, 16<<10)
		if len(wus) != 0 {
			t.Fatalf("expected 0 post-preface WINDOW_UPDATE frames for 512 KiB under Chrome profile, got %d: %+v", len(wus), wus)
		}
	})

	t.Run("nil_profile_emits_4k_ticks", func(t *testing.T) {
		wus := runDownloadCaptureWindowUpdates(t, nil, payload, 16<<10)
		if len(wus) == 0 {
			t.Fatal("expected vanilla http2 (fp=nil) to emit post-preface WINDOW_UPDATE frames for 512 KiB")
		}
	})

	t.Run("custom_threshold_batches_stream_and_conn", func(t *testing.T) {
		const (
			streamWin = 256 << 10
			connFlow  = 256 << 10
			threshold = 64 << 10
		)
		fp := &FingerprintProfile{
			Name: "batched",
			Settings: []Setting{
				{ID: SettingInitialWindowSize, Val: streamWin},
			},
			ConnectionFlow:           connFlow,
			ConnWindowRefreshBytes:   threshold,
			StreamWindowRefreshBytes: threshold,
		}
		// Total 384 KiB exceeds 256 KiB stream window, forcing stream+conn WINDOW_UPDATEs.
		bigPayload := payload[:384<<10]
		wus := runDownloadCaptureWindowUpdates(t, fp, bigPayload, 16<<10)
		var streamUpdates int
		for _, wu := range wus {
			if wu.Increment < threshold {
				t.Fatalf("observed sub-threshold WINDOW_UPDATE (stream=%d inc=%d < %d)", wu.StreamID, wu.Increment, threshold)
			}
			if wu.StreamID > 0 {
				streamUpdates++
			}
		}
		if streamUpdates == 0 {
			t.Fatal("expected at least one batched stream WINDOW_UPDATE during 384 KiB / 256 KiB transfer")
		}
	})
}

func TestFingerprintHPACKSensitiveHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type hpackResult struct {
		reqs [][]hpack.HeaderField
		err  error
	}
	resCh := make(chan hpackResult, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- hpackResult{err: err}
			return
		}
		defer conn.Close()

		preface := make([]byte, len(clientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			resCh <- hpackResult{err: err}
			return
		}

		fr := NewFramer(conn, conn)
		// Deliberately leave fr.ReadMetaHeaders nil so we decode raw HPACK fragments manually.
		if err := fr.WriteSettings(); err != nil {
			resCh <- hpackResult{err: err}
			return
		}

		dec := hpack.NewDecoder(65536, nil)
		var captured [][]hpack.HeaderField
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				resCh <- hpackResult{err: err}
				return
			}
			switch f := f.(type) {
			case *SettingsFrame:
				if !f.IsAck() {
					if err := fr.WriteSettingsAck(); err != nil {
						resCh <- hpackResult{err: err}
						return
					}
				}
			case *HeadersFrame:
				var fields []hpack.HeaderField
				dec.SetEmitFunc(func(hf hpack.HeaderField) {
					fields = append(fields, hf)
				})
				if _, err := dec.Write(f.HeaderBlockFragment()); err != nil {
					resCh <- hpackResult{err: err}
					return
				}
				if err := dec.Close(); err != nil {
					resCh <- hpackResult{err: err}
					return
				}
				captured = append(captured, fields)

				var hdrBuf bytes.Buffer
				enc := hpack.NewEncoder(&hdrBuf)
				_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				if err := fr.WriteHeaders(HeadersFrameParam{
					StreamID:      f.StreamID,
					BlockFragment: hdrBuf.Bytes(),
					EndStream:     true,
					EndHeaders:    true,
				}); err != nil {
					resCh <- hpackResult{err: err}
					return
				}
				if len(captured) == 2 {
					resCh <- hpackResult{reqs: captured}
					return
				}
			}
		}
	}()

	tr := &Transport{
		AllowHTTP:   true,
		Fingerprint: FingerprintChrome(),
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr}
	for range 2 {
		req, err := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/auth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Cookie", "sid=secret-session-value")
		req.Header.Set("Authorization", "Bearer top-secret-token")
		req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
		req.Header.Set("X-Normal", "regular-header-value")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("server error: %v", res.err)
	}
	for reqIdx, fields := range res.reqs {
		seen := make(map[string]bool)
		for _, hf := range fields {
			seen[hf.Name] = hf.Sensitive
		}
		for _, sens := range []string{"cookie", "authorization", "proxy-authorization"} {
			if isSens, ok := seen[sens]; !ok || !isSens {
				t.Fatalf("req %d header %q Sensitive=%v (present=%v), expected Never Indexed (true)", reqIdx, sens, isSens, ok)
			}
		}
		if isSens, ok := seen["x-normal"]; !ok || isSens {
			t.Fatalf("req %d header x-normal Sensitive=%v (present=%v), expected false", reqIdx, isSens, ok)
		}
	}
}

func TestFingerprintPriorityUpdate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type prioResult struct {
		reqStreamID uint32
		updates     []PriorityUpdateFrame
		err         error
	}
	resCh := make(chan prioResult, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- prioResult{err: err}
			return
		}
		defer conn.Close()

		preface := make([]byte, len(clientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			resCh <- prioResult{err: err}
			return
		}
		fr := NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
		if err := fr.WriteSettings(); err != nil {
			resCh <- prioResult{err: err}
			return
		}

		var (
			sid     uint32
			updates []PriorityUpdateFrame
		)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				resCh <- prioResult{err: err}
				return
			}
			switch f := f.(type) {
			case *SettingsFrame:
				if !f.IsAck() {
					if err := fr.WriteSettingsAck(); err != nil {
						resCh <- prioResult{err: err}
						return
					}
				}
			case *MetaHeadersFrame:
				sid = f.StreamID
			case *PriorityUpdateFrame:
				if f.StreamID != 0 {
					resCh <- prioResult{err: fmt.Errorf("PRIORITY_UPDATE frame must be on stream 0, got %d", f.StreamID)}
					return
				}
				updates = append(updates, *f)
				if sid != 0 {
					var hdrBuf bytes.Buffer
					enc := hpack.NewEncoder(&hdrBuf)
					_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					_ = fr.WriteHeaders(HeadersFrameParam{
						StreamID:      sid,
						BlockFragment: hdrBuf.Bytes(),
						EndStream:     true,
						EndHeaders:    true,
					})
					resCh <- prioResult{reqStreamID: sid, updates: updates}
					return
				}
			}
		}
	}()

	fp := FingerprintFirefox()
	fp.HeaderPriorityUpdate = "u=3, i"
	tr := &Transport{
		AllowHTTP:   true,
		Fingerprint: fp,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()

	ctx := ContextWithPriorityUpdate(context.Background(), "u=0")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ln.Addr().String()+"/prio", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	resp.Body.Close()

	res := <-resCh
	if res.err != nil {
		t.Fatalf("server error: %v", res.err)
	}
	if len(res.updates) != 1 {
		t.Fatalf("expected 1 PRIORITY_UPDATE frame, got %d", len(res.updates))
	}
	if res.updates[0].PrioritizedStreamID != res.reqStreamID {
		t.Fatalf("PrioritizedStreamID mismatch: got %d, want %d", res.updates[0].PrioritizedStreamID, res.reqStreamID)
	}
	if res.updates[0].Priority != "u=0" {
		t.Fatalf("Priority value mismatch: got %q, want %q", res.updates[0].Priority, "u=0")
	}
}
