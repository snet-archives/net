// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"context"
	"slices"
	"strings"
)

// PrioritySpec describes an HTTP/2 PRIORITY frame emitted after initial SETTINGS.
type PrioritySpec struct {
	StreamID      uint32
	PriorityParam PriorityParam
}

// FingerprintProfile customizes client HTTP/2 connection preface and header
// wire characteristics (SETTINGS IDs/order, initial connection WINDOW_UPDATE,
// PRIORITY frames, pseudo-header order, and regular header order) while
// preserving RFC 9113 state synchronization on the underlying ClientConn.
type FingerprintProfile struct {
	// Name identifies the browser fingerprint profile (e.g. "chrome", "firefox", "safari").
	Name string

	// Settings overrides the initial HTTP/2 SETTINGS frame entries and their wire order.
	// When non-empty, only these settings are emitted in the exact order specified, and
	// ClientConn decode limits / stream receive windows are synchronized accordingly.
	Settings []Setting

	// ConnectionFlow overrides the connection-level WINDOW_UPDATE increment sent
	// immediately after the initial SETTINGS frame (matching ClientConn.inflow).
	// Zero falls back to Transport defaults unless SkipConnectionFlow is true.
	ConnectionFlow uint32

	// SkipConnectionFlow suppresses the initial connection-level WINDOW_UPDATE frame.
	SkipConnectionFlow bool

	// Priorities emits optional HTTP/2 PRIORITY frames immediately after the
	// initial SETTINGS and connection-level WINDOW_UPDATE frames.
	Priorities []PrioritySpec

	// HeaderPriority, when non-zero, sets Priority on emitted request HEADERS frames.
	HeaderPriority PriorityParam

	// PseudoHeaderOrder defines the wire order of HTTP/2 pseudo-headers
	// (e.g. ":method", ":authority", ":scheme", ":path").
	PseudoHeaderOrder []string

	// HeaderOrder defines the preferred wire order of regular HTTP headers
	// (lowercase names). Headers not listed are emitted deterministically afterwards.
	HeaderOrder []string

	// DefaultUserAgent overrides Go's fallback "Go-http-client/2.0" User-Agent
	// when a request omits User-Agent (explicit nil/empty still suppresses it).
	DefaultUserAgent string

	// ConnWindowRefreshRatio and ConnWindowRefreshBytes configure the minimum
	// consumed-window threshold before emitting a connection-level WINDOW_UPDATE.
	// Explicit positive byte thresholds take precedence over Ratio; both are
	// safely clamped to at most half of the initial receive window. Zero leaves
	// Go's 4 KiB default active.
	ConnWindowRefreshRatio float64
	ConnWindowRefreshBytes int32

	// StreamWindowRefreshRatio and StreamWindowRefreshBytes configure the minimum
	// consumed-window threshold before emitting a stream-level WINDOW_UPDATE.
	StreamWindowRefreshRatio float64
	StreamWindowRefreshBytes int32

	// SensitiveHeaders lists header names (e.g. "cookie", "authorization",
	// "proxy-authorization") to encode using HPACK Never Indexed literals
	// (RFC 7541 Section 7.1.3) rather than adding them to the dynamic table.
	SensitiveHeaders []string

	// HeaderPriorityUpdate, when non-empty, emits an RFC 9218 PRIORITY_UPDATE
	// frame (stream 0 targeting the new request stream) coalesced with HEADERS.
	HeaderPriorityUpdate string
}

// Clone returns a deep copy of the FingerprintProfile, or nil if p is nil.
func (p *FingerprintProfile) Clone() *FingerprintProfile {
	if p == nil {
		return nil
	}
	cp := *p
	if p.Settings != nil {
		cp.Settings = slices.Clone(p.Settings)
	}
	if p.Priorities != nil {
		cp.Priorities = slices.Clone(p.Priorities)
	}
	if p.PseudoHeaderOrder != nil {
		cp.PseudoHeaderOrder = slices.Clone(p.PseudoHeaderOrder)
	}
	if p.HeaderOrder != nil {
		cp.HeaderOrder = slices.Clone(p.HeaderOrder)
	}
	if p.SensitiveHeaders != nil {
		cp.SensitiveHeaders = slices.Clone(p.SensitiveHeaders)
	}
	return &cp
}

type (
	headerOrderContextKey       struct{}
	pseudoHeaderOrderContextKey struct{}
	priorityUpdateContextKey    struct{}
)

// ContextWithHeaderOrder returns a derived context that overrides regular HTTP
// header wire ordering for requests made through an http2.Transport.
func ContextWithHeaderOrder(ctx context.Context, order []string) context.Context {
	return context.WithValue(ctx, headerOrderContextKey{}, slices.Clone(order))
}

// HeaderOrderFromContext returns any per-request regular header order stored on ctx.
func HeaderOrderFromContext(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	order, _ := ctx.Value(headerOrderContextKey{}).([]string)
	return order
}

// ContextWithPseudoHeaderOrder returns a derived context that overrides HTTP/2
// pseudo-header wire ordering for requests made through an http2.Transport.
func ContextWithPseudoHeaderOrder(ctx context.Context, order []string) context.Context {
	return context.WithValue(ctx, pseudoHeaderOrderContextKey{}, slices.Clone(order))
}

// PseudoHeaderOrderFromContext returns any per-request pseudo-header order stored on ctx.
func PseudoHeaderOrderFromContext(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	order, _ := ctx.Value(pseudoHeaderOrderContextKey{}).([]string)
	return order
}

// ContextWithPriorityUpdate returns a derived context that emits an RFC 9218
// PRIORITY_UPDATE frame payload (e.g. "u=0, i") for requests made through an http2.Transport.
func ContextWithPriorityUpdate(ctx context.Context, priority string) context.Context {
	return context.WithValue(ctx, priorityUpdateContextKey{}, priority)
}

// PriorityUpdateFromContext returns any per-request PRIORITY_UPDATE value stored on ctx.
func PriorityUpdateFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	p, _ := ctx.Value(priorityUpdateContextKey{}).(string)
	return p
}

var defaultBrowserSensitiveHeaders = []string{
	"cookie",
	"authorization",
	"proxy-authorization",
}

func resolveWindowRefresh(window, explicit int32, ratio float64) int32 {
	if window <= inflowMinRefresh {
		return inflowMinRefresh
	}
	half := window / 2
	var target int32
	if explicit > 0 {
		target = explicit
	} else if ratio > 0 {
		if ratio > 0.5 {
			ratio = 0.5
		}
		target = int32(float64(window) * ratio)
	}
	if target <= inflowMinRefresh {
		return inflowMinRefresh
	}
	if half > inflowMinRefresh && target > half {
		target = half
	}
	return target
}

var (
	chromeHeaderOrder = []string{
		"cache-control",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"accept-language",
		"cookie",
		"priority",
	}

	firefoxHeaderOrder = []string{
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"referer",
		"upgrade-insecure-requests",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-user",
		"priority",
		"cookie",
		"te",
	}

	safariHeaderOrder = []string{
		"sec-fetch-dest",
		"user-agent",
		"accept",
		"referer",
		"sec-fetch-site",
		"sec-fetch-mode",
		"accept-language",
		"priority",
		"accept-encoding",
		"cookie",
	}
)

// FingerprintChrome returns an Akamai-aligned HTTP/2 fingerprint profile for modern Chrome.
func FingerprintChrome() *FingerprintProfile {
	return &FingerprintProfile{
		Name: "chrome",
		Settings: []Setting{
			{ID: SettingHeaderTableSize, Val: 65536},
			{ID: SettingEnablePush, Val: 0},
			{ID: SettingInitialWindowSize, Val: 6291456},
			{ID: SettingMaxHeaderListSize, Val: 262144},
		},
		ConnectionFlow:           15663105,
		PseudoHeaderOrder:        []string{":method", ":authority", ":scheme", ":path"},
		HeaderOrder:              slices.Clone(chromeHeaderOrder),
		DefaultUserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
		ConnWindowRefreshRatio:   0.5,
		StreamWindowRefreshRatio: 0.5,
		SensitiveHeaders:         slices.Clone(defaultBrowserSensitiveHeaders),
	}
}

// FingerprintEdge returns an Akamai-aligned HTTP/2 fingerprint profile for modern Edge.
func FingerprintEdge() *FingerprintProfile {
	fp := FingerprintChrome()
	fp.Name = "edge"
	fp.DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"
	return fp
}

// FingerprintAndroid returns an Akamai-aligned HTTP/2 fingerprint profile for Android Chrome.
func FingerprintAndroid() *FingerprintProfile {
	fp := FingerprintChrome()
	fp.Name = "android"
	fp.DefaultUserAgent = "Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36"
	return fp
}

// FingerprintFirefox returns an Akamai-aligned HTTP/2 fingerprint profile for modern Firefox.
func FingerprintFirefox() *FingerprintProfile {
	return &FingerprintProfile{
		Name: "firefox",
		Settings: []Setting{
			{ID: SettingHeaderTableSize, Val: 65536},
			{ID: SettingInitialWindowSize, Val: 131072},
			{ID: SettingMaxFrameSize, Val: 16384},
			{ID: SettingNoRFC7540Priorities, Val: 1},
		},
		ConnectionFlow:           12517377,
		PseudoHeaderOrder:        []string{":method", ":path", ":authority", ":scheme"},
		HeaderOrder:              slices.Clone(firefoxHeaderOrder),
		DefaultUserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
		ConnWindowRefreshRatio:   0.5,
		StreamWindowRefreshRatio: 0.5,
		SensitiveHeaders:         slices.Clone(defaultBrowserSensitiveHeaders),
	}
}

// FingerprintFirefox120 returns an Akamai-aligned HTTP/2 fingerprint profile for Firefox 120.
func FingerprintFirefox120() *FingerprintProfile {
	fp := FingerprintFirefox()
	fp.Name = "firefox_120"
	fp.Settings = []Setting{
		{ID: SettingHeaderTableSize, Val: 65536},
		{ID: SettingInitialWindowSize, Val: 131072},
		{ID: SettingMaxFrameSize, Val: 16384},
	}
	fp.DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
	return fp
}

// FingerprintSafari returns an Akamai-aligned HTTP/2 fingerprint profile for modern macOS Safari.
func FingerprintSafari() *FingerprintProfile {
	return &FingerprintProfile{
		Name: "safari",
		Settings: []Setting{
			{ID: SettingEnablePush, Val: 0},
			{ID: SettingMaxConcurrentStreams, Val: 100},
			{ID: SettingInitialWindowSize, Val: 4194304},
			{ID: SettingNoRFC7540Priorities, Val: 1},
		},
		ConnectionFlow:           10420225,
		PseudoHeaderOrder:        []string{":method", ":scheme", ":path", ":authority"},
		HeaderOrder:              slices.Clone(safariHeaderOrder),
		DefaultUserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
		ConnWindowRefreshRatio:   0.5,
		StreamWindowRefreshRatio: 0.5,
		SensitiveHeaders:         slices.Clone(defaultBrowserSensitiveHeaders),
	}
}

// FingerprintSafari16 returns an Akamai-aligned HTTP/2 fingerprint profile for Safari 16.
func FingerprintSafari16() *FingerprintProfile {
	fp := FingerprintSafari()
	fp.Name = "safari_16"
	fp.Settings = []Setting{
		{ID: SettingEnablePush, Val: 0},
		{ID: SettingInitialWindowSize, Val: 4194304},
		{ID: SettingMaxConcurrentStreams, Val: 100},
	}
	fp.ConnectionFlow = 10485760
	fp.DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15"
	return fp
}

// FingerprintIOS returns an Akamai-aligned HTTP/2 fingerprint profile for iOS Safari.
func FingerprintIOS() *FingerprintProfile {
	fp := FingerprintSafari()
	fp.Name = "ios"
	fp.Settings = []Setting{
		{ID: SettingEnablePush, Val: 0},
		{ID: SettingMaxConcurrentStreams, Val: 100},
		{ID: SettingInitialWindowSize, Val: 2097152},
		{ID: SettingNoRFC7540Priorities, Val: 1},
	}
	fp.DefaultUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
	return fp
}

func normalizeProfileToken(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	if start == end {
		return ""
	}
	b := make([]byte, end-start)
	for i := start; i < end; i++ {
		b[i-start] = lower(s[i])
	}
	return string(b)
}

// FingerprintForName maps a browser or uTLS client name to a matching HTTP/2
// fingerprint profile. Unknown non-empty names fall back to FingerprintChrome;
// empty returns nil so native Go transport behavior is preserved.
func FingerprintForName(name string) *FingerprintProfile {
	normalized := normalizeProfileToken(name)
	if normalized == "" {
		return nil
	}
	switch {
	case normalized == "firefox_120" || normalized == "firefox120":
		return FingerprintFirefox120()
	case strings.Contains(normalized, "firefox"):
		return FingerprintFirefox()
	case strings.Contains(normalized, "safari_16") || strings.Contains(normalized, "safari16"):
		return FingerprintSafari16()
	case strings.Contains(normalized, "ios"):
		return FingerprintIOS()
	case strings.Contains(normalized, "safari"):
		return FingerprintSafari()
	case strings.Contains(normalized, "edge"):
		return FingerprintEdge()
	case strings.Contains(normalized, "android"):
		return FingerprintAndroid()
	case normalized == "chrome" || normalized == "randomized" || normalized == "random" ||
		normalized == "360" || normalized == "qq" || strings.HasPrefix(normalized, "chrome"):
		return FingerprintChrome()
	default:
		return FingerprintChrome()
	}
}

// FingerprintForUTLS maps a uTLS ClientHelloID (client + optional version) to a
// matching HTTP/2 fingerprint profile. Returns nil when client is empty.
func FingerprintForUTLS(client, version string) *FingerprintProfile {
	c := normalizeProfileToken(client)
	v := normalizeProfileToken(version)
	if c == "" {
		return nil
	}
	if v != "" {
		if strings.Contains(c, "firefox") && strings.HasPrefix(v, "120") {
			return FingerprintFirefox120()
		}
		if strings.Contains(c, "safari") && strings.HasPrefix(v, "16") {
			return FingerprintSafari16()
		}
	}
	return FingerprintForName(c)
}
