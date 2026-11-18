package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The endpoint routes (docs/design/lane-provider-routes.md §4): an entry's egress carries a request for a provider's
// API, a route set up with an address and a key, to the host the entry's table names for the route, never to a host
// the request names. It is on only with -routes, which config refuses beside -relay-listen, and it is served on the
// unix socket only; the relay listener refuses its paths by name (relayCall), with or without the flag.
//
//   - PUT /v1/routes replaces the whole table, versioned as the pin table (peer.go): a row is
//     `{route, host, path_prefix, not_after}`.
//   - /route/<id>/<path> is a request to the host of <id>'s live row: `https://<host><path>` with the path's raw
//     bytes, when <path> starts with the row's path prefix. The request's Host is ignored (the entry sends the fixed
//     route.gray.invalid). An id without a live row is route_unknown, a 502, before any dial.
//
// The outbound call is a direct vendor call's: the image's roots, HTTP/2, no proxy, no redirect followed, the same
// timeouts and body bound, outboundHeader, and the dial rule (dial_guard.go) after DNS, so a row whose name resolves
// to a private or internal address is refused at the dial. The table is defence in depth: only the entry's code
// reaches the unix socket, so a row limits what a bug in the entry could do.
const (
	endpointRoutePrefix = "/route/"
	routesControlPath   = "/v1/routes"
	// routeVersionHeader is the entry registry's start epoch, routePushHeader its push counter within it: both a u64
	// in decimal text, one each, compared in that order as the pin table's.
	routeVersionHeader = "X-Gray-Route-Version"
	routePushHeader    = "X-Gray-Route-Push"
	// The routes in the request log: no id, host, path or query reaches a log line (errors.go).
	endpointRouteLogName = "/route"
	routesControlLogName = "/v1/routes"
	// routeMaxRows has no measured source: one row per endpoint route the entry serves, and this only stops a broken
	// caller (design §4.2).
	routeMaxRows = 4096
	// routeRowMaxTTL: a row's not_after is at most an hour away, as a pin's.
	routeRowMaxTTL = time.Hour
	// routeIDMaxBytes bounds an id, 1-64 of [a-z0-9_-] (design §4.1).
	routeIDMaxBytes = 64
	// dnsNameMaxBytes and dnsLabelMaxBytes are RFC 1035's (section 2.3.4) in text form.
	dnsNameMaxBytes  = 253
	dnsLabelMaxBytes = 63
)

// routeRefusedZones are the names no row's host may be or be under, besides -route-deny-suffix: special-use and
// private names, none of which is a public provider's API host.
var routeRefusedZones = []string{
	"invalid",   // RFC 6761 §6.4: never resolves
	"local",     // RFC 6762: multicast DNS, the local link
	"internal",  // ICANN's private-use TLD (2024)
	"localhost", // RFC 6761 §6.3: the loopback
	"test",      // RFC 6761 §6.2: testing
	"example",   // RFC 6761 §6.5: documentation
	"arpa",      // RFC 3172 infrastructure: the reverse trees (RFC 6761 §6.1 names the private ranges') and home.arpa (RFC 8375)
	"onion",     // RFC 7686: Tor onion services
}

// endpointRoute is one row of the table. Its fields never change: a new table makes new rows, and carries an unchanged
// row's transport over (same id and host), so its pooled connections stay.
type endpointRoute struct {
	id         string
	host       string
	pathPrefix string
	notAfter   time.Time
	transport  *http.Transport
	client     *http.Client
}

// endpointRouteTable is the table and the per-row transports.
type endpointRouteTable struct {
	srv *server
	// now is time.Now in production; a test replaces it to expire a row without waiting.
	now func() time.Time

	mu   sync.Mutex
	rows map[string]*endpointRoute // by route id
	// version and push are the highest pair a table was accepted under; set is false until the first table.
	version uint64
	push    uint64
	set     bool
}

func newEndpointRouteTable(srv *server) *endpointRouteTable {
	return &endpointRouteTable{srv: srv, now: time.Now, rows: map[string]*endpointRoute{}}
}

// isRoutePath is every path of the endpoint routes, the rule the relay listener refuses them by.
func isRoutePath(path string) bool {
	return path == "/route" || strings.HasPrefix(path, endpointRoutePrefix) ||
		path == routesControlPath || strings.HasPrefix(path, routesControlPath+"/")
}

// newRouteTransport is one row's transport: a direct vendor transport (newTransport: the roots, HTTP/2, the timeouts
// and the dial with its rule), with no proxy, since the route kind has none.
func (s *server) newRouteTransport() *http.Transport {
	transport := newTransport(s.cfg, s.roots, routeRowDial(s.cfg, s.dial), true)
	transport.Proxy = nil
	transport.OnProxyConnectResponse = nil
	return transport
}

// routeClient never follows a redirect: it is the provider's answer, and following one would leave the row's host.
func routeClient(transport *http.Transport) *http.Client {
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// endpointRoutePlan is a /route/ request after every check before a dial: the vendor-call plan (route name, the row's
// host, the target) and the row's client.
type endpointRoutePlan struct {
	request requestPlan
	client  *http.Client
}

// plan checks a /route/ request in the order of design §4.1 and never dials, resolves or reads the body:
//
//  1. CONNECT (egress_method_refused), then a target that is not origin-form or holds a raw '#'
//     (egress_target_refused), as the vendor routes;
//  2. an id that is not 1-64 of [a-z0-9_-], or no '/' after it: egress_route_refused;
//  3. a method outside the vendor routes' set: egress_method_refused;
//  4. a raw path validRawPath refuses, a remainder that starts with "//" (url.URL.RequestURI would make it an
//     absolute-form target naming a host), or a remainder with a dot segment in any spelling (hasDotSegment; a server
//     that resolves it would leave the row's path prefix): egress_path_refused; then the row, where it is first needed:
//     none live is route_unknown (502); a remainder that does not start with the row's path prefix is
//     egress_path_refused;
//  5. any x-gray-egress header: egress_spec_refused (the route kind has no proxy).
//
// The body's limits come after it, in serveEndpointRoute.
func (t *endpointRouteTable) plan(r *http.Request) (endpointRoutePlan, string) {
	var plan endpointRoutePlan
	if r.Method == http.MethodConnect {
		return plan, errMethodRefused
	}
	if r.URL == nil || r.URL.IsAbs() || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.Opaque != "" || r.URL.Fragment != "" ||
		strings.Contains(r.RequestURI, "#") {
		return plan, errTargetRefused
	}
	path := rawPathOf(r)
	rest, prefixed := strings.CutPrefix(path, endpointRoutePrefix)
	id, tail, slashed := strings.Cut(rest, "/")
	if !prefixed || !slashed || !validRouteID(id) {
		return plan, errRouteRefused
	}
	if !allowedMethod(r.Method) {
		return plan, errMethodRefused
	}
	remainder := "/" + tail
	if !validRawPath(path) || strings.HasPrefix(remainder, "//") || hasDotSegment(remainder) {
		return plan, errPathRefused
	}
	row := t.lookup(id)
	if row == nil {
		return plan, errRouteUnknown
	}
	if !strings.HasPrefix(remainder, row.pathPrefix) {
		return plan, errPathRefused
	}
	if len(r.Header.Values(egressHeader)) != 0 {
		return plan, errSpecRefused
	}
	plan.request = requestPlan{
		route: route{name: endpointRouteLogName, host: row.host},
		// D59/D76 as the vendor routes: the target is built from parts, the path's raw bytes in Opaque.
		target: &url.URL{Scheme: "https", Host: row.host, Opaque: remainder, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery},
	}
	plan.client = row.client
	return plan, ""
}

// serveEndpointRoute is a request under /route/: the plan, the body, the plan again, then the row's host.
func (s *server) serveEndpointRoute(rec *responseRecorder, r *http.Request, entry *requestLog) {
	entry.Route = endpointRouteLogName
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	if _, code := s.routes.plan(r); code != "" {
		refuse(code)
		return
	}
	body, readBytes, err := readRequestBody(r, s.cfg.maxBodyBytes)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		refuse(code)
		return
	}
	// Again after the body, which may take minutes: the row may have ended or been replaced while it was read, and the
	// request goes to the table as it is now.
	plan, code := s.routes.plan(r)
	if code != "" {
		refuse(code)
		return
	}
	entry.Error = s.forward(r.Context(), plan.client, rec, r.Method, plan.request, outboundHeader(r.Header), body, nil)
}

// serveRoutesControl is /v1/routes: the table, PUT only.
func (s *server) serveRoutesControl(rec *responseRecorder, r *http.Request, entry *requestLog) {
	entry.Route = routesControlLogName
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	switch {
	case r.Method == http.MethodConnect:
		refuse(errMethodRefused)
	case r.URL == nil || r.URL.IsAbs() || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.Opaque != "" || r.URL.Fragment != "" ||
		strings.ContainsAny(r.RequestURI, "?#"):
		refuse(errTargetRefused)
	case rawPathOf(r) != routesControlPath:
		refuse(errRouteRefused)
	case r.Method != http.MethodPut:
		refuse(errMethodRefused)
	default:
		s.putRoutes(rec, r, entry)
	}
}

// wireRoute is one row as the entry sends it (design §4.2; test/route-table.json): route is the endpoint id, host the
// provider's API host (443 implied), path_prefix the path every request on the row starts with, and not_after Unix
// seconds, the first second the row no longer holds.
type wireRoute struct {
	Route      *string `json:"route"`
	Host       *string `json:"host"`
	PathPrefix *string `json:"path_prefix"`
	NotAfter   *uint64 `json:"not_after"`
}

// routeRowMembers are a row's members, all required and nothing else.
var routeRowMembers = []string{"route", "host", "path_prefix", "not_after"}

// exactRouteMembers holds every row to routeRowMembers by their exact names: encoding/json matches a struct's field
// names without regard to case, so `{"Route": ...}` would otherwise pass as route. checkStrictJSON has already refused
// a repeated member, so the map loses nothing.
func exactRouteMembers(body []byte) bool {
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(body, &rows); err != nil {
		return false
	}
	for _, row := range rows {
		if len(row) != len(routeRowMembers) {
			return false
		}
		for _, name := range routeRowMembers {
			if _, ok := row[name]; !ok {
				return false
			}
		}
	}
	return true
}

// putRoutes replaces the table. A row whose not_after has passed is accepted and never dialed: the table is the
// entry's, and expiry is judged at each use.
func (s *server) putRoutes(rec *responseRecorder, r *http.Request, entry *requestLog) {
	body, readBytes, err := readRequestBody(r, s.cfg.maxBodyBytes)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		entry.Error = code
		writeRefusal(rec, code)
		return
	}
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	version, versionOK := stackU64Header(r.Header, routeVersionHeader)
	push, pushOK := stackU64Header(r.Header, routePushHeader)
	var rows []wireRoute
	if !versionOK || !pushOK || checkStrictJSON(body) != nil || !exactRouteMembers(body) || !decodeControl(body, &rows) || rows == nil ||
		len(rows) > routeMaxRows {
		refuse(errRouteControlInvalid)
		return
	}
	// At most an hour from the current second rounded up, as a pin's.
	now := s.routes.now()
	ceiling := now.Unix() + int64(routeRowMaxTTL/time.Second)
	if now.Nanosecond() > 0 {
		ceiling++
	}
	parsed := make([]*endpointRoute, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		parsedRow, ok := parseRouteRow(row, ceiling, s.cfg.routeDenySuffixes)
		if !ok || seen[parsedRow.id] {
			refuse(errRouteControlInvalid)
			return
		}
		seen[parsedRow.id] = true
		parsed = append(parsed, parsedRow)
	}
	if !s.routes.replace(version, push, parsed) {
		refuse(errRoutesStale)
		return
	}
	rec.WriteHeader(http.StatusNoContent)
}

// parseRouteRow is one row under design §4.2's rules; deny is -route-deny-suffix.
func parseRouteRow(row wireRoute, ceiling int64, deny []string) (*endpointRoute, bool) {
	if row.Route == nil || row.Host == nil || row.PathPrefix == nil || row.NotAfter == nil {
		return nil, false
	}
	if !validRouteID(*row.Route) || !validRouteHost(*row.Host, deny) || !validRoutePathPrefix(*row.PathPrefix) || *row.NotAfter > uint64(ceiling) {
		return nil, false
	}
	return &endpointRoute{id: *row.Route, host: *row.Host, pathPrefix: *row.PathPrefix, notAfter: time.Unix(int64(*row.NotAfter), 0)}, true
}

// replace installs a table unless (version, push) is below the highest pair accepted, as the pin table's. A row equal
// to a current one in id and host keeps that row's transport; every other current row's idle connections are closed
// (connections in use finish their request).
func (t *endpointRouteTable) replace(version, push uint64, rows []*endpointRoute) bool {
	t.mu.Lock()
	if t.set && (version < t.version || (version == t.version && push < t.push)) {
		t.mu.Unlock()
		return false
	}
	old := t.rows
	next := make(map[string]*endpointRoute, len(rows))
	for _, row := range rows {
		if kept := old[row.id]; kept != nil && kept.host == row.host {
			row.transport, row.client = kept.transport, kept.client
			delete(old, row.id)
		} else {
			row.transport = t.srv.newRouteTransport()
			row.client = routeClient(row.transport)
		}
		next[row.id] = row
	}
	t.rows, t.version, t.push, t.set = next, version, push, true
	t.mu.Unlock()
	for _, gone := range old {
		gone.transport.CloseIdleConnections()
	}
	return true
}

// lookup is the live row for id, nil when there is none; a row past its not_after is removed here and its idle
// connections closed.
func (t *endpointRouteTable) lookup(id string) *endpointRoute {
	t.mu.Lock()
	row := t.rows[id]
	if row == nil || t.now().Before(row.notAfter) {
		t.mu.Unlock()
		return row
	}
	delete(t.rows, id)
	t.mu.Unlock()
	row.transport.CloseIdleConnections()
	return nil
}

func (t *endpointRouteTable) closeIdleConnections() {
	t.mu.Lock()
	transports := make([]*http.Transport, 0, len(t.rows))
	for _, row := range t.rows {
		transports = append(transports, row.transport)
	}
	t.mu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

// hasDotSegment reports whether a raw path holds a "." or ".." segment in a spelling WHATWG URL's path parser reads as
// one (its single-dot and double-dot path segments: ".", "%2e", "..", ".%2e", "%2e.", "%2e%2e", the hex in either
// case), anywhere, the last segment included. A server that resolves it would reach a path outside the row's prefix, so
// /route/ refuses it; the vendor routes keep forwarding such paths (D62), their prefix being the vendor's whole API. A
// dot inside a segment ("a..b", "...", ".well-known") is no dot segment.
func hasDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		switch strings.ToLower(segment) {
		case ".", "%2e", "..", ".%2e", "%2e.", "%2e%2e":
			return true
		}
	}
	return false
}

// validRouteID is an endpoint id as a path segment: 1-64 of [a-z0-9_-].
func validRouteID(id string) bool {
	if id == "" || len(id) > routeIDMaxBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// validDNSName is a lower-case host name: labels of 1-63 of [a-z0-9-], none starting or ending with '-', at most 253
// bytes, no trailing dot (and so no empty label).
func validDNSName(name string) bool {
	if name == "" || len(name) > dnsNameMaxBytes {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > dnsLabelMaxBytes || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// validRouteHost is a row's host (design §4.2): a lower-case DNS name of at least two labels, whose last label starts
// with a letter, as every top-level domain's does, so no spelling of an IPv4 address passes (WHATWG URL's "ends in a
// number": 10.0.0.1, 127.1, 0x7f.1; an IPv6 literal has a ':', which no label has); no port, no trailing dot, and
// neither one of routeRefusedZones and deny nor under one.
func validRouteHost(host string, deny []string) bool {
	if !validDNSName(host) {
		return false
	}
	dot := strings.LastIndexByte(host, '.')
	if dot < 0 || host[dot+1] < 'a' || host[dot+1] > 'z' {
		return false
	}
	for _, zones := range [][]string{routeRefusedZones, deny} {
		for _, zone := range zones {
			if host == zone || strings.HasSuffix(host, "."+zone) {
				return false
			}
		}
	}
	return true
}

// validRoutePathPrefix is a row's path prefix: it starts and ends with '/', does not start with "//" (a remainder under
// it would, which plan refuses), holds no '?' or '#' (a raw path never does: the query is cut off, a raw '#' refused),
// and passes the vendor routes' path rule (validRawPath).
func validRoutePathPrefix(prefix string) bool {
	return strings.HasPrefix(prefix, "/") && strings.HasSuffix(prefix, "/") && !strings.HasPrefix(prefix, "//") &&
		!strings.ContainsAny(prefix, "?#") && validRawPath(prefix)
}

// suffixList is -route-deny-suffix: repeatable, each value one zone or a comma-separated list. validate checks each.
type suffixList []string

func (l *suffixList) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, ",")
}

func (l *suffixList) Set(value string) error {
	*l = append(*l, strings.Split(value, ",")...)
	return nil
}
