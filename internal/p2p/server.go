package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/chainhash"
	"legacycoin/legacy-go/internal/mempool"
	"legacycoin/legacy-go/internal/wire"
)

const (
	protocolVersion       int32  = 70015
	nodeNetwork           uint64 = 1
userAgent = "/Legacy-GO:1.0.20/"
	maxPeers                     = 125
	maxOutboundPeers             = 16
	maxGetDataItems              = 1000
	maxServeInvItems             = 256
	peerWriteTimeout             = 60 * time.Second
	maxAddrRelayItems            = 10
	maxAddrDialItems             = 8
	maxAddrDialsPerPeer          = 16
	maxKnownPeerAddresses        = 2048
	addrMaxAge                   = 7 * 24 * time.Hour
	dnsSeedLookupTimeout         = 5 * time.Second
)

var (
	peerHandshakeTimeout = 2 * time.Minute
	peerIdleTimeout      = 2 * time.Minute
	peerPingInterval     = 30 * time.Second
	peerPongTimeout      = 90 * time.Second
	peerReconnectEvery   = 8 * time.Second
	syncWatchdogEvery    = 20 * time.Second
	syncStaleThreshold   = 10 * time.Minute
)

var (
	peerStaleThresholdMu sync.RWMutex
	peerStaleThreshold   = 15 * time.Minute
)

func getPeerStaleThreshold() time.Duration {
	peerStaleThresholdMu.RLock()
	defer peerStaleThresholdMu.RUnlock()
	return peerStaleThreshold
}

func setPeerStaleThreshold(d time.Duration) {
	peerStaleThresholdMu.Lock()
	defer peerStaleThresholdMu.Unlock()
	peerStaleThreshold = d
}

const (
	// getdataTimeout is how long we wait for a block requested via getdata
	// before marking it timed out and re-requesting from an alternative peer.
	getdataTimeout = 2 * time.Minute

	// getdataCleanupInterval is how often the watchdog sweeps timed-out
	// getdata requests.
	getdataCleanupInterval = 30 * time.Second

	// missingParentTTL stops us hammering one peer for the same missing
	// parent block over and over. missingParentEvictTTL bounds memory.
	missingParentTTL      = 2 * time.Minute
	missingParentEvictTTL = 10 * time.Minute
	missingParentSeenCap  = 2048
	// maxMissingParentPeers is how many ahead peers (besides the one that
	// relayed the orphan) we ask for the missing parent, so a single
	// unhelpful peer cannot stall synchronisation indefinitely.
	maxMissingParentPeers = 4
	missingParentWriteTO  = 5 * time.Second
)

const (
	MaxPeers         = maxPeers
	MaxOutboundPeers = maxOutboundPeers
)

type getdataReq struct {
	hash       string
	peer       string
	requested  time.Time
}

type peer struct {
	conn              net.Conn
	outbound          bool
	remote            string
	writeMu           sync.Mutex
	lastMu            sync.Mutex
	connected         time.Time
	lastSeen          time.Time
	lastPong          time.Time
	lastHeightUpdate  time.Time
	lastPing          time.Time
	lastRTT           time.Duration
	minRTT            time.Duration
	missedPongs       int
	version           int32
	subver            string
	height            int32
	chainID           string
	banScore          int
	bytesSent         uint64
	bytesRecv         uint64
	lastSyncRequest   time.Time
	lastSyncError     string
	lastBlockReject   string
	lastLocatorTip    string
	lastBlockHash     string
	lastBlockPrev     string
	lastBlockHeight   int32
	lastBestUpdate    string
	lastBlockReason   string
	lastHeaderRecv    time.Time
	lastBlockRecv     time.Time
	blocksRequested   int
	blocksServed      int
	syncFailures      int
	syncSuccesses     int
	lastPenaltyAt     time.Time
	lastPenaltyReason string
	rateLimited       bool
	addrDialCount     int
	wantHeaders       bool
	bannedUntil       time.Time
	rateWindowStart   time.Time
	rateWindowCount   int
}

type knownPeerAddress struct {
	Addr          string
	Source        string
	LastSeen      time.Time
	LastConnected time.Time
	LastFailure   time.Time
	Successes     int
	Failures      int
	LastDirection string
}

type Server struct {
	params            chaincfg.Params
	chain             *blockchain.Chain
	pool              *mempool.Pool
	log               *log.Logger
	pretty            bool
	heartbeat         bool
	compactHeartbeat  bool
	showLatency       bool
	showPeerHeight    bool
	trustedPeerName   string
	heartbeatInterval time.Duration
	pingInterval      time.Duration
	chainID           string
	enforceChainID    bool
	peerSafety        bool
	banThreshold      int
	banDuration       time.Duration
	maxInboundPeers   int
	maxPerIP          int
	maxPerSubnet      int
	peerRateLimit     int
	globalRateLimit   int
	reconnectBackoff  bool
	reconnectEvery    time.Duration
	misbehaviorDecay  time.Duration
	peerRateWindow    time.Duration
	globalRateWindow  time.Duration
	connectOnly       map[string]struct{}
	seedPeers         bool

	listener            net.Listener
	peers               atomic.Int32
	outbound            atomic.Int32
	knownMu             sync.Mutex
	knownOutbound       map[string]struct{}
	knownAddresses      map[string]knownPeerAddress
	bootstrap           []string
	listenHost          string
	activeMu            sync.Mutex
	activePeers         map[*peer]struct{}
	bannedMu            sync.Mutex
	bannedUntil         map[string]time.Time
	seedMu              sync.Mutex
	seedFailures        map[string]int
	seedLastLog         map[string]time.Time
	rejectMu            sync.Mutex
	rejectCounts        map[string]int
	rejectLastLog       map[string]time.Time
	outboundLastAttempt map[string]time.Time
	rateMu              sync.Mutex
	globalWindowStart   time.Time
	globalWindowCount   int
	healthMu            sync.Mutex
	startedAt           time.Time
	p2pRunning          bool
	syncRunning         bool
	watchdogRun         bool
	lastSyncBeat        time.Time
	lastSyncReq         time.Time
	lastPeerMsg         time.Time
	lastHeaderMsg       time.Time
	lastBlockMsg        time.Time
	lastGetHeader       time.Time
	lastGetBlock        time.Time
	lastWatchdog        time.Time
	lastWdAction        string
	wdReconnects        int64
	outboundDialSem     chan struct{}
	lastBlockConn       time.Time
	lastHeightChg       time.Time
	lastSyncPeer        string
	syncRetryCount      int64
	syncPeerRotations   int64
	blocksAnnounced     int64
	blockInvsReceived   int64
	getDataBlocksRecv   int64
	blocksServed        int64
	blocksRequested     int64
	blockReqTimeouts    int64
	blockMessagesRecv   int64
	headersBatchesRecv  int64
	headersRejected     int64
	// Missing-parent resolution: when a block arrives whose parent is
	// unknown we record it here so we can request that exact parent by
	// hash from the relaying peer (and a few other ahead peers) instead of
	// stalling sync forever waiting for headers that are keyed off the
	// active tip.
	missingParentMu   sync.Mutex
	missingParentSeen map[string]time.Time
	missingParentReqs int64

	// getdataTimeout tracks blocks we have requested via getdata but not yet
	// received. The watchdog uses this to detect unresponsive peers and
	// re-request from alternative peers instead of stalling forever.
	getdataMu     sync.Mutex
	getdataReqs   map[string]*getdataReq // block hash → request info
	wg            sync.WaitGroup
}

func New(params chaincfg.Params, chain *blockchain.Chain, pool *mempool.Pool, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		params:              params,
		chain:               chain,
		pool:                pool,
		log:                 logger,
		knownOutbound:       make(map[string]struct{}),
		knownAddresses:      make(map[string]knownPeerAddress),
		activePeers:         make(map[*peer]struct{}),
		bannedUntil:         make(map[string]time.Time),
		seedFailures:        make(map[string]int),
		seedLastLog:         make(map[string]time.Time),
		rejectCounts:        make(map[string]int),
		rejectLastLog:       make(map[string]time.Time),
		outboundLastAttempt: make(map[string]time.Time),
		missingParentSeen:   make(map[string]time.Time),
		getdataReqs:         make(map[string]*getdataReq),
		chainID:             params.ChainID,
		peerSafety:          true,
		banThreshold:        100,
		banDuration:         time.Hour,
		maxInboundPeers:     64,
		maxPerIP:            8,
		maxPerSubnet:        32,
		peerRateLimit:       250,
		globalRateLimit:     3000,
		reconnectBackoff:    true,
		reconnectEvery:      peerReconnectEvery,
		outboundDialSem:     make(chan struct{}, 32),
		misbehaviorDecay:    5 * time.Minute,
		peerRateWindow:      10 * time.Second,
		globalRateWindow:    10 * time.Second,
		seedPeers:           true,
	}
}

func (s *Server) ListenAddr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) PeerCount() int32 {
	return s.peers.Load()
}

func (s *Server) OutboundCount() int32 {
	return s.outbound.Load()
}

func (s *Server) SetPeerPolicy(chainID string, enforce bool, peerSafety bool, banThreshold int, seedPeers bool, connectOnly []string) {
	if strings.TrimSpace(chainID) != "" {
		s.chainID = strings.TrimSpace(chainID)
	}
	s.enforceChainID = enforce
	s.peerSafety = peerSafety
	if banThreshold > 0 {
		s.banThreshold = banThreshold
	}
	s.seedPeers = seedPeers
	if len(connectOnly) > 0 {
		s.connectOnly = make(map[string]struct{}, len(connectOnly))
		for _, addr := range connectOnly {
			normalized, err := normalizePeerAddress(addr, s.params.DefaultPort)
			if err != nil {
				continue
			}
			s.connectOnly[normalized] = struct{}{}
		}
	}
}

func (s *Server) SetRuntimePolicy(maxInboundPeers int, temporaryBanSeconds int, reconnectBackoff bool, reconnectBackoffSeconds int, peerRateLimit int, maxPerIP int, maxPerSubnet int, globalRateLimit int, misbehaviorDecaySeconds int, staleTimeoutSeconds int) {
	if maxInboundPeers > 0 {
		s.maxInboundPeers = maxInboundPeers
	}
	if temporaryBanSeconds > 0 {
		s.banDuration = time.Duration(temporaryBanSeconds) * time.Second
	}
	s.reconnectBackoff = reconnectBackoff
	if reconnectBackoffSeconds > 0 {
		s.reconnectEvery = time.Duration(reconnectBackoffSeconds) * time.Second
	}
	if peerRateLimit > 0 {
		s.peerRateLimit = peerRateLimit
	}
	if maxPerIP > 0 {
		s.maxPerIP = maxPerIP
	}
	if maxPerSubnet > 0 {
		s.maxPerSubnet = maxPerSubnet
	}
	if globalRateLimit > 0 {
		s.globalRateLimit = globalRateLimit
	}
	if misbehaviorDecaySeconds > 0 {
		s.misbehaviorDecay = time.Duration(misbehaviorDecaySeconds) * time.Second
	}
	if staleTimeoutSeconds >= 10 {
		setPeerStaleThreshold(time.Duration(staleTimeoutSeconds) * time.Second)
	}
}

func (s *Server) SetPrettyLogging(enabled bool, heartbeat bool, compact bool, showLatency bool, showPeerHeight bool, trustedPeerName string, heartbeatSeconds int) {
	s.pretty = enabled
	s.heartbeat = heartbeat
	s.compactHeartbeat = compact
	s.showLatency = showLatency
	s.showPeerHeight = showPeerHeight
	s.trustedPeerName = trustedPeerName
	if heartbeatSeconds >= 10 {
		s.heartbeatInterval = time.Duration(heartbeatSeconds) * time.Second
	}
}

func (s *Server) SetPeerPingInterval(seconds int) {
	if seconds < 10 {
		return
	}
	s.pingInterval = time.Duration(seconds) * time.Second
}

// recordGetdataReq records that we requested a block hash via getdata from
// a specific peer. Multiple peers may request the same hash; we keep the
// first (earliest) request for timeout tracking.
func (s *Server) recordGetdataReq(hash string, peerAddr string) {
	s.getdataMu.Lock()
	if _, exists := s.getdataReqs[hash]; !exists {
		s.getdataReqs[hash] = &getdataReq{
			hash:      hash,
			peer:      peerAddr,
			requested: time.Now(),
		}
	}
	s.getdataMu.Unlock()
}

// clearGetdataReq removes a block hash from the outstanding getdata tracking
// once it has been received.
func (s *Server) clearGetdataReq(hash string) {
	s.getdataMu.Lock()
	delete(s.getdataReqs, hash)
	s.getdataMu.Unlock()
}

// sweepGetdataTimeouts checks all outstanding getdata requests and returns
// hashes that have exceeded getdataTimeout. Callers should increment
// blockReqTimeouts and attempt re-request from alternative peers.
func (s *Server) sweepGetdataTimeouts() []string {
	s.getdataMu.Lock()
	defer s.getdataMu.Unlock()
	now := time.Now()
	var timedOut []string
	for hash, req := range s.getdataReqs {
		if now.Sub(req.requested) > getdataTimeout {
			timedOut = append(timedOut, hash)
			delete(s.getdataReqs, hash)
		}
	}
	return timedOut
}

func splitHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "" {
		return host
	}
	return addr
}

func normalizePeerAddress(addr string, defaultPort uint16) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("empty peer address")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = strconv.Itoa(int(defaultPort))
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	port = strings.TrimSpace(port)
	if host == "" || port == "" {
		return "", fmt.Errorf("invalid peer address %q", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return "", fmt.Errorf("invalid peer port %q", port)
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func relayableIP(ip net.IP, allowLocal bool) bool {
	if ip == nil {
		return false
	}
	ip = ip.To16()
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return allowLocal
	}
	return true
}

func relayableHost(host string, allowLocal bool) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return relayableIP(ip, allowLocal)
}

func localOrPrivateHost(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func subnetKey(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	// IPv6: use /64 subnet
	if len(ip) == net.IPv6len {
		return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x::/64",
			ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7])
	}
	return ""
}

func (s *Server) rememberPeerAddress(addr string, source string) bool {
	normalized, err := normalizePeerAddress(addr, s.params.DefaultPort)
	if err != nil {
		return false
	}
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	return s.rememberAddressLocked(normalized, source, time.Now())
}

func (s *Server) rememberAddressLocked(addr string, source string, seen time.Time) bool {
	if s.knownAddresses == nil {
		s.knownAddresses = make(map[string]knownPeerAddress)
	}
	if seen.IsZero() {
		seen = time.Now()
	}
	if existing, ok := s.knownAddresses[addr]; ok {
		if source != "" {
			existing.Source = source
		}
		existing.LastSeen = seen
		s.knownAddresses[addr] = existing
		return false
	}
	s.knownAddresses[addr] = knownPeerAddress{Addr: addr, Source: source, LastSeen: seen}
	s.trimKnownAddressesLocked(addr)
	return true
}

func (s *Server) trimKnownAddressesLocked(protected string) {
	for len(s.knownAddresses) > maxKnownPeerAddresses {
		oldestAddr := ""
		oldestSeen := time.Time{}
		for addr, info := range s.knownAddresses {
			if addr == protected {
				continue
			}
			if oldestAddr == "" || info.LastSeen.Before(oldestSeen) {
				oldestAddr = addr
				oldestSeen = info.LastSeen
			}
		}
		if oldestAddr == "" {
			return
		}
		delete(s.knownAddresses, oldestAddr)
	}
}

func (s *Server) knownAddressInfos() []knownPeerAddress {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	out := make([]knownPeerAddress, 0, len(s.knownAddresses))
	for _, addr := range s.knownAddresses {
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

func (s *Server) KnownAddressCount() int {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	return len(s.knownAddresses)
}

func (s *Server) KnownAddresses() []string {
	infos := s.knownAddressInfos()
	out := make([]string, 0, len(infos))
	for _, info := range infos {
		out = append(out, info.Addr)
	}
	return out
}

func (s *Server) KnownPeerInfos() []map[string]any {
	infos := s.knownAddressInfos()
	out := make([]map[string]any, 0, len(infos))
	now := time.Now()
	for _, info := range infos {
		row := map[string]any{
			"addr":                           info.Addr,
			"source":                         info.Source,
			"last_seen_time":                 unixOrZero(info.LastSeen),
			"last_seen_ago_seconds":          secondsSince(info.LastSeen),
			"last_connected_time":            unixOrZero(info.LastConnected),
			"last_connected_ago_seconds":     secondsSince(info.LastConnected),
			"last_failure_time":              unixOrZero(info.LastFailure),
			"last_failure_ago_seconds":       secondsSince(info.LastFailure),
			"success_count":                  info.Successes,
			"failure_count":                  info.Failures,
			"last_direction":                 info.LastDirection,
			"active":                         s.peerAddressActive(info.Addr),
			"serviceable":                    info.Failures == 0 || info.LastConnected.After(info.LastFailure) || (!info.LastFailure.IsZero() && now.Sub(info.LastFailure) > 30*time.Minute),
			"known_peer_cache_entry_version": 1,
		}
		out = append(out, row)
	}
	return out
}

func (s *Server) markKnownPeerConnected(addr string, outbound bool) {
	normalized, err := normalizePeerAddress(addr, s.params.DefaultPort)
	if err != nil {
		return
	}
	direction := "inbound"
	if outbound {
		direction = "outbound"
	}
	now := time.Now()
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if s.knownAddresses == nil {
		s.knownAddresses = make(map[string]knownPeerAddress)
	}
	info := s.knownAddresses[normalized]
	if info.Addr == "" {
		info.Addr = normalized
		info.Source = direction + "-handshake"
	}
	info.LastSeen = now
	info.LastConnected = now
	info.Successes++
	info.LastDirection = direction
	s.knownAddresses[normalized] = info
}

func (s *Server) markKnownPeerFailure(addr string) {
	normalized, err := normalizePeerAddress(addr, s.params.DefaultPort)
	if err != nil {
		return
	}
	now := time.Now()
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if s.knownAddresses == nil {
		s.knownAddresses = make(map[string]knownPeerAddress)
	}
	info := s.knownAddresses[normalized]
	if info.Addr == "" {
		info.Addr = normalized
		info.Source = "dial-failure"
	}
	info.LastFailure = now
	info.Failures++
	s.knownAddresses[normalized] = info
}

func (s *Server) inboundPeerCount() int {
	count := 0
	for _, p := range s.snapshotPeers() {
		if p.outbound {
			continue
		}
		count++
	}
	return count
}

func (s *Server) duplicateInboundHost(host string) bool {
	for _, p := range s.snapshotPeers() {
		if p.outbound {
			continue
		}
		if splitHost(p.remote) == host {
			return true
		}
	}
	return false
}

func (s *Server) inboundHostCount(host string) int {
	n := 0
	for _, p := range s.snapshotPeers() {
		if p.outbound {
			continue
		}
		if splitHost(p.remote) == host {
			n++
		}
	}
	return n
}

func (s *Server) inboundSubnetCount(subnet string) int {
	if subnet == "" {
		return 0
	}
	n := 0
	for _, p := range s.snapshotPeers() {
		if p.outbound {
			continue
		}
		if subnetKey(splitHost(p.remote)) == subnet {
			n++
		}
	}
	return n
}

func (s *Server) allowPeerMessage(p *peer, command string) bool {
	now := time.Now()
	window := s.peerRateWindow
	if window <= 0 {
		window = 10 * time.Second
	}
	allowed := true
	globalAllowed := true
	gWindow := s.globalRateWindow
	if s.globalRateLimit > 0 {
		if gWindow <= 0 {
			gWindow = 10 * time.Second
		}
		s.rateMu.Lock()
		if s.globalWindowStart.IsZero() || now.Sub(s.globalWindowStart) >= gWindow {
			s.globalWindowStart = now
			s.globalWindowCount = 0
		}
		s.globalWindowCount++
		gCount := s.globalWindowCount
		s.rateMu.Unlock()
		if gCount > s.globalRateLimit {
			globalAllowed = false
		}
	}
	p.lastMu.Lock()
	if p.rateWindowStart.IsZero() || now.Sub(p.rateWindowStart) >= window {
		p.rateWindowStart = now
		p.rateWindowCount = 0
	}
	p.rateWindowCount++
	count := p.rateWindowCount
	limit := s.peerRateLimit
	if limit > 0 && count > limit {
		p.rateLimited = true
		p.lastPenaltyReason = fmt.Sprintf("peer message rate limit exceeded (%d/%d per %s) cmd=%s", count, limit, window.String(), command)
		p.lastPenaltyAt = now
		allowed = false
	}
	if !globalAllowed {
		p.rateLimited = true
		p.lastPenaltyReason = fmt.Sprintf("global message rate limit exceeded (>%d per %s)", s.globalRateLimit, gWindow.String())
		p.lastPenaltyAt = now
		allowed = false
	}
	p.lastMu.Unlock()
	return allowed
}

func (s *Server) shouldThrottleOutboundDial(addr string) bool {
	if !s.reconnectBackoff || s.reconnectEvery <= 0 {
		return false
	}
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	now := time.Now()
	last, ok := s.outboundLastAttempt[addr]
	if ok && now.Sub(last) < s.reconnectEvery {
		return true
	}
	s.outboundLastAttempt[addr] = now
	return false
}

func (s *Server) clearOutboundThrottle() {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	s.outboundLastAttempt = make(map[string]time.Time)
}

type PeerInfo struct {
	Addr                             string  `json:"addr"`
	Direction                        string  `json:"direction"`
	Outbound                         bool    `json:"outbound"`
	ConnectedForSeconds              int64   `json:"connected_for_seconds"`
	LastSeenAgoSeconds               float64 `json:"last_seen_ago_seconds"`
	LastPongAgoSeconds               float64 `json:"last_pong_ago_seconds"`
	LastPingTime                     int64   `json:"last_ping_time,omitempty"`
	LastPongTime                     int64   `json:"last_pong_time,omitempty"`
	LastHeightUpdateAgoSeconds       float64 `json:"last_height_update_ago_seconds"`
	LastPeerMetadataUpdateAgoSeconds float64 `json:"last_peer_metadata_update_ago_seconds"`
	LastPingMS                       float64 `json:"last_ping_ms"`
	PingLatencyMS                    float64 `json:"ping_latency_ms"`
	MinPingMS                        float64 `json:"min_ping_ms"`
	MissedPongs                      int     `json:"missed_pongs"`
	Stale                            bool    `json:"stale"`
	ReportedHeight                   int32   `json:"reported_height"`
	SyncState                        string  `json:"sync_state"`
	Version                          int32   `json:"version"`
	SubVer                           string  `json:"subver"`
	SyncedBlocks                     int32   `json:"synced_blocks"`
	StartingHeight                   int32   `json:"starting_height"`
	ChainID                          string  `json:"chain_id"`
	BanScore                         int     `json:"ban_score"`
	MisbehaviorScore                 int     `json:"misbehavior_score"`
	BannedUntil                      int64   `json:"banned_until,omitempty"`
	RateLimited                      bool    `json:"rate_limited"`
	LastPenaltyReason                string  `json:"last_penalty_reason,omitempty"`
	PeerQuality                      string  `json:"peer_quality"`
	BytesSent                        uint64  `json:"bytes_sent"`
	BytesRecv                        uint64  `json:"bytes_recv"`
	ConnectionType                   string  `json:"connection_type"`
	LastSyncRequestAgoSeconds        float64 `json:"last_sync_request_ago_seconds"`
	LastSyncError                    string  `json:"last_sync_error,omitempty"`
	LastBlockReject                  string  `json:"last_block_reject,omitempty"`
	LastLocatorTip                   string  `json:"last_locator_tip,omitempty"`
	LastReceivedBlockHash            string  `json:"last_received_block_hash,omitempty"`
	LastReceivedBlockPrev            string  `json:"last_received_block_prev,omitempty"`
	LastReceivedBlockHeight          int32   `json:"last_received_block_height,omitempty"`
	LastBestChainUpdate              string  `json:"last_best_chain_update,omitempty"`
	LastBlockReason                  string  `json:"last_block_reason,omitempty"`
	LastHeaderReceivedAgoSeconds     float64 `json:"last_header_received_ago_seconds"`
	LastBlockReceivedAgoSeconds      float64 `json:"last_block_received_ago_seconds"`
	BlocksRequested                  int     `json:"blocks_requested"`
	BlocksServed                     int     `json:"blocks_served"`
	SyncFailures                     int     `json:"sync_failures"`
	SyncSuccesses                    int     `json:"sync_successes"`
	BestSyncCandidate                bool    `json:"best_sync_candidate"`
	GoodPeer                         bool    `json:"good_peer"`
	GoodPeerReason                   string  `json:"good_peer_reason"`
	PeerSafetyCategory               string  `json:"peer_safety_category"`
	PeerSafetyReason                 string  `json:"peer_safety_reason"`
	LagFromLocalHeight               int32   `json:"lag_from_local_height"`
}

func (s *Server) PeerInfos() []PeerInfo {
	now := time.Now()
	peers := s.snapshotPeers()
	bestPeer := s.bestSyncPeer()
	localHeight := int32(-1)
	if tip := s.chain.Tip(); tip != nil {
		localHeight = tip.Height
	}
	out := make([]PeerInfo, 0, len(peers))
	for _, p := range peers {
		p.lastMu.Lock()
		connected := p.connected
		seen := p.lastSeen
		pong := p.lastPong
		ping := p.lastPing
		heightUpdate := p.lastHeightUpdate
		rtt := p.lastRTT
		minRTT := p.minRTT
		missedPongs := p.missedPongs
		version := p.version
		subver := p.subver
		height := p.height
		chainID := p.chainID
		banScore := p.banScore
		rateLimited := p.rateLimited
		lastPenaltyReason := p.lastPenaltyReason
		bannedUntil := p.bannedUntil
		bytesSent := p.bytesSent
		bytesRecv := p.bytesRecv
		lastSyncRequest := p.lastSyncRequest
		lastSyncError := p.lastSyncError
		lastBlockReject := p.lastBlockReject
		lastLocatorTip := p.lastLocatorTip
		lastBlockHash := p.lastBlockHash
		lastBlockPrev := p.lastBlockPrev
		lastBlockHeight := p.lastBlockHeight
		lastBestUpdate := p.lastBestUpdate
		lastBlockReason := p.lastBlockReason
		lastHeaderRecv := p.lastHeaderRecv
		lastBlockRecv := p.lastBlockRecv
		blocksRequested := p.blocksRequested
		blocksServed := p.blocksServed
		syncFailures := p.syncFailures
		syncSuccesses := p.syncSuccesses
		p.lastMu.Unlock()
		lastSyncAgo := float64(-1)
		if !lastSyncRequest.IsZero() {
			lastSyncAgo = now.Sub(lastSyncRequest).Seconds()
		}
		direction := "inbound"
		if p.outbound {
			direction = "outbound"
		}
		stale := (!heightUpdate.IsZero() && now.Sub(heightUpdate) > getPeerStaleThreshold()) || (!seen.IsZero() && now.Sub(seen) > getPeerStaleThreshold())
		syncState := "current"
		if height > localHeight {
			syncState = "peer_ahead"
		} else if stale {
			syncState = "stale"
		}
		quality := "healthy"
		switch {
		case stale || missedPongs >= 3:
			quality = "poor"
		case banScore > 0 || rateLimited:
			quality = "watch"
		case rtt > time.Second:
			quality = "degraded"
		}
		lagFromLocal := int32(0)
		if localHeight >= 0 && height > 0 {
			lagFromLocal = localHeight - height
		}
		peerCategory, goodPeer, goodPeerReason := classifyPeerSafety(localHeight, height, stale, missedPongs, quality, chainID, s.chainID, lastSyncError, lastBlockReject, rtt)
		out = append(out, PeerInfo{
			Addr:                             p.remote,
			Direction:                        direction,
			Outbound:                         p.outbound,
			ConnectedForSeconds:              int64(now.Sub(connected).Seconds()),
			LastSeenAgoSeconds:               now.Sub(seen).Seconds(),
			LastPongAgoSeconds:               now.Sub(pong).Seconds(),
			LastPingTime:                     unixOrZero(ping),
			LastPongTime:                     unixOrZero(pong),
			LastHeightUpdateAgoSeconds:       secondsSince(heightUpdate),
			LastPeerMetadataUpdateAgoSeconds: secondsSince(heightUpdate),
			LastPingMS:                       float64(rtt.Microseconds()) / 1000,
			PingLatencyMS:                    float64(rtt.Microseconds()) / 1000,
			MinPingMS:                        float64(minRTT.Microseconds()) / 1000,
			MissedPongs:                      missedPongs,
			Stale:                            stale,
			ReportedHeight:                   height,
			SyncState:                        syncState,
			Version:                          version,
			SubVer:                           subver,
			StartingHeight:                   height,
			SyncedBlocks:                     height,
			ChainID:                          chainID,
			BanScore:                         banScore,
			MisbehaviorScore:                 banScore,
			BannedUntil:                      unixOrZero(bannedUntil),
			RateLimited:                      rateLimited,
			LastPenaltyReason:                lastPenaltyReason,
			PeerQuality:                      quality,
			BytesSent:                        bytesSent,
			BytesRecv:                        bytesRecv,
			ConnectionType:                   direction + "-full-relay",
			LastSyncRequestAgoSeconds:        lastSyncAgo,
			LastSyncError:                    lastSyncError,
			LastBlockReject:                  lastBlockReject,
			LastLocatorTip:                   lastLocatorTip,
			LastReceivedBlockHash:            lastBlockHash,
			LastReceivedBlockPrev:            lastBlockPrev,
			LastReceivedBlockHeight:          lastBlockHeight,
			LastBestChainUpdate:              lastBestUpdate,
			LastBlockReason:                  lastBlockReason,
			LastHeaderReceivedAgoSeconds:     secondsSince(lastHeaderRecv),
			LastBlockReceivedAgoSeconds:      secondsSince(lastBlockRecv),
			BlocksRequested:                  blocksRequested,
			BlocksServed:                     blocksServed,
			SyncFailures:                     syncFailures,
			SyncSuccesses:                    syncSuccesses,
			BestSyncCandidate:                p == bestPeer,
			GoodPeer:                         goodPeer,
			GoodPeerReason:                   goodPeerReason,
			PeerSafetyCategory:               peerCategory,
			PeerSafetyReason:                 goodPeerReason,
			LagFromLocalHeight:               lagFromLocal,
		})
	}
	return out
}

func classifyGoodPeer(localHeight, peerHeight int32, stale bool, missedPongs int, quality, chainID, expectedChainID, lastSyncError, lastBlockReject string, rtt time.Duration) (bool, string) {
	_, good, reason := classifyPeerSafety(localHeight, peerHeight, stale, missedPongs, quality, chainID, expectedChainID, lastSyncError, lastBlockReject, rtt)
	return good, reason
}

func classifyPeerSafety(localHeight, peerHeight int32, stale bool, missedPongs int, quality, chainID, expectedChainID, lastSyncError, lastBlockReject string, rtt time.Duration) (string, bool, string) {
	if strings.TrimSpace(chainID) != "" && strings.TrimSpace(expectedChainID) != "" && chainID != expectedChainID {
		return "wrong_chain_id", false, "wrong chain/genesis"
	}
	if strings.TrimSpace(lastBlockReject) != "" {
		return "protocol_error", false, "block rejected"
	}
	if strings.TrimSpace(lastSyncError) != "" {
		return "protocol_error", false, "sync error"
	}
	if missedPongs >= 3 {
		return "unresponsive", false, "timeout"
	}
	if localHeight > 0 && peerHeight <= 0 {
		return "stale_chain_data", false, "unknown height"
	}
	if localHeight > 0 && peerHeight > 0 {
		lag := localHeight - peerHeight
		switch {
		case lag < 0:
			return "stronger_chainwork", false, "peer reports higher chain height"
		case lag == 0:
			return "current_agreeing", true, "current and agreeing"
		case lag == 1:
			return "lagging_1_block", true, "lagging by 1 block"
		case lag == 2:
			return "lagging_2_blocks", true, "lagging by 2 blocks"
		case stale:
			return "stale_chain_data", false, "stale chain data"
		default:
			return "lagging_more_than_2", false, "lagging by more than 2 blocks"
		}
	}
	if strings.EqualFold(quality, "poor") {
		return "unresponsive", false, "poor peer quality"
	}
	if stale {
		return "stale_chain_data", false, "stale chain data"
	}
	if rtt > 5*time.Second {
		return "unresponsive", false, "poor ping"
	}
	return "current_agreeing", true, "current and agreeing"
}

func (s *Server) BestPeerHeight() int32 {
	best := int32(-1)
	for _, p := range s.snapshotPeers() {
		p.lastMu.Lock()
		height := p.height
		p.lastMu.Unlock()
		if height > best {
			best = height
		}
	}
	return best
}

func (s *Server) SyncStatus() map[string]any {
	localHeight := int32(-1)
	localHash := ""
	if tip := s.chain.Tip(); tip != nil {
		localHeight = tip.Height
		localHash = tip.Hash
	}
	peers := s.snapshotPeers()
	bestPeerHeight := int32(-1)
	stalePeerCount := 0
	syncingPeerCount := 0
	now := time.Now()
	for _, p := range peers {
		p.lastMu.Lock()
		height := p.height
		lastSeen := p.lastSeen
		lastHeightUpdate := p.lastHeightUpdate
		p.lastMu.Unlock()
		if height > bestPeerHeight {
			bestPeerHeight = height
		}
		if height > localHeight {
			syncingPeerCount++
		}
		heightStale := !lastHeightUpdate.IsZero() && now.Sub(lastHeightUpdate) > getPeerStaleThreshold()
		msgStale := !lastSeen.IsZero() && now.Sub(lastSeen) > getPeerStaleThreshold()
		if heightStale || msgStale {
			stalePeerCount++
		}
	}
	if bestPeerHeight < 0 {
		bestPeerHeight = localHeight
	}
	behind := bestPeerHeight > localHeight
	status := "current"
	message := "Local node is at or ahead of connected peers."
	if behind {
		status = "syncing"
		message = "Node is behind peers. Waiting for blocks / requesting blocks."
	}
	lastError := ""
	lastReject := ""
	lastLocatorTip := ""
	lastBlockHash := ""
	lastBlockPrev := ""
	lastBlockHeight := int32(-1)
	lastBestUpdate := ""
	lastBlockReason := ""
	for _, p := range peers {
		p.lastMu.Lock()
		if p.lastSyncError != "" && lastError == "" {
			lastError = p.lastSyncError
		}
		if p.lastBlockReject != "" && lastReject == "" {
			lastReject = p.lastBlockReject
		}
		if p.lastLocatorTip != "" && lastLocatorTip == "" {
			lastLocatorTip = p.lastLocatorTip
		}
		if p.lastBlockHash != "" && lastBlockHash == "" {
			lastBlockHash = p.lastBlockHash
			lastBlockPrev = p.lastBlockPrev
			lastBlockHeight = p.lastBlockHeight
			lastBestUpdate = p.lastBestUpdate
			lastBlockReason = p.lastBlockReason
		}
		p.lastMu.Unlock()
	}
	health := s.healthSnapshot()
	syncStalled := false
	possiblyStalled := false
	peerCount := len(peers)
	lastHeightChangeAge, _ := health["last_height_change_ago_seconds"].(float64)
	lastSyncReqAge, _ := health["last_p2p_sync_request_ago_seconds"].(float64)
	lastHeaderAge, _ := health["last_header_received_ago_seconds"].(float64)
	lastBlockAge, _ := health["last_block_received_ago_seconds"].(float64)
	lastPeerMsgAge, _ := health["last_peer_message_ago_seconds"].(float64)
	bestPeer := s.bestSyncPeer()
	syncPeer := ""
	syncPeerHeight := int32(-1)
	if bestPeer != nil {
		bestPeer.lastMu.Lock()
		syncPeer = bestPeer.remote
		syncPeerHeight = bestPeer.height
		bestPeer.lastMu.Unlock()
	}
	blocksBehind := max32(0, bestPeerHeight-localHeight)
	targetSeconds := chaincfg.TargetSpacing.Seconds()
	possiblyStalledAfter := 2 * targetSeconds
	stalledAfter := 3 * targetSeconds
	recentSyncRequest := lastSyncReqAge >= 0 && lastSyncReqAge < 2*targetSeconds
	syncRequestInFlight := recentSyncRequest && behind && blocksBehind > 1
	noUsefulChainData := peerCount > 0 &&
		lastHeaderAge > possiblyStalledAfter &&
		lastBlockAge > possiblyStalledAfter &&
		(behind || syncingPeerCount > 0 || stalePeerCount > 0)
	if behind {
		status = "catching_up"
		message = fmt.Sprintf("Catching up to peers. Behind by %d block(s).", blocksBehind)
		if recentSyncRequest || syncingPeerCount > 0 {
			status = "requesting_blocks"
			message = fmt.Sprintf("Requesting latest blocks from peers. Behind by %d block(s).", blocksBehind)
		}
		if blocksBehind <= 1 {
			status = "current"
			message = "Local node is at or within one block of connected peers."
		} else if lastHeightChangeAge > possiblyStalledAfter {
			possiblyStalled = true
			status = "possibly_stalled"
			message = "Still catching up, but no height progress for more than two target block intervals."
		}
		if lastHeightChangeAge > stalledAfter && (blocksBehind > 5 || noUsefulChainData || lastError != "") {
			syncStalled = true
		}
	}
	if noUsefulChainData {
		possiblyStalled = true
	}
	if peerCount == 0 {
		status = "no_peers"
		message = "No peers connected. Reconnecting seeds / addnodes."
	} else if syncStalled {
		status = "stalled"
		message = "No height progress for more than three target block intervals while peers are ahead."
	}
	return map[string]any{
		"status":                          status,
		"message":                         message,
		"local_height":                    localHeight,
		"local_best_hash":                 localHash,
		"best_peer_height":                bestPeerHeight,
		"peer_reported_height":            bestPeerHeight,
		"behind":                          behind,
		"catch_up_pending":                behind || syncingPeerCount > 0,
		"sync_state":                      status,
		"blocks_behind":                   blocksBehind,
		"connected_peers":                 peerCount,
		"sync_peer":                       syncPeer,
		"sync_peer_height":                syncPeerHeight,
		"active_syncing_peer_count":       syncingPeerCount,
		"request_in_flight":               syncRequestInFlight,
		"retry_count":                     health["sync_retry_count"],
		"peer_rotation_count":             health["sync_peer_rotation_count"],
		"last_requested_locator_tip_hash": lastLocatorTip,
		"last_received_block_hash":        lastBlockHash,
		"last_received_block_prev_hash":   lastBlockPrev,
		"last_received_block_height":      lastBlockHeight,
		"last_best_chain_update":          lastBestUpdate,
		"last_block_reason":               lastBlockReason,
		"last_sync_error":                 lastError,
		"last_block_reject":               lastReject,
		"sync_stalled":                    syncStalled,
		"possibly_stalled":                possiblyStalled,
		"peer_count":                      peerCount,
		"stale_peer_count":                stalePeerCount,
		"syncing_peer_count":              syncingPeerCount,
		"watchdog_running":                health["watchdog_running"],
		"last_watchdog_tick":              health["last_watchdog_tick_time"],
		"watchdog_last_action":            health["watchdog_last_action"],
		"watchdog_reconnect_count":        health["watchdog_reconnect_count"],
		"last_sync_attempt":               health["last_p2p_sync_request_time"],
		"last_sync_attempt_age":           lastSyncReqAge,
		"last_request_time":               health["last_p2p_sync_request_time"],
		"last_progress_time":              health["last_height_change_time"],
		"last_header_time":                health["last_header_received_time"],
		"last_block_time":                 health["last_block_received_time"],
		"last_height_change_age":          lastHeightChangeAge,
		"last_height_progress_age":        lastHeightChangeAge,
		"last_header_received_age":        lastHeaderAge,
		"last_block_received_age":         lastBlockAge,
		"last_getheaders_sent_age":        health["last_getheaders_sent_ago_seconds"],
		"last_getblocks_sent_age":         health["last_getblocks_sent_ago_seconds"],
		"last_peer_message_age":           lastPeerMsgAge,
		"no_useful_chain_data":            noUsefulChainData,
		"blocks_announced":                health["blocks_announced"],
		"block_invs_received":             health["block_invs_received"],
		"getdata_blocks_received":         health["getdata_blocks_received"],
		"blocks_served_to_peers":          health["blocks_served_to_peers"],
		"blocks_requested_from_peers":     health["blocks_requested_from_peers"],
		"block_request_timeouts":          health["block_request_timeouts"],
		"block_messages_received":         health["block_messages_received"],
		"header_batches_received":         health["header_batches_received"],
		"header_batches_rejected":         health["header_batches_rejected"],
		"missing_parent_requests":         health["missing_parent_requests"],
		"missing_parent_tracked":          health["missing_parent_tracked"],
		"diagnostic":                      s.syncDiagnostic(localHeight, bestPeerHeight, behind, health, lastError, lastReject, lastBlockHash),
		"health":                          health,
	}
}

// syncDiagnostic interprets the live sync counters into a single human-readable
// verdict so the operator can see, from getsyncstatus alone, exactly where the
// sync chain is breaking: no peers / no headers / headers rejected / no block
// bodies returned / orphan loop. This is the key diagnostic for the
// 1.0.6<->1.0.2 seed-node sync investigation.
func (s *Server) syncDiagnostic(localHeight, bestPeerHeight int32, behind bool, health map[string]any, lastError, lastReject, lastBlockHash string) string {
	if localHeight < 0 {
		return "chain tip not initialized (genesis not loaded)"
	}
	if bestPeerHeight <= localHeight {
		return "current; not behind any connected peer"
	}
	hdrBatches, _ := health["header_batches_received"].(int64)
	hdrRejected, _ := health["header_batches_rejected"].(int64)
	blockMsgs, _ := health["block_messages_received"].(int64)
	blocksReqd, _ := health["blocks_requested_from_peers"].(int64)
	blockInvs, _ := health["block_invs_received"].(int64)
	missingReqs, _ := health["missing_parent_requests"].(int64)
	lastBlockAge, _ := health["last_block_received_ago_seconds"].(float64)
	lastHeaderAge, _ := health["last_header_received_ago_seconds"].(float64)
	switch {
	case hdrBatches == 0 && lastHeaderAge < 0:
		return "no header batches received yet; peer is not responding to getheaders (check chain_id / protocol compatibility)"
	case hdrBatches > 0 && hdrRejected == hdrBatches && blocksReqd == 0:
		return fmt.Sprintf("all %d header batch(es) REJECTED by ValidateHeaderSequence; no getdata sent. Likely a consensus/protocol mismatch with the peer (difficulty, bits, pow, or parent linkage). Check daemon log for 'header batch ... REJECTED'.", hdrBatches)
	case blocksReqd > 0 && blockMsgs == 0:
		return fmt.Sprintf("requested %d block bodies via getdata but received 0 block messages; the peer is silently NOT serving blocks (header_batches_recv=%d, rejected=%d). If even the %d blocks the peer itself announced in inv are being requested with the peer's own hashes and still not served, the peer node itself is broken - it must be upgraded to 1.0.9 (which has the orphan fix and proper block serving). 1.0.2 seed nodes must be retired. Run: legacycoin-cli getpeerinfo and check subver/chain_id to confirm the peer version.", blocksReqd, hdrBatches, hdrRejected, blockInvs)
	case blockMsgs > 0 && lastBlockHash == "":
		return fmt.Sprintf("received %d block message(s) but none were processed as connected; all orphaned or rejected. Check 'Block processed | status=orphan' lines and last_block_reason.", blockMsgs)
	case missingReqs > 0:
		return fmt.Sprintf("orphan-parent resolution active: %d missing-parent request(s) issued. Sync may recover once a peer serves the parent. If it does not, the peer cannot serve the parent block (hash mismatch likely).", missingReqs)
	case lastBlockAge > 0 && behind:
		return fmt.Sprintf("behind by %d; last block message %.0fs ago. Watchdog should rotate peers.", bestPeerHeight-localHeight, lastBlockAge)
	default:
		return fmt.Sprintf("behind by %d; sync in progress", bestPeerHeight-localHeight)
	}
}

func (s *Server) ForceSync(reason string) map[string]any {
	if strings.TrimSpace(reason) == "" {
		reason = "manual refresh"
	}
	s.noteSyncRequest()
	s.log.Printf("p2p force sync requested: %s", reason)
	if s.PeerCount() == 0 {
		s.clearOutboundThrottle()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		s.noteWatchdogAction("force sync with no peers: reconnecting bootstrap peers")
		s.connectSeeds(ctx)
	}
	s.requestSyncFromAheadPeers(true)
	return s.SyncStatus()
}

func (s *Server) setP2PRunning(running bool) {
	now := time.Now()
	s.healthMu.Lock()
	if running && s.startedAt.IsZero() {
		s.startedAt = now
		if s.lastHeightChg.IsZero() {
			s.lastHeightChg = now
		}
	}
	s.p2pRunning = running
	s.healthMu.Unlock()
}

func (s *Server) setSyncRunning(running bool) {
	now := time.Now()
	s.healthMu.Lock()
	s.syncRunning = running
	if running {
		s.lastSyncBeat = now
	}
	s.healthMu.Unlock()
}

func (s *Server) setWatchdogRunning(running bool) {
	now := time.Now()
	s.healthMu.Lock()
	s.watchdogRun = running
	if running {
		s.lastWatchdog = now
	}
	s.healthMu.Unlock()
}

func (s *Server) noteSyncBeat() {
	s.healthMu.Lock()
	s.lastSyncBeat = time.Now()
	s.healthMu.Unlock()
}

// logSyncHeartbeat emits one consolidated sync-progress line per sync tick so
// the exact stall point (no headers / headers rejected / no block bodies) is
// visible in the daemon log without an RPC call. This is the single most
// useful diagnostic for the 1.0.6/1.0.8 seed-node sync investigation.
func (s *Server) logSyncHeartbeat() {
	tipHeight := int32(-1)
	tipHash := ""
	if tip := s.chain.Tip(); tip != nil {
		tipHeight = tip.Height
		tipHash = tip.Hash
	}
	bestPeer := s.BestPeerHeight()
	s.healthMu.Lock()
	lastBlock := s.lastBlockMsg
	blockMsgs := s.blockMessagesRecv
	getdataRecv := s.getDataBlocksRecv
	hdrBatches := s.headersBatchesRecv
	hdrRejected := s.headersRejected
	blocksReqd := s.blocksRequested
	s.healthMu.Unlock()
	missingReqs := atomic.LoadInt64(&s.missingParentReqs)
	var blockAgo string
	if lastBlock.IsZero() {
		blockAgo = "never"
	} else {
		blockAgo = fmt.Sprintf("%.0fs ago", time.Since(lastBlock).Seconds())
	}
	s.log.Printf("p2p sync heartbeat: tip=%d:%s best_peer=%d behind=%d | block_msgs_recv=%d (last %s) | getdata_block_reqs_recv=%d blocks_requested=%d | hdr_batches_recv=%d hdr_rejected=%d | missing_parent_reqs=%d",
		tipHeight, tipHash, bestPeer, max32(0, bestPeer-tipHeight),
		blockMsgs, blockAgo, getdataRecv, blocksReqd,
		hdrBatches, hdrRejected, missingReqs)
}

func (s *Server) noteSyncRequest() {
	s.healthMu.Lock()
	s.lastSyncReq = time.Now()
	s.healthMu.Unlock()
}

func (s *Server) notePeerMessage() {
	s.healthMu.Lock()
	s.lastPeerMsg = time.Now()
	s.healthMu.Unlock()
}

func (s *Server) noteHeaderMessage() {
	s.healthMu.Lock()
	s.lastHeaderMsg = time.Now()
	s.healthMu.Unlock()
}

func (s *Server) noteBlockMessage() {
	s.healthMu.Lock()
	s.lastBlockMsg = time.Now()
	s.blockMessagesRecv++
	s.healthMu.Unlock()
}

func (s *Server) noteGetHeadersSent() {
	s.healthMu.Lock()
	s.lastGetHeader = time.Now()
	s.healthMu.Unlock()
}

func (s *Server) noteGetBlocksSent() {
	s.healthMu.Lock()
	s.lastGetBlock = time.Now()
	s.healthMu.Unlock()
}

func (s *Server) noteWatchdogTick() {
	s.healthMu.Lock()
	s.lastWatchdog = time.Now()
	s.healthMu.Unlock()
}

func (s *Server) noteWatchdogAction(action string) {
	s.healthMu.Lock()
	s.lastWdAction = action
	s.healthMu.Unlock()
}

func (s *Server) addWatchdogReconnects(n int64) {
	if n <= 0 {
		return
	}
	s.healthMu.Lock()
	s.wdReconnects += n
	s.healthMu.Unlock()
}

func (s *Server) noteBlockConnected() {
	now := time.Now()
	s.healthMu.Lock()
	s.lastBlockConn = now
	s.lastHeightChg = now
	s.healthMu.Unlock()
}

func (s *Server) healthSnapshot() map[string]any {
	s.healthMu.Lock()
	startedAt := s.startedAt
	p2pRunning := s.p2pRunning
	syncRunning := s.syncRunning
	watchdogRunning := s.watchdogRun
	lastSyncBeat := s.lastSyncBeat
	lastSyncReq := s.lastSyncReq
	lastPeerMsg := s.lastPeerMsg
	lastHeaderMsg := s.lastHeaderMsg
	lastBlockMsg := s.lastBlockMsg
	lastGetHeader := s.lastGetHeader
	lastGetBlock := s.lastGetBlock
	lastWatchdog := s.lastWatchdog
	lastWatchdogAction := s.lastWdAction
	watchdogReconnectCount := s.wdReconnects
	lastBlockConn := s.lastBlockConn
	lastHeightChg := s.lastHeightChg
	lastSyncPeer := s.lastSyncPeer
	syncRetryCount := s.syncRetryCount
	syncPeerRotations := s.syncPeerRotations
	blocksAnnounced := s.blocksAnnounced
	blockInvsReceived := s.blockInvsReceived
	getDataBlocksRecv := s.getDataBlocksRecv
	blocksServed := s.blocksServed
	blocksRequested := s.blocksRequested
	blockReqTimeouts := s.blockReqTimeouts
	blockMessagesRecv := s.blockMessagesRecv
	headersBatchesRecv := s.headersBatchesRecv
	headersRejected := s.headersRejected
	missingParentReqs := atomic.LoadInt64(&s.missingParentReqs)
	s.missingParentMu.Lock()
	missingParentPending := len(s.missingParentSeen)
	s.missingParentMu.Unlock()
	s.healthMu.Unlock()
	return map[string]any{
		"node_uptime_seconds":                       secondsSince(startedAt),
		"p2p_loop_running":                          p2pRunning,
		"sync_loop_running":                         syncRunning,
		"watchdog_running":                          watchdogRunning,
		"last_sync_loop_beat_time":                  unixOrZero(lastSyncBeat),
		"last_sync_loop_beat_ago_seconds":           secondsSince(lastSyncBeat),
		"last_p2p_sync_request_time":                unixOrZero(lastSyncReq),
		"last_p2p_sync_request_ago_seconds":         secondsSince(lastSyncReq),
		"last_peer_message_time":                    unixOrZero(lastPeerMsg),
		"last_peer_message_ago_seconds":             secondsSince(lastPeerMsg),
		"last_header_received_time":                 unixOrZero(lastHeaderMsg),
		"last_header_received_ago_seconds":          secondsSince(lastHeaderMsg),
		"last_block_received_time":                  unixOrZero(lastBlockMsg),
		"last_block_received_ago_seconds":           secondsSince(lastBlockMsg),
		"last_getheaders_sent_time":                 unixOrZero(lastGetHeader),
		"last_getheaders_sent_ago_seconds":          secondsSince(lastGetHeader),
		"last_getblocks_sent_time":                  unixOrZero(lastGetBlock),
		"last_getblocks_sent_ago_seconds":           secondsSince(lastGetBlock),
		"last_watchdog_tick_time":                   unixOrZero(lastWatchdog),
		"last_watchdog_tick_ago_seconds":            secondsSince(lastWatchdog),
		"watchdog_last_action":                      lastWatchdogAction,
		"watchdog_reconnect_count":                  watchdogReconnectCount,
		"last_successful_block_connect_time":        unixOrZero(lastBlockConn),
		"last_successful_block_connect_ago_seconds": secondsSince(lastBlockConn),
		"last_height_change_time":                   unixOrZero(lastHeightChg),
		"last_height_change_ago_seconds":            secondsSince(lastHeightChg),
		"last_sync_peer":                            lastSyncPeer,
		"sync_retry_count":                          syncRetryCount,
		"sync_peer_rotation_count":                  syncPeerRotations,
		"blocks_announced":                          blocksAnnounced,
		"block_invs_received":                       blockInvsReceived,
		"getdata_blocks_received":                   getDataBlocksRecv,
		"blocks_served_to_peers":                    blocksServed,
		"blocks_requested_from_peers":               blocksRequested,
		"block_request_timeouts":                    blockReqTimeouts,
		"block_messages_received":                   blockMessagesRecv,
		"header_batches_received":                   headersBatchesRecv,
		"header_batches_rejected":                   headersRejected,
		"missing_parent_requests":                   missingParentReqs,
		"missing_parent_tracked":                    missingParentPending,
	}
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func secondsSince(t time.Time) float64 {
	if t.IsZero() {
		return -1
	}
	return time.Since(t).Seconds()
}

func (s *Server) SetBootstrapPeers(peers []string) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	s.bootstrap = s.bootstrap[:0]
	for _, peer := range peers {
		addr, err := normalizePeerAddress(peer, s.params.DefaultPort)
		if err != nil {
			continue
		}
		s.bootstrap = append(s.bootstrap, addr)
		s.rememberAddressLocked(addr, "bootstrap", time.Now())
	}
}

func (s *Server) BootstrapPeers() []string {
	return s.bootstrapPeers()
}

func (s *Server) addBootstrapPeer(addr string) {
	addr, err := normalizePeerAddress(addr, s.params.DefaultPort)
	if err != nil {
		return
	}
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	for _, existing := range s.bootstrap {
		if existing == addr {
			s.rememberAddressLocked(addr, "bootstrap", time.Now())
			return
		}
	}
	s.bootstrap = append(s.bootstrap, addr)
	s.rememberAddressLocked(addr, "bootstrap", time.Now())
}

func (s *Server) SetListenHost(host string) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	s.listenHost = host
}

func (s *Server) ListenHost() string {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	return s.listenHost
}

func (s *Server) AddNode(ctx context.Context, addr string) error {
	normalized, err := normalizePeerAddress(addr, s.params.DefaultPort)
	if err != nil {
		return err
	}
	addr = normalized
	if len(s.connectOnly) > 0 {
		if _, ok := s.connectOnly[addr]; !ok {
			return fmt.Errorf("peer %s is not allowed by connect-only policy", addr)
		}
	}
	s.addBootstrapPeer(addr)
	if s.shouldThrottleOutboundDial(addr) {
		return nil
	}
	if s.outbound.Load() >= maxOutboundPeers || s.peers.Load() >= maxPeers {
		s.log.Printf("p2p addnode %s queued but peer capacity is full", addr)
		return nil
	}
	if !s.markOutbound(addr) {
		return nil
	}
	select {
	case s.outboundDialSem <- struct{}{}:
	default:
		s.unmarkOutbound(addr)
		return nil
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.unmarkOutbound(addr)
		defer func() { <-s.outboundDialSem }()
		dialer := net.Dialer{Timeout: 15 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			s.markKnownPeerFailure(addr)
			s.log.Printf("p2p dial %s: %v", addr, err)
			return
		}
		s.markKnownPeerConnected(addr, true)
		s.log.Printf("p2p dial %s connected", addr)
		s.handleConn(ctx, conn, true)
	}()
	return nil
}

func (s *Server) Start(ctx context.Context) error {
	addr := net.JoinHostPort(s.ListenHost(), strconv.Itoa(int(s.params.DefaultPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.setP2PRunning(true)
	defer s.setP2PRunning(false)
	s.log.Printf("Legacy Coin P2P listening on %s", ln.Addr())

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		s.closeActivePeerConnections()
		_ = ln.Close()
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, ln)
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.seedLoop(ctx)
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.superviseSyncLoop(ctx)
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.superviseWatchdogLoop(ctx)
	}()

	<-ctx.Done()
	s.closeActivePeerConnections()
	_ = ln.Close()
	s.wg.Wait()
	return nil
}

func (s *Server) superviseSyncLoop(ctx context.Context) {
	for ctx.Err() == nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.setSyncRunning(false)
					s.log.Printf("p2p sync loop recovered after panic: %v", r)
				}
			}()
			s.syncLoop(ctx)
		}()
		if ctx.Err() != nil {
			return
		}
		s.setSyncRunning(false)
		s.log.Printf("p2p sync loop stopped unexpectedly; restarting")
		time.Sleep(time.Second)
	}
}

func (s *Server) superviseWatchdogLoop(ctx context.Context) {
	for ctx.Err() == nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.setWatchdogRunning(false)
					s.log.Printf("p2p sync watchdog recovered after panic: %v", r)
				}
			}()
			s.watchdogLoop(ctx)
		}()
		if ctx.Err() != nil {
			return
		}
		s.setWatchdogRunning(false)
		s.log.Printf("p2p sync watchdog stopped unexpectedly; restarting")
		time.Sleep(time.Second)
	}
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Printf("p2p accept: %v", err)
			continue
		}
		if s.peers.Load() >= maxPeers {
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn, false)
		}()
	}
}

func (s *Server) seedLoop(ctx context.Context) {
	interval := s.reconnectEvery
	if interval <= 0 {
		interval = peerReconnectEvery
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.connectSeeds(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.connectSeeds(ctx)
		}
	}
}

func (s *Server) syncLoop(ctx context.Context) {
	s.setSyncRunning(true)
	defer s.setSyncRunning(false)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.noteSyncBeat()
			s.logSyncHeartbeat()
			s.requestSyncFromAheadPeers(false)
		}
	}
}

func (s *Server) watchdogLoop(ctx context.Context) {
	s.setWatchdogRunning(true)
	defer s.setWatchdogRunning(false)
	ticker := time.NewTicker(syncWatchdogEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.noteWatchdogTick()
			s.watchdogStep(ctx)
		}
	}
}

func (s *Server) watchdogStep(ctx context.Context) {
	peers := s.snapshotPeers()
	if len(peers) == 0 {
		s.noteWatchdogAction("no peers detected; reconnecting bootstrap peers")
		s.connectSeeds(ctx)
		return
	}

	localHeight := int32(-1)
	if tip := s.chain.Tip(); tip != nil {
		localHeight = tip.Height
	}
	bestPeerHeight := s.BestPeerHeight()
	behind := bestPeerHeight > localHeight
	health := s.healthSnapshot()
	lastHeightChangeAge, _ := health["last_height_change_ago_seconds"].(float64)
	lastHeaderAge, _ := health["last_header_received_ago_seconds"].(float64)
	lastBlockAge, _ := health["last_block_received_ago_seconds"].(float64)

	targetSeconds := chaincfg.TargetSpacing.Seconds()
	possiblyStalledAfter := 2 * targetSeconds
	stalledAfter := 3 * targetSeconds
	possiblyStalled := behind && lastHeightChangeAge > possiblyStalledAfter
	stalled := behind && lastHeightChangeAge > stalledAfter && (bestPeerHeight-localHeight) > 5
	candidateNoUsefulData := lastHeaderAge > possiblyStalledAfter && lastBlockAge > possiblyStalledAfter

	reconnected := int64(0)
	stalePeers := 0
	syncingPeers := 0
	now := time.Now()
	for _, p := range peers {
		p.lastMu.Lock()
		peerHeight := p.height
		lastSeen := p.lastSeen
		lastHeightUpdate := p.lastHeightUpdate
		lastSyncErr := p.lastSyncError
		p.lastMu.Unlock()

		if peerHeight > localHeight {
			syncingPeers++
		}
		metaStale := !lastHeightUpdate.IsZero() && now.Sub(lastHeightUpdate) > getPeerStaleThreshold()
		msgStale := !lastSeen.IsZero() && now.Sub(lastSeen) > getPeerStaleThreshold()
		if metaStale || msgStale {
			stalePeers++
		}
		if (stalled || candidateNoUsefulData) && (metaStale || msgStale || (behind && lastSyncErr != "")) {
			_ = p.conn.Close()
			reconnected++
		}
	}
	// Sweep timed-out getdata requests and re-request from alternative peers
	timedOut := s.sweepGetdataTimeouts()
	for _, hash := range timedOut {
		s.addBlockReqTimeout()
		s.log.Printf("p2p getdata timeout for block %s; will re-request", hash)
	}
	if len(timedOut) > 0 {
		s.log.Printf("p2p getdata timeout: %d block(s) timed out, forcing sync request", len(timedOut))
	}

	noUsefulChainData := candidateNoUsefulData &&
		(behind || syncingPeers > 0 || stalePeers > 0)

	requested := 0
	if behind || stalled || noUsefulChainData || len(timedOut) > 0 {
		requested = s.requestSyncFromAheadPeers(true)
	}
	if stalled || noUsefulChainData || reconnected > 0 {
		s.connectSeeds(ctx)
	}
	s.addWatchdogReconnects(reconnected)

	switch {
	case stalled:
		s.noteWatchdogAction(fmt.Sprintf("sync stalled after %.0f minutes without height progress; requested blocks from %d peer(s); reconnecting %d stale peer(s)", lastHeightChangeAge/60, requested, reconnected))
	case possiblyStalled:
		s.noteWatchdogAction(fmt.Sprintf("possibly stalled: no height progress for %.0f minutes; requested latest blocks from %d peer(s)", lastHeightChangeAge/60, requested))
	case behind:
		s.noteWatchdogAction(fmt.Sprintf("catching up: requested latest blocks from %d peer(s); behind peers by %d block(s)", requested, bestPeerHeight-localHeight))
	case noUsefulChainData:
		s.noteWatchdogAction(fmt.Sprintf("no useful chain data for %.0fs; reconnecting %d stale peer(s)", maxFloat(lastHeaderAge, lastBlockAge), reconnected))
	case stalePeers > 0:
		s.noteWatchdogAction(fmt.Sprintf("detected %d stale peer metadata entries; monitoring", stalePeers))
	default:
		s.noteWatchdogAction("watchdog healthy: peers connected and chain data flowing")
	}
}

func (s *Server) requestSyncFromAheadPeers(force bool) int {
	peers := s.syncCandidates()
	requested := 0
	for _, p := range peers {
		if err := s.requestSyncFromPeerIfBehind(p, force); err == nil {
			requested++
		}
	}
	return requested
}

func (s *Server) requestSyncFromPeerIfBehind(p *peer, force bool) error {
	if p == nil {
		return nil
	}
	localHeight := int32(-1)
	if tip := s.chain.Tip(); tip != nil {
		localHeight = tip.Height
	}
	p.lastMu.Lock()
	peerHeight := p.height
	lastReq := p.lastSyncRequest
	lastHeightUpdate := p.lastHeightUpdate
	p.lastMu.Unlock()
	peerMetadataStale := !lastHeightUpdate.IsZero() && time.Since(lastHeightUpdate) > 2*time.Minute
	if peerHeight <= localHeight && !force && !peerMetadataStale {
		return nil
	}
	if !force && !lastReq.IsZero() && time.Since(lastReq) < 8*time.Second {
		return nil
	}
	switch {
	case peerHeight > localHeight:
		s.log.Printf("p2p sync behind peer %s: local height %d peer height %d, requesting headers/blocks", p.remote, localHeight, peerHeight)
	case force && peerMetadataStale:
		s.log.Printf("p2p sync metadata refresh from peer %s: local height %d peer height %d (stale metadata), requesting headers/blocks", p.remote, localHeight, peerHeight)
	case force:
		s.log.Printf("p2p sync forced refresh from peer %s: local height %d peer height %d, requesting headers/blocks", p.remote, localHeight, peerHeight)
	default:
		return nil
	}
	s.noteSyncRequest()
	s.noteSyncPeer(p.remote)
	if err := s.requestHeaders(p); err != nil {
		p.setSyncResult(err)
		return err
	}
	if err := s.requestBlocks(p); err != nil {
		p.setSyncResult(err)
		return err
	}
	p.setSyncResult(nil)
	return nil
}

func (s *Server) bestSyncPeer() *peer {
	candidates := s.syncCandidates()
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0]
}

func (s *Server) syncCandidates() []*peer {
	localHeight := int32(-1)
	if tip := s.chain.Tip(); tip != nil {
		localHeight = tip.Height
	}
	now := time.Now()
	peers := s.snapshotPeers()
	candidates := make([]*peer, 0, len(peers))
	for _, p := range peers {
		p.lastMu.Lock()
		height := p.height
		lastSeen := p.lastSeen
		lastHeightUpdate := p.lastHeightUpdate
		lastSyncError := p.lastSyncError
		p.lastMu.Unlock()
		if height < 0 {
			continue
		}
		stale := (!lastHeightUpdate.IsZero() && now.Sub(lastHeightUpdate) > getPeerStaleThreshold()) || (!lastSeen.IsZero() && now.Sub(lastSeen) > getPeerStaleThreshold())
		if stale && height <= localHeight && lastSyncError != "" {
			continue
		}
		candidates = append(candidates, p)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a := candidates[i]
		b := candidates[j]
		a.lastMu.Lock()
		ah := a.height
		aReq := a.lastSyncRequest
		aErr := a.lastSyncError != ""
		aFailures := a.syncFailures
		aSuccesses := a.syncSuccesses
		a.lastMu.Unlock()
		b.lastMu.Lock()
		bh := b.height
		bReq := b.lastSyncRequest
		bErr := b.lastSyncError != ""
		bFailures := b.syncFailures
		bSuccesses := b.syncSuccesses
		b.lastMu.Unlock()
		if ah != bh {
			return ah > bh
		}
		if aErr != bErr {
			return !aErr
		}
		if aSuccesses != bSuccesses {
			return aSuccesses > bSuccesses
		}
		if aFailures != bFailures {
			return aFailures < bFailures
		}
		if aReq.IsZero() != bReq.IsZero() {
			return aReq.IsZero()
		}
		return aReq.Before(bReq)
	})
	if len(candidates) > 8 {
		return candidates[:8]
	}
	return candidates
}

func (s *Server) noteSyncPeer(addr string) {
	s.healthMu.Lock()
	if s.lastSyncPeer != "" && s.lastSyncPeer != addr {
		s.syncPeerRotations++
	}
	s.lastSyncPeer = addr
	s.syncRetryCount++
	s.healthMu.Unlock()
}

func (s *Server) addBlocksRequested(n int) {
	if n <= 0 {
		return
	}
	s.healthMu.Lock()
	s.blocksRequested += int64(n)
	s.healthMu.Unlock()
}

func (s *Server) addBlocksServed(n int) {
	if n <= 0 {
		return
	}
	s.healthMu.Lock()
	s.blocksServed += int64(n)
	s.healthMu.Unlock()
}

func (s *Server) addBlockInvsReceived(n int) {
	if n <= 0 {
		return
	}
	s.healthMu.Lock()
	s.blockInvsReceived += int64(n)
	s.healthMu.Unlock()
}

func (s *Server) addGetDataBlocksReceived(n int) {
	if n <= 0 {
		return
	}
	s.healthMu.Lock()
	s.getDataBlocksRecv += int64(n)
	s.healthMu.Unlock()
}

func (s *Server) addBlocksAnnounced(n int) {
	if n <= 0 {
		return
	}
	s.healthMu.Lock()
	s.blocksAnnounced += int64(n)
	s.healthMu.Unlock()
}

func (s *Server) addBlockReqTimeout() {
	s.healthMu.Lock()
	s.blockReqTimeouts++
	s.healthMu.Unlock()
}

func (s *Server) connectSeeds(ctx context.Context) {
	if s.outbound.Load() >= maxOutboundPeers || s.peers.Load() >= maxPeers {
		return
	}
	for _, peer := range s.bootstrapPeers() {
		if s.outbound.Load() >= maxOutboundPeers || s.peers.Load() >= maxPeers {
			return
		}
		if err := s.AddNode(ctx, peer); err != nil {
			s.log.Printf("p2p add bootstrap peer %s: %v", peer, err)
		}
	}
	for _, peer := range s.KnownAddresses() {
		if s.outbound.Load() >= maxOutboundPeers || s.peers.Load() >= maxPeers {
			return
		}
		if err := s.AddNode(ctx, peer); err != nil {
			s.log.Printf("p2p add known peer %s: %v", peer, err)
		}
	}
	if !s.seedPeers || len(s.connectOnly) > 0 {
		return
	}
	for _, peer := range s.params.FixedSeeds {
		if s.outbound.Load() >= maxOutboundPeers || s.peers.Load() >= maxPeers {
			return
		}
		addr, err := normalizePeerAddress(peer, s.params.DefaultPort)
		if err != nil {
			s.log.Printf("p2p fixed seed %s ignored: %v", peer, err)
			continue
		}
		s.rememberPeerAddress(addr, "fixed-seed")
		if err := s.AddNode(ctx, addr); err != nil {
			s.log.Printf("p2p add fixed seed peer %s: %v", addr, err)
		}
	}
	for _, seed := range s.params.DNSSeeds {
		lookupCtx, cancel := context.WithTimeout(ctx, dnsSeedLookupTimeout)
		hosts, err := net.DefaultResolver.LookupHost(lookupCtx, seed)
		cancel()
		if err != nil {
			s.logSeedError(seed, err)
			continue
		}
		if len(hosts) == 0 {
			s.logSeedError(seed, fmt.Errorf("no A/AAAA records"))
			continue
		}
		for _, host := range hosts {
			if s.outbound.Load() >= maxOutboundPeers || s.peers.Load() >= maxPeers {
				return
			}
			addr := net.JoinHostPort(host, strconv.Itoa(int(s.params.DefaultPort)))
			s.rememberPeerAddress(addr, "dns:"+seed)
			if err := s.AddNode(ctx, addr); err != nil {
				s.log.Printf("p2p add seed peer %s: %v", addr, err)
			}
		}
	}
}

func (s *Server) logSeedError(seed string, err error) {
	if !s.pretty {
		s.log.Printf("p2p seed %s: %v", seed, err)
		return
	}
	now := time.Now()
	s.seedMu.Lock()
	s.seedFailures[seed]++
	count := s.seedFailures[seed]
	last := s.seedLastLog[seed]
	if last.IsZero() || now.Sub(last) >= 5*time.Minute || count == 1 {
		s.seedLastLog[seed] = now
		s.seedMu.Unlock()
		if count == 1 {
			s.log.Printf("СЂСџРЉВ± DNS seed unavailable | %s | normal if seeds are offline/private test", seed)
		} else {
			s.log.Printf("СЂСџРЉВ± DNS seed warning repeated | %s | repeats %d | suppressing noise", seed, count)
		}
		return
	}
	s.seedMu.Unlock()
}

func (s *Server) knownNetAddresses(limit int, includeLocal bool) []wire.NetAddress {
	if limit <= 0 || limit > wire.MaxAddrPerMessage {
		limit = wire.MaxAddrPerMessage
	}
	infos := s.knownAddressInfos()
	out := make([]wire.NetAddress, 0, minInt(limit, len(infos)))
	for _, info := range infos {
		host, port, err := net.SplitHostPort(info.Addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if !relayableIP(ip, includeLocal) {
			continue
		}
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 {
			continue
		}
		seen := info.LastSeen
		if seen.IsZero() {
			seen = time.Now()
		}
		out = append(out, wire.NetAddress{
			Timestamp: uint32(seen.Unix()),
			Services:  nodeNetwork,
			IP:        ip,
			Port:      uint16(n),
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (s *Server) sendKnownAddresses(p *peer, limit int) error {
	if p == nil {
		return nil
	}
	includeLocal := localOrPrivateHost(splitHost(p.remote))
	addrs := s.knownNetAddresses(limit, includeLocal)
	payload, err := wire.AddrPayload(addrs)
	if err != nil {
		return err
	}
	if err := s.writePeerMessage(p, wire.CommandAddr, payload); err != nil {
		return err
	}
	s.log.Printf("p2p sent %d known address(es) to %s", len(addrs), p.remote)
	return nil
}

func (s *Server) requestKnownAddresses(p *peer) error {
	if p == nil {
		return nil
	}
	return s.writePeerMessage(p, wire.CommandGetAddr, nil)
}

func (s *Server) addressString(addr wire.NetAddress, allowLocal bool) (string, bool) {
	if addr.Port == 0 || !relayableIP(addr.IP, allowLocal) {
		return "", false
	}
	now := time.Now()
	seen := time.Unix(int64(addr.Timestamp), 0)
	if addr.Timestamp != 0 && now.Sub(seen) > addrMaxAge {
		return "", false
	}
	if addr.Timestamp != 0 && seen.After(now.Add(10*time.Minute)) {
		return "", false
	}
	normalized, err := normalizePeerAddress(net.JoinHostPort(addr.IP.String(), strconv.Itoa(int(addr.Port))), s.params.DefaultPort)
	if err != nil {
		return "", false
	}
	return normalized, true
}

func (s *Server) handleAddrPayload(ctx context.Context, p *peer, payload []byte) error {
	addrs, err := wire.ReadAddrPayload(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	allowLocal := localOrPrivateHost(splitHost(p.remote))
	added := 0
	dialed := 0
	relay := make([]wire.NetAddress, 0, minInt(maxAddrRelayItems, len(addrs)))
	for _, netAddr := range addrs {
		addr, ok := s.addressString(netAddr, allowLocal)
		if !ok {
			continue
		}
		if s.isSelfAddress(addr) {
			continue
		}
		fresh := s.rememberPeerAddress(addr, "addr:"+p.remote)
		if fresh {
			added++
			if relayableHost(splitHost(addr), false) && len(relay) < maxAddrRelayItems {
				relay = append(relay, netAddr)
			}
		}
		if fresh && dialed < maxAddrDialItems && !s.peerAddressActive(addr) {
			p.lastMu.Lock()
			overLimit := p.addrDialCount >= maxAddrDialsPerPeer
			p.lastMu.Unlock()
			if overLimit {
				continue
			}
			if err := s.AddNode(ctx, addr); err != nil {
				s.log.Printf("p2p discovered peer %s from %s not dialed: %v", addr, p.remote, err)
			} else {
				dialed++
				p.lastMu.Lock()
				p.addrDialCount++
				p.lastMu.Unlock()
			}
		}
	}
	if len(relay) > 0 {
		s.relayKnownAddresses(relay, p)
	}
	if added > 0 {
		s.log.Printf("p2p learned %d peer address(es) from %s; dialed %d", added, p.remote, dialed)
	}
	return nil
}

func (s *Server) isSelfAddress(addr string) bool {
	normalized, err := normalizePeerAddress(addr, s.params.DefaultPort)
	if err != nil {
		return false
	}
	listen := s.ListenAddr()
	if listen == "" {
		return false
	}
	listenNormalized, err := normalizePeerAddress(listen, s.params.DefaultPort)
	if err == nil && listenNormalized == normalized {
		return true
	}
	return false
}

func (s *Server) relayKnownAddresses(addrs []wire.NetAddress, skip *peer) {
	if len(addrs) == 0 {
		return
	}
	payload, err := wire.AddrPayload(addrs)
	if err != nil {
		s.log.Printf("p2p build addr relay: %v", err)
		return
	}
	sent := 0
	for _, p := range s.snapshotPeers() {
		if p == nil || p == skip || localOrPrivateHost(splitHost(p.remote)) {
			continue
		}
		if err := s.writePeerMessage(p, wire.CommandAddr, payload); err != nil {
			s.log.Printf("p2p relay addr to %s: %v", p.remote, err)
			continue
		}
		sent++
	}
	if sent > 0 {
		s.log.Printf("p2p relayed %d peer address(es) to %d peer(s)", len(addrs), sent)
	}
}

func (s *Server) peerAddressActive(addr string) bool {
	normalized, err := normalizePeerAddress(addr, s.params.DefaultPort)
	if err != nil {
		return false
	}
	for _, p := range s.snapshotPeers() {
		if p.remote == normalized {
			return true
		}
	}
	return false
}

func (s *Server) logConnectOnlyReject(addr string) {
	if !s.pretty {
		s.log.Printf("p2p rejected inbound peer %s by connect-only developer policy", addr)
		return
	}
	host, _, err := net.SplitHostPort(addr)
	key := addr
	if err == nil && host != "" {
		key = host
	}
	now := time.Now()
	s.rejectMu.Lock()
	s.rejectCounts[key]++
	count := s.rejectCounts[key]
	last := s.rejectLastLog[key]
	// Show first rejection from an address, then summarize at most every 5 minutes.
	if count == 1 || last.IsZero() || now.Sub(last) >= 5*time.Minute {
		s.rejectLastLog[key] = now
		s.rejectMu.Unlock()
		if count == 1 {
			s.log.Printf("СЂСџвЂєРЋРїС‘РЏ Connect-only active | rejected inbound peer %s | allowed peers only", addr)
		} else {
			s.log.Printf("СЂСџвЂєРЋРїС‘РЏ Connect-only summary | rejected inbound peer %s | repeats %d | suppressing repeats for 5m", key, count)
		}
		return
	}
	s.rejectMu.Unlock()
}

func (s *Server) bootstrapPeers() []string {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	return append([]string(nil), s.bootstrap...)
}

func (s *Server) markOutbound(addr string) bool {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if _, ok := s.knownOutbound[addr]; ok {
		return false
	}
	s.knownOutbound[addr] = struct{}{}
	return true
}

func (s *Server) unmarkOutbound(addr string) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	delete(s.knownOutbound, addr)
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn, outbound bool) {
	now := time.Now()
	p := &peer{conn: conn, outbound: outbound, remote: conn.RemoteAddr().String(), connected: now, lastSeen: now, lastPong: now, lastHeightUpdate: now}
	defer conn.Close()
	if s.isBanned(conn.RemoteAddr().String()) {
		s.log.Printf("p2p rejected banned peer %s", conn.RemoteAddr())
		return
	}
	host := splitHost(conn.RemoteAddr().String())
	if !outbound {
		if s.maxInboundPeers > 0 && s.inboundPeerCount() >= s.maxInboundPeers {
			s.log.Printf("p2p rejected inbound peer %s (max inbound reached: %d)", conn.RemoteAddr(), s.maxInboundPeers)
			return
		}
		if s.maxPerIP > 0 && s.inboundHostCount(host) >= s.maxPerIP {
			s.log.Printf("p2p rejected inbound peer %s (per-ip cap %d)", conn.RemoteAddr(), s.maxPerIP)
			return
		}
		subnet := subnetKey(host)
		if s.maxPerSubnet > 0 && subnet != "" && s.inboundSubnetCount(subnet) >= s.maxPerSubnet {
			s.log.Printf("p2p rejected inbound peer %s (subnet cap %d for %s)", conn.RemoteAddr(), s.maxPerSubnet, subnet)
			return
		}
	}
	if len(s.connectOnly) > 0 && !outbound {
		if _, ok := s.connectOnly[conn.RemoteAddr().String()]; !ok {
			s.logConnectOnlyReject(conn.RemoteAddr().String())
			return
		}
	}
	s.registerPeer(p)
	defer s.unregisterPeer(p)
	pingDone := make(chan struct{})
	go s.pingLoop(ctx, p, pingDone)
	defer close(pingDone)
	s.peers.Add(1)
	defer s.peers.Add(-1)
	if outbound {
		s.outbound.Add(1)
		defer s.outbound.Add(-1)
	}

	_ = conn.SetReadDeadline(time.Now().Add(peerHandshakeTimeout))
	if err := s.writeVersion(p, conn.RemoteAddr()); err != nil {
		s.log.Printf("p2p write version to %s: %v", conn.RemoteAddr(), err)
		return
	}

	gotVersion := false
	gotVerAck := false
	didSyncRequest := false
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := wire.ReadMessage(conn, s.params.MessageStart)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.log.Printf("p2p read from %s: %v (got_version=%v got_verack=%v)", conn.RemoteAddr(), err, gotVersion, gotVerAck)
			}
			return
		}
		p.addBytesRecv(uint64(len(msg.Payload) + 24))
		p.markSeen()
		s.notePeerMessage()
		if !s.allowPeerMessage(p, msg.Command) {
			s.scorePeer(p, 20, "peer message rate limit exceeded")
			s.log.Printf("p2p disconnect %s due to peer rate limit", conn.RemoteAddr())
			return
		}
		if gotVersion && gotVerAck {
			_ = conn.SetReadDeadline(time.Now().Add(peerIdleTimeout))
		}
		if !gotVersion || !gotVerAck {
			switch msg.Command {
			case wire.CommandVersion, wire.CommandVerAck, wire.CommandPing, wire.CommandPong:
				// Allowed during handshake.
			default:
				s.log.Printf("p2p protocol violation from %s: %s before handshake complete", conn.RemoteAddr(), msg.Command)
				return
			}
		}
		switch msg.Command {
		case wire.CommandVersion:
			gotVersion = true
			meta, err := s.parseVersionPayload(msg.Payload)
			if err != nil {
				s.scorePeer(p, 20, "bad version payload")
				s.log.Printf("p2p bad version from %s: %v", conn.RemoteAddr(), err)
				return
			}
			p.setVersionMeta(meta)
			if s.enforceChainID && s.chainID != "" && meta.ChainID != s.chainID {
				s.scorePeer(p, 100, "wrong or empty chain id")
				if s.pretty {
					s.log.Printf("СЂСџС™В« Peer rejected | %s | chain_id=%q expected=%q", conn.RemoteAddr(), meta.ChainID, s.chainID)
				} else {
					s.log.Printf("p2p reject wrong-chain peer %s chain_id=%q expected=%q", conn.RemoteAddr(), meta.ChainID, s.chainID)
				}
				return
			}
			if err := s.writePeerMessage(p, wire.CommandVerAck, nil); err != nil {
				s.log.Printf("p2p write verack to %s: %v", conn.RemoteAddr(), err)
				return
			}
		case wire.CommandVerAck:
			gotVerAck = true
			p.lastMu.Lock()
			p.wantHeaders = true
			p.lastMu.Unlock()
			_ = s.writePeerMessage(p, wire.CommandSendHeaders, nil)
		case wire.CommandSendHeaders:
			p.lastMu.Lock()
			p.wantHeaders = true
			p.lastMu.Unlock()
		case wire.CommandPing:
			if err := s.writePeerMessage(p, wire.CommandPong, msg.Payload); err != nil {
				s.log.Printf("p2p write pong to %s: %v", conn.RemoteAddr(), err)
				return
			}
		case wire.CommandPong:
			rtt := p.markPong()
			if s.pretty && s.heartbeat {
				height := int32(-1)
				if tip := s.chain.Tip(); tip != nil {
					height = tip.Height
				}
				name := s.peerLabel(p)
				if s.compactHeartbeat {
					s.log.Printf("СЂСџРЏвЂњ %s pong %.1fms | peers %d | height %d | storage РІСљвЂ¦", name, float64(rtt.Microseconds())/1000, s.PeerCount(), height)
				} else {
					s.log.Printf("СЂСџСџСћ PONG РІвЂ С’ %s | latency %.1fms | height %d | connection stable", name, float64(rtt.Microseconds())/1000, height)
				}
			}
		case wire.CommandBlock:
			s.noteBlockMessage()
			p.markBlockReceived()
			block, err := wire.ReadBlock(bytes.NewReader(msg.Payload))
			if err != nil {
				s.log.Printf("p2p parse block from %s: %v", conn.RemoteAddr(), err)
				return
			}
			// Clear any outstanding getdata tracking for this block hash
			if blockHash, hashErr := s.chain.BlockHash(block); hashErr == nil {
				s.clearGetdataReq(blockHash.String())
			}
			result, err := s.chain.ProcessBlockWithResult(block)
			if err != nil {
				p.setLastBlockReject(err.Error())
				blockHash := "unknown"
				if h, hashErr := s.chain.BlockHash(block); hashErr == nil {
					blockHash = h.String()
					s.sendRejectWithHash(p, "block", wire.RejectInvalid, err.Error(), h)
				} else {
					s.sendReject(p, "block", wire.RejectInvalid, err.Error())
				}
				s.log.Printf("p2p reject block from %s: hash=%s prev=%s reason=%v", conn.RemoteAddr(), blockHash, block.Header.PrevBlock.String(), err)
				return
			}
			p.setLastBlockResult(result)
			p.setLastBlockReject("")
			if s.pretty {
				s.log.Printf("рџ“¦ Block processed | status=%s | hash=%s | prev=%s | block_height=%d | parent_known=%v | extends_tip=%v | best_changed=%v | old_best=%d:%s | new_best=%d:%s | txs=%d | from=%s | reason=%s",
					result.Status, result.Hash, result.PrevHash, result.CalculatedHeight, result.ParentKnown, result.ExtendsActiveTip, result.BestChanged, result.OldBestHeight, result.OldBestHash, result.NewBestHeight, result.NewBestHash, len(block.Transactions), s.peerLabel(p), result.Reason)
			} else {
				s.log.Printf("p2p processed block from %s status=%s hash=%s height=%d best_changed=%v reason=%s", conn.RemoteAddr(), result.Status, result.Hash, result.CalculatedHeight, result.BestChanged, result.Reason)
			}
			// Any block that lands on the active chain makes the transactions it
			// confirmed unbuildable, so the mempool is reconciled for every
			// connected block and not only for the ones that change the best
			// chain. Leaving a confirmed transaction behind poisons every later
			// block template (bad-txns-inputs-missingorspent).
			if result.Connected && s.pool != nil {
				s.pool.RemoveForBlock(block)
			}
			if !result.Connected || !result.BestChanged {
				// The block's parent is unknown: store it as an orphan and
				// proactively request the missing parent by hash. Without
				// this the node only ever asks for blocks "after its tip"
				// (via getheaders/getblocks), so an orphan whose parent is
				// not on the active chain leaves sync stuck forever.
				if result.Status == blockchain.BlockStatusOrphan && !result.ParentKnown && result.PrevHash != "" {
					if payload, ok := s.tryClaimMissingParent(result.PrevHash); ok {
						s.sendMissingParentRequest(p, result.PrevHash, payload)
					}
				}
				continue
			}
			s.noteBlockConnected()
			hash, err := chainhash.FromString(result.Hash)
			if err == nil {
				s.log.Printf("p2p connected active block %s height=%d from %s", hash.String(), result.NewBestHeight, conn.RemoteAddr())
				// Relay the accepted block using the canonical Yespower block hash.
				// Do not announce back to the peer that supplied the block.
				s.announceBlockToPeersExcept(hash, p)
				_ = s.requestHeaders(p)
			}
		case wire.CommandTx:
			if s.pool == nil {
				continue
			}
			tx, err := wire.ReadTx(bytes.NewReader(msg.Payload))
			if err != nil {
				s.log.Printf("p2p parse tx from %s: %v", conn.RemoteAddr(), err)
				return
			}
			entry, err := s.pool.Add(s.chain, tx)
			if err != nil {
				if errors.Is(err, mempool.ErrOrphanTx) {
					continue
				}
				s.sendReject(p, "tx", wire.RejectInvalid, err.Error())
				s.log.Printf("p2p reject tx from %s: %v", conn.RemoteAddr(), err)
				continue
			}
			// Relay accepted transactions onward so wallet-created transactions can
			// propagate beyond the first peer and receivers can see pending funds.
			if s.pretty {
				s.log.Printf("СЂСџвЂ™С‘ TX accepted to mempool | %s | from %s", entry.TxID, s.peerLabel(p))
			}
			if h, err := chainhash.FromString(entry.TxID); err == nil {
				s.announceTxToPeersExcept(h, p)
				if s.pretty {
					s.log.Printf("СЂСџвЂњР€ TX relayed | %s | peers %d", entry.TxID, s.PeerCount())
				}
			}
		case wire.CommandInv:
			inv, err := wire.ReadInvPayload(bytes.NewReader(msg.Payload))
			if err != nil {
				s.log.Printf("p2p parse inv from %s: %v", conn.RemoteAddr(), err)
				return
			}
			blockInvs := 0
			for _, item := range inv {
				if item.Type == wire.InvTypeBlock {
					blockInvs++
				}
			}
			s.addBlockInvsReceived(blockInvs)
			if err := s.requestUnknownBlocks(p, inv); err != nil {
				s.log.Printf("p2p request blocks from %s: %v", conn.RemoteAddr(), err)
				return
			}
		case wire.CommandGetData:
			inv, err := wire.ReadInvPayload(bytes.NewReader(msg.Payload))
			if err != nil {
				s.log.Printf("p2p parse getdata from %s: %v", conn.RemoteAddr(), err)
				return
			}
			blockRequests := 0
			for _, item := range inv {
				if item.Type == wire.InvTypeBlock {
					blockRequests++
				}
			}
			s.addGetDataBlocksReceived(blockRequests)
			if err := s.serveInventory(p, inv); err != nil {
				s.log.Printf("p2p serve getdata to %s: %v", conn.RemoteAddr(), err)
				return
			}
		case wire.CommandGetAddr:
			if err := s.sendKnownAddresses(p, wire.MaxAddrPerMessage); err != nil {
				s.log.Printf("p2p serve getaddr to %s: %v", conn.RemoteAddr(), err)
				return
			}
		case wire.CommandAddr:
			if err := s.handleAddrPayload(ctx, p, msg.Payload); err != nil {
				s.log.Printf("p2p parse addr from %s: %v", conn.RemoteAddr(), err)
				return
			}
		case wire.CommandGetBlocks:
			req, err := wire.ReadGetBlocks(bytes.NewReader(msg.Payload))
			if err != nil {
				s.log.Printf("p2p parse getblocks from %s: %v", conn.RemoteAddr(), err)
				return
			}
			if err := s.serveBlockInventory(p, req); err != nil {
				s.log.Printf("p2p serve getblocks to %s: %v", conn.RemoteAddr(), err)
				return
			}
		case wire.CommandGetHeaders:
			req, err := wire.ReadGetBlocks(bytes.NewReader(msg.Payload))
			if err != nil {
				s.log.Printf("p2p parse getheaders from %s: %v", conn.RemoteAddr(), err)
				return
			}
			if err := s.serveHeaders(p, req); err != nil {
				s.log.Printf("p2p serve headers to %s: %v", conn.RemoteAddr(), err)
				return
			}
		case wire.CommandHeaders:
			s.noteHeaderMessage()
			p.markHeaderReceived()
			s.healthMu.Lock()
			s.headersBatchesRecv++
			s.healthMu.Unlock()
			headers, err := wire.ReadHeadersPayload(bytes.NewReader(msg.Payload))
			if err != nil {
				s.log.Printf("p2p parse headers from %s: %v", conn.RemoteAddr(), err)
				return
			}
			if err := s.requestHeaderBlocks(p, headers); err != nil {
				// A peer that is behind us can legitimately send a stale header
				// batch when we also asked it for headers. Do not disconnect for
				// non-connecting header batches; keep the peer available so its
				// own sync request can fetch our blocks.
				s.healthMu.Lock()
				s.headersRejected++
				s.healthMu.Unlock()
				s.log.Printf("p2p ignore non-syncable headers from %s: %v", conn.RemoteAddr(), err)
			}
		case wire.CommandReject:
			reject, err := wire.ReadReject(bytes.NewReader(msg.Payload))
			if err != nil {
				s.log.Printf("p2p bad reject message from %s: %v", p.remote, err)
				break
			}
			s.log.Printf("p2p reject from %s: %s %s", p.remote, reject.Cmd, reject.Reason)
		}
		if gotVersion && gotVerAck && !didSyncRequest {
			didSyncRequest = true
			if s.pretty {
				s.log.Printf("СЂСџРЉС’ Connected peer | %s | outbound=%v | height %d | chain_id=%s", s.peerLabel(p), outbound, p.height, p.chainID)
			} else {
				s.log.Printf("p2p handshake complete with %s outbound=%v", conn.RemoteAddr(), outbound)
			}
			_ = conn.SetReadDeadline(time.Now().Add(peerIdleTimeout))
			if err := s.requestHeaders(p); err != nil {
				s.log.Printf("p2p request headers from %s: %v", conn.RemoteAddr(), err)
			}
			if err := s.requestBlocks(p); err != nil {
				s.log.Printf("p2p request blocks from %s: %v", conn.RemoteAddr(), err)
			}
			if outbound {
				s.rememberPeerAddress(p.remote, "outbound-handshake")
			}
			s.markKnownPeerConnected(p.remote, outbound)
			if err := s.sendKnownAddresses(p, 32); err != nil {
				s.log.Printf("p2p send addr to %s: %v", conn.RemoteAddr(), err)
			}
			if err := s.requestKnownAddresses(p); err != nil {
				s.log.Printf("p2p request addr from %s: %v", conn.RemoteAddr(), err)
			}
		}
	}
}

func (p *peer) markSeen() {
	p.lastMu.Lock()
	p.lastSeen = time.Now()
	p.lastMu.Unlock()
}

func (p *peer) markPong() time.Duration {
	p.lastMu.Lock()
	now := time.Now()
	p.lastSeen = now
	p.lastPong = now
	if !p.lastPing.IsZero() {
		p.lastRTT = now.Sub(p.lastPing)
		if p.minRTT == 0 || p.lastRTT < p.minRTT {
			p.minRTT = p.lastRTT
		}
	}
	p.missedPongs = 0
	rtt := p.lastRTT
	p.lastMu.Unlock()
	return rtt
}

func (p *peer) markPing() {
	p.lastMu.Lock()
	p.lastPing = time.Now()
	p.missedPongs++
	p.lastMu.Unlock()
}

func (p *peer) setSyncResult(err error) {
	p.lastMu.Lock()
	p.lastSyncRequest = time.Now()
	if err != nil {
		p.lastSyncError = err.Error()
		p.syncFailures++
	} else {
		p.lastSyncError = ""
		p.syncSuccesses++
	}
	p.lastMu.Unlock()
}

func (p *peer) markHeaderReceived() {
	p.lastMu.Lock()
	p.lastHeaderRecv = time.Now()
	p.lastMu.Unlock()
}

func (p *peer) markBlockReceived() {
	p.lastMu.Lock()
	p.lastBlockRecv = time.Now()
	p.lastMu.Unlock()
}

func (p *peer) markBlocksRequested(n int) {
	if n <= 0 {
		return
	}
	p.lastMu.Lock()
	p.blocksRequested += n
	p.lastSyncRequest = time.Now()
	p.lastMu.Unlock()
}

func (p *peer) markBlocksServed(n int) {
	if n <= 0 {
		return
	}
	p.lastMu.Lock()
	p.blocksServed += n
	p.lastMu.Unlock()
}

func (p *peer) setLastBlockReject(reason string) {
	p.lastMu.Lock()
	p.lastBlockReject = reason
	p.lastMu.Unlock()
}

func (p *peer) setLastLocatorTip(hash string) {
	p.lastMu.Lock()
	p.lastLocatorTip = hash
	p.lastSyncRequest = time.Now()
	p.lastMu.Unlock()
}

func (p *peer) setLastBlockResult(result blockchain.BlockProcessResult) {
	p.lastMu.Lock()
	p.lastBlockHash = result.Hash
	p.lastBlockPrev = result.PrevHash
	p.lastBlockHeight = result.CalculatedHeight
	p.lastBlockReason = result.Reason
	if result.BestChanged {
		p.lastBestUpdate = fmt.Sprintf("%d:%s -> %d:%s", result.OldBestHeight, result.OldBestHash, result.NewBestHeight, result.NewBestHash)
	}
	if result.NewBestHeight > p.height {
		p.height = result.NewBestHeight
		p.lastHeightUpdate = time.Now()
	}
	if result.Status == blockchain.BlockStatusSideChain && result.OldBestHeight < p.height {
		p.lastSyncError = fmt.Sprintf("peer advertised height %d but sent non-connecting side-chain block %s at height %d", p.height, result.Hash, result.CalculatedHeight)
	}
	if result.Status == blockchain.BlockStatusOrphan && result.OldBestHeight < p.height {
		p.lastSyncError = fmt.Sprintf("peer advertised height %d but sent block %s with unknown parent %s after local tip %s", p.height, result.Hash, result.PrevHash, result.OldBestHash)
	}
	if result.Connected && result.BestChanged {
		p.lastSyncError = ""
		p.syncSuccesses++
	}
	p.lastMu.Unlock()
}

func (p *peer) lastActivity() (seen time.Time, pong time.Time) {
	p.lastMu.Lock()
	defer p.lastMu.Unlock()
	return p.lastSeen, p.lastPong
}

func (s *Server) peerLabel(p *peer) string {
	if s.trustedPeerName != "" {
		return s.trustedPeerName
	}
	return p.remote
}

func (s *Server) pingLoop(ctx context.Context, p *peer, done <-chan struct{}) {
	interval := peerPingInterval
	if s.pingInterval > 0 {
		interval = s.pingInterval
	} else if s.heartbeatInterval > 0 {
		interval = s.heartbeatInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			seen, pong := p.lastActivity()
			if time.Since(seen) > peerPongTimeout && time.Since(pong) > peerPongTimeout {
				s.log.Printf("p2p peer %s liveness timeout; closing connection", p.remote)
				_ = p.conn.Close()
				return
			}
			nonce := make([]byte, 8)
			if _, err := rand.Read(nonce); err != nil {
				binary.LittleEndian.PutUint64(nonce, uint64(time.Now().UnixNano()))
			}
			p.markPing()
			if s.pretty && s.heartbeat && !s.compactHeartbeat {
				s.log.Printf("СЂСџРЏвЂњ PING РІвЂ вЂ™ %s", s.peerLabel(p))
			}
			if err := s.writePeerMessage(p, wire.CommandPing, nonce); err != nil {
				s.log.Printf("p2p ping %s failed: %v", p.remote, err)
				_ = p.conn.Close()
				return
			}
		}
	}
}

func (s *Server) registerPeer(p *peer) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.activePeers == nil {
		s.activePeers = make(map[*peer]struct{})
	}
	s.activePeers[p] = struct{}{}
}

func (s *Server) unregisterPeer(p *peer) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	delete(s.activePeers, p)
}

func (s *Server) snapshotPeers() []*peer {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	out := make([]*peer, 0, len(s.activePeers))
	for p := range s.activePeers {
		out = append(out, p)
	}
	return out
}

func (s *Server) closeActivePeerConnections() {
	for _, p := range s.snapshotPeers() {
		_ = p.conn.Close()
	}
}

func (s *Server) writePeerMessage(p *peer, command string, payload []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(peerWriteTimeout))
	defer p.conn.SetWriteDeadline(time.Time{})
	err := wire.WriteMessage(p.conn, s.params.MessageStart, command, payload)
	if err == nil {
		p.addBytesSent(uint64(len(payload) + 24))
	}
	return err
}

func (s *Server) sendReject(p *peer, cmd string, code uint8, reason string) {
	reject := wire.NewReject(cmd, code, reason)
	payload, err := reject.Bytes()
	if err != nil {
		return
	}
	_ = s.writePeerMessage(p, wire.CommandReject, payload)
}

func (s *Server) sendRejectWithHash(p *peer, cmd string, code uint8, reason string, hash chainhash.Hash) {
	reject := wire.NewRejectWithHash(cmd, code, reason, hash)
	payload, err := reject.Bytes()
	if err != nil {
		return
	}
	_ = s.writePeerMessage(p, wire.CommandReject, payload)
}

func (s *Server) writeVersion(p *peer, remote net.Addr) error {
	payload, err := s.versionPayload(remote)
	if err != nil {
		return err
	}
	return s.writePeerMessage(p, wire.CommandVersion, payload)
}

func (s *Server) versionPayload(remote net.Addr) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, protocolVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, nodeNetwork); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, time.Now().Unix()); err != nil {
		return nil, err
	}
	writeNetAddr(&buf, remote, s.params.DefaultPort)
	writeNetAddr(&buf, nil, s.params.DefaultPort)
	nonce, err := randomUint64()
	if err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, nonce); err != nil {
		return nil, err
	}
	if err := wire.WriteVarBytes(&buf, []byte(userAgent)); err != nil {
		return nil, err
	}
	height := int32(-1)
	if tip := s.chain.Tip(); tip != nil {
		height = tip.Height
	}
	if err := binary.Write(&buf, binary.LittleEndian, height); err != nil {
		return nil, err
	}
	if err := buf.WriteByte(0); err != nil {
		return nil, err
	}
	if s.enforceChainID {
		if err := wire.WriteVarBytes(&buf, []byte(s.chainID)); err != nil {
			return nil, err
		}
		if _, err := buf.Write(s.params.MessageStart[:]); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type versionMeta struct {
	Version int32
	SubVer  string
	Height  int32
	ChainID string
}

func (s *Server) parseVersionPayload(payload []byte) (versionMeta, error) {
	var meta versionMeta
	r := bytes.NewReader(payload)
	if err := binary.Read(r, binary.LittleEndian, &meta.Version); err != nil {
		return meta, err
	}
	// services, timestamp, addr_recv, addr_from, nonce
	if r.Len() < 8+8+26+26+8 {
		return meta, fmt.Errorf("short version payload")
	}
	if _, err := r.Seek(8+8+26+26+8, io.SeekCurrent); err != nil {
		return meta, err
	}
	ua, err := wire.ReadVarBytes(r, 256, "user agent")
	if err != nil {
		return meta, err
	}
	meta.SubVer = string(ua)
	if err := binary.Read(r, binary.LittleEndian, &meta.Height); err != nil {
		return meta, err
	}
	// relay byte is optional in older payloads.
	if r.Len() > 0 {
		_, _ = r.ReadByte()
	}
	// V5.12+ metadata: varbytes chain_id + 4-byte message start. Older peers may omit it.
	if r.Len() > 0 {
		chainID, err := wire.ReadVarBytes(r, 256, "chain id")
		if err == nil {
			meta.ChainID = string(chainID)
		}
	}
	return meta, nil
}

func (p *peer) setVersionMeta(meta versionMeta) {
	p.lastMu.Lock()
	defer p.lastMu.Unlock()
	p.version = meta.Version
	p.subver = meta.SubVer
	p.height = meta.Height
	p.chainID = meta.ChainID
	p.lastHeightUpdate = time.Now()
}

func (p *peer) setAdvertisedHeight(height int32) {
	p.lastMu.Lock()
	if height > p.height {
		p.height = height
	}
	p.lastHeightUpdate = time.Now()
	p.lastMu.Unlock()
}

func (p *peer) markHeightMetadataSeen() {
	p.lastMu.Lock()
	p.lastHeightUpdate = time.Now()
	p.lastMu.Unlock()
}

func (p *peer) addBytesSent(n uint64) {
	p.lastMu.Lock()
	p.bytesSent += n
	p.lastMu.Unlock()
}

func (p *peer) addBytesRecv(n uint64) {
	p.lastMu.Lock()
	p.bytesRecv += n
	p.lastMu.Unlock()
}

func (s *Server) scorePeer(p *peer, score int, reason string) {
	if !s.peerSafety || p == nil || score <= 0 {
		return
	}
	now := time.Now()
	p.lastMu.Lock()
	if s.misbehaviorDecay > 0 && !p.lastPenaltyAt.IsZero() && p.banScore > 0 {
		elapsed := now.Sub(p.lastPenaltyAt)
		steps := int(elapsed / s.misbehaviorDecay)
		if steps > 0 {
			p.banScore -= steps
			if p.banScore < 0 {
				p.banScore = 0
			}
			p.lastPenaltyAt = p.lastPenaltyAt.Add(time.Duration(steps) * s.misbehaviorDecay)
		}
	}
	p.banScore += score
	total := p.banScore
	p.lastPenaltyAt = now
	p.lastPenaltyReason = reason
	p.lastMu.Unlock()
	if s.banThreshold > 0 && total >= s.banThreshold {
		d := s.banDuration
		if d <= 0 {
			d = time.Hour
		}
		s.banPeer(p.remote, d, reason)
		p.lastMu.Lock()
		p.bannedUntil = now.Add(d)
		p.lastMu.Unlock()
		_ = p.conn.Close()
	}
}

func (s *Server) banPeer(addr string, d time.Duration, reason string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	s.bannedMu.Lock()
	if s.bannedUntil == nil {
		s.bannedUntil = make(map[string]time.Time)
	}
	s.bannedUntil[host] = time.Now().Add(d)
	s.bannedMu.Unlock()
	s.log.Printf("p2p temporarily banned peer %s for %s: %s", host, d, reason)
}

func (s *Server) isBanned(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	s.bannedMu.Lock()
	defer s.bannedMu.Unlock()
	until, ok := s.bannedUntil[host]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(s.bannedUntil, host)
		return false
	}
	return true
}

func (s *Server) DisconnectNode(addr string) bool {
	for _, p := range s.snapshotPeers() {
		if p.remote == addr || strings.HasPrefix(p.remote, addr) {
			_ = p.conn.Close()
			return true
		}
	}
	return false
}

func (s *Server) ConnectionCount() int32 { return s.PeerCount() }

func writeNetAddr(w io.Writer, addr net.Addr, defaultPort uint16) {
	_ = binary.Write(w, binary.LittleEndian, nodeNetwork)
	var ip [16]byte
	port := defaultPort
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if parsed := tcp.IP.To16(); parsed != nil {
			copy(ip[:], parsed)
		}
		if tcp.Port > 0 {
			port = uint16(tcp.Port)
		}
	}
	_, _ = w.Write(ip[:])
	_ = binary.Write(w, binary.BigEndian, port)
}

func randomUint64() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("random nonce: %w", err)
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func (s *Server) requestHeaders(p *peer) error {
	locator := s.chain.Locator()
	if len(locator) == 0 {
		return nil
	}
	payload, err := (wire.GetBlocks{Version: protocolVersion, Locator: locator}).Bytes()
	if err != nil {
		return err
	}
	s.log.Printf("p2p send getheaders to %s locator_tip=%s", p.remote, locator[0].String())
	s.noteSyncRequest()
	s.noteGetHeadersSent()
	p.setLastLocatorTip(locator[0].String())
	return s.writePeerMessage(p, wire.CommandGetHeaders, payload)
}

func (s *Server) requestBlocks(p *peer) error {
	locator := s.chain.Locator()
	if len(locator) == 0 {
		return nil
	}
	payload, err := (wire.GetBlocks{Version: protocolVersion, Locator: locator}).Bytes()
	if err != nil {
		return err
	}
	s.log.Printf("p2p send getblocks to %s locator_tip=%s", p.remote, locator[0].String())
	s.noteSyncRequest()
	s.noteGetBlocksSent()
	p.setLastLocatorTip(locator[0].String())
	return s.writePeerMessage(p, wire.CommandGetBlocks, payload)
}

func (s *Server) requestUnknownBlocks(p *peer, inv []wire.InvVect) error {
	want := make([]wire.InvVect, 0, len(inv))
	requestedHeaders := false
	for _, v := range inv {
		switch v.Type {
		case wire.InvTypeBlock:
			if s.chain.HasBlock(v.Hash.String()) {
				s.log.Printf("p2p received inv block %s from %s: already known", v.Hash.String(), p.remote)
				continue
			}
			s.log.Printf("p2p received inv block %s from %s: unknown, requesting getdata", v.Hash.String(), p.remote)
			// Ask for headers once per inv batch so a node that is behind can
			// recover any missing ancestors, but do not wait for headers before
			// requesting the announced block body. The common case is a peer
			// announcing the next block after our tip; waiting for a header round
			// trip can leave followers stuck even though they received the INV.
			if !requestedHeaders {
				requestedHeaders = true
				if err := s.requestHeaders(p); err != nil {
					s.log.Printf("p2p request headers for inv %s: %v", v.Hash.String(), err)
				}
			}
			want = append(want, v)
		case wire.InvTypeTx:
			if s.pool == nil {
				continue
			}
			if _, ok := s.pool.Lookup(v.Hash.String()); ok {
				continue
			}
			s.log.Printf("p2p received inv tx %s from %s: unknown, requesting getdata", v.Hash.String(), p.remote)
			want = append(want, v)
		}
		if len(want) >= maxGetDataItems {
			break
		}
	}
	if len(want) == 0 {
		return nil
	}
	payload, err := wire.InvPayload(want)
	if err != nil {
		return err
	}
	requestedBlocks := 0
	for _, item := range want {
		if item.Type == wire.InvTypeBlock {
			requestedBlocks++
		}
	}
	p.markBlocksRequested(requestedBlocks)
	s.addBlocksRequested(requestedBlocks)
	s.log.Printf("p2p sent getdata for %d inventory items to %s", len(want), p.remote)
	return s.writePeerMessage(p, wire.CommandGetData, payload)
}

// tryClaimMissingParent checks the dedup map for parentHash under
// missingParentMu and, if not recently seen, builds and returns a getdata
// payload. Returns (ok, payload). Callers must NOT hold any peer writeMu
// (locking convention: missingParentMu before writeMu).
func (s *Server) tryClaimMissingParent(parentHash string) ([]byte, bool) {
	if parentHash == "" {
		return nil, false
	}
	now := time.Now()
	s.missingParentMu.Lock()
	if s.missingParentSeen == nil {
		s.missingParentSeen = make(map[string]time.Time)
	}
	if last, ok := s.missingParentSeen[parentHash]; ok && now.Sub(last) < missingParentTTL {
		s.missingParentMu.Unlock()
		return nil, false
	}
	if len(s.missingParentSeen) >= missingParentSeenCap {
		for h, t := range s.missingParentSeen {
			if now.Sub(t) > missingParentEvictTTL {
				delete(s.missingParentSeen, h)
			}
		}
	}
	s.missingParentSeen[parentHash] = now
	s.missingParentMu.Unlock()

	h, err := chainhash.FromString(parentHash)
	if err != nil {
		s.log.Printf("p2p orphan parent %s not a valid hash: %v", parentHash, err)
		return nil, false
	}
	inv := []wire.InvVect{{Type: wire.InvTypeBlock, Hash: h}}
	payload, err := wire.InvPayload(inv)
	if err != nil {
		s.log.Printf("p2p orphan parent %s inv payload: %v", parentHash, err)
		return nil, false
	}
	return payload, true
}

// sendMissingParentRequest sends the pre-built getdata payload to peer p,
// then spawns a goroutine to ask a few other ahead peers asynchronously.
func (s *Server) sendMissingParentRequest(p *peer, parentHash string, payload []byte) {
	if p != nil {
		if err := s.writePeerMessage(p, wire.CommandGetData, payload); err != nil {
			s.log.Printf("p2p request missing parent %s from %s: %v", parentHash, p.remote, err)
		} else {
			atomic.AddInt64(&s.missingParentReqs, 1)
			p.markBlocksRequested(1)
			s.addBlocksRequested(1)
			if s.pretty {
				s.log.Printf("рџ“¦ Orphan parent %s unknown; requested getdata from %s", parentHash, s.peerLabel(p))
			} else {
				s.log.Printf("p2p orphan block parent %s unknown; requested getdata from %s", parentHash, p.remote)
			}
		}
	}

	// Ask a few other ahead peers asynchronously so one unhelpful peer
	// cannot block sync. Runs in its own goroutine with a short per-write
	// deadline; it never touches consensus state.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.requestMissingParentFromOthers(parentHash, payload, p)
	}()
}

// requestMissingParentFromOthers asks up to maxMissingParentPeers ahead peers
// (other than skip) for the missing parent block identified by payload's inv.
func (s *Server) requestMissingParentFromOthers(parentHash string, payload []byte, skip *peer) {
	localHeight := int32(-1)
	if tip := s.chain.Tip(); tip != nil {
		localHeight = tip.Height
	}
	asked := 0
	for _, other := range s.syncCandidates() {
		if asked >= maxMissingParentPeers {
			break
		}
		if other == nil || other == skip {
			continue
		}
		other.lastMu.Lock()
		peerHeight := other.height
		otherErr := other.lastSyncError
		other.lastMu.Unlock()
		if peerHeight <= localHeight {
			continue
		}
		if otherErr != "" {
			continue
		}
		_ = other.conn.SetWriteDeadline(time.Now().Add(missingParentWriteTO))
		err := s.writePeerMessage(other, wire.CommandGetData, payload)
		_ = other.conn.SetWriteDeadline(time.Time{})
		if err != nil {
			continue
		}
		asked++
		atomic.AddInt64(&s.missingParentReqs, 1)
		other.markBlocksRequested(1)
		s.addBlocksRequested(1)
		s.log.Printf("p2p orphan block parent %s unknown; also requested getdata from %s", parentHash, other.remote)
	}
}

func (s *Server) serveInventory(p *peer, inv []wire.InvVect) error {
	inv = limitInv(inv, maxServeInvItems)
	servedBlocks := 0
	for _, v := range inv {
		switch v.Type {
		case wire.InvTypeBlock:
			s.log.Printf("p2p received getdata block %s from %s", v.Hash.String(), p.remote)
			block, _, err := s.chain.BlockByHash(v.Hash.String())
			if err != nil {
				s.log.Printf("p2p getdata block %s from %s: not found", v.Hash.String(), p.remote)
				continue
			}
			payload, err := block.Bytes()
			if err != nil {
				return err
			}
			if err := s.writePeerMessage(p, wire.CommandBlock, payload); err != nil {
				return err
			}
			servedBlocks++
			s.log.Printf("p2p sent block %s to %s", v.Hash.String(), p.remote)
		case wire.InvTypeTx:
			if s.pool == nil {
				continue
			}
			tx, ok := s.pool.Lookup(v.Hash.String())
			if !ok {
				continue
			}
			payload, err := tx.Bytes()
			if err != nil {
				return err
			}
			if err := s.writePeerMessage(p, wire.CommandTx, payload); err != nil {
				return err
			}
		}
	}
	p.markBlocksServed(servedBlocks)
	s.addBlocksServed(servedBlocks)
	return nil
}

func limitInv(inv []wire.InvVect, max int) []wire.InvVect {
	if max <= 0 {
		return nil
	}
	if len(inv) <= max {
		return inv
	}
	return inv[:max]
}

func max32(a int32, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

func maxFloat(a float64, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Server) announceTip(p *peer) error {
	tip := s.chain.Tip()
	if tip == nil || tip.Hash == "" {
		return nil
	}
	blockHash, err := chainhash.FromString(tip.Hash)
	if err != nil {
		return err
	}
	payload, err := wire.InvPayload([]wire.InvVect{{Type: wire.InvTypeBlock, Hash: blockHash}})
	if err != nil {
		return err
	}
	s.addBlocksAnnounced(1)
	return s.writePeerMessage(p, wire.CommandInv, payload)
}

func (s *Server) serveBlockInventory(p *peer, req wire.GetBlocks) error {
	headers, err := s.chain.HeadersAfter(req.Locator, req.Stop, maxServeInvItems)
	if err != nil {
		return err
	}
	if len(headers) == 0 {
		s.log.Printf("p2p no block inventory after locator for %s", p.remote)
		return nil
	}
	inv := make([]wire.InvVect, 0, len(headers))
	for _, header := range headers {
		hash, err := s.chain.HashHeader(header)
		if err != nil {
			return err
		}
		inv = append(inv, wire.InvVect{Type: wire.InvTypeBlock, Hash: hash})
	}
	payload, err := wire.InvPayload(inv)
	if err != nil {
		return err
	}
	s.addBlocksAnnounced(len(inv))
	s.log.Printf("p2p serve %d block inv items to %s", len(inv), p.remote)
	return s.writePeerMessage(p, wire.CommandInv, payload)
}

func (s *Server) serveHeaders(p *peer, req wire.GetBlocks) error {
	headers, err := s.chain.HeadersAfter(req.Locator, req.Stop, wire.MaxHeadersPerMessage)
	if err != nil {
		return err
	}
	payload, err := wire.HeadersPayload(headers)
	if err != nil {
		return err
	}
	s.log.Printf("p2p serve %d headers to %s", len(headers), p.remote)
	return s.writePeerMessage(p, wire.CommandHeaders, payload)
}

func (s *Server) requestHeaderBlocks(p *peer, headers []wire.BlockHeader) error {
	if len(headers) == 0 {
		p.markHeightMetadataSeen()
		return nil
	}
	tipHeight := int32(-1)
	tipHash := ""
	if tip := s.chain.Tip(); tip != nil {
		tipHeight = tip.Height
		tipHash = tip.Hash
	}
	firstPrev := headers[0].PrevBlock.String()
	s.log.Printf("p2p received %d headers from %s (first_prev=%s, our_tip=%d:%s)", len(headers), p.remote, firstPrev, tipHeight, tipHash)
	hashes, err := s.chain.ValidateHeaderSequence(headers)
	if err != nil {
		s.log.Printf("p2p header batch from %s REJECTED by ValidateHeaderSequence: %v (first_prev=%s, our_tip=%d:%s, batch_len=%d)",
			p.remote, err, firstPrev, tipHeight, tipHash, len(headers))
		// Fix #9: if the batch does not connect to our tip, the peer is
		// likely multiple batches ahead and the announced PrevBlock is a
		// block we do not yet have. Request that exact parent by hash
		// (same mechanism as the block-orphan path) instead of stalling.
		if firstPrev != "" && firstPrev != tipHash {
			if payload, ok := s.tryClaimMissingParent(firstPrev); ok {
				s.sendMissingParentRequest(p, firstPrev, payload)
			}
		}
		return err
	}
	if tipHeight >= 0 {
		// Cap at int32 max to satisfy gosec G115 (len is bounded by
		// MaxHeadersPerMessage=2000 so this never overflows in practice).
		advertised := tipHeight + int32(len(hashes))
		if advertised < 0 {
			advertised = 0
		}
		p.setAdvertisedHeight(advertised)
	}
	// Build the full list of wanted inv entries (all headers, no cap).
	// Split into batches of maxGetDataItems and send one getdata per batch.
	allWant := make([]wire.InvVect, 0, len(hashes)*2)
	skipped := 0
	dualHash := 0
	for i, hash := range hashes {
		if s.chain.HasBlock(hash.String()) {
			skipped++
			continue
		}
		allWant = append(allWant, wire.InvVect{Type: wire.InvTypeBlock, Hash: hash})
		if legacy, lerr := s.chain.LegacyHeaderHash(headers[i]); lerr == nil && legacy != hash {
			allWant = append(allWant, wire.InvVect{Type: wire.InvTypeBlock, Hash: legacy})
			dualHash++
		}
	}
	if len(allWant) == 0 {
		s.log.Printf("p2p validated %d headers from %s but all %d block bodies already present (want=0, skipped=%d)",
			len(hashes), p.remote, len(hashes), skipped)
		return nil
	}
	totalRequested := 0
	for batchStart := 0; batchStart < len(allWant); batchStart += maxGetDataItems {
		batchEnd := batchStart + maxGetDataItems
		if batchEnd > len(allWant) {
			batchEnd = len(allWant)
		}
		batch := allWant[batchStart:batchEnd]
		payload, err := wire.InvPayload(batch)
		if err != nil {
			return err
		}
		p.markBlocksRequested(len(batch))
		s.addBlocksRequested(len(batch))
		// Record each canonical hash for timeout tracking
		for _, inv := range batch {
			if inv.Type == wire.InvTypeBlock {
				s.recordGetdataReq(inv.Hash.String(), p.remote)
			}
		}
		if err := s.writePeerMessage(p, wire.CommandGetData, payload); err != nil {
			return err
		}
		totalRequested += len(batch)
	}
	s.log.Printf("p2p validated %d headers from %s; requested %d block bodies via getdata in %d batch(es) (tip=%d, skipped=%d, dual_hash=%d)",
		len(hashes), p.remote, totalRequested, (len(allWant)+maxGetDataItems-1)/maxGetDataItems, tipHeight, skipped, dualHash)
	return nil
}
