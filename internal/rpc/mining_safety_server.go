package rpc

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"legacycoin/legacy-go/internal/config"
	"legacycoin/legacy-go/internal/mining"
	"legacycoin/legacy-go/internal/p2p"
	"legacycoin/legacy-go/internal/version"
	"legacycoin/legacy-go/internal/wallet"
)

func (s *Server) checkSafeToMine(w *wallet.Wallet, cfg config.MiningConfig, requireDestination bool) MiningSafetyStatus {
	input := MiningSafetyInput{
		RPCHealth:           "ok",
		StorageOK:           true,
		DestinationOK:       true,
		SafeRequired:        cfg.SafeRequired,
		AllowUnsafe:         cfg.AllowUnsafe,
		MinGoodPeers:        cfg.MinGoodPeers,
		MinAgreeingPeers:    cfg.MinAgreeingPeers,
		PeerGraceSeconds:    cfg.PeerGraceSeconds,
		PeerRecoverySeconds: cfg.PeerRecoverySeconds,
		BlocksBehindAllowed: cfg.BlocksBehindOK,
		SyncState:           "unknown",
	}
	if s.chain != nil {
		health := s.chain.StorageHealth()
		input.StorageOK = health.OK
		input.StorageError = health.Error
		if tip := s.chain.Tip(); tip != nil {
			input.LocalHeight = tip.Height
			input.BestPeerHeight = tip.Height
			input.CurrentTipHeight = tip.Height
			input.CurrentTemplateHeight = tip.Height + 1
			input.CurrentTipHash = tip.Hash
		}
	}
	if requireDestination {
		dest := s.miningDestinationStatus(w, cfg)
		input.DestinationOK = dest.Owned || dest.External
		input.DestinationError = dest.Error
	}
	if s.p2p != nil {
		sync := s.p2p.SyncStatus()
		input.SyncState = stringFromMap(sync, "sync_state", stringFromMap(sync, "status", "unknown"))
		input.PeerCount = intFromMap(sync, "peer_count", int(s.p2p.PeerCount()))
		input.BestPeerHeight = int32FromMap(sync, "best_peer_height", input.BestPeerHeight)
		input.LocalHeight = int32FromMap(sync, "local_height", input.LocalHeight)
		input.BlocksBehind = int32FromMap(sync, "blocks_behind", maxInt32(0, input.BestPeerHeight-input.LocalHeight))
		input.StalePeerCount = intFromMap(sync, "stale_peer_count", 0)
		input.RequestInFlight = boolFromMap(sync, "request_in_flight")
		input.NoUsefulChainData = boolFromMap(sync, "no_useful_chain_data")
		input.LastSyncError = stringFromMap(sync, "last_sync_error", "")
		peers := s.p2p.PeerInfos()
		peerAssessment := assessMiningPeers(peers, input.LocalHeight)
		input.GoodPeerCount = peerAssessment.Compatible
		input.AgreeingPeerCount = peerAssessment.CurrentAgreeing
		input.CompatiblePeerCount = peerAssessment.Compatible
		input.Lagging1PeerCount = peerAssessment.Lagging1
		input.Lagging2PeerCount = peerAssessment.Lagging2
		input.LaggingMorePeerCount = peerAssessment.LaggingMore
		input.StaleChainDataPeerCount = peerAssessment.StaleChainData
		input.UnresponsivePeerCount = peerAssessment.Unresponsive
		input.ConflictingTipPeerCount = peerAssessment.ConflictingTip
		input.StrongerChainworkPeerCount = peerAssessment.StrongerChainwork
		input.WrongChainPeerCount = peerAssessment.WrongChain
		input.ProtocolErrorPeerCount = peerAssessment.ProtocolError
		input.PeerSplit = miningPeerSetSplit(peers)
		if input.PeerCount == 0 && len(peers) > 0 {
			input.PeerCount = len(peers)
		}
	} else {
		input.SyncState = "no_peers"
	}
	s.minerMu.Lock()
	accepted := s.minerBlocks
	stale := s.minerStaleBlocks
	rejected := s.minerRejectedBlocks
	minerActive := s.minerActive
	templateAt := s.minerLastTemplateTime
	templateHeight := s.minerLastTemplateHeight
	templatePrevHash := strings.TrimSpace(s.minerLastTemplatePrevHash)
	templateTipHeight := s.minerLastTemplateTipHeight
	templateFresh := s.minerLastTemplateFresh
	templateStaleReason := strings.TrimSpace(s.minerLastTemplateStaleReason)
	staleRatePauseActive := s.minerStaleRatePauseActive
	s.minerMu.Unlock()
	input.AcceptedBlocks = accepted
	input.StaleBlocks = stale
	input.RejectedBlocks = rejected
	input.HasActiveTemplate = minerActive && !templateAt.IsZero() && templateHeight > 0
	if templateHeight > 0 {
		input.CurrentTemplateHeight = templateHeight
	}
	input.CurrentTipHeight = maxInt32(input.CurrentTipHeight, templateTipHeight)
	input.ActiveTemplatePrevHash = templatePrevHash
	input.ActiveTemplateFresh = templateFresh
	input.ActiveTemplateStaleReason = templateStaleReason
	input.TemplateSoftRefreshAgeSeconds = miningTemplateSoftRefreshAgeSeconds()
	input.TemplateMaxAgeSeconds = miningTemplateHardStaleAgeSeconds()
	input.StaleRatePauseActive = staleRatePauseActive
	if templateAt.IsZero() {
		input.TemplateAgeSeconds = -1
	} else {
		input.TemplateAgeSeconds = time.Since(templateAt).Seconds()
	}
	if input.HasActiveTemplate {
		input.ActiveTemplateFresh, input.ActiveTemplateStaleReason = s.activeTemplateFreshness(input.CurrentTemplateHeight, input.ActiveTemplatePrevHash, templateAt)
		if !input.ActiveTemplateFresh {
			input.ActiveTemplateRefreshDue = true
			input.ActiveTemplateRefreshReason = staleTemplateRefreshReason(input.ActiveTemplateStaleReason)
		} else if input.TemplateSoftRefreshAgeSeconds > 0 && input.TemplateAgeSeconds > input.TemplateSoftRefreshAgeSeconds {
			input.ActiveTemplateRefreshDue = true
			input.ActiveTemplateRefreshReason = "refreshing template in background; current template still valid"
		}
	}
	s.applyMiningPeerAgreementWindow(&input)
	return CheckSafeToMine(input)
}

func (s *Server) activeTemplateFreshness(templateHeight int32, templatePrevHash string, templateAt time.Time) (bool, string) {
	if templateHeight <= 0 || strings.TrimSpace(templatePrevHash) == "" || templateAt.IsZero() {
		return false, "template unavailable"
	}
	tip := s.chain.Tip()
	if tip == nil || tip.Hash == "" {
		return false, "chain tip unavailable"
	}
	if templatePrevHash != tip.Hash {
		return false, "template prev hash does not match current tip"
	}
	if templateHeight != tip.Height+1 {
		return false, "template height is not current tip height + 1"
	}
	if time.Since(templateAt) > miningTemplateHardStaleAge() {
		return false, "template age exceeds hard stale limit"
	}
	return true, ""
}

type miningPeerAssessment struct {
	CurrentAgreeing   int
	Compatible        int
	Lagging1          int
	Lagging2          int
	LaggingMore       int
	StaleChainData    int
	Unresponsive      int
	ConflictingTip    int
	StrongerChainwork int
	WrongChain        int
	ProtocolError     int
	Counts            map[string]int
}

func assessMiningPeers(peers []p2p.PeerInfo, localHeight int32) miningPeerAssessment {
	out := miningPeerAssessment{Counts: make(map[string]int)}
	for _, peer := range peers {
		category := strings.TrimSpace(peer.PeerSafetyCategory)
		if category == "" {
			category = miningPeerCategory(peer, localHeight)
		}
		out.Counts[category]++
		switch category {
		case "current_agreeing":
			out.CurrentAgreeing++
			out.Compatible++
		case "lagging_1_block":
			out.Lagging1++
			out.Compatible++
		case "lagging_2_blocks":
			out.Lagging2++
			out.Compatible++
		case "lagging_more_than_2":
			out.LaggingMore++
		case "stale_chain_data":
			out.StaleChainData++
		case "unresponsive":
			out.Unresponsive++
		case "conflicting_tip":
			out.ConflictingTip++
		case "stronger_chainwork":
			out.StrongerChainwork++
		case "wrong_chain_id":
			out.WrongChain++
		case "protocol_error":
			out.ProtocolError++
		}
	}
	return out
}

func miningPeerCategory(peer p2p.PeerInfo, localHeight int32) string {
	reason := strings.ToLower(strings.TrimSpace(peer.GoodPeerReason))
	if strings.Contains(reason, "wrong chain") {
		return "wrong_chain_id"
	}
	if strings.TrimSpace(peer.LastBlockReject) != "" || strings.TrimSpace(peer.LastSyncError) != "" {
		return "protocol_error"
	}
	if peer.MissedPongs >= 3 || strings.EqualFold(peer.PeerQuality, "poor") {
		return "unresponsive"
	}
	if localHeight > 0 && peer.ReportedHeight <= 0 {
		return "stale_chain_data"
	}
	if localHeight > 0 && peer.ReportedHeight > 0 {
		lag := localHeight - peer.ReportedHeight
		switch {
		case lag < 0:
			return "stronger_chainwork"
		case lag == 0:
			return "current_agreeing"
		case lag == 1:
			return "lagging_1_block"
		case lag == 2:
			return "lagging_2_blocks"
		case peer.Stale:
			return "stale_chain_data"
		default:
			return "lagging_more_than_2"
		}
	}
	if peer.Stale {
		return "stale_chain_data"
	}
	if peer.GoodPeer {
		return "current_agreeing"
	}
	return "stale_chain_data"
}

func (s *Server) applyMiningPeerAgreementWindow(input *MiningSafetyInput) {
	if s == nil || input == nil {
		return
	}
	minAgreeing := input.MinAgreeingPeers
	if minAgreeing <= 0 {
		minAgreeing = defaultMiningMinAgreeingPeers
	}
	graceSeconds := input.PeerGraceSeconds
	if graceSeconds <= 0 {
		graceSeconds = defaultMiningPeerGraceSeconds
	}
	recoverySeconds := input.PeerRecoverySeconds
	if recoverySeconds <= 0 {
		recoverySeconds = defaultMiningPeerRecoverySeconds
	}
	input.MinAgreeingPeers = minAgreeing
	input.PeerGraceSeconds = graceSeconds
	input.PeerRecoverySeconds = recoverySeconds
	immediateRisk := input.PeerCount == 0 ||
		input.StrongerChainworkPeerCount > 0 ||
		input.ConflictingTipPeerCount > 0 ||
		input.WrongChainPeerCount > 0 ||
		input.ProtocolErrorPeerCount > 0 ||
		input.BlocksBehind > int32(input.BlocksBehindAllowed)
	if minAgreeing <= 0 || immediateRisk {
		// Clear local block propagation grace on the server so stale state
		// does not persist when the danger condition resolves.
		s.minerMu.Lock()
		if s.minerLocalBlockGraceActive {
			s.minerLocalBlockGraceActive = false
			s.minerLocalBlockGraceHash = ""
			s.minerLocalBlockGraceHeight = 0
			s.minerLocalBlockGraceStartedAt = time.Time{}
		}
		s.minerMu.Unlock()
		return
	}
	now := time.Now()
	s.minerMu.Lock()
	defer s.minerMu.Unlock()
	if s.applyLocalBlockPropagationGraceLocked(input, now, minAgreeing) {
		// Local block propagation grace was denied due to a danger condition
		// (expired, incompatible peers, reorg, conflicting tip, etc.).
		// Mining must pause immediately — do not fall through to ordinary
		// peer-agreement grace.
		return
	}
	if input.AgreeingPeerCount < minAgreeing {
		if s.minerPeerAgreementLostSince.IsZero() {
			s.minerPeerAgreementLostSince = now
		}
		s.minerPeerAgreementRecoveredSince = time.Time{}
		elapsed := now.Sub(s.minerPeerAgreementLostSince)
		if elapsed < time.Duration(graceSeconds)*time.Second {
			input.PeerAgreementGraceActive = true
			input.PeerAgreementGraceRemaining = int((time.Duration(graceSeconds)*time.Second - elapsed + time.Second - 1) / time.Second)
			return
		}
		s.minerPeerAgreementPaused = true
		input.PeerSafetyPauseActive = true
		return
	}
	s.minerPeerAgreementLostSince = time.Time{}
	if s.minerPeerAgreementPaused {
		if s.minerPeerAgreementRecoveredSince.IsZero() {
			s.minerPeerAgreementRecoveredSince = now
		}
		elapsed := now.Sub(s.minerPeerAgreementRecoveredSince)
		if elapsed < time.Duration(recoverySeconds)*time.Second {
			input.PeerAgreementRecoveryActive = true
			input.PeerAgreementRecoveryRemaining = int((time.Duration(recoverySeconds)*time.Second - elapsed + time.Second - 1) / time.Second)
			input.PeerSafetyPauseActive = true
			return
		}
	}
	s.minerPeerAgreementRecoveredSince = time.Time{}
	s.minerPeerAgreementPaused = false
}

func (s *Server) applyLocalBlockPropagationGraceLocked(input *MiningSafetyInput, now time.Time, minAgreeing int) bool {
	if !s.minerLocalBlockGraceActive {
		return false
	}
	graceSeconds := defaultLocalBlockPropagationSeconds
	clearGrace := func() {
		s.minerLocalBlockGraceActive = false
		s.minerLocalBlockGraceHash = ""
		s.minerLocalBlockGraceHeight = 0
		s.minerLocalBlockGraceStartedAt = time.Time{}
	}
	elapsed := now.Sub(s.minerLocalBlockGraceStartedAt)
	remaining := int((time.Duration(graceSeconds)*time.Second - elapsed + time.Second - 1) / time.Second)
	if remaining < 0 {
		remaining = 0
	}
	if s.chain == nil {
		clearGrace()
		return true
	}
	if elapsed >= time.Duration(graceSeconds)*time.Second {
		clearGrace()
		input.LocalBlockPropagationGraceRemaining = 0
		return true
	}
	tip := s.chain.Tip()
	if tip == nil || tip.Hash == "" {
		clearGrace()
		return true
	}
	if tip.Hash != s.minerLocalBlockGraceHash || tip.Height != s.minerLocalBlockGraceHeight {
		clearGrace()
		return true
	}
	if input.AgreeingPeerCount >= minAgreeing {
		clearGrace()
		return false
	}
	if input.CompatiblePeerCount < 2 {
		clearGrace()
		return true
	}
	if input.ConflictingTipPeerCount > 0 || input.StrongerChainworkPeerCount > 0 ||
		input.WrongChainPeerCount > 0 || input.ProtocolErrorPeerCount > 0 {
		clearGrace()
		return true
	}
	if input.BlocksBehind > int32(input.BlocksBehindAllowed) {
		clearGrace()
		return true
	}
	input.LocalBlockPropagationGraceActive = true
	input.LocalBlockPropagationGraceRemaining = remaining
	input.LocalBlockPropagationHeight = s.minerLocalBlockGraceHeight
	input.LocalBlockPropagationHash = s.minerLocalBlockGraceHash
	input.LastLocalBlockAnnouncementTime = s.minerLastLocalBlockAnnouncement.Unix()
	input.LocalBlockAnnouncementTargetCount = s.minerLocalBlockAnnouncementPeers
	return false
}

func miningTemplateSoftRefreshAge() time.Duration {
	return mining.DefaultSoftTemplateRefreshAge
}

func miningTemplateSoftRefreshAgeSeconds() float64 {
	return miningTemplateSoftRefreshAge().Seconds()
}

func miningTemplateHardStaleAge() time.Duration {
	return mining.DefaultHardTemplateStaleAge
}

func miningTemplateMaxAge() time.Duration {
	return miningTemplateHardStaleAge()
}

func miningTemplateMaxAgeSeconds() float64 {
	return miningTemplateHardStaleAgeSeconds()
}

func miningTemplateHardStaleAgeSeconds() float64 {
	return miningTemplateHardStaleAge().Seconds()
}

func miningTemplateRecoveryTimeout() time.Duration {
	return 30 * time.Second
}

func miningTemplateRecoveryTimeoutSeconds() float64 {
	return miningTemplateRecoveryTimeout().Seconds()
}

func goodMiningPeerCount(peers []p2p.PeerInfo, localHeight int32) int {
	return assessMiningPeers(peers, localHeight).Compatible
}

func miningPeerSetSplit(peers []p2p.PeerInfo) bool {
	if len(peers) < 3 {
		return false
	}
	heights := make([]int, 0, len(peers))
	for _, peer := range peers {
		if peer.Stale || peer.ReportedHeight <= 0 || strings.EqualFold(peer.PeerQuality, "poor") {
			continue
		}
		heights = append(heights, int(peer.ReportedHeight))
	}
	if len(heights) < 3 {
		return false
	}
	sort.Ints(heights)
	best := heights[len(heights)-1]
	atBest := 0
	for _, height := range heights {
		if best-height <= 1 {
			atBest++
		}
	}
	return best-heights[0] > 3 && atBest*2 < len(heights)
}

func (s *Server) chainStatus() map[string]any {
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	safety := s.checkSafeToMine(s.defaultWallet(), cfg, false)
	localHash := ""
	currentBits := ""
	lastBlockAge := float64(-1)
	if tip := s.chain.Tip(); tip != nil {
		localHash = tip.Hash
		currentBits = fmt.Sprintf("%08x", tip.Bits)
		lastBlockAge = time.Since(time.Unix(int64(tip.Time), 0)).Seconds()
	}
	out := map[string]any{
		"version":                    version.CoreVersion,
		"core_version":               version.CoreVersion,
		"chain":                      s.chain.Params().Name,
		"chain_id":                   s.chain.Params().ChainID,
		"genesis_hash":               s.chain.Params().GenesisHash,
		"local_height":               safety.LocalHeight,
		"local_best_hash":            localHash,
		"best_peer_height":           safety.BestPeerHeight,
		"blocks_behind":              safety.BlocksBehind,
		"peer_count":                 safety.PeerCount,
		"good_peer_count":            safety.GoodPeerCount,
		"sync_state":                 safety.SyncState,
		"safe_to_mine":               safety.Safe,
		"mining_blocked_reason":      safety.Reason,
		"network_hashps":             s.estimateNetworkHashPS(100),
		"current_bits":               currentBits,
		"last_block_age_seconds":     lastBlockAge,
		"recent_reorg":               false,
		"recent_reorg_count":         0,
		"last_reorg_depth":           0,
		"last_reorg_time":            0,
		"last_orphaned_mined_blocks": []any{},
		"rpc_health":                 safety.RPCHealth,
		"consensus_rules_changed":    false,
	}
	for key, value := range safety.Fields() {
		out[key] = value
	}
	return out
}

func (s *Server) forkStatus() map[string]any {
	out := s.chainStatus()
	peers := []map[string]any{}
	if s.p2p != nil {
		heightCounts := map[int32]int{}
		for _, peer := range s.p2p.PeerInfos() {
			heightCounts[peer.ReportedHeight]++
		}
		heights := make([]int, 0, len(heightCounts))
		for height := range heightCounts {
			heights = append(heights, int(height))
		}
		sort.Ints(heights)
		for _, height := range heights {
			peers = append(peers, map[string]any{"height": height, "count": heightCounts[int32(height)]})
		}
	}
	out["peer_height_distribution"] = peers
	out["peer_tip_hash_distribution"] = []any{}
	out["best_peer_hash"] = ""
	out["last_disconnected_blocks"] = []any{}
	return out
}

func stringFromMap(m map[string]any, key, fallback string) string {
	if v, ok := m[key]; ok {
		s := strings.TrimSpace(fmt.Sprint(v))
		if s != "" {
			return s
		}
	}
	return fallback
}

func intFromMap(m map[string]any, key string, fallback int) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int32:
			return int(n)
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return fallback
}

func int32FromMap(m map[string]any, key string, fallback int32) int32 {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return int32(n)
		case int32:
			return n
		case int64:
			return int32(n)
		case float64:
			return int32(n)
		}
	}
	return fallback
}

func boolFromMap(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		return boolFromAny(v)
	}
	return false
}

func maxInt32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
