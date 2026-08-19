package rpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"golang.org/x/crypto/ripemd160"

	"legacycoin/legacy-go/internal/address"
	"legacycoin/legacy-go/internal/amount"
	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/chainhash"
	"legacycoin/legacy-go/internal/config"
	"legacycoin/legacy-go/internal/consensus"
	"legacycoin/legacy-go/internal/mempool"
	"legacycoin/legacy-go/internal/mining"
	"legacycoin/legacy-go/internal/p2p"
	"legacycoin/legacy-go/internal/pow"
	"legacycoin/legacy-go/internal/script"
	"legacycoin/legacy-go/internal/tokens"
	"legacycoin/legacy-go/internal/version"
	"legacycoin/legacy-go/internal/wallet"
	"legacycoin/legacy-go/internal/wire"
)

type walletContextKey struct{}

type Server struct {
	chain            *blockchain.Chain
	pool             *mempool.Pool
	wallet           *wallet.Wallet
	wallets          map[string]*wallet.Wallet
	defaultWalletName string
	dataDir          string
	p2p              *p2p.Server
	server           *http.Server
	stop             context.CancelFunc
	auth             config.RPCAuth
	bind             config.RPCBind
	policy           config.LaunchPolicy
	configPath       string

	minerMu                           sync.Mutex
	minerActive                       bool
	minerHashing                      bool
	minerCancel                       context.CancelFunc
	minerThreads                      int
	minerBlocks                       int64
	minerLastHash                     string
	minerLastError                    string
	minerPausedReason                 string
	minerLastStopReason               string
	minerRequestedStopReason          string
	minerStartedAt                    time.Time
	minerStopAfterBlocks              int64
	minerRewardHash                   string
	minerPeerRequired                 bool
	minerLocalHashPS                  float64
	minerSessionHashes                uint64
	minerLastNonce                    uint32
	minerWorkerEpochStartedAt         time.Time
	minerLastHashProgressTime         time.Time
	minerStaleBlocks                  int64
	minerRejectedBlocks               int64
	minerLastStaleTime                time.Time
	minerLastStaleReason              string
	minerLastTemplateTime             time.Time
	minerLastTemplateHeight           int32
	minerLastTemplatePrevHash         string
	minerLastTemplateTipHeight        int32
	minerLastTemplateTipHash          string
	minerLastTemplateFresh            bool
	minerLastTemplateStaleReason      string
	minerLastTemplateRefreshDue       bool
	minerLastTemplateRefreshReason    string
	minerLastTemplateRefreshAttempt   time.Time
	minerTemplateRefreshCount         int64
	minerStaleTemplateRefreshAttempts int64
	minerStaleTemplateSkips           int64
	minerLastTemplateRefreshError     string
	minerStaleRatePauseActive         bool
	minerAcceptedRecords              []minerAcceptedRecord
	minerSupervisorRestartAttempts    int64
	minerLoopWg                       sync.WaitGroup
	minerLastSupervisorCancelTime     time.Time
	minerLastRestartSuccessTime       time.Time
	minerLastRestartFailure           string
	minerPeerAgreementLostSince       time.Time
	minerPeerAgreementRecoveredSince  time.Time
	minerPeerAgreementPaused          bool
	minerLocalBlockGraceActive        bool
	minerLocalBlockGraceStartedAt     time.Time
	minerLocalBlockGraceHeight        int32
	minerLocalBlockGraceHash          string
	minerLastLocalBlockAnnouncement   time.Time
	minerLocalBlockAnnouncementPeers  int
	minerTemplateRecoveryPending      bool
	minerTemplateRecoveryStartedAt    time.Time
	minerStateGen                     int64
	defaultTxFee                      int64

	startedAt time.Time

	rpcDiagMu          sync.Mutex
	rpcActiveRequests  int64
	rpcOldestRequestAt time.Time
	rpcTotalCalls      int64
	rpcTotalDuration   time.Duration
	rpcTimeoutCount    int64
	rpcErrorCount      int64

	rateLimiters     sync.Map
	disableRateLimit bool

	corsOrigin string

	minerStatusDiagActive atomic.Int64
	minerStatusDiagTotal  atomic.Int64
	minerStatusDiagMax    atomic.Int64
	netHashDiagActive     atomic.Int64
	netHashDiagTotal      atomic.Int64
	netHashDiagMax        atomic.Int64
}

type rateLimiter struct {
	mu         sync.Mutex
	tokens     int
	lastRefill time.Time
	maxTokens  int
	refillRate time.Duration
}

func newRateLimiter(maxTokens int, refillRate time.Duration) *rateLimiter {
	return &rateLimiter{
		tokens:     maxTokens,
		lastRefill: time.Now(),
		maxTokens:  maxTokens,
		refillRate: refillRate,
	}
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	elapsed := time.Since(rl.lastRefill)
	rl.tokens += int(elapsed / rl.refillRate)
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}
	rl.lastRefill = rl.lastRefill.Add(time.Duration(int(elapsed/rl.refillRate)) * rl.refillRate)
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

func (s *Server) checkRateLimit(ip string) bool {
	if s.disableRateLimit {
		return true
	}
	v, _ := s.rateLimiters.LoadOrStore(ip, newRateLimiter(60, time.Second))
	return v.(*rateLimiter).allow()
}

func (s *Server) cleanupRateLimiters() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.rateLimiters.Range(func(key, value any) bool {
			rl := value.(*rateLimiter)
			rl.mu.Lock()
			stale := time.Since(rl.lastRefill) > 10*time.Minute
			rl.mu.Unlock()
			if stale {
				s.rateLimiters.Delete(key)
			}
			return true
		})
	}
}

type minerAcceptedRecord struct {
	Hash         string
	Height       int32
	AcceptedAt   time.Time
	PayoutHash   string
	CoinbaseTxID string
}

type request struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcHelpEntry struct {
	Method      string `json:"method"`
	Usage       string `json:"usage"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

type response struct {
	ID     any       `json:"id"`
	Result any       `json:"result,omitempty"`
	Error  *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	MaxRPCBatchRequests = 100
	MaxConcurrentRPC    = 32
)

var rpcHelpEntries = []rpcHelpEntry{
	{Method: "getblockcount", Usage: "getblockcount", Category: "chain", Description: "Return the current best block height."},
	{Method: "getbestblockhash", Usage: "getbestblockhash", Category: "chain", Description: "Return the best tip block hash."},
	{Method: "getblockhash", Usage: "getblockhash <height>", Category: "chain", Description: "Return block hash by height."},
	{Method: "getblock", Usage: "getblock <hash>", Category: "chain", Description: "Return a decoded block by hash."},
	{Method: "getblockheader", Usage: "getblockheader <hash>", Category: "chain", Description: "Return a decoded block header by hash."},
	{Method: "getblockchaininfo", Usage: "getblockchaininfo", Category: "chain", Description: "Return chain status and sync summary."},
	{Method: "getchaintips", Usage: "getchaintips", Category: "chain", Description: "Return info about all chain tips."},
	{Method: "estimatefee", Usage: "estimatefee [nblocks]", Category: "mempool", Description: "Return estimated fee per KB for a transaction to be confirmed within nblocks (default 6). Uses mempool median feerate."},
	{Method: "estimatesmartfee", Usage: "estimatesmartfee [nblocks]", Category: "mempool", Description: "Alias for estimatefee."},
	{Method: "uptime", Usage: "uptime", Category: "network", Description: "Return the server uptime in seconds."},
	{Method: "getnetworkinfo", Usage: "getnetworkinfo", Category: "network", Description: "Return network and connection summary."},
	{Method: "getchainstatus", Usage: "getchainstatus", Category: "network", Description: "Return support-ready chain, sync, fork, RPC, and safe-mining status."},
	{Method: "getforkstatus", Usage: "getforkstatus", Category: "network", Description: "Return fork/reorg and peer-tip diagnostics for support."},
	{Method: "getpeerinfo", Usage: "getpeerinfo", Category: "network", Description: "Return connected peer diagnostics."},
	{Method: "getknownpeers", Usage: "getknownpeers", Category: "network", Description: "Return locally cached known-peer diagnostics."},
	{Method: "getsyncstatus", Usage: "getsyncstatus", Category: "network", Description: "Return sync watchdog and peer sync health."},
	{Method: "getmempoolinfo", Usage: "getmempoolinfo", Category: "mempool", Description: "Return mempool counters and limits."},
	{Method: "getrawmempool", Usage: "getrawmempool", Category: "mempool", Description: "Return mempool txid list."},
	{Method: "getmempoolentry", Usage: "getmempoolentry <txid>", Category: "mempool", Description: "Return a mempool entry for a txid."},
	{Method: "getrawtransaction", Usage: "getrawtransaction <txid> [verbose]", Category: "tx", Description: "Return raw tx hex or verbose object."},
	{Method: "getaddresstxids", Usage: "getaddresstxids <address>", Category: "index", Description: "Return confirmed txids for an indexed address (requires addressindex=1)."},
	{Method: "getaddressutxos", Usage: "getaddressutxos <address>", Category: "index", Description: "Return address UTXOs from address index (requires addressindex=1)."},
	{Method: "getaddressbalance", Usage: "getaddressbalance <address>", Category: "index", Description: "Return confirmed/total base-unit balance for indexed address (requires addressindex=1)."},
	{Method: "getaddresshistory", Usage: "getaddresshistory <address>", Category: "index", Description: "Return receive/spend history foundation for indexed address outputs (requires addressindex=1)."},
	{Method: "decoderawtransaction", Usage: "decoderawtransaction <hex>", Category: "tx", Description: "Decode raw transaction hex."},
	{Method: "sendrawtransaction", Usage: "sendrawtransaction <hex>", Category: "tx", Description: "Submit a raw transaction to mempool."},
	{Method: "gettxout", Usage: "gettxout <txid> <vout>", Category: "tx", Description: "Return UTXO entry for an outpoint."},
	{Method: "gettxoutsetinfo", Usage: "gettxoutsetinfo", Category: "tx", Description: "Return UTXO set statistics."},
	{Method: "getblocktemplate", Usage: "getblocktemplate [request_object]", Category: "mining", Description: "Return pool/miner template (BIP22/BIP23 style fields)."},
	{Method: "getdifficultyhistory", Usage: "getdifficultyhistory [window]", Category: "mining", Description: "Return recent DGW difficulty and solve-time diagnostics."},
	{Method: "submitblock", Usage: "submitblock <block_hex>", Category: "mining", Description: "Submit a candidate block; null on accepted, reject string otherwise."},
	{Method: "submitblockdebug", Usage: "submitblockdebug <block_hex>", Category: "mining", Description: "Submit a candidate block and return detailed accept/reject diagnostics."},
	{Method: "validateblockproposal", Usage: "validateblockproposal <block_hex>", Category: "mining", Description: "Preflight a candidate block without storing it."},
	{Method: "testblock", Usage: "testblock <block_hex>", Category: "mining", Description: "Alias for validateblockproposal."},
	{Method: "getminingaddress", Usage: "getminingaddress", Category: "mining", Description: "Return or create the wallet-owned mining reward address."},
	{Method: "getminerstatus", Usage: "getminerstatus", Category: "mining", Description: "Return miner runtime status and counters."},
	{Method: "startminer", Usage: "startminer", Category: "mining", Description: "Start local CPU mining."},
	{Method: "stopminer", Usage: "stopminer", Category: "mining", Description: "Stop local CPU mining."},
	{Method: "restartminer", Usage: "restartminer", Category: "mining", Description: "Restart local CPU mining."},
	{Method: "setminerthreads", Usage: "setminerthreads <threads>", Category: "mining", Description: "Set mining thread count."},
	{Method: "setupwallet", Usage: "setupwallet [passphrase]", Category: "wallet", Description: "Initialize wallet and default mining address."},
	{Method: "getwalletsummary", Usage: "getwalletsummary", Category: "wallet", Description: "Return wallet balance, address, and security summary."},
	{Method: "getnewaddress", Usage: "getnewaddress", Category: "wallet", Description: "Generate a new wallet receive address."},
	{Method: "listunspent", Usage: "listunspent [minconf] [maxconf] [addresses]", Category: "wallet", Description: "Return spendable and tracked UTXOs."},
	{Method: "getbalance", Usage: "getbalance [address]", Category: "wallet", Description: "Return wallet balance (LBTC display units)."},
	{Method: "getwalletinfo", Usage: "getwalletinfo", Category: "wallet", Description: "Return wallet lock/encryption/key stats."},
	{Method: "gettransaction", Usage: "gettransaction <txid>", Category: "wallet", Description: "Return wallet transaction details and categories."},
	{Method: "listtransactions", Usage: "listtransactions [count] [skip]", Category: "wallet", Description: "Return recent wallet history."},
	{Method: "listsinceblock", Usage: "listsinceblock [blockhash]", Category: "wallet", Description: "Return wallet history since block."},
	{Method: "sendtoaddress", Usage: "sendtoaddress <address> <amount_lbtc> [fee_lbtc]", Category: "wallet", Description: "Send LBTC to one address."},
	{Method: "sendmany", Usage: "sendmany \"\" {\"addr\":amount,...}", Category: "wallet", Description: "Send LBTC to multiple addresses in one tx."},
	{Method: "sendmanyraw", Usage: "sendmanyraw \"\" {\"addr\":base_units,...}", Category: "wallet", Description: "sendmany using explicit base units."},
	{Method: "signrawtransactionwithwallet", Usage: "signrawtransactionwithwallet <rawtx_hex>", Category: "wallet", Description: "Sign wallet-known inputs in raw transaction."},
	{Method: "validateaddress", Usage: "validateaddress <address>", Category: "wallet", Description: "Validate address and ownership hints."},
	{Method: "verifymessage", Usage: "verifymessage <address> <signature> <message>", Category: "wallet", Description: "Verify a signed message."},
	{Method: "getaddressinfo", Usage: "getaddressinfo <address>", Category: "wallet", Description: "Return detailed address metadata."},
	{Method: "sethdseed", Usage: "sethdseed [seed|mnemonic]", Category: "wallet", Description: "Set HD seed from hex or BIP39 mnemonic. Empty = generate new."},
	{Method: "exportmnemonic", Usage: "exportmnemonic", Category: "wallet", Description: "Export wallet backup mnemonic phrase (BIP39)."},
	{Method: "backupwallet", Usage: "backupwallet <path>", Category: "wallet", Description: "Export wallet backup file."},
	{Method: "walletpassphrase", Usage: "walletpassphrase <passphrase> <timeout>", Category: "wallet", Description: "Unlock encrypted wallet for signing."},
	{Method: "walletpassphrasechange", Usage: "walletpassphrasechange <oldpassphrase> <newpassphrase>", Category: "wallet", Description: "Change encrypted wallet passphrase."},
	{Method: "walletlock", Usage: "walletlock", Category: "wallet", Description: "Lock encrypted wallet."},
	{Method: "addnode", Usage: "addnode <addr>", Category: "network", Description: "Connect to a peer."},
	{Method: "disconnectnode", Usage: "disconnectnode <addr>", Category: "network", Description: "Disconnect a matching peer."},
	{Method: "doctor", Usage: "doctor", Category: "ops", Description: "Return operator health checks."},
	{Method: "checkstorage", Usage: "checkstorage [repair]", Category: "ops", Description: "Return block/index/UTXO storage health. Use repair=true to rebuild active-chain indexes."},
	{Method: "reindex", Usage: "reindex", Category: "ops", Description: "Rebuild active-chain indexes (height/hash + optional txindex/addressindex)."},
	{Method: "help", Usage: "help [method]", Category: "meta", Description: "List supported RPC methods or show one method summary."},
	{Method: "stop", Usage: "stop", Category: "meta", Description: "Stop Legacy Core daemon."},
}

func (s *Server) rpcBindHost() string {
	if s.bind.Host != "" {
		return s.bind.Host
	}
	return "127.0.0.1"
}

func (s *Server) nodeRole() string {
	if s.policy.NodeRole != "" {
		return s.policy.NodeRole
	}
	return "full"
}

func firstStrings(in []string, max int) []string {
	if max <= 0 || len(in) == 0 {
		return []string{}
	}
	if len(in) > max {
		in = in[:max]
	}
	return append([]string(nil), in...)
}

func parsePassphraseArg(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err == nil {
		return n.String(), nil
	}
	return "", fmt.Errorf("invalid passphrase argument")
}

func parseRPCAmount(raw json.RawMessage, baseUnits bool) (int64, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if baseUnits {
			return amount.ParseBaseUnits(s)
		}
		return amount.ParseLBTC(s)
	}
	var num json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&num); err != nil {
		return 0, err
	}
	if baseUnits {
		return amount.ParseBaseUnits(num.String())
	}
	return amount.ParseLBTC(num.String())
}

func (s *Server) announceMempoolTx(txid string) {
	if s.p2p == nil || txid == "" {
		return
	}
	h, err := chainhash.FromString(txid)
	if err != nil {
		return
	}
	s.p2p.AnnounceTx(h)
}

func txSendResult(txid string, sendAmount int64, fee int64, rawMode bool) map[string]any {
	return map[string]any{
		"txid":              txid,
		"amount":            amount.FormatWithTicker(sendAmount),
		"amount_base_units": sendAmount,
		"fee":               amount.FormatWithTicker(fee),
		"fee_base_units":    fee,
		"total":             amount.FormatWithTicker(sendAmount + fee),
		"total_base_units":  sendAmount + fee,
		"amount_mode":       map[bool]string{true: "base_units", false: "LBTC"}[rawMode],
		"status":            "broadcast",
	}
}

func rpcTokenOpName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "deploy", "deploysimple", "deploy_simple":
		return "DEPLOY_SIMPLE"
	case "deploycurve", "deploy_curve":
		return "DEPLOY_CURVE"
	case "transfer":
		return "TRANSFER"
	case "burn":
		return "BURN"
	case "buy":
		return "BUY"
	case "sell":
		return "SELL"
	default:
		return name
	}
}

func rpcSendError(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "insufficient available") ||
		strings.Contains(msg, "pending transactions already lock") ||
		strings.Contains(msg, "input already spent by mempool transaction") ||
		strings.Contains(msg, "insufficient funds"):
		return "Not enough available LBTC. Some coins are already used by pending transactions. Wait for confirmation or use another address/UTXO."
	default:
		return err.Error()
	}
}

func rpcIsLocalhost(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}

func p2pIsLocalhost(host string) bool {
	return rpcIsLocalhost(host)
}

const MaxRPCRequestBytes int64 = 1 << 20

func New(chain *blockchain.Chain, pool *mempool.Pool, w *wallet.Wallet, p2pServer *p2p.Server, stop context.CancelFunc, auth config.RPCAuth, bind config.RPCBind, policy config.LaunchPolicy, configPath string) *Server {
	return &Server{
		chain:             chain,
		pool:              pool,
		wallet:            w,
		wallets:           map[string]*wallet.Wallet{"": w},
		defaultWalletName: "",
		p2p:               p2pServer,
		stop:              stop,
		auth:              auth,
		bind:              bind,
		policy:            policy,
		configPath:        strings.TrimSpace(configPath),
		defaultTxFee:      1_000,
	}
}

func NewMultiWallet(chain *blockchain.Chain, pool *mempool.Pool, walletMap map[string]*wallet.Wallet, defaultWalletName string, dataDir string, p2pServer *p2p.Server, stop context.CancelFunc, auth config.RPCAuth, bind config.RPCBind, policy config.LaunchPolicy, configPath string) *Server {
	var defaultWallet *wallet.Wallet
	if w, ok := walletMap[defaultWalletName]; ok {
		defaultWallet = w
	} else if len(walletMap) > 0 {
		for _, w := range walletMap {
			defaultWallet = w
			break
		}
	}
	return &Server{
		chain:              chain,
		pool:               pool,
		wallet:             defaultWallet,
		wallets:            walletMap,
		defaultWalletName:  defaultWalletName,
		dataDir:            dataDir,
		p2p:                p2pServer,
		stop:               stop,
		auth:               auth,
		bind:               bind,
		policy:             policy,
		configPath:         strings.TrimSpace(configPath),
		defaultTxFee:       1_000,
	}
}

func (s *Server) defaultWallet() *wallet.Wallet {
	return s.wallet
}

func (s *Server) createWallet(name string) (*wallet.Wallet, error) {
	if s.dataDir == "" {
		return nil, fmt.Errorf("data directory not configured")
	}
	if _, ok := s.wallets[name]; ok {
		return nil, fmt.Errorf("wallet %q already loaded", name)
	}
	nw, err := wallet.OpenNamed(s.dataDir, name)
	if err != nil {
		return nil, err
	}
	s.wallets[name] = nw
	return nw, nil
}

func (s *Server) loadWallet(name string) error {
	if s.dataDir == "" {
		return fmt.Errorf("data directory not configured")
	}
	if _, ok := s.wallets[name]; ok {
		return fmt.Errorf("wallet %q already loaded", name)
	}
	nw, err := wallet.OpenNamed(s.dataDir, name)
	if err != nil {
		return err
	}
	s.wallets[name] = nw
	return nil
}

func (s *Server) unloadWallet(name string) error {
	if name == "" {
		name = s.defaultWalletName
	}
	if name == s.defaultWalletName {
		return fmt.Errorf("cannot unload the default wallet")
	}
	if _, ok := s.wallets[name]; !ok {
		return fmt.Errorf("wallet %q not loaded", name)
	}
	delete(s.wallets, name)
	return nil
}

func (s *Server) listWallets() []string {
	names := make([]string, 0, len(s.wallets))
	for k := range s.wallets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (s *Server) resolveWallet(ctx context.Context) *wallet.Wallet {
	if ctx != nil {
		if name, ok := ctx.Value(walletContextKey{}).(string); ok && name != "" {
			if w, ok := s.wallets[name]; ok {
				return w
			}
		}
	}
	return s.wallet
}

func (s *Server) resolveWalletName(ctx context.Context) string {
	if ctx != nil {
		if name, ok := ctx.Value(walletContextKey{}).(string); ok && name != "" {
			return name
		}
	}
	return s.defaultWalletName
}

func (s *Server) miningConfigPath() string {
	if strings.TrimSpace(s.configPath) != "" {
		return s.configPath
	}
	return config.DefaultConfigPath()
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	s.startedAt = time.Now()
	host := s.bind.Host
	if host == "" {
		host = "127.0.0.1"
	}
	if !rpcIsLocalhost(host) && !s.auth.Enabled {
		return fmt.Errorf("refusing rpc bind on non-local interface without auth")
	}
	if !rpcIsLocalhost(host) && !s.bind.TLS {
		return fmt.Errorf("refusing rpc bind on non-local interface without tls")
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(s.chain.Params().RPCPort)))
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.server = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Mining RPC calls can legitimately run longer than 30 seconds at launch
		// difficulty. Use 60s as a reasonable timeout for all calls; long-running
		// generate calls should be handled asynchronously rather than leaving
		// WriteTimeout disabled.
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()
	go func() {
		time.Sleep(120 * time.Second)
		SetDiagWarmupDone()
	}()
	go s.cleanupRateLimiters()
	if cfg, err := config.LoadMiningConfig(s.miningConfigPath()); err == nil && !s.policy.SeedNode && (cfg.AutoStart || cfg.Enabled) {
		go func() {
			time.Sleep(2 * time.Second)
			_, _ = s.startMiner(ctx, json.RawMessage("[]"))
		}()
	}
	var err error
	if s.bind.TLS {
		err = s.server.ListenAndServeTLS(s.bind.TLSCert, s.bind.TLSKey)
	} else {
		err = s.server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

var globalCORSOrigin string

func (s *Server) SetCORSOrigin(origin string) {
	origin = strings.TrimSpace(origin)
	s.corsOrigin = origin
	globalCORSOrigin = origin
}

func (s *Server) corsAllowedOrigin() string {
	if s.corsOrigin != "" {
		return s.corsOrigin
	}
	return "*"
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", s.corsAllowedOrigin())
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "JSON-RPC requires POST", http.StatusMethodNotAllowed)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.checkRateLimit(ip) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	if s.auth.Enabled && !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="LegacyCoin RPC"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxRPCRequestBytes)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		writeResponse(w, response{Error: &rpcError{Code: -32700, Message: err.Error()}})
		return
	}
	ctx := r.Context()
	walletName := strings.TrimSpace(r.Header.Get("X-LegacyCoin-Wallet"))
	if walletName != "" {
		ctx = context.WithValue(ctx, walletContextKey{}, walletName)
	}
	trimmed := bytes.TrimSpace(rawBody)
	if len(trimmed) == 0 {
		writeResponse(w, response{Error: &rpcError{Code: -32600, Message: "empty request"}})
		return
	}
	if trimmed[0] == '[' {
		var reqs []request
		if err := json.Unmarshal(trimmed, &reqs); err != nil {
			writeResponse(w, response{Error: &rpcError{Code: -32700, Message: err.Error()}})
			return
		}
		if len(reqs) == 0 {
			writeResponse(w, response{Error: &rpcError{Code: -32600, Message: "invalid batch request"}})
			return
		}
		if len(reqs) > MaxRPCBatchRequests {
			writeResponse(w, response{Error: &rpcError{Code: -32600, Message: fmt.Sprintf("batch request too large: max %d", MaxRPCBatchRequests)}})
			return
		}
		responses := make([]response, 0, len(reqs))
		for _, req := range reqs {
			responses = append(responses, s.handleRPCRequest(ctx, req))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses)
		return
	}
	var req request
	if err := json.Unmarshal(trimmed, &req); err != nil {
		writeResponse(w, response{Error: &rpcError{Code: -32700, Message: err.Error()}})
		return
	}
	writeResponse(w, s.handleRPCRequest(ctx, req))
}

func (s *Server) handleRPCRequest(ctx context.Context, req request) response {
	if strings.TrimSpace(req.Method) == "" {
		return response{ID: req.ID, Error: &rpcError{Code: -32600, Message: "invalid request: missing method"}}
	}
	params := req.Params
	if len(bytes.TrimSpace(params)) == 0 {
		params = json.RawMessage("[]")
	}

	s.rpcDiagMu.Lock()
	if s.rpcActiveRequests >= MaxConcurrentRPC {
		s.rpcDiagMu.Unlock()
		return response{ID: req.ID, Error: &rpcError{Code: -32603, Message: "server too busy"}}
	}
	s.rpcActiveRequests++
	s.rpcTotalCalls++
	if s.rpcActiveRequests == 1 {
		s.rpcOldestRequestAt = time.Now()
	}
	s.rpcDiagMu.Unlock()
	EnterDiag(&diagFanoutActive, &diagFanoutTotal, &diagFanoutMax)

	var result any
	var rpcErr *rpcError

	defer func() {
		if r := recover(); r != nil {
			rpcErr = &rpcError{Code: -32603, Message: fmt.Sprintf("internal error: %v", r)}
			result = nil
			s.rpcDiagMu.Lock()
			s.rpcErrorCount++
			s.rpcDiagMu.Unlock()
		}
		LeaveDiag(&diagFanoutActive)
		s.rpcDiagMu.Lock()
		s.rpcActiveRequests--
		if s.rpcActiveRequests == 0 {
			s.rpcOldestRequestAt = time.Time{}
		}
		s.rpcDiagMu.Unlock()
	}()

	start := time.Now()
	result, rpcErr = s.call(ctx, req.Method, params)
	duration := time.Since(start)

	if duration > 15*time.Second {
		s.rpcDiagMu.Lock()
		s.rpcTimeoutCount++
		s.rpcDiagMu.Unlock()
	}
	if rpcErr != nil {
		s.rpcDiagMu.Lock()
		s.rpcErrorCount++
		s.rpcDiagMu.Unlock()
	}

	s.rpcDiagMu.Lock()
	s.rpcTotalDuration += duration
	s.rpcDiagMu.Unlock()

	return response{ID: req.ID, Result: result, Error: rpcErr}
}

func (s *Server) authorized(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.auth.User)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(s.auth.Password)) == 1
	return userOK && passOK
}

func (s *Server) currentTxFee() int64 {
	s.minerMu.Lock()
	defer s.minerMu.Unlock()
	if s.defaultTxFee <= 0 {
		return 1_000
	}
	return s.defaultTxFee
}

func (s *Server) call(ctx context.Context, method string, params json.RawMessage) (any, *rpcError) {
	w := s.resolveWallet(ctx)
	switch method {
	case "getinfo":
		tip := s.chain.Tip()
		height := int32(-1)
		best := ""
		if tip != nil {
			height = tip.Height
			best = tip.Hash
		}
		return map[string]any{
			"version":        version.CoreFull(),
			"core_version":   version.CoreVersion,
			"wallet_version": version.WalletVersion,
			"network":        "mainnet",
			"coin":           s.chain.Params().CoinName,
			"ticker":         s.chain.Params().Ticker,
			"blocks":         height,
			"bestblockhash":  best,
			"connections":    s.p2p.PeerCount(),
			"node_role":      s.nodeRole(),
			"seed_node":      s.policy.SeedNode,
			"datadir":        config.DefaultDataDir(),
			"genesislocked":  s.chain.Params().GenesisHash != "",
		}, nil
	case "getchainparams":
		p := s.chain.Params()
		return map[string]any{
			"name":              p.Name,
			"coin":              p.CoinName,
			"ticker":            p.Ticker,
			"message_start":     fmt.Sprintf("%x", p.MessageStart),
			"default_port":      p.DefaultPort,
			"rpc_port":          p.RPCPort,
			"dns_seeds":         p.DNSSeeds,
			"fixed_seeds":       p.FixedSeeds,
			"yespower_pers":     p.YespowerPers,
			"genesis_time":      p.GenesisTime,
			"genesis_bits":      fmt.Sprintf("%08x", p.GenesisBits),
			"post_genesis_bits": fmt.Sprintf("%08x", p.PostGenesisBits),
			"genesis_nonce":     p.GenesisNonce,
			"genesis_hash":      p.GenesisHash,
			"max_future_drift":  chaincfg.MaxFutureDrift.String(),
		}, nil
	case "getbootstrapinfo":
		p := s.chain.Params()
		manual := s.p2p.BootstrapPeers()
		return map[string]any{
			"dns_seeds":         p.DNSSeeds,
			"dns_seed_count":    len(p.DNSSeeds),
			"fixed_seeds":       p.FixedSeeds,
			"fixed_seed_count":  len(p.FixedSeeds),
			"bootstrap_addnode": manual,
			"bootstrap_count":   len(manual),
			"known_peers":       firstStrings(s.p2p.KnownAddresses(), 50),
			"known_peer_count":  s.p2p.KnownAddressCount(),
			"default_port":      p.DefaultPort,
		}, nil
	case "getnodeconfig":
		p := s.chain.Params()
		warnings := make([]string, 0)
		if !rpcIsLocalhost(s.rpcBindHost()) && !s.auth.Enabled {
			warnings = append(warnings, "rpc_exposed_without_auth")
		}
		if !rpcIsLocalhost(s.rpcBindHost()) && !s.bind.TLS {
			warnings = append(warnings, "rpc_exposed_without_tls")
		}
		if p2pIsLocalhost(s.p2p.ListenHost()) {
			warnings = append(warnings, "p2p_bind_localhost_only")
		}
		if len(s.p2p.BootstrapPeers()) == 0 && len(p.DNSSeeds) == 0 && len(p.FixedSeeds) == 0 {
			warnings = append(warnings, "no_bootstrap_peers_configured")
		}
		return map[string]any{
			"coin": map[string]any{
				"name":   p.CoinName,
				"ticker": p.Ticker,
				"chain":  p.Name,
			},
			"paths": map[string]any{
				"datadir": config.DefaultDataDir(),
				"config":  s.miningConfigPath(),
			},
			"ports": map[string]any{
				"p2p": p.DefaultPort,
				"rpc": p.RPCPort,
			},
			"network": map[string]any{
				"message_start":      fmt.Sprintf("%x", p.MessageStart),
				"dns_seeds":          p.DNSSeeds,
				"fixed_seeds":        p.FixedSeeds,
				"addnodes":           s.p2p.BootstrapPeers(),
				"known_peer_count":   s.p2p.KnownAddressCount(),
				"known_peer_samples": firstStrings(s.p2p.KnownAddresses(), 20),
			},
			"bind": map[string]any{
				"p2p": s.p2p.ListenHost(),
				"rpc": s.rpcBindHost(),
			},
			"rpc_tls": map[string]any{
				"enabled": s.bind.TLS,
				"cert":    s.bind.TLSCert,
			},
			"auth": map[string]any{
				"rpc_enabled": s.auth.Enabled,
				"rpc_user":    s.auth.User,
			},
			"role": map[string]any{
				"node_role":        s.nodeRole(),
				"seed_node":        s.policy.SeedNode,
				"mining_allowed":   !s.policy.SeedNode,
				"rpc_private_only": s.policy.SeedNode,
			},
			"warnings": warnings,
		}, nil
	case "getpolicy":
		scriptCoverage := script.Coverage()
		return map[string]any{
			"mempool": map[string]any{
				"max_transactions":           mempool.DefaultMaxTransactions,
				"max_orphans":                mempool.DefaultMaxOrphans,
				"min_relay_fee_perk":         mempool.MinRelayFeePerKB,
				"incremental_relay_fee_perk": mempool.IncrementalRelayFeeKB,
				"max_standard_tx_sz":         mempool.MaxStandardTxSize,
				"max_standard_sigsz":         mempool.MaxStandardSigScript,
				"dust_threshold":             mempool.DustThreshold,
				"max_ancestor_depth":         mempool.MaxAncestorDepth,
				"rbf_optin_enabled":          false,
			},
			"script": map[string]any{
				"max_tx_sigops":    script.MaxTxSigOps,
				"max_block_sigops": script.MaxBlockSigOps,
				"coverage_pending": len(scriptCoverage.Pending),
				"coverage_percent": scriptCoverage.Percent,
			},
			"p2p": map[string]any{
				"max_peers":          p2p.MaxPeers,
				"max_outbound_peers": p2p.MaxOutboundPeers,
				"max_block_orphans":  blockchain.MaxOrphanBlocks,
			},
			"time": map[string]any{
				"max_future_drift": chaincfg.MaxFutureDrift.String(),
			},
		}, nil
	case "getscriptstatus":
		c := script.Coverage()
		return map[string]any{
			"implemented": c.Implemented,
			"pending":     c.Pending,
			"percent":     c.Percent,
			"ready":       len(c.Pending) == 0,
		}, nil
	case "gethealth":
		tip := s.chain.Tip()
		height := int32(-1)
		hash := ""
		if tip != nil {
			height = tip.Height
			hash = tip.Hash
		}
		entries := s.pool.Entries()
		totalBytes := 0
		for _, e := range entries {
			totalBytes += e.Size
		}
		withParents, withChildren, orphanDeps := s.pool.DependencyStats()
		maxAncDepth := s.pool.MaxAncestorDepthObserved()
		return map[string]any{
			"ok":            true,
			"coin":          s.chain.Params().CoinName,
			"height":        height,
			"bestblockhash": hash,
			"peers": map[string]any{
				"total":    s.p2p.PeerCount(),
				"outbound": s.p2p.OutboundCount(),
				"listen":   s.p2p.ListenAddr(),
				"max":      p2p.MaxPeers,
				"maxout":   p2p.MaxOutboundPeers,
			},
			"mempool": map[string]any{
				"size":           len(entries),
				"bytes":          totalBytes,
				"orphans_tx":     s.pool.OrphanCount(),
				"orphans_blocks": s.chain.OrphanCount(),
				"txwithparents":  withParents,
				"txwithchildren": withChildren,
				"orphandepkeys":  orphanDeps,
				"maxancdepth":    maxAncDepth,
				"minrelayfeekb":  mempool.MinRelayFeePerKB,
				"maxmempooltx":   mempool.DefaultMaxTransactions,
			},
			"wallet": w.SecurityInfo(),
		}, nil
	case "getreadiness":
		tip := s.chain.Tip()
		height := int32(-1)
		if tip != nil {
			height = tip.Height
		}
		entries := s.pool.Entries()
		withParents, withChildren, orphanDeps := s.pool.DependencyStats()
		winfo := w.SecurityInfo()
		checks := []map[string]any{
			{
				"id":      "genesis_locked",
				"ok":      s.chain.Params().GenesisHash != "",
				"message": "genesis hash is locked in chain params",
			},
			{
				"id":      "chain_has_blocks",
				"ok":      height >= 0,
				"message": "chain has at least genesis",
			},
			{
				"id":      "p2p_listener",
				"ok":      s.p2p.ListenAddr() != "",
				"message": "p2p listener is active",
			},
			{
				"id":      "peer_capacity_ok",
				"ok":      s.p2p.PeerCount() <= p2p.MaxPeers && s.p2p.OutboundCount() <= p2p.MaxOutboundPeers,
				"message": "peer counts are within configured caps",
			},
			{
				"id":      "wallet_loaded",
				"ok":      winfo != nil,
				"message": "wallet subsystem is available",
			},
			{
				"id":      "wallet_encrypted",
				"ok":      winfo["encrypted"] == true,
				"message": "wallet is encrypted at rest",
			},
			{
				"id":      "orphan_pressure_ok",
				"ok":      s.pool.OrphanCount() < mempool.DefaultMaxOrphans,
				"message": "orphan tx pool is below cap",
			},
			{
				"id":      "mempool_pressure_ok",
				"ok":      len(entries) < mempool.DefaultMaxTransactions,
				"message": "mempool is below cap",
			},
			{
				"id":      "block_orphans_low",
				"ok":      s.chain.OrphanCount() <= blockchain.MaxOrphanBlocks,
				"message": "block orphan queue is within operational threshold",
			},
			{
				"id":      "graph_integrity",
				"ok":      withParents >= 0 && withChildren >= 0 && orphanDeps >= 0 && s.pool.MaxAncestorDepthObserved() <= mempool.MaxAncestorDepth,
				"message": "mempool dependency graph is internally readable",
			},
			{
				"id":      "rpc_exposure_guard",
				"ok":      rpcIsLocalhost(s.rpcBindHost()) || s.auth.Enabled,
				"message": "non-local RPC bind requires rpc auth",
			},
			{
				"id":      "rpc_tls_guard",
				"ok":      rpcIsLocalhost(s.rpcBindHost()) || s.bind.TLS,
				"message": "non-local RPC bind requires TLS",
			},
			{
				"id":      "p2p_bind_reachable",
				"ok":      !p2pIsLocalhost(s.p2p.ListenHost()),
				"message": "p2p bind should not be localhost-only for launch",
			},
		}
		ready := true
		for _, c := range checks {
			ok, _ := c["ok"].(bool)
			if !ok {
				ready = false
				break
			}
		}
		return map[string]any{
			"ready":       ready,
			"target":      "mainnet_candidate",
			"checks":      checks,
			"height":      height,
			"peer_count":  s.p2p.PeerCount(),
			"mempool_tx":  len(entries),
			"orphans_tx":  s.pool.OrphanCount(),
			"orphans_blk": s.chain.OrphanCount(),
			"notes": []string{
				"readiness is operational and policy focused",
				"consensus breadth and PQC spend activation remain separate launch gates",
			},
		}, nil
	case "getselfcheck":
		tip := s.chain.Tip()
		height := int32(-1)
		if tip != nil {
			height = tip.Height
		}
		winfo := w.SecurityInfo()
		checks := []map[string]any{
			{
				"id":      "network_magic_locked",
				"ok":      s.chain.Params().MessageStart == chaincfg.MainNet.MessageStart,
				"expect":  fmt.Sprintf("%x", chaincfg.MainNet.MessageStart),
				"actual":  fmt.Sprintf("%x", s.chain.Params().MessageStart),
				"message": "network message start matches expected mainnet magic",
			},
			{
				"id":      "ports_locked",
				"ok":      s.chain.Params().DefaultPort == 19555 && s.chain.Params().RPCPort == 19556,
				"expect":  "p2p=19555 rpc=19556",
				"actual":  fmt.Sprintf("p2p=%d rpc=%d", s.chain.Params().DefaultPort, s.chain.Params().RPCPort),
				"message": "p2p/rpc ports match launch configuration",
			},
			{
				"id":      "genesis_locked",
				"ok":      s.chain.Params().GenesisHash != "",
				"expect":  "non-empty locked genesis hash",
				"actual":  s.chain.Params().GenesisHash,
				"message": "genesis hash is locked",
			},
			{
				"id":      "chain_initialized",
				"ok":      height >= 0,
				"expect":  "height >= 0",
				"actual":  height,
				"message": "chain is initialized",
			},
			{
				"id":      "peer_caps_configured",
				"ok":      p2p.MaxPeers > 0 && p2p.MaxOutboundPeers > 0 && p2p.MaxOutboundPeers <= p2p.MaxPeers,
				"expect":  "0 < outbound <= total",
				"actual":  fmt.Sprintf("outbound=%d total=%d", p2p.MaxOutboundPeers, p2p.MaxPeers),
				"message": "peer caps are configured sanely",
			},
			{
				"id":      "orphan_caps_configured",
				"ok":      blockchain.MaxOrphanBlocks > 0 && mempool.DefaultMaxOrphans > 0,
				"expect":  "positive orphan caps",
				"actual":  fmt.Sprintf("block_orphans=%d tx_orphans=%d", blockchain.MaxOrphanBlocks, mempool.DefaultMaxOrphans),
				"message": "orphan pool caps are configured",
			},
			{
				"id":      "mempool_caps_configured",
				"ok":      mempool.DefaultMaxTransactions > 0 && mempool.MaxAncestorDepth > 0,
				"expect":  "positive mempool caps",
				"actual":  fmt.Sprintf("max_tx=%d max_ancestor_depth=%d", mempool.DefaultMaxTransactions, mempool.MaxAncestorDepth),
				"message": "mempool limits are configured",
			},
			{
				"id":      "time_drift_guard_configured",
				"ok":      chaincfg.MaxFutureDrift > 0,
				"expect":  "max future drift > 0",
				"actual":  chaincfg.MaxFutureDrift.String(),
				"message": "future-time drift guard is configured",
			},
			{
				"id":      "wallet_encrypted",
				"ok":      winfo["encrypted"] == true,
				"expect":  true,
				"actual":  winfo["encrypted"],
				"message": "wallet is encrypted at rest",
			},
			{
				"id":      "peer_pressure_ok",
				"ok":      s.p2p.PeerCount() <= p2p.MaxPeers && s.p2p.OutboundCount() <= p2p.MaxOutboundPeers,
				"expect":  fmt.Sprintf("<= %d / <= %d", p2p.MaxPeers, p2p.MaxOutboundPeers),
				"actual":  fmt.Sprintf("%d / %d", s.p2p.PeerCount(), s.p2p.OutboundCount()),
				"message": "live peer counts are within caps",
			},
			{
				"id":      "orphan_pressure_ok",
				"ok":      s.chain.OrphanCount() <= blockchain.MaxOrphanBlocks && s.pool.OrphanCount() <= mempool.DefaultMaxOrphans,
				"expect":  fmt.Sprintf("<= %d / <= %d", blockchain.MaxOrphanBlocks, mempool.DefaultMaxOrphans),
				"actual":  fmt.Sprintf("%d / %d", s.chain.OrphanCount(), s.pool.OrphanCount()),
				"message": "live orphan pressure is within caps",
			},
			{
				"id":      "rpc_exposure_guard",
				"ok":      rpcIsLocalhost(s.rpcBindHost()) || s.auth.Enabled,
				"expect":  "localhost bind or rpc auth enabled",
				"actual":  fmt.Sprintf("rpcbind=%s rpcauth=%t", s.rpcBindHost(), s.auth.Enabled),
				"message": "non-local RPC bind requires rpc auth",
			},
			{
				"id":      "rpc_tls_guard",
				"ok":      rpcIsLocalhost(s.rpcBindHost()) || s.bind.TLS,
				"expect":  "localhost bind or rpc tls enabled",
				"actual":  fmt.Sprintf("rpcbind=%s rpctls=%t", s.rpcBindHost(), s.bind.TLS),
				"message": "non-local RPC bind requires TLS",
			},
			{
				"id":      "p2p_bind_reachable",
				"ok":      !p2pIsLocalhost(s.p2p.ListenHost()),
				"expect":  "p2p bind not localhost-only",
				"actual":  fmt.Sprintf("p2pbind=%s", s.p2p.ListenHost()),
				"message": "p2p bind should not be localhost-only for launch",
			},
		}
		ok := true
		for _, c := range checks {
			pass, _ := c["ok"].(bool)
			if !pass {
				ok = false
				break
			}
		}
		return map[string]any{
			"ok":     ok,
			"target": "mainnet-selfcheck",
			"checks": checks,
		}, nil
	case "getlaunchstatus":
		tip := s.chain.Tip()
		height := int32(-1)
		if tip != nil {
			height = tip.Height
		}
		entries := s.pool.Entries()
		winfo := w.SecurityInfo()
		selfOK := true
		if s.chain.Params().MessageStart != chaincfg.MainNet.MessageStart {
			selfOK = false
		}
		if s.chain.Params().DefaultPort != 19555 || s.chain.Params().RPCPort != 19556 {
			selfOK = false
		}
		if s.chain.Params().GenesisHash == "" {
			selfOK = false
		}
		if winfo["encrypted"] != true {
			selfOK = false
		}
		if s.p2p.PeerCount() > p2p.MaxPeers || s.p2p.OutboundCount() > p2p.MaxOutboundPeers {
			selfOK = false
		}
		if s.chain.OrphanCount() > blockchain.MaxOrphanBlocks || s.pool.OrphanCount() > mempool.DefaultMaxOrphans {
			selfOK = false
		}
		if !rpcIsLocalhost(s.rpcBindHost()) && !s.auth.Enabled {
			selfOK = false
		}
		if !rpcIsLocalhost(s.rpcBindHost()) && !s.bind.TLS {
			selfOK = false
		}
		if p2pIsLocalhost(s.p2p.ListenHost()) {
			selfOK = false
		}
		readinessOK := height >= 0 &&
			s.p2p.ListenAddr() != "" &&
			len(entries) < mempool.DefaultMaxTransactions &&
			s.pool.OrphanCount() < mempool.DefaultMaxOrphans &&
			s.chain.OrphanCount() <= blockchain.MaxOrphanBlocks
		blockers := make([]string, 0)
		blockerDetails := make([]map[string]any, 0)
		if !selfOK {
			blockers = append(blockers, "selfcheck_invariants_failed")
			blockerDetails = append(blockerDetails, map[string]any{
				"id":      "selfcheck_invariants_failed",
				"message": "one or more selfcheck invariants failed",
			})
		}
		if !readinessOK {
			blockers = append(blockers, "readiness_checks_failed")
			blockerDetails = append(blockerDetails, map[string]any{
				"id":      "readiness_checks_failed",
				"message": "one or more readiness checks failed",
			})
		}
		hybridReady := false
		if hk, ok := winfo["hybrid_keys"].(int); ok && hk > 0 {
			hybridReady = true
		}
		if !hybridReady {
			blockers = append(blockers, "pqc_hybrid_wallet_not_initialized")
			blockerDetails = append(blockerDetails, map[string]any{
				"id":      "pqc_hybrid_wallet_not_initialized",
				"message": "no hybrid wallet keys are initialized",
			})
		}
		if !rpcIsLocalhost(s.rpcBindHost()) && !s.auth.Enabled {
			blockers = append(blockers, "rpc_exposed_without_auth")
			blockerDetails = append(blockerDetails, map[string]any{
				"id":      "rpc_exposed_without_auth",
				"message": "RPC is exposed beyond localhost without auth",
			})
		}
		if !rpcIsLocalhost(s.rpcBindHost()) && !s.bind.TLS {
			blockers = append(blockers, "rpc_exposed_without_tls")
			blockerDetails = append(blockerDetails, map[string]any{
				"id":      "rpc_exposed_without_tls",
				"message": "RPC is exposed beyond localhost without TLS",
			})
		}
		if p2pIsLocalhost(s.p2p.ListenHost()) {
			blockers = append(blockers, "p2p_bind_localhost_only")
			blockerDetails = append(blockerDetails, map[string]any{
				"id":      "p2p_bind_localhost_only",
				"message": "P2P bind is localhost-only",
			})
		}
		scriptCoverage := script.Coverage()
		if len(scriptCoverage.Pending) > 0 && !s.policy.AllowScriptCoveragePending {
			blockers = append(blockers, "script_coverage_pending")
			blockerDetails = append(blockerDetails, map[string]any{
				"id":      "script_coverage_pending",
				"message": "script coverage has pending items",
				"pending": scriptCoverage.Pending,
			})
		}
		if len(scriptCoverage.Pending) > 0 && s.policy.AllowScriptCoveragePending {
			blockerDetails = append(blockerDetails, map[string]any{
				"id":      "script_coverage_pending_overridden",
				"message": "script coverage pending is temporarily allowed by local policy override",
				"pending": scriptCoverage.Pending,
			})
		}
		launchReady := selfOK && readinessOK && hybridReady && len(blockers) == 0
		productionReady := launchReady && !s.policy.AllowScriptCoveragePending
		return map[string]any{
			"launch_ready":     launchReady,
			"production_ready": productionReady,
			"selfcheck_ok":     selfOK,
			"readiness_ok":     readinessOK,
			"pqc_ready":        hybridReady,
			"height":           height,
			"peers": map[string]any{
				"total":    s.p2p.PeerCount(),
				"outbound": s.p2p.OutboundCount(),
				"max":      p2p.MaxPeers,
				"maxout":   p2p.MaxOutboundPeers,
			},
			"mempool": map[string]any{
				"tx":            len(entries),
				"orphans_tx":    s.pool.OrphanCount(),
				"orphans_block": s.chain.OrphanCount(),
			},
			"blockers":        blockers,
			"blocker_details": blockerDetails,
			"notes": []string{
				"launch_ready requires no blockers",
				"production_ready additionally requires no temporary policy overrides",
				"this endpoint is an operator summary, not a consensus rule",
			},
			"policy": map[string]any{
				"allow_script_coverage_pending": s.policy.AllowScriptCoveragePending,
			},
		}, nil
	case "getlaunchchecklist":
		scriptCoverage := script.Coverage()
		p2pReachable := !p2pIsLocalhost(s.p2p.ListenHost())
		rpcSafe := rpcIsLocalhost(s.rpcBindHost()) || s.auth.Enabled
		rpcTLSSafe := rpcIsLocalhost(s.rpcBindHost()) || s.bind.TLS
		tip := s.chain.Tip()
		height := int32(-1)
		if tip != nil {
			height = tip.Height
		}
		winfo := w.SecurityInfo()
		hybridReady := false
		if hk, ok := winfo["hybrid_keys"].(int); ok && hk > 0 {
			hybridReady = true
		}
		checks := []map[string]any{
			{"id": "chain_initialized", "ok": height >= 0, "message": "chain has at least genesis", "remediation": "run the node once to initialize genesis and chainstate"},
			{"id": "wallet_encrypted", "ok": winfo["encrypted"] == true, "message": "wallet encrypted at rest", "remediation": "call encryptwallet and restart with locked wallet workflow"},
			{"id": "pqc_hybrid_ready", "ok": hybridReady, "message": "hybrid wallet key exists", "remediation": "call getnewhybridaddress at least once after unlock"},
			{"id": "rbf_policy_disabled", "ok": true, "message": "opt-in RBF is intentionally disabled until end-to-end replacement tests pass", "remediation": "do not advertise RBF until Pool.Add replacement behavior is fixed and tested"},
			{"id": "rpc_exposure_guard", "ok": rpcSafe, "message": "RPC exposure/auth policy passes", "remediation": "use rpcbind=127.0.0.1 or set rpcuser/rpcpassword"},
			{"id": "rpc_tls_guard", "ok": rpcTLSSafe, "message": "RPC transport security policy passes", "remediation": "use rpcbind=127.0.0.1 or set rpctls=1 with rpctlscert and rpctlskey"},
			{"id": "p2p_bind_reachable", "ok": p2pReachable, "message": "P2P bind is launch reachable", "remediation": "set bind=0.0.0.0 or a non-localhost interface"},
			{"id": "script_coverage_complete", "ok": len(scriptCoverage.Pending) == 0 || s.policy.AllowScriptCoveragePending, "message": "script coverage pending list is empty or explicitly overridden", "remediation": "complete pending script features before public launch"},
			{"id": "bootstrap_available", "ok": len(s.chain.Params().DNSSeeds) > 0 || len(s.chain.Params().FixedSeeds) > 0 || len(s.p2p.BootstrapPeers()) > 0, "message": "DNS seed, fixed seed, or addnode bootstrap is configured", "remediation": "configure addnode entries, fixed seeds, or DNS seed records"},
		}
		passed := 0
		for _, c := range checks {
			if ok, _ := c["ok"].(bool); ok {
				passed++
			}
		}
		percent := 0
		if len(checks) > 0 {
			percent = passed * 100 / len(checks)
		}
		ready := passed == len(checks)
		productionReady := ready && !s.policy.AllowScriptCoveragePending
		return map[string]any{
			"ready":            ready,
			"production_ready": productionReady,
			"score_percent":    percent,
			"passed":           passed,
			"total":            len(checks),
			"checks":           checks,
			"script_pending":   scriptCoverage.Pending,
			"rpcbind":          s.rpcBindHost(),
			"rpcauth":          s.auth.Enabled,
			"rpctls":           s.bind.TLS,
			"p2pbind":          s.p2p.ListenHost(),
			"bootstrap_count":  len(s.p2p.BootstrapPeers()),
			"dns_seed_count":   len(s.chain.Params().DNSSeeds),
			"fixed_seed_count": len(s.chain.Params().FixedSeeds),
			"policy": map[string]any{
				"allow_script_coverage_pending": s.policy.AllowScriptCoveragePending,
			},
		}, nil
	case "getblockcount":
		if tip := s.chain.Tip(); tip != nil {
			return tip.Height, nil
		}
		return int32(-1), nil
	case "getbestblockhash":
		if tip := s.chain.Tip(); tip != nil {
			return tip.Hash, nil
		}
		return "", nil
	case "getblockhash":
		var args []int32
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "getblockhash expects height"}
		}
		idx, err := s.chain.IndexByHeight(args[0])
		if err != nil {
			return nil, blockLookupError(err)
		}
		return idx.Hash, nil
	case "getblock":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "getblock expects block hash"}
		}
		block, idx, err := s.chain.BlockByHash(args[0])
		if err != nil {
			return nil, blockLookupError(err)
		}
		raw, err := block.Bytes()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		txids := make([]string, len(block.Transactions))
		for i, tx := range block.Transactions {
			h, err := tx.TxHash()
			if err != nil {
				txids[i] = ""
			} else {
				txids[i] = h.String()
			}
		}
		return map[string]any{
			"hash":          idx.Hash,
			"height":        idx.Height,
			"version":       block.Header.Version,
			"merkleroot":    block.Header.MerkleRoot.String(),
			"time":          block.Header.Timestamp,
			"bits":          strconv.FormatUint(uint64(block.Header.Bits), 16),
			"nonce":         block.Header.Nonce,
			"tx":            txids,
			"confirmations": confirmations(s.chain.Tip(), idx),
			"hex":           hex.EncodeToString(raw),
		}, nil
	case "getblockheader":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
			return nil, &rpcError{Code: -32602, Message: "getblockheader expects block hash and optional verbose flag"}
		}
		var hash string
		if err := json.Unmarshal(args[0], &hash); err != nil {
			return nil, &rpcError{Code: -32602, Message: "invalid block hash"}
		}
		verbose := true
		if len(args) > 1 {
			if b, ok := parseBoolish(args[1]); ok {
				verbose = b
			}
		}
		block, idx, err := s.chain.BlockByHash(strings.TrimSpace(hash))
		if err != nil {
			return nil, blockLookupError(err)
		}
		if !verbose {
			rawHeader, err := block.Header.Bytes()
			if err != nil {
				return nil, &rpcError{Code: -32603, Message: err.Error()}
			}
			return hex.EncodeToString(rawHeader), nil
		}
		nextHash := ""
		if nextIdx, err := s.chain.IndexByHeight(idx.Height + 1); err == nil {
			if nextBlock, _, nextErr := s.chain.BlockByHash(nextIdx.Hash); nextErr == nil && nextBlock.Header.PrevBlock.String() == idx.Hash {
				nextHash = nextIdx.Hash
			}
		}
		return map[string]any{
			"hash":          idx.Hash,
			"confirmations": confirmations(s.chain.Tip(), idx),
			"height":        idx.Height,
			"version":       block.Header.Version,
			"versionHex":    fmt.Sprintf("%08x", uint32(block.Header.Version)),
			"merkleroot":    block.Header.MerkleRoot.String(),
			"time":          block.Header.Timestamp,
			"bits":          fmt.Sprintf("%08x", block.Header.Bits),
			"nonce":         block.Header.Nonce,
			"previousblockhash": func() string {
				if idx.Height == 0 {
					return ""
				}
				return block.Header.PrevBlock.String()
			}(),
			"nextblockhash": nextHash,
		}, nil
	case "submitblock":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "submitblock expects block hex"}
		}
		raw, err := hex.DecodeString(args[0])
		if err != nil {
			return nil, &rpcError{Code: -22, Message: err.Error()}
		}
		block, err := wire.ReadBlock(bytes.NewReader(raw))
		if err != nil {
			return nil, &rpcError{Code: -22, Message: err.Error()}
		}
		result, err := s.chain.ProcessBlockWithResult(block)
		if err != nil {
			return submitBlockRejectCode(err), nil
		}
		switch result.Status {
		case blockchain.BlockStatusDuplicate:
			return "duplicate", nil
		case blockchain.BlockStatusOrphan:
			return "bad-prevblk", nil
		case blockchain.BlockStatusSideChain:
			return "inconclusive", nil
		case blockchain.BlockStatusConnected:
			// success (nil) below
		default:
			if !result.Connected || !result.BestChanged {
				return "rejected", nil
			}
		}
		if hash, err := s.chain.BlockHash(block); err == nil && s.p2p != nil {
			// Announce the block by canonical Yespower block hash, not SHA256d.
			s.p2p.AnnounceBlock(hash)
		}
		return nil, nil
	case "submitblockdebug":
		return s.submitBlockDiagnostic(params, true)
	case "validateblockproposal", "testblock":
		return s.submitBlockDiagnostic(params, false)
	case "disconnecttip":
		if err := s.chain.DisconnectTip(); err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		if tip := s.chain.Tip(); tip != nil {
			return map[string]any{"height": tip.Height, "hash": tip.Hash}, nil
		}
		return map[string]any{"height": -1, "hash": ""}, nil
	case "getblocktemplate":
		return s.getBlockTemplate(ctx, params)
	case "getrawtransaction":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
			return nil, &rpcError{Code: -32602, Message: "getrawtransaction expects txid and optional verbose flag"}
		}
		var txid string
		if err := json.Unmarshal(args[0], &txid); err != nil {
			return nil, &rpcError{Code: -32602, Message: "invalid txid"}
		}
		verbose := false
		if len(args) > 1 {
			if b, ok := parseBoolish(args[1]); ok {
				verbose = b
			}
		}
		lookup, err := s.lookupTransaction(txid)
		if err != nil {
			if !s.chain.TxIndexEnabled() {
				return nil, &rpcError{Code: -5, Message: "transaction not found (txindex disabled; enable txindex=1 for reliable historical lookup)"}
			}
			return nil, &rpcError{Code: -5, Message: "transaction not found"}
		}
		rawTx, err := lookup.Tx.Bytes()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		if !verbose {
			return hex.EncodeToString(rawTx), nil
		}
		return txVerboseResult(lookup), nil
	case "getaddresstxids":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "getaddresstxids expects address"}
		}
		if !s.chain.AddressIndexEnabled() {
			return nil, &rpcError{Code: -5, Message: "addressindex disabled (set addressindex=1 and reindex)"}
		}
		txids, err := s.chain.AddressTxIDs(args[0])
		if err != nil {
			return nil, &rpcError{Code: -5, Message: err.Error()}
		}
		return txids, nil
	case "getaddressutxos":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "getaddressutxos expects address"}
		}
		if !s.chain.AddressIndexEnabled() {
			return nil, &rpcError{Code: -5, Message: "addressindex disabled (set addressindex=1 and reindex)"}
		}
		utxos, err := s.chain.AddressUTXOs(args[0])
		if err != nil {
			return nil, &rpcError{Code: -5, Message: err.Error()}
		}
		return utxos, nil
	case "getaddressbalance":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "getaddressbalance expects address"}
		}
		if !s.chain.AddressIndexEnabled() {
			return nil, &rpcError{Code: -5, Message: "addressindex disabled (set addressindex=1 and reindex)"}
		}
		confirmed, total, err := s.chain.AddressBalance(args[0])
		if err != nil {
			return nil, &rpcError{Code: -5, Message: err.Error()}
		}
		return map[string]any{
			"address":                     args[0],
			"balance":                     amountFloat(confirmed),
			"balance_base_units":          confirmed,
			"received_base_units":         total,
			"received":                    amountFloat(total),
			"addressindex_confirmed_only": true,
		}, nil
	case "getaddresshistory":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 || len(args) > 5 {
			return nil, &rpcError{Code: -32602, Message: "getaddresshistory expects <address> [limit] [offset] [type_filter] [confirmations_filter]"}
		}
		var addr string
		if err := json.Unmarshal(args[0], &addr); err != nil || strings.TrimSpace(addr) == "" {
			return nil, &rpcError{Code: -32602, Message: "getaddresshistory expects address"}
		}

		limit := 0
		offset := 0
		typeFilter := "all"
		confFilter := "all"

		if len(args) >= 2 {
			if err := json.Unmarshal(args[1], &limit); err != nil || limit < 0 {
				return nil, &rpcError{Code: -32602, Message: "invalid limit"}
			}
		}
		if len(args) >= 3 {
			if err := json.Unmarshal(args[2], &offset); err != nil || offset < 0 {
				return nil, &rpcError{Code: -32602, Message: "invalid offset"}
			}
		}
		if len(args) >= 4 {
			if err := json.Unmarshal(args[3], &typeFilter); err != nil {
				return nil, &rpcError{Code: -32602, Message: "invalid type_filter"}
			}
			typeFilter = strings.ToLower(strings.TrimSpace(typeFilter))
			switch typeFilter {
			case "", "all":
				typeFilter = "all"
			case "receive", "received":
				typeFilter = "receive"
			case "spend", "spent":
				typeFilter = "spend"
			default:
				return nil, &rpcError{Code: -32602, Message: "type_filter must be all, receive, received, spend, or spent"}
			}
		}
		if len(args) >= 5 {
			if err := json.Unmarshal(args[4], &confFilter); err != nil {
				return nil, &rpcError{Code: -32602, Message: "invalid confirmations_filter"}
			}
			confFilter = strings.ToLower(strings.TrimSpace(confFilter))
			switch confFilter {
			case "", "all":
				confFilter = "all"
			case "confirmed", "confirm":
				confFilter = "confirmed"
			case "unconfirmed", "mempool":
				confFilter = "unconfirmed"
			default:
				return nil, &rpcError{Code: -32602, Message: "confirmations_filter must be all, confirmed, or unconfirmed"}
			}
		}

		if !s.chain.AddressIndexEnabled() {
			return nil, &rpcError{Code: -5, Message: "addressindex disabled (set addressindex=1 and reindex)"}
		}
		history, err := s.chain.AddressHistory(addr)
		if err != nil {
			return nil, &rpcError{Code: -5, Message: err.Error()}
		}
		txids, err := s.chain.AddressTxIDs(addr)
		if err != nil {
			return nil, &rpcError{Code: -5, Message: err.Error()}
		}

		tipHeight := int32(-1)
		if tip := s.chain.Tip(); tip != nil {
			tipHeight = tip.Height
		}

		type historyEntry struct {
			TxID          string `json:"txid"`
			Height        int32  `json:"height"`
			Confirmations int32  `json:"confirmations"`
			Type          string `json:"type"`
			Amount        string `json:"amount"`
			AmountBase    int64  `json:"amount_base_units"`
			Vout          uint32 `json:"vout,omitempty"`
			Spent         bool   `json:"spent,omitempty"`
			SpendTxID     string `json:"spend_txid,omitempty"`
			SpendHeight   int32  `json:"spend_height,omitempty"`
			Coinbase      bool   `json:"coinbase"`
			Mature        bool   `json:"mature"`
			RelatedTxID   string `json:"related_txid,omitempty"`
		}

		entries := make([]historyEntry, 0, len(history)*2)
		for _, rec := range history {
			confs := int32(0)
			if tipHeight >= rec.Height && rec.Height >= 0 {
				confs = tipHeight - rec.Height + 1
			}
			mature := !rec.Coinbase || confs >= int32(chaincfg.CoinbaseMaturity)

			entries = append(entries, historyEntry{
				TxID:          rec.TxID,
				Height:        rec.Height,
				Confirmations: confs,
				Type:          "receive",
				Amount:        amount.FormatWithTicker(rec.Value),
				AmountBase:    rec.Value,
				Vout:          rec.Vout,
				Spent:         rec.Spent,
				SpendTxID:     rec.SpendTxID,
				SpendHeight:   rec.SpendHeight,
				Coinbase:      rec.Coinbase,
				Mature:        mature,
			})

			if rec.Spent && rec.SpendTxID != "" {
				spendConfs := int32(0)
				if tipHeight >= rec.SpendHeight && rec.SpendHeight > 0 {
					spendConfs = tipHeight - rec.SpendHeight + 1
				}
				entries = append(entries, historyEntry{
					TxID:          rec.SpendTxID,
					Height:        rec.SpendHeight,
					Confirmations: spendConfs,
					Type:          "spend",
					Amount:        amount.FormatWithTicker(-rec.Value),
					AmountBase:    -rec.Value,
					Coinbase:      rec.Coinbase,
					Mature:        mature,
					RelatedTxID:   rec.TxID,
				})
			}
		}

		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Height == entries[j].Height {
				if entries[i].TxID == entries[j].TxID {
					return entries[i].Type < entries[j].Type
				}
				return entries[i].TxID < entries[j].TxID
			}
			return entries[i].Height < entries[j].Height
		})

		filtered := make([]historyEntry, 0, len(entries))
		for _, entry := range entries {
			if typeFilter != "all" && entry.Type != typeFilter {
				continue
			}
			if confFilter == "confirmed" && entry.Confirmations <= 0 {
				continue
			}
			if confFilter == "unconfirmed" && entry.Confirmations > 0 {
				continue
			}
			filtered = append(filtered, entry)
		}

		total := len(filtered)
		if offset > total {
			filtered = filtered[:0]
		} else {
			filtered = filtered[offset:]
		}
		if limit > 0 && limit < len(filtered) {
			filtered = filtered[:limit]
		}

		return map[string]any{
			"address":              addr,
			"txids":                txids,
			"entries":              filtered,
			"total":                total,
			"limit":                limit,
			"offset":               offset,
			"type_filter":          typeFilter,
			"confirmations_filter": confFilter,
			"addressindex_mode":    "utxo-plus-history-foundation",
		}, nil
	case "gettransaction":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
			return nil, &rpcError{Code: -32602, Message: "gettransaction expects txid"}
		}
		var txid string
		if err := json.Unmarshal(args[0], &txid); err != nil {
			return nil, &rpcError{Code: -32602, Message: "invalid txid"}
		}
		lookup, err := s.lookupTransaction(txid)
		if err != nil {
			if !s.chain.TxIndexEnabled() {
				return nil, &rpcError{Code: -5, Message: "transaction not found (txindex disabled; enable txindex=1 for reliable historical lookup)"}
			}
			return nil, &rpcError{Code: -5, Message: "transaction not found"}
		}
		rawTx, err := lookup.Tx.Bytes()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		out := txVerboseResult(lookup)
		out["hex"] = hex.EncodeToString(rawTx)
		summary := s.walletTransactionSummary(lookup)
		out["amount"] = amountFloat(summary.AmountBaseUnits)
		out["amount_base_units"] = summary.AmountBaseUnits
		out["fee"] = amountFloat(summary.FeeBaseUnits)
		out["fee_base_units"] = summary.FeeBaseUnits
		out["generated"] = summary.Generated
		out["timereceived"] = summary.TimeReceived
		out["details"] = summary.Details
		return out, nil
	case "decoderawtransaction":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "decoderawtransaction expects transaction hex"}
		}
		raw, err := hex.DecodeString(strings.TrimSpace(args[0]))
		if err != nil {
			return nil, &rpcError{Code: -22, Message: err.Error()}
		}
		tx, err := wire.ReadTx(bytes.NewReader(raw))
		if err != nil {
			return nil, &rpcError{Code: -22, Message: err.Error()}
		}
		h, err := tx.TxHash()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		lookup := &txLookupResult{
			Tx:            tx,
			TxID:          h.String(),
			Confirmations: 0,
			BlockHeight:   -1,
			InMempool:     false,
		}
		out := txVerboseResult(lookup)
		out["hex"] = strings.ToLower(strings.TrimSpace(args[0]))
		return out, nil
	case "sendrawtransaction":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "sendrawtransaction expects transaction hex"}
		}
		raw, err := hex.DecodeString(args[0])
		if err != nil {
			return nil, &rpcError{Code: -22, Message: err.Error()}
		}
		tx, err := wire.ReadTx(bytes.NewReader(raw))
		if err != nil {
			return nil, &rpcError{Code: -22, Message: err.Error()}
		}
		entry, err := s.pool.Add(s.chain, tx)
		if err != nil {
			return nil, &rpcError{Code: -26, Message: err.Error()}
		}
		s.announceMempoolTx(entry.TxID)
		return entry.TxID, nil
	case "getmempoolentry":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "getmempoolentry expects txid"}
		}
		e, ok := s.pool.Entry(args[0])
		if !ok {
			return nil, &rpcError{Code: -5, Message: "transaction not in mempool"}
		}
		parents, children := s.pool.EntryDependencies(e.TxID)
		return map[string]any{"txid": e.TxID, "size": e.Size, "fee": e.Fee, "fee_per_kb": float64(e.Fee) * 1000 / float64(e.Size), "depends": parents, "spentby": children}, nil
	case "getrawmempool":
		entries := s.pool.Entries()
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e.TxID)
		}
		return out, nil
	case "getmempoolinfo":
		entries := s.pool.Entries()
		totalBytes := 0
		for _, e := range entries {
			totalBytes += e.Size
		}
		withParents, withChildren, orphanDeps := s.pool.DependencyStats()
		maxAncDepth := s.pool.MaxAncestorDepthObserved()
		return map[string]any{
			"size":           len(entries),
			"bytes":          totalBytes,
			"maxmempooltx":   mempool.DefaultMaxTransactions,
			"minrelayfeekb":  mempool.MinRelayFeePerKB,
			"increlayfeekb":  mempool.IncrementalRelayFeeKB,
			"orphanstx":      s.pool.OrphanCount(),
			"txwithparents":  withParents,
			"txwithchildren": withChildren,
			"orphandepkeys":  orphanDeps,
			"maxancdepth":    maxAncDepth,
			"orphans":        s.chain.OrphanCount(),
		}, nil
	case "setupwallet":
		var args []string
		_ = json.Unmarshal(params, &args)
		passphrase := ""
		if len(args) > 0 {
			passphrase = args[0]
		}
		winfo := w.SecurityInfo()
		if winfo["hdseed"] != true {
			if _, err := w.SetHDSeed(""); err != nil {
				return nil, &rpcError{Code: -13, Message: "setupwallet sethdseed: " + err.Error()}
			}
		}
		if winfo["classic_keys"].(int) == 0 {
			if _, err := w.NewAddress(); err != nil {
				return nil, &rpcError{Code: -13, Message: "setupwallet classic address: " + err.Error()}
			}
		}
		if winfo["hybrid_keys"].(int) == 0 {
			if _, err := w.NewHybridAddress(); err != nil {
				return nil, &rpcError{Code: -13, Message: "setupwallet hybrid address: " + err.Error()}
			}
		}
		miningInfo, err := firstWalletMiningAddress(w)
		if err != nil {
			return nil, &rpcError{Code: -13, Message: "setupwallet mining address: " + err.Error()}
		}
		_ = s.persistMiningDestination(miningInfo)
		if passphrase != "" {
			if err := w.Encrypt(passphrase); err != nil && !strings.Contains(err.Error(), "already encrypted") {
				return nil, &rpcError{Code: -13, Message: "setupwallet encrypt: " + err.Error()}
			}
		}
		mnem := w.Mnemonic()
		res := map[string]any{
			"wallet":             w.SecurityInfo(),
			"mining_address":     miningInfo.Address,
			"mining_pubkey_hash": miningInfo.PubKeyHashHex,
			"config":             s.miningConfigPath(),
			"next":               "start miner with this mining_pubkey_hash; coinbase rewards mature after 100 blocks",
		}
		if mnem != "" {
			res["mnemonic"] = mnem
			res["warning"] = "WRITE DOWN THESE 24 WORDS — they are the ONLY backup of your wallet. Without them, coins are unrecoverable."
		}
		return res, nil
	case "getminingaddress":
		cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
		dest, err := s.resolveMiningDestination(w, cfg, true)
		if err != nil {
			return nil, &rpcError{Code: -13, Message: err.Error()}
		}
		return wallet.MiningAddressInfo{Address: dest.Address, PubKeyHashHex: dest.PubKeyHashHex}, nil
	case "setminingaddress":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "setminingaddress expects one wallet-owned Legacy address"}
		}
		input := strings.TrimSpace(args[0])
		info := wallet.MiningAddressInfo{}
		if hashErr := validateMiningPubKeyHash(input); hashErr == nil {
			addr := walletClassicAddressForHash(w, input)
			if addr == "" {
				return nil, &rpcError{Code: -32602, Message: unownedMiningDestinationMessage}
			}
			info = wallet.MiningAddressInfo{Address: addr, PubKeyHashHex: strings.ToLower(input)}
		} else {
			if err := decodeMiningAddressInput(input, &info); err != nil {
				return nil, &rpcError{Code: -32602, Message: "setminingaddress expects a wallet-owned classic Legacy address"}
			}
			if !walletOwnsClassicAddress(w, info.Address) {
				return nil, &rpcError{Code: -32602, Message: unownedMiningDestinationMessage}
			}
		}
		if err := s.persistMiningDestination(info); err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{
			"mining_address":     info.Address,
			"mining_pubkey_hash": strings.ToLower(info.PubKeyHashHex),
			"wallet_owned":       true,
			"external_payout":    false,
			"config":             s.miningConfigPath(),
			"message":            "wallet-owned mining reward address saved",
		}, nil
	case "getwalletsummary":
		cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
		return s.walletSummary(w, []string{cfg.PubKeyHash}), nil
	case "listimmature":
		cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
		summary := s.walletSummary(w, []string{cfg.PubKeyHash})
		return summary["immature_outputs"], nil
	case "checkstorage":
		var args []json.RawMessage
		_ = json.Unmarshal(params, &args)
		repair := false
		if len(args) > 0 {
			if err := json.Unmarshal(args[0], &repair); err != nil {
				var str string
				if err2 := json.Unmarshal(args[0], &str); err2 == nil {
					l := strings.ToLower(strings.TrimSpace(str))
					repair = l == "1" || l == "true" || l == "yes" || l == "repair"
				}
			}
		}
		if repair {
			report, err := s.chain.ReindexActiveChain()
			if err != nil {
				return nil, &rpcError{Code: -32603, Message: "checkstorage repair failed: " + err.Error()}
			}
			report["repair_requested"] = true
			report["health"] = s.chain.StorageHealth()
			return report, nil
		}
		return s.chain.StorageHealth(), nil
	case "reindex":
		report, err := s.chain.ReindexActiveChain()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: "reindex failed: " + err.Error()}
		}
		report["health"] = s.chain.StorageHealth()
		return report, nil
	case "getmininginfo":
		cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
		storage := s.chain.StorageHealth()
		peerOK := !cfg.PeerRequired || (s.p2p != nil && s.p2p.PeerCount() > 0)
		dest := s.miningDestinationStatus(w, cfg)
		miningReady := storage.OK && peerOK && (dest.Owned || dest.External)
		return s.minerStatus(w, cfg, storage, miningReady), nil

	case "getminerstatus":
		cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
		storage := s.chain.StorageHealth()
		peerOK := !cfg.PeerRequired || (s.p2p != nil && s.p2p.PeerCount() > 0)
		dest := s.miningDestinationStatus(w, cfg)
		miningReady := storage.OK && peerOK && (dest.Owned || dest.External)
		return s.minerStatus(w, cfg, storage, miningReady), nil

	case "benchmarkminer":
		return s.benchmarkMiner(ctx, params)
	case "autotuneminer":
		return s.autoTuneMiner(ctx, params)
	case "setminerthreads":
		return s.setMinerThreads(params)
	case "configureminer":
		return s.configureMiner(w, params)
	case "startminer":
		return s.startMiner(ctx, params)
	case "stopminer":
		return s.stopMiner(parseMinerStopReason(params, MinerStopRPCStopMiner)), nil
	case "restartminer":
		cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
		if safety := s.checkSafeToMine(w, cfg, true); !safety.Safe {
			return nil, &rpcError{Code: -32603, Message: safety.Reason}
		}
		_ = s.stopMiner(MinerStopSupervisorShutdown)
		return s.startMiner(ctx, params)
	case "getpeerinfo":
		return map[string]any{"count": s.p2p.PeerCount(), "outbound": s.p2p.OutboundCount(), "peers": s.p2p.PeerInfos()}, nil
	case "getknownpeers":
		return map[string]any{"count": s.p2p.KnownAddressCount(), "known_peers_available": true, "peers": s.p2p.KnownPeerInfos()}, nil
	case "getsyncstatus":
		return s.p2p.SyncStatus(), nil
	case "getchainstatus":
		return s.chainStatus(), nil
	case "getforkstatus":
		return s.forkStatus(), nil
	case "getconnectioncount":
		return s.p2p.ConnectionCount(), nil
	case "addnode":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
			return nil, &rpcError{Code: -32602, Message: "addnode expects address"}
		}
		if err := s.p2p.AddNode(ctx, args[0]); err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{"added": args[0]}, nil
	case "disconnectnode":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
			return nil, &rpcError{Code: -32602, Message: "disconnectnode expects address"}
		}
		return map[string]any{"addr": args[0], "disconnected": s.p2p.DisconnectNode(args[0])}, nil
	case "getnetworkhashps":
		return s.estimateNetworkHashPS(rpcWindowParam(params, 100)), nil
	case "getchaintips":
		tip := s.chain.Tip()
		if tip == nil {
			return []map[string]any{}, nil
		}
		return []map[string]any{
			{
				"height":    tip.Height,
				"hash":      tip.Hash,
				"branchlen": 0,
				"status":    "active",
			},
		}, nil
	case "getblockchaininfo":
		return s.getBlockchainInfo(), nil
	case "getchaintiming":
		return s.chainTiming(100), nil
	case "getdifficultyhistory":
		history := s.difficultyHistory(rpcWindowParam(params, 100))
		return map[string]any{"count": len(history), "history": history}, nil
	case "doctor":
		return s.doctor(), nil
	case "captureresourcediagnostics":
		return ManualDiagnosticCapture("rpc-trigger"), nil
	case "getnewaddress":
		addr, err := w.NewAddress()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return addr, nil
	case "getnewhybridaddress":
		addr, err := w.NewHybridAddress()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{
			"address":   addr,
			"type":      "hybrid",
			"algorithm": "hybrid-secp256k1-ecdsa+mldsa65",
		}, nil
	case "listaddresses":
		return w.ListAddresses(), nil
	case "listunspent":
		var args []json.RawMessage
		_ = json.Unmarshal(params, &args)
		minConf := int32(1)
		if len(args) > 0 {
			var parsed int32
			if err := json.Unmarshal(args[0], &parsed); err == nil {
				minConf = parsed
			}
		}
		var unspent []wallet.UTXOView
		var err error
		if minConf <= 0 {
			unspent, err = w.ListUnspentForSpend(s.chain, s.pool)
		} else {
			unspent, err = w.ListUnspent(s.chain)
		}
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		addressFilter := map[string]struct{}{}
		if len(args) > 2 {
			var addresses []string
			if err := json.Unmarshal(args[2], &addresses); err == nil {
				for _, a := range addresses {
					a = strings.TrimSpace(a)
					if a != "" {
						addressFilter[a] = struct{}{}
					}
				}
			}
		}
		rows := make([]map[string]any, 0, len(unspent))
		for _, u := range unspent {
			if minConf > 0 && u.Confirmations < minConf {
				continue
			}
			if len(addressFilter) > 0 {
				if _, ok := addressFilter[u.Address]; !ok {
					continue
				}
			}
			row, err := s.rpcUnspentRow(u)
			if err != nil {
				continue
			}
			rows = append(rows, row)
		}
		return rows, nil
	case "backupwallet":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "backupwallet expects destination path"}
		}
		dest, err := resolveSafePath(args[0], config.DefaultDataDir())
		if err != nil {
			return nil, &rpcError{Code: -8, Message: err.Error()}
		}
		src := filepath.Join(config.DefaultDataDir(), "wallet.json")
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		if err := os.WriteFile(dest, data, 0600); err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{"backup": dest, "ok": true}, nil
	case "dumpwallet":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "dumpwallet expects destination path"}
		}
		dest, err := resolveSafePath(args[0], config.DefaultDataDir())
		if err != nil {
			return nil, &rpcError{Code: -8, Message: err.Error()}
		}
		src := filepath.Join(config.DefaultDataDir(), "wallet.json")
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		if err := os.WriteFile(dest, data, 0600); err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{"dump": dest, "ok": true, "note": "encrypted wallets remain encrypted"}, nil
	case "dumpprivkey":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "dumpprivkey expects address"}
		}
		wif, err := w.DumpPrivKey(args[0])
		if err != nil {
			return nil, &rpcError{Code: -4, Message: err.Error()}
		}
		return wif, nil
	case "importprivkey":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "importprivkey expects WIF key"}
		}
		addr, err := w.ImportPrivKey(args[0])
		if err != nil {
			return nil, &rpcError{Code: -5, Message: err.Error()}
		}
		return addr, nil
	case "sendtoaddress", "sendtoaddressraw":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
			return nil, &rpcError{Code: -32602, Message: "sendtoaddress expects address, amount_lbtc, optional fee_lbtc; use sendtoaddressraw for base units"}
		}
		var addr string
		if err := json.Unmarshal(args[0], &addr); err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad address"}
		}
		rawMode := method == "sendtoaddressraw"
		amountValue, err := parseRPCAmount(args[1], rawMode)
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad amount: " + err.Error()}
		}
		feeValue := s.currentTxFee()
		if len(args) > 2 {
			feeValue, err = parseRPCAmount(args[2], rawMode)
			if err != nil {
				return nil, &rpcError{Code: -32602, Message: "bad fee: " + err.Error()}
			}
		}
		txid, err := w.SendToAddress(s.chain, s.pool, addr, amountValue, feeValue)
		if err != nil {
			return nil, &rpcError{Code: -6, Message: rpcSendError(err)}
		}
		s.announceMempoolTx(txid)
		return txSendResult(txid, amountValue, feeValue, rawMode), nil
	case "sendfromaddress", "sendfromaddressraw":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 3 {
			return nil, &rpcError{Code: -32602, Message: "sendfromaddress expects from, to, amount_lbtc, optional fee_lbtc; use sendfromaddressraw for base units"}
		}
		var from string
		var to string
		if err := json.Unmarshal(args[0], &from); err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad source address"}
		}
		if err := json.Unmarshal(args[1], &to); err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad destination address"}
		}
		rawMode := method == "sendfromaddressraw"
		amountValue, err := parseRPCAmount(args[2], rawMode)
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad amount: " + err.Error()}
		}
		feeValue := s.currentTxFee()
		if len(args) > 3 {
			feeValue, err = parseRPCAmount(args[3], rawMode)
			if err != nil {
				return nil, &rpcError{Code: -32602, Message: "bad fee: " + err.Error()}
			}
		}
		txid, err := w.SendFromAddress(s.chain, s.pool, from, to, amountValue, feeValue)
		if err != nil {
			return nil, &rpcError{Code: -6, Message: rpcSendError(err)}
		}
		s.announceMempoolTx(txid)
		return txSendResult(txid, amountValue, feeValue, rawMode), nil
	case "sendmany", "sendmanyraw":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
			return nil, &rpcError{Code: -32602, Message: method + " expects account, {address:amount}, optional minconf/comment/subtractfeefrom"}
		}
		// Bitcoin compatibility: first arg is a legacy account string and is ignored.
		from := ""
		if len(args) > 0 {
			_ = json.Unmarshal(args[0], &from)
			from = strings.TrimSpace(from)
		}
		rawMode := method == "sendmanyraw"
		outputs, err := parseSendManyOutputs(args[1], rawMode)
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		feeValue := s.currentTxFee()
		if len(args) > 6 {
			feeValue, err = parseRPCAmount(args[6], rawMode)
			if err != nil {
				return nil, &rpcError{Code: -32602, Message: "bad fee: " + err.Error()}
			}
		}
		txid, totalAmount, err := w.SendMany(s.chain, s.pool, from, outputs, feeValue)
		if err != nil {
			return nil, &rpcError{Code: -6, Message: rpcSendError(err)}
		}
		s.announceMempoolTx(txid)
		return txSendResult(txid, totalAmount, feeValue, rawMode), nil
	case "sendtokendeploy", "sendtokendeploycurve", "sendtokentransfer", "sendtokenburn", "sendtokenbuy", "sendtokensell":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 || len(args) > 2 {
			return nil, &rpcError{Code: -32602, Message: method + " expects token operation object and optional fee_lbtc"}
		}
		var op tokens.Operation
		if err := json.Unmarshal(args[0], &op); err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad token operation: " + err.Error()}
		}
		opName := rpcTokenOpName(strings.TrimPrefix(method, "sendtoken"))
		op = tokens.Normalize(op, opName)
		if err := tokens.Validate(op); err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		source := op.Creator
		if op.Op == "TRANSFER" || op.Op == "BURN" || op.Op == "BUY" || op.Op == "SELL" {
			source = op.From
		}
		if op.Op == "SELL" {
			return nil, &rpcError{Code: -32602, Message: "SELL is disabled in this v0.3 test build because automatic LBTC payout is not enforceable without a reviewed reserve signer or protocol support"}
		}
		feeValue := int64(1_000)
		if len(args) > 1 {
			var err error
			feeValue, err = parseRPCAmount(args[1], false)
			if err != nil {
				return nil, &rpcError{Code: -32602, Message: "bad fee: " + err.Error()}
			}
		}
		scriptHexes, raw, err := tokens.MarkerScriptHexes(op)
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		markerScripts := make([][]byte, 0, len(scriptHexes))
		for _, h := range scriptHexes {
			pk, err := hex.DecodeString(h)
			if err != nil {
				return nil, &rpcError{Code: -32602, Message: "bad marker script: " + err.Error()}
			}
			markerScripts = append(markerScripts, pk)
		}
		txid, err := w.SendTokenMarkers(s.chain, s.pool, source, markerScripts, feeValue)
		if err != nil {
			return nil, &rpcError{Code: -6, Message: rpcSendError(err)}
		}
		s.announceMempoolTx(txid)
		tokenID := op.TokenID
		if op.Op == "DEPLOY_SIMPLE" || op.Op == "DEPLOY_CURVE" {
			tokenID = txid
		}
		return map[string]any{
			"txid":                txid,
			"status":              "submitted",
			"op":                  op.Op,
			"token_id":            tokenID,
			"source_address":      source,
			"fee":                 feeValue,
			"fee_lbtc":            amount.FormatWithTicker(feeValue),
			"marker_output_count": len(markerScripts),
			"marker_output_value": mempool.DustThreshold,
			"marker_scripts_hex":  scriptHexes,
			"metadata_json":       string(raw),
			"server_custody":      false,
			"server_private_keys": false,
			"wallet_signed_local": true,
			"indexing_note":       "Token appears after the launchpad indexer sees this transaction in mempool or a block.",
		}, nil
	case "tobaseunits", "legacytoamount":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: method + " expects one LBTC amount"}
		}
		v, err := parseRPCAmount(args[0], false)
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		return map[string]any{"amount": amount.FormatWithTicker(v), "base_units": v}, nil
	case "frombaseunits", "amounttolegacy":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: method + " expects one base-unit integer"}
		}
		v, err := parseRPCAmount(args[0], true)
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		return map[string]any{"amount": amount.FormatWithTicker(v), "base_units": v}, nil
	case "encryptwallet":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "encryptwallet expects passphrase"}
		}
		if err := w.Encrypt(args[0]); err != nil {
			return nil, &rpcError{Code: -15, Message: err.Error()}
		}
		return "wallet encrypted and locked", nil
	case "walletpassphrase":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
			return nil, &rpcError{Code: -32602, Message: "walletpassphrase expects passphrase and timeout seconds"}
		}
		pass, err := parsePassphraseArg(args[0])
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad passphrase"}
		}
		var seconds int64
		if err := json.Unmarshal(args[1], &seconds); err != nil || seconds < 0 {
			return nil, &rpcError{Code: -32602, Message: "bad timeout"}
		}
		if err := w.Unlock(pass, time.Duration(seconds)*time.Second); err != nil {
			return nil, &rpcError{Code: -14, Message: err.Error()}
		}
		return "wallet unlocked", nil
	case "walletpassphrasechange":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 2 {
			return nil, &rpcError{Code: -32602, Message: "walletpassphrasechange expects oldpassphrase and newpassphrase"}
		}
		oldPass, err := parsePassphraseArg(args[0])
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad old passphrase"}
		}
		newPass, err := parsePassphraseArg(args[1])
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad new passphrase"}
		}
		if err := w.ChangePassphrase(oldPass, newPass); err != nil {
			switch {
			case strings.Contains(err.Error(), "not encrypted"):
				return nil, &rpcError{Code: -15, Message: err.Error()}
			default:
				return nil, &rpcError{Code: -14, Message: err.Error()}
			}
		}
		return "wallet passphrase updated", nil
	case "walletlock":
		if err := w.Lock(); err != nil {
			return nil, &rpcError{Code: -13, Message: err.Error()}
		}
		return "wallet locked", nil
	case "getwalletinfo":
		return w.SecurityInfo(), nil
	case "createwallet":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "createwallet requires one wallet name"}
		}
		name := strings.TrimSpace(args[0])
		if !config.IsWalletName(name) {
			return nil, &rpcError{Code: -32602, Message: "invalid wallet name: must be alphanumeric"}
		}
		nw, err := s.createWallet(name)
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{"name": name, "wallet": nw.SecurityInfo()}, nil
	case "loadwallet":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "loadwallet requires one wallet name"}
		}
		name := strings.TrimSpace(args[0])
		if err := s.loadWallet(name); err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{"name": name, "loaded": true}, nil
	case "unloadwallet":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "unloadwallet requires one wallet name"}
		}
		name := strings.TrimSpace(args[0])
		if err := s.unloadWallet(name); err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{"name": name, "unloaded": true}, nil
	case "listwallets":
		return s.listWallets(), nil
	case "getbalance":
		var args []json.RawMessage
		_ = json.Unmarshal(params, &args)
		minConf := int32(1)
		if len(args) == 1 {
			var n int32
			if err := json.Unmarshal(args[0], &n); err == nil {
				minConf = n
			}
		}
		if len(args) >= 2 {
			var n int32
			if err := json.Unmarshal(args[1], &n); err == nil {
				minConf = n
			}
		}
		var utxos []wallet.UTXOView
		var err error
		if minConf <= 0 {
			utxos, err = w.ListUnspentForSpend(s.chain, s.pool)
		} else {
			utxos, err = w.ListUnspent(s.chain)
		}
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		total := int64(0)
		for _, u := range utxos {
			if u.Locked {
				continue
			}
			if minConf > 0 && u.Confirmations < minConf {
				continue
			}
			total += u.Value
		}
		return amountFloat(total), nil
	case "listtransactions":
		var args []json.RawMessage
		_ = json.Unmarshal(params, &args)
		count := 10
		skip := 0
		if len(args) > 1 {
			_ = json.Unmarshal(args[1], &count)
		}
		if len(args) > 2 {
			_ = json.Unmarshal(args[2], &skip)
		}
		if count <= 0 {
			count = 10
		}
		if count > 1000 {
			count = 1000
		}
		if skip < 0 {
			skip = 0
		}
		rows, err := s.walletTransactionRows(count)
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		if skip >= len(rows) {
			return []map[string]any{}, nil
		}
		end := skip + count
		if end > len(rows) {
			end = len(rows)
		}
		return rows[skip:end], nil
	case "listsinceblock":
		var args []json.RawMessage
		_ = json.Unmarshal(params, &args)
		startHeight := int32(-1)
		if len(args) > 0 {
			var blockHash string
			if err := json.Unmarshal(args[0], &blockHash); err == nil && strings.TrimSpace(blockHash) != "" {
				_, idx, err := s.chain.BlockByHash(strings.TrimSpace(blockHash))
				if err != nil {
					return nil, &rpcError{Code: -5, Message: "block not found"}
				}
				startHeight = idx.Height
			}
		}
		rows, err := s.walletTransactionRows(1000)
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		filtered := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			h, _ := row["blockheight"].(int32)
			if h > startHeight {
				filtered = append(filtered, row)
			}
		}
		lastBlock := ""
		if tip := s.chain.Tip(); tip != nil {
			lastBlock = tip.Hash
		}
		return map[string]any{"transactions": filtered, "lastblock": lastBlock}, nil
	case "getreceivedbyaddress":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
			return nil, &rpcError{Code: -32602, Message: "getreceivedbyaddress expects address and optional minconf"}
		}
		var addr string
		if err := json.Unmarshal(args[0], &addr); err != nil || strings.TrimSpace(addr) == "" {
			return nil, &rpcError{Code: -32602, Message: "bad address"}
		}
		addr = strings.TrimSpace(addr)
		minConf := int32(1)
		if len(args) > 1 {
			var parsed int32
			if err := json.Unmarshal(args[1], &parsed); err == nil {
				minConf = parsed
			}
		}
		var utxos []wallet.UTXOView
		var err error
		if minConf <= 0 {
			utxos, err = w.ListUnspentForSpend(s.chain, s.pool)
		} else {
			utxos, err = w.ListUnspent(s.chain)
		}
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		total := int64(0)
		for _, u := range utxos {
			if u.Address != addr {
				continue
			}
			if minConf > 0 && u.Confirmations < minConf {
				continue
			}
			total += u.Value
		}
		return amountFloat(total), nil
	case "getrawchangeaddress":
		addr, err := w.NewAddress()
		if err != nil {
			return nil, &rpcError{Code: -13, Message: err.Error()}
		}
		return addr, nil
	case "settxfee":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
			return nil, &rpcError{Code: -32602, Message: "settxfee expects fee_lbtc"}
		}
		feeValue, err := parseRPCAmount(args[0], false)
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		if feeValue < 0 {
			return nil, &rpcError{Code: -32602, Message: "fee must be >= 0"}
		}
		// Avoid accidental huge fees in wallet mode.
		if feeValue > 10*chaincfg.Coin {
			return nil, &rpcError{Code: -32602, Message: "fee too large"}
		}
		s.minerMu.Lock()
		s.defaultTxFee = feeValue
		s.minerMu.Unlock()
		return true, nil
	case "signrawtransactionwithwallet":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
			return nil, &rpcError{Code: -32602, Message: "signrawtransactionwithwallet expects raw transaction hex"}
		}
		raw, err := hex.DecodeString(strings.TrimSpace(args[0]))
		if err != nil {
			return nil, &rpcError{Code: -22, Message: err.Error()}
		}
		tx, err := wire.ReadTx(bytes.NewReader(raw))
		if err != nil {
			return nil, &rpcError{Code: -22, Message: err.Error()}
		}
		signed, complete, signErrs, err := w.SignRawTransaction(s.chain, tx)
		if err != nil {
			code := -13
			if strings.Contains(strings.ToLower(err.Error()), "locked") {
				code = -13
			}
			return nil, &rpcError{Code: code, Message: err.Error()}
		}
		outRaw, err := signed.Bytes()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		out := map[string]any{
			"hex":      hex.EncodeToString(outRaw),
			"complete": complete,
		}
		if len(signErrs) > 0 {
			out["errors"] = signErrs
		}
		return out, nil
	case "validateaddress":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "validateaddress expects address"}
		}
		addr := strings.TrimSpace(args[0])
		isValid := false
		isHybrid := false
		pubHashHex := ""
		if version, payload, err := address.DecodeBase58Check(addr); err == nil && version == chaincfg.PublicKeyHashVersion && len(payload) == 20 {
			isValid = true
			pubHashHex = hex.EncodeToString(payload)
		} else if payload, err := address.DecodeHybridAddress(addr); err == nil && len(payload) == 20 {
			isValid = true
			isHybrid = true
			pubHashHex = hex.EncodeToString(payload)
		}
		ismine := false
		for _, owned := range w.ListAddresses() {
			if owned == addr {
				ismine = true
				break
			}
		}
		return map[string]any{
			"isvalid":         isValid,
			"address":         addr,
			"ismine":          ismine,
			"iswatchonly":     false,
			"isscript":        false,
			"is_hybrid":       isHybrid,
			"pubkey_hash_hex": pubHashHex,
		}, nil
	case "verifymessage":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 3 {
			return nil, &rpcError{Code: -32602, Message: "verifymessage expects address, signature, message"}
		}
		addr := strings.TrimSpace(args[0])
		sigBase64 := strings.TrimSpace(args[1])
		msg := args[2]

		sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
		if err != nil || len(sigBytes) != 65 {
			return false, nil
		}
		hash := chainhash.DoubleHashB([]byte(fmt.Sprintf("\x18Legacy Coin Signed Message:\n%d%s", len(msg), msg)))
		recoveredPub, wasCompressed, err := btcecdsa.RecoverCompact(sigBytes, hash[:])
		if err != nil {
			return false, nil
		}
		var pubKeyBytes []byte
		if wasCompressed {
			pubKeyBytes = recoveredPub.SerializeCompressed()
		} else {
			pubKeyBytes = recoveredPub.SerializeUncompressed()
		}
		sha := sha256.Sum256(pubKeyBytes)
		ripemd := ripemd160.New()
		ripemd.Write(sha[:])
		pubHash := ripemd.Sum(nil)
		expected := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, pubHash)
		return expected == addr, nil
	case "getaddressinfo":
		var args []string
		if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
			return nil, &rpcError{Code: -32602, Message: "getaddressinfo expects address"}
		}
		addr := strings.TrimSpace(args[0])
		info, err := s.call(ctx, "validateaddress", json.RawMessage(fmt.Sprintf("[\"%s\"]", addr)))
		if err != nil {
			return nil, err
		}
		row, _ := info.(map[string]any)
		if row == nil {
			row = map[string]any{}
		}
		row["ismine"] = row["ismine"] == true
		row["iswatchonly"] = false
		row["isscript"] = false
		row["ischange"] = false
		row["iswitness"] = false
		return row, nil
	case "sethdseed":
		var args []string
		_ = json.Unmarshal(params, &args)
		seed := ""
		if len(args) > 0 {
			seed = args[0]
		}
		seedHex, err := w.SetHDSeed(seed)
		if err != nil {
			return nil, &rpcError{Code: -8, Message: err.Error()}
		}
		mnem := w.Mnemonic()
		res := map[string]any{"seed": seedHex}
		if mnem != "" {
			res["mnemonic"] = mnem
		}
		return res, nil
	case "exportmnemonic":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) == 0 {
			return nil, &rpcError{Code: -32602, Message: "passphrase required (pass as 1st param, or \"-\" for stdin)"}
		}
		pass, err := parsePassphraseArg(args[0])
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad passphrase"}
		}
		if err := w.VerifyPassphrase(pass); err != nil {
			return nil, &rpcError{Code: -14, Message: "invalid passphrase"}
		}
		mnem := w.Mnemonic()
		if mnem == "" {
			return nil, &rpcError{Code: -8, Message: "wallet has no mnemonic seed"}
		}
		return map[string]any{"mnemonic": mnem}, nil
	case "generate":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &rpcError{Code: -32602, Message: "bad generate parameters"}
		}

		// V5.12 UX: `generate 1` means mine one block using the configured
		// mining_pubkey_hash. The legacy/raw developer form remains:
		// `generate <pubkey_hash_hex> [threads] [force]`.
		blocksToMine := 1
		threads := 1
		force := false
		pubHashHex := ""
		rawDeveloperHash := false

		cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
		if cfg.Threads > 0 {
			threads = cfg.Threads
		}
		if cfg.PubKeyHash != "" {
			pubHashHex = cfg.PubKeyHash
		}

		if len(args) > 0 {
			var rawPubHash string
			if err := json.Unmarshal(args[0], &rawPubHash); err == nil {
				// Raw/developer mode: first argument is the 20-byte pubkey hash hex.
				pubHashHex = rawPubHash
				rawDeveloperHash = true
				if len(args) > 1 {
					if err := json.Unmarshal(args[1], &threads); err != nil || threads <= 0 {
						return nil, &rpcError{Code: -32602, Message: "invalid thread count"}
					}
				}
				if len(args) > 2 {
					if err := json.Unmarshal(args[2], &force); err != nil {
						return nil, &rpcError{Code: -32602, Message: "invalid force flag"}
					}
				}
			} else {
				// User mode: first argument is a block count.
				if err := json.Unmarshal(args[0], &blocksToMine); err != nil || blocksToMine <= 0 {
					return nil, &rpcError{Code: -32602, Message: "generate expects block count or pubkey hash hex"}
				}
				if len(args) > 1 {
					if err := json.Unmarshal(args[1], &threads); err != nil || threads <= 0 {
						return nil, &rpcError{Code: -32602, Message: "invalid thread count"}
					}
				}
				if len(args) > 2 {
					if err := json.Unmarshal(args[2], &force); err != nil {
						return nil, &rpcError{Code: -32602, Message: "invalid force flag"}
					}
				}
			}
		}

		if !rawDeveloperHash {
			dest, err := s.resolveMiningDestination(w, cfg, true)
			if err != nil {
				return nil, &rpcError{Code: -32602, Message: err.Error()}
			}
			pubHashHex = dest.PubKeyHashHex
		}
		if pubHashHex == "" {
			return nil, &rpcError{Code: -32602, Message: "generate needs mining_pubkey_hash in config, or use generate <pubkey_hash_hex> [threads]"}
		}
		if err := validateMiningPubKeyHash(pubHashHex); err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		if rawDeveloperHash && walletClassicAddressForHash(w, pubHashHex) == "" && !cfg.ExternalPayout {
			return nil, &rpcError{Code: -32602, Message: unownedMiningDestinationMessage}
		}
		pubHash, err := hex.DecodeString(pubHashHex)
		if err != nil || len(pubHash) != 20 {
			return nil, &rpcError{Code: -32602, Message: "invalid pubkey hash"}
		}
		if health := s.chain.StorageHealth(); !health.OK {
			return nil, &rpcError{Code: -32603, Message: "mining refused: storage health failed: " + health.Error}
		}
		if s.p2p != nil && s.p2p.PeerCount() == 0 && !force {
			tip := s.chain.Tip()
			if tip != nil && tip.Height > 0 {
				return nil, &rpcError{Code: -32603, Message: "mining refused: node has no peers; reconnect peers or pass force=true as third generate parameter"}
			}
		}

		hashes := make([]string, 0, blocksToMine)
		results := make([]map[string]any, 0, blocksToMine)
		totalStaleRetries := 0
		for blockNum := 0; blockNum < blocksToMine; blockNum++ {
			mempoolBefore := 0
			if s.pool != nil {
				mempoolBefore = s.pool.Count()
			}
			var result mining.Result
			var staleRetries int
			for attempt := 0; attempt < 5; attempt++ {
				result, err = mining.MineBlock(ctx, s.chain, s.pool, pow.YespowerHasher{Personalization: s.chain.Params().YespowerPers}, pubHash, threads, nil)
				if err == nil {
					break
				}
				if errors.Is(err, blockchain.ErrBadPrevBlock) {
					staleRetries++
					if attempt < 4 {
						continue
					}
				}
				return nil, &rpcError{Code: -32603, Message: err.Error()}
			}
			totalStaleRetries += staleRetries
			if s.p2p != nil {
				s.p2p.AnnounceBlock(result.Hash)
			}
			txCount := len(result.Block.Transactions)
			mempoolTxIncluded := 0
			if txCount > 0 {
				mempoolTxIncluded = txCount - 1
			}
			hashes = append(hashes, result.Hash.String())
			results = append(results, map[string]any{
				"height":              result.Height,
				"hash":                result.Hash.String(),
				"nonce":               result.Block.Header.Nonce,
				"tx_count":            txCount,
				"mempool_before":      mempoolBefore,
				"mempool_tx_included": mempoolTxIncluded,
				"stale_retries":       staleRetries,
			})
		}
		if blocksToMine == 1 && len(results) == 1 {
			results[0]["hashes"] = hashes
			results[0]["blocks_mined"] = 1
			results[0]["total_stale_retries"] = totalStaleRetries
			return results[0], nil
		}
		return map[string]any{
			"blocks_mined":        blocksToMine,
			"hashes":              hashes,
			"results":             results,
			"total_stale_retries": totalStaleRetries,
		}, nil
	case "getnetworkinfo":
		rpcBind := s.rpcBindHost()
		p2pBind := s.p2p.ListenHost()
		storage := s.chain.StorageHealth()
		s.minerMu.Lock()
		activeMining := s.minerActive
		s.minerMu.Unlock()
		return map[string]any{
			"version":               version.CoreFull(),
			"core_version":          version.CoreVersion,
			"wallet_version":        version.WalletVersion,
			"network":               "mainnet",
			"chain_id":              s.chain.Params().ChainID,
			"genesis_hash":          s.chain.Params().GenesisHash,
			"protocol":              70015,
			"connections":           s.p2p.PeerCount(),
			"outbound":              s.p2p.OutboundCount(),
			"node_role":             s.nodeRole(),
			"seed_node":             s.policy.SeedNode,
			"known_peers":           s.p2p.KnownAddressCount(),
			"known_peer_count":      s.p2p.KnownAddressCount(),
			"known_peers_available": true,
			"mining_safe":           s.p2p.PeerCount() > 0 && storage.OK,
			"active_mining":         activeMining,
			"storage_ok":            storage.OK,
			"port":                  s.chain.Params().DefaultPort,
			"localaddr":             s.p2p.ListenAddr(),
			"dns_seeds":             len(s.chain.Params().DNSSeeds),
			"fixed_seeds":           len(s.chain.Params().FixedSeeds),
			"addnodes":              len(s.p2p.BootstrapPeers()),
			"known_peer_samples":    firstStrings(s.p2p.KnownAddresses(), 20),
			"rpcbind":               rpcBind,
			"rpcauth":               s.auth.Enabled,
			"rpctls":                s.bind.TLS,
			"p2pbind":               p2pBind,
		}, nil
	case "getdifficulty":
		bits, err := s.chain.NextRequiredBits()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{
			"algorithm": "DGWv3",
			"bits":      strconv.FormatUint(uint64(bits), 16),
		}, nil
	case "getblocklocator":
		locator := s.chain.Locator()
		out := make([]string, len(locator))
		for i, hash := range locator {
			out[i] = hash.String()
		}
		return out, nil
	case "gettxout":
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
			return nil, &rpcError{Code: -32602, Message: "gettxout expects txid and vout"}
		}
		var txid string
		var vout uint32
		if err := json.Unmarshal(args[0], &txid); err != nil {
			return nil, &rpcError{Code: -32602, Message: "invalid txid"}
		}
		if err := json.Unmarshal(args[1], &vout); err != nil {
			return nil, &rpcError{Code: -32602, Message: "invalid vout"}
		}
		entry, err := s.chain.UTXO(txid, vout)
		if err != nil {
			return nil, blockLookupError(err)
		}
		return entry, nil
	case "gettxoutsetinfo":
		stats, err := s.chain.UTXOStats()
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return stats, nil
	case "help":
		return s.help(params)
	case "uptime":
		if s.startedAt.IsZero() {
			return int64(0), nil
		}
		return int64(time.Since(s.startedAt).Seconds()), nil
	case "stop":
		go s.stop()
		return "Legacy Coin server stopping", nil
	case "estimatefee", "estimatesmartfee":
		var args []json.RawMessage
		_ = json.Unmarshal(params, &args)
		nblocks := int64(6)
		if len(args) > 0 {
			var n int64
			if err := json.Unmarshal(args[0], &n); err == nil && n > 0 {
				nblocks = n
			}
		}
		entries := s.pool.Entries()
		var feeEstimate int64
		if len(entries) == 0 {
			feeEstimate = mempool.MinRelayFeePerKB
		} else {
			rates := make([]float64, 0, len(entries))
			for _, e := range entries {
				if e.Size > 0 {
					rates = append(rates, float64(e.Fee*1000)/float64(e.Size))
				}
			}
			if len(rates) == 0 {
				feeEstimate = mempool.MinRelayFeePerKB
			} else {
				sort.Slice(rates, func(i, j int) bool { return rates[i] < rates[j] })
				var pct float64
				switch {
				case nblocks <= 2:
					pct = 0.75
				case nblocks <= 5:
					pct = 0.50
				default:
					pct = 0.25
				}
				idx := int(float64(len(rates)-1) * pct)
				feeEstimate = int64(rates[idx])
			}
		}
		if feeEstimate < mempool.MinRelayFeePerKB {
			feeEstimate = mempool.MinRelayFeePerKB
		}
		return map[string]any{
			"feerate": float64(feeEstimate) / float64(chaincfg.Coin),
			"blocks":  nblocks,
			"errors":  []string{},
		}, nil
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found"}
	}
}

func (s *Server) help(params json.RawMessage) (any, *rpcError) {
	var args []json.RawMessage
	if len(strings.TrimSpace(string(params))) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &rpcError{Code: -32602, Message: "help expects zero args or help <method>"}
		}
	}
	if len(args) == 0 {
		methods := make([]string, 0, len(rpcHelpEntries))
		for _, entry := range rpcHelpEntries {
			methods = append(methods, entry.Method)
		}
		sort.Strings(methods)
		return map[string]any{
			"count":   len(methods),
			"methods": methods,
			"note":    "use help <method> for detailed usage",
		}, nil
	}

	var topic string
	if err := json.Unmarshal(args[0], &topic); err != nil {
		return nil, &rpcError{Code: -32602, Message: "help expects a method name string"}
	}
	topic = strings.ToLower(strings.TrimSpace(topic))
	if topic == "" {
		return nil, &rpcError{Code: -32602, Message: "help method name cannot be empty"}
	}
	for _, entry := range rpcHelpEntries {
		if entry.Method == topic {
			return entry, nil
		}
	}

	matches := make([]rpcHelpEntry, 0, 8)
	for _, entry := range rpcHelpEntries {
		if strings.Contains(entry.Method, topic) {
			matches = append(matches, entry)
		}
	}
	if len(matches) > 0 {
		return map[string]any{
			"query":   topic,
			"matches": matches,
		}, nil
	}

	return nil, &rpcError{Code: -32601, Message: "method not found"}
}

func (s *Server) getBlockchainInfo() map[string]any {
	p := s.chain.Params()
	tip := s.chain.Tip()
	storage := s.chain.StorageHealth()
	timing := s.chainTiming(100)

	height := int32(-1)
	best := ""
	bits := ""
	if tip != nil {
		height = tip.Height
		best = tip.Hash
		bits = fmt.Sprintf("%08x", tip.Bits)
	}

	return map[string]any{
		"chain":                      p.Name,
		"coin":                       p.CoinName,
		"ticker":                     p.Ticker,
		"blocks":                     height,
		"headers":                    height,
		"bestblockhash":              best,
		"chainwork":                  s.chain.TipChainwork(),
		"fork_choice":                "most-cumulative-work",
		"current_bits":               bits,
		"difficulty_bits":            bits,
		"difficulty_trend":           timing["difficulty_trend"],
		"target_spacing_seconds":     timing["target_spacing_seconds"],
		"average_block_time_seconds": timing["average_block_time_seconds"],
		"networkhashps":              s.estimateNetworkHashPS(100),
		"known_peers_available":      true,
		"known_peer_count":           s.p2p.KnownAddressCount(),
		"known_peer_samples":         firstStrings(s.p2p.KnownAddresses(), 20),
		"peer_count":                 s.p2p.PeerCount(),
		"outbound_peer_count":        s.p2p.OutboundCount(),
		"inbound_peer_count":         s.p2p.PeerCount() - s.p2p.OutboundCount(),
		"connections":                s.p2p.PeerCount(),
		"initialblockdownload":       false,
		"verificationprogress":       1.0,
		"genesis_hash":               p.GenesisHash,
		"genesis_time":               p.GenesisTime,
		"storage":                    storage,
		"txindex": map[string]any{
			"enabled": s.chain.TxIndexEnabled(),
			"mode": func() string {
				if s.chain.TxIndexEnabled() {
					return "on-disk-txindex"
				}
				return "legacy-chain-scan"
			}(),
			"note": func() string {
				if s.chain.TxIndexEnabled() {
					return "getrawtransaction uses txindex for confirmed lookup and mempool fallback"
				}
				return "txindex disabled; getrawtransaction scans active chain and mempool"
			}(),
		},
		"addressindex": map[string]any{
			"enabled": s.chain.AddressIndexEnabled(),
			"mode": func() string {
				if s.chain.AddressIndexEnabled() {
					return "utxo-plus-history-foundation"
				}
				return "disabled"
			}(),
			"note": func() string {
				if s.chain.AddressIndexEnabled() {
					return "address RPCs are enabled (getaddresstxids/getaddressutxos/getaddressbalance/getaddresshistory)"
				}
				return "addressindex disabled; no fake address search is exposed"
			}(),
		},
		"reindex": map[string]any{
			"supported": true,
			"rpc":       "reindex",
			"check":     "checkstorage true",
		},
		"warnings": []string{},
	}
}

func blockLookupError(err error) *rpcError {
	if errors.Is(err, os.ErrNotExist) {
		return &rpcError{Code: -5, Message: "block not found"}
	}
	return &rpcError{Code: -5, Message: err.Error()}
}

func submitBlockRejectCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, blockchain.ErrBadPrevBlock):
		return "bad-prevblk"
	case errors.Is(err, blockchain.ErrBadMerkleRoot):
		return "bad-txnmrklroot"
	case errors.Is(err, blockchain.ErrBadBits):
		return "bad-diffbits"
	case errors.Is(err, blockchain.ErrTimeTooOld):
		return "time-too-old"
	case errors.Is(err, blockchain.ErrTimeTooNew):
		return "time-too-new"
	case errors.Is(err, blockchain.ErrNoTransactions):
		return "bad-blk-length"
	case errors.Is(err, blockchain.ErrBadBlockSize):
		return "bad-blk-length"
	case errors.Is(err, blockchain.ErrBadCoinbase):
		return "bad-cb"
	case errors.Is(err, blockchain.ErrBadCoinbaseValue):
		return "bad-cb-amount"
	case errors.Is(err, blockchain.ErrMissingTxOut):
		return "bad-txns-inputs-missingorspent"
	case errors.Is(err, blockchain.ErrDuplicateSpend):
		return "bad-txns-inputs-duplicate"
	case errors.Is(err, blockchain.ErrBadTxValue):
		return "bad-txns-vout"
	case errors.Is(err, blockchain.ErrImmatureCoinbase):
		return "bad-txns-premature-spend-of-coinbase"
	case errors.Is(err, blockchain.ErrNonFinalTx):
		return "bad-txns-nonfinal"
	case errors.Is(err, blockchain.ErrDuplicateTxID):
		return "bad-txns-duplicate"
	case errors.Is(err, blockchain.ErrTooManySigOps):
		return "bad-blk-sigops"
	case errors.Is(err, consensus.ErrHighHash):
		return "high-hash"
	case errors.Is(err, consensus.ErrTargetTooHigh):
		return "bad-target"
	default:
		return "rejected"
	}
}

func submitBlockRejectCategory(code string, err error, result blockchain.BlockProcessResult) string {
	switch {
	case code == "":
		return ""
	case code == "duplicate":
		return "duplicate"
	case code == "bad-prevblk" && result.Orphan:
		return "orphan"
	case code == "bad-prevblk":
		return "bad-prevblk"
	case code == "inconclusive":
		return "side-chain"
	case code == "bad-txnmrklroot":
		return "bad-merkle-root"
	case code == "bad-cb-length" || errors.Is(err, blockchain.ErrBadCoinbase) || errors.Is(err, blockchain.ErrBadCoinbaseValue):
		return "bad-coinbase"
	case code == "bad-diffbits":
		return "bad-bits"
	case code == "high-hash":
		return "high-hash"
	case code == "time-too-old" || code == "time-too-new":
		return "bad-timestamp"
	case strings.HasPrefix(code, "bad-tx") || errors.Is(err, blockchain.ErrBadTxValue) || errors.Is(err, blockchain.ErrMissingTxOut) || errors.Is(err, blockchain.ErrDuplicateSpend):
		return "invalid-transaction"
	default:
		return code
	}
}

func (s *Server) submitBlockDiagnostic(params json.RawMessage, process bool) (any, *rpcError) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 {
		return nil, &rpcError{Code: -32602, Message: "block diagnostic expects block hex"}
	}
	raw, err := hex.DecodeString(args[0])
	if err != nil {
		return blockDecodeDiagnostic("bad-hex", err), nil
	}
	block, err := wire.ReadBlock(bytes.NewReader(raw))
	if err != nil {
		return blockDecodeDiagnostic("bad-serialization", err), nil
	}
	diagnostic := s.blockDiagnosticBase(block, process)
	if !process {
		result, err := s.chain.ValidateBlockProposal(block)
		diagnostic["processblock_result"] = result
		code, reason := blockResultRejectCode(result, err)
		diagnostic["accepted"] = code == ""
		diagnostic["would_accept"] = code == ""
		diagnostic["reject_code"] = code
		diagnostic["reject_category"] = submitBlockRejectCategory(code, err, result)
		diagnostic["reject_reason"] = reason
		return diagnostic, nil
	}
	result, err := s.chain.ProcessBlockWithResult(block)
	diagnostic["processblock_result"] = result
	code, reason := blockResultRejectCode(result, err)
	accepted := err == nil && result.Status == blockchain.BlockStatusConnected && result.Connected && result.BestChanged
	diagnostic["accepted"] = accepted
	diagnostic["reject_code"] = code
	diagnostic["reject_category"] = submitBlockRejectCategory(code, err, result)
	diagnostic["reject_reason"] = reason
	if accepted && s.p2p != nil {
		if hash, hashErr := s.chain.BlockHash(block); hashErr == nil {
			s.p2p.AnnounceBlock(hash)
		}
	}
	if tip := s.chain.Tip(); tip != nil {
		diagnostic["daemon_after_height"] = tip.Height
		diagnostic["daemon_after_best_hash"] = tip.Hash
	}
	return diagnostic, nil
}

func blockResultRejectCode(result blockchain.BlockProcessResult, err error) (string, string) {
	if err != nil {
		return submitBlockRejectCode(err), err.Error()
	}
	switch result.Status {
	case blockchain.BlockStatusDuplicate:
		return "duplicate", result.Reason
	case blockchain.BlockStatusOrphan:
		return "bad-prevblk", result.Reason
	case blockchain.BlockStatusSideChain:
		return "inconclusive", result.Reason
	case blockchain.BlockStatusConnected, blockchain.BlockStatusProposal:
		return "", result.Reason
	case blockchain.BlockStatusRejected:
		if result.Reason != "" {
			return "rejected", result.Reason
		}
		return "rejected", "block rejected"
	default:
		if !result.Connected || !result.BestChanged {
			if result.Reason != "" {
				return "rejected", result.Reason
			}
			return "rejected", "block rejected"
		}
		return "", result.Reason
	}
}

func blockDecodeDiagnostic(code string, err error) map[string]any {
	return map[string]any{
		"accepted":        false,
		"would_accept":    false,
		"reject_code":     code,
		"reject_category": "wrong-serialization",
		"reject_reason":   err.Error(),
	}
}

func (s *Server) blockDiagnosticBase(block *wire.MsgBlock, process bool) map[string]any {
	hash := ""
	hashErr := ""
	if h, err := s.chain.BlockHash(block); err == nil {
		hash = h.String()
	} else {
		hashErr = err.Error()
	}
	prevHash := block.Header.PrevBlock.String()
	tipHeight := int32(-1)
	tipHash := ""
	if tip := s.chain.Tip(); tip != nil {
		tipHeight = tip.Height
		tipHash = tip.Hash
	}
	knownHeight := int32(-1)
	if prevHash == tipHash && tipHeight >= 0 {
		knownHeight = tipHeight + 1
	} else if _, idx, err := s.chain.BlockByHash(prevHash); err == nil && idx != nil {
		knownHeight = idx.Height + 1
	}
	out := map[string]any{
		"processed":                     process,
		"submitted_block_hash":          hash,
		"submitted_block_hash_error":    hashErr,
		"submitted_prevhash":            prevHash,
		"submitted_height":              knownHeight,
		"submitted_tx_count":            len(block.Transactions),
		"submitted_bits":                fmt.Sprintf("%08x", block.Header.Bits),
		"submitted_time":                block.Header.Timestamp,
		"daemon_current_height":         tipHeight,
		"daemon_current_best_hash":      tipHash,
		"submitted_prevhash_equals_tip": prevHash == tipHash && tipHash != "",
		"submitted_prevhash_known":      prevHash == tipHash && tipHash != "",
		"processblock_result":           nil,
	}
	if _, idx, err := s.chain.BlockByHash(prevHash); err == nil && idx != nil {
		out["submitted_prevhash_known"] = true
		out["submitted_prevhash_height"] = idx.Height
	}
	root, err := block.BuildMerkleRoot()
	if err == nil {
		out["calculated_merkleroot"] = root.String()
		out["submitted_merkleroot_matches"] = root == block.Header.MerkleRoot
	}
	return out
}

func (s *Server) validateBlockProposalCode(block *wire.MsgBlock) (string, string) {
	result, err := s.chain.ValidateBlockProposal(block)
	return blockResultRejectCode(result, err)
}

type txLookupResult struct {
	Tx            *wire.MsgTx
	TxID          string
	BlockHash     string
	BlockHeight   int32
	BlockTime     uint32
	Confirmations int32
	InMempool     bool
}

func (s *Server) lookupTransaction(txid string) (*txLookupResult, error) {
	txid = strings.ToLower(strings.TrimSpace(txid))
	if txid == "" {
		return nil, fmt.Errorf("missing txid")
	}
	if s.pool != nil {
		if tx, ok := s.pool.Lookup(txid); ok {
			return &txLookupResult{
				Tx:            tx,
				TxID:          txid,
				BlockHeight:   -1,
				Confirmations: 0,
				InMempool:     true,
			}, nil
		}
	}
	if s.chain.TxIndexEnabled() {
		tx, idx, _, err := s.chain.LookupTransactionByIndex(txid)
		if err == nil && tx != nil && idx != nil {
			tip := s.chain.Tip()
			return &txLookupResult{
				Tx:            tx,
				TxID:          txid,
				BlockHash:     idx.Hash,
				BlockHeight:   idx.Height,
				BlockTime:     idx.Time,
				Confirmations: confirmations(tip, idx),
				InMempool:     false,
			}, nil
		}
	}
	tip := s.chain.Tip()
	if tip == nil {
		return nil, os.ErrNotExist
	}
	for h := tip.Height; h >= 0; h-- {
		idx, err := s.chain.IndexByHeight(h)
		if err != nil {
			continue
		}
		block, _, err := s.chain.BlockByHash(idx.Hash)
		if err != nil {
			continue
		}
		for _, tx := range block.Transactions {
			hash, err := tx.TxHash()
			if err != nil {
				continue
			}
			if hash.String() == txid {
				return &txLookupResult{
					Tx:            tx,
					TxID:          txid,
					BlockHash:     idx.Hash,
					BlockHeight:   idx.Height,
					BlockTime:     idx.Time,
					Confirmations: confirmations(tip, idx),
					InMempool:     false,
				}, nil
			}
		}
	}
	return nil, os.ErrNotExist
}

func txVerboseResult(lookup *txLookupResult) map[string]any {
	if lookup == nil || lookup.Tx == nil {
		return map[string]any{}
	}
	raw, _ := lookup.Tx.Bytes()
	return map[string]any{
		"txid":          lookup.TxID,
		"hash":          lookup.TxID,
		"size":          len(raw),
		"version":       lookup.Tx.Version,
		"locktime":      lookup.Tx.LockTime,
		"vin":           txVinRows(lookup.Tx),
		"vout":          txVoutRows(lookup.Tx),
		"confirmations": lookup.Confirmations,
		"blockhash":     lookup.BlockHash,
		"blockheight":   lookup.BlockHeight,
		"time":          lookup.BlockTime,
		"blocktime":     lookup.BlockTime,
		"in_mempool":    lookup.InMempool,
	}
}

func txVinRows(tx *wire.MsgTx) []map[string]any {
	if tx == nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(tx.TxIn))
	for _, in := range tx.TxIn {
		if in.PreviousOutPoint.Index == ^uint32(0) && in.PreviousOutPoint.Hash == (chainhash.Hash{}) {
			out = append(out, map[string]any{
				"coinbase": hex.EncodeToString(in.SignatureScript),
				"sequence": in.Sequence,
			})
			continue
		}
		out = append(out, map[string]any{
			"txid": in.PreviousOutPoint.Hash.String(),
			"vout": in.PreviousOutPoint.Index,
			"scriptSig": map[string]any{
				"hex": hex.EncodeToString(in.SignatureScript),
			},
			"sequence": in.Sequence,
		})
	}
	return out
}

func txVoutRows(tx *wire.MsgTx) []map[string]any {
	if tx == nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(tx.TxOut))
	for i, vout := range tx.TxOut {
		row := map[string]any{
			"n":                i,
			"value_base_units": vout.Value,
			"value":            float64(vout.Value) / 1e8,
			"scriptPubKey": map[string]any{
				"hex":  hex.EncodeToString(vout.PkScript),
				"type": scriptType(vout.PkScript),
			},
		}
		if addr := decodeOutputAddress(vout.PkScript); addr != "" {
			row["scriptPubKey"].(map[string]any)["address"] = addr
			row["scriptPubKey"].(map[string]any)["addresses"] = []string{addr}
		}
		out = append(out, row)
	}
	return out
}

func scriptType(pkScript []byte) string {
	switch {
	case script.IsPayToPubKeyHash(pkScript):
		return "pubkeyhash"
	case script.IsPayToHybridPubKeyHash(pkScript):
		return "hybridpubkeyhash"
	default:
		return "nonstandard"
	}
}

func decodeOutputAddress(pkScript []byte) string {
	switch {
	case script.IsPayToPubKeyHash(pkScript) && len(pkScript) >= 23:
		return address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, pkScript[3:23])
	case script.IsPayToHybridPubKeyHash(pkScript) && len(pkScript) >= 23:
		return address.HybridPrefix + address.EncodeBase58Check(address.HybridVersion, pkScript[3:23])
	default:
		return ""
	}
}

func parseBoolish(raw json.RawMessage) (bool, bool) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, true
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n != 0, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(strings.ToLower(s))
		switch s {
		case "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off":
			return false, true
		}
	}
	return false, false
}

func confirmations(tip *blockchain.BlockIndex, idx *blockchain.BlockIndex) int32 {
	if tip == nil || tip.Height < idx.Height || idx.Height < 0 {
		return 0
	}
	return tip.Height - idx.Height + 1
}

func blockTxIDs(block *wire.MsgBlock) []string {
	out := make([]string, 0, len(block.Transactions))
	for _, tx := range block.Transactions {
		h, err := tx.TxHash()
		if err != nil {
			continue
		}
		out = append(out, h.String())
	}
	return out
}

func blockTemplateTransactions(block *wire.MsgBlock, pool *mempool.Pool) []map[string]any {
	entries := []mempool.Entry{}
	if pool != nil {
		entries = pool.Entries()
	}
	return blockTemplateTransactionsFromEntries(block, entries)
}

func blockTemplateTransactionsFromEntries(block *wire.MsgBlock, entries []mempool.Entry) []map[string]any {
	if block == nil || len(block.Transactions) <= 1 {
		return []map[string]any{}
	}
	feesByTxID := map[string]mempool.Entry{}
	for _, entry := range entries {
		feesByTxID[entry.TxID] = entry
	}
	out := make([]map[string]any, 0, len(block.Transactions)-1)
	for _, tx := range block.Transactions[1:] { // exclude coinbase
		raw, err := tx.Bytes()
		if err != nil {
			continue
		}
		h, err := tx.TxHash()
		if err != nil {
			continue
		}
		txid := h.String()
		fee := int64(0)
		size := len(raw)
		if e, ok := feesByTxID[txid]; ok {
			fee = e.Fee
			if e.Size > 0 {
				size = e.Size
			}
		}
		out = append(out, map[string]any{
			"data":    hex.EncodeToString(raw),
			"hash":    txid,
			"txid":    txid,
			"fee":     fee,
			"size":    size,
			"sigops":  0,
			"weight":  size * 4,
			"depends": []int{},
		})
	}
	return out
}

func compactTargetHex(bits uint32) string {
	target := consensus.CompactToBig(bits)
	if target == nil || target.Sign() <= 0 {
		return strings.Repeat("0", 64)
	}
	return fmt.Sprintf("%064x", target)
}

type gbtRequest struct {
	Mode         string
	Capabilities []string
	Rules        []string
	LongPollID   string
	Data         string
	PubKeyHash   string
}

func (s *Server) getBlockTemplate(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	req, pubHash, err := parseGBTRequest(params)
	if err != nil {
		return nil, &rpcError{Code: -32602, Message: err.Error()}
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "template"
	}
	if mode == "proposal" {
		return s.getBlockTemplateProposal(req.Data)
	}
	if mode != "template" {
		return nil, &rpcError{Code: -32602, Message: "getblocktemplate mode must be template or proposal"}
	}
	if req.LongPollID != "" {
		s.waitForTemplateChange(ctx, req.LongPollID, 30*time.Second)
	}
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	safety := s.checkSafeToMine(s.defaultWallet(), cfg, false)
	if !safety.Safe && cfg.RejectUnsafeGBT {
		return nil, &rpcError{Code: -32010, Message: safety.Reason}
	}
	block, height, err := mining.NewBlockTemplate(s.chain, s.pool, pubHash)
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}
	raw, err := block.Bytes()
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}
	previousHash := block.Header.PrevBlock.String()
	transactions := blockTemplateTransactions(block, s.pool)
	coinbaseValue := int64(0)
	if len(block.Transactions) > 0 {
		for _, out := range block.Transactions[0].TxOut {
			coinbaseValue += out.Value
		}
	}
	mempoolCount := 0
	if s.pool != nil {
		mempoolCount = s.pool.Count()
	}
	longPollID := s.currentTemplateLongPollID()
	result := map[string]any{
		"height":            height,
		"version":           block.Header.Version,
		"previoushash":      previousHash,
		"previousblockhash": previousHash,
		"bits":              fmt.Sprintf("%08x", block.Header.Bits),
		"target":            compactTargetHex(block.Header.Bits),
		"merkleroot":        block.Header.MerkleRoot.String(),
		"time":              block.Header.Timestamp,
		"curtime":           block.Header.Timestamp,
		"transactions":      transactions,
		"transaction_count": len(transactions),
		"txids":             blockTxIDs(block),
		"mempoolsize":       mempoolCount,
		"coinbasevalue":     coinbaseValue,
		"mutable":           []string{"time", "transactions", "prevblock"},
		"submitold":         false,
		"noncerange":        "00000000ffffffff",
		"hex":               hex.EncodeToString(raw),
		"longpollid":        longPollID,
		"capabilities":      []string{"proposal", "longpoll", "coinbasetxn"},
		"expires":           15,
		"mintime":           block.Header.Timestamp,
		"maxtime":           block.Header.Timestamp + uint32(chaincfg.MaxFutureDrift.Seconds()),
		"sigoplimit":        80_000,
		"sizelimit":         1_000_000,
		"weightlimit":       4_000_000,
		"coinbaseaux":       map[string]any{"flags": ""},
		"rules":             req.Rules,
		"vbavailable":       map[string]any{},
		"vbrequired":        0,
	}
	for key, value := range safety.Fields() {
		result[key] = value
	}
	if hasCapability(req.Capabilities, "coinbasetxn") || hasCapability(req.Capabilities, "coinbasevalue") {
		result["coinbasetxn"] = buildCoinbaseTxnField(block, height, coinbaseValue)
	}
	return result, nil
}

func parseGBTRequest(params json.RawMessage) (gbtRequest, []byte, error) {
	req := gbtRequest{Mode: "template"}
	pubHash := make([]byte, 20)
	var args []json.RawMessage
	_ = json.Unmarshal(params, &args)
	if len(args) == 0 {
		return req, pubHash, nil
	}
	var reqObj map[string]json.RawMessage
	if err := json.Unmarshal(args[0], &reqObj); err == nil && len(reqObj) > 0 {
		if raw, ok := reqObj["mode"]; ok {
			_ = json.Unmarshal(raw, &req.Mode)
		}
		if raw, ok := reqObj["capabilities"]; ok {
			_ = json.Unmarshal(raw, &req.Capabilities)
		}
		if raw, ok := reqObj["rules"]; ok {
			_ = json.Unmarshal(raw, &req.Rules)
		}
		if raw, ok := reqObj["longpollid"]; ok {
			_ = json.Unmarshal(raw, &req.LongPollID)
		}
		if raw, ok := reqObj["data"]; ok {
			_ = json.Unmarshal(raw, &req.Data)
		}
		if raw, ok := reqObj["pubkeyhash"]; ok {
			_ = json.Unmarshal(raw, &req.PubKeyHash)
		}
	} else {
		var legacyPubHash string
		if err := json.Unmarshal(args[0], &legacyPubHash); err == nil {
			req.PubKeyHash = legacyPubHash
		}
	}
	if strings.TrimSpace(req.PubKeyHash) != "" {
		decoded, err := hex.DecodeString(strings.TrimSpace(req.PubKeyHash))
		if err != nil || len(decoded) != 20 {
			return gbtRequest{}, nil, fmt.Errorf("getblocktemplate expects optional pubkey hash hex")
		}
		pubHash = decoded
	}
	return req, pubHash, nil
}

func (s *Server) getBlockTemplateProposal(blockHex string) (any, *rpcError) {
	blockHex = strings.TrimSpace(blockHex)
	if blockHex == "" {
		return nil, &rpcError{Code: -32602, Message: "proposal mode requires data field with block hex"}
	}
	raw, err := hex.DecodeString(blockHex)
	if err != nil {
		return "rejected", nil
	}
	block, err := wire.ReadBlock(bytes.NewReader(raw))
	if err != nil {
		return "rejected", nil
	}
	code, _ := s.validateBlockProposalCode(block)
	if code != "" {
		return code, nil
	}
	return nil, nil
}

func (s *Server) currentTemplateLongPollID() string {
	tipHash := ""
	if tip := s.chain.Tip(); tip != nil {
		tipHash = tip.Hash
	}
	mempoolCount := 0
	if s.pool != nil {
		mempoolCount = s.pool.Count()
	}
	return fmt.Sprintf("%s:%d", tipHash, mempoolCount)
}

func (s *Server) waitForTemplateChange(ctx context.Context, currentID string, timeout time.Duration) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.currentTemplateLongPollID() != currentID {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-ticker.C:
		}
	}
}

func hasCapability(capabilities []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, c := range capabilities {
		if strings.ToLower(strings.TrimSpace(c)) == want {
			return true
		}
	}
	return false
}

func buildCoinbaseTxnField(block *wire.MsgBlock, height int32, coinbaseValue int64) map[string]any {
	if block == nil || len(block.Transactions) == 0 || block.Transactions[0] == nil {
		return map[string]any{}
	}
	cb := block.Transactions[0]
	raw, _ := cb.Bytes()
	h, _ := cb.TxHash()
	totalFees := coinbaseValue - chaincfg.BlockSubsidy(height)
	if totalFees < 0 {
		totalFees = 0
	}
	return map[string]any{
		"data":     hex.EncodeToString(raw),
		"txid":     h.String(),
		"hash":     h.String(),
		"fee":      -totalFees,
		"sigops":   0,
		"weight":   len(raw) * 4,
		"depends":  []int{},
		"required": true,
	}
}

func parseSendManyOutputs(raw json.RawMessage, baseUnits bool) (map[string]int64, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		// CLI compatibility: allow the outputs object to be passed as a JSON string.
		var wrapped string
		if err2 := json.Unmarshal(raw, &wrapped); err2 == nil {
			if err3 := json.Unmarshal([]byte(wrapped), &obj); err3 != nil {
				return nil, fmt.Errorf("sendmany outputs must be a JSON object of address->amount")
			}
		} else {
			return nil, fmt.Errorf("sendmany outputs must be a JSON object of address->amount")
		}
	}
	if len(obj) == 0 {
		return nil, fmt.Errorf("sendmany requires at least one destination")
	}
	out := make(map[string]int64, len(obj))
	for addr, amtRaw := range obj {
		addr = strings.TrimSpace(addr)
		if err := validateRPCAddress(addr); err != nil {
			return nil, err
		}
		amountValue, err := parseRPCAmount(amtRaw, baseUnits)
		if err != nil {
			return nil, fmt.Errorf("bad amount for %s: %w", addr, err)
		}
		if amountValue <= 0 {
			return nil, fmt.Errorf("amount for %s must be > 0", addr)
		}
		out[addr] = amountValue
	}
	return out, nil
}

func validateRPCAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return fmt.Errorf("bad destination address")
	}
	if payload, err := address.DecodeHybridAddress(addr); err == nil && len(payload) == 20 {
		return nil
	}
	version, payload, err := address.DecodeBase58Check(addr)
	if err != nil || version != chaincfg.PublicKeyHashVersion || len(payload) != 20 {
		return fmt.Errorf("bad destination address: %s", addr)
	}
	return nil
}

func (s *Server) rpcUnspentRow(u wallet.UTXOView) (map[string]any, error) {
	scriptHex := u.PkScriptHex
	if scriptHex == "" {
		entry, err := s.chain.UTXO(u.TxID, u.Vout)
		if err == nil && entry != nil {
			scriptHex = entry.PkScript
		}
	}
	spendable := !u.Locked
	if u.Coinbase && u.Confirmations > 0 && u.Confirmations < int32(chaincfg.CoinbaseMaturity) {
		spendable = false
	}
	safe := u.SafeToSpend && spendable
	if u.Unconfirmed && u.ChainDepth > 1 {
		safe = false
	}
	return map[string]any{
		"txid":              u.TxID,
		"vout":              u.Vout,
		"address":           u.Address,
		"scriptPubKey":      scriptHex,
		"amount":            amountFloat(u.Value),
		"amount_base_units": u.Value,
		"value":             u.Value,
		"value_base_units":  u.Value,
		"confirmations":     u.Confirmations,
		"spendable":         spendable,
		"solvable":          true,
		"safe":              safe,
		"coinbase":          u.Coinbase,
		"height":            u.Height,
		"pubkey_hash_hex":   u.PubKeyHashHex,
		"locked":            u.Locked,
		"locked_by":         u.LockedBy,
		"safe_to_spend":     u.SafeToSpend,
		"unconfirmed":       u.Unconfirmed,
	}, nil
}

type walletTxSummary struct {
	AmountBaseUnits int64
	FeeBaseUnits    int64
	Generated       bool
	TimeReceived    uint32
	Details         []map[string]any
	Category        string
	Address         string
	InvolvesWallet  bool
}

func (s *Server) walletTransactionSummary(lookup *txLookupResult) walletTxSummary {
	if lookup == nil || lookup.Tx == nil {
		return walletTxSummary{}
	}
	return s.summarizeWalletTx(lookup.TxID, lookup.Tx, lookup.Confirmations, lookup.BlockHash, lookup.BlockHeight, lookup.BlockTime, lookup.InMempool)
}

func (s *Server) summarizeWalletTx(txid string, tx *wire.MsgTx, confirmations int32, blockHash string, blockHeight int32, blockTime uint32, inMempool bool) walletTxSummary {
	summary := walletTxSummary{
		TimeReceived: blockTime,
		Details:      []map[string]any{},
		Category:     "receive",
	}
	if summary.TimeReceived == 0 {
		summary.TimeReceived = uint32(time.Now().Unix())
	}
	if tx == nil {
		return summary
	}
	addressSet := map[string]struct{}{}
	for _, addr := range s.defaultWallet().ListAddresses() {
		addressSet[addr] = struct{}{}
	}
	isCoinbase := len(tx.TxIn) == 1 &&
		tx.TxIn[0].PreviousOutPoint.Index == ^uint32(0) &&
		tx.TxIn[0].PreviousOutPoint.Hash == (chainhash.Hash{})
	walletOutTotal := int64(0)
	totalOut := int64(0)
	firstAddress := ""
	for vout, out := range tx.TxOut {
		totalOut += out.Value
		addr := decodeOutputAddress(out.PkScript)
		if addr == "" {
			continue
		}
		if _, ok := addressSet[addr]; !ok {
			continue
		}
		if firstAddress == "" {
			firstAddress = addr
		}
		walletOutTotal += out.Value
		category := "receive"
		if isCoinbase {
			if confirmations > 0 && confirmations < int32(chaincfg.CoinbaseMaturity) {
				category = "immature"
			} else {
				category = "generate"
			}
		}
		summary.Details = append(summary.Details, map[string]any{
			"address":           addr,
			"category":          category,
			"amount":            amountFloat(out.Value),
			"amount_base_units": out.Value,
			"vout":              vout,
		})
	}
	walletInTotal := int64(0)
	for _, in := range tx.TxIn {
		if in.PreviousOutPoint.Index == ^uint32(0) && in.PreviousOutPoint.Hash == (chainhash.Hash{}) {
			continue
		}
		prevTxID := in.PreviousOutPoint.Hash.String()
		entry, err := s.chain.UTXO(prevTxID, in.PreviousOutPoint.Index)
		if err != nil || entry == nil {
			continue
		}
		pkScript, err := hex.DecodeString(entry.PkScript)
		if err != nil {
			continue
		}
		addr := decodeOutputAddress(pkScript)
		if _, ok := addressSet[addr]; !ok {
			continue
		}
		walletInTotal += entry.Value
	}
	fee := int64(0)
	if s.pool != nil {
		if memEntry, ok := s.pool.Entry(txid); ok {
			fee = memEntry.Fee
		}
	}
	if fee == 0 && walletInTotal > 0 && walletInTotal >= totalOut {
		fee = walletInTotal - totalOut
	}
	summary.FeeBaseUnits = fee
	summary.Generated = isCoinbase && walletOutTotal > 0
	summary.Address = firstAddress
	switch {
	case isCoinbase && walletOutTotal > 0:
		summary.AmountBaseUnits = walletOutTotal
		if confirmations > 0 && confirmations < int32(chaincfg.CoinbaseMaturity) {
			summary.Category = "immature"
		} else {
			summary.Category = "generate"
		}
	case walletInTotal > 0 && walletOutTotal == 0:
		summary.AmountBaseUnits = -totalOut
		summary.Category = "send"
	case walletInTotal > 0 && walletOutTotal > 0:
		external := totalOut - walletOutTotal
		if external > 0 {
			summary.AmountBaseUnits = -external
			summary.Category = "send"
		} else {
			summary.AmountBaseUnits = 0
			summary.Category = "self"
		}
	default:
		summary.AmountBaseUnits = walletOutTotal
		summary.Category = "receive"
	}
	summary.InvolvesWallet = walletOutTotal > 0 || walletInTotal > 0
	if inMempool && summary.Category == "receive" && summary.AmountBaseUnits == 0 {
		summary.InvolvesWallet = false
	}
	_ = blockHash
	_ = blockHeight
	return summary
}

func (s *Server) walletTransactionRows(maxRows int) ([]map[string]any, error) {
	rows := make([]map[string]any, 0, 128)
	if tip := s.chain.Tip(); tip != nil {
		for h := tip.Height; h >= 0 && len(rows) < maxRows; h-- {
			idx, err := s.chain.IndexByHeight(h)
			if err != nil {
				continue
			}
			block, _, err := s.chain.BlockByHash(idx.Hash)
			if err != nil {
				continue
			}
			conf := confirmations(tip, idx)
			for _, tx := range block.Transactions {
				hash, err := tx.TxHash()
				if err != nil {
					continue
				}
				txid := hash.String()
				sum := s.summarizeWalletTx(txid, tx, conf, idx.Hash, idx.Height, idx.Time, false)
				if !sum.InvolvesWallet {
					continue
				}
				row := map[string]any{
					"address":           sum.Address,
					"category":          sum.Category,
					"amount":            amountFloat(sum.AmountBaseUnits),
					"amount_base_units": sum.AmountBaseUnits,
					"confirmations":     conf,
					"txid":              txid,
					"vout":              0,
					"time":              idx.Time,
					"timereceived":      idx.Time,
					"blockhash":         idx.Hash,
					"blockheight":       idx.Height,
					"blocktime":         idx.Time,
					"generated":         sum.Generated,
				}
				if sum.FeeBaseUnits > 0 {
					row["fee"] = amountFloat(-sum.FeeBaseUnits)
					row["fee_base_units"] = -sum.FeeBaseUnits
				}
				if len(sum.Details) > 0 {
					row["details"] = sum.Details
				}
				rows = append(rows, row)
			}
		}
	}
	if s.pool != nil {
		for _, tx := range s.pool.Transactions(0) {
			hash, err := tx.TxHash()
			if err != nil {
				continue
			}
			txid := hash.String()
			sum := s.summarizeWalletTx(txid, tx, 0, "", -1, 0, true)
			if !sum.InvolvesWallet {
				continue
			}
			row := map[string]any{
				"address":           sum.Address,
				"category":          sum.Category,
				"amount":            amountFloat(sum.AmountBaseUnits),
				"amount_base_units": sum.AmountBaseUnits,
				"confirmations":     int32(0),
				"txid":              txid,
				"vout":              0,
				"time":              int64(time.Now().Unix()),
				"timereceived":      int64(time.Now().Unix()),
				"generated":         sum.Generated,
				"in_mempool":        true,
			}
			if sum.FeeBaseUnits > 0 {
				row["fee"] = amountFloat(-sum.FeeBaseUnits)
				row["fee_base_units"] = -sum.FeeBaseUnits
			}
			if len(sum.Details) > 0 {
				row["details"] = sum.Details
			}
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		ti := asInt64(rows[i]["timereceived"])
		tj := asInt64(rows[j]["timereceived"])
		return ti > tj
	})
	return rows, nil
}

func asInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case int32:
		return int64(t)
	case uint32:
		return int64(t)
	case uint64:
		if t > uint64(^uint64(0)>>1) {
			return int64(^uint64(0) >> 1)
		}
		return int64(t)
	default:
		return 0
	}
}

func amountFloat(v int64) float64 {
	return float64(v) / float64(chaincfg.Coin)
}

func writeResponse(w http.ResponseWriter, resp response) {
	w.Header().Set("Content-Type", "application/json")
	origin := globalCORSOrigin
	if origin == "" {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	_ = json.NewEncoder(w).Encode(resp)
}

func validateMiningPubKeyHash(pubHashHex string) error {
	pubHashHex = strings.ToLower(strings.TrimSpace(pubHashHex))
	decoded, err := hex.DecodeString(pubHashHex)
	if err != nil || len(decoded) != 20 {
		return fmt.Errorf("mining pubkey hash must be 40 hex characters")
	}
	allZero := true
	for _, b := range decoded {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("refusing all-zero mining pubkey hash; run setupwallet or getminingaddress")
	}
	return nil
}

const unownedMiningDestinationMessage = "Configured mining reward address is not owned by this wallet. Choose a wallet receive address or explicitly enable external payout mode."

type miningDestination struct {
	Address       string
	PubKeyHashHex string
	Owned         bool
	External      bool
	Error         string
}

func decodeClassicMiningAddressHash(addr string) ([]byte, error) {
	version, payload, err := address.DecodeBase58Check(strings.TrimSpace(addr))
	if err != nil || version != chaincfg.PublicKeyHashVersion || len(payload) != 20 {
		return nil, fmt.Errorf("invalid mining address")
	}
	return payload, nil
}

func classicAddressHashHex(addr string) (string, error) {
	pubHash, err := decodeClassicMiningAddressHash(addr)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pubHash), nil
}

func decodeMiningAddressInput(addr string, out *wallet.MiningAddressInfo) error {
	addr = strings.TrimSpace(addr)
	hashHex, err := classicAddressHashHex(addr)
	if err != nil {
		return err
	}
	*out = wallet.MiningAddressInfo{Address: addr, PubKeyHashHex: hashHex}
	return nil
}

func walletClassicAddressForHash(w *wallet.Wallet, pubHashHex string) string {
	pubHashHex = strings.ToLower(strings.TrimSpace(pubHashHex))
	if validateMiningPubKeyHash(pubHashHex) != nil {
		return ""
	}
	for _, addr := range w.ListAddresses() {
		hashHex, err := classicAddressHashHex(addr)
		if err == nil && strings.EqualFold(hashHex, pubHashHex) {
			return addr
		}
	}
	return ""
}

func walletOwnsClassicAddress(w *wallet.Wallet, addr string) bool {
	hashHex, err := classicAddressHashHex(addr)
	if err != nil {
		return false
	}
	return walletClassicAddressForHash(w, hashHex) == strings.TrimSpace(addr)
}

func firstWalletMiningAddress(w *wallet.Wallet) (wallet.MiningAddressInfo, error) {
	for _, addr := range w.ListAddresses() {
		hashHex, err := classicAddressHashHex(addr)
		if err == nil {
			return wallet.MiningAddressInfo{Address: addr, PubKeyHashHex: hashHex}, nil
		}
	}
	return w.NewMiningAddress()
}

func (s *Server) persistMiningDestination(info wallet.MiningAddressInfo) error {
	if err := config.AppendConfigLine(s.miningConfigPath(), "mining_reward_address", info.Address); err != nil {
		return err
	}
	if err := config.AppendConfigLine(s.miningConfigPath(), "mining_pubkey_hash", strings.ToLower(info.PubKeyHashHex)); err != nil {
		return err
	}
	_ = config.AppendConfigLine(s.miningConfigPath(), "mining_external_payout", "false")
	_ = config.AppendConfigLine(s.miningConfigPath(), "mining_safe_required", "true")
	_ = config.AppendConfigLine(s.miningConfigPath(), "reject_zero_mining_hash", "true")
	return nil
}

func (s *Server) resolveMiningDestination(w *wallet.Wallet, cfg config.MiningConfig, createIfMissing bool) (miningDestination, error) {
	rewardAddress := strings.TrimSpace(cfg.RewardAddress)
	pubHashHex := strings.ToLower(strings.TrimSpace(cfg.PubKeyHash))
	if rewardAddress != "" {
		addrHash, err := classicAddressHashHex(rewardAddress)
		if err != nil {
			return miningDestination{Address: rewardAddress, PubKeyHashHex: pubHashHex, Error: err.Error()}, err
		}
		if pubHashHex != "" && !strings.EqualFold(pubHashHex, addrHash) {
			err := fmt.Errorf("configured mining reward address/hash mismatch")
			return miningDestination{Address: rewardAddress, PubKeyHashHex: pubHashHex, Error: err.Error()}, err
		}
		owned := walletOwnsClassicAddress(w, rewardAddress)
		if !owned {
			if cfg.ExternalPayout {
				return miningDestination{Address: rewardAddress, PubKeyHashHex: addrHash, External: true}, nil
			}
			err := errors.New(unownedMiningDestinationMessage)
			return miningDestination{Address: rewardAddress, PubKeyHashHex: addrHash, Error: err.Error()}, err
		}
		info := wallet.MiningAddressInfo{Address: rewardAddress, PubKeyHashHex: addrHash}
		_ = s.persistMiningDestination(info)
		return miningDestination{Address: rewardAddress, PubKeyHashHex: addrHash, Owned: true}, nil
	}
	if pubHashHex != "" {
		if err := validateMiningPubKeyHash(pubHashHex); err != nil {
			return miningDestination{PubKeyHashHex: pubHashHex, Error: err.Error()}, err
		}
		addr := walletClassicAddressForHash(w, pubHashHex)
		if addr == "" {
			if cfg.ExternalPayout {
				return miningDestination{PubKeyHashHex: pubHashHex, External: true}, nil
			}
			err := errors.New(unownedMiningDestinationMessage)
			return miningDestination{PubKeyHashHex: pubHashHex, Error: err.Error()}, err
		}
		info := wallet.MiningAddressInfo{Address: addr, PubKeyHashHex: pubHashHex}
		_ = s.persistMiningDestination(info)
		return miningDestination{Address: addr, PubKeyHashHex: pubHashHex, Owned: true}, nil
	}
	if !createIfMissing {
		err := fmt.Errorf("mining reward address is not configured")
		return miningDestination{Error: err.Error()}, err
	}
	info, err := firstWalletMiningAddress(w)
	if err != nil {
		return miningDestination{Error: err.Error()}, err
	}
	if !walletOwnsClassicAddress(w, info.Address) {
		err := fmt.Errorf("created mining reward address is not owned by this wallet")
		return miningDestination{Address: info.Address, PubKeyHashHex: info.PubKeyHashHex, Error: err.Error()}, err
	}
	if err := s.persistMiningDestination(info); err != nil {
		return miningDestination{Address: info.Address, PubKeyHashHex: info.PubKeyHashHex, Error: err.Error()}, err
	}
	return miningDestination{Address: info.Address, PubKeyHashHex: strings.ToLower(info.PubKeyHashHex), Owned: true}, nil
}

func (s *Server) miningDestinationStatus(w *wallet.Wallet, cfg config.MiningConfig) miningDestination {
	dest, err := s.resolveMiningDestination(w, cfg, false)
	if err != nil {
		return dest
	}
	return dest
}

func (s *Server) walletSummary(w *wallet.Wallet, pubKeyHashes []string) map[string]any {
	tip := s.chain.Tip()
	currentHeight := int32(-1)
	if tip != nil {
		currentHeight = tip.Height
	}
	type out struct {
		TxID          string `json:"txid"`
		Vout          uint32 `json:"vout"`
		Height        int32  `json:"height"`
		Value         int64  `json:"value"`
		Confirmations int32  `json:"confirmations"`
		MaturesAt     int32  `json:"matures_at"`
		PubKeyHash    string `json:"pubkey_hash"`
		Address       string `json:"address,omitempty"`
	}
	spendable := int64(0)
	immature := int64(0)
	immatureOut := make([]out, 0)
	spendableOut := make([]out, 0)
	want := make(map[string]struct{})
	addressByHash := make(map[string]string)
	hashByAddress := make(map[string]string)
	for _, addr := range w.ListAddresses() {
		hashHex, err := classicAddressHashHex(addr)
		if err != nil {
			continue
		}
		addressByHash[hashHex] = addr
		hashByAddress[addr] = hashHex
		want[hashHex] = struct{}{}
	}
	for _, h := range pubKeyHashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if validateMiningPubKeyHash(h) == nil && addressByHash[h] != "" {
			want[h] = struct{}{}
		}
	}
	// Also include unlocked wallet classic addresses where possible.
	if unspent, err := w.ListUnspent(s.chain); err == nil {
		for _, u := range unspent {
			maturesAt := u.Height
			if u.Coinbase {
				maturesAt = u.Height + int32(chaincfg.CoinbaseMaturity)
			}
			row := out{TxID: u.TxID, Vout: u.Vout, Height: u.Height, Value: u.Value, Confirmations: u.Confirmations, MaturesAt: maturesAt, PubKeyHash: u.PubKeyHashHex, Address: u.Address}
			if u.Coinbase && u.Confirmations < int32(chaincfg.CoinbaseMaturity) {
				immature += u.Value
				immatureOut = append(immatureOut, row)
			} else {
				spendable += u.Value
				spendableOut = append(spendableOut, row)
			}
		}
	}
	utxos, err := s.chain.ListUTXO()
	if err == nil && len(want) > 0 {
		seen := make(map[string]struct{})
		for _, r := range append(append([]out{}, spendableOut...), immatureOut...) {
			seen[fmt.Sprintf("%s:%d", r.TxID, r.Vout)] = struct{}{}
		}
		for _, u := range utxos {
			pk, err := hex.DecodeString(u.PkScript)
			if err != nil || !script.IsPayToPubKeyHash(pk) {
				continue
			}
			pkh := hex.EncodeToString(pk[3:23])
			if _, ok := want[pkh]; !ok {
				continue
			}
			addr := addressByHash[pkh]
			key := fmt.Sprintf("%s:%d", u.TxID, u.Vout)
			if _, ok := seen[key]; ok {
				continue
			}
			confs := int32(0)
			if currentHeight >= u.Height {
				confs = currentHeight - u.Height + 1
			}
			maturesAt := u.Height
			if u.Coinbase {
				maturesAt = u.Height + int32(chaincfg.CoinbaseMaturity)
			}
			row := out{TxID: u.TxID, Vout: u.Vout, Height: u.Height, Value: u.Value, Confirmations: confs, MaturesAt: maturesAt, PubKeyHash: pkh, Address: addr}
			if u.Coinbase && confs < int32(chaincfg.CoinbaseMaturity) {
				immature += u.Value
				immatureOut = append(immatureOut, row)
			} else {
				spendable += u.Value
				spendableOut = append(spendableOut, row)
			}
		}
	}
	nextMaturity := int32(0)
	for _, o := range immatureOut {
		if nextMaturity == 0 || o.MaturesAt < nextMaturity {
			nextMaturity = o.MaturesAt
		}
	}
	lockedViewLimited := w.SecurityInfo()["locked"] == true
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	dest := s.miningDestinationStatus(w, cfg)
	return map[string]any{
		"height":                      currentHeight,
		"wallet":                      w.SecurityInfo(),
		"spendable":                   spendable,
		"immature":                    immature,
		"next_maturity_height":        nextMaturity,
		"spendable_outputs":           spendableOut,
		"immature_outputs":            immatureOut,
		"address_by_pubkey_hash":      addressByHash,
		"pubkey_hash_by_address":      hashByAddress,
		"default_mining_address":      dest.Address,
		"default_mining_pubkey_hash":  dest.PubKeyHashHex,
		"default_mining_wallet_owned": dest.Owned,
		"external_payout_mode":        dest.External,
		"mining_destination_error":    dest.Error,
		"note":                        "coinbase rewards require 100 confirmations before spending",
		"locked_balance_view_limited": lockedViewLimited,
	}
}

func (s *Server) doctor() map[string]any {
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	dest := s.miningDestinationStatus(s.defaultWallet(), cfg)
	storage := s.chain.StorageHealth()
	winfo := s.defaultWallet().SecurityInfo()
	checks := []map[string]any{
		{"id": "daemon_reachable", "ok": true, "message": "RPC daemon answered"},
		{"id": "storage_ok", "ok": storage.OK, "message": "best block, height index and UTXO stats readable"},
		{"id": "wallet_initialized", "ok": winfo["hdseed"] == true && winfo["classic_keys"].(int) > 0, "message": "wallet has HD seed and classic key"},
		{"id": "hybrid_wallet_initialized", "ok": winfo["hybrid_keys"].(int) > 0, "message": "hybrid wallet path has at least one key"},
		{"id": "mining_destination_wallet_owned", "ok": dest.Owned || dest.External, "message": func() string {
			if dest.Error != "" {
				return dest.Error
			}
			if dest.External {
				return "external payout mode is explicitly enabled"
			}
			return "mining reward destination is wallet-owned"
		}()},
		{"id": "rpc_local_or_authenticated", "ok": rpcIsLocalhost(s.rpcBindHost()) || s.auth.Enabled, "message": "non-local RPC requires auth"},
		{"id": "peers_visible", "ok": s.p2p.PeerCount() >= 0, "message": "peer subsystem is readable"},
	}
	ok := true
	for _, c := range checks {
		pass, _ := c["ok"].(bool)
		if !pass {
			ok = false
			break
		}
	}
	return map[string]any{
		"ok":     ok,
		"checks": checks,
		"height": func() int32 {
			if tip := s.chain.Tip(); tip != nil {
				return tip.Height
			}
			return -1
		}(),
		"peers":   s.p2p.PeerCount(),
		"storage": storage,
		"wallet":  winfo,
		"mining":  map[string]any{"address": dest.Address, "pubkey_hash": dest.PubKeyHashHex, "wallet_owned": dest.Owned, "external_payout": dest.External, "destination_error": dest.Error, "threads": cfg.Threads},
	}
}

func (s *Server) estimateNetworkHashPS(window int32) map[string]any {
	cur := s.netHashDiagActive.Add(1)
	s.netHashDiagTotal.Add(1)
	if cur > s.netHashDiagMax.Load() {
		s.netHashDiagMax.Store(cur)
	}
	defer s.netHashDiagActive.Add(-1)
	tip := s.chain.Tip()
	if tip == nil || tip.Height < 3 {
		return map[string]any{
			"estimate":                        "difficulty_time_estimate",
			"hps":                             0,
			"khps":                            0,
			"mhps":                            0,
			"network_hash_ps":                 0,
			"network_hashps_window":           0,
			"network_hashps_blocks_used":      0,
			"network_hashps_timespan_seconds": 0,
			"network_hashps_formula":          "sum(expected_hashes_for_bits[post-genesis blocks]) / elapsed_seconds",
			"network_hashps_confidence":       "very_low",
			"network_hashps_source":           "difficulty_time_estimate",
			"window":                          0,
			"blocks_used":                     0,
			"timespan_seconds":                0,
			"formula":                         "sum(expected_hashes_for_bits[post-genesis blocks]) / elapsed_seconds",
			"confidence":                      "very_low",
			"source":                          "difficulty_time_estimate",
			"units":                           "H/s",
			"genesis_excluded":                true,
			"status":                          "estimating",
			"note":                            "not enough post-genesis blocks for a reliable network hashrate estimate",
		}
	}
	start := tip.Height - window
	if start < 1 {
		start = 1
	}
	if start >= tip.Height {
		start = tip.Height - 1
	}
	first, err := s.chain.IndexByHeight(start)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	last, err := s.chain.IndexByHeight(tip.Height)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	totalTime := int64(last.Time) - int64(first.Time)
	totalExpected := float64(0)
	for h := start + 1; h <= tip.Height; h++ {
		idx, err := s.chain.IndexByHeight(h)
		if err != nil {
			continue
		}
		totalExpected += rpcExpectedHashesForBits(idx.Bits)
	}
	hps := float64(0)
	if totalTime > 0 {
		hps = totalExpected / float64(totalTime)
	}
	blocks := tip.Height - start
	avgSpacing := float64(0)
	if blocks > 0 && totalTime > 0 {
		avgSpacing = float64(totalTime) / float64(blocks)
	}
	confidence := networkHashConfidence(blocks)
	return map[string]any{
		"estimate":                        "difficulty_time_estimate",
		"hps":                             hps,
		"khps":                            hps / 1000,
		"mhps":                            hps / 1_000_000,
		"network_hash_ps":                 hps,
		"network_hashps_window":           window,
		"network_hashps_blocks_used":      blocks,
		"network_hashps_timespan_seconds": totalTime,
		"network_hashps_formula":          "sum(expected_hashes_for_bits[post-genesis blocks]) / elapsed_seconds",
		"network_hashps_confidence":       confidence,
		"network_hashps_source":           "difficulty_time_estimate",
		"start_height":                    start,
		"tip_height":                      tip.Height,
		"blocks":                          blocks,
		"blocks_used":                     blocks,
		"window":                          window,
		"total_time_seconds":              totalTime,
		"timespan_seconds":                totalTime,
		"average_spacing_seconds":         avgSpacing,
		"target_spacing_seconds":          int64(chaincfg.TargetSpacing.Seconds()),
		"expected_hashes":                 totalExpected,
		"formula":                         "sum(expected_hashes_for_bits[post-genesis blocks]) / elapsed_seconds",
		"confidence":                      confidence,
		"source":                          "difficulty_time_estimate",
		"units":                           "H/s",
		"genesis_excluded":                true,
		"status":                          "estimated",
	}
}

func networkHashConfidence(blocks int32) string {
	switch {
	case blocks >= 100:
		return "high"
	case blocks >= 50:
		return "medium"
	case blocks >= 10:
		return "low"
	default:
		return "very_low"
	}
}

func rpcWindowParam(params json.RawMessage, fallback int32) int32 {
	if fallback <= 0 {
		fallback = 100
	}
	var args []json.RawMessage
	if len(params) == 0 || json.Unmarshal(params, &args) != nil || len(args) == 0 {
		return fallback
	}
	var window int32
	if err := json.Unmarshal(args[0], &window); err != nil || window <= 0 {
		return fallback
	}
	if window > 1000 {
		return 1000
	}
	return window
}

func rpcExpectedHashesForBits(bits uint32) float64 {
	target := consensus.CompactToBig(bits)
	if target.Sign() <= 0 {
		return 0
	}
	space := new(big.Int).Lsh(big.NewInt(1), 256)
	ratio := new(big.Rat).SetFrac(space, target)
	out, _ := ratio.Float64()
	return out
}

func (s *Server) chainTiming(window int32) map[string]any {
	tip := s.chain.Tip()
	if tip == nil || tip.Height <= 0 {
		return map[string]any{"height": 0, "target_spacing_seconds": int64(chaincfg.TargetSpacing.Seconds()), "average_block_time_seconds": 0, "genesis_excluded": true}
	}
	if window <= 0 {
		window = 100
	}
	primary := s.chainTimingStats(window)
	last10 := s.chainTimingStats(10)
	last50 := s.chainTimingStats(50)
	last100 := s.chainTimingStats(100)
	bits := ""
	if tip != nil {
		bits = fmt.Sprintf("%08x", tip.Bits)
	}
	return map[string]any{
		"height":                         tip.Height,
		"bestblockhash":                  tip.Hash,
		"current_bits":                   bits,
		"current_compact_target":         compactTargetHex(tip.Bits),
		"target_spacing_seconds":         int64(chaincfg.TargetSpacing.Seconds()),
		"window_blocks":                  primary["blocks"],
		"start_height":                   primary["start_height"],
		"tip_height":                     tip.Height,
		"total_time_seconds":             primary["total_time_seconds"],
		"average_block_time_seconds":     primary["average_block_time_seconds"],
		"average_solve_time_seconds":     primary["average_block_time_seconds"],
		"fastest_block_seconds":          primary["fastest_block_seconds"],
		"slowest_block_seconds":          primary["slowest_block_seconds"],
		"last_10_block_average_seconds":  last10["average_block_time_seconds"],
		"last_50_block_average_seconds":  last50["average_block_time_seconds"],
		"last_100_block_average_seconds": last100["average_block_time_seconds"],
		"last_10":                        last10,
		"last_50":                        last50,
		"last_100":                       last100,
		"windows":                        map[string]any{"10": last10, "50": last50, "100": last100},
		"last_block_age_seconds":         int64(time.Now().Unix()) - int64(tip.Time),
		"genesis_excluded":               true,
		"trend":                          primary["trend"],
		"difficulty_trend":               primary["trend"],
		"estimated_next_adjustment":      primary["trend"],
		"difficulty_history":             s.difficultyHistory(100),
		"network_hashps":                 s.estimateNetworkHashPS(window),
		"network_hashps_50":              s.estimateNetworkHashPS(50),
		"network_hashps_100":             s.estimateNetworkHashPS(100),
	}
}

func (s *Server) chainTimingStats(window int32) map[string]any {
	tip := s.chain.Tip()
	if tip == nil || tip.Height <= 0 {
		return map[string]any{"blocks": 0, "average_block_time_seconds": 0.0, "fastest_block_seconds": 0, "slowest_block_seconds": 0, "trend": "near_target", "genesis_excluded": true}
	}
	if window <= 0 {
		window = 100
	}
	start := tip.Height - window
	if start < 1 {
		start = 1
	}
	if start >= tip.Height {
		start = tip.Height - 1
	}
	first, err := s.chain.IndexByHeight(start)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	last, err := s.chain.IndexByHeight(tip.Height)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	blocks := tip.Height - start
	totalTime := int64(last.Time) - int64(first.Time)
	avg := float64(0)
	if blocks > 0 && totalTime > 0 {
		avg = float64(totalTime) / float64(blocks)
	}
	fastest := int64(0)
	slowest := int64(0)
	for h := start + 1; h <= tip.Height; h++ {
		prev, prevErr := s.chain.IndexByHeight(h - 1)
		cur, curErr := s.chain.IndexByHeight(h)
		if prevErr != nil || curErr != nil {
			continue
		}
		solve := int64(cur.Time) - int64(prev.Time)
		if solve < 0 {
			continue
		}
		if fastest == 0 || solve < fastest {
			fastest = solve
		}
		if solve > slowest {
			slowest = solve
		}
	}
	return map[string]any{
		"requested_window":           window,
		"blocks":                     blocks,
		"start_height":               start,
		"tip_height":                 tip.Height,
		"total_time_seconds":         totalTime,
		"average_block_time_seconds": avg,
		"average_solve_time_seconds": avg,
		"fastest_block_seconds":      fastest,
		"slowest_block_seconds":      slowest,
		"target_spacing_seconds":     int64(chaincfg.TargetSpacing.Seconds()),
		"trend":                      timingTrend(avg),
		"genesis_excluded":           true,
		"low_hash_variance_note":     "Short windows can look uneven on low-hash PoW; prefer the 100-block average for release decisions.",
	}
}

func (s *Server) difficultyHistory(window int32) []map[string]any {
	tip := s.chain.Tip()
	if tip == nil || tip.Height <= 0 {
		return nil
	}
	if window <= 0 {
		window = 100
	}
	if window > 500 {
		window = 500
	}
	start := tip.Height - window + 1
	if start < 1 {
		start = 1
	}
	out := make([]map[string]any, 0, tip.Height-start+1)
	for h := start; h <= tip.Height; h++ {
		idx, err := s.chain.IndexByHeight(h)
		if err != nil {
			continue
		}
		solve := int64(0)
		direction := "same"
		became := "same"
		if h > 0 {
			prev, prevErr := s.chain.IndexByHeight(h - 1)
			if prevErr == nil {
				solve = int64(idx.Time) - int64(prev.Time)
				prevTarget := consensus.CompactToBig(prev.Bits)
				curTarget := consensus.CompactToBig(idx.Bits)
				switch curTarget.Cmp(prevTarget) {
				case -1:
					direction = "harder"
					became = "harder"
				case 1:
					direction = "easier"
					became = "easier"
				}
			}
		}
		out = append(out, map[string]any{
			"height":                  idx.Height,
			"timestamp":               idx.Time,
			"solve_time_seconds":      solve,
			"bits":                    fmt.Sprintf("%08x", idx.Bits),
			"compact_target":          compactTargetHex(idx.Bits),
			"difficulty_direction":    direction,
			"difficulty_became":       became,
			"target_spacing_seconds":  int64(chaincfg.TargetSpacing.Seconds()),
			"consensus_rules_changed": false,
		})
	}
	return out
}

func timingTrend(avg float64) string {
	target := float64(chaincfg.TargetSpacing.Seconds())
	if avg > 0 && avg < target*0.8 {
		return "faster_than_target"
	}
	if avg > target*1.2 {
		return "slower_than_target"
	}
	return "near_target"
}

func (s *Server) MinerStatus() map[string]any {
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	storage := s.chain.StorageHealth()
	peerOK := !cfg.PeerRequired || (s.p2p != nil && s.p2p.PeerCount() > 0)
	dest := s.miningDestinationStatus(s.defaultWallet(), cfg)
	miningReady := storage.OK && peerOK && (dest.Owned || dest.External)
	return s.minerStatus(s.defaultWallet(), cfg, storage, miningReady)
}

func (s *Server) minerStatus(w *wallet.Wallet, cfg config.MiningConfig, storage any, miningReady bool) map[string]any {
	cur := s.minerStatusDiagActive.Add(1)
	s.minerStatusDiagTotal.Add(1)
	if cur > s.minerStatusDiagMax.Load() {
		s.minerStatusDiagMax.Store(cur)
	}
	defer s.minerStatusDiagActive.Add(-1)
	s.minerMu.Lock()
	minerEnabled := s.minerActive
	activeMining := s.minerHashing
	minerThreads := s.minerThreads
	minerBlocks := s.minerBlocks
	minerLastHash := s.minerLastHash
	minerLastError := s.minerLastError
	minerPausedReason := s.minerPausedReason
	minerLastStopReason := s.minerLastStopReason
	minerSupervisorRestartAttempts := s.minerSupervisorRestartAttempts
	minerLastSupervisorCancelTime := s.minerLastSupervisorCancelTime
	minerLastRestartSuccessTime := s.minerLastRestartSuccessTime
	minerLastRestartFailure := s.minerLastRestartFailure
	minerStartedAt := s.minerStartedAt
	stopAfter := s.minerStopAfterBlocks
	rewardHash := s.minerRewardHash
	peerRequired := s.minerPeerRequired
	localHashPS := s.minerLocalHashPS
	sessionHashes := s.minerSessionHashes
	lastNonce := s.minerLastNonce
	workerEpochStartedAt := s.minerWorkerEpochStartedAt
	lastHashProgressTime := s.minerLastHashProgressTime
	staleBlocks := s.minerStaleBlocks
	rejectedBlocks := s.minerRejectedBlocks
	lastStaleTime := s.minerLastStaleTime
	lastStaleReason := s.minerLastStaleReason
	lastTemplateTime := s.minerLastTemplateTime
	lastTemplateHeight := s.minerLastTemplateHeight
	lastTemplatePrevHash := s.minerLastTemplatePrevHash
	lastTemplateTipHeight := s.minerLastTemplateTipHeight
	lastTemplateTipHash := s.minerLastTemplateTipHash
	lastTemplateFresh := s.minerLastTemplateFresh
	lastTemplateStaleReason := s.minerLastTemplateStaleReason
	lastTemplateRefreshDue := s.minerLastTemplateRefreshDue
	lastTemplateRefreshReason := s.minerLastTemplateRefreshReason
	lastTemplateRefreshAttempt := s.minerLastTemplateRefreshAttempt
	templateRefreshCount := s.minerTemplateRefreshCount
	staleTemplateRefreshAttempts := s.minerStaleTemplateRefreshAttempts
	staleTemplateSkips := s.minerStaleTemplateSkips
	lastTemplateRefreshError := s.minerLastTemplateRefreshError
	templateRecoveryPending := s.minerTemplateRecoveryPending
	templateRecoveryStartedAt := s.minerTemplateRecoveryStartedAt
	acceptedRecords := append([]minerAcceptedRecord(nil), s.minerAcceptedRecords...)
	stateGen := s.minerStateGen
	lifecycleCounters := mining.LifecycleCounters()
	yespowerCounters := pow.YespowerCounters()
	s.minerMu.Unlock()
	genAfter := stateGen
	for retry := 0; retry < 3; retry++ {
		s.minerMu.Lock()
		genAfter = s.minerStateGen
		s.minerMu.Unlock()
		if genAfter == stateGen {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	snapshotConsistent := genAfter == stateGen
	uptime := int64(0)
	startedAt := ""
	if minerEnabled && !minerStartedAt.IsZero() {
		uptime = int64(time.Since(minerStartedAt).Seconds())
		startedAt = minerStartedAt.Format(time.RFC3339)
	}
	blocksRemaining := int64(0)
	if stopAfter > 0 && minerBlocks < stopAfter {
		blocksRemaining = stopAfter - minerBlocks
	}
	safety := s.checkSafeToMine(w, cfg, true)
	miningReady = miningReady && safety.Safe
	canStart := miningReady && !minerEnabled
	currentBits := ""
	if tip := s.chain.Tip(); tip != nil {
		currentBits = fmt.Sprintf("%08x", tip.Bits)
	}
	dest := s.miningDestinationStatus(w, cfg)
	displayRewardHash := strings.TrimSpace(rewardHash)
	if displayRewardHash == "" {
		displayRewardHash = dest.PubKeyHashHex
	}
	displayRewardAddress := dest.Address
	if displayRewardAddress == "" && displayRewardHash != "" {
		displayRewardAddress = walletClassicAddressForHash(w, displayRewardHash)
	}
	estimatedSeconds := float64(0)
	if localHashPS > 0 {
		if nh, ok := s.estimateNetworkHashPS(100)["hps"].(float64); ok && nh > 0 {
			estimatedSeconds = float64(chaincfg.TargetSpacing.Seconds()) * nh / localHashPS
		}
	}
	lastError := strings.TrimSpace(minerLastError)
	lastAction := ""
	lastHistoricalEvent := ""
	lastErrorRaw := ""
	if isNormalMinerStopReason(lastError) {
		lastAction = "stopped by user/RPC"
		lastErrorRaw = lastError
		lastError = ""
	} else if !activeMining && isHistoricalMinerRetryReason(lastError) {
		lastHistoricalEvent = lastError
		lastErrorRaw = lastError
		lastError = ""
	}
	lastStaleTimeValue := int64(0)
	if !lastStaleTime.IsZero() {
		lastStaleTimeValue = lastStaleTime.Unix()
	}
	workerEpochAge := float64(0)
	if !workerEpochStartedAt.IsZero() {
		workerEpochAge = time.Since(workerEpochStartedAt).Seconds()
	}
	lastTemplateAge := float64(-1)
	lastTemplateTimeValue := int64(0)
	templateRecoveryAge := float64(0)
	templateRecoveryStartedAtValue := int64(0)
	if !lastTemplateTime.IsZero() {
		lastTemplateTimeValue = lastTemplateTime.Unix()
		lastTemplateAge = time.Since(lastTemplateTime).Seconds()
	}
	if templateRecoveryPending && !templateRecoveryStartedAt.IsZero() {
		templateRecoveryStartedAtValue = templateRecoveryStartedAt.Unix()
		templateRecoveryAge = time.Since(templateRecoveryStartedAt).Seconds()
	}
	hasActiveTemplate := minerEnabled && !lastTemplateTime.IsZero() && lastTemplateHeight > 0
	if hasActiveTemplate {
		lastTemplateFresh, lastTemplateStaleReason = s.activeTemplateFreshness(lastTemplateHeight, lastTemplatePrevHash, lastTemplateTime)
		if !lastTemplateFresh {
			lastTemplateRefreshDue = true
			if strings.TrimSpace(lastTemplateRefreshReason) == "" {
				lastTemplateRefreshReason = staleTemplateRefreshReason(lastTemplateStaleReason)
			}
		} else if miningTemplateSoftRefreshAgeSeconds() > 0 && lastTemplateAge > miningTemplateSoftRefreshAgeSeconds() {
			lastTemplateRefreshDue = true
			if strings.TrimSpace(lastTemplateRefreshReason) == "" {
				lastTemplateRefreshReason = "refreshing template in background; current template still valid"
			}
		} else {
			lastTemplateStaleReason = ""
			lastTemplateRefreshDue = false
			lastTemplateRefreshReason = ""
			lastTemplateRefreshError = ""
			s.clearValidTemplateStateIfCurrent(lastTemplateHeight, lastTemplatePrevHash, lastTemplateTime)
		}
	}
	acceptedBlockStatuses, activeAcceptedBlocks := s.acceptedBlockStatuses(acceptedRecords)
	runtimeState := ResolveMinerRuntimeState(MinerRuntimeInput{
		SessionActive:         minerEnabled,
		WorkersHashing:        activeMining,
		ConfiguredThreads:     cfg.Threads,
		HashAttempts:          sessionHashes,
		LastNonce:             lastNonce,
		LocalHashPS:           localHashPS,
		WorkerEpochAgeSeconds: workerEpochAge,
		SafetySafe:            safety.Safe,
		SafetyReason:          safety.Reason,
		RPCHealth:             safety.RPCHealth,
		DataFresh:             true,
		SyncState:             safety.SyncState,
		BlocksBehind:          safety.BlocksBehind,
		BlocksBehindAllowed:   int32(cfg.BlocksBehindOK),
		GoodPeerCount:         safety.GoodPeerCount,
		MinGoodPeers:          cfg.MinGoodPeers,
		DestinationOK:         dest.Owned || dest.External,
		DestinationError:      dest.Error,
		HasActiveTemplate:     hasActiveTemplate,
		TemplateFresh:         hasActiveTemplate && lastTemplateFresh,
		TemplateRefreshDue:    hasActiveTemplate && lastTemplateRefreshDue,
		TemplateStaleReason:   lastTemplateStaleReason,
		TemplateRefreshError:  lastTemplateRefreshError,
		LastError:             lastError,
		PausedReason:          minerPausedReason,
		LastStopReason:        minerLastStopReason,
		EverStarted:           !minerStartedAt.IsZero(),
		StaleRatePauseActive:  safety.StaleRatePauseActive,
		RecentReorg:           safety.RecentReorg,
	})
	activeMining = minerStateCountsAsActive(runtimeState.State)
	liveThreads := runtimeState.ActiveThreads
	liveHashPS := float64(0)
	if runtimeState.LiveHashing {
		liveHashPS = localHashPS
	}
	currentMiningState := runtimeState.State
	currentSafetyState := "idle / ready, miner stopped"
	if runtimeState.State == MinerStateStopped {
		currentSafetyState = "idle / ready, miner stopped"
	} else if runtimeState.Reason != "" {
		currentSafetyState = runtimeState.Reason
	} else if runtimeState.State == MinerStateRunning {
		currentSafetyState = "safe"
	} else if runtimeState.State == MinerStateSoftRefreshingStillMining {
		currentSafetyState = "refreshing template in background; current template still valid"
	} else if runtimeState.SupervisorAction != "" {
		currentSafetyState = "starting / resuming workers"
	}
	goodPeerReasonCounts, peerQualityDiagnostics := s.miningPeerDiagnostics(safety.LocalHeight)
	out := map[string]any{
		"mining_ready":              miningReady,
		"can_start":                 canStart,
		"mining_enabled":            minerEnabled,
		"mining_config_enabled":     cfg.Enabled,
		"mining_session_active":     minerEnabled,
		"active_mining":             activeMining,
		"actual_worker_hashing":     runtimeState.LiveHashing,
		"miner_loop_enabled":        minerEnabled,
		"miner_state":               runtimeState.State,
		"miner_state_reason":        runtimeState.Reason,
		"miner_supervisor_action":   runtimeState.SupervisorAction,
		"miner_invariant_violation": runtimeState.InvariantViolation,
		"mining_safe":               safety.Safe,
		"threads":                   cfg.Threads,
		"configured_threads":        cfg.Threads,
		"max_threads":               cfg.MaxThreads,
		"active_threads":            liveThreads,
		"live_active_threads":       liveThreads,
		"last_session_active_threads": func() int {
			if minerEnabled {
				return liveThreads
			}
			return minerThreads
		}(),
		"effective_threads": func() int {
			if activeMining {
				return liveThreads
			}
			return cfg.Threads
		}(),
		"thread_state": func() string {
			if runtimeState.LiveHashing {
				return "active"
			}
			if runtimeState.ShouldHaveWorkers {
				return "resuming_workers"
			}
			if minerEnabled && runtimeState.Reason != "" {
				return "paused"
			}
			return "configured_only"
		}(),
		"threads_note": func() string {
			if runtimeState.LiveHashing {
				return "active_threads is the live worker count currently mining"
			}
			if runtimeState.ShouldHaveWorkers {
				return "miner supervisor is resuming workers because no active blocker is present"
			}
			if minerEnabled && runtimeState.Reason != "" {
				return "miner session is paused until the displayed blocker clears"
			}
			return "miner is stopped; configured_threads will be used next time mining starts"
		}(),
		"auto_start":        cfg.AutoStart,
		"peer_required":     cfg.PeerRequired || peerRequired,
		"safe_required":     cfg.SafeRequired,
		"stop_after_blocks": stopAfter,
		"blocks_remaining":  blocksRemaining,
		"session_blocks":    minerBlocks,
		"started_at":        startedAt,
		"uptime_seconds":    uptime,
		"last_block_hash":   minerLastHash,
		"last_error":        lastError,
		"last_error_raw":    lastErrorRaw,
		"last_action":       lastAction,
		"last_stop_reason": func() string {
			if strings.TrimSpace(minerLastStopReason) != "" {
				return minerLastStopReason
			}
			if !minerEnabled && !minerStartedAt.IsZero() {
				return MinerStopWorkerExitUnexpected
			}
			return ""
		}(),
		"supervisor_restart_attempts":     minerSupervisorRestartAttempts,
		"last_supervisor_cancel_time":     unixOrZero(minerLastSupervisorCancelTime),
		"last_restart_success_time":       unixOrZero(minerLastRestartSuccessTime),
		"last_restart_failure":            minerLastRestartFailure,
		"outer_node_context_cancelled":    false,
		"supervisor_recovery_max_seconds": 10,
		"last_historical_event":           lastHistoricalEvent,
		"current_mining_state":            currentMiningState,
		"current_safety_state":            currentSafetyState,
		"last_start_command_time": func() int64 {
			if minerStartedAt.IsZero() {
				return 0
			}
			return minerStartedAt.Unix()
		}(),
		"start_command_accepted":         minerEnabled,
		"start_confirmation_status":      currentMiningState,
		"last_miner_status_success_time": time.Now().Unix(),
		"miner_status_age_seconds":       0.0,
		"status_data_fresh":              true,
		"worker_epoch_started_at":        unixOrZero(workerEpochStartedAt),
		"worker_epoch_age_seconds":       workerEpochAge,
		"last_hash_progress_time":        unixOrZero(lastHashProgressTime),
		"worker_startup_grace_seconds":   minerWorkerProgressGraceSeconds,
		"worker_progress_stalled":        runtimeState.State == MinerStateWorkerStalled,
		"live_hashrate":                  liveHashPS,
		"live_hashps":                    liveHashPS,
		"live_khps":                      liveHashPS / 1000,
		"local_hashps":                   liveHashPS,
		"local_khps":                     liveHashPS / 1000,
		"local_hashps_live":              liveHashPS,
		"local_khps_live":                liveHashPS / 1000,
		"last_session_hashps": func() float64 {
			if activeMining {
				return 0
			}
			return localHashPS
		}(),
		"last_session_khps": func() float64 {
			if activeMining {
				return 0
			}
			return localHashPS / 1000
		}(),
		"live_active_threads_note":              "active_threads and local_khps are live-only; use last_session_* for stopped miner history",
		"session_hashes":                        sessionHashes,
		"hash_attempts":                         sessionHashes,
		"hashes_per_thread":                     hashesPerThread(localHashPS, minerThreads),
		"last_nonce":                            lastNonce,
		"current_bits":                          currentBits,
		"estimated_time_to_block_seconds":       estimatedSeconds,
		"accepted_blocks":                       activeAcceptedBlocks,
		"accepted_blocks_total":                 minerBlocks,
		"accepted_blocks_active_chain":          activeAcceptedBlocks,
		"accepted_blocks_orphaned":              int64(len(acceptedBlockStatuses)) - activeAcceptedBlocks,
		"accepted_block_hashes":                 acceptedBlockHashes(acceptedBlockStatuses),
		"accepted_block_heights":                acceptedBlockHeights(acceptedBlockStatuses),
		"accepted_mined_blocks":                 acceptedBlockStatuses,
		"stale_blocks":                          staleBlocks,
		"rejected_blocks":                       rejectedBlocks,
		"stale_rate":                            safety.StaleRate,
		"stale_rate_warning":                    safety.StaleRateWarning,
		"last_stale_time":                       lastStaleTimeValue,
		"last_stale_reason":                     lastStaleReason,
		"last_template_refresh_time":            lastTemplateTimeValue,
		"last_template_refresh_ago_seconds":     lastTemplateAge,
		"last_template_refresh_attempt_time":    unixOrZero(lastTemplateRefreshAttempt),
		"last_template_refresh_success_time":    lastTemplateTimeValue,
		"last_template_refresh_error":           lastTemplateRefreshError,
		"template_recovery_pending":             templateRecoveryPending,
		"template_recovery_started_time":        templateRecoveryStartedAtValue,
		"template_recovery_age_seconds":         templateRecoveryAge,
		"template_recovery_timeout_seconds":     miningTemplateRecoveryTimeoutSeconds(),
		"last_template_refresh_tip_height":      lastTemplateTipHeight,
		"last_template_refresh_tip_hash":        lastTemplateTipHash,
		"template_refresh_count":                templateRefreshCount,
		"template_refresh_attempts_since_stale": staleTemplateRefreshAttempts,
		"stale_template_skip_count":             staleTemplateSkips,
		"template_refresh_final_state": func() string {
			if hasActiveTemplate && lastTemplateFresh {
				return "fresh"
			}
			if hasActiveTemplate && lastTemplateRefreshDue {
				return "refreshing"
			}
			if hasActiveTemplate {
				return "stale"
			}
			return "idle"
		}(),
		"active_threads_after_template_refresh": liveThreads,
		"last_mined_template_height":            lastTemplateHeight,
		"current_template_height":               safety.CurrentTemplateHeight,
		"current_tip_height":                    safety.CurrentTipHeight,
		"current_tip_hash":                      safety.CurrentTipHash,
		"active_template_height":                lastTemplateHeight,
		"active_template_prev_hash":             lastTemplatePrevHash,
		"active_template_age_seconds":           lastTemplateAge,
		"active_template_is_fresh":              hasActiveTemplate && lastTemplateFresh,
		"active_template_refresh_due":           hasActiveTemplate && lastTemplateRefreshDue,
		"active_template_stale_reason":          lastTemplateStaleReason,
		"active_template_refresh_reason":        lastTemplateRefreshReason,
		"has_active_template":                   hasActiveTemplate,
		"template_soft_refresh_age_seconds":     miningTemplateSoftRefreshAgeSeconds(),
		"template_max_age_seconds":              miningTemplateHardStaleAgeSeconds(),
		"template_hard_stale_age_seconds":       miningTemplateHardStaleAgeSeconds(),
		"mining_paused_reason":                  minerPausedReason,
		"mining_reward_address":                 displayRewardAddress,
		"configured_mining_address":             strings.TrimSpace(cfg.RewardAddress),
		"mining_address_wallet_owned":           dest.Owned,
		"owned_by_wallet":                       dest.Owned,
		"external_payout_mode":                  dest.External,
		"mining_destination_error":              dest.Error,
		"payout_warning": func() string {
			if dest.External {
				return "External payout mode: rewards will not appear in this wallet unless you own or import that address."
			}
			if dest.Error != "" {
				return dest.Error
			}
			return ""
		}(),
		"mining_pubkey_hash": dest.PubKeyHashHex,
		"active_reward_hash": displayRewardHash,
		"reject_zero_hash":   cfg.RejectZeroHash,
		"peers": func() int32 {
			if s.p2p == nil {
				return 0
			}
			return s.p2p.PeerCount()
		}(),
		"good_peer_rejection_reasons": goodPeerReasonCounts,
		"peer_quality_diagnostics":    peerQualityDiagnostics,
		"good_peer_diagnostics_note":  "Peer count includes all connected peers; good peers have useful current chain data, acceptable latency/pongs, matching chain ID, and no recent sync or block errors.",
		"storage":                     storage,
		"wallet":                      w.SecurityInfo(),
		"config":                      s.miningConfigPath(),
		"control_rpcs":                []string{"startminer", "stopminer", "restartminer", "getminerstatus", "benchmarkminer", "autotuneminer", "setminerthreads", "setminingaddress", "configureminer"},
	}
	out["rpc_active_requests"] = func() int64 {
		s.rpcDiagMu.Lock()
		defer s.rpcDiagMu.Unlock()
		return s.rpcActiveRequests
	}()
	out["rpc_oldest_request_age_seconds"] = func() float64 {
		s.rpcDiagMu.Lock()
		defer s.rpcDiagMu.Unlock()
		if s.rpcOldestRequestAt.IsZero() {
			return 0
		}
		return time.Since(s.rpcOldestRequestAt).Seconds()
	}()
	out["rpc_total_calls"] = func() int64 {
		s.rpcDiagMu.Lock()
		defer s.rpcDiagMu.Unlock()
		return s.rpcTotalCalls
	}()
	out["rpc_total_duration_seconds"] = func() float64 {
		s.rpcDiagMu.Lock()
		defer s.rpcDiagMu.Unlock()
		return s.rpcTotalDuration.Seconds()
	}()
	out["rpc_timeout_count"] = func() int64 {
		s.rpcDiagMu.Lock()
		defer s.rpcDiagMu.Unlock()
		return s.rpcTimeoutCount
	}()
	out["rpc_error_count"] = func() int64 {
		s.rpcDiagMu.Lock()
		defer s.rpcDiagMu.Unlock()
		return s.rpcErrorCount
	}()
	out["node_goroutine_count"] = runtime.NumGoroutine()
	for key, val := range lifecycleCounters {
		out["lifecycle_"+key] = val
	}
	for key, val := range yespowerCounters {
		out["yespower_"+key] = val
	}
	out["miner_state_generation"] = stateGen
	out["snapshot_consistent"] = snapshotConsistent
	out["diag_miner_status_active"] = s.minerStatusDiagActive.Load()
	out["diag_miner_status_total"] = s.minerStatusDiagTotal.Load()
	out["diag_miner_status_max"] = s.minerStatusDiagMax.Load()
	out["diag_net_hash_active"] = s.netHashDiagActive.Load()
	out["diag_net_hash_total"] = s.netHashDiagTotal.Load()
	out["diag_net_hash_max"] = s.netHashDiagMax.Load()
	dc := DiagCounters()
	for key, val := range dc {
		out["diag_"+key] = val
	}
	out["diag_bundle_count"] = atomic.LoadInt32(&diagBundleCount)
	out["diag_base_dir"] = diagBaseDir()
	for key, value := range safety.Fields() {
		out[key] = value
	}
	out["miner_state"] = runtimeState.State
	out["miner_state_reason"] = runtimeState.Reason
	out["miner_supervisor_action"] = runtimeState.SupervisorAction
	out["miner_invariant_violation"] = runtimeState.InvariantViolation
	out["active_mining"] = activeMining
	out["actual_worker_hashing"] = runtimeState.LiveHashing
	out["active_threads"] = liveThreads
	out["live_active_threads"] = liveThreads
	out["local_hashps"] = liveHashPS
	out["local_khps"] = liveHashPS / 1000
	out["local_hashps_live"] = liveHashPS
	out["local_khps_live"] = liveHashPS / 1000
	out["active_template_is_fresh"] = hasActiveTemplate && lastTemplateFresh
	out["active_template_refresh_due"] = hasActiveTemplate && lastTemplateRefreshDue
	out["active_template_stale_reason"] = lastTemplateStaleReason
	out["active_template_refresh_reason"] = lastTemplateRefreshReason
	out["active_template_prev_hash"] = lastTemplatePrevHash
	out["active_template_height"] = lastTemplateHeight
	return out
}

func isNormalMinerStopReason(s string) bool {
	normalized := strings.ToLower(strings.TrimSpace(s))
	return normalized == "rpc stopminer" || normalized == "rpc restartminer" || normalized == "stopminer" || normalized == "stopped" || normalized == "stopped by user" ||
		normalized == MinerStopUserStop || normalized == MinerStopUserForceStop || normalized == MinerStopRPCStopMiner || normalized == MinerStopSupervisorShutdown
}

func isHistoricalMinerRetryReason(s string) bool {
	normalized := strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(normalized, "stale tip") || strings.Contains(normalized, "retry") || strings.Contains(normalized, "refresh")
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func (s *Server) acceptedBlockStatuses(records []minerAcceptedRecord) ([]map[string]any, int64) {
	out := make([]map[string]any, 0, len(records))
	activeCount := int64(0)
	tip := s.chain.Tip()
	tipHeight := int32(-1)
	if tip != nil {
		tipHeight = tip.Height
	}
	for _, rec := range records {
		active := false
		confirmations := int32(0)
		status := "orphaned/reorged"
		if idx, err := s.chain.IndexByHeight(rec.Height); err == nil && idx != nil && idx.Hash == rec.Hash {
			active = true
			activeCount++
			if tipHeight >= rec.Height {
				confirmations = tipHeight - rec.Height + 1
			}
			status = "immature"
			if confirmations >= int32(chaincfg.CoinbaseMaturity) {
				status = "mature"
			}
		}
		out = append(out, map[string]any{
			"hash":                  rec.Hash,
			"height":                rec.Height,
			"accepted_at":           unixOrZero(rec.AcceptedAt),
			"accepted_active_chain": active,
			"active_chain":          active,
			"confirmations":         confirmations,
			"status":                status,
			"orphaned":              !active,
			"reorged":               !active,
			"payout_hash":           rec.PayoutHash,
			"coinbase_txid":         rec.CoinbaseTxID,
		})
	}
	return out, activeCount
}

func acceptedBlockHashes(records []map[string]any) []string {
	out := make([]string, 0, len(records))
	for _, rec := range records {
		if hash := strings.TrimSpace(fmt.Sprint(rec["hash"])); hash != "" {
			out = append(out, hash)
		}
	}
	return out
}

func acceptedBlockHeights(records []map[string]any) []int32 {
	out := make([]int32, 0, len(records))
	for _, rec := range records {
		switch v := rec["height"].(type) {
		case int32:
			out = append(out, v)
		case int:
			out = append(out, int32(v))
		case int64:
			out = append(out, int32(v))
		}
	}
	return out
}

func (s *Server) parseMinerStartOptions(params json.RawMessage, cfg config.MiningConfig) (threads int, stopAfter int64, peerRequired bool, err error) {
	threads = cfg.Threads
	stopAfter = cfg.StopAfterBlocks
	peerRequired = cfg.PeerRequired
	var args []json.RawMessage
	_ = json.Unmarshal(params, &args)
	if len(args) == 0 {
		return
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(args[0], &obj) == nil && len(obj) > 0 {
		if v, ok := obj["threads"]; ok {
			_ = json.Unmarshal(v, &threads)
		}
		if v, ok := obj["stop_after_blocks"]; ok {
			_ = json.Unmarshal(v, &stopAfter)
		}
		if v, ok := obj["peer_required"]; ok {
			_ = json.Unmarshal(v, &peerRequired)
		}
	} else {
		if err = json.Unmarshal(args[0], &threads); err != nil {
			return
		}
		if len(args) > 1 {
			_ = json.Unmarshal(args[1], &stopAfter)
		}
	}
	if threads <= 0 {
		err = fmt.Errorf("threads must be positive")
		return
	}
	if cfg.MaxThreads > 0 && threads > cfg.MaxThreads {
		err = fmt.Errorf("threads %d exceeds mining_max_threads %d", threads, cfg.MaxThreads)
		return
	}
	if stopAfter < 0 {
		err = fmt.Errorf("stop_after_blocks cannot be negative")
	}
	return
}

func (s *Server) startMiner(parent context.Context, params json.RawMessage) (any, *rpcError) {
	if s.policy.SeedNode {
		return nil, &rpcError{Code: -32603, Message: "mining disabled: node_role=seed runs full-node relay only"}
	}
	w := s.resolveWallet(parent)
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	threads, stopAfter, peerRequired, err := s.parseMinerStartOptions(params, cfg)
	if err != nil {
		return nil, &rpcError{Code: -32602, Message: "startminer options: " + err.Error()}
	}
	dest, err := s.resolveMiningDestination(w, cfg, true)
	if err != nil {
		return nil, &rpcError{Code: -32602, Message: err.Error()}
	}
	pubHash, err := hex.DecodeString(dest.PubKeyHashHex)
	if err != nil || len(pubHash) != 20 {
		return nil, &rpcError{Code: -32602, Message: "invalid mining_pubkey_hash"}
	}
	if health := s.chain.StorageHealth(); !health.OK {
		return nil, &rpcError{Code: -32603, Message: "mining refused: storage health failed: " + health.Error}
	}
	if peerRequired && (s.p2p == nil || s.p2p.PeerCount() == 0) {
		return nil, &rpcError{Code: -32603, Message: "mining refused: mining_peer_required=true and no peers are connected"}
	}
	safety := s.checkSafeToMine(w, cfg, true)
	if !safety.Safe {
		return nil, &rpcError{Code: -32603, Message: safety.Reason}
	}
	s.minerMu.Lock()
	if s.minerActive {
		activeThreads := s.minerThreads
		s.minerMu.Unlock()
		return map[string]any{"active_mining": true, "threads": activeThreads, "message": "miner already running"}, nil
	}
	minerCtx, cancel := context.WithCancel(context.Background())
	s.minerActive = true
	s.minerHashing = false
	s.minerStateGen++
	s.minerCancel = cancel
	s.minerThreads = threads
	s.minerBlocks = 0
	s.minerLastHash = ""
	s.minerLastError = ""
	s.minerPausedReason = ""
	s.minerLastStopReason = ""
	s.minerRequestedStopReason = ""
	s.minerStartedAt = time.Now()
	s.minerStopAfterBlocks = stopAfter
	s.minerRewardHash = strings.ToLower(dest.PubKeyHashHex)
	s.minerPeerRequired = peerRequired
	s.minerLocalHashPS = 0
	s.minerSessionHashes = 0
	s.minerLastNonce = 0
	s.minerWorkerEpochStartedAt = time.Time{}
	s.minerLastHashProgressTime = time.Time{}
	s.minerStaleBlocks = 0
	s.minerRejectedBlocks = 0
	s.minerLastStaleTime = time.Time{}
	s.minerLastStaleReason = ""
	s.minerLastTemplateTime = time.Time{}
	s.minerLastTemplateHeight = 0
	s.minerLastTemplatePrevHash = ""
	s.minerLastTemplateTipHeight = 0
	s.minerLastTemplateTipHash = ""
	s.minerLastTemplateFresh = false
	s.minerLastTemplateStaleReason = ""
	s.minerLastTemplateRefreshDue = false
	s.minerLastTemplateRefreshReason = ""
	s.minerLastTemplateRefreshAttempt = time.Time{}
	s.minerTemplateRefreshCount = 0
	s.minerStaleTemplateRefreshAttempts = 0
	s.minerStaleTemplateSkips = 0
	s.minerLastTemplateRefreshError = ""
	s.minerStaleRatePauseActive = false
	s.minerAcceptedRecords = nil
	s.minerSupervisorRestartAttempts = 0
	s.minerLastSupervisorCancelTime = time.Time{}
	s.minerLastRestartSuccessTime = time.Time{}
	s.minerLastRestartFailure = ""
	s.minerMu.Unlock()
	_ = config.AppendConfigLine(s.miningConfigPath(), "mining_enabled", "true")
	_ = config.AppendConfigLine(s.miningConfigPath(), "mining_threads", fmt.Sprint(threads))
	_ = config.AppendConfigLine(s.miningConfigPath(), "mining_stop_after_blocks", fmt.Sprint(stopAfter))
	_ = config.AppendConfigLine(s.miningConfigPath(), "mining_peer_required", fmt.Sprint(peerRequired))

	s.minerLoopWg.Add(1)
	go s.minerLoop(minerCtx, pubHash, threads)
	out := map[string]any{
		"active_mining":               true,
		"threads":                     threads,
		"stop_after_blocks":           stopAfter,
		"peer_required":               peerRequired,
		"mining_address":              dest.Address,
		"mining_reward_address":       dest.Address,
		"mining_pubkey_hash":          strings.ToLower(dest.PubKeyHashHex),
		"active_reward_hash":          strings.ToLower(dest.PubKeyHashHex),
		"mining_address_wallet_owned": dest.Owned,
		"owned_by_wallet":             dest.Owned,
		"external_payout_mode":        dest.External,
	}
	for key, value := range safety.Fields() {
		out[key] = value
	}
	return out, nil
}

func (s *Server) stopMiner(reason string) map[string]any {
	stopReason := normalizeMinerStopReason(reason)
	if stopReason == "" {
		stopReason = MinerStopRPCStopMiner
	}
	s.minerMu.Lock()
	active := s.minerActive
	cancel := s.minerCancel
	blocks := s.minerBlocks
	last := s.minerLastHash
	startedAt := s.minerStartedAt
	s.minerRequestedStopReason = stopReason
	if cancel != nil {
		cancel()
	}
	s.minerActive = false
	s.minerHashing = false
	s.minerStateGen++
	s.minerCancel = nil
	s.minerLastError = stopReason
	s.minerPausedReason = ""
	s.minerLastStopReason = stopReason
	s.minerLocalHashPS = 0
	s.minerMu.Unlock()
	s.minerLoopWg.Wait()
	_ = config.AppendConfigLine(s.miningConfigPath(), "mining_enabled", "false")
	uptime := int64(0)
	if !startedAt.IsZero() {
		uptime = int64(time.Since(startedAt).Seconds())
	}
	return map[string]any{"active_mining": false, "was_active": active, "session_blocks": blocks, "last_block_hash": last, "uptime_seconds": uptime, "reason": stopReason, "last_stop_reason": stopReason}
}

func (s *Server) benchmarkMiner(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	w := s.resolveWallet(ctx)
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	threads := cfg.Threads
	durationSeconds := int64(30)
	var args []json.RawMessage
	_ = json.Unmarshal(params, &args)
	if len(args) > 0 {
		if err := json.Unmarshal(args[0], &durationSeconds); err != nil {
			var obj map[string]json.RawMessage
			if json.Unmarshal(args[0], &obj) == nil {
				if v, ok := obj["duration_seconds"]; ok {
					_ = json.Unmarshal(v, &durationSeconds)
				}
				if v, ok := obj["threads"]; ok {
					_ = json.Unmarshal(v, &threads)
				}
			}
		}
	}
	if len(args) > 1 {
		_ = json.Unmarshal(args[1], &threads)
	}
	if durationSeconds <= 0 || durationSeconds > 300 {
		return nil, &rpcError{Code: -32602, Message: "benchmark duration must be 1..300 seconds"}
	}
	if threads <= 0 {
		return nil, &rpcError{Code: -32602, Message: "threads must be positive"}
	}
	if cfg.MaxThreads > 0 && threads > cfg.MaxThreads {
		return nil, &rpcError{Code: -32602, Message: fmt.Sprintf("threads %d exceeds mining_max_threads %d", threads, cfg.MaxThreads)}
	}
	dest, err := s.resolveMiningDestination(w, cfg, true)
	if err != nil {
		return nil, &rpcError{Code: -32602, Message: err.Error()}
	}
	pubHash, err := hex.DecodeString(dest.PubKeyHashHex)
	if err != nil || len(pubHash) != 20 {
		return nil, &rpcError{Code: -32602, Message: "invalid mining_pubkey_hash"}
	}
	res, err := mining.BenchmarkHashrate(ctx, s.chain, s.pool, pow.YespowerHasher{Personalization: s.chain.Params().YespowerPers}, pubHash, threads, time.Duration(durationSeconds)*time.Second)
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}
	liveBits := ""
	if tip := s.chain.Tip(); tip != nil {
		liveBits = fmt.Sprintf("%08x", tip.Bits)
	}

	return map[string]any{
		"duration_seconds":        res.DurationSeconds,
		"threads":                 res.Threads,
		"hashes":                  res.Hashes,
		"local_hashps":            res.HashPS,
		"local_khps":              res.HashPS / 1000,
		"hashes_per_thread":       res.HashesPerThread,
		"last_nonce":              res.LastNonce,
		"current_bits":            liveBits,
		"benchmark_template_bits": fmt.Sprintf("%08x", res.CurrentBits),
		"note":                    "benchmark only; no block is connected",
	}, nil
}

func (s *Server) autoTuneMiner(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	maxThreads := cfg.MaxThreads
	if maxThreads <= 0 {
		maxThreads = cfg.Threads
	}
	if maxThreads <= 0 {
		maxThreads = 1
	}
	durationSeconds := int64(8)
	var args []json.RawMessage
	_ = json.Unmarshal(params, &args)
	if len(args) > 0 {
		_ = json.Unmarshal(args[0], &durationSeconds)
	}
	if durationSeconds <= 0 || durationSeconds > 120 {
		return nil, &rpcError{Code: -32602, Message: "autotune duration must be 1..120 seconds per level"}
	}
	levels := []int{maxThreads / 4, maxThreads / 2, (maxThreads * 3) / 4, maxThreads}
	seen := map[int]bool{}
	results := []map[string]any{}
	bestThreads := 1
	bestHPS := float64(-1)
	for _, threads := range levels {
		if threads < 1 {
			threads = 1
		}
		if threads > maxThreads {
			threads = maxThreads
		}
		if seen[threads] {
			continue
		}
		seen[threads] = true
		bench, rpcErr := s.benchmarkMiner(ctx, mustRawParams(fmt.Sprintf(`[%d,%d]`, durationSeconds, threads)))
		if rpcErr != nil {
			return nil, rpcErr
		}
		m := bench.(map[string]any)
		results = append(results, m)
		if hps, ok := m["local_hashps"].(float64); ok && hps > bestHPS {
			bestHPS = hps
			bestThreads = threads
		}
	}
	return map[string]any{"recommended_threads": bestThreads, "best_local_hashps": bestHPS, "results": results, "note": "use setminerthreads or startminer with recommended_threads"}, nil
}

func mustRawParams(s string) json.RawMessage { return json.RawMessage([]byte(s)) }

func (s *Server) setMinerThreads(params json.RawMessage) (any, *rpcError) {
	var args []int
	if err := json.Unmarshal(params, &args); err != nil || len(args) != 1 || args[0] <= 0 {
		return nil, &rpcError{Code: -32602, Message: "setminerthreads expects one positive integer"}
	}
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	if cfg.MaxThreads > 0 && args[0] > cfg.MaxThreads {
		return nil, &rpcError{Code: -32602, Message: fmt.Sprintf("threads %d exceeds mining_max_threads %d", args[0], cfg.MaxThreads)}
	}
	if err := config.AppendConfigLine(s.miningConfigPath(), "mining_threads", fmt.Sprint(args[0])); err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}
	return map[string]any{"configured_threads": args[0], "note": "restart miner for active thread change to take effect"}, nil
}

func (s *Server) configureMiner(w *wallet.Wallet, params json.RawMessage) (any, *rpcError) {
	var opts map[string]any
	if err := json.Unmarshal(params, &opts); err != nil || opts == nil {
		var args []json.RawMessage
		if err2 := json.Unmarshal(params, &args); err2 != nil || len(args) != 1 || json.Unmarshal(args[0], &opts) != nil {
			return nil, &rpcError{Code: -32602, Message: "configureminer expects an object or one object parameter"}
		}
	}
	set := map[string]any{}
	externalPayoutRequested := boolFromAny(opts["external_payout"]) || boolFromAny(opts["mining_external_payout"])
	for k, v := range opts {
		switch k {
		case "threads", "mining_threads":
			n := intFromAny(v)
			if n <= 0 {
				return nil, &rpcError{Code: -32602, Message: "threads must be positive"}
			}
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_threads", fmt.Sprint(n))
			set["threads"] = n
		case "max_threads", "mining_max_threads":
			n := intFromAny(v)
			if n <= 0 {
				return nil, &rpcError{Code: -32602, Message: "max_threads must be positive"}
			}
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_max_threads", fmt.Sprint(n))
			set["max_threads"] = n
		case "enabled", "mining_enabled":
			b := boolFromAny(v)
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_enabled", fmt.Sprint(b))
			set["enabled"] = b
		case "auto_start", "mining_auto_start":
			b := boolFromAny(v)
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_auto_start", fmt.Sprint(b))
			set["auto_start"] = b
		case "peer_required", "mining_peer_required":
			b := boolFromAny(v)
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_peer_required", fmt.Sprint(b))
			set["peer_required"] = b
		case "safe_required", "mining_safe_required":
			b := boolFromAny(v)
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_safe_required", fmt.Sprint(b))
			set["safe_required"] = b
		case "allow_unsafe", "mining_allow_unsafe":
			b := boolFromAny(v)
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_allow_unsafe", fmt.Sprint(b))
			set["allow_unsafe"] = b
		case "min_good_peers", "mining_min_good_peers":
			n := intFromAny(v)
			if n < 0 {
				return nil, &rpcError{Code: -32602, Message: "min_good_peers cannot be negative"}
			}
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_min_good_peers", fmt.Sprint(n))
			set["min_good_peers"] = n
		case "min_agreeing_peers", "mining_min_agreeing_peers":
			n := intFromAny(v)
			if n < 0 {
				return nil, &rpcError{Code: -32602, Message: "min_agreeing_peers cannot be negative"}
			}
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_min_agreeing_peers", fmt.Sprint(n))
			set["min_agreeing_peers"] = n
		case "peer_grace_seconds", "mining_peer_grace_seconds":
			n := intFromAny(v)
			if n < 0 {
				return nil, &rpcError{Code: -32602, Message: "peer_grace_seconds cannot be negative"}
			}
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_peer_grace_seconds", fmt.Sprint(n))
			set["peer_grace_seconds"] = n
		case "peer_recovery_seconds", "mining_peer_recovery_seconds":
			n := intFromAny(v)
			if n < 0 {
				return nil, &rpcError{Code: -32602, Message: "peer_recovery_seconds cannot be negative"}
			}
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_peer_recovery_seconds", fmt.Sprint(n))
			set["peer_recovery_seconds"] = n
		case "blocks_behind_allowed", "mining_blocks_behind_allowed":
			n := intFromAny(v)
			if n < 0 {
				return nil, &rpcError{Code: -32602, Message: "blocks_behind_allowed cannot be negative"}
			}
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_blocks_behind_allowed", fmt.Sprint(n))
			set["blocks_behind_allowed"] = n
		case "reject_unsafe_templates", "mining_reject_unsafe_templates":
			b := boolFromAny(v)
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_reject_unsafe_templates", fmt.Sprint(b))
			set["reject_unsafe_templates"] = b
		case "stop_after_blocks", "mining_stop_after_blocks":
			n := intFromAny(v)
			if n < 0 {
				return nil, &rpcError{Code: -32602, Message: "stop_after_blocks cannot be negative"}
			}
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_stop_after_blocks", fmt.Sprint(n))
			set["stop_after_blocks"] = n
		case "pubkey_hash", "mining_pubkey_hash":
			str := strings.ToLower(fmt.Sprint(v))
			if err := validateMiningPubKeyHash(str); err != nil {
				return nil, &rpcError{Code: -32602, Message: err.Error()}
			}
			addr := walletClassicAddressForHash(w, str)
			if addr == "" && !externalPayoutRequested {
				return nil, &rpcError{Code: -32602, Message: unownedMiningDestinationMessage}
			}
			if addr != "" {
				info := wallet.MiningAddressInfo{Address: addr, PubKeyHashHex: str}
				if err := s.persistMiningDestination(info); err != nil {
					return nil, &rpcError{Code: -32603, Message: err.Error()}
				}
				set["mining_reward_address"] = addr
				set["external_payout"] = false
			} else {
				_ = config.AppendConfigLine(s.miningConfigPath(), "mining_pubkey_hash", str)
				_ = config.AppendConfigLine(s.miningConfigPath(), "mining_external_payout", "true")
				set["external_payout"] = true
			}
			set["mining_pubkey_hash"] = str
		case "address", "mining_address", "mining_reward_address":
			addr := strings.TrimSpace(fmt.Sprint(v))
			hashHex, err := classicAddressHashHex(addr)
			if err != nil {
				return nil, &rpcError{Code: -32602, Message: "invalid mining address"}
			}
			owned := walletOwnsClassicAddress(w, addr)
			if !owned && !externalPayoutRequested {
				return nil, &rpcError{Code: -32602, Message: unownedMiningDestinationMessage}
			}
			if owned {
				info := wallet.MiningAddressInfo{Address: addr, PubKeyHashHex: hashHex}
				if err := s.persistMiningDestination(info); err != nil {
					return nil, &rpcError{Code: -32603, Message: err.Error()}
				}
				set["external_payout"] = false
			} else {
				_ = config.AppendConfigLine(s.miningConfigPath(), "mining_reward_address", addr)
				_ = config.AppendConfigLine(s.miningConfigPath(), "mining_pubkey_hash", hashHex)
				_ = config.AppendConfigLine(s.miningConfigPath(), "mining_external_payout", "true")
				set["external_payout"] = true
			}
			set["mining_reward_address"] = addr
			set["mining_pubkey_hash"] = hashHex
		case "external_payout", "mining_external_payout":
			b := boolFromAny(v)
			_ = config.AppendConfigLine(s.miningConfigPath(), "mining_external_payout", fmt.Sprint(b))
			set["external_payout"] = b
		default:
			return nil, &rpcError{Code: -32602, Message: "unknown miner option: " + k}
		}
	}
	cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
	dest := s.miningDestinationStatus(w, cfg)
	return map[string]any{"updated": set, "config": s.miningConfigPath(), "miner": map[string]any{"threads": cfg.Threads, "max_threads": cfg.MaxThreads, "auto_start": cfg.AutoStart, "peer_required": cfg.PeerRequired, "safe_required": cfg.SafeRequired, "allow_unsafe": cfg.AllowUnsafe, "min_good_peers": cfg.MinGoodPeers, "min_agreeing_peers": cfg.MinAgreeingPeers, "peer_grace_seconds": cfg.PeerGraceSeconds, "peer_recovery_seconds": cfg.PeerRecoverySeconds, "blocks_behind_allowed": cfg.BlocksBehindOK, "reject_unsafe_templates": cfg.RejectUnsafeGBT, "stop_after_blocks": cfg.StopAfterBlocks, "address": dest.Address, "pubkey_hash": dest.PubKeyHashHex, "wallet_owned": dest.Owned, "external_payout": dest.External, "destination_error": dest.Error}}, nil
}

func hashesPerThread(total float64, threads int) float64 {
	if threads <= 0 {
		return 0
	}
	return total / float64(threads)
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(n))
		return i
	default:
		return 0
	}
}

func boolFromAny(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		s := strings.ToLower(strings.TrimSpace(b))
		return s == "1" || s == "true" || s == "yes" || s == "on"
	case float64:
		return b != 0
	default:
		return false
	}
}

func staleTemplateSafetyBlock(status MiningSafetyStatus) bool {
	if status.Safe || !status.HasActiveTemplate {
		return false
	}
	if !status.ActiveTemplateFresh {
		return true
	}
	if status.CurrentTemplateHeight > 0 && status.CurrentTipHeight >= 0 && status.CurrentTemplateHeight != status.CurrentTipHeight+1 {
		return true
	}
	return status.ActiveTemplatePrevHash != "" && status.CurrentTipHash != "" && status.ActiveTemplatePrevHash != status.CurrentTipHash
}

func (s *Server) miningPeerDiagnostics(localHeight int32) (map[string]int, []map[string]any) {
	reasonCounts := map[string]int{}
	if s == nil || s.p2p == nil {
		return reasonCounts, nil
	}
	peers := s.p2p.PeerInfos()
	rows := make([]map[string]any, 0, len(peers))
	for _, peer := range peers {
		reason := strings.TrimSpace(peer.GoodPeerReason)
		category := strings.TrimSpace(peer.PeerSafetyCategory)
		if category == "" {
			category = "unknown"
		}
		if reason == "" {
			if peer.GoodPeer {
				reason = "current enough"
			} else {
				reason = "not reliable for mining yet"
			}
		}
		if !peer.GoodPeer {
			reasonCounts[reason]++
		}
		lag := peer.LagFromLocalHeight
		if lag == 0 && localHeight >= 0 && peer.ReportedHeight > 0 {
			lag = localHeight - peer.ReportedHeight
		}
		rows = append(rows, map[string]any{
			"address":                          peer.Addr,
			"direction":                        peer.Direction,
			"good_peer":                        peer.GoodPeer,
			"good_peer_reason":                 reason,
			"peer_safety_category":             category,
			"peer_safety_reason":               peer.PeerSafetyReason,
			"peer_quality":                     peer.PeerQuality,
			"reported_height":                  peer.ReportedHeight,
			"lag_from_local_height":            lag,
			"stale":                            peer.Stale,
			"missed_pongs":                     peer.MissedPongs,
			"ping_latency_ms":                  peer.PingLatencyMS,
			"last_sync_error":                  peer.LastSyncError,
			"last_block_reject":                peer.LastBlockReject,
			"last_seen_ago_seconds":            peer.LastSeenAgoSeconds,
			"last_height_update_ago_seconds":   peer.LastHeightUpdateAgoSeconds,
			"last_sync_request_ago_seconds":    peer.LastSyncRequestAgoSeconds,
			"last_header_received_ago_seconds": peer.LastHeaderReceivedAgoSeconds,
			"last_block_received_ago_seconds":  peer.LastBlockReceivedAgoSeconds,
		})
	}
	return reasonCounts, rows
}

func (s *Server) clearValidTemplateStateIfCurrent(templateHeight int32, templatePrevHash string, templateAt time.Time) {
	s.minerMu.Lock()
	defer s.minerMu.Unlock()
	if s.minerLastTemplateHeight != templateHeight || s.minerLastTemplatePrevHash != templatePrevHash || !s.minerLastTemplateTime.Equal(templateAt) {
		return
	}
	s.minerLastTemplateFresh = true
	s.minerLastTemplateStaleReason = ""
	s.minerLastTemplateRefreshDue = false
	s.minerLastTemplateRefreshReason = ""
	s.minerLastTemplateRefreshError = ""
	s.minerTemplateRecoveryPending = false
	s.minerTemplateRecoveryStartedAt = time.Time{}
}

func (s *Server) markStaleTemplateRefreshLocked(staleReason string, incrementSkip bool) {
	now := time.Now()
	staleReason = strings.TrimSpace(staleReason)
	if staleReason == "" {
		staleReason = "template is stale"
	}
	s.minerHashing = false
	s.minerLocalHashPS = 0
	s.minerLastTemplateFresh = false
	s.minerLastTemplateStaleReason = staleReason
	s.minerLastTemplateRefreshDue = true
	s.minerLastTemplateRefreshReason = staleTemplateRefreshReason(staleReason)
	s.minerLastTemplateRefreshError = ""
	s.minerLastTemplateRefreshAttempt = now
	s.minerTemplateRecoveryPending = true
	if s.minerTemplateRecoveryStartedAt.IsZero() {
		s.minerTemplateRecoveryStartedAt = now
	}
	if now.Sub(s.minerTemplateRecoveryStartedAt) > miningTemplateRecoveryTimeout() {
		s.minerLastTemplateRefreshReason = "template_refresh_failed"
		s.minerLastTemplateRefreshError = "template_refresh_failed: recovery timeout waiting for fresh block template"
	}
	s.minerStaleTemplateRefreshAttempts++
	if incrementSkip {
		s.minerStaleTemplateSkips++
	}
}

func (s *Server) markAcceptedBlockTemplateRefreshLocked() {
	now := time.Now()
	s.minerLastTemplateRefreshDue = true
	s.minerLastTemplateRefreshReason = "accepted_block_refresh: accepted block connected; refreshing template for new tip"
	s.minerLastTemplateRefreshAttempt = now
	s.minerLastTemplateRefreshError = ""
	s.minerLastTemplateFresh = false
	s.minerLastTemplateStaleReason = "accepted block connected; template belongs to previous tip"
	s.minerTemplateRecoveryPending = true
	if s.minerTemplateRecoveryStartedAt.IsZero() {
		s.minerTemplateRecoveryStartedAt = now
	}
	s.minerStaleTemplateRefreshAttempts++
}

func (s *Server) minerLoop(ctx context.Context, pubHash []byte, threads int) {
	exitStopReason := MinerStopWorkerExitUnexpected
	defer func() {
		s.minerLoopWg.Done()
		s.minerMu.Lock()
		if requested := strings.TrimSpace(s.minerRequestedStopReason); requested != "" {
			exitStopReason = requested
		}
		if exitStopReason == "" {
			exitStopReason = MinerStopWorkerExitUnexpected
		}
		s.minerActive = false
		s.minerHashing = false
		s.minerCancel = nil
		s.minerLocalHashPS = 0
		s.minerRequestedStopReason = ""
		s.minerLastStopReason = normalizeMinerStopReason(exitStopReason)
		if s.minerLastStopReason == "" {
			s.minerLastStopReason = MinerStopWorkerExitUnexpected
		}
		if minerStopReasonIsUnexpected(s.minerLastStopReason) && strings.TrimSpace(s.minerLastError) == "" {
			s.minerLastError = "Mining stopped unexpectedly: worker exited without an intentional stop request."
		}
		s.minerMu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			exitStopReason = MinerStopNodeShutdown
			return
		default:
		}
		s.minerMu.Lock()
		peerRequired := s.minerPeerRequired
		stopAfter := s.minerStopAfterBlocks
		blocks := s.minerBlocks
		s.minerMu.Unlock()
		if stopAfter > 0 && blocks >= stopAfter {
			s.minerMu.Lock()
			s.minerLastError = "stopped after requested block limit"
			s.minerPausedReason = ""
			s.minerLastStopReason = MinerStopSupervisorShutdown
			s.minerHashing = false
			s.minerStateGen++
			s.minerLocalHashPS = 0
			s.minerMu.Unlock()
			exitStopReason = MinerStopSupervisorShutdown
			return
		}
		if peerRequired && (s.p2p == nil || s.p2p.PeerCount() == 0) {
			s.minerMu.Lock()
			s.minerLastError = "Mining blocked: node has no peers."
			s.minerPausedReason = s.minerLastError
			s.minerHashing = false
			s.minerStateGen++
			s.minerLocalHashPS = 0
			s.minerMu.Unlock()
			timer := time.NewTimer(3 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				exitStopReason = MinerStopUnsafePeers
				return
			case <-timer.C:
			}
			continue
		}
		if health := s.chain.StorageHealth(); !health.OK {
			s.minerMu.Lock()
			s.minerLastError = "stopped: storage health failed: " + health.Error
			s.minerPausedReason = s.minerLastError
			s.minerLastStopReason = MinerStopInternalError
			s.minerHashing = false
			s.minerStateGen++
			s.minerLocalHashPS = 0
			s.minerMu.Unlock()
			exitStopReason = MinerStopInternalError
			return
		}
		cfg, _ := config.LoadMiningConfig(s.miningConfigPath())
		if safety := s.checkSafeToMine(s.defaultWallet(), cfg, false); !safety.Safe {
			if staleTemplateSafetyBlock(safety) {
				staleReason := strings.TrimSpace(safety.ActiveTemplateStaleReason)
				if staleReason == "" {
					staleReason = safety.Reason
				}
				s.minerMu.Lock()
				s.markStaleTemplateRefreshLocked(staleReason, true)
				s.minerLastError = ""
				s.minerPausedReason = ""
				s.minerMu.Unlock()
			} else {
				pausedForHighStale := strings.Contains(strings.ToLower(safety.Reason), "high stale rate")
				s.minerMu.Lock()
				s.minerLastError = safety.Reason
				s.minerPausedReason = safety.Reason
				s.minerHashing = false
				s.minerStateGen++
				s.minerLocalHashPS = 0
				s.minerMu.Unlock()
				retryDelay := 3 * time.Second
				if pausedForHighStale {
					retryDelay = 15 * time.Second
				}
				timer := time.NewTimer(retryDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				if pausedForHighStale {
					s.minerMu.Lock()
					s.minerStaleRatePauseActive = false
					s.minerStaleBlocks = 0
					s.minerRejectedBlocks = 0
					s.minerLastTemplateTime = time.Time{}
					s.minerLastTemplateHeight = 0
					s.minerLastTemplatePrevHash = ""
					s.minerLastTemplateFresh = false
					s.minerLastTemplateRefreshDue = false
					s.minerLastTemplateRefreshReason = ""
					s.minerLastTemplateStaleReason = "refreshing after high stale rate"
					s.minerLastTemplateRefreshError = "high stale rate pause completed; refreshing template"
					s.minerMu.Unlock()
				}
				continue
			}
		}
		templateHeight := int32(-1)
		templatePrevHash := ""
		templateTipHeight := int32(-1)
		templateTipHash := ""
		if tip := s.chain.Tip(); tip != nil {
			templateHeight = tip.Height + 1
			templatePrevHash = tip.Hash
			templateTipHeight = tip.Height
			templateTipHash = tip.Hash
		}
		s.minerMu.Lock()
		s.minerLastTemplateTime = time.Now()
		s.minerLastTemplateHeight = templateHeight
		s.minerLastTemplatePrevHash = templatePrevHash
		s.minerLastTemplateTipHeight = templateTipHeight
		s.minerLastTemplateTipHash = templateTipHash
		s.minerLastTemplateFresh = templateHeight == templateTipHeight+1 && templatePrevHash != ""
		s.minerLastTemplateStaleReason = ""
		s.minerLastTemplateRefreshDue = false
		s.minerLastTemplateRefreshReason = ""
		s.minerLastTemplateRefreshError = ""
		s.minerTemplateRecoveryPending = false
		s.minerTemplateRecoveryStartedAt = time.Time{}
		s.minerTemplateRefreshCount++
		epochBaseHashes := s.minerSessionHashes
		s.minerWorkerEpochStartedAt = time.Now()
		if isTransientMinerRecoveryReason(s.minerLastError) || isTransientMinerRecoveryReason(s.minerPausedReason) {
			s.minerLastError = ""
			s.minerPausedReason = ""
		}
		s.minerPausedReason = ""
		s.minerHashing = true
		s.minerStateGen++
		s.minerLastRestartSuccessTime = time.Now()
		s.minerLastRestartFailure = ""
		s.minerMu.Unlock()
		result, err := mining.MineBlock(ctx, s.chain, s.pool, pow.YespowerHasher{Personalization: s.chain.Params().YespowerPers}, pubHash, threads, func(p mining.Progress) {
			s.minerMu.Lock()
			if p.Attempts > 0 {
				s.minerLocalHashPS = p.Rate
				s.minerSessionHashes = epochBaseHashes + p.Attempts
				s.minerLastNonce = p.Nonce
				s.minerLastHashProgressTime = time.Now()
			}
			if p.TemplateHeight > 0 {
				s.minerLastTemplateHeight = p.TemplateHeight
				s.minerTemplateRecoveryPending = false
				s.minerTemplateRecoveryStartedAt = time.Time{}
			}
			if strings.TrimSpace(p.TemplatePrevHash) != "" {
				s.minerLastTemplatePrevHash = p.TemplatePrevHash
			}
			s.minerLastTemplateFresh = p.TemplateFresh
			s.minerLastTemplateRefreshDue = p.TemplateRefreshDue
			s.minerLastTemplateStaleReason = p.TemplateStaleReason
			s.minerLastTemplateRefreshReason = p.TemplateRefreshReason
			if p.TemplateFresh {
				s.minerLastTemplateStaleReason = ""
				if !p.TemplateRefreshDue {
					s.minerLastTemplateRefreshReason = ""
					s.minerLastTemplateRefreshError = ""
				}
			}
			s.minerMu.Unlock()
		})
		if err != nil {
			if stopReason, shouldExit := classifyMinerContextCancellation(err, ctx); stopReason != "" {
				s.minerMu.Lock()
				s.minerHashing = false
				s.minerStateGen++
				s.minerLocalHashPS = 0
				if !shouldExit {
					s.minerLastError = MinerStopSupervisorCancelled + ": mining worker epoch cancelled; restarting workers."
					s.minerPausedReason = "Mining worker epoch cancelled unexpectedly; restarting workers."
					s.minerSupervisorRestartAttempts++
					s.minerLastSupervisorCancelTime = time.Now()
					s.minerLastRestartFailure = ""
				}
				s.minerMu.Unlock()
				if shouldExit {
					exitStopReason = stopReason
					return
				}
				timer := time.NewTimer(500 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					exitStopReason = MinerStopNodeShutdown
					return
				case <-timer.C:
				}
				continue
			}
			if errors.Is(err, mining.ErrTemplateRefreshRequired) {
				s.minerMu.Lock()
				s.minerLastError = ""
				s.minerPausedReason = ""
				s.minerLastTemplateRefreshDue = true
				s.minerLastTemplateRefreshReason = strings.TrimPrefix(err.Error(), mining.ErrTemplateRefreshRequired.Error()+": ")
				if strings.TrimSpace(s.minerLastTemplateRefreshReason) == "" {
					s.minerLastTemplateRefreshReason = "refreshing template in background; current template still valid"
				}
				s.minerLastTemplateRefreshAttempt = time.Now()
				s.minerLastTemplateRefreshError = ""
				s.minerTemplateRecoveryPending = true
				if s.minerTemplateRecoveryStartedAt.IsZero() {
					s.minerTemplateRecoveryStartedAt = s.minerLastTemplateRefreshAttempt
				}
				s.minerHashing = true
				s.minerStateGen++
				s.minerMu.Unlock()
				continue
			}
			s.minerMu.Lock()
			s.minerHashing = false
			s.minerStateGen++
			s.minerLocalHashPS = 0
			s.minerMu.Unlock()
			if errors.Is(err, mining.ErrStaleTemplate) {
				s.minerMu.Lock()
				staleReason := strings.TrimPrefix(err.Error(), mining.ErrStaleTemplate.Error()+": ")
				s.markStaleTemplateRefreshLocked(staleReason, true)
				s.minerLastError = ""
				s.minerPausedReason = ""
				s.minerMu.Unlock()
				timer := time.NewTimer(250 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					exitStopReason = MinerStopNodeShutdown
					return
				case <-timer.C:
				}
				continue
			}
			s.minerMu.Lock()
			refreshingTemplate := s.minerTemplateRecoveryPending
			s.minerMu.Unlock()
			if refreshingTemplate && !errors.Is(err, blockchain.ErrBadPrevBlock) {
				s.minerMu.Lock()
				s.minerLastError = "template_refresh_failed: " + err.Error()
				s.minerPausedReason = "Mining paused: template refresh failed; retrying with the current tip."
				s.minerLastTemplateRefreshDue = true
				s.minerLastTemplateRefreshError = s.minerLastError
				s.minerLastTemplateRefreshReason = "template_refresh_failed"
				s.minerLastTemplateRefreshAttempt = time.Now()
				s.minerHashing = false
				s.minerStateGen++
				s.minerLocalHashPS = 0
				s.minerMu.Unlock()
				timer := time.NewTimer(3 * time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					exitStopReason = MinerStopNodeShutdown
					return
				case <-timer.C:
				}
				continue
			}
			if errors.Is(err, blockchain.ErrBadPrevBlock) {
				s.minerMu.Lock()
				s.minerLastError = "stale tip retry"
				s.minerStaleBlocks++
				s.minerLastStaleTime = time.Now()
				s.minerLastStaleReason = "stale tip retry"
				if staleRate(s.minerBlocks, s.minerStaleBlocks, s.minerRejectedBlocks) >= minerStalePauseRate {
					s.minerStaleRatePauseActive = true
					s.minerPausedReason = "Mining paused: repeated stale-tip retries."
				}
				s.minerMu.Unlock()
				continue
			}
			s.minerMu.Lock()
			s.minerLastError = "worker_exit_unexpected: " + err.Error()
			s.minerPausedReason = "Mining worker exited unexpectedly; restarting workers."
			s.minerRejectedBlocks++
			s.minerSupervisorRestartAttempts++
			s.minerLastRestartFailure = err.Error()
			s.minerHashing = false
			s.minerStateGen++
			s.minerLocalHashPS = 0
			s.minerMu.Unlock()
			timer := time.NewTimer(1500 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				exitStopReason = MinerStopWorkerExitUnexpected
				return
			case <-timer.C:
			}
			continue
		}
		s.minerMu.Lock()
		s.minerHashing = false
		s.minerLocalHashPS = 0
		s.minerMu.Unlock()
		if s.p2p != nil {
			peers := len(s.p2p.PeerInfos())
			s.minerMu.Lock()
			s.minerLastLocalBlockAnnouncement = time.Now()
			s.minerLocalBlockAnnouncementPeers = peers
			s.minerMu.Unlock()
			s.p2p.AnnounceBlock(result.Hash)
		}
		s.minerMu.Lock()
		s.minerBlocks++
		if result.Block != nil {
			s.minerLastNonce = result.Block.Header.Nonce
		}
		s.minerLastHash = result.Hash.String()
		s.minerLastError = ""
		s.minerPausedReason = ""
		s.minerStaleRatePauseActive = false
		s.minerAcceptedRecords = append(s.minerAcceptedRecords, minerAcceptedRecord{
			Hash:         result.Hash.String(),
			Height:       result.Height,
			AcceptedAt:   time.Now(),
			PayoutHash:   strings.ToLower(hex.EncodeToString(pubHash)),
			CoinbaseTxID: coinbaseTxID(result.Block),
		})
		if len(s.minerAcceptedRecords) > 500 {
			s.minerAcceptedRecords = s.minerAcceptedRecords[len(s.minerAcceptedRecords)-250:]
		}
		s.minerLocalBlockGraceActive = true
		s.minerLocalBlockGraceStartedAt = time.Now()
		s.minerLocalBlockGraceHeight = result.Height
		s.minerLocalBlockGraceHash = result.Hash.String()
		s.markAcceptedBlockTemplateRefreshLocked()
		s.minerMu.Unlock()
	}
}

func staleRate(accepted, stale, rejected int64) float64 {
	total := accepted + stale + rejected
	if total <= 0 {
		return 0
	}
	return float64(stale) / float64(total)
}

// resolveSafePath resolves dest relative to base and ensures it stays within
// base (preventing directory traversal). Returns the cleaned absolute path.
func resolveSafePath(dest, base string) (string, error) {
	cleaned := filepath.Clean(dest)
	if !filepath.IsAbs(cleaned) {
		cleaned = filepath.Join(base, cleaned)
	}
	absDest, err := filepath.Abs(cleaned)
	if err != nil {
		return "", err
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absDest, absBase+string(os.PathSeparator)) && absDest != absBase {
		return "", fmt.Errorf("destination path is outside allowed directory")
	}
	return absDest, nil
}

func coinbaseTxID(block *wire.MsgBlock) string {
	if block == nil || len(block.Transactions) == 0 || block.Transactions[0] == nil {
		return ""
	}
	hash, err := block.Transactions[0].TxHash()
	if err != nil {
		return ""
	}
	return hash.String()
}
