package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/config"
	"legacycoin/legacy-go/internal/mempool"
	"legacycoin/legacy-go/internal/p2p"
	"legacycoin/legacy-go/internal/pow"
	"legacycoin/legacy-go/internal/rpc"
	"legacycoin/legacy-go/internal/storage"
	"legacycoin/legacy-go/internal/stratum"
	"legacycoin/legacy-go/internal/version"
	"legacycoin/legacy-go/internal/wallet"
)

type nodeLogWriter struct {
	cfg     config.LogConfig
	mu      sync.Mutex
	repeats map[string]int
	last    map[string]time.Time
}

func newNodeLogWriter(cfg config.LogConfig) *nodeLogWriter {
	return &nodeLogWriter{cfg: cfg, repeats: make(map[string]int), last: make(map[string]time.Time)}
}

func (w *nodeLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(bytes.TrimRight(p, "\r\n")))
	if line == "" {
		return len(p), nil
	}
	line = repairPrettyLogArtifacts(line, w.cfg.Emoji)
	if w.cfg.Mode != "pretty" {
		fmt.Fprintln(os.Stdout, line)
		return len(p), nil
	}
	if w.suppressPretty(line) {
		return len(p), nil
	}
	if strings.Contains(line, "DNS seed unavailable") || strings.Contains(line, "DNS seed warning repeated") {
		w.writeSuppressed(line, "seed")
		return len(p), nil
	}
	fmt.Fprintln(os.Stdout, repairPrettyLogArtifacts(prettyLine(line, w.cfg.Emoji), w.cfg.Emoji))
	return len(p), nil
}

func (w *nodeLogWriter) suppressPretty(line string) bool {
	// Hide low-level P2P trace noise in normal pretty mode. Debug/plain mode keeps it.
	drop := []string{
		"p2p send getheaders", "p2p send getblocks", "p2p received inv block",
		"p2p received inv tx", "p2p sent getdata", "p2p received getdata block",
		"p2p sent block", "p2p serve ", "p2p no block inventory",
		"p2p request ", "p2p parse ", "p2p ignore ", "p2p handshake complete",
		"p2p connected block", "p2p accepted block from", "p2p announced block",
		"p2p announced tx", "p2p seed ", "p2p add seed peer",
	}
	for _, pat := range drop {
		if strings.Contains(line, pat) {
			return true
		}
	}
	return false
}

func (w *nodeLogWriter) writeSuppressed(line, key string) {
	if !w.cfg.SuppressRepeatedWarnings {
		fmt.Fprintln(os.Stdout, repairPrettyLogArtifacts(prettyLine(line, w.cfg.Emoji), w.cfg.Emoji))
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	w.repeats[key]++
	if w.repeats[key] == 1 || now.Sub(w.last[key]) >= 5*time.Minute {
		w.last[key] = now
		if w.repeats[key] == 1 {
			fmt.Fprintln(os.Stdout, repairPrettyLogArtifacts(prettyLine(line, w.cfg.Emoji), w.cfg.Emoji))
		} else {
			prefix := "[WARN]"
			if w.cfg.Emoji {
				prefix = "⚠️ [WARN]"
			}
			prefix = repairPrettyLogArtifacts(prefix, w.cfg.Emoji)
			fmt.Fprintf(os.Stdout, "[%s] %s DNS seed warnings repeated %d times | suppressing repeats for 5m\n", now.Format("15:04:05"), prefix, w.repeats[key])
		}
	}
}

func prettyLine(line string, emoji bool) string {
	if strings.HasPrefix(line, "20") || strings.HasPrefix(line, "19") {
		return line
	}
	if strings.Contains(line, "Peer connected") || strings.Contains(line, "Connected peer") {
		return withTime(line)
	}
	if strings.Contains(line, "Block accepted") || strings.Contains(line, "TX accepted") || strings.Contains(line, "TX relayed") || strings.Contains(line, "PONG") || strings.Contains(line, "PING") || strings.Contains(line, "DNS seed") || strings.Contains(line, "Peer rejected") {
		return withTime(line)
	}
	if strings.Contains(line, "Legacy Coin P2P listening") {
		if emoji {
			return withTime("🌐 [P2P] " + line)
		}
		return withTime("[P2P] " + line)
	}
	if strings.Contains(line, "rpc auth enabled") {
		if emoji {
			return withTime("🔐 [RPC] RPC cookie/auth enabled")
		}
		return withTime("[RPC] RPC cookie/auth enabled")
	}
	if strings.Contains(line, "configured bootstrap peers") {
		if emoji {
			return withTime("🌐 [P2P] " + line)
		}
		return withTime("[P2P] " + line)
	}
	return withTime(line)
}

func withTime(line string) string {
	return fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line)
}

func repairPrettyLogArtifacts(line string, emoji bool) string {
	repaired := strings.NewReplacer(
		"рџЊ±", "🌱",
		"рџ›ЎпёЏ", "🛡️",
		"рџљ«", "🚫",
		"рџЏ“", "📡",
		"рџџў", "🏓",
		"рџ’ё", "💸",
		"рџ“Ј", "📣",
		"рџЊђ", "🌐",
		"рџ”ђ", "🔐",
		"вњ…", "✅",
		"в†ђ", "←",
		"в†’", "→",
	).Replace(line)
	if emoji {
		return repaired
	}
	return strings.NewReplacer(
		"🌱 ", "",
		"🛡️ ", "",
		"🚫 ", "",
		"📡 ", "",
		"🏓 ", "",
		"💸 ", "",
		"📣 ", "",
		"🌐 ", "",
		"🔐 ", "",
		"✅ ", "",
		"⚠️ ", "",
	).Replace(repaired)
}

type Node struct {
	chain       *blockchain.Chain
	pool        *mempool.Pool
	wallets     map[string]*wallet.Wallet
	defaultWalletName string
	p2p         *p2p.Server
	auth        config.RPCAuth
	rpcBind     config.RPCBind
	p2pBind     config.P2PBind
	policy      config.LaunchPolicy
	interop     config.InteropReference
	logCfg      config.LogConfig
	peerPol     config.PeerPolicy
	paths       config.RuntimePaths
	stratum     *stratum.Server
	stratumAddr string
	rpcServer   *rpc.Server
}

func (n *Node) RPCServer() *rpc.Server { return n.rpcServer }

func New() (*Node, error) {
	return NewWithOptions(Options{Paths: config.DefaultRuntimePaths()})
}

type Options struct {
	Paths config.RuntimePaths
	// WalletNames forces loading specific named wallets at startup.
	// If empty, all wallets found in wallets/ are auto-loaded.
	WalletNames []string
}

func NewWithDataDir(dataDir string) (*Node, error) {
	return NewWithOptions(Options{Paths: config.RuntimePathsForDataDir(dataDir)})
}

func NewWithOptions(opts Options) (*Node, error) {
	paths := opts.Paths
	if strings.TrimSpace(paths.DataDir) == "" {
		paths = config.DefaultRuntimePaths()
	}
	if strings.TrimSpace(paths.ConfigPath) == "" {
		paths.ConfigPath = filepath.Join(paths.DataDir, config.ConfigFile)
	}

	params := chaincfg.MainNet
	if portOverride, err := config.LoadRuntimePortOverride(paths.ConfigPath); err == nil {
		if portOverride.P2P != 0 {
			params.DefaultPort = portOverride.P2P
		}
		if portOverride.RPC != 0 {
			params.RPCPort = portOverride.RPC
		}
	} else {
		return nil, fmt.Errorf("load runtime port override: %w", err)
	}

	store := storage.NewFileStore(paths.DataDir)
	indexCfg, err := config.LoadIndexConfig(paths.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load index config: %w", err)
	}
	store.SetIndexOptions(indexCfg.TxIndex, indexCfg.AddressIndex)
	chain, err := blockchain.New(params, pow.YespowerHasher{Personalization: params.YespowerPers}, store)
	if err != nil {
		return nil, err
	}
	w, err := wallet.Open(paths.DataDir)
	if err != nil {
		return nil, err
	}
	wallets := map[string]*wallet.Wallet{"default": w}
	walletNames := wallet.ListWalletDirs(paths.DataDir)
	if len(opts.WalletNames) > 0 {
		walletNames = opts.WalletNames
	}
	for _, name := range walletNames {
		if name == "default" {
			continue
		}
		if !config.IsWalletName(name) {
			continue
		}
		nw, err := wallet.OpenNamed(paths.DataDir, name)
		if err != nil {
			return nil, fmt.Errorf("load wallet %q: %w", name, err)
		}
		wallets[name] = nw
	}
	pool := mempool.New()
	logCfg, err := config.LoadLogConfig(paths.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load logging config: %w", err)
	}
	logger := log.New(newNodeLogWriter(logCfg), "", log.LstdFlags)
	p2pServer := p2p.New(params, chain, pool, logger)
	addnodes, err := config.LoadAddNodes(paths.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load config addnode entries: %w", err)
	}
	auth, err := config.LoadRPCAuth(paths.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load rpc auth config: %w", err)
	}
	if !auth.Enabled {
		cookieAuth, err := config.EnsureRPCCookieForDataDir(paths.DataDir)
		if err != nil {
			return nil, fmt.Errorf("create rpc cookie %s: %w", config.CookiePathForDataDir(paths.DataDir), err)
		}
		auth = cookieAuth
	}
	rpcBind, err := config.LoadRPCBindWithDataDir(paths.ConfigPath, paths.DataDir)
	if err != nil {
		return nil, fmt.Errorf("load rpc bind config: %w", err)
	}
	p2pBind, err := config.LoadP2PBind(paths.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load p2p bind config: %w", err)
	}
	policy, err := config.LoadLaunchPolicy(paths.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load launch policy config: %w", err)
	}
	interop, err := config.LoadInteropReference(paths.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load interoperability config: %w", err)
	}
	peerPol, err := config.LoadPeerPolicy(paths.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load peer policy config: %w", err)
	}
	if policy.SeedNode {
		if !isLocalhostBind(rpcBind.Host) {
			return nil, fmt.Errorf("unsafe seed-node configuration: rpcbind=%q must stay local", rpcBind.Host)
		}
		peerPol = applySeedNodePeerDefaults(peerPol)
	}
	chainID := peerPol.ChainID
	if chainID == "" {
		chainID = chaincfg.MainNet.ChainID
	}
	p2pServer.SetPeerPolicy(chainID, peerPol.EnforceChainID, peerPol.PeerSafety, peerPol.BanThreshold, peerPol.SeedPeers, peerPol.ConnectOnly)
	p2pServer.SetRuntimePolicy(peerPol.MaxInboundPeers, peerPol.TemporaryBanSeconds, peerPol.ReconnectBackoff, peerPol.ReconnectBackoffSeconds, peerPol.PeerRateLimit, peerPol.MaxPerIP, peerPol.MaxPerSubnet, peerPol.GlobalRateLimit, peerPol.MisbehaviorDecaySeconds, peerPol.StaleTimeoutSeconds)
	p2pServer.SetPrettyLogging(logCfg.Mode == "pretty", logCfg.P2PHeartbeat, logCfg.P2PCompactHeartbeat, logCfg.P2PShowLatency, logCfg.P2PShowPeerHeight, logCfg.TrustedPeerName, logCfg.P2PHeartbeatSeconds)
	p2pServer.SetPeerPingInterval(logCfg.PeerPingIntervalSeconds)
	bootstrap := append([]string{}, addnodes...)
	if len(peerPol.ConnectOnly) > 0 {
		seen := make(map[string]struct{}, len(bootstrap))
		for _, addr := range bootstrap {
			seen[strings.TrimSpace(addr)] = struct{}{}
		}
		for _, addr := range peerPol.ConnectOnly {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			bootstrap = append(bootstrap, addr)
		}
	}
	p2pServer.SetBootstrapPeers(bootstrap)
	p2pServer.SetListenHost(p2pBind.Host)
	if len(bootstrap) > 0 {
		logger.Printf("configured bootstrap peers: %d", len(bootstrap))
	}
	if policy.SeedNode {
		logger.Printf("node role seed active: rpc local, mining disabled, max inbound peers %d", peerPol.MaxInboundPeers)
	}
	if auth.Enabled {
		logger.Printf("rpc auth enabled")
	}
	if !isLocalhostBind(rpcBind.Host) {
		if !auth.Enabled {
			return nil, fmt.Errorf("unsafe rpc configuration: rpcbind=%q requires rpcuser and rpcpassword", rpcBind.Host)
		}
		if !rpcBind.TLS {
			return nil, fmt.Errorf("unsafe rpc configuration: rpcbind=%q requires rpctls=1 for non-local exposure", rpcBind.Host)
		}
		if rpcBind.TLSCert == "" || rpcBind.TLSKey == "" {
			return nil, fmt.Errorf("unsafe rpc configuration: rpctlscert and rpctlskey must be set when rpctls=1")
		}
		if _, err := os.Stat(rpcBind.TLSCert); err != nil {
			return nil, fmt.Errorf("rpc tls cert not readable: %w", err)
		}
		if _, err := os.Stat(rpcBind.TLSKey); err != nil {
			return nil, fmt.Errorf("rpc tls key not readable: %w", err)
		}
	}
	if err := validateInteropReference(chaincfg.MainNet, interop); err != nil {
		return nil, err
	}
	stratumCfg, err := config.LoadStratumConfig(paths.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load stratum config: %w", err)
	}
	var stratumServer *stratum.Server
	var stratumAddr string
	if stratumCfg.Enabled {
		stratumServer = stratum.New(params, chain, pool)
		stratumServer.SetShareDiff(stratumCfg.Diff)
		if stratumCfg.OperatorAddress != "" {
			if err := stratumServer.SetOperatorAddress(stratumCfg.OperatorAddress); err != nil {
				return nil, fmt.Errorf("stratum operator address: %w", err)
			}
		}
		stratumAddr = fmt.Sprintf("0.0.0.0:%d", stratumCfg.Port)
	}
	return &Node{chain: chain, pool: pool, wallets: wallets, defaultWalletName: "default", p2p: p2pServer, auth: auth, rpcBind: rpcBind, p2pBind: p2pBind, policy: policy, interop: interop, logCfg: logCfg, peerPol: peerPol, paths: paths, stratum: stratumServer, stratumAddr: stratumAddr}, nil
}

func isLocalhostBind(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	return h == "" || h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func applySeedNodePeerDefaults(p config.PeerPolicy) config.PeerPolicy {
	if p.MaxInboundPeers < 512 {
		p.MaxInboundPeers = 512
	}
	if p.MaxPerIP < 32 {
		p.MaxPerIP = 32
	}
	if p.MaxPerSubnet < 128 {
		p.MaxPerSubnet = 128
	}
	if p.PeerRateLimit < 500 {
		p.PeerRateLimit = 500
	}
	if p.GlobalRateLimit < 10_000 {
		p.GlobalRateLimit = 10_000
	}
	p.PeerSafety = true
	p.NoSeedNode = false
	p.SeedPeers = true
	return p
}

func validateInteropReference(params chaincfg.Params, ref config.InteropReference) error {
	if !ref.Enabled {
		return nil
	}
	if ref.GenesisHash != "" && !strings.EqualFold(ref.GenesisHash, params.GenesisHash) {
		return fmt.Errorf("interop mismatch: genesis hash %q != %q", params.GenesisHash, ref.GenesisHash)
	}
	if ref.MessageStart != "" {
		actual := strings.ToLower(hex.EncodeToString(params.MessageStart[:]))
		if actual != strings.ToLower(ref.MessageStart) {
			return fmt.Errorf("interop mismatch: message start %q != %q", actual, ref.MessageStart)
		}
	}
	if ref.P2PPort != 0 && ref.P2PPort != params.DefaultPort {
		return fmt.Errorf("interop mismatch: p2p port %d != %d", params.DefaultPort, ref.P2PPort)
	}
	if ref.RPCPort != 0 && ref.RPCPort != params.RPCPort {
		return fmt.Errorf("interop mismatch: rpc port %d != %d", params.RPCPort, ref.RPCPort)
	}
	return nil
}

func (n *Node) Run(ctx context.Context, cancel context.CancelFunc) error {
	if err := n.chain.EnsureGenesis(); err != nil {
		return fmt.Errorf("initialize chain: %w", err)
	}
	n.printStartupBanner()
	errc := make(chan error, 2)
	go func() {
		errc <- n.p2p.Start(ctx)
	}()
	fmt.Printf("Legacy Coin Go node listening on RPC port %d\n", n.chain.Params().RPCPort)
	server := rpc.NewMultiWallet(n.chain, n.pool, n.wallets, n.defaultWalletName, n.paths.DataDir, n.p2p, cancel, n.auth, n.rpcBind, n.policy, n.paths.ConfigPath)
	n.rpcServer = server
	go func() {
		errc <- server.ListenAndServe(ctx)
	}()
	if n.stratum != nil && n.stratumAddr != "" {
		go func() {
			if err := n.stratum.Start(n.stratumAddr); err != nil {
				log.Printf("[Stratum] start error: %v", err)
			}
		}()
	}
	err := <-errc
	cancel()
	if n.stratum != nil {
		n.stratum.Stop()
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *Node) Chain() *blockchain.Chain { return n.chain }

func (n *Node) Mempool() *mempool.Pool { return n.pool }

func (n *Node) Wallet() *wallet.Wallet { return n.wallets[n.defaultWalletName] }
func (n *Node) defaultWallet() *wallet.Wallet { return n.wallets[n.defaultWalletName] }

// WalletByName returns the named wallet. If name is empty, the default wallet is returned.
func (n *Node) WalletByName(name string) *wallet.Wallet {
	if name == "" {
		return n.wallets[n.defaultWalletName]
	}
	return n.wallets[name]
}

// WalletNames returns all loaded wallet names sorted.
func (n *Node) WalletNames() []string {
	names := make([]string, 0, len(n.wallets))
	for k := range n.wallets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// LoadWallet loads a named wallet at runtime from the wallets/ directory.
func (n *Node) LoadWallet(name string) error {
	if !config.IsWalletName(name) {
		return fmt.Errorf("invalid wallet name: %q", name)
	}
	if _, ok := n.wallets[name]; ok {
		return fmt.Errorf("wallet %q already loaded", name)
	}
	nw, err := wallet.OpenNamed(n.paths.DataDir, name)
	if err != nil {
		return err
	}
	n.wallets[name] = nw
	return nil
}

// UnloadWallet unloads a named wallet. The default wallet cannot be unloaded.
func (n *Node) UnloadWallet(name string) error {
	if name == "" {
		name = n.defaultWalletName
	}
	if name == n.defaultWalletName {
		return fmt.Errorf("cannot unload the default wallet")
	}
	if _, ok := n.wallets[name]; !ok {
		return fmt.Errorf("wallet %q not loaded", name)
	}
	delete(n.wallets, name)
	return nil
}

// CreateWallet creates a new named wallet directory and loads it.
func (n *Node) CreateWallet(name string) (*wallet.Wallet, error) {
	if !config.IsWalletName(name) {
		return nil, fmt.Errorf("invalid wallet name: %q", name)
	}
	if _, ok := n.wallets[name]; ok {
		return nil, fmt.Errorf("wallet %q already loaded", name)
	}
	nw, err := wallet.OpenNamed(n.paths.DataDir, name)
	if err != nil {
		return nil, err
	}
	n.wallets[name] = nw
	return nw, nil
}

// HasWallet reports whether a wallet with the given name is loaded.
func (n *Node) HasWallet(name string) bool {
	_, ok := n.wallets[name]
	return ok
}

func (n *Node) P2P() *p2p.Server { return n.p2p }

func (n *Node) RPCAuth() config.RPCAuth { return n.auth }

func (n *Node) RuntimePaths() config.RuntimePaths { return n.paths }

func (n *Node) printStartupBanner() {
	if n.logCfg.Mode != "pretty" {
		return
	}
	tip := n.chain.Tip()
	height := int32(-1)
	best := ""
	if tip != nil {
		height = tip.Height
		best = tip.Hash
	}
	storage := n.chain.StorageHealth()
	winfo := n.defaultWallet().SecurityInfo()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  🪙 Legacy Coin Node                                          ║")
	fmt.Println("║  onecpuonevote • Satoshi legacy • CPU-friendly PoW            ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Version      %-48s║\n", version.CoreFull())
	fmt.Printf("║  Chain        %-48s║\n", n.chain.Params().CoinName+" / "+n.chain.Params().Ticker)
	fmt.Printf("║  Chain ID     %-48s║\n", n.chain.Params().ChainID)
	fmt.Printf("║  Height       %-48d║\n", height)
	fmt.Printf("║  P2P          %-48d║\n", n.chain.Params().DefaultPort)
	fmt.Printf("║  RPC          %-48s║\n", n.rpcBind.Host+":"+fmt.Sprint(n.chain.Params().RPCPort))
	fmt.Printf("║  Wallet       encrypted=%t locked=%t [%d loaded]            ║\n", winfo["encrypted"], winfo["locked"], len(n.wallets))
	fmt.Printf("║  Storage      ok=%t                                         ║\n", storage.OK)
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	if best != "" {
		fmt.Printf("[BOOT] 🧱 Best block %s at height %d\n", best, height)
	}
	fmt.Println("[BOOT] 💾 Storage integrity checked.")
	if n.logCfg.P2PHeartbeat {
		fmt.Printf("[BOOT] 🏓 Pretty P2P heartbeat enabled every %ds.\n", n.logCfg.P2PHeartbeatSeconds)
	}
	fmt.Println("[BOOT] ✅ Legacy Coin node is ready.")
}
