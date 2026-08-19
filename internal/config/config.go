package config

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	AppName    = "LegacyCoin"
	ConfigFile = "legacycoin.conf"
)

func DefaultDataDir() string {
	if override := strings.TrimSpace(os.Getenv("LEGACYCOIN_DATADIR")); override != "" {
		return override
	}
	switch runtime.GOOS {
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, AppName)
		}
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Application Support", AppName)
		}
	default:
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".legacycoin")
		}
	}
	return "." + string(os.PathSeparator) + ".legacycoin"
}

func DefaultConfigPath() string {
	return filepath.Join(DefaultDataDir(), ConfigFile)
}

type RPCAuth struct {
	User     string
	Password string
	Enabled  bool
}

type RPCBind struct {
	Host    string
	TLS     bool
	TLSCert string
	TLSKey  string
}

type RuntimePaths struct {
	DataDir    string
	ConfigPath string
}

func DefaultRuntimePaths() RuntimePaths {
	dataDir := DefaultDataDir()
	return RuntimePaths{DataDir: dataDir, ConfigPath: filepath.Join(dataDir, ConfigFile)}
}

func RuntimePathsForDataDir(dataDir string) RuntimePaths {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return DefaultRuntimePaths()
	}
	return RuntimePaths{DataDir: dataDir, ConfigPath: filepath.Join(dataDir, ConfigFile)}
}

type P2PBind struct {
	Host string
}

type RuntimePortOverride struct {
	P2P uint16
	RPC uint16
}

type IndexConfig struct {
	TxIndex      bool
	AddressIndex bool
}

type LaunchPolicy struct {
	AllowScriptCoveragePending bool
	NodeRole                   string
	SeedNode                   bool
}

type InteropReference struct {
	Enabled      bool
	GenesisHash  string
	MessageStart string
	P2PPort      uint16
	RPCPort      uint16
}

func loadConfigKV(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	kv := make(map[string][]string)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	firstLine := true
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			line = strings.TrimPrefix(line, "\ufeff")
			firstLine = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		if key == "" || val == "" {
			continue
		}
		kv[key] = append(kv[key], val)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return kv, nil
}

func LoadAddNodes(path string) ([]string, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	nodes := make([]string, 0)
	for _, addr := range kv["addnode"] {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		nodes = append(nodes, addr)
	}
	return nodes, nil
}

func CookiePath() string {
	return filepath.Join(DefaultDataDir(), ".cookie")
}

func CookiePathForDataDir(dataDir string) string {
	return filepath.Join(dataDir, ".cookie")
}

func EnsureRPCCookie() (RPCAuth, error) {
	return EnsureRPCCookieForDataDir(DefaultDataDir())
}

func EnsureRPCCookieForDataDir(dataDir string) (RPCAuth, error) {
	path := CookiePathForDataDir(dataDir)
	if data, err := os.ReadFile(path); err == nil {
		parts := strings.SplitN(strings.TrimSpace(string(data)), ":", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return RPCAuth{User: parts[0], Password: parts[1], Enabled: true}, nil
		}
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return RPCAuth{}, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return RPCAuth{}, err
	}
	auth := RPCAuth{User: "__cookie__", Password: hex.EncodeToString(buf), Enabled: true}
	if err := os.WriteFile(path, []byte(auth.User+":"+auth.Password+"\n"), 0600); err != nil {
		return RPCAuth{}, err
	}
	return auth, nil
}

func LoadRPCCookie() (RPCAuth, error) {
	return LoadRPCCookieForDataDir(DefaultDataDir())
}

func LoadRPCCookieForDataDir(dataDir string) (RPCAuth, error) {
	data, err := os.ReadFile(CookiePathForDataDir(dataDir))
	if err != nil {
		return RPCAuth{}, err
	}
	parts := strings.SplitN(strings.TrimSpace(string(data)), ":", 2)
	if len(parts) != 2 {
		return RPCAuth{}, fmt.Errorf("invalid rpc cookie")
	}
	return RPCAuth{User: parts[0], Password: parts[1], Enabled: true}, nil
}

func LoadRPCAuth(path string) (RPCAuth, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return RPCAuth{}, err
	}
	var auth RPCAuth
	if vals := kv["rpcuser"]; len(vals) > 0 {
		auth.User = vals[len(vals)-1]
	}
	if vals := kv["rpcpassword"]; len(vals) > 0 {
		auth.Password = vals[len(vals)-1]
	}
	if auth.User == "" && auth.Password == "" {
		return auth, nil
	}
	if auth.User == "" || auth.Password == "" {
		return RPCAuth{}, fmt.Errorf("rpc auth requires both rpcuser and rpcpassword")
	}
	auth.Enabled = true
	return auth, nil
}

func LoadRPCBind(path string) (RPCBind, error) {
	return LoadRPCBindWithDataDir(path, DefaultDataDir())
}

func LoadRPCBindWithDataDir(path string, dataDir string) (RPCBind, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return RPCBind{}, err
	}
	bind := RPCBind{
		Host:    "127.0.0.1",
		TLS:     false,
		TLSCert: filepath.Join(dataDir, "rpc.cert"),
		TLSKey:  filepath.Join(dataDir, "rpc.key"),
	}
	if vals := kv["rpcbind"]; len(vals) > 0 {
		host := strings.TrimSpace(vals[len(vals)-1])
		if host != "" {
			bind.Host = host
		}
	}
	if vals := kv["rpctls"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		bind.TLS = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["rpctlscert"]; len(vals) > 0 {
		v := strings.TrimSpace(vals[len(vals)-1])
		if v != "" {
			bind.TLSCert = v
		}
	}
	if vals := kv["rpctlskey"]; len(vals) > 0 {
		v := strings.TrimSpace(vals[len(vals)-1])
		if v != "" {
			bind.TLSKey = v
		}
	}
	return bind, nil
}

func LoadP2PBind(path string) (P2PBind, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return P2PBind{}, err
	}
	bind := P2PBind{Host: ""}
	if vals := kv["bind"]; len(vals) > 0 {
		host := strings.TrimSpace(vals[len(vals)-1])
		if host != "" {
			bind.Host = host
		}
	}
	return bind, nil
}

func LoadRuntimePortOverride(path string) (RuntimePortOverride, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return RuntimePortOverride{}, err
	}
	out := RuntimePortOverride{}
	parsePort := func(values []string) uint16 {
		if len(values) == 0 {
			return 0
		}
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(values[len(values)-1]), "%d", &n)
		if n > 0 && n <= 65535 {
			return uint16(n)
		}
		return 0
	}
	if p := parsePort(kv["p2pport"]); p != 0 {
		out.P2P = p
	} else if p := parsePort(kv["port"]); p != 0 {
		out.P2P = p
	}
	out.RPC = parsePort(kv["rpcport"])
	return out, nil
}

func LoadIndexConfig(path string) (IndexConfig, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return IndexConfig{}, err
	}
	return IndexConfig{
		TxIndex:      boolFromKV(kv, "txindex", false),
		AddressIndex: boolFromKV(kv, "addressindex", false),
	}, nil
}

func LoadLaunchPolicy(path string) (LaunchPolicy, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return LaunchPolicy{}, err
	}
	p := LaunchPolicy{}
	if vals := kv["allow_script_coverage_pending"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		p.AllowScriptCoveragePending = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["node_role"]; len(vals) > 0 {
		p.NodeRole = strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
	}
	p.SeedNode = boolFromKV(kv, "seednode", p.NodeRole == "seed")
	if p.SeedNode {
		p.NodeRole = "seed"
	}
	return p, nil
}

func LoadInteropReference(path string) (InteropReference, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return InteropReference{}, err
	}
	ref := InteropReference{}
	if vals := kv["interop_check"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		ref.Enabled = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["interop_genesis_hash"]; len(vals) > 0 {
		ref.GenesisHash = strings.TrimSpace(vals[len(vals)-1])
	}
	if vals := kv["interop_message_start"]; len(vals) > 0 {
		ref.MessageStart = strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
	}
	if vals := kv["interop_p2p_port"]; len(vals) > 0 {
		var port int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &port)
		if port > 0 && port <= 65535 {
			ref.P2PPort = uint16(port)
		}
	}
	if vals := kv["interop_rpc_port"]; len(vals) > 0 {
		var port int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &port)
		if port > 0 && port <= 65535 {
			ref.RPCPort = uint16(port)
		}
	}
	return ref, nil
}

type LogConfig struct {
	Mode                     string
	Color                    bool
	Emoji                    bool
	P2PHeartbeat             bool
	P2PHeartbeatSeconds      int
	PeerPingIntervalSeconds  int
	P2PShowLatency           bool
	P2PShowPeerHeight        bool
	P2PCompactHeartbeat      bool
	SuppressRepeatedWarnings bool
	TrustedPeerName          string
}

func boolFromKV(kv map[string][]string, key string, def bool) bool {
	vals := kv[key]
	if len(vals) == 0 {
		return def
	}
	v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func LoadLogConfig(path string) (LogConfig, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return LogConfig{}, err
	}
	cfg := LogConfig{
		// Default to pretty console output for normal node operators.
		// Developers can set log_mode=debug or log_mode=plain for raw traces.
		Mode:                     "pretty",
		Color:                    true,
		Emoji:                    true,
		P2PHeartbeatSeconds:      60,
		PeerPingIntervalSeconds:  30,
		SuppressRepeatedWarnings: true,
	}
	if vals := kv["log_mode"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		switch v {
		case "plain", "pretty", "debug":
			cfg.Mode = v
		}
	}
	cfg.Color = boolFromKV(kv, "log_color", cfg.Color)
	cfg.Emoji = boolFromKV(kv, "log_emoji", cfg.Emoji)
	if vals := kv["pretty_logs"]; len(vals) > 0 {
		if boolFromKV(kv, "pretty_logs", cfg.Mode == "pretty") {
			cfg.Mode = "pretty"
		} else {
			cfg.Mode = "plain"
		}
	}
	if vals := kv["log_icons"]; len(vals) > 0 {
		cfg.Emoji = boolFromKV(kv, "log_icons", cfg.Emoji)
	}
	cfg.P2PHeartbeat = boolFromKV(kv, "p2p_heartbeat", cfg.Mode == "pretty")
	cfg.P2PShowLatency = boolFromKV(kv, "p2p_show_latency", cfg.Mode == "pretty")
	cfg.P2PShowPeerHeight = boolFromKV(kv, "p2p_show_peer_height", cfg.Mode == "pretty")
	cfg.P2PCompactHeartbeat = boolFromKV(kv, "p2p_compact_heartbeat", true)
	cfg.SuppressRepeatedWarnings = boolFromKV(kv, "suppress_repeated_warnings", cfg.SuppressRepeatedWarnings)
	if vals := kv["p2p_heartbeat_seconds"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n >= 10 {
			cfg.P2PHeartbeatSeconds = n
		}
	}
	if vals := kv["peer_ping_interval_seconds"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n >= 10 {
			cfg.PeerPingIntervalSeconds = n
		}
	}
	if vals := kv["trusted_peer_name"]; len(vals) > 0 {
		cfg.TrustedPeerName = strings.TrimSpace(vals[len(vals)-1])
	}
	return cfg, nil
}

type StratumConfig struct {
	Enabled         bool
	Port            int
	Diff            float64
	OperatorAddress string
}

func LoadStratumConfig(path string) (StratumConfig, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return StratumConfig{}, err
	}
	cfg := StratumConfig{Port: 3333, Diff: 1.0}
	cfg.Enabled = boolFromKV(kv, "stratum", false)
	if vals := kv["stratum_port"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 && n <= 65535 {
			cfg.Port = n
		}
	}
	if vals := kv["stratum_diff"]; len(vals) > 0 {
		var f float64
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%f", &f)
		if f > 0 {
			cfg.Diff = f
		}
	}
	if vals := kv["stratum_operator_address"]; len(vals) > 0 {
		cfg.OperatorAddress = strings.TrimSpace(vals[len(vals)-1])
	}
	return cfg, nil
}

type MiningConfig struct {
	Enabled             bool
	PubKeyHash          string
	RewardAddress       string
	Threads             int
	MaxThreads          int
	AutoStart           bool
	PeerRequired        bool
	SafeRequired        bool
	MinGoodPeers        int
	MinAgreeingPeers    int
	PeerGraceSeconds    int
	PeerRecoverySeconds int
	AllowUnsafe         bool
	BlocksBehindOK      int
	RejectUnsafeGBT     bool
	RejectZeroHash      bool
	ExternalPayout      bool
	StopAfterBlocks     int64
}

func LoadMiningConfig(path string) (MiningConfig, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return MiningConfig{}, err
	}
	cfg := MiningConfig{Threads: 1, MaxThreads: runtime.NumCPU(), PeerRequired: false, SafeRequired: true, MinGoodPeers: 3, MinAgreeingPeers: 2, PeerGraceSeconds: 90, PeerRecoverySeconds: 30, BlocksBehindOK: 1, RejectUnsafeGBT: true, RejectZeroHash: true}
	if vals := kv["mining_enabled"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		cfg.Enabled = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["mining_pubkey_hash"]; len(vals) > 0 {
		cfg.PubKeyHash = strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
	}
	if vals := kv["mining_reward_address"]; len(vals) > 0 {
		cfg.RewardAddress = strings.TrimSpace(vals[len(vals)-1])
	}
	if vals := kv["mining_threads"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			cfg.Threads = n
		}
	}
	if vals := kv["mining_max_threads"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			cfg.MaxThreads = n
		}
	}
	if cfg.MaxThreads < 1 {
		cfg.MaxThreads = 1
	}
	if cfg.Threads > cfg.MaxThreads {
		cfg.Threads = cfg.MaxThreads
	}
	if vals := kv["mining_auto_start"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		cfg.AutoStart = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["mining_peer_required"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		cfg.PeerRequired = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["mining_stop_after_blocks"]; len(vals) > 0 {
		var n int64
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			cfg.StopAfterBlocks = n
		}
	}
	if vals := kv["mining_safe_required"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		cfg.SafeRequired = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["mining_min_good_peers"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n >= 0 {
			cfg.MinGoodPeers = n
		}
	}
	if vals := kv["mining_min_agreeing_peers"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n >= 0 {
			cfg.MinAgreeingPeers = n
		}
	}
	if vals := kv["mining_peer_grace_seconds"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n >= 0 {
			cfg.PeerGraceSeconds = n
		}
	}
	if vals := kv["mining_peer_recovery_seconds"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n >= 0 {
			cfg.PeerRecoverySeconds = n
		}
	}
	if vals := kv["mining_blocks_behind_allowed"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n >= 0 {
			cfg.BlocksBehindOK = n
		}
	}
	if vals := kv["mining_allow_unsafe"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		cfg.AllowUnsafe = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["mining_reject_unsafe_templates"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		cfg.RejectUnsafeGBT = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["reject_zero_mining_hash"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		cfg.RejectZeroHash = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if vals := kv["mining_external_payout"]; len(vals) > 0 {
		v := strings.ToLower(strings.TrimSpace(vals[len(vals)-1]))
		cfg.ExternalPayout = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	return cfg, nil
}

// configMultiValueKeys are keys that legitimately may appear on many lines
// (peer lists). They are deduplicated by value rather than replaced.
var configMultiValueKeys = map[string]bool{
	"addnode": true,
	"connect": true,
}

// AppendConfigLine upserts a single key=value line into the config file.
//
// For scalar keys (everything except addnode/connect) every existing line with
// the same key is replaced by exactly one new line holding the new value, so
// repeated calls (e.g. mining RPC toggles) no longer make the file grow
// without bound.
//
// For multi-valued keys (addnode/connect) the new value is appended only if no
// existing line already has that exact value, so the same peer cannot be
// added many times.
func AppendConfigLine(path, key, value string) error {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" {
		return fmt.Errorf("AppendConfigLine: empty key")
	}
	// Reject empty or relative paths that could escape the data directory.
	cleanPath := filepath.Clean(path)
	if cleanPath == "" || cleanPath == "." || cleanPath == ".." {
		return fmt.Errorf("AppendConfigLine: invalid config path")
	}
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0700); err != nil {
		return err
	}
	lowerKey := strings.ToLower(key)
	multi := configMultiValueKeys[lowerKey]

	existing, err := os.ReadFile(cleanPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var out []string
	alreadyPresent := false
	for _, raw := range strings.Split(string(existing), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			out = append(out, raw)
			continue
		}
		kv := line
		if i := strings.IndexByte(kv, '#'); i >= 0 {
			kv = strings.TrimSpace(kv[:i])
		}
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			out = append(out, raw)
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[:eq]))
		v := strings.TrimSpace(kv[eq+1:])
		if k != lowerKey {
			out = append(out, raw)
			continue
		}
		if multi {
			if v == value {
				alreadyPresent = true
				out = append(out, raw) // keep existing duplicate, do not add again
			} else {
				out = append(out, raw) // keep other peer values
			}
			continue
		}
		// scalar key: drop the old line; a single fresh line is appended below
	}
	newLine := key + "=" + value
	if multi && alreadyPresent {
		// nothing to add; still normalise the file ending below
	} else {
		out = append(out, newLine)
	}
	joined := strings.Join(out, "\n")
	if !strings.HasSuffix(joined, "\n") {
		joined += "\n"
	}
	tmp := cleanPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(joined), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, cleanPath)
}

// WalletsDir returns the path to the wallets/ subdirectory inside the given data dir.
func WalletsDir(dataDir string) string {
	return filepath.Join(dataDir, "wallets")
}

// WalletDirForName returns the path for a named wallet directory inside dataDir/wallets/{name}.
func WalletDirForName(dataDir string, name string) string {
	return filepath.Join(WalletsDir(dataDir), filepath.Clean(name))
}

// IsWalletName validates that name is a safe single path component suitable for a wallet directory.
func IsWalletName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, "/\\") {
		return false
	}
	return filepath.Base(name) == name
}

type PeerPolicy struct {
	ChainID                 string
	EnforceChainID          bool
	PeerSafety              bool
	MaxInboundPeers         int
	MaxPerIP                int
	MaxPerSubnet            int
	BanThreshold            int
	TemporaryBanSeconds     int
	ReconnectBackoff        bool
	ReconnectBackoffSeconds int
	PeerRateLimit           int
	GlobalRateLimit         int
	MisbehaviorDecaySeconds int
	StaleTimeoutSeconds     int
	NoSeedNode              bool
	SeedPeers               bool
	ConnectOnly             []string
}

func LoadPeerPolicy(path string) (PeerPolicy, error) {
	kv, err := loadConfigKV(path)
	if err != nil {
		return PeerPolicy{}, err
	}
	p := PeerPolicy{
		PeerSafety:              true,
		MaxInboundPeers:         64,
		MaxPerIP:                8,
		MaxPerSubnet:            32,
		BanThreshold:            100,
		TemporaryBanSeconds:     3600,
		ReconnectBackoff:        true,
		ReconnectBackoffSeconds: 15,
		PeerRateLimit:           250,
		GlobalRateLimit:         3000,
		MisbehaviorDecaySeconds: 300,
		StaleTimeoutSeconds:     900,
		SeedPeers:               true,
	}
	if vals := kv["chain_id"]; len(vals) > 0 {
		p.ChainID = strings.TrimSpace(vals[len(vals)-1])
	}
	p.EnforceChainID = boolFromKV(kv, "chain_id_enforce", p.EnforceChainID)
	p.PeerSafety = boolFromKV(kv, "peer_safety", p.PeerSafety)
	p.ReconnectBackoff = boolFromKV(kv, "peer_reconnect_backoff", p.ReconnectBackoff)
	p.NoSeedNode = boolFromKV(kv, "noseednode", false)
	p.SeedPeers = boolFromKV(kv, "seed_peers", !p.NoSeedNode)
	if p.NoSeedNode {
		p.SeedPeers = false
	}
	if vals := kv["max_inbound_peers"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.MaxInboundPeers = n
		}
	}
	if vals := kv["peer_max_inbound"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.MaxInboundPeers = n
		}
	}
	if vals := kv["peer_max_per_ip"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.MaxPerIP = n
		}
	}
	if vals := kv["peer_max_per_subnet"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.MaxPerSubnet = n
		}
	}
	if vals := kv["peer_ban_threshold"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.BanThreshold = n
		}
	}
	if vals := kv["peer_ban_score_threshold"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.BanThreshold = n
		}
	}
	if vals := kv["peer_temp_ban_seconds"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.TemporaryBanSeconds = n
		}
	}
	if vals := kv["peer_ban_minutes"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.TemporaryBanSeconds = n * 60
		}
	}
	if vals := kv["peer_rate_limit"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.PeerRateLimit = n
		}
	}
	if vals := kv["peer_global_rate_limit"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.GlobalRateLimit = n
		}
	}
	if vals := kv["peer_reconnect_backoff_seconds"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n >= 0 {
			p.ReconnectBackoffSeconds = n
		}
	}
	if vals := kv["peer_misbehavior_decay_seconds"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.MisbehaviorDecaySeconds = n
		}
	}
	if vals := kv["peer_stale_timeout_seconds"]; len(vals) > 0 {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(vals[len(vals)-1]), "%d", &n)
		if n > 0 {
			p.StaleTimeoutSeconds = n
		}
	}
	for _, addr := range kv["connect"] {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			p.ConnectOnly = append(p.ConnectOnly, addr)
		}
	}
	for _, addr := range kv["connect_only"] {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			p.ConnectOnly = append(p.ConnectOnly, addr)
		}
	}
	return p, nil
}
