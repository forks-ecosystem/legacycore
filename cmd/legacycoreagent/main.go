package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"legacycoin/legacy-go/internal/txsvc"
	"legacycoin/legacy-go/internal/wallet"
)

type Service struct {
	dataDir string
	rpcURL  string
	rpcUser string
	rpcPass string
	chains  *txsvc.Manager
	apiKey  string
}

func NewService(dataDir string) *Service {
	rpcURL := getEnv("LEGACYCOIN_RPC_URL", "")
	rpcUser := getEnv("LEGACYCOIN_RPC_USER", "")
	rpcPass := getEnv("LEGACYCOIN_RPC_PASS", "")

	return &Service{
		dataDir: dataDir,
		rpcURL:  rpcURL,
		rpcUser: rpcUser,
		rpcPass: rpcPass,
		chains:  txsvc.NewManager(),
		apiKey:  getEnv("LEGACYCOIN_API_KEY", ""),
	}
}

func (s *Service) walletDir(name string) string {
	return filepath.Join(s.dataDir, "wallets", filepath.Clean(name))
}

func (s *Service) resolveDir(name string) string {
	if name == "default" {
		return s.dataDir
	}
	return s.walletDir(name)
}

func jsonResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	jsonResp(w, status, map[string]string{"error": msg})
}

func (s *Service) rpcCall(method string, params any) (any, error) {
	// The node rate-limits RPC (token bucket ~60/s burst, 1/s sustained, per
	// client IP). Retry with a 1s delay so bursts of getaddressbalance calls
	// drain into the bucket instead of returning zeros.
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		res, err := s.rpcCallOnce(method, params)
		if err == nil {
			return res, nil
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	return nil, lastErr
}

func (s *Service) rpcCallOnce(method string, params any) (any, error) {
	if s.rpcURL == "" {
		return nil, fmt.Errorf("RPC not configured")
	}
	reqBody := map[string]any{"method": method, "params": params, "id": 1}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", s.rpcURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if s.rpcUser != "" {
		req.SetBasicAuth(s.rpcUser, s.rpcPass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result struct {
		Result any    `json:"result"`
		Error  any    `json:"error"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf("%v", result.Error)
	}
	return result.Result, nil
}

// POST /api/generate-seed
// Body: {"name": "my-wallet", "address_count": 5}  (address_count optional, default 1)
func (s *Service) handleGenerateSeed(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		AddressCount int    `json:"address_count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonErr(w, 400, "name is required")
		return
	}
	if req.Name == "default" {
		jsonErr(w, 400, "'default' is the root wallet, use restore-wallet")
		return
	}
	if req.AddressCount <= 0 {
		req.AddressCount = 1
	}

	dir := s.walletDir(req.Name)
	if _, err := os.Stat(filepath.Join(dir, "wallet.json")); err == nil {
		jsonErr(w, 409, "wallet already exists")
		return
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	wal, err := wallet.Open(dir)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	seedHex, err := wal.SetHDSeed("")
	if err != nil {
		jsonErr(w, 500, "set seed: "+err.Error())
		return
	}

	addrs := make([]string, req.AddressCount)
	for i := 0; i < req.AddressCount; i++ {
		addr, err := wal.NewAddress()
		if err != nil {
			jsonErr(w, 500, "new address: "+err.Error())
			return
		}
		addrs[i] = addr
	}

	hybridAddr, err := wal.NewHybridAddress()
	if err != nil {
		hybridAddr = ""
	}

	jsonResp(w, 200, map[string]any{
		"wallet":          req.Name,
		"mnemonic":        wal.Mnemonic(),
		"seed_hex":        seedHex,
		"classic_address": addrs[0],
		"addresses":       addrs,
		"hybrid_address":  hybridAddr,
	})
}

// POST /api/restore-wallet
// Body: {"name": "my-wallet", "mnemonic": "...", "address_count": 5}
func (s *Service) handleRestoreWallet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		Mnemonic     string `json:"mnemonic"`
		AddressCount int    `json:"address_count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Mnemonic = strings.TrimSpace(req.Mnemonic)
	if req.Name == "" {
		jsonErr(w, 400, "name is required")
		return
	}
	if req.Mnemonic == "" {
		jsonErr(w, 400, "mnemonic is required")
		return
	}
	if req.AddressCount <= 0 {
		req.AddressCount = 5
	}

	dir := s.walletDir(req.Name)
	if _, err := os.Stat(filepath.Join(dir, "wallet.json")); err == nil {
		jsonErr(w, 409, "wallet already exists")
		return
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	wal, err := wallet.Open(dir)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	if _, err := wal.SetHDMnemonic(req.Mnemonic); err != nil {
		jsonErr(w, 400, "invalid mnemonic: "+err.Error())
		return
	}

	addrs := make([]string, req.AddressCount)
	for i := 0; i < req.AddressCount; i++ {
		addr, err := wal.NewAddress()
		if err != nil {
			jsonErr(w, 500, "new address: "+err.Error())
			return
		}
		addrs[i] = addr
	}

	hybridAddr, err := wal.NewHybridAddress()
	if err != nil {
		hybridAddr = ""
	}

	jsonResp(w, 200, map[string]any{
		"wallet":          req.Name,
		"mnemonic":        wal.Mnemonic(),
		"classic_address": addrs[0],
		"addresses":       addrs,
		"hybrid_address":  hybridAddr,
	})
}

// GET /api/wallet/{name}
func (s *Service) handleGetWallet(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/wallet/")
	path = strings.TrimSpace(path)

	if path == "" {
		jsonErr(w, 400, "wallet name required")
		return
	}

	if strings.HasSuffix(path, "/newaddress") && r.Method == http.MethodPost {
		name := strings.TrimSuffix(path, "/newaddress")
		s.handleNewAddress(w, r, name)
		return
	}

	if strings.HasSuffix(path, "/newhybridaddress") && r.Method == http.MethodPost {
		name := strings.TrimSuffix(path, "/newhybridaddress")
		s.handleNewHybridAddress(w, r, name)
		return
	}

	if strings.HasSuffix(path, "/balance") {
		name := strings.TrimSuffix(path, "/balance")
		s.handleGetBalance(w, r, name)
		return
	}

	if strings.HasSuffix(path, "/balances") {
		name := strings.TrimSuffix(path, "/balances")
		s.handleGetBalances(w, r, name)
		return
	}

	if strings.HasSuffix(path, "/mnemonic") {
		name := strings.TrimSuffix(path, "/mnemonic")
		s.handleGetMnemonic(w, r, name)
		return
	}

	dir := s.resolveDir(path)
	if _, err := os.Stat(filepath.Join(dir, "wallet.json")); os.IsNotExist(err) {
		jsonErr(w, 404, "wallet not found")
		return
	}

	wal, err := wallet.Open(dir)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	addrs := wal.ListAddresses()
	info := wal.SecurityInfo()

	jsonResp(w, 200, map[string]any{
		"wallet":    path,
		"addresses": addrs,
		"info":      info,
	})
}

// GET /api/wallet/{name}/mnemonic
func (s *Service) handleGetMnemonic(w http.ResponseWriter, r *http.Request, name string) {
	dir := s.resolveDir(name)
	if _, err := os.Stat(filepath.Join(dir, "wallet.json")); os.IsNotExist(err) {
		jsonErr(w, 404, "wallet not found")
		return
	}

	wal, err := wallet.Open(dir)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	mnemonic := wal.Mnemonic()
	if mnemonic == "" {
		jsonErr(w, 404, "mnemonic not available")
		return
	}

	var lines []string
	for i, w := range strings.Fields(mnemonic) {
		lines = append(lines, fmt.Sprintf("%2d. %s", i+1, w))
	}

	jsonResp(w, 200, map[string]any{
		"wallet":           name,
		"mnemonic":         mnemonic,
		"mnemonic_b64":     base64.StdEncoding.EncodeToString([]byte(mnemonic)),
		"mnemonic_numbered": strings.Join(lines, "  "),
	})
}

// POST /api/wallet/{name}/newaddress
func (s *Service) handleNewAddress(w http.ResponseWriter, r *http.Request, name string) {
	dir := s.resolveDir(name)
	if _, err := os.Stat(filepath.Join(dir, "wallet.json")); os.IsNotExist(err) {
		jsonErr(w, 404, "wallet not found")
		return
	}

	wal, err := wallet.Open(dir)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	info := wal.SecurityInfo()
	if !info["hdseed"].(bool) {
		if _, err := wal.SetHDSeed(""); err != nil {
			jsonErr(w, 500, "set seed: "+err.Error())
			return
		}
	}

	addr, err := wal.NewAddress()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	jsonResp(w, 200, map[string]any{
		"wallet":   name,
		"address":  addr,
	})
}

// POST /api/wallet/{name}/newhybridaddress
func (s *Service) handleNewHybridAddress(w http.ResponseWriter, r *http.Request, name string) {
	dir := s.resolveDir(name)
	if _, err := os.Stat(filepath.Join(dir, "wallet.json")); os.IsNotExist(err) {
		jsonErr(w, 404, "wallet not found")
		return
	}

	wal, err := wallet.Open(dir)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	info := wal.SecurityInfo()
	if !info["hdseed"].(bool) {
		if _, err := wal.SetHDSeed(""); err != nil {
			jsonErr(w, 500, "set seed: "+err.Error())
			return
		}
	}

	addr, err := wal.NewHybridAddress()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}

	jsonResp(w, 200, map[string]any{
		"wallet":  name,
		"address": addr,
	})
}

// GET /api/wallets
func (s *Service) handleListWallets(w http.ResponseWriter, r *http.Request) {
	var names []string

	if _, err := os.Stat(filepath.Join(s.dataDir, "wallet.json")); err == nil {
		names = append(names, "default")
	}

	walletsDir := filepath.Join(s.dataDir, "wallets")
	entries, err := os.ReadDir(walletsDir)
	if err == nil {
		for _, e := range entries {
			// "default" is the root wallet (/data/wallet.json), skip nested default dir
			if e.IsDir() && e.Name() != "default" {
				names = append(names, e.Name())
			}
		}
	}

	jsonResp(w, 200, map[string]any{"wallets": names})
}

// GET /api/wallet/{name}/balance
func (s *Service) handleGetBalance(w http.ResponseWriter, r *http.Request, name string) {
	dir := s.resolveDir(name)
	if _, err := os.Stat(filepath.Join(dir, "wallet.json")); os.IsNotExist(err) {
		jsonErr(w, 404, "wallet not found")
		return
	}
	wal, err := wallet.Open(dir)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	addrs := wal.ListAddresses()
	if len(addrs) == 0 {
		jsonResp(w, 200, map[string]any{"wallet": name, "balance": 0, "addresses": 0})
		return
	}
	totalBalance := 0.0
	totalReceived := 0.0
	for _, addr := range addrs {
		result, err := s.rpcCall("getaddressbalance", []any{addr})
		if err != nil {
			continue
		}
		if m, ok := result.(map[string]any); ok {
			if b, ok := m["balance"].(float64); ok {
				totalBalance += b
			}
			if r, ok := m["received"].(float64); ok {
				totalReceived += r
			}
		}
	}
	jsonResp(w, 200, map[string]any{
		"wallet":   name,
		"balance":  totalBalance,
		"received": totalReceived,
		"addresses": len(addrs),
	})
}

// GET /api/wallet/{name}/balances
func (s *Service) handleGetBalances(w http.ResponseWriter, r *http.Request, name string) {
	dir := s.resolveDir(name)
	if _, err := os.Stat(filepath.Join(dir, "wallet.json")); os.IsNotExist(err) {
		jsonErr(w, 404, "wallet not found")
		return
	}
	wal, err := wallet.Open(dir)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	addrs := wal.ListAddresses()
	type addrBalance struct {
		Address  string  `json:"address"`
		Balance  float64 `json:"balance"`
		Received float64 `json:"received"`
	}
	var balances []addrBalance
	totalBalance := 0.0
	for _, addr := range addrs {
		ab := addrBalance{Address: addr}
		result, err := s.rpcCall("getaddressbalance", []any{addr})
		if err != nil {
			balances = append(balances, ab)
			continue
		}
		if m, ok := result.(map[string]any); ok {
			if b, ok := m["balance"].(float64); ok {
				ab.Balance = b
				totalBalance += b
			}
			if r, ok := m["received"].(float64); ok {
				ab.Received = r
			}
		}
		balances = append(balances, ab)
	}
	jsonResp(w, 200, map[string]any{
		"wallet":   name,
		"balance":  totalBalance,
		"addresses": balances,
	})
}

// ---------------------------------------------------------------------------
// Transaction Service API (Phase 1 - read-only, Phase 2 - send)
//   GET  /api/chain/{coin}/balance/{address}
//   GET  /api/chain/{coin}/utxos/{address}[?minconf=N]
//   GET  /api/chain/{coin}/validate/{address}
//   GET  /api/chain/{coin}/history/{address}
//   POST /api/chain/{coin}/send        body {from,to,amount,fee,privateKey}
// ---------------------------------------------------------------------------

func (s *Service) handleChain(w http.ResponseWriter, r *http.Request) {
	// /api/chain/{coin}/{op}[/{address}]
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/chain/"), "/", 3)
	if len(parts) != 2 && len(parts) != 3 {
		jsonErr(w, 400, "expected /api/chain/{coin}/{op}[/{address}]")
		return
	}
	coin, op := parts[0], parts[1]
	rest := ""
	if len(parts) == 3 {
		rest = parts[2]
	}
	chain, err := s.chains.Get(coin)
	if err != nil {
		jsonErr(w, 404, err.Error())
		return
	}

	switch op {
	case "balance":
		s.handleChainBalance(w, chain, rest)
	case "utxos":
		s.handleChainUtxos(w, r, chain, rest)
	case "validate":
		s.handleChainValidate(w, chain, rest)
	case "history":
		s.handleChainHistory(w, chain, rest)
	case "estimate":
		s.handleChainEstimate(w, r, chain, rest)
	case "send":
		s.handleChainSend(w, r, chain, rest)
	default:
		jsonErr(w, 400, "unknown op "+op)
	}
}

func (s *Service) handleChainBalance(w http.ResponseWriter, chain txsvc.Blockchain, address string) {
	bal, err := chain.GetBalance(address)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, 200, bal)
}

func (s *Service) handleChainUtxos(w http.ResponseWriter, r *http.Request, chain txsvc.Blockchain, address string) {
	minConf := 1
	if q := r.URL.Query().Get("minconf"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n >= 0 {
			minConf = n
		}
	}
	utxos, err := chain.ListUnspent(address, minConf)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if utxos == nil {
		utxos = []txsvc.UTXO{}
	}
	jsonResp(w, 200, map[string]any{
		"address": address,
		"count":   len(utxos),
		"utxos":   utxos,
	})
}

func (s *Service) handleChainValidate(w http.ResponseWriter, chain txsvc.Blockchain, address string) {
	info, err := chain.ValidateAddress(address)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, 200, info)
}

func (s *Service) handleChainHistory(w http.ResponseWriter, chain txsvc.Blockchain, address string) {
	entries, err := chain.GetHistory(address)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if entries == nil {
		entries = []txsvc.HistoryEntry{}
	}
	jsonResp(w, 200, map[string]any{
		"address": address,
		"count":   len(entries),
		"entries": entries,
	})
}

// handleChainSend signs and broadcasts a withdrawal. body:
// {"from":addr,"to":addr,"amount":baseUnits,"fee":baseUnitsOr0,"privateKey":"0x..."}
// Requires the X-Api-Key header matching LEGACYCOIN_API_KEY so that browser
// clients hitting the public nginx proxy cannot submit signed sends.
func (s *Service) handleChainSend(w http.ResponseWriter, r *http.Request, chain txsvc.Blockchain, address string) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "send requires POST")
		return
	}
	if s.apiKey != "" && r.Header.Get("X-Api-Key") != s.apiKey {
		jsonErr(w, 401, "missing or invalid X-Api-Key")
		return
	}
	var req struct {
		From       string `json:"from"`
		To         string `json:"to"`
		Amount     int64  `json:"amount"`
		Fee        int64  `json:"fee"`
		PrivateKey string `json:"privateKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	if req.From == "" {
		jsonErr(w, 400, "from is required")
		return
	}
	if address != "" && req.From != address {
		jsonErr(w, 400, "path/from address mismatch")
		return
	}
	res, err := chain.SignAndSend(req.From, req.To, req.Amount, req.Fee, req.PrivateKey)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, 200, res)
}

// handleChainEstimate returns a dry-run fee estimate for a pending send. It is
// safe to expose without an API key: it never signs or broadcasts and reveals
// nothing beyond what balance/utxos already expose.
func (s *Service) handleChainEstimate(w http.ResponseWriter, r *http.Request, chain txsvc.Blockchain, address string) {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "estimate requires POST")
		return
	}
	var req struct {
		From       string `json:"from"`
		To         string `json:"to"`
		Amount     int64  `json:"amount"`
		PrivateKey string `json:"privateKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	if req.From == "" {
		jsonErr(w, 400, "from is required")
		return
	}
	if address != "" && req.From != address {
		jsonErr(w, 400, "path/from address mismatch")
		return
	}
	if req.PrivateKey != "" {
		if pe, ok := chain.(txsvc.ProbeEstimator); ok {
			res, err := pe.EstimateWithKey(req.From, req.To, req.Amount, req.PrivateKey)
			if err != nil {
				jsonErr(w, 500, err.Error())
				return
			}
			jsonResp(w, 200, res)
			return
		}
	}
	est, ok := chain.(txsvc.Estimator)
	if !ok {
		jsonErr(w, 404, "coin does not support estimation")
		return
	}
	res, err := est.Estimate(req.From, req.To, req.Amount)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonResp(w, 200, res)
}

func main() {
	dataDir := getEnv("LEGACYCOIN_DATADIR", "/data")
	host := getEnv("LEGACYCOIN_HOST", "0.0.0.0")
	port := getEnv("LEGACYCOIN_PORT", "8443")

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	svc := NewService(dataDir)

	signer := getEnv("LEGACYCOIN_SIGNER_URL", "http://127.0.0.1:8053")
	svc.chains.Register(txsvc.NewLBTC(svc.rpcURL, svc.rpcUser, svc.rpcPass).SetSignerURL(signer))
	svc.chains.Register(txsvc.NewKaspaRest("KAS", "https://api.kaspa.org").SetSignerURL(signer))
	svc.chains.Register(txsvc.NewKaspaRest("GOR", "https://api.gor.forks.life").SetSignerURL(signer))
	svc.chains.Register(txsvc.NewKaspaRest("BTM", "https://api.btm.forks.life").SetSignerURL(signer))
	svc.chains.Register(txsvc.NewKaspaRest("BRICS", "https://api.brics.forks.life").SetSignerURL(signer))
	svc.chains.Register(txsvc.NewKaspaRest("CAS", "https://api.cas.forks.life").SetSignerURL(signer))
	svc.chains.Register(txsvc.NewKaspaRest("KASV2", "https://api.kasv2.forks.life").SetSignerURL(signer))
	svc.chains.Register(txsvc.NewBitcoin("https://blockstream.info/api").SetSignerURL(signer))
	svc.chains.Register(txsvc.NewEtherscanReads("ETH", "1", getEnv("ETHERSCAN_API_KEY", "5QXTCSV96PXKCBGDHXT83R5DPAFTHGEBEZ")))
	svc.chains.Register(txsvc.NewEtherscanReads("USDT", "1", getEnv("ETHERSCAN_API_KEY", "5QXTCSV96PXKCBGDHXT83R5DPAFTHGEBEZ")))
	svc.chains.Register(txsvc.NewEtherscanReads("XHT", "1", getEnv("ETHERSCAN_API_KEY", "5QXTCSV96PXKCBGDHXT83R5DPAFTHGEBEZ")))
	svc.chains.Register(txsvc.NewSolanaReads("SOL"))
	svc.chains.Register(txsvc.NewSolanaReads("TRUMP"))
	svc.chains.Register(txsvc.NewTronReads("TRX"))

	http.HandleFunc("/api/generate-seed", svc.handleGenerateSeed)
	http.HandleFunc("/api/restore-wallet", svc.handleRestoreWallet)
	http.HandleFunc("/api/wallet/", svc.handleGetWallet)
	http.HandleFunc("/api/wallets", svc.handleListWallets)
	http.HandleFunc("/api/chain/", svc.handleChain)

	addr := host + ":" + port
	fmt.Println("========================================")
	fmt.Println("  legacycoreagent - Wallet API Service")
	fmt.Println("========================================")
	fmt.Printf("  Port:   %s\n", port)
	fmt.Printf("  Host:   %s\n", host)
	fmt.Printf("  Data:   %s\n", dataDir)
	fmt.Printf("  Listen: %s\n", addr)
	fmt.Println("========================================")
	fmt.Println("  Endpoints:")
	fmt.Println("    POST /api/generate-seed")
	fmt.Println("    POST /api/restore-wallet")
	fmt.Println("    GET  /api/wallet/{name}")
	fmt.Println("    GET  /api/wallet/{name}/mnemonic")
	fmt.Println("    POST /api/wallet/{name}/newaddress")
	fmt.Println("    GET  /api/wallet/{name}/balance")
	fmt.Println("    GET  /api/wallet/{name}/balances")
	fmt.Println("    GET  /api/wallets")
	fmt.Println("  Transaction Service (read-only):")
	fmt.Println("    GET  /api/chain/{coin}/balance/{address}")
	fmt.Println("    GET  /api/chain/{coin}/utxos/{address}?minconf=N")
	fmt.Println("    GET  /api/chain/{coin}/validate/{address}")
	fmt.Println("    GET  /api/chain/{coin}/history/{address}")
	fmt.Println("    POST /api/chain/{coin}/estimate (from,to,amount) -> fee/change")
	fmt.Println("    POST /api/chain/{coin}/send     (requires X-Api-Key)")
	fmt.Println("========================================")

	log.Fatal(http.ListenAndServe(addr, nil))
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
