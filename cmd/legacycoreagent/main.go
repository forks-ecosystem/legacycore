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
	"strings"

	"legacycoin/legacy-go/internal/wallet"
)

type Service struct {
	dataDir string
	rpcURL  string
	rpcUser string
	rpcPass string
}

func NewService(dataDir string) *Service {
	return &Service{
		dataDir: dataDir,
		rpcURL:  getEnv("LEGACYCOIN_RPC_URL", ""),
		rpcUser: getEnv("LEGACYCOIN_RPC_USER", ""),
		rpcPass: getEnv("LEGACYCOIN_RPC_PASS", ""),
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

func main() {
	dataDir := getEnv("LEGACYCOIN_DATADIR", "/data")
	host := getEnv("LEGACYCOIN_HOST", "0.0.0.0")
	port := getEnv("LEGACYCOIN_PORT", "8443")

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	svc := NewService(dataDir)

	http.HandleFunc("/api/generate-seed", svc.handleGenerateSeed)
	http.HandleFunc("/api/restore-wallet", svc.handleRestoreWallet)
	http.HandleFunc("/api/wallet/", svc.handleGetWallet)
	http.HandleFunc("/api/wallets", svc.handleListWallets)

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
	fmt.Println("========================================")

	log.Fatal(http.ListenAndServe(addr, nil))
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
