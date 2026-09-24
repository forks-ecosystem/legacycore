// Package txsvc implements the Transaction Service - a multi-coin interface
// that the PHP wallet calls instead of poking at chain explorers directly.
//
// Phase 0: Blockchain interface + Manager + per-coin implementations.
// Phase 1: read-only operations (balance, UTXOs, address validation).
//
// Coins register one Blockchain implementation each; adding a new coin is a
// new *coin.go file plus one Manager.Register call.
package txsvc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrNotImplemented is returned by Blockchain methods that a coin
// implementation does not support yet (e.g. sends before Phase 3).
var ErrNotImplemented = errors.New("not implemented")

// TxOptions carries per-send parameters understood by all chains.
type TxOptions struct {
	FeeRate              float64 // satoshis/KB, sompi/KB, gas price, ...
	SubtractFeeFromAmount bool
	Comment              string
}

// Tx is the normalized transaction view returned to PHP.
type Tx struct {
	Txid          string    `json:"txid"`
	Confirmations int       `json:"confirmations"`
	Amount        int64     `json:"amount"` // base units
	Fee           int64     `json:"fee"`    // base units
	BlockHeight   int64     `json:"block_height"`
	Timestamp     time.Time `json:"timestamp"`
	Status        string    `json:"status"` // pending, confirmed, failed
}

// UTXO is a normalized unspent output in base units.
type UTXO struct {
	Txid      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	Value     int64  `json:"value"` // base units
	Address   string `json:"address"`
	Height    int32  `json:"height"`
	Coinbase  bool   `json:"coinbase"`
	ScriptHex string `json:"script_pub_key"`
}

// Balance is a normalized address balance in base units and display units.
type Balance struct {
	Address            string  `json:"address"`
	BalanceBaseUnits   int64   `json:"balance_base_units"`
	Balance            float64 `json:"balance"`
	ReceivedBaseUnits  int64   `json:"received_base_units"`
	Received           float64 `json:"received"`
	Confirmed          bool    `json:"confirmed"`
}

// AddrInfo is the normalized result of address validation.
type AddrInfo struct {
	IsValid    bool   `json:"isvalid"`
	Address    string `json:"address"`
	IsMine     bool   `json:"ismine"`
	IsHybrid   bool   `json:"is_hybrid"`
	PubKeyHash string `json:"pubkey_hash_hex,omitempty"`
}

// HistoryEntry is one address event (receive/send) in base units.
type HistoryEntry struct {
	Txid          string `json:"txid"`
	Height        int64  `json:"height"`
	Confirmations int64  `json:"confirmations"`
	Type          string `json:"type"` // receive | send
	Amount        int64  `json:"amount"` // base units
	AmountDisplay string `json:"amount_display"`
	Coinbase      bool   `json:"coinbase"`
	Mature        bool   `json:"mature"`
}

// SendResult is the outcome of a signed-and-broadcast transaction.
type SendResult struct {
	Txid  string `json:"txid"`
	Fee   int64  `json:"fee"` // base units actually paid
	RawTx string `json:"raw_tx"`
	Size  int    `json:"size"` // tx serialized size in bytes
}

// FeeEstimate is the result of a dry-run fee calculation (no signing).
type FeeEstimate struct {
	Fee    int64  `json:"fee"`    // minimum relay fee, base units
	Change int64  `json:"change"` // base units returned to sender
	Inputs int    `json:"inputs"` // number of inputs used
	Size   int    `json:"size"`   // expected tx size in bytes
}

// Blockchain is the per-coin interface. Implementations talk to a node RPC
// (or a remote explorer API) and normalize results into the structures above.
type Blockchain interface {
	Name() string

	// GetBalance returns the confirmed spendable balance for address.
	GetBalance(address string) (Balance, error)

	// ListUnspent returns confirmed spendable UTXOs for address.
	ListUnspent(address string, minConf int) ([]UTXO, error)

	// ValidateAddress reports whether addr is a valid address for this chain.
	ValidateAddress(addr string) (AddrInfo, error)

	// GetConfirmations returns the confirmation count for a txid.
	GetConfirmations(txid string) (int, error)

	// GetHistory returns confirmed address events (receive/send).
	GetHistory(address string) ([]HistoryEntry, error)

	// GetNewAddress generates a new receive address for label.
	GetNewAddress(label string) (string, error)

	// SendTransaction builds, signs and broadcasts a transaction.
	SendTransaction(from, to string, amount int64, opts TxOptions) (string, error)

	// GetTransaction returns a normalized transaction by txid.
	GetTransaction(txid string) (*Tx, error)

	// SignAndSend builds, signs and broadcasts a transaction using an
	// externally provided private key (self-custody wallets). fee<=0 asks the
	// chain to pick the minimum fee. Returns the normalized send result.
	SignAndSend(from, to string, amount, fee int64, privateKey string) (SendResult, error)
}

// Manager routes requests to the registered coin implementations by name.
// Lookup is case-insensitive.
type Manager struct {
	chains map[string]Blockchain
}

func NewManager() *Manager {
	return &Manager{chains: make(map[string]Blockchain)}
}

func (m *Manager) Register(chain Blockchain) {
	if chain == nil {
		return
	}
	m.chains[strings.ToUpper(chain.Name())] = chain
}

func (m *Manager) Get(name string) (Blockchain, error) {
	chain, ok := m.chains[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return nil, fmt.Errorf("blockchain %q not registered", name)
	}
	return chain, nil
}

func (m *Manager) Names() []string {
	names := make([]string, 0, len(m.chains))
	for n := range m.chains {
		names = append(names, n)
	}
	return names
}

// RPCClient is a tiny JSON-RPC client with retries. The node rate-limits
// RPC (token bucket per client IP), so callers retry with a 1s delay.
type RPCClient struct {
	url      string
	user     string
	pass     string
	attempts int
}

func NewRPCClient(url, user, pass string) *RPCClient {
	return &RPCClient{url: url, user: user, pass: pass, attempts: 3}
}

func (c *RPCClient) Call(method string, params any) (any, error) {
	var lastErr error
	for attempt := 0; attempt < c.attempts; attempt++ {
		res, err := c.callOnce(method, params)
		if err == nil {
			return res, nil
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	return nil, lastErr
}

func (c *RPCClient) callOnce(method string, params any) (any, error) {
	if c.url == "" {
		return nil, fmt.Errorf("RPC not configured")
	}
	reqBody := map[string]any{"method": method, "params": params, "id": 1}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", c.url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
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