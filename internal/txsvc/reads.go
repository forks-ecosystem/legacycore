package txsvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func readonlySignErr() error {
	return errors.New("sending is not supported for this coin")
}

type readOnlyBase struct{}

func (readOnlyBase) ListUnspent(address string, minConf int) ([]UTXO, error) {
	return nil, ErrNotImplemented
}
func (readOnlyBase) ValidateAddress(addr string) (AddrInfo, error) {
	return AddrInfo{}, ErrNotImplemented
}
func (readOnlyBase) GetNewAddress(label string) (string, error) { return "", ErrNotImplemented }
func (readOnlyBase) SendTransaction(from, to string, amount int64, opts TxOptions) (string, error) {
	return "", readonlySignErr()
}
func (readOnlyBase) GetTransaction(txid string) (*Tx, error) { return nil, ErrNotImplemented }
func (readOnlyBase) GetConfirmations(txid string) (int, error) {
	return 0, ErrNotImplemented
}
func (readOnlyBase) SignAndSend(from, to string, amount, fee int64, privateKey string) (SendResult, error) {
	return SendResult{}, readonlySignErr()
}

// ---------------------------------------------------------------------------
// Etherscan (ETH / USDT / XHT) - read-only
// ---------------------------------------------------------------------------

type EtherscanReads struct {
	readOnlyBase
	symbol   string
	chainID  string
	apiKey   string
	erc20    string
	decimals int
}

func NewEtherscanReads(symbol, chainID, apiKey string) *EtherscanReads {
	e := &EtherscanReads{symbol: symbol, chainID: chainID, apiKey: apiKey, decimals: 18}
	switch symbol {
	case "USDT":
		e.erc20 = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
	case "XHT":
		e.erc20 = "0xD3c625F54dec647DB8780dBBe0E880eF21BA4329"
	}
	return e
}

func (e *EtherscanReads) Name() string { return e.symbol }

func (e *EtherscanReads) call(action string, extra map[string]string, out any) error {
	q := url.Values{}
	q.Set("chainid", e.chainID)
	q.Set("apikey", e.apiKey)
	q.Set("module", "account")
	q.Set("action", action)
	for k, v := range extra {
		q.Set(k, v)
	}
	var wrapped struct {
		Status  string          `json:"status"`
		Message string          `json:"message"`
		Result  json.RawMessage `json:"result"`
	}
	if err := getJSON("https://api.etherscan.io/v2/api?"+q.Encode(), &wrapped); err != nil {
		return err
	}
	if wrapped.Status != "1" {
		msg := wrapped.Message
		if msg == "" {
			msg = "etherscan error"
		}
		return errors.New(msg)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(wrapped.Result, out)
}

func (e *EtherscanReads) GetBalance(address string) (Balance, error) {
	var bal Balance
	if address == "" {
		return bal, errors.New("address is required")
	}
	units := int64(0)
	if e.erc20 != "" {
		var v string
		if err := e.call("tokenbalance", map[string]string{"contractaddress": e.erc20, "address": address}, &v); err != nil {
			return bal, err
		}
		units = parseAtomic(v)
	} else {
		var v string
		if err := e.call("balance", map[string]string{"address": address}, &v); err != nil {
			return bal, err
		}
		units = parseAtomic(v)
	}
	bal.Address = address
	bal.BalanceBaseUnits = units
	bal.Balance = float64(units) / float64(pow10(e.decimals))
	bal.ReceivedBaseUnits = units
	bal.Received = bal.Balance
	bal.Confirmed = true
	return bal, nil
}

type etherscanTx struct {
	Hash            string `json:"hash"`
	BlockNumber     string `json:"blockNumber"`
	Value           string `json:"value"`
	To              string `json:"to"`
	From            string `json:"from"`
	IsError         string `json:"isError"`
	ContractAddress string `json:"contractAddress"`
	TokenDecimal    string `json:"tokenDecimal"`
}

func (e *EtherscanReads) GetHistory(address string) ([]HistoryEntry, error) {
	if address == "" {
		return nil, errors.New("address is required")
	}
	action := "txlist"
	if e.erc20 != "" {
		action = "tokentx"
	}
	var list []etherscanTx
	err := e.call(action, map[string]string{"address": address, "sort": "desc", "page": "1", "offset": "50"}, &list)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "no transactions found") {
		return []HistoryEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	addr := address
	dec := e.decimals
	entries := make([]HistoryEntry, 0, len(list))
	for _, t := range list {
		if e.erc20 == "" && t.IsError == "1" {
			continue
		}
		if e.erc20 != "" && (t.ContractAddress == "" || strings.EqualFold(t.ContractAddress, e.erc20) == false) {
			continue
		}
		if e.erc20 != "" && t.TokenDecimal != "" {
			if d, derr := strconv.Atoi(t.TokenDecimal); derr == nil && d > 0 {
				dec = d
			}
		}
		amt := parseAtomic(t.Value)
		var h HistoryEntry
		h.Txid = t.Hash
		if n, err := strconv.ParseInt(t.BlockNumber, 10, 64); err == nil {
			h.Height = n
			h.Confirmations = 1
			h.Mature = true
		}
		switch {
		case strings.EqualFold(t.To, addr):
			h.Type = "receive"
			h.Amount = amt
		case strings.EqualFold(t.From, addr):
			h.Type = "send"
			h.Amount = -amt
		default:
			continue
		}
		h.AmountDisplay = formatAtomicDec(h.Amount, dec, e.symbol)
		entries = append(entries, h)
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// Solana (SOL / TRUMP) - read-only
// ---------------------------------------------------------------------------

type SolanaReads struct {
	readOnlyBase
	symbol string
	rpc    string
}

func NewSolanaReads(symbol string) *SolanaReads {
	return &SolanaReads{symbol: symbol, rpc: "https://api.mainnet-beta.solana.com"}
}

func (s *SolanaReads) Name() string { return s.symbol }

func (s *SolanaReads) rpcCall(method string, params any, out any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	respBody, status, err := postRaw(s.rpc, body, "application/json")
	if err != nil {
		return err
	}
	var wrapped struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &wrapped); err != nil {
		return err
	}
	if status >= 300 || wrapped.Error != nil {
		if wrapped.Error != nil {
			return errors.New(wrapped.Error.Message)
		}
		return fmt.Errorf("solana rpc: HTTP %d", status)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(wrapped.Result, out)
}

func (s *SolanaReads) GetBalance(address string) (Balance, error) {
	var bal Balance
	if address == "" {
		return bal, errors.New("address is required")
	}
	var res struct {
		Value uint64 `json:"value"`
	}
	err := s.rpcCall("getBalance", []any{address, map[string]string{"commitment": "confirmed"}}, &res)
	if err != nil {
		return bal, err
	}
	units := int64(res.Value)
	bal.Address = address
	bal.BalanceBaseUnits = units
	bal.Balance = float64(units) / 1e9
	bal.ReceivedBaseUnits = units
	bal.Received = bal.Balance
	bal.Confirmed = true
	return bal, nil
}

type solanaTx struct {
	Txid string `json:"signature"`
	Meta struct {
		Err          *json.RawMessage `json:"err"`
		PreBalances  []uint64         `json:"preBalances"`
		PostBalances []uint64         `json:"postBalances"`
	} `json:"meta"`
	BlockTime *int64 `json:"blockTime"`
	Slot      *int64 `json:"slot"`
	Tx        struct {
		Signatures []string `json:"signatures"`
		Message    struct {
			AccountKeys []struct {
				Pubkey string `json:"pubkey"`
			} `json:"accountKeys"`
		} `json:"message"`
	} `json:"transaction"`
}

func (s *SolanaReads) GetHistory(address string) ([]HistoryEntry, error) {
	if address == "" {
		return nil, errors.New("address is required")
	}
	var sigs []struct {
		Signature string `json:"signature"`
	}
	err := s.rpcCall("getSignaturesForAddress", []any{address, map[string]any{"limit": 30}}, &sigs)
	if err != nil {
		return nil, err
	}
	ge := make([]HistoryEntry, 0, 10)
	for _, sg := range sigs {
		var tx solanaTx
		params := []any{sg.Signature, map[string]any{"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}}
		if err := s.rpcCall("getTransaction", params, &tx); err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		h := s.historyFromTx(tx, address)
		if h != nil {
			ge = append(ge, *h)
		}
		if len(ge) >= 10 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if ge == nil {
		ge = []HistoryEntry{}
	}
	return ge, nil
}

func (s *SolanaReads) historyFromTx(tx solanaTx, address string) *HistoryEntry {
	if tx.Txid == "" {
		if len(tx.Tx.Signatures) > 0 {
			tx.Txid = tx.Tx.Signatures[0]
		}
	}
	if tx.Txid == "" || tx.Meta.Err != nil {
		return nil
	}
	idx := -1
	for i, k := range tx.Tx.Message.AccountKeys {
		if k.Pubkey == address {
			idx = i
			break
		}
	}
	if idx < 0 || idx >= len(tx.Meta.PreBalances) || idx >= len(tx.Meta.PostBalances) {
		return nil
	}
	delta := int64(tx.Meta.PostBalances[idx]) - int64(tx.Meta.PreBalances[idx])
	if delta == 0 {
		return nil
	}
	h := &HistoryEntry{Txid: tx.Txid}
	if tx.BlockTime != nil {
		h.Height = solanaSlot(tx.Slot)
		h.Confirmations = 1
		h.Mature = true
	}
	h.Amount = delta
	if delta < 0 {
		h.Type = "send"
	} else {
		h.Type = "receive"
	}
	h.AmountDisplay = formatAtomicDec(delta, 9, s.symbol)
	return h
}

func solanaSlot(slot *int64) int64 {
	if slot == nil {
		return 0
	}
	return *slot
}

// ---------------------------------------------------------------------------
// Tron (TRX) - read-only
// ---------------------------------------------------------------------------

type TronReads struct {
	readOnlyBase
	symbol string
	base   string
}

func NewTronReads(symbol string) *TronReads {
	return &TronReads{symbol: symbol, base: "https://apilist.tronscanapi.com"}
}

func (t *TronReads) Name() string { return t.symbol }

func (t *TronReads) GetBalance(address string) (Balance, error) {
	var bal Balance
	if address == "" {
		return bal, errors.New("address is required")
	}
	var out struct {
		Balance      int64 `json:"balance"`
		TotalBalance int64 `json:"totalBalance"`
	}
	if err := getJSON(t.base+"/api/account?address="+address, &out); err != nil {
		return bal, err
	}
	bal.Address = address
	bal.BalanceBaseUnits = out.Balance
	bal.Balance = float64(out.Balance) / 1e6
	bal.ReceivedBaseUnits = out.TotalBalance
	bal.Received = float64(out.TotalBalance) / 1e6
	bal.Confirmed = true
	return bal, nil
}

type tronTx struct {
	Hash         string `json:"hash"`
	Timestamp    int64  `json:"timestamp"`
	Block        int64  `json:"block"`
	OwnerAddress string `json:"ownerAddress"`
	ToAddress    string `json:"toAddress"`
	Amount       string `json:"amount"`
	ContractType int    `json:"contractType"`
	Confirmed    bool   `json:"confirmed"`
}

func (t *TronReads) GetHistory(address string) ([]HistoryEntry, error) {
	if address == "" {
		return nil, errors.New("address is required")
	}
	var out struct {
		Data []tronTx `json:"data"`
	}
	u := t.base + "/api/transaction?sort=-timestamp&limit=20&address=" + address
	if err := getJSON(u, &out); err != nil {
		return nil, err
	}
	addr := address
	entries := make([]HistoryEntry, 0, len(out.Data))
	for _, tr := range out.Data {
		if tr.OwnerAddress == "" || tr.ToAddress == "" {
			continue
		}
		direction := ""
		if strings.EqualFold(tr.ToAddress, addr) {
			direction = "receive"
		} else if strings.EqualFold(tr.OwnerAddress, addr) {
			direction = "send"
		}
		if direction == "" {
			continue
		}
		amt := parseAtomic(tr.Amount)
		var h HistoryEntry
		h.Txid = tr.Hash
		h.Height = tr.Block
		if tr.Confirmed {
			h.Confirmations = 1
			h.Mature = true
		}
		h.Type = direction
		if direction == "send" && amt != 0 {
			amt = -amt
		}
		h.Amount = amt
		h.AmountDisplay = formatAtomicDec(amt, 6, t.symbol)
		entries = append(entries, h)
	}
	if entries == nil {
		entries = []HistoryEntry{}
	}
	return entries, nil
}
