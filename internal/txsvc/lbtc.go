package txsvc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// LBTC implements Blockchain for the LegacyCoin chain. Backed by the local
// legacycoind JSON-RPC node (default 127.0.0.1:19556). All amounts are base
// units (sompi): value fields returned by the node are already in sompi, and
// the balance RPC gives us both confirmed sompi and display units.
type LBTC struct {
	rpc       *RPCClient
	signerURL string
}

func NewLBTC(rpcURL, user, pass string) *LBTC {
	return &LBTC{rpc: NewRPCClient(rpcURL, user, pass), signerURL: "http://127.0.0.1:8053"}
}

func (b *LBTC) SetSignerURL(url string) *LBTC {
	if url != "" {
		b.signerURL = url
	}
	return b
}

func (b *LBTC) Name() string { return "LBTC" }

func (b *LBTC) GetBalance(address string) (Balance, error) {
	var bal Balance
	if address == "" {
		return bal, fmt.Errorf("address is required")
	}
	res, err := b.rpc.Call("getaddressbalance", []any{address})
	if err != nil {
		return bal, err
	}
	m, ok := res.(map[string]any)
	if !ok {
		return bal, fmt.Errorf("unexpected getaddressbalance result")
	}
	bal.Address = address
	if v, ok := m["balance_base_units"].(float64); ok {
		bal.BalanceBaseUnits = int64(v)
	}
	if v, ok := m["balance"].(float64); ok {
		bal.Balance = v
	}
	if v, ok := m["received_base_units"].(float64); ok {
		bal.ReceivedBaseUnits = int64(v)
	}
	if v, ok := m["received"].(float64); ok {
		bal.Received = v
	}
	bal.Confirmed = true
	return bal, nil
}

func (b *LBTC) ListUnspent(address string, minConf int) ([]UTXO, error) {
	if address == "" {
		return nil, fmt.Errorf("address is required")
	}
	res, err := b.rpc.Call("getaddressutxos", []any{address})
	if err != nil {
		return nil, err
	}
	list, ok := res.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected getaddressutxos result")
	}
	utxos := make([]UTXO, 0, len(list))
	for _, row := range list {
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		var u UTXO
		if v, ok := m["txid"].(string); ok {
			u.Txid = v
		}
		if v, ok := m["vout"].(float64); ok {
			u.Vout = uint32(v)
		}
		if v, ok := m["value"].(float64); ok {
			u.Value = int64(v)
		}
		if v, ok := m["address"].(string); ok {
			u.Address = v
		}
		if v, ok := m["height"].(float64); ok {
			u.Height = int32(v)
		}
		if v, ok := m["coinbase"].(bool); ok {
			u.Coinbase = v
		}
		if v, ok := m["script_pub_key"].(string); ok {
			u.ScriptHex = v
		}
		utxos = append(utxos, u)
	}
	return utxos, nil
}

func (b *LBTC) ValidateAddress(addr string) (AddrInfo, error) {
	var info AddrInfo
	if addr == "" {
		return info, fmt.Errorf("address is required")
	}
	res, err := b.rpc.Call("validateaddress", []any{addr})
	if err != nil {
		return info, err
	}
	m, ok := res.(map[string]any)
	if !ok {
		return info, fmt.Errorf("unexpected validateaddress result")
	}
	info.Address = addr
	if v, ok := m["isvalid"].(bool); ok {
		info.IsValid = v
	}
	if v, ok := m["ismine"].(bool); ok {
		info.IsMine = v
	}
	if v, ok := m["is_hybrid"].(bool); ok {
		info.IsHybrid = v
	}
	if v, ok := m["pubkey_hash_hex"].(string); ok {
		info.PubKeyHash = v
	}
	return info, nil
}

func (b *LBTC) GetConfirmations(txid string) (int, error) {
	if txid == "" {
		return 0, fmt.Errorf("txid is required")
	}
	res, err := b.rpc.Call("getrawtransaction", []any{txid, 1})
	if err != nil {
		return 0, err
	}
	m, ok := res.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("unexpected getrawtransaction result")
	}
	if v, ok := m["confirmations"].(float64); ok {
		return int(v), nil
	}
	return 0, nil
}

// GetHistory returns address events from the node's getaddresshistory RPC.
func (b *LBTC) GetHistory(address string) ([]HistoryEntry, error) {
	if address == "" {
		return nil, fmt.Errorf("address is required")
	}
	res, err := b.rpc.Call("getaddresshistory", []any{address})
	if err != nil {
		return nil, err
	}
	m, ok := res.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected getaddresshistory result")
	}
	raw, _ := m["entries"].([]any)
	entries := make([]HistoryEntry, 0, len(raw))
	for _, row := range raw {
		e, ok := row.(map[string]any)
		if !ok {
			continue
		}
		var h HistoryEntry
		if v, ok := e["txid"].(string); ok {
			h.Txid = v
		}
		if v, ok := e["height"].(float64); ok {
			h.Height = int64(v)
		}
		if v, ok := e["confirmations"].(float64); ok {
			h.Confirmations = int64(v)
		}
		if v, ok := e["type"].(string); ok {
			h.Type = v
		}
		if v, ok := e["amount_base_units"].(float64); ok {
			h.Amount = int64(v)
		}
		if v, ok := e["amount"].(string); ok {
			h.AmountDisplay = v
		}
		if v, ok := e["coinbase"].(bool); ok {
			h.Coinbase = v
		}
		if v, ok := e["mature"].(bool); ok {
			h.Mature = v
		}
		entries = append(entries, h)
	}
	return entries, nil
}

// GetNewAddress is not supported on LBTC yet - wallet addresses are managed
// by the legacycoreagent wallet service, not by the transaction service.
func (b *LBTC) GetNewAddress(label string) (string, error) {
	return "", ErrNotImplemented
}

// SignAndSend builds, signs (via the local 8053 signer) and broadcasts an LBTC
// transaction. fee<=0 picks the minimum relay fee, which here is 1000 sompi/KB
// (~1 sompi per tx byte). Signer contract: POST /v2/tx with
// {symbol, privateKey, inputs:[{txId,vOut}], outputs:[{address,amount}], fee}
// returns {status:"ok", rawTx:'{"rawTx":"<hex>"}'}.
func (b *LBTC) SignAndSend(from, to string, amount, fee int64, privateKey string) (SendResult, error) {
	var res SendResult
	if from == "" || to == "" {
		return res, fmt.Errorf("from and to are required")
	}
	if amount <= 0 {
		return res, fmt.Errorf("amount must be positive")
	}
	if privateKey == "" {
		return res, fmt.Errorf("privateKey is required")
	}
	if info, err := b.ValidateAddress(to); err != nil {
		return res, err
	} else if !info.IsValid {
		return res, fmt.Errorf("invalid destination address")
	}

	utxos, err := b.ListUnspent(from, 1)
	if err != nil {
		return res, err
	}
	if len(utxos) == 0 {
		return res, fmt.Errorf("no confirmed UTXOs available")
	}

	// pickInputs greedily accumulates UTXOs (largest first) until >= needed.
	pickInputs := func(needed int64) ([]UTXO, int64) {
		sorted := make([]UTXO, len(utxos))
		copy(sorted, utxos)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Value > sorted[j].Value })
		out := sorted[:0]
		var total int64
		for _, u := range sorted {
			out = append(out, u)
			total += u.Value
			if total >= needed {
				break
			}
		}
		return out, total
	}

	// Estimate fee iteratively: fee depends on tx size which depends on the
	// number of inputs picked, which depends on fee.
	const maxIters = 8
	var inputs []UTXO
	var total int64
	usedFee := fee
	if usedFee <= 0 {
		usedFee = 0 // first pass: required size unknown
	}
	// We need at least one pass to learn the assembled tx size. Do the
	// selection with a generous initial guess so the pick count is stable.
	for iter := 0; iter < maxIters; iter++ {
		needed := amount + usedFee
		ins, tot := pickInputs(needed)
		if tot < needed {
			return res, fmt.Errorf("insufficient funds: have %d, need %d", tot, needed)
		}
		inputs, total = ins, tot

		change := total - amount - usedFee
		outputs := []signOut{{Address: to, Amount: amount}}
		if change > 0 {
			outputs = append(outputs, signOut{Address: from, Amount: change})
		}

		hex, err := b.callSigner(privateKey, inputsToSigner(inputs), outputs, usedFee)
		if err != nil {
			return res, err
		}
		needFee := minRelayFee(int64(len(hex) / 2)) // 1000 sompi/KB
		if usedFee >= needFee {
			break // fee already pays the relay floor
		}
		usedFee = needFee
	}

	// Verify the last selection also covers amount+fee (fee may have risen in
	// the final pass, changing the change value but not the picks).
	// Rebuild once more with the final fee so the signed change is exact.
	change := total - amount - usedFee
	if change < 0 {
		return res, fmt.Errorf("insufficient funds after fee of %d", usedFee)
	}
	outputs := []signOut{{Address: to, Amount: amount}}
	if change > 0 {
		outputs = append(outputs, signOut{Address: from, Amount: change})
	}
	hex, err := b.callSigner(privateKey, inputsToSigner(inputs), outputs, usedFee)
	if err != nil {
		return res, err
	}
	res.RawTx = hex
	res.Fee = usedFee
	res.Size = len(hex) / 2

	txid, err := b.broadcast(hex)
	if err != nil {
		return res, err
	}
	res.Txid = txid
	return res, nil
}

type signIn struct {
	TxId   string `json:"txId"`
	VOut   uint32 `json:"vOut"`
	Amount int64  `json:"amount"`
}

type signOut struct {
	Address string `json:"address"`
	Amount  int64  `json:"amount"`
}

func inputsToSigner(utxos []UTXO) []signIn {
	out := make([]signIn, 0, len(utxos))
	for _, u := range utxos {
		out = append(out, signIn{TxId: u.Txid, VOut: u.Vout, Amount: u.Value})
	}
	return out
}

// minRelayFee returns the fee needed to satisfy the node's
// min_relay_fee_per_kb (1000 sompi/KB) for a tx of `size` bytes.
// The node checks fee >= (size*1000+999)/1000, i.e. ~1 sompi/byte.
func minRelayFee(size int64) int64 {
	return (size*1000 + 999) / 1000
}

// Estimate is a dry-run fee calculation for a send without signing or
// broadcasting. It is optional: LBTC implements it, other chains may not.
type Estimator interface {
	Estimate(from, to string, amount int64) (FeeEstimate, error)
}

// Estimate picks UTXOs for amount+fee and reports the minimum relay fee,
// expected size and change. No signing, no broadcast, no network write.
func (b *LBTC) Estimate(from, to string, amount int64) (FeeEstimate, error) {
	var est FeeEstimate
	if from == "" || to == "" {
		return est, fmt.Errorf("from and to are required")
	}
	if amount <= 0 {
		return est, fmt.Errorf("amount must be positive")
	}
	if info, err := b.ValidateAddress(to); err != nil {
		return est, err
	} else if !info.IsValid {
		return est, fmt.Errorf("invalid destination address")
	}
	utxos, err := b.ListUnspent(from, 1)
	if err != nil {
		return est, err
	}
	if len(utxos) == 0 {
		return est, fmt.Errorf("no confirmed UTXOs available")
	}

	// Iterate: fee depends on size, size depends on input count, input
	// count depends on fee. Converges in 2-3 passes.
	usedFee := int64(0)
	var selected []UTXO
	for iter := 0; iter < 8; iter++ {
		sorted := make([]UTXO, len(utxos))
		copy(sorted, utxos)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Value > sorted[j].Value })

		selected = sorted[:0]
		var total int64
		for _, u := range sorted {
			selected = append(selected, u)
			total += u.Value
			if total >= amount+usedFee {
				break
			}
		}
		if total < amount+usedFee {
			return est, fmt.Errorf("insufficient funds: have %d, need %d", total, amount+usedFee)
		}
		change := total - amount - usedFee
		nOut := 2
		if change == 0 {
			nOut = 1
		}
		size := int64(10 + len(selected)*148 + nOut*34)
		needFee := minRelayFee(size)
		if needFee == usedFee {
			est.Fee = needFee
			est.Change = change
			est.Inputs = len(selected)
			est.Size = int(size)
			return est, nil
		}
		usedFee = needFee
	}
	return est, fmt.Errorf("fee estimation did not converge")
}

func (b *LBTC) callSigner(privateKey string, inputs []signIn, outputs []signOut, fee int64) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"symbol":      "LBTC",
		"privateKey":  privateKey,
		"inputs":      inputs,
		"outputs":     outputs,
		"fee":         fee,
	})
	req, err := http.NewRequest("POST", b.signerURL+"/v2/tx", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("signer: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(rb, &e)
		msg := e.Message
		if msg == "" {
			msg = string(rb)
		}
		return "", fmt.Errorf("signer returned %d: %s", resp.StatusCode, msg)
	}
	var r struct {
		RawTx string `json:"rawTx"`
	}
	if err := json.Unmarshal(rb, &r); err != nil || r.RawTx == "" {
		return "", fmt.Errorf("signer: unexpected response: %s", truncate(string(rb), 200))
	}
	// LBTC signer wraps the hex: rawTx is '{"rawTx":"<hex>"}'.
	var inner struct {
		RawTx string `json:"rawTx"`
	}
	_ = json.Unmarshal([]byte(r.RawTx), &inner)
	hex := inner.RawTx
	if hex == "" {
		hex = strings.Trim(r.RawTx, `"`)
	}
	if hex == "" {
		return "", fmt.Errorf("signer: empty signed tx")
	}
	return hex, nil
}

func (b *LBTC) broadcast(rawHex string) (string, error) {
	res, err := b.rpc.Call("sendrawtransaction", []any{rawHex})
	if err != nil {
		return "", fmt.Errorf("broadcast: %v", err)
	}
	txid, ok := res.(string)
	if !ok || txid == "" {
		return "", fmt.Errorf("broadcast: unexpected result")
	}
	return txid, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// SendTransaction is implemented in Phase 3 (withdrawals).
func (b *LBTC) SendTransaction(from, to string, amount int64, opts TxOptions) (string, error) {
	return "", ErrNotImplemented
}

// GetTransaction is implemented in Phase 3.
func (b *LBTC) GetTransaction(txid string) (*Tx, error) {
	return nil, ErrNotImplemented
}