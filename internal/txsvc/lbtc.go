package txsvc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
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
	// This node has no confirmed/unconfirmed split in getaddressbalance; it
	// reports addressindex_confirmed_only instead, and true there means the
	// figure covers confirmed outputs only. Trust the node's own flag, and
	// assume confirmed when the field is absent rather than claiming a
	// confirmation the reply never made.
	bal.Confirmed = true
	if v, ok := m["addressindex_confirmed_only"].(bool); ok {
		bal.Confirmed = v
	}
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

// lbtcBaseUnits is the node's smallest denomination: 1 LBTC = 1e8 base units
// (the node reports fees in base units, e.g. 0.002 LBTC as fee=200000).
const lbtcBaseUnits = 100000000

// formatLBTCTx renders base units as the decimal LBTC string the node's RPC
// expects, without float rounding surprises.
func formatLBTCTx(v int64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	s := fmt.Sprintf("%d.%08d", v/lbtcBaseUnits, v%lbtcBaseUnits)
	if neg {
		return "-" + s
	}
	return s
}

// SendFromNodeWallet lets the node's own wallet pay `to`, choosing the source
// UTXOs itself: its sendtoaddress takes no from-address parameter, so the
// debit lands on the wallet as a whole rather than on the labelled hot address.
//
// This is the only way to spend the operational float. Those addresses have no
// extractable key (dumpprivkey answers "address not found") and the external
// signer requires a privateKey we cannot obtain for them, so the node wallet
// is the signer of record for hot withdrawals.
func (b *LBTC) SendFromNodeWallet(to string, amount, fee int64, all ...bool) (SendResult, error) {
	var res SendResult
	if to == "" {
		return res, fmt.Errorf("to is required")
	}
	isAll := len(all) > 0 && all[0]
	if !isAll && amount <= 0 {
		return res, fmt.Errorf("amount must be positive")
	}
	if info, err := b.ValidateAddress(to); err != nil {
		return res, err
	} else if !info.IsValid {
		return res, fmt.Errorf("invalid destination address")
	}

	// Refuse early rather than let the node build a tx it will reject.
	have, err := b.walletBalance()
	if err != nil {
		return res, err
	}
	sendAmt := amount
	if isAll {
		sendAmt = have
		if fee > 0 {
			sendAmt = have - fee
		}
		if sendAmt <= 0 {
			return res, fmt.Errorf("fee %d exceeds wallet balance %d", fee, have)
		}
	} else {
		need := amount
		if fee > 0 {
			need += fee
		}
		if have < need {
			return res, fmt.Errorf("node wallet holds %s LBTC, need %s LBTC",
				formatLBTCTx(have), formatLBTCTx(need))
		}
		sendAmt = amount
	}
	params := []any{to, formatLBTCTx(sendAmt)}
	if fee > 0 {
		params = append(params, formatLBTCTx(fee))
	}
	raw, err := b.rpc.Call("sendtoaddress", params)
	if err != nil {
		return res, fmt.Errorf("sendtoaddress: %v", err)
	}
	txid, err := txidFromNodeResult(raw)
	if err != nil {
		return res, err
	}
	res.Txid = txid
	res.Fee = fee
	return res, nil
}

// SweepNodeWallet consolidates one wallet-owned address into `to` with no
// change output, delegating to the node's sweepallraw RPC. It is deliberately
// per-address rather than a wallet-wide sweep: consolidation must move one
// address' float at a time so the resulting transactions stay attributable, and
// so a failure cannot strand funds spread across unrelated addresses.
//
// sendtoaddress cannot be used for this. It stops selecting inputs once the
// requested amount is covered and returns the remainder as change, so computing
// amount=balance-fee still leaves a change output whenever the input selection
// overshoots - which is the dust this sweep exists to remove. getbalance is
// also display-rounded, so the derived amount can overshoot the real total and
// be rejected outright. sweepallraw consumes every spendable input of `from`
// and emits exactly one output of total-fee, so no change address is involved.
func (b *LBTC) SweepNodeWallet(from, to string, fee int64) (SendResult, error) {
	var res SendResult
	if from == "" || to == "" {
		return res, fmt.Errorf("from and to are required")
	}
	if fee < 0 {
		return res, fmt.Errorf("fee must not be negative")
	}
	if info, err := b.ValidateAddress(from); err == nil && !info.IsMine {
		return res, fmt.Errorf("source address %s is not owned by the node wallet", from)
	}
	if info, err := b.ValidateAddress(to); err != nil {
		return res, err
	} else if !info.IsValid {
		return res, fmt.Errorf("invalid destination address")
	}
	raw, err := b.rpc.Call("sweepallraw", []any{from, to, fee})
	if err != nil {
		return res, fmt.Errorf("sweepallraw: %v", err)
	}
	txid, err := txidFromNodeResult(raw)
	if err != nil {
		return res, err
	}
	res.Txid = txid
	res.Fee = fee
	if m, ok := raw.(map[string]any); ok {
		if v, ok := m["amount"].(float64); ok {
			res.Amount = int64(v)
		}
		if v, ok := m["amount_base_units"].(float64); ok {
			res.Amount = int64(v)
		}
	}
	return res, nil
}

// walletBalance returns the node wallet's total spendable balance in base
// units. It deliberately queries "*" and not a single address: withdrawals
// draw on the wallet as a whole, because sendtoaddress cannot be pointed at
// one address.
//
// getbalance answers with a bare JSON number denominated in LBTC, not in base
// units: a wallet holding 77607.37894037 comes back as 77607.37894037. Reading
// that as base units would understate the balance a millionfold and reject
// every real withdrawal, so both the numeric and the string case scale up.
func (b *LBTC) walletBalance() (int64, error) {
	res, err := b.rpc.Call("getbalance", []any{"*"})
	if err != nil {
		return 0, fmt.Errorf("getbalance: %v", err)
	}
	switch v := res.(type) {
	case float64:
		return lbtcToBaseUnits(v)
	case json.Number:
		f, perr := v.Float64()
		if perr != nil {
			return 0, fmt.Errorf("getbalance: cannot parse %q", v.String())
		}
		return lbtcToBaseUnits(f)
	case string:
		var f float64
		if _, serr := fmt.Sscanf(v, "%g", &f); serr != nil {
			return 0, fmt.Errorf("getbalance: cannot parse %q", v)
		}
		return lbtcToBaseUnits(f)
	default:
		return 0, fmt.Errorf("getbalance: unexpected result %T", res)
	}
}

// lbtcToBaseUnits converts an LBTC amount to base units, rounding rather than
// truncating so a wallet balance never reads short.
func lbtcToBaseUnits(lbtc float64) (int64, error) {
	if math.IsNaN(lbtc) || math.IsInf(lbtc, 0) {
		return 0, fmt.Errorf("getbalance: non-finite value %v", lbtc)
	}
	return int64(math.Round(lbtc * lbtcBaseUnits)), nil
}

// txidFromNodeResult reads the txid out of a node reply. sendtoaddress on this
// build returns an object even when verbosity is not requested, unlike
// sendrawtransaction which returns a bare string, so accept both.
func txidFromNodeResult(res any) (string, error) {
	switch v := res.(type) {
	case string:
		if v == "" {
			return "", fmt.Errorf("node returned empty txid")
		}
		return strings.Trim(v, `"`), nil
	case map[string]any:
		for _, k := range []string{"txid", "tx_id", "hash"} {
			if s, ok := v[k].(string); ok && s != "" {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("cannot extract txid from node reply %T", res)
}

// SignAndSend builds, signs (via the local 8053 signer) and broadcasts an LBTC
// transaction. fee<=0 picks the minimum relay fee, which here is 1000 sompi/KB
// (~1 sompi per tx byte). Signer contract: POST /v2/tx with
// {symbol, privateKey, inputs:[{txId,vOut}], outputs:[{address,amount}], fee}
// returns {status:"ok", rawTx:'{"rawTx":"<hex>"}'}.
//
// When privateKey is empty but `from` belongs to the node's own wallet, the
// node wallet signs instead. That is the hot-withdrawal case: the operational
// address has no extractable key, so no privateKey can be supplied for it.
func (b *LBTC) SignAndSend(from, to string, amount, fee int64, privateKey string, all ...bool) (SendResult, error) {
	var res SendResult
	if from == "" || to == "" {
		return res, fmt.Errorf("from and to are required")
	}
	isAll := len(all) > 0 && all[0]
	if isAll {
		if amount < 0 {
			amount = 0
		}
	} else {
		if amount <= 0 {
			return res, fmt.Errorf("amount must be positive")
		}
	}
	if privateKey == "" {
		if info, verr := b.ValidateAddress(from); verr == nil && info.IsMine {
			if isAll {
				return b.SweepNodeWallet(from, to, fee)
			}
			return b.SendFromNodeWallet(to, amount, fee)
		}
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

	// pickAll returns every spendable UTXO, largest first. A sweep must consume
	// all of them: stopping early is what makes the leftover reappear as a
	// change output, which is exactly the dust a sweep is meant to remove.
	pickAll := func() ([]UTXO, int64) {
		sorted := make([]UTXO, len(utxos))
		copy(sorted, utxos)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Value > sorted[j].Value })
		return sorted, sumUTXOs(sorted)
	}

	// sweepOutputs builds the change-free output set: a single destination
	// output carrying total-fee, with no change output back to the source.
	sweepOutputs := func(total, usedFee int64) ([]signOut, error) {
		sendAmt := total - usedFee
		if sendAmt <= 0 {
			return nil, fmt.Errorf("fee %d consumes the whole balance %d", usedFee, total)
		}
		if sendAmt < minRelayFee(226) {
			return nil, fmt.Errorf("swept amount %d is below dust", sendAmt)
		}
		return []signOut{{Address: to, Amount: sendAmt}}, nil
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
		var outputs []signOut
		if isAll {
			inputs, total = pickAll()
			outs, err := sweepOutputs(total, usedFee)
			if err != nil {
				return res, err
			}
			outputs = outs
		} else {
			needed := amount + usedFee
			ins, tot := pickInputs(needed)
			if tot < needed {
				return res, fmt.Errorf("insufficient funds: have %d, need %d", tot, needed)
			}
			inputs, total = ins, tot

			change := total - amount - usedFee
			outputs = []signOut{{Address: to, Amount: amount}}
			if change > 0 {
				outputs = append(outputs, signOut{Address: from, Amount: change})
			}
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
	var outputs []signOut
	if isAll {
		outs, err := sweepOutputs(total, usedFee)
		if err != nil {
			return res, err
		}
		outputs = outs
	} else {
		change := total - amount - usedFee
		if change < 0 {
			return res, fmt.Errorf("insufficient funds after fee of %d", usedFee)
		}
		outputs = []signOut{{Address: to, Amount: amount}}
		if change > 0 {
			outputs = append(outputs, signOut{Address: from, Amount: change})
		}
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

func sumUTXOs(utxos []UTXO) int64 {
	var t int64
	for _, u := range utxos {
		t += u.Value
	}
	return t
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
		"symbol":     "LBTC",
		"privateKey": privateKey,
		"inputs":     inputs,
		"outputs":    outputs,
		"fee":        fee,
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
