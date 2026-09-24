package txsvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var kaspaRequiredFeeRE = regexp.MustCompile(`(?i)required amount of (\d+)`)

const kaspaDustCutoff = int64(10000)

type ProbeEstimator interface {
	EstimateWithKey(from, to string, amount int64, privateKey string) (FeeEstimate, error)
}

type KaspaRest struct {
	symbol    string
	api       string
	signerURL string
	prefix    string
}

func NewKaspaRest(symbol, api string) *KaspaRest {
	k := &KaspaRest{symbol: symbol, api: strings.TrimRight(api, "/"), signerURL: "http://127.0.0.1:8053", prefix: strings.ToLower(symbol)}
	if strings.EqualFold(symbol, "KAS") {
		k.prefix = "kaspa"
	}
	return k
}

func (k *KaspaRest) SetSignerURL(url string) *KaspaRest {
	if url != "" {
		k.signerURL = url
	}
	return k
}

func (k *KaspaRest) Name() string { return k.symbol }

func (k *KaspaRest) GetBalance(address string) (Balance, error) {
	var bal Balance
	if address == "" {
		return bal, errors.New("address is required")
	}
	var out struct {
		Address string          `json:"address"`
		Balance json.RawMessage `json:"balance"`
	}
	if err := getJSON(k.api+"/addresses/"+address+"/balance", &out); err != nil {
		return bal, err
	}
	units := parseAtomicRaw(out.Balance)
	bal.Address = address
	bal.BalanceBaseUnits = units
	bal.Balance = float64(units) / 1e8
	bal.ReceivedBaseUnits = units
	bal.Received = float64(units) / 1e8
	bal.Confirmed = true
	return bal, nil
}

type kaspaUTXO struct {
	Address  string `json:"address"`
	Outpoint struct {
		TransactionID string `json:"transactionId"`
		Index         uint32 `json:"index"`
	} `json:"outpoint"`
	UtxoEntry struct {
		Amount          json.RawMessage `json:"amount"`
		BlockDaaScore   json.RawMessage `json:"blockDaaScore"`
		ScriptPublicKey struct {
			Version uint16 `json:"version"`
			Script  string `json:"scriptPublicKey"`
		} `json:"scriptPublicKey"`
		IsCoinbase bool `json:"isCoinbase"`
		Spent      bool `json:"spent"`
	} `json:"utxoEntry"`
}

func (k *KaspaRest) ListUnspent(address string, minConf int) ([]UTXO, error) {
	if address == "" {
		return nil, errors.New("address is required")
	}
	var list []kaspaUTXO
	if err := getJSON(k.api+"/addresses/"+address+"/utxos", &list); err != nil {
		if isHTTP404(err) {
			return []UTXO{}, nil
		}
		return nil, err
	}
	utxos := make([]UTXO, 0, len(list))
	for _, e := range list {
		if e.UtxoEntry.Spent {
			continue
		}
		if e.UtxoEntry.BlockDaaScore == nil {
			continue
		}
		daaScore := parseAtomicRaw(e.UtxoEntry.BlockDaaScore)
		if daaScore == 0 {
			continue
		}
		utxos = append(utxos, UTXO{
			Txid:      e.Outpoint.TransactionID,
			Vout:      e.Outpoint.Index,
			Value:     parseAtomicRaw(e.UtxoEntry.Amount),
			Address:   e.Address,
			Height:    int32(daaScore),
			Coinbase:  e.UtxoEntry.IsCoinbase,
			ScriptHex: e.UtxoEntry.ScriptPublicKey.Script,
		})
	}
	return utxos, nil
}

func (k *KaspaRest) ValidateAddress(addr string) (AddrInfo, error) {
	var info AddrInfo
	if addr == "" {
		return info, errors.New("address is required")
	}
	re := regexp.MustCompile(`^` + k.prefix + `:[qQpP][a-z0-9]{30,90}$`)
	info.Address = addr
	info.IsValid = re.MatchString(addr)
	info.IsMine = false
	info.IsHybrid = false
	return info, nil
}

func (k *KaspaRest) GetNewAddress(label string) (string, error) {
	return "", ErrNotImplemented
}

func (k *KaspaRest) SendTransaction(from, to string, amount int64, opts TxOptions) (string, error) {
	return "", ErrNotImplemented
}

func (k *KaspaRest) GetTransaction(txid string) (*Tx, error) {
	return nil, ErrNotImplemented
}

func isHTTP404(err error) bool {
	return err != nil && strings.Contains(err.Error(), "HTTP 404")
}

type kaspaFTx struct {
	TransactionID string   `json:"transaction_id"`
	BlockHash     []string `json:"block_hash"`
	BlockTime     int64    `json:"block_time"`
	IsAccepted    bool     `json:"is_accepted"`
	AccBlueScore  *int64   `json:"accepting_block_blue_score"`
	IsCoinbase    bool     `json:"is_coinbase"`
	Inputs        []struct {
		PreviousOutpointHash     string  `json:"previous_outpoint_hash"`
		PreviousOutpointIndex    string  `json:"previous_outpoint_index"`
		PreviousOutpointAddress  *string `json:"previous_outpoint_address"`
		PreviousOutpointAmount   *string `json:"previous_outpoint_amount"`
		PreviousOutpointResolved *struct {
			Address string `json:"address"`
			Amount  string `json:"amount"`
		} `json:"previous_outpoint_resolved"`
	} `json:"inputs"`
	Outputs []struct {
		Address string          `json:"script_public_key_address"`
		Amount  json.RawMessage `json:"amount"`
	} `json:"outputs"`
}

type kaspaResolvedTx struct {
	Outputs []struct {
		Index   uint32          `json:"index"`
		Address string          `json:"script_public_key_address"`
		Amount  json.RawMessage `json:"amount"`
	} `json:"outputs"`
}

func (k *KaspaRest) resolveOutpoint(hash, index string, cache map[string]*kaspaResolvedTx) (string, int64) {
	if hash == "" {
		return "", 0
	}
	rt, ok := cache[hash]
	if !ok {
		rt = &kaspaResolvedTx{}
		if err := getJSON(k.api+"/transactions/"+hash, rt); err != nil {
			rt = &kaspaResolvedTx{}
		}
		cache[hash] = rt
	}
	idx, _ := strconv.ParseUint(index, 10, 32)
	for _, o := range rt.Outputs {
		if uint64(o.Index) == idx {
			return o.Address, parseAtomicRaw(o.Amount)
		}
	}
	return "", 0
}

func (k *KaspaRest) GetConfirmations(txid string) (int, error) {
	if txid == "" {
		return 0, errors.New("txid is required")
	}
	var out struct {
		BlockHash []string `json:"block_hash"`
	}
	if err := getJSON(k.api+"/transactions/"+txid, &out); err != nil {
		if isHTTP404(err) {
			return 0, nil
		}
		return 0, err
	}
	if len(out.BlockHash) > 0 {
		return 1, nil
	}
	return 0, nil
}

func (k *KaspaRest) GetHistory(address string) ([]HistoryEntry, error) {
	if address == "" {
		return nil, errors.New("address is required")
	}
	var list []kaspaFTx
	if err := getJSON(k.api+"/addresses/"+address+"/full-transactions", &list); err != nil {
		if isHTTP404(err) {
			return []HistoryEntry{}, nil
		}
		return nil, err
	}
	entries := make([]HistoryEntry, 0, len(list))
	resolved := make(map[string]*kaspaResolvedTx)
	for _, ftx := range list {
		var recv int64
		for _, o := range ftx.Outputs {
			if o.Address == address {
				recv += parseAtomicRaw(o.Amount)
			}
		}
		var spent int64
		for _, i := range ftx.Inputs {
			if i.PreviousOutpointAddress != nil && *i.PreviousOutpointAddress == address {
				spent += parseAtomic(i.PreviousOutpointAmount)
				continue
			}
			if i.PreviousOutpointResolved != nil && i.PreviousOutpointResolved.Address == address {
				spent += parseAtomic(i.PreviousOutpointResolved.Amount)
				continue
			}
			if addr, amt := k.resolveOutpoint(i.PreviousOutpointHash, i.PreviousOutpointIndex, resolved); addr == address {
				spent += amt
			}
		}
		var h HistoryEntry
		h.Txid = ftx.TransactionID
		if ftx.AccBlueScore != nil {
			h.Height = *ftx.AccBlueScore
		}
		if ftx.IsAccepted {
			h.Confirmations = 1
		}
		h.Coinbase = ftx.IsCoinbase
		h.Mature = true
		switch {
		case spent > 0:
			h.Type = "send"
			h.Amount = spent - recv
		case recv > 0:
			h.Type = "receive"
			h.Amount = recv
		default:
			continue
		}
		h.AmountDisplay = formatAtomicDec(h.Amount, 8, k.symbol)
		entries = append(entries, h)
	}
	return entries, nil
}

type kaspaSignIn struct {
	TxId    string `json:"txId"`
	VOut    uint32 `json:"vOut"`
	Amount  string `json:"amount"`
	Address string `json:"address"`
}

type kaspaSignOut struct {
	Address string `json:"address"`
	Amount  string `json:"amount"`
}

func kaspaInputs(utxos []UTXO) []kaspaSignIn {
	out := make([]kaspaSignIn, 0, len(utxos))
	for _, u := range utxos {
		out = append(out, kaspaSignIn{TxId: u.Txid, VOut: u.Vout, Amount: strconv.FormatInt(u.Value, 10), Address: u.Address})
	}
	return out
}

func pickGreedy(utxos []UTXO, needed int64) ([]UTXO, int64) {
	sorted := make([]UTXO, len(utxos))
	copy(sorted, utxos)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Value > sorted[j].Value })
	var total int64
	sel := sorted[:0]
	for _, u := range sorted {
		sel = append(sel, u)
		total += u.Value
		if total >= needed {
			break
		}
	}
	return sel, total
}

func (k *KaspaRest) callSigner(privateKey string, inputs []kaspaSignIn, to, changeAddr string, amount, fee int64) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"symbol":     k.symbol,
		"privateKey": privateKey,
		"inputs":     inputs,
		"outputs":    []kaspaSignOut{{Address: to, Amount: strconv.FormatInt(amount, 10)}},
		"fee":        fee,
		"address":    changeAddr,
		"dustSize":   kaspaDustCutoff,
	})
	respBody, status, err := postRaw(k.signerURL+"/v2/tx", body, "application/json")
	if err != nil {
		return "", fmt.Errorf("signer: %v", err)
	}
	var r struct {
		Status  string `json:"status"`
		RawTx   string `json:"rawTx"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(respBody, &r)
	if status >= 300 || r.Status != "ok" {
		msg := r.Message
		if msg == "" {
			msg = truncate(string(respBody), 240)
		}
		return "", fmt.Errorf("signer returned %d: %s", status, msg)
	}
	if r.RawTx == "" {
		return "", fmt.Errorf("signer: unexpected response: %s", truncate(string(respBody), 200))
	}
	return r.RawTx, nil
}

func (k *KaspaRest) broadcast(raw string) (string, error) {
	respBody, status, err := postRaw(k.api+"/transactions", []byte(raw), "application/json")
	if err != nil {
		return "", err
	}
	if status >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &e)
		msg := e.Error
		if msg == "" {
			msg = string(respBody)
		}
		return "", errors.New(massageKaspaErr(msg))
	}
	var r struct {
		TransactionID string `json:"transactionId"`
	}
	_ = json.Unmarshal(respBody, &r)
	if r.TransactionID == "" {
		return "", fmt.Errorf("broadcast: unexpected response: %s", truncate(string(respBody), 160))
	}
	return r.TransactionID, nil
}

func massageKaspaErr(msg string) string {
	re := regexp.MustCompile(`(?i)^rejected transaction [0-9a-f]{64}: ?`)
	msg = re.ReplaceAllString(msg, "")
	re2 := regexp.MustCompile(`(?i)^transaction [0-9a-f]{64} is not standard: ?`)
	msg = re2.ReplaceAllString(msg, "")
	return strings.TrimSpace(msg)
}

func (k *KaspaRest) SignAndSend(from, to string, amount, fee int64, privateKey string) (SendResult, error) {
	var res SendResult
	if from == "" || to == "" {
		return res, errors.New("from and to are required")
	}
	if amount <= 0 {
		return res, errors.New("amount must be positive")
	}
	if privateKey == "" {
		return res, errors.New("privateKey is required")
	}
	if info, err := k.ValidateAddress(to); err != nil {
		return res, err
	} else if !info.IsValid {
		return res, errors.New("invalid destination address")
	}
	utxos, err := k.ListUnspent(from, 1)
	if err != nil {
		return res, err
	}
	if len(utxos) == 0 {
		return res, errors.New("no confirmed UTXOs available")
	}
	if fee <= 0 {
		est, err := k.EstimateWithKey(from, to, amount, privateKey)
		if err != nil {
			return res, err
		}
		fee = est.Fee
	}
	inputs, total := pickGreedy(utxos, amount+fee)
	if total < amount+fee {
		return res, fmt.Errorf("insufficient funds: have %d, need %d", total, amount+fee)
	}
	raw, err := k.callSigner(privateKey, kaspaInputs(inputs), to, from, amount, fee)
	if err != nil {
		return res, err
	}
	txid, err := k.broadcast(raw)
	if err != nil {
		return res, err
	}
	res.Txid = txid
	res.RawTx = raw
	res.Size = len(raw)
	res.Fee = feePaidFromRaw(raw, total)
	return res, nil
}

func feePaidFromRaw(raw string, totalIn int64) int64 {
	var doc struct {
		Transaction struct {
			Outputs []struct {
				Amount string `json:"amount"`
			} `json:"outputs"`
		} `json:"transaction"`
	}
	_ = json.Unmarshal([]byte(raw), &doc)
	var changeOut int64
	for _, o := range doc.Transaction.Outputs {
		if v := parseAtomic(o.Amount); v > 0 {
			changeOut += v
		}
	}
	return totalIn - changeOut
}

func (k *KaspaRest) Estimate(from, to string, amount int64) (FeeEstimate, error) {
	return k.EstimateWithKey(from, to, amount, "")
}

func (k *KaspaRest) EstimateWithKey(from, to string, amount int64, privateKey string) (FeeEstimate, error) {
	var est FeeEstimate
	if from == "" || to == "" {
		return est, errors.New("from and to are required")
	}
	if amount <= 0 {
		return est, errors.New("amount must be positive")
	}
	if privateKey == "" {
		return est, errors.New("privateKey required for fee estimation on this chain")
	}
	if info, err := k.ValidateAddress(to); err != nil {
		return est, err
	} else if !info.IsValid {
		return est, errors.New("invalid destination address")
	}
	utxos, err := k.ListUnspent(from, 1)
	if err != nil {
		return est, err
	}
	if len(utxos) == 0 {
		return est, errors.New("no confirmed UTXOs available")
	}

	required := int64(0)
	var sel []UTXO
	var total int64
	for iter := 0; iter < 12; iter++ {
		next, nextTotal := pickGreedy(utxos, amount+required)
		if nextTotal < amount+required {
			return est, fmt.Errorf("insufficient funds: have %d, need %d", nextTotal, amount+required)
		}
		if iter > 0 && sameInputs(sel, next) {
			est.Fee = required
			est.Change = nextTotal - amount - required
			est.Inputs = len(next)
			if probe, err := k.callSigner(privateKey, kaspaInputs(next), to, from, amount, required); err == nil {
				est.Size = len(probe)
			}
			return est, nil
		}
		sel, total = next, nextTotal
		rawProbe, err := k.callSigner(privateKey, kaspaInputs(sel), to, from, amount, 1)
		if err != nil {
			return est, err
		}
		respBody, status, err := postRaw(k.api+"/transactions", []byte(rawProbe), "application/json")
		if err != nil {
			return est, err
		}
		m := kaspaRequiredFeeRE.FindStringSubmatch(string(respBody))
		if len(m) == 2 {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			if n <= required {
				required = required + 1
			} else {
				required = n
			}
			continue
		}
		if status < 300 {
			est.Fee = required
			est.Change = total - amount - required
			est.Inputs = len(sel)
			est.Size = len(rawProbe)
			return est, nil
		}
		return est, errors.New(massageKaspaErr(string(respBody)))
	}
	est.Fee = required
	est.Change = total - amount - required
	est.Inputs = len(sel)
	return est, nil
}

func sameInputs(a, b []UTXO) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Txid != b[i].Txid || a[i].Vout != b[i].Vout {
			return false
		}
	}
	return true
}

var _ Blockchain = (*KaspaRest)(nil)
var _ Estimator = (*KaspaRest)(nil)
var _ ProbeEstimator = (*KaspaRest)(nil)
