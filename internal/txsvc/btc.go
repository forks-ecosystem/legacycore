package txsvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Bitcoin struct {
	api       string
	signerURL string
}

func NewBitcoin(api string) *Bitcoin {
	return &Bitcoin{api: strings.TrimRight(api, "/"), signerURL: "http://127.0.0.1:8053"}
}

func (b *Bitcoin) SetSignerURL(url string) *Bitcoin {
	if url != "" {
		b.signerURL = url
	}
	return b
}

func (b *Bitcoin) Name() string { return "BTC" }

type btcAddrStats struct {
	ChainStats struct {
		FundedTxoSum int64 `json:"funded_txo_sum"`
		SpentTxoSum  int64 `json:"spent_txo_sum"`
		TxCount      int64 `json:"tx_count"`
	} `json:"chain_stats"`
	MempoolStats struct {
		FundedTxoSum int64 `json:"funded_txo_sum"`
		SpentTxoSum  int64 `json:"spent_txo_sum"`
		TxCount      int64 `json:"tx_count"`
	} `json:"mempool_stats"`
}

func (b *Bitcoin) GetBalance(address string) (Balance, error) {
	var bal Balance
	if address == "" {
		return bal, errors.New("address is required")
	}
	var stats btcAddrStats
	if err := getJSON(b.api+"/address/"+address, &stats); err != nil {
		return bal, err
	}
	confirmed := stats.ChainStats.FundedTxoSum - stats.ChainStats.SpentTxoSum
	pending := stats.MempoolStats.FundedTxoSum - stats.MempoolStats.SpentTxoSum
	bal.Address = address
	bal.BalanceBaseUnits = confirmed + pending
	bal.Balance = float64(bal.BalanceBaseUnits) / 1e8
	bal.ReceivedBaseUnits = stats.ChainStats.FundedTxoSum + stats.MempoolStats.FundedTxoSum
	bal.Received = float64(bal.ReceivedBaseUnits) / 1e8
	bal.Confirmed = stats.MempoolStats.TxCount == 0
	return bal, nil
}

type btcUTXO struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Value  int64  `json:"value"`
	Status struct {
		Confirmed   bool  `json:"confirmed"`
		BlockHeight int64 `json:"block_height"`
	} `json:"status"`
}

func (b *Bitcoin) ListUnspent(address string, minConf int) ([]UTXO, error) {
	if address == "" {
		return nil, errors.New("address is required")
	}
	var list []btcUTXO
	if err := getJSON(b.api+"/address/"+address+"/utxo", &list); err != nil {
		return nil, err
	}
	tip := int64(0)
	if minConf > 1 {
		if _, h, err := b.tip(); err == nil {
			tip = h
		}
	}
	utxos := make([]UTXO, 0, len(list))
	for _, e := range list {
		if minConf > 0 && !e.Status.Confirmed {
			continue
		}
		if minConf > 1 && e.Status.BlockHeight > 0 && tip > e.Status.BlockHeight && int(tip-e.Status.BlockHeight+1) < minConf {
			continue
		}
		utxos = append(utxos, UTXO{
			Txid:    e.Txid,
			Vout:    e.Vout,
			Value:   e.Value,
			Height:  int32(e.Status.BlockHeight),
			Address: address,
		})
	}
	return utxos, nil
}

func (b *Bitcoin) tip() (int, int64, error) {
	body, err := b.getText(b.api + "/blocks/tip/height")
	if err != nil {
		return 0, 0, err
	}
	h, err := strconv.ParseInt(strings.TrimSpace(body), 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return int(h), h, nil
}

func (b *Bitcoin) getText(url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "legacycore-wallet-agent/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, truncate(string(body), 240))
	}
	return string(body), nil
}

func (b *Bitcoin) ValidateAddress(addr string) (AddrInfo, error) {
	var info AddrInfo
	if addr == "" {
		return info, errors.New("address is required")
	}
	bech32 := regexp.MustCompile(`^(bc1|BC1)[a-zA-HJ-NP-Z0-9]{25,62}$`)
	base58 := regexp.MustCompile(`^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$`)
	info.Address = addr
	info.IsValid = bech32.MatchString(addr) || base58.MatchString(addr)
	info.IsMine = false
	info.IsHybrid = false
	return info, nil
}

func (b *Bitcoin) GetNewAddress(label string) (string, error) {
	return "", ErrNotImplemented
}

func (b *Bitcoin) SendTransaction(from, to string, amount int64, opts TxOptions) (string, error) {
	return "", ErrNotImplemented
}

func (b *Bitcoin) GetTransaction(txid string) (*Tx, error) {
	if txid == "" {
		return nil, errors.New("txid is required")
	}
	var out struct {
		Txid   string `json:"txid"`
		Status struct {
			Confirmed   bool  `json:"confirmed"`
			BlockHeight int64 `json:"block_height"`
			BlockTime   int64 `json:"block_time"`
		} `json:"status"`
		Fee int64 `json:"fee"`
	}
	if err := getJSON(b.api+"/tx/"+txid, &out); err != nil {
		return nil, err
	}
	tx := &Tx{Txid: out.Txid, Fee: out.Fee, Status: "pending"}
	if out.Status.Confirmed {
		tx.Status = "confirmed"
		tx.Confirmations = 1
		tx.BlockHeight = out.Status.BlockHeight
		tx.Timestamp = timeFromUnix(out.Status.BlockTime)
	}
	return tx, nil
}

func (b *Bitcoin) GetConfirmations(txid string) (int, error) {
	if txid == "" {
		return 0, errors.New("txid is required")
	}
	var out struct {
		Status struct {
			Confirmed   bool  `json:"confirmed"`
			BlockHeight int64 `json:"block_height"`
		} `json:"status"`
	}
	if err := getJSON(b.api+"/tx/"+txid, &out); err != nil {
		return 0, err
	}
	if !out.Status.Confirmed {
		return 0, nil
	}
	_, tip, err := b.tip()
	if err != nil {
		return 1, nil
	}
	return int(tip - out.Status.BlockHeight + 1), nil
}

type btcTx struct {
	Txid   string `json:"txid"`
	Status struct {
		Confirmed   bool  `json:"confirmed"`
		BlockHeight int64 `json:"block_height"`
	} `json:"status"`
	Vin []struct {
		Prevout *struct {
			Address string `json:"scriptpubkey_address"`
			Value   int64  `json:"value"`
		} `json:"prevout"`
	} `json:"vin"`
	Vout []struct {
		Address string `json:"scriptpubkey_address"`
		Value   int64  `json:"value"`
	} `json:"vout"`
}

func (b *Bitcoin) GetHistory(address string) ([]HistoryEntry, error) {
	if address == "" {
		return nil, errors.New("address is required")
	}
	var list []btcTx
	if err := getJSON(b.api+"/address/"+address+"/txs", &list); err != nil {
		return nil, err
	}
	_, tip, err := b.tip()
	if err != nil {
		return nil, err
	}
	entries := make([]HistoryEntry, 0, len(list))
	for _, t := range list {
		var spent int64
		for _, i := range t.Vin {
			if i.Prevout != nil && i.Prevout.Address == address {
				spent += i.Prevout.Value
			}
		}
		var recv int64
		for _, o := range t.Vout {
			if o.Address == address {
				recv += o.Value
			}
		}
		var h HistoryEntry
		h.Txid = t.Txid
		if t.Status.Confirmed && t.Status.BlockHeight > 0 && tip >= t.Status.BlockHeight {
			h.Height = t.Status.BlockHeight
			h.Confirmations = tip - t.Status.BlockHeight + 1
			h.Mature = true
		}
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
		h.AmountDisplay = formatAtomicDec(h.Amount, 8, "BTC")
		entries = append(entries, h)
	}
	return entries, nil
}

type btcSignIn struct {
	TxId           string `json:"txId"`
	VOut           uint32 `json:"vOut"`
	Amount         int64  `json:"amount"`
	Address        string `json:"address"`
	NonWitnessUtxo string `json:"nonWitnessUtxo"`
}

type btcSignOut struct {
	Address string `json:"address"`
	Amount  int64  `json:"amount"`
}

func (b *Bitcoin) SignAndSend(from, to string, amount, fee int64, privateKey string) (SendResult, error) {
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
	if info, err := b.ValidateAddress(to); err != nil {
		return res, err
	} else if !info.IsValid {
		return res, errors.New("invalid destination address")
	}
	utxos, err := b.ListUnspent(from, 1)
	if err != nil {
		return res, err
	}
	if len(utxos) == 0 {
		return res, errors.New("no confirmed UTXOs available")
	}
	if fee <= 0 {
		est, err := b.Estimate(from, to, amount)
		if err != nil {
			return res, err
		}
		fee = est.Fee
	}
	var inputs []btcSignIn
	var total int64
	sel, total := pickGreedy(utxos, amount+fee)
	if total < amount+fee {
		return res, fmt.Errorf("insufficient funds: have %d, need %d", total, amount+fee)
	}
	for _, u := range sel {
		prevHex, err := b.getText(b.api + "/tx/" + u.Txid + "/hex")
		if err != nil {
			return res, err
		}
		inputs = append(inputs, btcSignIn{TxId: u.Txid, VOut: u.Vout, Amount: u.Value, Address: u.Address, NonWitnessUtxo: prevHex})
	}
	change := total - amount - fee
	outputs := []btcSignOut{{Address: to, Amount: amount}}
	if change > 0 {
		outputs = append(outputs, btcSignOut{Address: from, Amount: change})
	}
	hex, err := b.callSigner(privateKey, inputs, outputs, fee)
	if err != nil {
		return res, err
	}
	res.RawTx = hex
	res.Size = len(hex) / 2
	res.Fee = fee
	txid, err := b.broadcast(hex)
	if err != nil {
		return res, err
	}
	res.Txid = txid
	return res, nil
}

func (b *Bitcoin) callSigner(privateKey string, inputs []btcSignIn, outputs []btcSignOut, fee int64) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"symbol":     "BTC",
		"privateKey": privateKey,
		"inputs":     inputs,
		"outputs":    outputs,
		"fee":        fee,
	})
	respBody, status, err := postRaw(b.signerURL+"/v2/tx", body, "application/json")
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
	var inner struct {
		RawTx string `json:"rawTx"`
	}
	_ = json.Unmarshal([]byte(r.RawTx), &inner)
	hex := inner.RawTx
	if hex == "" {
		hex = strings.Trim(r.RawTx, `"`)
	}
	if hex == "" {
		return "", errors.New("signer: empty signed tx")
	}
	return hex, nil
}

func (b *Bitcoin) broadcast(hex string) (string, error) {
	respBody, status, err := postRaw(b.api+"/tx", []byte(hex), "text/plain")
	if err != nil {
		return "", err
	}
	if status >= 300 {
		return "", fmt.Errorf("broadcast: HTTP %d: %s", status, truncate(string(respBody), 240))
	}
	txid := strings.TrimSpace(string(respBody))
	if len(txid) != 64 {
		return "", fmt.Errorf("broadcast: unexpected response: %s", truncate(string(respBody), 160))
	}
	return txid, nil
}

func (b *Bitcoin) Estimate(from, to string, amount int64) (FeeEstimate, error) {
	var est FeeEstimate
	if from == "" || to == "" {
		return est, errors.New("from and to are required")
	}
	if amount <= 0 {
		return est, errors.New("amount must be positive")
	}
	if info, err := b.ValidateAddress(to); err != nil {
		return est, err
	} else if !info.IsValid {
		return est, errors.New("invalid destination address")
	}
	utxos, err := b.ListUnspent(from, 1)
	if err != nil {
		return est, err
	}
	if len(utxos) == 0 {
		return est, errors.New("no confirmed UTXOs available")
	}
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
	return est, errors.New("fee estimation did not converge")
}

var _ Blockchain = (*Bitcoin)(nil)
var _ Estimator = (*Bitcoin)(nil)
