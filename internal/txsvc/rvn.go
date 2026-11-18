package txsvc

// RVN implements Blockchain for Ravencoin (mainnet ravend, docker
// rvn-core, bitcoin-core style JSON-RPC). Mirrors the LBTC adapter but leans
// on the node wallet for everything wallet-related: ravend has no address
// index, so per-address balance/history come out of listunspent and the
// wallet's own transaction list (the exchange owns every deposit address
// through the node wallet, so that is sufficient).
//
// Amounts are base units (1 RVN = 1e8), same convention as LBTC/BTC here.
//
// Auth: static rpcuser/rpcpassword (raven.conf), unlike the cookie-only LBTC
// node — no cookie handling needed.

import (
	"fmt"
	"math"
	"strings"
	"sync"
)

type RVN struct {
	rpc       *RPCClient
	signerURL string
}

func NewRVN(rpcURL, user, pass string) *RVN {
	return &RVN{
		rpc:       NewRPCClient(rpcURL, user, pass),
		signerURL: "http://127.0.0.1:8053",
	}
}

func (b *RVN) SetSignerURL(url string) *RVN {
	if url != "" {
		b.signerURL = url
	}
	return b
}

func (b *RVN) Name() string { return "RVN" }

// rvnBaseUnits: 1 RVN = 1e8 base units.
const rvnBaseUnits = 100000000

func rvnFromFloat(v float64) int64 { return int64(math.Round(v * rvnBaseUnits)) }

// formatRVNTx renders base units as the decimal RVN string the node's RPC
// expects, without float rounding surprises.
func formatRVNTx(v int64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	s := fmt.Sprintf("%d.%08d", v/rvnBaseUnits, v%rvnBaseUnits)
	if neg {
		return "-" + s
	}
	return s
}

// listAddressUTXOs returns confirmed UTXOs paying address via the node's
// listunspent (minConf..maxConf window + explicit address filter).
func (b *RVN) listAddressUTXOs(address string, minConf int) ([]map[string]any, error) {
	if address == "" {
		return nil, fmt.Errorf("address is required")
	}
	res, err := b.rpc.Call("listunspent", []any{minConf, 9999999, []any{address}})
	if err != nil {
		return nil, err
	}
	list, ok := res.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected listunspent result")
	}
	rows := make([]map[string]any, 0, len(list))
	for _, row := range list {
		if m, ok := row.(map[string]any); ok {
			rows = append(rows, m)
		}
	}
	return rows, nil
}

// --- watch-only tracking for arbitrary (self-custody) addresses ---
//
// ravend по умолчанию не знает чужих адресов, поэтому getreceivedbyaddress
// и listunspent для них возвращают 0. importaddress (без rescan) добавляет
// адрес в кошелёк как watch-only; затем rescanblockchain подхватывает его
// транзакции. Авто-импорт срабатывает при первом запросе баланса чужого
// адреса — баланс появится после завершения фонового rescana (~минуты).
var rvnWatched sync.Map
var rvnRescanMu sync.Mutex

// ensureWatched импортирует чужой адрес как watch-only (если ещё не импортирован)
// и запускает фоновый rescan последних блоков. Идемпотентно.
func (b *RVN) ensureWatched(addr string) {
	if addr == "" {
		return
	}
	if _, ok := rvnWatched.Load(addr); ok {
		return
	}
	info, err := b.ValidateAddress(addr)
	if err != nil || !info.IsValid {
		return
	}
	if info.IsMine {
		rvnWatched.Store(addr, true)
		return
	}
	// importaddress может вернуть ошибку "already have address" — это нормально.
	_, _ = b.rpc.Call("importaddress", []any{addr, "watch", false})
	rvnWatched.Store(addr, true)

	// Фоновый rescan: берём последние ~200k блоков (~140 дней для RVN).
	go func() {
		rvnRescanMu.Lock()
		defer rvnRescanMu.Unlock()
		tipRes, err := b.rpc.Call("getblockcount", []any{})
		if err != nil {
			return
		}
		tip, ok := tipRes.(float64)
		if !ok {
			return
		}
		start := int(tip) - 200000
		if start < 1 {
			start = 1
		}
		_, _ = b.rpc.Call("rescanblockchain", []any{start, int(tip)})
	}()
}

// GetBalance — для собственных адресов ноды (ismine) считается из
// listunspent/getreceivedbyaddress; для чужих сначала авто-импортируется
// watch-only адрес (ensureWatched) и возвращается то, что уже известно ноде.
func (b *RVN) GetBalance(address string) (Balance, error) {
	var bal Balance
	if address == "" {
		return bal, fmt.Errorf("address is required")
	}
	b.ensureWatched(address)
	rows, err := b.listAddressUTXOs(address, 1)
	if err != nil {
		return bal, err
	}
	var spendable int64
	for _, m := range rows {
		if v, ok := m["amount"].(float64); ok {
			spendable += rvnFromFloat(v)
		}
	}
	var received int64
	res, err := b.rpc.Call("getreceivedbyaddress", []any{address, 1})
	if err == nil {
		if v, ok := res.(float64); ok {
			received = rvnFromFloat(v)
		}
	}
	bal.Address = address
	bal.BalanceBaseUnits = spendable
	bal.Balance = float64(spendable) / rvnBaseUnits
	bal.ReceivedBaseUnits = received
	bal.Received = float64(received) / rvnBaseUnits
	bal.Confirmed = true
	return bal, nil
}

func (b *RVN) ListUnspent(address string, minConf int) ([]UTXO, error) {
	b.ensureWatched(address)
	rows, err := b.listAddressUTXOs(address, minConf)
	if err != nil {
		return nil, err
	}
	var tip float64
	if res, err := b.rpc.Call("getblockcount", []any{}); err == nil {
		if v, ok := res.(float64); ok {
			tip = v
		}
	}
	utxos := make([]UTXO, 0, len(rows))
	for _, m := range rows {
		var u UTXO
		if v, ok := m["txid"].(string); ok {
			u.Txid = v
		}
		if v, ok := m["vout"].(float64); ok {
			u.Vout = uint32(v)
		}
		if v, ok := m["amount"].(float64); ok {
			u.Value = rvnFromFloat(v)
		}
		if v, ok := m["address"].(string); ok {
			u.Address = v
		}
		if v, ok := m["scriptPubKey"].(string); ok {
			u.ScriptHex = v
		}
		if confs, ok := m["confirmations"].(float64); ok && tip > 0 {
			u.Height = int32(tip - confs + 1)
		}
		utxos = append(utxos, u)
	}
	return utxos, nil
}

func (b *RVN) ValidateAddress(addr string) (AddrInfo, error) {
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
	if v, ok := m["pubkeyhash"].(string); ok {
		info.PubKeyHash = v
	}
	return info, nil
}

func (b *RVN) GetConfirmations(txid string) (int, error) {
	if txid == "" {
		return 0, fmt.Errorf("txid is required")
	}
	res, err := b.rpc.Call("getrawtransaction", []any{txid, 1})
	if err != nil {
		// Unknown to this node (pruned/never seen) — treat as unconfirmed.
		return 0, nil
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

// GetHistory walks the node wallet's own transaction list and keeps the events
// for address. The exchange owns every deposit address through the node
// wallet, so the wallet list covers the addresses we care about.
func (b *RVN) GetHistory(address string) ([]HistoryEntry, error) {
	if address == "" {
		return nil, fmt.Errorf("address is required")
	}
	res, err := b.rpc.Call("listtransactions", []any{"*", 1000, 0, false})
	if err != nil {
		return nil, err
	}
	list, ok := res.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected listtransactions result")
	}
	var tip float64
	if r, err := b.rpc.Call("getblockcount", []any{}); err == nil {
		if v, ok := r.(float64); ok {
			tip = v
		}
	}
	entries := make([]HistoryEntry, 0, len(list))
	for _, row := range list {
		e, ok := row.(map[string]any)
		if !ok {
			continue
		}
		if a, ok := e["address"].(string); !ok || !strings.EqualFold(a, address) {
			continue
		}
		var h HistoryEntry
		if v, ok := e["txid"].(string); ok {
			h.Txid = v
		}
		if v, ok := e["blockheight"].(float64); ok {
			h.Height = int64(v)
		} else if confs, ok := e["confirmations"].(float64); ok && tip > 0 {
			h.Height = int64(tip - confs + 1)
			h.Confirmations = int64(confs)
		}
		if v, ok := e["confirmations"].(float64); ok {
			h.Confirmations = int64(v)
		}
		if v, ok := e["category"].(string); ok {
			switch v {
			case "receive", "immature":
				h.Type = "receive"
				h.Coinbase = v == "immature"
				h.Mature = v != "immature"
			case "send":
				h.Type = "send"
				h.Mature = true
			default:
				continue
			}
		}
		if v, ok := e["amount"].(float64); ok {
			h.Amount = rvnFromFloat(v)
			h.AmountDisplay = formatRVNTx(h.Amount)
		}
		entries = append(entries, h)
	}
	return entries, nil
}

// GetNewAddress creates a node-owned receive address (the key lands in the
// ravend wallet.dat and is backed up with the node data dir). The exchange
// persists only the address.
func (b *RVN) GetNewAddress(label string) (string, error) {
	params := []any{}
	if strings.TrimSpace(label) != "" {
		params = []any{label}
	}
	res, err := b.rpc.Call("getnewaddress", params)
	if err != nil {
		return "", err
	}
	addr, ok := res.(string)
	if !ok || !strings.HasPrefix(addr, "R") {
		return "", fmt.Errorf("unexpected getnewaddress result: %v", res)
	}
	return addr, nil
}

// SendTransaction pays `to` from the node wallet (the node wallet is the
// signer of record; the wallet picks the source UTXOs itself, so `from` is
// only checked for membership — the debit lands on the wallet as a whole).
func (b *RVN) SendTransaction(from, to string, amount int64, opts TxOptions) (string, error) {
	if to == "" {
		return "", fmt.Errorf("to is required")
	}
	if amount <= 0 {
		return "", fmt.Errorf("amount must be positive")
	}
	if strings.TrimSpace(from) != "" {
		info, err := b.ValidateAddress(from)
		if err != nil {
			return "", err
		}
		if !info.IsValid {
			return "", fmt.Errorf("from address is invalid: %s", from)
		}
		if !info.IsMine {
			return "", fmt.Errorf("from address is not owned by the node wallet: %s", from)
		}
	}
	// sanity: the receiving address must at least be well-formed
	if info, err := b.ValidateAddress(to); err != nil {
		return "", err
	} else if !info.IsValid {
		return "", fmt.Errorf("to address is invalid: %s", to)
	}
	res, err := b.rpc.Call("sendtoaddress", []any{
		to, formatRVNTx(amount), "forkex", "withdrawal", opts.SubtractFeeFromAmount,
	})
	if err != nil {
		return "", err
	}
	txid, ok := res.(string)
	if !ok || txid == "" {
		return "", fmt.Errorf("unexpected sendtoaddress result: %v", res)
	}
	return txid, nil
}

// GetTransaction normalizes a wallet transaction (the node wallet owns the
// exchange addresses, so gettransaction covers our sends and deposits).
func (b *RVN) GetTransaction(txid string) (*Tx, error) {
	if txid == "" {
		return nil, fmt.Errorf("txid is required")
	}
	res, err := b.rpc.Call("gettransaction", []any{txid})
	if err != nil {
		// Not a wallet transaction — still report confirmation count.
		res, err2 := b.rpc.Call("getrawtransaction", []any{txid, 1})
		if err2 != nil {
			return nil, err
		}
		m, ok := res.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unexpected getrawtransaction result")
		}
		tx := &Tx{Txid: txid}
		if v, ok := m["confirmations"].(float64); ok {
			tx.Confirmations = int(v)
		}
		return tx, nil
	}
	m, ok := res.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected gettransaction result")
	}
	tx := &Tx{Txid: txid}
	if v, ok := m["amount"].(float64); ok {
		tx.Amount = rvnFromFloat(v)
	}
	if v, ok := m["fee"].(float64); ok {
		tx.Fee = rvnFromFloat(v)
	}
	if v, ok := m["confirmations"].(float64); ok {
		tx.Confirmations = int(v)
	}
	return tx, nil
}

// Estimate implements the optional Estimator hook for /api/chain/rvn/estimate:
// dry-run input selection against the from-address UTXOs and minimum relay fee.
func (b *RVN) Estimate(from, to string, amount int64) (FeeEstimate, error) {
	var est FeeEstimate
	if amount <= 0 {
		return est, fmt.Errorf("amount must be positive")
	}
	rows, err := b.listAddressUTXOs(from, 1)
	if err != nil {
		return est, err
	}
	var have int64
	inputs := 0
	for _, m := range rows {
		if v, ok := m["amount"].(float64); ok {
			have += rvnFromFloat(v)
			inputs++
			if have >= amount {
				break
			}
		}
	}
	if have < amount {
		return est, fmt.Errorf("insufficient confirmed balance for %s: have %d, need %d", from, have, amount)
	}
	// ~148 bytes per P2PKH input + ~34 per output + ~10 overhead; minimum
	// relay fee on Ravencoin is 1,000 base units per KB (DEFAULT_MIN_RELAY_FEE).
	size := 10 + 148*inputs + 34*2
	fee := int64(1000) * int64((size+999)/1000)
	est.Fee = fee
	est.Change = have - amount - fee
	if est.Change < 0 {
		est.Change = 0
	}
	est.Inputs = inputs
	est.Size = size
	return est, nil
}

// RPCPassThrough exposes raw node JSON-RPC for ops scripts (getnewaddress,
// listunspent, getrawtransaction, ...), mirroring the LBTC agent pass-through.
// The policy blacklist (key export, wallet lifecycle) is enforced by the
// agent handler before this is reached.
func (b *RVN) RPCPassThrough(method string, params []any) (any, error) {
	return b.rpc.Call(strings.ToLower(strings.TrimSpace(method)), params)
}

// SignAndSend is the agent's send route for node-owned wallets: keys never
// leave the node, so privateKey is refused by design. With a wallet-owned
// `from`:
//   all=true  → sweep: every confirmed UTXO of `from` becomes one output to
//               `to` (sendtoaddress with subtractfeefromamount, so no change
//               output is left behind — the ravend analogue of sweepallraw).
//   otherwise → sendtoaddress(to, amount). ravend has no per-send fee
//               parameter; a requested fee is advisory, the actually paid fee
//               is read back from gettransaction and reported in the result.
func (b *RVN) SignAndSend(from, to string, amount, fee int64, privateKey string, all ...bool) (SendResult, error) {
	var res SendResult
	if privateKey != "" {
		return res, fmt.Errorf("RVN uses node-owned wallets: private keys are not accepted")
	}
	if from == "" || to == "" {
		return res, fmt.Errorf("from and to are required")
	}
	if info, err := b.ValidateAddress(to); err != nil {
		return res, err
	} else if !info.IsValid {
		return res, fmt.Errorf("invalid destination address: %s", to)
	}
	if info, err := b.ValidateAddress(from); err != nil {
		return res, err
	} else if !info.IsValid {
		return res, fmt.Errorf("invalid source address: %s", from)
	} else if !info.IsMine {
		return res, fmt.Errorf("source address is not owned by the node wallet: %s", from)
	}

	var sendAmt int64
	subtractFee := false
	if len(all) > 0 && all[0] {
		rows, err := b.listAddressUTXOs(from, 1)
		if err != nil {
			return res, err
		}
		var total int64
		for _, m := range rows {
			if v, ok := m["amount"].(float64); ok {
				total += rvnFromFloat(v)
			}
		}
		if total <= 0 {
			return res, fmt.Errorf("no confirmed balance to sweep from %s", from)
		}
		// Whole balance in one output: the recipient gets total minus the real
		// network fee. A requested fee is folded into that subtraction by the
		// node itself; asking for a fee above the balance is meaningless here.
		sendAmt = total
		subtractFee = true
	} else {
		if amount <= 0 {
			return res, fmt.Errorf("amount must be positive")
		}
		sendAmt = amount
	}

	res.Amount = sendAmt
	res.Fee = fee
	raw, err := b.rpc.Call("sendtoaddress", []any{
		to, formatRVNTx(sendAmt), "forkex", "withdrawal", subtractFee,
	})
	if err != nil {
		return res, fmt.Errorf("sendtoaddress: %v", err)
	}
	txid, ok := raw.(string)
	if !ok || txid == "" {
		return res, fmt.Errorf("unexpected sendtoaddress result: %v", raw)
	}
	res.Txid = txid

	// Read back the actual fee: ravend bills what its feerate produced, not
	// what the caller suggested.
	if tx, err := b.GetTransaction(txid); err == nil && tx != nil {
		if tx.Fee != 0 {
			res.Fee = -tx.Fee // wallet reports fee as a negative amount
		}
	}
	return res, nil
}

var _ Blockchain = (*RVN)(nil)
var _ Estimator = (*RVN)(nil)

// RPCPassThrough is implemented by node-backed chains (LBTC handled by the
// agent's own RPC client, RVN via its adapter) that proxy raw JSON-RPC.
type RPCPassThrough interface {
	RPCPassThrough(method string, params []any) (any, error)
}

var _ RPCPassThrough = (*RVN)(nil)
