package txsvc

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// ---------------------------------------------------------------------------
// BSC / BEP-20 token chain (USDT on Binance Smart Chain) — public JSON-RPC.
//
// Base units: the exchange stores token amounts with 8 decimal places
// (numeric(30,8)), so this chain reports and accepts amounts scaled by 1e8
// tokens ("8dp scale"), NOT wei. In wei scale an int64 would overflow above
// ~9.2 tokens; at 8dp scale it holds ~92 billion.
//
// Reads:
//   * token balance — eth_call balanceOf on the token contract;
//   * native (BNB) gas balance — eth_getBalance, exposed via the gasbalance op;
//   * history — eth_getLogs over the token contract Transfer events, windowed
//     to a range the public endpoint accepts;
//   * confirmations — eth_getTransactionReceipt distance from the tip.
//
// Send (SignAndSend / SignTokenTransfer):
//   * signs a legacy EIP-155 transaction locally — the private key comes from
//     the request, or from the configured hot-wallet key file — and broadcasts
//     with eth_sendRawTransaction;
//   * gas is paid in BNB by the sender: the hot float must hold it, an unfunded
//     sender fails before anything is broadcast;
//   * `fee` in the result is the gas actually paid (receipt), else the planned
//     gas, in BNB wei.
//
// Sources: free public endpoints (bsc-dataseed pool), rotated per call on
// failure. Etherscan's free key does not cover chainid 56.
// ---------------------------------------------------------------------------

const (
	bscChainID            = int64(56)
	bscTransferSelector   = "0xa9059cbb" // transfer(address,uint256)
	bscBalanceOfSelector  = "0x70a08231" // balanceOf(address)
	bscTransferSigTopic   = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	bscMinGasPriceWei     = 1_000_000_000       // 1 gwei floor (BSC minimum baseline)
	bscMaxGasLimit        = 200_000             // a token transfer always stays well below this
	bscGasPriceBumpPct    = 10                  // broadcast buffer over the node's quote
	bscSendPollTries      = 8                   // receipt poll attempts (~16 s)
	bscSendPollIntervalMs = 2000
	bscHistoryDefaultWin  = int64(21600) // ~18 h of 3 s blocks
	bscHistoryMinWin      = int64(1000)
)

// DefaultBSCRPCs is the public BSC endpoint pool, tried front to back.
var DefaultBSCRPCs = []string{
	"https://bsc-dataseed.bnbchain.org",
	"https://bsc-dataseed1.bnbchain.org",
	"https://bsc-dataseed2.bnbchain.org",
	"https://bsc-dataseed3.bnbchain.org",
	"https://bsc-dataseed1.defibit.io",
	"https://bsc-dataseed1.ninicoin.io",
	"https://bsc.publicnode.com",
}

type hotWalletFile struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privateKey"`
	Mnemonic   string `json:"mnemonic"`
	HDPath     string `json:"path"`
}

// BscErc20 implements Blockchain (plus the BEP20 extensions) for one BEP-20
// token on BSC.
type BscErc20 struct {
	readOnlyBase
	symbol     string
	token      common.Address
	decimals   int      // token decimals (USDT on BSC: 18)
	unitScale  *big.Int // wei per 8dp unit = 10^(decimals - 8)
	rpcs       []string
	hotKeyFile string
	historyWin int64
}

// NewBscErc20 builds the chain driver. tokenContract = BEP-20 contract addr.
func NewBscErc20(symbol, tokenContract string, decimals int) *BscErc20 {
	var scale *big.Int
	switch d := decimals - 8; {
	case d > 0:
		scale = new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(d)), nil)
	default:
		scale = big.NewInt(1) // tokens coarser than 8dp do not exist in practice
	}
	return &BscErc20{
		symbol:     symbol,
		token:      common.HexToAddress(tokenContract),
		decimals:   decimals,
		unitScale:  scale,
		rpcs:       DefaultBSCRPCs,
		historyWin: bscHistoryDefaultWin,
	}
}

func (c *BscErc20) SetRPCs(urls []string) *BscErc20 {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	if len(out) > 0 {
		c.rpcs = out
	}
	return c
}

func (c *BscErc20) SetHotKeyFile(path string) *BscErc20 { c.hotKeyFile = path; return c }

// SetHistoryWindow caps the GetHistory block range before the shrink logic.
func (c *BscErc20) SetHistoryWindow(blocks int64) *BscErc20 {
	if blocks > 0 {
		c.historyWin = blocks
	}
	return c
}

func (c *BscErc20) Name() string { return c.symbol }

// --- JSON-RPC plumbing ------------------------------------------------------

// call tries every configured endpoint until one answers without an error.
// Chain verdicts (execution reverts and similar) are surfaced immediately:
// retrying a revert against other hosts only burns rate limits.
func (c *BscErc20) call(method string, params any, out any) error {
	var lastErr error
	for i := 0; i < len(c.rpcs); i++ {
		url := c.rpcs[i%len(c.rpcs)] // start position rotates per call
		err := c.rpcPost(url, method, params, out)
		if err == nil {
			return nil
		}
		msg := strings.ToLower(err.Error())
		lastErr = err
		if strings.Contains(msg, "revert") ||
			strings.Contains(msg, "execution") ||
			strings.Contains(msg, "out of gas") ||
			strings.Contains(msg, "nonce too low") {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("no rpc endpoint configured")
	}
	return fmt.Errorf("BSC %s: all %d endpoints failed: %w", method, len(c.rpcs), lastErr)
}

func (c *BscErc20) rpcPost(url, method string, params any, out any) error {
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	body, status, err := postRaw(url, payload, "application/json")
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("HTTP %d", status)
	}
	var wrapped struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return fmt.Errorf("unparsable rpc reply from %s: %w", url, err)
	}
	if wrapped.Error != nil && strings.TrimSpace(wrapped.Error.Message) != "" {
		return errors.New(strings.TrimSpace(wrapped.Error.Message))
	}
	if out == nil || len(wrapped.Result) == 0 || string(wrapped.Result) == "null" {
		return nil
	}
	return json.Unmarshal(wrapped.Result, out)
}

// --- small helpers ----------------------------------------------------------

func bscHexToInt(s string) (int64, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("bad hex quantity %q", s)
	}
	return v, nil
}

func bscHexToBig(s string) *big.Int {
	s = strings.TrimSpace(s)
	if s == "" || s == "0x" || s == "0X" {
		return new(big.Int)
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base, s = 16, s[2:]
	}
	v := new(big.Int)
	v.SetString(s, base)
	return v
}

// pad32Topic renders a 20-byte address as an EVM log topic.
func pad32Topic(hexAddr string) string {
	b := make([]byte, 32)
	copy(b[12:], common.HexToAddress(hexAddr).Bytes())
	return "0x" + common.Bytes2Hex(b)
}

func (c *BscErc20) blockNumber() (int64, error) {
	var hexv string
	if err := c.call("eth_blockNumber", []any{}, &hexv); err != nil {
		return 0, err
	}
	return bscHexToInt(hexv)
}

// weiStringToUnits8 converts a hex wei quantity (or plain number) into an 8dp
// scaled int64 via big arithmetic.
func (c *BscErc20) weiToUnits8(s string) int64 {
	wei := bscHexToBig(s)
	wei.Div(wei, c.unitScale)
	return wei.Int64()
}

// units8ToWei converts an 8dp scaled amount into base-token wei.
func (c *BscErc20) units8ToWei(units8 int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(units8), c.unitScale)
}

// --- chain data -------------------------------------------------------------

// GetBalance returns the token balance in 8dp units.
func (c *BscErc20) GetBalance(address string) (Balance, error) {
	var bal Balance
	if address == "" {
		return bal, errors.New("address is required")
	}
	if !common.IsHexAddress(address) {
		return bal, errors.New("invalid EVM address: " + address)
	}
	var res string
	if err := c.call("eth_call", []any{
		map[string]string{"to": c.token.Hex(), "data": bscBalanceOfSelector + strings.TrimPrefix(pad32Topic(strings.ToLower(address)), "0x")},
		"latest",
	}, &res); err != nil {
		return bal, err
	}
	units := c.weiToUnits8(res)
	bal.Address = address
	bal.BalanceBaseUnits = units
	bal.Balance = float64(units) / 1e8
	bal.ReceivedBaseUnits = units
	bal.Received = bal.Balance
	bal.Confirmed = true
	return bal, nil
}

// NativeBalance returns the address's BNB balance in wei — the gas headroom
// check for the hot float and for sweep funding.
func (c *BscErc20) NativeBalance(address string) (*big.Int, error) {
	if !common.IsHexAddress(address) {
		return nil, errors.New("invalid EVM address: " + address)
	}
	var res string
	if err := c.call("eth_getBalance", []any{strings.ToLower(address), "latest"}, &res); err != nil {
		return nil, err
	}
	return bscHexToBig(res), nil
}

func (c *BscErc20) ValidateAddress(addr string) (AddrInfo, error) {
	if addr == "" {
		return AddrInfo{}, errors.New("address is required")
	}
	ok := common.IsHexAddress(addr)
	return AddrInfo{IsValid: ok, Address: addr}, nil
}

// txReceipt returns the receipt map, or nil when the tx is pending/unknown.
func (c *BscErc20) txReceipt(txid string) (map[string]any, error) {
	var raw map[string]any
	if err := c.call("eth_getTransactionReceipt", []any{strings.ToLower(txid)}, &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	return raw, nil
}

func receiptHex(rc map[string]any, key string) int64 {
	var s string
	if v, ok := rc[key]; ok {
		switch t := v.(type) {
		case string:
			s = t
		case map[string]any:
			_ = json.Unmarshal(mustJSONBytes(v), &s)
		default:
			_ = json.Unmarshal(mustJSONBytes(v), &s)
		}
	}
	n, _ := bscHexToInt(s)
	return n
}

func (c *BscErc20) GetConfirmations(txid string) (int, error) {
	rc, err := c.txReceipt(txid)
	if err != nil {
		return 0, err
	}
	if rc == nil {
		return 0, nil
	}
	h := receiptHex(rc, "blockNumber")
	tip, err := c.blockNumber()
	if err != nil {
		return 0, err
	}
	if h <= 0 || h > tip {
		return 0, fmt.Errorf("receipt block %d against tip %d", h, tip)
	}
	return int(tip - h + 1), nil
}

func mustJSONBytes(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// GetTransaction normalizes a receipt. Pending/unknown txs return
// ErrNotImplemented (the LBTC contract treats an unknown tx the same way).
func (c *BscErc20) GetTransaction(txid string) (*Tx, error) {
	rc, err := c.txReceipt(txid)
	if err != nil {
		return nil, err
	}
	if rc == nil {
		return nil, ErrNotImplemented
	}
        status := "failed"
        if receiptHex(rc, "status") == 1 {
            status = "confirmed"
        }
	gasUsed := receiptHex(rc, "gasUsed")
	gasPrice := receiptHex(rc, "effectiveGasPrice")
	height := receiptHex(rc, "blockNumber")
	tip, err := c.blockNumber()
	if err != nil {
		return nil, err
	}
	confs := int(tip - height + 1)
	if confs < 0 {
		confs = 0
	}
	return &Tx{
		Txid:          txid,
		Confirmations: confs,
		Fee:           gasUsed * gasPrice, // BNB wei
		Status:        status,
		BlockHeight:   height,
		Timestamp:     time.Now().UTC(),
	}, nil
}

// ListUnspent is meaningless for an account (balance) model.
func (c *BscErc20) ListUnspent(address string, minConf int) ([]UTXO, error) {
	return nil, ErrNotImplemented
}

// GetNewAddress stays with the multi-wallet service (server-coin), so keys
// always land in one audited store.
func (c *BscErc20) GetNewAddress(label string) (string, error) {
	return "", ErrNotImplemented
}

func (c *BscErc20) SendTransaction(from, to string, amount int64, opts TxOptions) (string, error) {
	return "", errors.New("sending without a private key is not supported for " + c.symbol)
}

// --- history ------------------------------------------------------------------

type bscLog struct {
	BlockNumber string   `json:"blockNumber"`
	Topics      []string `json:"topics"`
	Data        string   `json:"data"`
	TxHash      string   `json:"transactionHash"`
	Address     string   `json:"address"`
}

// GetHistory lists transfer events touching address inside the block window.
// Public endpoints cap the scanned range, so the window shrinks on range
// errors, never below 1 k blocks. With nothing answering, history is an empty
// list rather than an error — the exchange's own ledger is budget history.
func (c *BscErc20) GetHistory(address string) ([]HistoryEntry, error) {
	if !common.IsHexAddress(address) {
		return nil, errors.New("invalid EVM address")
	}
	lower := strings.ToLower(address)
	window := c.historyWin
	if w, err := strconv.ParseInt(os.Getenv("BSC_HISTORY_BLOCKS"), 10, 64); err == nil && w > 0 {
		window = w
	}
	tip, err := c.blockNumber()
	if err != nil {
		return nil, err
	}
	for window >= bscHistoryMinWin {
		from := tip - window + 1
		if from < 1 {
			from = 1
		}
		logs, err := c.transferLogs(from, tip, lower)
		if err == nil {
			return c.logsToHistory(logs, lower), nil
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "limit") ||
			strings.Contains(msg, "range") ||
			strings.Contains(msg, "too many") ||
			strings.Contains(msg, "-32005") ||
			strings.Contains(msg, "-32603") {
			window /= 4
			continue
		}
		return c.logsToHistory(logs, lower), nil // partial answer is still history
	}
	return []HistoryEntry{}, nil
}

// transferLogs pulls both in- and outbound transfers for one address over a
// block range.
func (c *BscErc20) transferLogs(fromBlock, toBlock int64, lowerAddr string) ([]bscLog, error) {
	out := make([]bscLog, 0, 16)
	hexb := func(n int64) string { return "0x" + strconv.FormatInt(n, 16) }
	filter := func(topic2, topic3 any) map[string]any {
		return map[string]any{
			"fromBlock": hexb(fromBlock),
			"toBlock":   hexb(toBlock),
			"address":   c.token.Hex(),
			"topics":    []any{bscTransferSigTopic, topic2, topic3},
		}
	}
	// Topics is an AND across positions, so inbound and outbound need the two
	// separate queries; both are stacked together below.
	var inLogs, outLogs []bscLog
	if err := c.call("eth_getLogs", []any{filter(nil, pad32Topic(lowerAddr))}, &inLogs); err != nil {
		return nil, err
	}
	if err := c.call("eth_getLogs", []any{filter(pad32Topic(lowerAddr), nil)}, &outLogs); err != nil {
		return nil, err
	}
	out = append(out, inLogs...)
	out = append(out, outLogs...)
	sort.SliceStable(out, func(i, j int) bool {
		bi, _ := bscHexToInt(out[i].BlockNumber)
		bj, _ := bscHexToInt(out[j].BlockNumber)
		return bi < bj
	})
	return out, nil
}

func (c *BscErc20) logsToHistory(logs []bscLog, lowerAddr string) []HistoryEntry {
	entries := make([]HistoryEntry, 0, len(logs))
	seen := map[string]*HistoryEntry{}
	for _, lg := range logs {
		if len(lg.Topics) < 3 || strings.ToLower(lg.Address) != strings.ToLower(c.token.Hex()) {
			continue
		}
		// One tx can pay the same address twice and emit two events with
		// identical data (and there might be a log index we do not get from
		// some endpoints) — dedup on txhash+amount, keep the first.
		key := strings.ToLower(lg.TxHash) + ":" + strings.TrimPrefix(string(lg.Data), "")
		if seen[key] != nil {
			continue
		}
		units := c.weiToUnits8(lg.Data)
		var h HistoryEntry
		h.Txid = lg.TxHash
		h.Height, _ = bscHexToInt(lg.BlockNumber)
		fromAddr := "0x" + strings.TrimPrefix(lg.Topics[1], "0x000000000000000000000000")
		if fromAddr == "0x0000000000000000000000000000000000000000" {
			// Minted supply entering the pegged pool: still a receive for the
			// wallet that got it.
			h.Type = "receive"
			h.Amount = units
		} else if strings.EqualFold(fromAddr, lowerAddr) {
			h.Type = "send"
			h.Amount = -units
		} else {
			h.Type = "receive"
			h.Amount = units
		}
		h.Confirmations = 1
		h.Mature = true
		h.AmountDisplay = formatAtomicDec(h.Amount, 8, c.symbol)
		seen[key] = &h
		entries = append(entries, h)
	}
	if entries == nil {
		entries = []HistoryEntry{}
	}
	return entries
}

// --- send path ----------------------------------------------------------------

func (c *BscErc20) loadHotKey(privateKey string) (string, string, error) {
	if privateKey != "" {
		return privateKey, "", nil
	}
	if c.hotKeyFile == "" {
		return "", "", errors.New(
			"no private key in request and no USDT_HOT_KEY_FILE configured on the agent")
	}
	content, err := os.ReadFile(c.hotKeyFile)
	if err != nil {
		return "", "", fmt.Errorf("hot key file %q: %w", c.hotKeyFile, err)
	}
	var wf hotWalletFile
	if err := json.Unmarshal(content, &wf); err != nil {
		return "", "", fmt.Errorf("hot key file %q is not a wallet file: %w", c.hotKeyFile, err)
	}
	if strings.TrimSpace(wf.PrivateKey) == "" {
		return "", "", errors.New("hot key file has no privateKey")
	}
	return wf.PrivateKey, wf.Address, nil
}

// transferCalldata encodes transfer(address,uint256).
func transferCalldata(to common.Address, weiAmount *big.Int) []byte {
	data := make([]byte, 68)
	copy(data, common.Hex2Bytes(bscTransferSelector[2:]))
	copy(data[4:], common.LeftPadBytes(to.Bytes(), 32))
	copy(data[36:], common.LeftPadBytes(weiAmount.Bytes(), 32))
	return data
}

// SignAndSend is the generic send entry called by the agent send route.
// For a BEP-20 token: amount is in 8dp units, fee is the cap on the gas price
// in wei (0 = take the node quote with a small buffer), privateKey signs.
// `all` sweeps the whole token balance of `from` (to is still the recipient).
func (c *BscErc20) SignAndSend(from, to string, amount, fee int64, privateKey string, all ...bool) (SendResult, error) {
	if all != nil && len(all) > 0 && all[0] {
		bal, err := c.GetBalance(from)
		if err != nil {
			return SendResult{}, err
		}
		if amount <= 0 || all[0] && bal.BalanceBaseUnits > amount {
			amount = bal.BalanceBaseUnits
		}
	}
	if amount <= 0 {
		return SendResult{}, fmt.Errorf("amount must be positive (8dp units of %s)", c.symbol)
	}
	return c.signSendToken(from, to, amount, fee, privateKey)
}

// SignTokenTransfer is the typed send: units8dp in token 8dp units,
// maxGasPriceWei = 0 disables the gas-price cap.
func (c *BscErc20) SignTokenTransfer(from, to string, units8dp, maxGasPriceWei int64, privateKey string) (SendResult, error) {
	return c.signSendToken(from, to, units8dp, maxGasPriceWei, privateKey)
}

// ParsePrivKey normalizes the (optionally 0x-prefixed) hex key.
func ParsePrivKey(hexKey string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(hexKey), "0x"))
}

// signSendToken is the real send: every step re-checks the chain before the
// broadcast so money cannot leave on a stale assumption (wrong key, no token,
// no BNB for gas).
func (c *BscErc20) signSendToken(from, to string, units8dp, maxGasPriceWei int64, privateKey string) (SendResult, error) {
	if !common.IsHexAddress(from) || !common.IsHexAddress(to) {
		return SendResult{}, errors.New("invalid EVM address: from/to must be 0x addresses")
	}
	if units8dp <= 0 {
		return SendResult{}, fmt.Errorf("amount must be positive (8dp units of %s)", c.symbol)
	}
	if strings.EqualFold(from, to) {
		return SendResult{}, errors.New("self transfer of " + c.symbol + " is not a withdrawal")
	}
	keyHex, hotAddr, err := c.loadHotKey(privateKey)
	if err != nil {
		return SendResult{}, err
	}
	key, err := ParsePrivKey(keyHex)
	if err != nil {
		return SendResult{}, fmt.Errorf("bad private key: %w", err)
	}
	keyAddr := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	if hotAddr != "" && privateKey == "" {
		// Key loaded from the file: the file's own address is the only sender
		// it may finance.
		if !strings.EqualFold(hotAddr, strings.ToLower(from)) {
			return SendResult{}, fmt.Errorf(
				"hot key file signs only %s, refusing to spend from %s", hotAddr, from)
		}
	} else if strings.ToLower(keyAddr) != strings.ToLower(from) {
		return SendResult{}, fmt.Errorf("private key owns %s, refusing to spend from %s", keyAddr, from)
	}
	// The token balance must cover the transfer BEFORE gas is touched: gas buys
	// nothing if the token side is short.
	tokenBal, err := c.GetBalance(from)
	if err != nil {
		return SendResult{}, fmt.Errorf("token balance check: %w", err)
	}
	if tokenBal.BalanceBaseUnits < units8dp {
		return SendResult{}, fmt.Errorf(
			"insufficient %s on %s: have %.8f, want %.8f",
			c.symbol, from, float64(tokenBal.BalanceBaseUnits)/1e8, float64(units8dp)/1e8)
	}

	// Gas price: node quote with a small bump, floored at BSC's baseline, and
	// clamped by the optional cap so runaway quotes abort the send.
	var gasPriceRes string
	if err := c.call("eth_gasPrice", []any{}, &gasPriceRes); err != nil {
		return SendResult{}, fmt.Errorf("gas price: %w", err)
	}
	quote := bscHexToBig(gasPriceRes)
	quote.Mul(quote, big.NewInt(100+bscGasPriceBumpPct))
	quote.Div(quote, big.NewInt(100))
	if quote.Cmp(big.NewInt(bscMinGasPriceWei)) < 0 {
		quote.SetInt64(bscMinGasPriceWei)
	}
	if maxGasPriceWei > 0 && big.NewInt(maxGasPriceWei).Cmp(quote) < 0 {
		quote.SetInt64(maxGasPriceWei)
	}

	// Gas limit: the node's own estimate for THIS transfer.
	gasLimit := int64(0)
	var gasHex string
	if err := c.call("eth_estimateGas", []any{map[string]any{
		"from": strings.ToLower(from),
		"to":   c.token.Hex(),
		"data": "0x" + common.Bytes2Hex(transferCalldata(common.HexToAddress(strings.ToLower(to)), c.units8ToWei(units8dp))),
	}}, &gasHex); err == nil {
		if v, err2 := bscHexToInt(gasHex); err2 == nil {
			gasLimit = v + v/5 // 20% headroom for EIP-7623 style accounting
		}
	}
	if gasLimit < 21_000 {
		gasLimit = 100_000 // safe default for a token transfer
	}
	if gasLimit > bscMaxGasLimit {
		gasLimit = bscMaxGasLimit
	}

	// BNB for gas must exist before anything is broadcast: "USDT transfers
	// from an address without BNB" is the classic trapped-token situation.
	nativeBal, err := c.NativeBalance(from)
	if err != nil {
		return SendResult{}, fmt.Errorf("gas (BNB) balance check: %w", err)
	}
	needed := new(big.Int).Mul(quote, big.NewInt(gasLimit))
	if nativeBal.Cmp(needed) < 0 {
		return SendResult{}, fmt.Errorf(
			"insufficient BNB for gas on %s: have %.10f, need %.10f — fund the address with BNB first",
			from,
			float64(nativeBal.Int64())/1e18,
			float64(needed.Int64())/1e18)
	}

	// Nonce: pending so a queued sibling tx does not collide with this one.
	var nonceHex string
	if err := c.call("eth_getTransactionCount", []any{strings.ToLower(from), "pending"}, &nonceHex); err != nil {
		return SendResult{}, fmt.Errorf("nonce: %w", err)
	}
	nonce, _ := bscHexToInt(nonceHex)

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    uint64(nonce),
		GasPrice: quote,
		Gas:      uint64(gasLimit),
		To:       addrP(c.token.Hex()),
		Value:    big.NewInt(0),
		Data:     transferCalldata(common.HexToAddress(strings.ToLower(to)), c.units8ToWei(units8dp)),
	})
	signed, err := types.SignTx(tx, types.NewLondonSigner(big.NewInt(bscChainID)), key)
	if err != nil {
		return SendResult{}, fmt.Errorf("signing: %w", err)
	}
	raw, err := rlp.EncodeToBytes(signed)
	if err != nil {
		return SendResult{}, fmt.Errorf("rlp encode: %w", err)
	}
	var txHashHex string
	if err := c.call("eth_sendRawTransaction", []any{"0x" + common.Bytes2Hex(raw)}, &txHashHex); err != nil {
		return SendResult{}, fmt.Errorf("broadcast: %w", err)
	}
	txid := strings.TrimPrefix(strings.ToLower(txHashHex), "0x")

	// BSC mines ~3 s blocks, so the receipt normally arrives inside the first
	// two polls; anything later is still returned, fee falls back to planned.
	plannedFee := new(big.Int).Mul(quote, big.NewInt(gasLimit)).Int64()
	feePaid := plannedFee
	confirmed := false
	for try := 0; try < bscSendPollTries && !confirmed; try++ {
		time.Sleep(bscSendPollIntervalMs * time.Millisecond)
		rc, err := c.txReceipt(txid)
		if err != nil || rc == nil {
			continue
		}
		if gu := receiptHex(rc, "gasUsed"); gu > 0 {
			feePaid = gu * quote.Int64()
		}
		if receiptHex(rc, "status") == 1 {
			confirmed = true
		} else {
			return SendResult{}, fmt.Errorf("transaction %s reverted on chain (check token balance / contract)", txid)
		}
	}

	return SendResult{
		Txid:   txid,
		Fee:    feePaid, // BNB wei
		RawTx:  "0x" + common.Bytes2Hex(raw),
		Size:   len(raw),
		Amount: units8dp,
	}, nil
}

func addrP(hex string) *common.Address {
	a := common.HexToAddress(hex)
	return &a
}

// EstimateTokenTransfer prices a transfer without signing. privateKey is
// accepted for signature parity; the estimate itself never uses it.
func (c *BscErc20) EstimateTokenTransfer(from, to string, units8dp, maxGasPriceWei int64, privateKey string) (FeeEstimate, error) {
	if !common.IsHexAddress(from) || !common.IsHexAddress(to) {
		return FeeEstimate{}, errors.New("invalid EVM address: from/to must be 0x addresses")
	}
	if units8dp <= 0 {
		return FeeEstimate{}, fmt.Errorf("amount must be positive (8dp units of %s)", c.symbol)
	}
	var gasHex string
	err := c.call("eth_estimateGas", []any{map[string]any{
		"from": strings.ToLower(from),
		"to":   c.token.Hex(),
		"data": "0x" + common.Bytes2Hex(transferCalldata(common.HexToAddress(strings.ToLower(to)), c.units8ToWei(units8dp))),
	}}, &gasHex)
	if err != nil {
		// A revert here is a usable verdict: the token side of the transfer
		// cannot complete (balance short, allowlist, contract paused...).
		return FeeEstimate{}, fmt.Errorf("estimate rejected: %w", err)
	}
	gasLimit, _ := bscHexToInt(gasHex)
	if gasLimit < 21_000 {
		gasLimit = 100_000
	}
	var gasPriceRes string
	if err := c.call("eth_gasPrice", []any{}, &gasPriceRes); err != nil {
		return FeeEstimate{}, fmt.Errorf("gas price: %w", err)
	}
	rate := bscHexToBig(gasPriceRes)
	rate.Mul(rate, big.NewInt(100+bscGasPriceBumpPct))
	rate.Div(rate, big.NewInt(100))
	if rate.Cmp(big.NewInt(bscMinGasPriceWei)) < 0 {
		rate.SetInt64(bscMinGasPriceWei)
	}
	if maxGasPriceWei > 0 && big.NewInt(maxGasPriceWei).Cmp(rate) < 0 {
		rate.SetInt64(maxGasPriceWei)
	}
	total := new(big.Int).Mul(rate, big.NewInt(gasLimit))
        if !total.IsInt64() {
            return FeeEstimate{}, fmt.Errorf("fee estimate %s wei overflows int64", total.String())
        }
        fee := total.Int64()
	return FeeEstimate{
		Fee:    fee, // BNB wei
		Inputs: 1,
		Size:   int(gasLimit),
	}, nil
}

// Estimate implements the generic Estimator hook used by the /estimate route.
// amount is 8dp units; the fee value is the full gas price in BNB wei.
func (c *BscErc20) Estimate(from, to string, amount int64) (FeeEstimate, error) {
	return c.EstimateTokenTransfer(from, to, amount, 0, "")
}

// EstimateWithKey is the probe variant: the estimate runs with the actual
// signing address, so balance/allowance reverts surface right here.
func (c *BscErc20) EstimateWithKey(from, to string, amount int64, privateKey string) (FeeEstimate, error) {
	return c.EstimateTokenTransfer(from, to, amount, 0, privateKey)
}

// BEP20TokenChain is the extension contract the agent uses for token chains:
// typed sends with big-friendly amounts, the native-gas read and the
// estimate. Assert the pointer at build time so the interface never drifts.
type BEP20TokenChain interface {
	Blockchain
	NativeBalance(address string) (*big.Int, error)
	SignTokenTransfer(from, to string, units8dp, maxGasPriceWei int64, privateKey string) (SendResult, error)
	EstimateTokenTransfer(from, to string, units8dp, maxGasPriceWei int64, privateKey string) (FeeEstimate, error)
}

var _ BEP20TokenChain = (*BscErc20)(nil)
