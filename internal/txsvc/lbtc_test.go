package txsvc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMockNode serves the handful of JSON-RPC methods these tests exercise and
// records every method it saw, so a test can assert that sendtoaddress was
// never reached.
type mockNode struct {
	t        *testing.T
	handlers map[string]any // method -> result value, or func(params []any) any
	calls    []string
	srv      *httptest.Server
}

func newMockNode(t *testing.T) *mockNode {
	t.Helper()
	m := &mockNode{t: t, handlers: map[string]any{}}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		m.calls = append(m.calls, req.Method)
		h, ok := m.handlers[req.Method]
		if !ok {
			w.Write([]byte(`{"result":null}`))
			return
		}
		res := h
		if f, isFn := h.(func([]any) any); isFn {
			var params []any
			for _, p := range req.Params {
				var v any
				_ = json.Unmarshal(p, &v)
				params = append(params, v)
			}
			res = f(params)
		}
		out, _ := json.Marshal(map[string]any{"result": res})
		w.Write(out)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockNode) client() *LBTC {
	return &LBTC{rpc: NewRPCClient(m.srv.URL, "", "")}
}

func (m *mockNode) saw(method string) bool {
	for _, c := range m.calls {
		if c == method {
			return true
		}
	}
	return false
}

func validAddressHandler() any {
	return map[string]any{"isvalid": true, "ismine": false, "is_hybrid": false}
}

// The node answers getbalance with a bare number in LBTC, not in base units.
// Reading it as base units understated a 77k LBTC wallet as 0.00077 LBTC and
// rejected every withdrawal as underfunded.
func TestWalletBalanceScalesLBTCUnits(t *testing.T) {
	m := newMockNode(t)
	m.handlers["getbalance"] = 77607.37894037

	have, err := m.client().walletBalance()
	if err != nil {
		t.Fatalf("walletBalance: %v", err)
	}
	const want = int64(7760737894037)
	if have != want {
		t.Fatalf("walletBalance = %d, want %d (getbalance result is in LBTC)", have, want)
	}
}

func TestWalletBalanceStringForm(t *testing.T) {
	m := newMockNode(t)
	m.handlers["getbalance"] = "1.5"

	have, err := m.client().walletBalance()
	if err != nil {
		t.Fatalf("walletBalance: %v", err)
	}
	if have != 150000000 {
		t.Fatalf("walletBalance = %d, want 150000000", have)
	}
}

// The node accepts fixed 8-decimal amounts, which is what the funding
// transaction used, so the trailing zeros are deliberate and must stay.
func TestFormatLBTCTx(t *testing.T) {
	cases := map[int64]string{
		150000000:           "1.50000000",
		7760737894037:       "77607.37894037",
		749999000000:        "7499.99000000",
		1:                   "0.00000001",
		0:                   "0.00000000",
		1234567:             "0.01234567",
		1000000000000000000: "10000000000.00000000",
		200000:              "0.00200000",
	}
	for in, want := range cases {
		if got := formatLBTCTx(in); got != want {
			t.Errorf("formatLBTCTx(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestTxidFromNodeResult(t *testing.T) {
	const txid = "03bba3366ca598daec0e0782f4b2241fc8b56913621018e5544352e8e3d0a666"
	if got, err := txidFromNodeResult(txid); err != nil || got != txid {
		t.Errorf("string form: got %q, err %v", got, err)
	}
	if got, err := txidFromNodeResult(map[string]any{"txid": txid}); err != nil || got != txid {
		t.Errorf("map form: got %q, err %v", got, err)
	}
	if _, err := txidFromNodeResult(42); err == nil {
		t.Error("expected an error for a non-string, non-map reply")
	}
	if _, err := txidFromNodeResult(""); err == nil {
		t.Error("expected an error for an empty txid")
	}
}

// An underfunded wallet must be refused before sendtoaddress, so no transaction
// is ever built or broadcast.
func TestSendRefusesWhenWalletShort(t *testing.T) {
	m := newMockNode(t)
	m.handlers["getbalance"] = 0.5
	m.handlers["validateaddress"] = validAddressHandler()
	m.handlers["sendtoaddress"] = func([]any) any { return "should-not-happen" }

	_, err := m.client().SendFromNodeWallet("Ldest", 100000000, 20000)
	if err == nil {
		t.Fatal("expected an error for a withdrawal larger than the wallet")
	}
	if !strings.Contains(err.Error(), "node wallet holds") {
		t.Errorf("unexpected error: %v", err)
	}
	if m.saw("sendtoaddress") {
		t.Fatal("sendtoaddress was called despite the insufficient balance")
	}
}

// The requested amount alone is not enough: the fee has to be covered too.
func TestSendRefusesWhenAmountFitsButFeeDoesNot(t *testing.T) {
	m := newMockNode(t)
	m.handlers["getbalance"] = 1.0
	m.handlers["validateaddress"] = validAddressHandler()

	// 0.9999 LBTC in hand, asking for exactly 0.9999 plus a fee.
	_, err := m.client().SendFromNodeWallet("Ldest", 99990000, 20000)
	if err == nil {
		t.Fatal("expected an error when the fee pushes the total over the balance")
	}
	if m.saw("sendtoaddress") {
		t.Fatal("sendtoaddress was called although the fee was uncovered")
	}
}

func TestSendRejectsInvalidDestination(t *testing.T) {
	m := newMockNode(t)
	m.handlers["getbalance"] = 100.0
	m.handlers["validateaddress"] = map[string]any{"isvalid": false}

	_, err := m.client().SendFromNodeWallet("Lbogus", 1000000, 20000)
	if err == nil || !strings.Contains(err.Error(), "invalid destination") {
		t.Fatalf("expected an invalid destination error, got %v", err)
	}
	if m.saw("sendtoaddress") {
		t.Fatal("sendtoaddress was called for an invalid address")
	}
}

// An explicit fee must reach the node as a formatted LBTC string: a bare 0
// makes the node pick its default, which lands below min_relay_fee_per_kb and
// gets the 32 KB funding transaction rejected as under-paying.
func TestSendPassesExplicitFeeInLBTC(t *testing.T) {
	m := newMockNode(t)
	m.handlers["getbalance"] = 100.0
	m.handlers["validateaddress"] = validAddressHandler()

	var got []any
	m.handlers["sendtoaddress"] = func(p []any) any {
		got = p
		return "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66"
	}

	res, err := m.client().SendFromNodeWallet("Ldest", 100000000, 200000)
	if err != nil {
		t.Fatalf("SendFromNodeWallet: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("sendtoaddress got %d params, want 3: %v", len(got), got)
	}
	if got[1] != "1.00000000" {
		t.Errorf("amount param = %v, want \"1.00000000\"", got[1])
	}
	if got[2] != "0.00200000" {
		t.Errorf("fee param = %v, want \"0.00200000\"", got[2])
	}
	if res.Fee != 200000 {
		t.Errorf("res.Fee = %d, want 200000", res.Fee)
	}
	if !strings.HasPrefix(res.Txid, "aa11bb22") {
		t.Errorf("res.Txid = %q", res.Txid)
	}
}

// With no fee the node picks its own, and the accounting must not claim one.
func TestSendWithoutFeeOmitsParam(t *testing.T) {
	m := newMockNode(t)
	m.handlers["getbalance"] = 100.0
	m.handlers["validateaddress"] = validAddressHandler()

	var got []any
	m.handlers["sendtoaddress"] = func(p []any) any {
		got = p
		return "aa11"
	}

	res, err := m.client().SendFromNodeWallet("Ldest", 100000000, 0)
	if err != nil {
		t.Fatalf("SendFromNodeWallet: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("sendtoaddress got %d params, want 2 (no fee): %v", len(got), got)
	}
	if res.Fee != 0 {
		t.Errorf("res.Fee = %d, want 0 when the node chose the fee", res.Fee)
	}
}

// getaddressbalance on this node reports addressindex_confirmed_only rather
// than a confirmed/unconfirmed pair, so Confirmed must follow that flag instead
// of being asserted.
func TestGetBalanceFollowsNodeFlag(t *testing.T) {
	m := newMockNode(t)
	m.handlers["getaddressbalance"] = map[string]any{
		"address":                     "Lsome",
		"balance":                     7499.99,
		"balance_base_units":          749999000000,
		"addressindex_confirmed_only": true,
	}
	b, err := m.client().GetBalance("Lsome")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if b.BalanceBaseUnits != 749999000000 {
		t.Errorf("BalanceBaseUnits = %d, want 749999000000", b.BalanceBaseUnits)
	}
	if b.Balance != 7499.99 {
		t.Errorf("Balance = %v, want 7499.99", b.Balance)
	}
	if !b.Confirmed {
		t.Error("Confirmed = false, want true when the node reports a confirmed-only index")
	}
}

func TestGetBalanceUnconfirmedIndex(t *testing.T) {
	m := newMockNode(t)
	m.handlers["getaddressbalance"] = map[string]any{
		"address":                     "Lsome",
		"balance":                     10,
		"balance_base_units":          1000000000,
		"addressindex_confirmed_only": false,
	}
	b, err := m.client().GetBalance("Lsome")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if b.Confirmed {
		t.Error("Confirmed = true, but the node index is not confirmed-only")
	}
}
