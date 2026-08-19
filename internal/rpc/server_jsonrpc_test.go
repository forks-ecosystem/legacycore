package rpc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"legacycoin/legacy-go/internal/address"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/config"
	"legacycoin/legacy-go/internal/wallet"
)

func TestJSONRPCSingleRequestMethodNotFound(t *testing.T) {
	s := &Server{}
	body := `{"jsonrpc":"1.0","id":"t1","method":"doesnotexist","params":[]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	s.handle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("expected method-not-found error, got %+v", resp.Error)
	}
}

func TestJSONRPCBatchRequest(t *testing.T) {
	s := &Server{}
	body := `[
		{"jsonrpc":"1.0","id":"1","method":"doesnotexist","params":[]},
		{"jsonrpc":"1.0","id":"2","method":"also_missing","params":[]}
	]`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	s.handle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var responses []response
	if err := json.Unmarshal(rec.Body.Bytes(), &responses); err != nil {
		t.Fatalf("decode batch response: %v", err)
	}
	if len(responses) != 2 {
		t.Fatalf("batch response len = %d, want 2", len(responses))
	}
	for _, r := range responses {
		if r.Error == nil || r.Error.Code != -32601 {
			t.Fatalf("expected method-not-found for response %+v", r)
		}
	}
}

func TestJSONRPCInvalidParamsSubmitBlockNoArgs(t *testing.T) {
	s := &Server{}
	body := `{"jsonrpc":"1.0","id":"probe","method":"submitblock","params":[]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	s.handle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("expected invalid params, got %+v", resp.Error)
	}
}

func TestParseSendManyOutputs(t *testing.T) {
	addr := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, bytes.Repeat([]byte{0x11}, 20))
	out, err := parseSendManyOutputs(json.RawMessage(`{"`+addr+`": 1.5}`), false)
	if err != nil {
		t.Fatalf("parseSendManyOutputs failed: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected one output, got %d", len(out))
	}
}

func TestJSONRPCHelpMethod(t *testing.T) {
	s := &Server{}
	body := `{"jsonrpc":"1.0","id":"help","method":"help","params":[]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	s.handle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected help error: %+v", resp.Error)
	}
	out, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("help result type = %T, want map[string]any", resp.Result)
	}
	methods, ok := out["methods"].([]any)
	if !ok || len(methods) == 0 {
		t.Fatalf("help methods missing or empty: %#v", out["methods"])
	}
}

func TestRPCHelpEntriesIncludeAddressHistoryAndPassphraseChange(t *testing.T) {
	hasHistory := false
	hasPassphraseChange := false
	for _, entry := range rpcHelpEntries {
		if entry.Method == "getaddresshistory" {
			hasHistory = true
		}
		if entry.Method == "walletpassphrasechange" {
			hasPassphraseChange = true
		}
	}
	if !hasHistory {
		t.Fatalf("rpc help table missing getaddresshistory")
	}
	if !hasPassphraseChange {
		t.Fatalf("rpc help table missing walletpassphrasechange")
	}
}

func TestJSONRPCGetAddressHistoryParamValidation(t *testing.T) {
	s := &Server{}

	cases := []struct {
		name string
		body string
	}{
		{
			name: "missing address",
			body: `{"jsonrpc":"1.0","id":"hist","method":"getaddresshistory","params":[]}`,
		},
		{
			name: "bad limit",
			body: `{"jsonrpc":"1.0","id":"hist","method":"getaddresshistory","params":["Lbad",-1,0,"all","all"]}`,
		},
		{
			name: "bad offset",
			body: `{"jsonrpc":"1.0","id":"hist","method":"getaddresshistory","params":["Lbad",10,-1,"all","all"]}`,
		},
		{
			name: "bad type filter",
			body: `{"jsonrpc":"1.0","id":"hist","method":"getaddresshistory","params":["Lbad",10,0,"badtype","all"]}`,
		},
		{
			name: "bad confirmations filter",
			body: `{"jsonrpc":"1.0","id":"hist","method":"getaddresshistory","params":["Lbad",10,0,"all","badconf"]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tc.body))
			s.handle(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			var resp response
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.Error == nil || resp.Error.Code != -32602 {
				t.Fatalf("expected invalid params, got %+v", resp.Error)
			}
		})
	}
}

func TestSetMiningAddressRequiresWalletOwnedAddress(t *testing.T) {
	dir := t.TempDir()
	w, err := wallet.Open(dir)
	if err != nil {
		t.Fatalf("wallet.Open: %v", err)
	}
	owned, err := w.NewAddress()
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	unowned := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, bytes.Repeat([]byte{0x42}, 20))
	s := &Server{wallet: w, configPath: filepath.Join(dir, config.ConfigFile)}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"jsonrpc":"1.0","id":"set","method":"setminingaddress","params":["`+unowned+`"]}`))
	s.handle(rec, req)
	var rejected response
	if err := json.Unmarshal(rec.Body.Bytes(), &rejected); err != nil {
		t.Fatalf("decode rejected response: %v", err)
	}
	if rejected.Error == nil || rejected.Error.Code != -32602 {
		t.Fatalf("expected unowned address rejection, got %+v", rejected.Error)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"jsonrpc":"1.0","id":"set","method":"setminingaddress","params":["`+owned+`"]}`))
	s.handle(rec, req)
	var accepted response
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatalf("decode accepted response: %v", err)
	}
	if accepted.Error != nil {
		t.Fatalf("unexpected owned address error: %+v", accepted.Error)
	}
	cfg, err := config.LoadMiningConfig(filepath.Join(dir, config.ConfigFile))
	if err != nil {
		t.Fatalf("LoadMiningConfig: %v", err)
	}
	if cfg.RewardAddress != owned || cfg.PubKeyHash == "" {
		t.Fatalf("mining destination not persisted: %+v", cfg)
	}
}

func TestResolveMiningDestinationRejectsStaleUnownedHash(t *testing.T) {
	dir := t.TempDir()
	w, err := wallet.Open(dir)
	if err != nil {
		t.Fatalf("wallet.Open: %v", err)
	}
	if _, err := w.NewAddress(); err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	s := &Server{wallet: w, configPath: filepath.Join(dir, config.ConfigFile)}
	cfg := config.MiningConfig{PubKeyHash: "85f774538db4b5243fe64121bbfe53bc83441e0e"}
	dest, err := s.resolveMiningDestination(w, cfg, true)
	if err == nil {
		t.Fatalf("expected stale unowned hash to be rejected, got %+v", dest)
	}
	if dest.Owned || dest.External {
		t.Fatalf("unexpected ownership flags for stale hash: %+v", dest)
	}
}
