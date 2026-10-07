package rpc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/pow"
	"legacycoin/legacy-go/internal/storage"
)

// gettxout обязан отвечать null на потраченный или неизвестный выход, как это
// делает Bitcoin Core. Раньше отсутствующий UTXO-файл доходил до
// blockLookupError и превращался в -5 "block not found", из-за чего бэкфилл
// депозитов и live-монитор читали нормальное «выхода уже нет» как сбой RPC.
func TestJSONRPCGetTxoutMissingOutpointReturnsNullNotError(t *testing.T) {
	chain, err := blockchain.New(chaincfg.MainNet,
		pow.YespowerHasher{Personalization: chaincfg.MainNet.YespowerPers},
		storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	s := &Server{chain: chain}

	body := `{"jsonrpc":"1.0","id":"t1","method":"gettxout","params":["0000000000000000000000000000000000000000000000000000000000000000",0]}`
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
		t.Fatalf("spent/unknown outpoint must not be an error, got %+v", resp.Error)
	}
	if strings.Contains(rec.Body.String(), "block not found") {
		t.Fatalf("response still blames a missing block: %s", rec.Body.String())
	}
	if resp.Result != nil {
		t.Fatalf("result = %+v, want null for a missing outpoint", resp.Result)
	}
}

// Валидация аргументов должна остаться: неверный vout по-прежнему -32602.
func TestJSONRPCGetTxoutInvalidVoutStillRejected(t *testing.T) {
	chain, err := blockchain.New(chaincfg.MainNet,
		pow.YespowerHasher{Personalization: chaincfg.MainNet.YespowerPers},
		storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	s := &Server{chain: chain}

	body := `{"jsonrpc":"1.0","id":"t2","method":"gettxout","params":["not-a-txid"]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	s.handle(rec, req)

	var resp response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == nil {
		t.Fatalf("expected a params error, got result %+v", resp.Result)
	}
}
