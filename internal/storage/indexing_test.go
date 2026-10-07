package storage

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"legacycoin/legacy-go/internal/address"
	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/chainhash"
	"legacycoin/legacy-go/internal/script"
	"legacycoin/legacy-go/internal/wire"
)

func TestTxIndexLookupAfterSaveBlock(t *testing.T) {
	store := NewFileStore(t.TempDir())
	store.SetIndexOptions(true, false)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: ^uint32(0)},
			SignatureScript:  []byte{0x01, 0x01},
			Sequence:         ^uint32(0),
		}},
		TxOut: []wire.TxOut{{Value: 50, PkScript: []byte{script.OP_1}}},
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 1, Bits: 0x1e7fffff, Nonce: 1},
		Transactions: []*wire.MsgTx{tx},
	}
	bh, err := block.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	idx := blockchain.BlockIndex{Height: 0, Hash: bh.String(), Time: 1, Bits: 0x1e7fffff, Nonce: 1, Parent: "", ChainWork: "1"}
	if err := store.SaveBlock(block, idx, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	txHash, err := tx.TxHash()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := store.LookupTxIndex(txHash.String())
	if err != nil {
		t.Fatalf("LookupTxIndex failed: %v", err)
	}
	if rec.TxID != txHash.String() || rec.BlockHash != idx.Hash || rec.BlockHeight != idx.Height || rec.TxPosition != 0 {
		t.Fatalf("unexpected txindex record: %+v", rec)
	}
}

func TestAddressIndexLookupAfterSaveBlock(t *testing.T) {
	store := NewFileStore(t.TempDir())
	store.SetIndexOptions(false, true)

	pubHash := make([]byte, 20)
	for i := range pubHash {
		pubHash[i] = byte(i + 1)
	}
	pkScript, err := script.PayToPubKeyHashScript(pubHash)
	if err != nil {
		t.Fatal(err)
	}
	addr := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, pubHash)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: ^uint32(0)},
			SignatureScript:  []byte{0x01, 0x01},
			Sequence:         ^uint32(0),
		}},
		TxOut: []wire.TxOut{{Value: 5000000000, PkScript: pkScript}},
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 1, Bits: 0x1e7fffff, Nonce: 2},
		Transactions: []*wire.MsgTx{tx},
	}
	bh, err := block.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	idx := blockchain.BlockIndex{Height: 0, Hash: bh.String(), Time: 1, Bits: 0x1e7fffff, Nonce: 2, Parent: "", ChainWork: "1"}
	txHash, err := tx.TxHash()
	if err != nil {
		t.Fatal(err)
	}
	adds := []blockchain.UTXOEntry{{
		Key:      blockchain.OutPointKey(txHash.String(), 0),
		TxID:     txHash.String(),
		Vout:     0,
		Value:    5000000000,
		PkScript: hex.EncodeToString(pkScript),
		Height:   0,
		Coinbase: true,
	}}
	if err := store.SaveBlock(block, idx, adds, nil, nil); err != nil {
		t.Fatal(err)
	}

	txids, err := store.AddressTxIDs(addr)
	if err != nil {
		t.Fatalf("AddressTxIDs failed: %v", err)
	}
	if len(txids) != 1 || txids[0] != txHash.String() {
		t.Fatalf("unexpected address txids: %#v", txids)
	}
	utxos, err := store.AddressUTXOs(addr)
	if err != nil {
		t.Fatalf("AddressUTXOs failed: %v", err)
	}
	if len(utxos) != 1 || utxos[0].Value != 5000000000 {
		t.Fatalf("unexpected address utxos: %#v", utxos)
	}
	confirmed, total, err := store.AddressBalance(addr)
	if err != nil {
		t.Fatalf("AddressBalance failed: %v", err)
	}
	if confirmed != 5000000000 || total != 5000000000 {
		t.Fatalf("unexpected address balance confirmed=%d total=%d", confirmed, total)
	}
	history, err := store.AddressHistory(addr)
	if err != nil {
		t.Fatalf("AddressHistory failed: %v", err)
	}
	if len(history) != 1 || !history[0].Coinbase || history[0].TxID != txHash.String() || history[0].Value != 5000000000 {
		t.Fatalf("unexpected address history for coinbase output: %#v", history)
	}
}

func TestTxIndexSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	store.SetIndexOptions(true, false)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: ^uint32(0)},
			SignatureScript:  []byte{0x01, 0x02},
			Sequence:         ^uint32(0),
		}},
		TxOut: []wire.TxOut{{Value: 42, PkScript: []byte{script.OP_1}}},
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 2, Bits: 0x1e7fffff, Nonce: 10},
		Transactions: []*wire.MsgTx{tx},
	}
	bh, err := block.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	idx := blockchain.BlockIndex{Height: 0, Hash: bh.String(), Time: 2, Bits: 0x1e7fffff, Nonce: 10, Parent: "", ChainWork: "1"}
	if err := store.SaveBlock(block, idx, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	txHash, err := tx.TxHash()
	if err != nil {
		t.Fatal(err)
	}

	reopened := NewFileStore(dir)
	reopened.SetIndexOptions(true, false)
	rec, err := reopened.LookupTxIndex(txHash.String())
	if err != nil {
		t.Fatalf("LookupTxIndex after restart failed: %v", err)
	}
	if rec.BlockHash != idx.Hash || rec.BlockHeight != idx.Height {
		t.Fatalf("unexpected txindex record after restart: %+v", rec)
	}
}

func TestRepairIndexesRebuildsTxAndAddressIndexes(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	store.SetIndexOptions(true, true)

	pubHash := make([]byte, 20)
	for i := range pubHash {
		pubHash[i] = byte(0x30 + i)
	}
	pkScript, err := script.PayToPubKeyHashScript(pubHash)
	if err != nil {
		t.Fatal(err)
	}
	addr := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, pubHash)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: ^uint32(0)},
			SignatureScript:  []byte{0x51},
			Sequence:         ^uint32(0),
		}},
		TxOut: []wire.TxOut{{Value: 123_000_000, PkScript: pkScript}},
	}
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 3, Bits: 0x1e7fffff, Nonce: 11},
		Transactions: []*wire.MsgTx{tx},
	}
	bh, err := block.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	idx := blockchain.BlockIndex{Height: 0, Hash: bh.String(), Time: 3, Bits: 0x1e7fffff, Nonce: 11, Parent: "", ChainWork: "1"}
	txHash, err := tx.TxHash()
	if err != nil {
		t.Fatal(err)
	}
	adds := []blockchain.UTXOEntry{{
		Key:      blockchain.OutPointKey(txHash.String(), 0),
		TxID:     txHash.String(),
		Vout:     0,
		Value:    123_000_000,
		PkScript: hex.EncodeToString(pkScript),
		Height:   0,
		Coinbase: true,
	}}
	if err := store.SaveBlock(block, idx, adds, nil, nil); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(store.txIndexPath(txHash.String())); err != nil {
		t.Fatalf("remove txindex path: %v", err)
	}
	if err := os.RemoveAll(store.addressDir(addr)); err != nil {
		t.Fatalf("remove address index dir: %v", err)
	}

	if err := store.RepairIndexes(); err != nil {
		t.Fatalf("RepairIndexes failed: %v", err)
	}

	rec, err := store.LookupTxIndex(txHash.String())
	if err != nil {
		t.Fatalf("LookupTxIndex after RepairIndexes failed: %v", err)
	}
	if rec.TxID != txHash.String() || rec.BlockHash != idx.Hash {
		t.Fatalf("unexpected rebuilt txindex record: %+v", rec)
	}

	utxos, err := store.AddressUTXOs(addr)
	if err != nil {
		t.Fatalf("AddressUTXOs after RepairIndexes failed: %v", err)
	}
	if len(utxos) != 1 || utxos[0].TxID != txHash.String() || utxos[0].Value != 123_000_000 {
		t.Fatalf("unexpected rebuilt address utxos: %#v", utxos)
	}
}

func TestAddressHistoryTracksSpendsAndSurvivesRepair(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	store.SetIndexOptions(false, true)

	pubHashA := bytesRepeat(0x41)
	pubHashB := bytesRepeat(0x51)
	pkScriptA, err := script.PayToPubKeyHashScript(pubHashA)
	if err != nil {
		t.Fatal(err)
	}
	pkScriptB, err := script.PayToPubKeyHashScript(pubHashB)
	if err != nil {
		t.Fatal(err)
	}
	addrA := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, pubHashA)
	addrB := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, pubHashB)

	tx1 := &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: ^uint32(0)},
			SignatureScript:  []byte{0x01, 0x01},
			Sequence:         ^uint32(0),
		}},
		TxOut: []wire.TxOut{{Value: 5_000_000_000, PkScript: pkScriptA}},
	}
	tx1Hash, err := tx1.TxHash()
	if err != nil {
		t.Fatal(err)
	}
	block1 := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 10, Bits: 0x1e7fffff, Nonce: 21},
		Transactions: []*wire.MsgTx{tx1},
	}
	block1Hash, err := block1.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	idx1 := blockchain.BlockIndex{Height: 0, Hash: block1Hash.String(), Time: 10, Bits: 0x1e7fffff, Nonce: 21, Parent: "", ChainWork: "1"}
	adds1 := []blockchain.UTXOEntry{{
		Key:      blockchain.OutPointKey(tx1Hash.String(), 0),
		TxID:     tx1Hash.String(),
		Vout:     0,
		Value:    5_000_000_000,
		PkScript: hex.EncodeToString(pkScriptA),
		Height:   0,
		Coinbase: true,
	}}
	if err := store.SaveBlock(block1, idx1, adds1, nil, nil); err != nil {
		t.Fatal(err)
	}

	tx2 := &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: tx1Hash, Index: 0},
			SignatureScript:  []byte{0x51},
			Sequence:         ^uint32(0),
		}},
		TxOut: []wire.TxOut{{Value: 4_900_000_000, PkScript: pkScriptB}},
	}
	tx2Hash, err := tx2.TxHash()
	if err != nil {
		t.Fatal(err)
	}
	block2 := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 20, Bits: 0x1e7fffff, Nonce: 22},
		Transactions: []*wire.MsgTx{tx2},
	}
	block2Hash, err := block2.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	idx2 := blockchain.BlockIndex{Height: 1, Hash: block2Hash.String(), Time: 20, Bits: 0x1e7fffff, Nonce: 22, Parent: idx1.Hash, ChainWork: "2"}
	adds2 := []blockchain.UTXOEntry{{
		Key:      blockchain.OutPointKey(tx2Hash.String(), 0),
		TxID:     tx2Hash.String(),
		Vout:     0,
		Value:    4_900_000_000,
		PkScript: hex.EncodeToString(pkScriptB),
		Height:   1,
		Coinbase: false,
	}}
	if err := store.SaveBlock(block2, idx2, adds2, []string{adds1[0].Key}, []blockchain.UTXOEntry{adds1[0]}); err != nil {
		t.Fatal(err)
	}

	utxosA, err := store.AddressUTXOs(addrA)
	if err != nil {
		t.Fatalf("AddressUTXOs A: %v", err)
	}
	if len(utxosA) != 0 {
		t.Fatalf("address A should have no spendable utxos after spend: %#v", utxosA)
	}
	txidsA, err := store.AddressTxIDs(addrA)
	if err != nil {
		t.Fatalf("AddressTxIDs A: %v", err)
	}
	if !contains(txidsA, tx1Hash.String()) || !contains(txidsA, tx2Hash.String()) {
		t.Fatalf("address A txids should include receive and spend txids: %#v", txidsA)
	}
	historyA, err := store.AddressHistory(addrA)
	if err != nil {
		t.Fatalf("AddressHistory A: %v", err)
	}
	if len(historyA) != 1 {
		t.Fatalf("address A history len=%d want 1 output record", len(historyA))
	}
	if !historyA[0].Spent || historyA[0].SpendTxID != tx2Hash.String() || historyA[0].SpendHeight != 1 {
		t.Fatalf("address A history spent metadata mismatch: %#v", historyA[0])
	}

	historyB, err := store.AddressHistory(addrB)
	if err != nil {
		t.Fatalf("AddressHistory B: %v", err)
	}
	if len(historyB) != 1 || historyB[0].Spent {
		t.Fatalf("address B history mismatch: %#v", historyB)
	}

	if err := os.RemoveAll(store.addressDir(addrA)); err != nil {
		t.Fatalf("remove address index A: %v", err)
	}
	if err := os.RemoveAll(store.addressDir(addrB)); err != nil {
		t.Fatalf("remove address index B: %v", err)
	}
	if err := store.RepairIndexes(); err != nil {
		t.Fatalf("RepairIndexes: %v", err)
	}
	historyA2, err := store.AddressHistory(addrA)
	if err != nil {
		t.Fatalf("AddressHistory A after repair: %v", err)
	}
	if len(historyA2) != 1 || !historyA2[0].Spent || historyA2[0].SpendTxID != tx2Hash.String() {
		t.Fatalf("address A repaired history mismatch: %#v", historyA2)
	}
}

func bytesRepeat(b byte) []byte {
	out := make([]byte, 20)
	for i := range out {
		out[i] = b
	}
	return out
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func TestRepairIndexesRebuildsUTXOSet(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	store.SetIndexOptions(true, true)

	pkFor := func(seed byte) ([]byte, string) {
		pkScript, err := script.PayToPubKeyHashScript(bytesRepeat(seed))
		if err != nil {
			t.Fatal(err)
		}
		return pkScript, address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, bytesRepeat(seed))
	}
	coinbaseTx := func(pkScript []byte, value int64, seed byte) *wire.MsgTx {
		return &wire.MsgTx{
			Version: 1,
			TxIn: []wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: ^uint32(0)},
				SignatureScript:  []byte{seed},
				Sequence:         ^uint32(0),
			}},
			TxOut: []wire.TxOut{{Value: value, PkScript: pkScript}},
		}
	}
	txIDOf := func(tx *wire.MsgTx) chainhash.Hash {
		h, err := tx.TxHash()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	entryFor := func(tx *wire.MsgTx, vout int, value int64, pkScript []byte, height int32, coinbase bool) blockchain.UTXOEntry {
		h := txIDOf(tx)
		return blockchain.UTXOEntry{
			Key:      blockchain.OutPointKey(h.String(), uint32(vout)),
			TxID:     h.String(),
			Vout:     uint32(vout),
			Value:    value,
			PkScript: hex.EncodeToString(pkScript),
			Height:   height,
			Coinbase: coinbase,
		}
	}

	pkA, addrA := pkFor(0x11)
	pkB, _ := pkFor(0x22)
	pkC, addrC := pkFor(0x33)
	pkCB, _ := pkFor(0x44)

	// Block 0: one coinbase output A.
	cb0 := coinbaseTx(pkA, 5000, 0x51)
	blk0 := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 3, Bits: 0x1e7fffff, Nonce: 11},
		Transactions: []*wire.MsgTx{cb0},
	}
	hash0, err := blk0.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	entryA := entryFor(cb0, 0, 5000, pkA, 0, true)
	if err := store.SaveBlock(blk0,
		blockchain.BlockIndex{Height: 0, Hash: hash0.String(), Time: 3, Bits: 0x1e7fffff, Nonce: 11, ChainWork: "1"},
		[]blockchain.UTXOEntry{entryA}, nil, nil); err != nil {
		t.Fatal(err)
	}

	// Block 1: a coinbase plus two spends. tx2 spends an output that tx1 created
	// in the same block, so that output must never reach the UTXO set.
	cb1 := coinbaseTx(pkCB, 1234, 0x52)
	tx1 := &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: txIDOf(cb0), Index: 0},
			SignatureScript:  []byte{0x53},
			Sequence:         ^uint32(0),
		}},
		TxOut: []wire.TxOut{{Value: 3000, PkScript: pkB}, {Value: 2000, PkScript: pkC}},
	}
	tx2 := &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: txIDOf(tx1), Index: 0},
			SignatureScript:  []byte{0x54},
			Sequence:         ^uint32(0),
		}},
		TxOut: []wire.TxOut{{Value: 2990, PkScript: pkC}},
	}
	blk1 := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1, Timestamp: 4, Bits: 0x1e7fffff, Nonce: 12, PrevBlock: hash0},
		Transactions: []*wire.MsgTx{cb1, tx1, tx2},
	}
	hash1, err := blk1.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	// A is spent by tx1; the vout 0 of tx1 is spent by tx2 within the same block.
	entryB := entryFor(tx1, 0, 3000, pkB, 1, false)
	survivors := []blockchain.UTXOEntry{
		entryFor(cb1, 0, 1234, pkCB, 1, true),
		entryFor(tx1, 1, 2000, pkC, 1, false),
		entryFor(tx2, 0, 2990, pkC, 1, false),
	}
	if err := store.SaveBlock(blk1,
		blockchain.BlockIndex{Height: 1, Hash: hash1.String(), Parent: hash0.String(), Time: 4, Bits: 0x1e7fffff, Nonce: 12, ChainWork: "2"},
		survivors, []string{entryA.Key}, []blockchain.UTXOEntry{entryA}); err != nil {
		t.Fatal(err)
	}

	// Leave behind exactly what a real incident looks like: a UTXO directory
	// holding a truncated, wrong entry for an output that is in fact unspent.
	keep := filepath.Join(dir, "utxo", strings.ReplaceAll(survivors[1].Key, ":", "_")+".json")
	if err := os.MkdirAll(filepath.Dir(keep), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keep, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := store.RepairIndexes(); err != nil {
		t.Fatalf("RepairIndexes failed: %v", err)
	}

	for _, gone := range []blockchain.UTXOEntry{entryA, entryB} {
		if _, err := store.LoadUTXO(gone.Key); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("spent output %s should be absent from the rebuilt UTXO set, got err=%v", gone.Key, err)
		}
	}
	for _, want := range survivors {
		got, err := store.LoadUTXO(want.Key)
		if err != nil {
			t.Fatalf("rebuilt UTXO %s missing: %v", want.Key, err)
		}
		if got.Value != want.Value || got.Height != want.Height || got.Coinbase != want.Coinbase {
			t.Fatalf("rebuilt UTXO %s = %+v, want value=%d height=%d coinbase=%v",
				want.Key, *got, want.Value, want.Height, want.Coinbase)
		}
	}
	all, err := store.ListUTXO()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(survivors) {
		t.Fatalf("rebuilt UTXO set has %d entries, want %d", len(all), len(survivors))
	}
	stats, err := store.UTXOStats()
	if err != nil {
		t.Fatal(err)
	}
	var wantTotal int64
	for _, a := range survivors {
		wantTotal += a.Value
	}
	if stats.Total != wantTotal {
		t.Fatalf("rebuilt UTXO total = %d, want %d", stats.Total, wantTotal)
	}
	utxosA, err := store.AddressUTXOs(addrA)
	if err != nil {
		t.Fatal(err)
	}
	if len(utxosA) != 0 {
		t.Fatalf("addrA should have no unspent outputs, got %#v", utxosA)
	}
	utxosC, err := store.AddressUTXOs(addrC)
	if err != nil {
		t.Fatal(err)
	}
	if len(utxosC) != 2 {
		t.Fatalf("addrC should have 2 unspent outputs, got %#v", utxosC)
	}
}
