package wallet

import (
	"fmt"
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"legacycoin/legacy-go/internal/address"
	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/chainhash"
	"legacycoin/legacy-go/internal/consensus"
	"legacycoin/legacy-go/internal/mempool"
	"legacycoin/legacy-go/internal/mining"
	"legacycoin/legacy-go/internal/pqc"
	"legacycoin/legacy-go/internal/script"
	"legacycoin/legacy-go/internal/storage"
	"legacycoin/legacy-go/internal/wire"
)

func TestHybridAddressPersistence(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := w.NewHybridAddress()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr, "lhyb1") {
		t.Fatalf("unexpected hybrid prefix: %s", addr)
	}
	info := w.SecurityInfo()
	if got, ok := info["hybrid_keys"].(int); !ok || got != 1 {
		t.Fatalf("hybrid_keys=%v", info["hybrid_keys"])
	}

	w2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	all := w2.ListAddresses()
	found := false
	for _, a := range all {
		if a == addr {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("reopened wallet missing hybrid address")
	}
	info2 := w2.SecurityInfo()
	if got, ok := info2["hybrid_keys"].(int); !ok || got != 1 {
		t.Fatalf("reopened hybrid_keys=%v", info2["hybrid_keys"])
	}
}

func TestClassicAndHybridAddressLists(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	classic, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := w.NewHybridAddress()
	if err != nil {
		t.Fatal(err)
	}
	addrs := w.ListAddresses()
	if len(addrs) != 2 {
		t.Fatalf("address count=%d want=2", len(addrs))
	}
	var hasClassic, hasHybrid bool
	for _, a := range addrs {
		if a == classic {
			hasClassic = true
		}
		if a == hybrid {
			hasHybrid = true
		}
	}
	if !hasClassic || !hasHybrid {
		t.Fatalf("missing classic/hybrid in address list")
	}
}

func TestEncryptedLockedWalletPreservesAddressMetadata(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	classic, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := w.NewHybridAddress()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Encrypt("passphrase"); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	info := reopened.SecurityInfo()
	if locked, _ := info["locked"].(bool); !locked {
		t.Fatalf("expected reopened wallet to be locked: %#v", info)
	}
	addrs := reopened.ListAddresses()
	if len(addrs) != 2 {
		t.Fatalf("locked address count=%d want=2 (%#v)", len(addrs), addrs)
	}
	var hasClassic, hasHybrid bool
	for _, addr := range addrs {
		if addr == classic {
			hasClassic = true
		}
		if addr == hybrid {
			hasHybrid = true
		}
	}
	if !hasClassic || !hasHybrid {
		t.Fatalf("locked wallet missing address metadata classic=%t hybrid=%t addrs=%#v", hasClassic, hasHybrid, addrs)
	}
}

func TestDestinationScriptClassicAndHybrid(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	classicHash := script.Hash160(priv.PubKey().SerializeCompressed())
	classicAddr := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, classicHash)
	classicScript, err := destinationScript(classicAddr)
	if err != nil {
		t.Fatal(err)
	}
	if !script.IsPayToPubKeyHash(classicScript) {
		t.Fatalf("expected classic p2pkh script")
	}

	hk, err := pqc.GenerateHybridKey()
	if err != nil {
		t.Fatal(err)
	}
	hpub := hk.Public().Bytes()
	hybridAddr := address.NewHybridAddress(hpub.SecpCompressed, hpub.MLDSA65)
	hybridScript, err := destinationScript(hybridAddr)
	if err != nil {
		t.Fatal(err)
	}
	if !script.IsPayToHybridPubKeyHash(hybridScript) {
		t.Fatalf("expected hybrid script")
	}
	if bytes.Equal(classicScript, hybridScript) {
		t.Fatalf("classic and hybrid scripts should differ")
	}
}

func TestDestinationScriptRejectsBadAddress(t *testing.T) {
	if _, err := destinationScript("not-an-address"); err == nil {
		t.Fatalf("expected bad destination address error")
	}
}

type fakeHasher struct{}

func (fakeHasher) HashHeader(h wire.BlockHeader) (chainhash.Hash, error) {
	var out chainhash.Hash
	out[0] = 0x00
	out[1] = byte(h.Nonce)
	out[2] = byte(h.Nonce >> 8)
	out[3] = byte(h.Nonce >> 16)
	out[4] = byte(h.Nonce >> 24)
	out[5] = byte(h.Timestamp)
	out[6] = byte(h.Timestamp >> 8)
	out[7] = byte(h.Timestamp >> 16)
	out[8] = byte(h.Timestamp >> 24)
	return out, nil
}

func TestHybridSpendEndToEnd(t *testing.T) {
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	classicAddr, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	hybridAddr, err := w.NewHybridAddress()
	if err != nil {
		t.Fatal(err)
	}
	_, classicHash, err := address.DecodeBase58Check(classicAddr)
	if err != nil {
		t.Fatal(err)
	}

	chain, err := blockchain.New(chaincfg.MainNet, fakeHasher{}, storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New()
	var prev chainhash.Hash
	for i := 0; i <= chaincfg.CoinbaseMaturity; i++ {
		bits, err := chain.NextRequiredBits()
		if err != nil {
			t.Fatal(err)
		}
		b, err := buildCoinbaseBlock(prev, int32(i), uint32(1000+i), bits, classicHash)
		if err != nil {
			t.Fatal(err)
		}
		if err := chain.ProcessBlock(b); err != nil {
			t.Fatalf("process block %d: %v", i, err)
		}
		prev, err = fakeHasher{}.HashHeader(b.Header)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Classic -> hybrid creates a confirmed hybrid UTXO after mining one block.
	txid1, err := w.SendToAddress(chain, pool, hybridAddr, 1000000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if txid1 == "" {
		t.Fatalf("empty txid for classic->hybrid send")
	}
	if err := mineTemplateAndConnect(chain, pool, fakeHasher{}, classicHash); err != nil {
		t.Fatalf("mine inclusion block: %v", err)
	}

	// Hybrid -> classic must now validate/sign/enter mempool.
	txid2, err := w.SendFromAddress(chain, pool, hybridAddr, classicAddr, 500000, 7000)
	if err != nil {
		t.Fatal(err)
	}
	if txid2 == "" {
		t.Fatalf("empty txid for hybrid->classic send")
	}
	if pool.Count() == 0 {
		t.Fatalf("expected hybrid spend in mempool")
	}
}

func TestCoinSelectionSkipsMempoolSpentInputs(t *testing.T) {
	w, classicAddr, classicHash, chain, pool := fundedClassicWallet(t)
	recipient, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}

	txid1, err := w.SendToAddress(chain, pool, recipient, 1000000, 1000)
	if err != nil {
		t.Fatalf("first send: %v", err)
	}
	txid2, err := w.SendToAddress(chain, pool, recipient, 2000000, 1000)
	if err != nil {
		t.Fatalf("second send should use a different unlocked UTXO: %v", err)
	}
	if txid1 == txid2 {
		t.Fatalf("two distinct sends returned the same txid")
	}
	if pool.Count() != 2 {
		t.Fatalf("mempool count=%d want 2", pool.Count())
	}
	locked := 0
	unspent, err := w.ListUnspentForSpend(chain, pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range unspent {
		if u.Locked {
			locked++
		}
	}
	if locked != 2 {
		t.Fatalf("locked UTXO count=%d want 2", locked)
	}

	if err := mineTemplateAndConnect(chain, pool, fakeHasher{}, classicHash); err != nil {
		t.Fatalf("mine pending sends: %v", err)
	}
	if pool.Count() != 0 {
		t.Fatalf("mempool should be empty after mining, got %d", pool.Count())
	}
	if _, err := w.SendToAddress(chain, pool, classicAddr, 1000000, 1000); err != nil {
		t.Fatalf("send after confirmation should work: %v", err)
	}
}

func TestWalletOwnedUnconfirmedChangeCanChainPendingSends(t *testing.T) {
	w, _, _, chain, pool := fundedClassicWallet(t)
	recipient, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	unspent, err := w.ListUnspentForSpend(chain, pool)
	if err != nil {
		t.Fatal(err)
	}
	var spendable int64
	for _, u := range unspent {
		if !(u.Coinbase && u.Confirmations > 0 && u.Confirmations < int32(chaincfg.CoinbaseMaturity)) {
			spendable += u.Value
		}
	}
	if spendable <= 2000 {
		t.Fatalf("test wallet has too little spendable balance: %d", spendable)
	}
	if _, err := w.SendToAddress(chain, pool, recipient, 1000000, 1000); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if _, err := w.SendToAddress(chain, pool, recipient, 2000000, 1000); err != nil {
		t.Fatalf("second send should spend safe wallet-owned unconfirmed change if needed: %v", err)
	}
	if _, err := w.SendToAddress(chain, pool, recipient, 3000000, 1000); err != nil {
		t.Fatalf("third send should keep valid pending chain: %v", err)
	}
	if pool.Count() != 3 {
		t.Fatalf("mempool count=%d want 3", pool.Count())
	}
	ordered := pool.Transactions(10)
	for _, tx := range ordered {
		if len(tx.TxIn) == 0 {
			t.Fatalf("bad pending transaction in mempool")
		}
	}
	tpl, _, err := mining.NewBlockTemplate(chain, pool, bytes.Repeat([]byte{0x33}, 20))
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	if got := len(tpl.Transactions); got != 4 {
		t.Fatalf("template tx count=%d want coinbase + 3 mempool txs", got)
	}
	assertBlockTemplateTopological(t, tpl)
	if err := mineTemplateAndConnect(chain, pool, fakeHasher{}, bytes.Repeat([]byte{0x33}, 20)); err != nil {
		t.Fatalf("mine chained pending sends: %v", err)
	}
	if pool.Count() != 0 {
		t.Fatalf("mempool should be empty after confirming chained sends, got %d", pool.Count())
	}
}

func assertBlockTemplateTopological(t *testing.T, block *wire.MsgBlock) {
	t.Helper()
	positions := make(map[string]int, len(block.Transactions))
	for i, tx := range block.Transactions {
		h, err := tx.TxHash()
		if err != nil {
			t.Fatal(err)
		}
		positions[h.String()] = i
	}
	for i, tx := range block.Transactions {
		if i == 0 {
			continue
		}
		for _, in := range tx.TxIn {
			parent := in.PreviousOutPoint.Hash.String()
			if parentPos, ok := positions[parent]; ok && parentPos >= i {
				t.Fatalf("block template is not topological: parent %s at %d child at %d", parent, parentPos, i)
			}
		}
	}
}

func TestTokenMarkerSendsRespectPendingInputLocks(t *testing.T) {
	w, classicAddr, _, chain, pool := fundedClassicWallet(t)
	markerScript, err := script.PayToPubKeyHashScript(bytes.Repeat([]byte{0x42}, 20))
	if err != nil {
		t.Fatal(err)
	}
	txid1, err := w.SendTokenMarkers(chain, pool, classicAddr, [][]byte{markerScript}, 1000)
	if err != nil {
		t.Fatalf("first token marker send: %v", err)
	}
	txid2, err := w.SendTokenMarkers(chain, pool, classicAddr, [][]byte{markerScript}, 1000)
	if err != nil {
		t.Fatalf("second token marker send should skip locked input: %v", err)
	}
	if txid1 == txid2 {
		t.Fatalf("token marker sends returned duplicate txid")
	}
	if pool.Count() != 2 {
		t.Fatalf("mempool count=%d want 2", pool.Count())
	}
}

func TestSendManyCreatesSingleMultiOutputTransaction(t *testing.T) {
	w, classicAddr, _, chain, pool := fundedClassicWallet(t)
	addr1, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	txid, total, err := w.SendMany(chain, pool, classicAddr, map[string]int64{
		addr1: 1_000_000,
		addr2: 2_000_000,
	}, 1_000)
	if err != nil {
		t.Fatalf("sendmany failed: %v", err)
	}
	if txid == "" {
		t.Fatalf("sendmany returned empty txid")
	}
	if total != 3_000_000 {
		t.Fatalf("total=%d want=3000000", total)
	}
	if pool.Count() != 1 {
		t.Fatalf("mempool count=%d want=1", pool.Count())
	}
	tx, ok := pool.Lookup(txid)
	if !ok {
		t.Fatalf("mempool missing sendmany tx")
	}
	if len(tx.TxOut) < 3 {
		t.Fatalf("expected 2 payment outputs + change, got %d outputs", len(tx.TxOut))
	}
}

func TestSignRawTransactionWithWalletKeys(t *testing.T) {
	w, _, _, chain, pool := fundedClassicWallet(t)
	dest, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	unspent, err := w.ListUnspentForSpend(chain, pool)
	if err != nil {
		t.Fatal(err)
	}
	var selected *UTXOView
	for i := range unspent {
		u := &unspent[i]
		if u.Locked {
			continue
		}
		if u.Coinbase && u.Confirmations > 0 && u.Confirmations < int32(chaincfg.CoinbaseMaturity) {
			continue
		}
		selected = u
		break
	}
	if selected == nil {
		t.Fatalf("no spendable utxo found")
	}
	prevHash, err := chainhash.FromString(selected.TxID)
	if err != nil {
		t.Fatal(err)
	}
	payScript, err := destinationScript(dest)
	if err != nil {
		t.Fatal(err)
	}
	changeScript, err := destinationScript(selected.Address)
	if err != nil {
		t.Fatal(err)
	}
	sendAmount := int64(500_000)
	fee := int64(1_000)
	change := selected.Value - sendAmount - fee
	if change <= 0 {
		t.Fatalf("insufficient selected utxo for test")
	}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: selected.Vout},
			Sequence:         0xffffffff,
		}},
		TxOut: []wire.TxOut{
			{Value: sendAmount, PkScript: payScript},
			{Value: change, PkScript: changeScript},
		},
	}
	signed, complete, signErrs, err := w.SignRawTransaction(chain, tx)
	if err != nil {
		t.Fatalf("sign raw tx failed: %v", err)
	}
	if !complete {
		t.Fatalf("expected complete signature, errors: %+v", signErrs)
	}
	if len(signed.TxIn) != 1 || len(signed.TxIn[0].SignatureScript) == 0 {
		t.Fatalf("signature script missing")
	}
	if _, err := pool.Add(chain, signed); err != nil {
		t.Fatalf("signed tx rejected by mempool: %v", err)
	}
}

func fundedClassicWallet(t *testing.T) (*Wallet, string, []byte, *blockchain.Chain, *mempool.Pool) {
	t.Helper()
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	classicAddr, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	_, classicHash, err := address.DecodeBase58Check(classicAddr)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := blockchain.New(chaincfg.MainNet, fakeHasher{}, storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New()
	var prev chainhash.Hash
	for i := 0; i <= chaincfg.CoinbaseMaturity; i++ {
		bits, err := chain.NextRequiredBits()
		if err != nil {
			t.Fatal(err)
		}
		b, err := buildCoinbaseBlock(prev, int32(i), uint32(10_000+i), bits, classicHash)
		if err != nil {
			t.Fatal(err)
		}
		if err := chain.ProcessBlock(b); err != nil {
			t.Fatalf("process block %d: %v", i, err)
		}
		prev, err = fakeHasher{}.HashHeader(b.Header)
		if err != nil {
			t.Fatal(err)
		}
	}
	return w, classicAddr, classicHash, chain, pool
}

func buildCoinbaseBlock(prev chainhash.Hash, height int32, nonce uint32, bits uint32, pubKeyHash []byte) (*wire.MsgBlock, error) {
	coinbase, err := mining.NewCoinbaseTx(height, pubKeyHash, chaincfg.BlockSubsidy(height))
	if err != nil {
		return nil, err
	}
	b := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			PrevBlock: prev,
			Timestamp: uint32(time.Now().UTC().Unix()-100_000) + nonce,
			Bits:      bits,
			Nonce:     nonce,
		},
		Transactions: []*wire.MsgTx{coinbase},
	}
	root, err := b.BuildMerkleRoot()
	if err != nil {
		return nil, err
	}
	b.Header.MerkleRoot = root
	// Keep coinbase script in allowed size range for consensus checks.
	if len(b.Transactions[0].TxIn) == 1 && len(b.Transactions[0].TxIn[0].SignatureScript) < 2 {
		b.Transactions[0].TxIn[0].SignatureScript = []byte{0x01, byte(height), '/'}
	}
	return b, nil
}

func mineTemplateAndConnect(chain *blockchain.Chain, pool *mempool.Pool, hasher fakeHasher, pubKeyHash []byte) error {
	tpl, _, err := mining.NewBlockTemplate(chain, pool, pubKeyHash)
	if err != nil {
		return err
	}
	for nonce := uint32(0); ; nonce++ {
		tpl.Header.Nonce = nonce
		h, err := hasher.HashHeader(tpl.Header)
		if err != nil {
			return err
		}
		if consensus.CheckProofOfWork(h, tpl.Header.Bits) != nil {
			if nonce == ^uint32(0) {
				break
			}
			continue
		}
		if err := chain.ConnectBlock(tpl); err != nil {
			return err
		}
		pool.RemoveForBlock(tpl)
		return nil
	}
	return nil
}

func TestEncryptedLockedWalletKeepsReadinessMetadata(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.SetHDSeed(""); err != nil {
		t.Fatal(err)
	}
	if _, err := w.NewAddress(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.NewHybridAddress(); err != nil {
		t.Fatal(err)
	}
	if err := w.Encrypt("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	info := w.SecurityInfo()
	if info["locked"] != true || info["encrypted"] != true {
		t.Fatalf("wallet should be encrypted and locked: %#v", info)
	}
	if got, ok := info["classic_keys"].(int); !ok || got != 1 {
		t.Fatalf("locked classic_keys=%v", info["classic_keys"])
	}
	if got, ok := info["hybrid_keys"].(int); !ok || got != 1 {
		t.Fatalf("locked hybrid_keys=%v", info["hybrid_keys"])
	}
	if info["hdseed"] != true {
		t.Fatalf("locked hdseed metadata lost: %#v", info)
	}

	w2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	info2 := w2.SecurityInfo()
	if got, ok := info2["classic_keys"].(int); !ok || got != 1 {
		t.Fatalf("reopened locked classic_keys=%v", info2["classic_keys"])
	}
	if got, ok := info2["hybrid_keys"].(int); !ok || got != 1 {
		t.Fatalf("reopened locked hybrid_keys=%v", info2["hybrid_keys"])
	}
	if info2["hdseed"] != true {
		t.Fatalf("reopened locked hdseed metadata lost: %#v", info2)
	}
}

func TestChangePassphraseKeepsWalletUnlockable(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.NewAddress(); err != nil {
		t.Fatal(err)
	}
	if err := w.Encrypt("old-passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := w.Unlock("old-passphrase", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := w.ChangePassphrase("old-passphrase", "new-passphrase"); err != nil {
		t.Fatal(err)
	}
	w.Lock()
	if err := w.Unlock("old-passphrase", time.Minute); err == nil {
		t.Fatalf("old passphrase should no longer unlock wallet")
	}
	if err := w.Unlock("new-passphrase", time.Minute); err != nil {
		t.Fatalf("new passphrase did not unlock wallet: %v", err)
	}
}

func TestRestorePlainBackupImportsKeysAdditively(t *testing.T) {
	sourceDir := t.TempDir()
	source, err := Open(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	classic, err := source.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := source.NewHybridAddress()
	if err != nil {
		t.Fatal(err)
	}
	target, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	result, err := target.RestorePlainBackup(filepath.Join(sourceDir, "wallet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if result["classic_imported"] == 0 || result["hybrid_imported"] == 0 {
		t.Fatalf("restore imported counts too low: %+v", result)
	}
	got := map[string]bool{}
	for _, addr := range target.ListAddresses() {
		got[addr] = true
	}
	if !got[classic] || !got[hybrid] {
		t.Fatalf("restored wallet missing classic=%v hybrid=%v from %v", got[classic], got[hybrid], got)
	}
}

// A sweep with fee=0 must fall through to auto-fee, consume every input and emit
// exactly one output. The auto-fee branch used to reject every sweep because it
// compared the freshly estimated fee against the already-consumed total, and it
// reported the pre-fee amount back to the caller.
func TestSweepAutoFeeConsumesAllInputsAndReportsRealFee(t *testing.T) {
	w, srcAddr, _, chain, pool := fundedClassicWallet(t)
	dest, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	unspent, err := w.ListUnspentForSpend(chain, pool)
	if err != nil {
		t.Fatal(err)
	}
	total := int64(0)
	inputs := 0
	for _, u := range unspent {
		if u.Locked || u.Address != srcAddr {
			continue
		}
		if u.Coinbase && u.Confirmations > 0 && u.Confirmations < int32(chaincfg.CoinbaseMaturity) {
			continue
		}
		total += u.Value
		inputs++
	}
	if inputs < 2 {
		t.Fatalf("sweep needs several inputs, got %d", inputs)
	}

	txid, swept, err := w.Sweep(chain, pool, srcAddr, dest, 0)
	if err != nil {
		t.Fatalf("sweep with auto fee: %v", err)
	}
	if txid == "" {
		t.Fatal("empty txid for auto-fee sweep")
	}

	var found *wire.MsgTx
	for _, mtx := range pool.Transactions(0) {
		h, herr := mtx.TxHash()
		if herr != nil {
			t.Fatalf("hash swept tx: %v", herr)
		}
		if h.String() == txid {
			found = mtx
		}
	}
	if found == nil {
		t.Fatal("swept transaction is not in the mempool")
	}
	if len(found.TxOut) != 1 {
		t.Fatalf("sweep must emit exactly one output, got %d", len(found.TxOut))
	}
	if len(found.TxIn) != inputs {
		t.Fatalf("sweep must consume every input: got %d, want %d", len(found.TxIn), inputs)
	}
	var outSum int64
	for _, o := range found.TxOut {
		outSum += o.Value
		if o.Value < mempool.DustThreshold {
			t.Fatalf("sweep produced dust output %d", o.Value)
		}
	}
	if outSum != swept {
		t.Fatalf("reported swept amount %d does not match the real output %d", swept, outSum)
	}
	paid := total - outSum
	if paid <= 0 {
		t.Fatalf("no fee deducted: total %d, output %d", total, outSum)
	}
	if paid >= total {
		t.Fatalf("swept amount %d leaves no room for the input total %d", swept, total)
	}
}

// An explicit fee must survive untouched so the consolidation panel keeps paying
// the amount it asked for.
func TestSweepWithExplicitFeeDeductsExactlyThatFee(t *testing.T) {
	w, srcAddr, _, chain, pool := fundedClassicWallet(t)
	dest, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	unspent, err := w.ListUnspentForSpend(chain, pool)
	if err != nil {
		t.Fatal(err)
	}
	total := int64(0)
	for _, u := range unspent {
		if u.Locked || u.Address != srcAddr {
			continue
		}
		if u.Coinbase && u.Confirmations > 0 && u.Confirmations < int32(chaincfg.CoinbaseMaturity) {
			continue
		}
		total += u.Value
	}
	const fee = int64(20000)
	txid, swept, err := w.Sweep(chain, pool, srcAddr, dest, fee)
	if err != nil {
		t.Fatalf("sweep with explicit fee: %v", err)
	}
	if want := total - fee; swept != want {
		t.Fatalf("explicit fee sweep reported %d, want %d", swept, want)
	}
	var outSum int64
	for _, mtx := range pool.Transactions(0) {
		h, herr := mtx.TxHash()
		if herr != nil {
			t.Fatalf("hash swept tx: %v", herr)
		}
		if h.String() != txid {
			continue
		}
		if len(mtx.TxOut) != 1 {
			t.Fatalf("sweep must emit exactly one output, got %d", len(mtx.TxOut))
		}
		for _, o := range mtx.TxOut {
			outSum += o.Value
		}
	}
	if outSum != total-fee {
		t.Fatalf("explicit fee sweep output %d, want %d", outSum, total-fee)
	}
}

// An empty source address has to draw inputs from every wallet address, so a
// single transfer can top up an external deposit address with an exact amount
// even when no single wallet address holds that much.
func TestSendFromEmptySourceSpansAddressesAndPaysExactAmount(t *testing.T) {
	w, chain, pool, addrs := fundedMultiAddressWallet(t, 4)
	dest, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}

	unspent, err := w.ListUnspentForSpend(chain, pool)
	if err != nil {
		t.Fatal(err)
	}
	perAddr := map[string]int64{}
	var total int64
	for _, u := range unspent {
		if u.Locked {
			continue
		}
		if u.Coinbase && u.Confirmations > 0 && u.Confirmations < int32(chaincfg.CoinbaseMaturity) {
			continue
		}
		perAddr[u.Address] += u.Value
		total += u.Value
	}
	if len(perAddr) < 4 {
		t.Fatalf("expected funding across several addresses, got %d", len(perAddr))
	}
	var largest int64
	for _, v := range perAddr {
		if v > largest {
			largest = v
		}
	}

	// Pick an amount larger than any single address holds, so only a
	// multi-input selection can satisfy it.
	amount := largest + largest/2
	const fee = int64(20000)
	// Deliberately omit one funded address: an explicit allowlist must keep the
	// transfer away from any wallet address that was not named.
	used := addrs[:len(addrs)-1]
	txid, err := w.SendToAddressFromAddrs(chain, pool, used, dest, amount, fee)
	if err != nil {
		t.Fatalf("send from address allowlist: %v", err)
	}

	var found *wire.MsgTx
	for _, mtx := range pool.Transactions(0) {
		h, herr := mtx.TxHash()
		if herr != nil {
			t.Fatalf("hash transfer tx: %v", herr)
		}
		if h.String() == txid {
			found = mtx
		}
	}
	if found == nil {
		t.Fatal("transfer transaction is not in the mempool")
	}
	if len(found.TxIn) < 2 {
		t.Fatalf("expected a multi-input transfer, got %d inputs", len(found.TxIn))
	}

	destScript, err := destinationScript(dest)
	if err != nil {
		t.Fatal(err)
	}
	var paid, change int64
	for _, o := range found.TxOut {
		if bytes.Equal(o.PkScript, destScript) {
			paid = o.Value
			continue
		}
		change += o.Value
		if o.Value < mempool.DustThreshold {
			t.Fatalf("transfer produced dust output %d", o.Value)
		}
	}
	if paid != amount {
		t.Fatalf("destination received %d, want exact %d", paid, amount)
	}
	// Sum only the inputs the wallet actually selected, not the whole wallet:
	// selection must stop as soon as amount+fee is covered.
	byOutpoint := map[string]int64{}
	for _, u := range unspent {
		byOutpoint[fmt.Sprintf("%s:%d", u.TxID, u.Vout)] = u.Value
	}
	var selectedSum int64
	for _, in := range found.TxIn {
		key := fmt.Sprintf("%s:%d", in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		v, ok := byOutpoint[key]
		if !ok {
			t.Fatalf("selected input %s is not a known wallet utxo", key)
		}
		selectedSum += v
	}
	if want := selectedSum - amount - fee; change != want {
		t.Fatalf("change %d does not balance selected inputs %d against amount %d and fee %d", change, selectedSum, amount, fee)
	}
	if selectedSum >= total {
		t.Fatalf("selection consumed the whole wallet (%d of %d) instead of stopping at the requested amount", selectedSum, total)
	}
}

// fundedMultiAddressWallet mines mature coinbase blocks to n distinct wallet
// addresses so no single address can cover a whole transfer.
func fundedMultiAddressWallet(t *testing.T, n int) (*Wallet, *blockchain.Chain, *mempool.Pool, []string) {
	t.Helper()
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	addrs := make([]string, 0, n)
	hashes := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		addr, err := w.NewAddress()
		if err != nil {
			t.Fatal(err)
		}
		_, hash, err := address.DecodeBase58Check(addr)
		if err != nil {
			t.Fatal(err)
		}
		addrs = append(addrs, addr)
		hashes = append(hashes, hash)
	}
	chain, err := blockchain.New(chaincfg.MainNet, fakeHasher{}, storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New()
	var prev chainhash.Hash
	for i := 0; i <= chaincfg.CoinbaseMaturity+n; i++ {
		bits, err := chain.NextRequiredBits()
		if err != nil {
			t.Fatal(err)
		}
		b, err := buildCoinbaseBlock(prev, int32(i), uint32(10_000+i), bits, hashes[i%n])
		if err != nil {
			t.Fatal(err)
		}
		if err := chain.ProcessBlock(b); err != nil {
			t.Fatalf("process block %d: %v", i, err)
		}
		prev, err = fakeHasher{}.HashHeader(b.Header)
		if err != nil {
			t.Fatal(err)
		}
	}
	return w, chain, pool, addrs
}
