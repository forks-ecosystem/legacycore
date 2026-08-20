package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/scrypt"

	"legacycoin/legacy-go/internal/address"
	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/chainhash"
	"legacycoin/legacy-go/internal/config"
	"legacycoin/legacy-go/internal/fsutil"
	"legacycoin/legacy-go/internal/mempool"
	"legacycoin/legacy-go/internal/pqc"
	"legacycoin/legacy-go/internal/script"
	"legacycoin/legacy-go/internal/wire"
)

type Wallet struct {
	mu           sync.RWMutex
	path         string
	keys         map[string]string
	hybridKeys   map[string]pqc.HybridPrivateBytes
	addresses    map[string]struct{}
	hybridAddrs  map[string]struct{}
	encrypted    bool
	locked       bool
	saltHex      string
	nonceHex     string
	cipherHex    string
	unlockPass   []byte
	unlockTimer  *time.Timer
	seedHex      string
	mnemonic     string
	nextIndex    uint32
	classicCount uint32
	hybridCount  uint32
	hasHDSeed    bool
}

type stored struct {
	Keys            map[string]string                 `json:"keys,omitempty"`
	HybridKeys      map[string]pqc.HybridPrivateBytes `json:"hybrid_keys,omitempty"`
	Addresses       []string                          `json:"addresses,omitempty"`
	HybridAddresses []string                          `json:"hybrid_addresses,omitempty"`
	Encrypted       bool                              `json:"encrypted,omitempty"`
	Salt            string                            `json:"salt,omitempty"`
	Nonce           string                            `json:"nonce,omitempty"`
	Cipher          string                            `json:"cipher,omitempty"`
	SeedHex         string                            `json:"seed_hex,omitempty"`
	Mnemonic        string                            `json:"mnemonic,omitempty"`
	NextIndex       uint32                            `json:"next_index,omitempty"`
	ClassicKeyCount uint32                            `json:"classic_key_count,omitempty"`
	HybridKeyCount  uint32                            `json:"hybrid_key_count,omitempty"`
	HasHDSeed       bool                              `json:"has_hd_seed,omitempty"`
}

type keyState struct {
	Keys            map[string]string                 `json:"keys"`
	HybridKeys      map[string]pqc.HybridPrivateBytes `json:"hybrid_keys,omitempty"`
	SeedHex         string                            `json:"seed_hex,omitempty"`
	Mnemonic        string                            `json:"mnemonic,omitempty"`
	NextIndex       uint32                            `json:"next_index,omitempty"`
	ClassicKeyCount uint32                            `json:"classic_key_count,omitempty"`
	HybridKeyCount  uint32                            `json:"hybrid_key_count,omitempty"`
	HasHDSeed       bool                              `json:"has_hd_seed,omitempty"`
}

type UTXOView struct {
	TxID          string `json:"txid"`
	Vout          uint32 `json:"vout"`
	Address       string `json:"address"`
	Value         int64  `json:"value"`
	Height        int32  `json:"height"`
	Confirmations int32  `json:"confirmations"`
	Coinbase      bool   `json:"coinbase"`
	PubKeyHashHex string `json:"pubkey_hash_hex,omitempty"`
	Locked        bool   `json:"locked,omitempty"`
	LockedBy      string `json:"locked_by,omitempty"`
	Unconfirmed   bool   `json:"unconfirmed,omitempty"`
	SafeToSpend   bool   `json:"safe_to_spend,omitempty"`
	ParentTxID    string `json:"parent_txid,omitempty"`
	ChainDepth    int    `json:"unconfirmed_chain_depth,omitempty"`
	PkScriptHex   string `json:"pk_script_hex,omitempty"`
}

func encodeMnemonic(m string) string {
	if m == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(m))
}

func decodeMnemonic(s string) string {
	if s == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(b)
}

func Open(dataDir string) (*Wallet, error) {
	path := filepath.Join(dataDir, "wallet.json")
	w := &Wallet{
		path:        path,
		keys:        make(map[string]string),
		hybridKeys:  make(map[string]pqc.HybridPrivateBytes),
		addresses:   make(map[string]struct{}),
		hybridAddrs: make(map[string]struct{}),
	}
	b, err := os.ReadFile(path)
	if err == nil {
		var s stored
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, err
		}
		w.loadAddressMetadataLocked(s.Addresses, s.HybridAddresses)
		if s.Encrypted {
			w.encrypted = true
			w.locked = true
			w.saltHex = s.Salt
			w.nonceHex = s.Nonce
			w.cipherHex = s.Cipher
			w.classicCount = s.ClassicKeyCount
			w.hybridCount = s.HybridKeyCount
			w.hasHDSeed = s.HasHDSeed
			w.nextIndex = s.NextIndex
		} else {
			if s.Keys != nil {
				w.keys = s.Keys
			}
			if s.HybridKeys != nil {
				w.hybridKeys = s.HybridKeys
			}
			w.seedHex = s.SeedHex
			w.mnemonic = decodeMnemonic(s.Mnemonic)
			w.nextIndex = s.NextIndex
			w.refreshMetadataLocked()
		}
		return w, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if err := w.persist(); err != nil {
		return nil, err
	}
	return w, nil
}

// OpenNamed opens a named wallet from dataDir/wallets/{name}/wallet.json.
// The wallet file is created if it does not exist.
func OpenNamed(dataDir string, name string) (*Wallet, error) {
	walletDir := config.WalletDirForName(dataDir, name)
	return Open(walletDir)
}

// ListWalletDirs returns the names of subdirectories under dataDir/wallets/ that contain a wallet.json file.
func ListWalletDirs(dataDir string) []string {
	walletsDir := config.WalletsDir(dataDir)
	entries, err := os.ReadDir(walletsDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		walletFile := filepath.Join(walletsDir, e.Name(), "wallet.json")
		if _, err := os.Stat(walletFile); err == nil {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func (w *Wallet) NewHybridAddress() (string, error) {
	if err := w.requireUnlocked(); err != nil {
		return "", err
	}
	key, err := pqc.GenerateHybridKey()
	if err != nil {
		return "", err
	}
	addr := key.Public().Address()
	w.mu.Lock()
	w.hybridKeys[addr] = key.Bytes()
	w.hybridAddrs[addr] = struct{}{}
	w.refreshMetadataLocked()
	w.mu.Unlock()
	return addr, w.persist()
}

func (w *Wallet) NewAddress() (string, error) {
	if err := w.requireUnlocked(); err != nil {
		return "", err
	}
	var (
		priv *btcec.PrivateKey
		err  error
	)
	w.mu.Lock()
	if w.seedHex != "" {
		priv, err = w.deriveNextPrivateKeyLocked()
	} else {
		priv, err = btcec.NewPrivateKey()
	}
	w.mu.Unlock()
	if err != nil {
		return "", err
	}
	pubHash := script.Hash160(priv.PubKey().SerializeCompressed())
	addr := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, pubHash)
	w.mu.Lock()
	w.keys[addr] = hex.EncodeToString(priv.Serialize())
	w.addresses[addr] = struct{}{}
	w.refreshMetadataLocked()
	w.mu.Unlock()
	return addr, w.persist()
}

func (w *Wallet) SetHDSeed(seedHex string) (string, error) {
	if err := w.requireUnlocked(); err != nil {
		return "", err
	}
	seed := make([]byte, 32)
	mnem := ""
	if seedHex == "" {
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return "", err
		}
		mnem, err := bip39.NewMnemonic(seed)
		if err != nil {
			return "", err
		}
		_ = mnem // store below
	} else {
		if bip39.IsMnemonicValid(seedHex) {
			decoded, err := bip39.EntropyFromMnemonic(seedHex)
			if err != nil || len(decoded) < 16 {
				return "", fmt.Errorf("invalid mnemonic phrase")
			}
			if len(decoded) != 32 {
				h := sha256.Sum256(decoded)
				seed = h[:]
			} else {
				copy(seed, decoded)
			}
			mnem = seedHex
		} else {
			decoded, err := hex.DecodeString(seedHex)
			if err != nil || len(decoded) < 16 {
				return "", fmt.Errorf("seed must be a 24-word mnemonic phrase or hex with at least 16 bytes")
			}
			sum := sha256.Sum256(decoded)
			copy(seed, sum[:])
		}
	}
	if mnem == "" {
		var err error
		mnem, err = bip39.NewMnemonic(seed)
		if err != nil {
			return "", err
		}
	}
	w.mu.Lock()
	w.seedHex = hex.EncodeToString(seed)
	w.mnemonic = mnem
	w.nextIndex = 0
	w.refreshMetadataLocked()
	w.mu.Unlock()
	return w.seedHex, w.persist()
}

func (w *Wallet) SetHDMnemonic(mnemonic string) (string, error) {
	return w.SetHDSeed(mnemonic)
}

func (w *Wallet) Mnemonic() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.mnemonic
}

func (w *Wallet) ListAddresses() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	seen := make(map[string]struct{}, len(w.keys)+len(w.hybridKeys)+len(w.addresses)+len(w.hybridAddrs))
	out := make([]string, 0, len(w.keys)+len(w.hybridKeys)+len(w.addresses)+len(w.hybridAddrs))
	for addr := range w.keys {
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	for addr := range w.hybridKeys {
		if _, ok := seen[addr]; !ok {
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	for addr := range w.addresses {
		if _, ok := seen[addr]; !ok {
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	for addr := range w.hybridAddrs {
		if _, ok := seen[addr]; !ok {
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	sort.Strings(out)
	return out
}

func (w *Wallet) DumpPrivKey(addr string) (string, error) {
	if err := w.requireUnlocked(); err != nil {
		return "", err
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	hexKey, ok := w.keys[addr]
	if !ok {
		return "", fmt.Errorf("address not found")
	}
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil || len(keyBytes) != 32 {
		return "", fmt.Errorf("invalid private key")
	}
	payload := append([]byte{}, keyBytes...)
	payload = append(payload, 0x01)
	return address.EncodeBase58Check(chaincfg.PrivateKeyVersion, payload), nil
}

func (w *Wallet) ImportPrivKey(wif string) (string, error) {
	if err := w.requireUnlocked(); err != nil {
		return "", err
	}
	version, payload, err := address.DecodeBase58Check(wif)
	if err != nil {
		return "", err
	}
	if version != chaincfg.PrivateKeyVersion {
		return "", fmt.Errorf("wrong WIF version")
	}
	if len(payload) != 32 && len(payload) != 33 {
		return "", fmt.Errorf("invalid WIF payload size")
	}
	if len(payload) == 33 && payload[32] != 0x01 {
		return "", fmt.Errorf("unsupported WIF suffix")
	}
	priv, _ := btcec.PrivKeyFromBytes(payload[:32])
	pubHash := script.Hash160(priv.PubKey().SerializeCompressed())
	addr := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, pubHash)
	w.mu.Lock()
	w.keys[addr] = hex.EncodeToString(priv.Serialize())
	w.addresses[addr] = struct{}{}
	w.refreshMetadataLocked()
	w.mu.Unlock()
	return addr, w.persist()
}

func (w *Wallet) Encrypt(passphrase string) error {
	w.mu.Lock()
	if w.encrypted {
		w.mu.Unlock()
		return fmt.Errorf("wallet already encrypted")
	}
	if passphrase == "" {
		w.mu.Unlock()
		return fmt.Errorf("empty passphrase")
	}
	w.refreshMetadataLocked()
	cipherHex, saltHex, nonceHex, err := encryptState(keyState{
		Keys:            w.keys,
		HybridKeys:      w.hybridKeys,
		SeedHex:         w.seedHex,
		NextIndex:       w.nextIndex,
		ClassicKeyCount: w.classicCount,
		HybridKeyCount:  w.hybridCount,
		HasHDSeed:       w.hasHDSeed,
	}, passphrase)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	w.encrypted = true
	w.locked = true
	w.saltHex = saltHex
	w.nonceHex = nonceHex
	w.cipherHex = cipherHex
	for i := range w.unlockPass {
		w.unlockPass[i] = 0
	}
	w.unlockPass = nil
	for k := range w.keys {
		delete(w.keys, k)
	}
	for k := range w.hybridKeys {
		delete(w.hybridKeys, k)
	}
	w.mu.Unlock()
	return w.persistLocked()
}

func (w *Wallet) Unlock(passphrase string, timeout time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.encrypted {
		return nil
	}
	if passphrase == "" {
		return fmt.Errorf("empty passphrase")
	}
	state, err := decryptState(w.cipherHex, w.saltHex, w.nonceHex, passphrase)
	if err != nil {
		return err
	}
	w.keys = state.Keys
	if w.keys == nil {
		w.keys = make(map[string]string)
	}
	w.hybridKeys = state.HybridKeys
	if w.hybridKeys == nil {
		w.hybridKeys = make(map[string]pqc.HybridPrivateBytes)
	}
	w.seedHex = state.SeedHex
	w.mnemonic = state.Mnemonic
	w.nextIndex = state.NextIndex
	w.refreshMetadataLocked()
	w.locked = false
	w.unlockPass = []byte(passphrase)
	if w.unlockTimer != nil {
		w.unlockTimer.Stop()
		w.unlockTimer = nil
	}
	if timeout > 0 {
		w.unlockTimer = time.AfterFunc(timeout, func() {
			_ = w.Lock()
		})
	}
	return nil
}

func (w *Wallet) Lock() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.encrypted {
		return nil
	}
	if w.unlockTimer != nil {
		w.unlockTimer.Stop()
		w.unlockTimer = nil
	}
	for k := range w.keys {
		delete(w.keys, k)
	}
	for k := range w.hybridKeys {
		delete(w.hybridKeys, k)
	}
	w.locked = true
	for i := range w.unlockPass {
		w.unlockPass[i] = 0
	}
	w.unlockPass = nil
	w.mnemonic = ""
	w.seedHex = ""
	return nil
}

func (w *Wallet) ChangePassphrase(oldPassphrase, newPassphrase string) error {
	if newPassphrase == "" {
		return fmt.Errorf("empty new passphrase")
	}
	if err := w.Unlock(oldPassphrase, 0); err != nil {
		return err
	}
	w.mu.Lock()
	if !w.encrypted {
		w.mu.Unlock()
		return fmt.Errorf("wallet is not encrypted")
	}
	w.refreshMetadataLocked()
	cipherHex, saltHex, nonceHex, err := encryptState(keyState{
		Keys:            w.keys,
		HybridKeys:      w.hybridKeys,
		SeedHex:         w.seedHex,
		NextIndex:       w.nextIndex,
		ClassicKeyCount: w.classicCount,
		HybridKeyCount:  w.hybridCount,
		HasHDSeed:       w.hasHDSeed,
	}, newPassphrase)
	if err != nil {
		return err
	}
	w.cipherHex = cipherHex
	w.saltHex = saltHex
	w.nonceHex = nonceHex
	for i := range w.unlockPass {
		w.unlockPass[i] = 0
	}
	w.unlockPass = []byte(newPassphrase)
	w.mu.Unlock()
	return w.persistLocked()
}

func (w *Wallet) RestorePlainBackup(path string) (map[string]int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s stored
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Encrypted {
		return nil, fmt.Errorf("encrypted backup restore requires restoring the wallet file manually after backing up the current wallet")
	}
	if err := w.requireUnlocked(); err != nil {
		return nil, err
	}
	importedClassic := 0
	importedHybrid := 0
	w.mu.Lock()
	if w.keys == nil {
		w.keys = make(map[string]string)
	}
	for addr, key := range s.Keys {
		if _, exists := w.keys[addr]; !exists {
			importedClassic++
		}
		w.keys[addr] = key
		w.addresses[addr] = struct{}{}
	}
	if w.hybridKeys == nil {
		w.hybridKeys = make(map[string]pqc.HybridPrivateBytes)
	}
	for addr, key := range s.HybridKeys {
		if _, exists := w.hybridKeys[addr]; !exists {
			importedHybrid++
		}
		w.hybridKeys[addr] = key
		w.hybridAddrs[addr] = struct{}{}
	}
	if w.seedHex == "" && s.SeedHex != "" {
		w.seedHex = s.SeedHex
	}
	if s.NextIndex > w.nextIndex {
		w.nextIndex = s.NextIndex
	}
	w.refreshMetadataLocked()
	classicTotal := len(w.keys)
	hybridTotal := len(w.hybridKeys)
	w.mu.Unlock()
	if err := w.persist(); err != nil {
		return nil, err
	}
	return map[string]int{"classic_imported": importedClassic, "hybrid_imported": importedHybrid, "classic_total": classicTotal, "hybrid_total": hybridTotal}, nil
}

func (w *Wallet) SecurityInfo() map[string]any {
	w.mu.RLock()
	defer w.mu.RUnlock()
	classicKeys := int(w.classicCount)
	hybridKeys := int(w.hybridCount)
	hasHDSeed := w.hasHDSeed
	if !w.encrypted || !w.locked {
		classicKeys = len(w.keys)
		hybridKeys = len(w.hybridKeys)
		hasHDSeed = w.seedHex != ""
	}
	return map[string]any{
		"encrypted":    w.encrypted,
		"locked":       w.encrypted && w.locked,
		"hdseed":       hasHDSeed,
		"hdindex":      w.nextIndex,
		"classic_keys": classicKeys,
		"hybrid_keys":  hybridKeys,
	}
}

func (w *Wallet) ListUnspent(chain *blockchain.Chain) ([]UTXOView, error) {
	return w.listUnspent(chain, nil, nil)
}

func (w *Wallet) ListUnspentForSpend(chain *blockchain.Chain, pool *mempool.Pool) ([]UTXOView, error) {
	locked := map[string]string{}
	var mempoolTxs []*wire.MsgTx
	if pool != nil {
		locked = pool.SpentOutpoints()
		mempoolTxs = pool.Transactions(0)
	}
	return w.listUnspent(chain, locked, mempoolTxs)
}

func (w *Wallet) listUnspent(chain *blockchain.Chain, locked map[string]string, mempoolTxs []*wire.MsgTx) ([]UTXOView, error) {
	set, err := chain.ListUTXO()
	if err != nil {
		return nil, err
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	owned, ownedHybrid, scriptToAddr := w.ownedMapsLocked()
	tip := chain.Tip()
	out := make([]UTXOView, 0)
	confirmedOwned := map[string]struct{}{}
	for _, u := range set {
		pk, err := hex.DecodeString(u.PkScript)
		if err != nil {
			continue
		}
		addr := ""
		pkhHex := ""
		switch {
		case script.IsPayToPubKeyHash(pk):
			var k [20]byte
			copy(k[:], pk[3:23])
			pkhHex = hex.EncodeToString(k[:])
			addr = owned[k]
		case script.IsPayToHybridPubKeyHash(pk):
			var k [20]byte
			copy(k[:], pk[3:23])
			pkhHex = hex.EncodeToString(k[:])
			addr = ownedHybrid[k]
		}
		if addr == "" {
			continue
		}
		key := blockchain.OutPointKey(u.TxID, u.Vout)
		confirmedOwned[key] = struct{}{}
		confs := int32(0)
		if tip != nil && tip.Height >= u.Height {
			confs = tip.Height - u.Height + 1
		}
		lockedBy := ""
		if locked != nil {
			lockedBy = locked[key]
		}
		out = append(out, UTXOView{
			TxID:          u.TxID,
			Vout:          u.Vout,
			Address:       addr,
			Value:         u.Value,
			Height:        u.Height,
			Confirmations: confs,
			Coinbase:      u.Coinbase,
			PubKeyHashHex: pkhHex,
			Locked:        lockedBy != "",
			LockedBy:      lockedBy,
			PkScriptHex:   u.PkScript,
		})
	}
	if locked != nil {
		out = append(out, w.safeMempoolChangeLocked(mempoolTxs, locked, confirmedOwned, scriptToAddr)...)
	}
	return out, nil
}

func (w *Wallet) ownedMapsLocked() (map[[20]byte]string, map[[20]byte]string, map[string]string) {
	owned := make(map[[20]byte]string)
	scriptToAddr := make(map[string]string)
	for addr := range w.keys {
		version, payload, err := address.DecodeBase58Check(addr)
		if err != nil || version != chaincfg.PublicKeyHashVersion || len(payload) != 20 {
			continue
		}
		var k [20]byte
		copy(k[:], payload)
		owned[k] = addr
		if pk, err := script.PayToPubKeyHashScript(payload); err == nil {
			scriptToAddr[hex.EncodeToString(pk)] = addr
		}
	}
	ownedHybrid := make(map[[20]byte]string)
	for addr := range w.hybridKeys {
		payload, err := address.DecodeHybridAddress(addr)
		if err != nil || len(payload) != 20 {
			continue
		}
		var k [20]byte
		copy(k[:], payload)
		ownedHybrid[k] = addr
		if pk, err := script.PayToHybridPubKeyHashScript(payload); err == nil {
			scriptToAddr[hex.EncodeToString(pk)] = addr
		}
	}
	return owned, ownedHybrid, scriptToAddr
}

func (w *Wallet) safeMempoolChangeLocked(txs []*wire.MsgTx, locked map[string]string, confirmedOwned map[string]struct{}, scriptToAddr map[string]string) []UTXOView {
	const maxDepth = 10
	safeDepth := map[string]int{}
	for changed := true; changed; {
		changed = false
		for _, tx := range txs {
			txHash, err := tx.TxHash()
			if err != nil {
				continue
			}
			txid := txHash.String()
			if _, exists := safeDepth[txid]; exists {
				continue
			}
			depth := 0
			safe := false
			for _, in := range tx.TxIn {
				key := blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
				if _, ok := confirmedOwned[key]; ok {
					safe = true
					if depth < 1 {
						depth = 1
					}
					continue
				}
				if parentDepth, ok := safeDepth[in.PreviousOutPoint.Hash.String()]; ok {
					safe = true
					if depth < parentDepth+1 {
						depth = parentDepth + 1
					}
				}
			}
			if safe && depth <= maxDepth {
				safeDepth[txid] = depth
				changed = true
			}
		}
	}
	out := []UTXOView{}
	for _, tx := range txs {
		txHash, err := tx.TxHash()
		if err != nil {
			continue
		}
		txid := txHash.String()
		depth, ok := safeDepth[txid]
		if !ok || depth > maxDepth {
			continue
		}
		for i, txOut := range tx.TxOut {
			scriptHex := hex.EncodeToString(txOut.PkScript)
			addr := scriptToAddr[scriptHex]
			if addr == "" {
				continue
			}
			key := blockchain.OutPointKey(txid, uint32(i))
			lockedBy := locked[key]
			out = append(out, UTXOView{
				TxID:          txid,
				Vout:          uint32(i),
				Address:       addr,
				Value:         txOut.Value,
				Height:        -1,
				Confirmations: 0,
				Locked:        lockedBy != "",
				LockedBy:      lockedBy,
				Unconfirmed:   true,
				SafeToSpend:   lockedBy == "",
				ParentTxID:    txid,
				ChainDepth:    depth,
				PkScriptHex:   scriptHex,
			})
		}
	}
	return out
}

func (w *Wallet) SendToAddress(chain *blockchain.Chain, pool *mempool.Pool, to string, amount int64, fee int64) (string, error) {
	return w.sendWithSource(chain, pool, "", to, amount, fee, nil)
}

func (w *Wallet) SendFromAddress(chain *blockchain.Chain, pool *mempool.Pool, from string, to string, amount int64, fee int64) (string, error) {
	if from == "" {
		return "", fmt.Errorf("bad source address")
	}
	return w.sendWithSource(chain, pool, from, to, amount, fee, nil)
}

func (w *Wallet) SendMany(chain *blockchain.Chain, pool *mempool.Pool, from string, outputs map[string]int64, fee int64) (string, int64, error) {
	if fee < 0 {
		return "", 0, fmt.Errorf("bad fee")
	}
	if len(outputs) == 0 {
		return "", 0, fmt.Errorf("missing outputs")
	}
	addrs := make([]string, 0, len(outputs))
	for addr := range outputs {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)
	totalAmount := int64(0)
	extra := make([]wire.TxOut, 0, len(addrs))
	for _, addr := range addrs {
		amountValue := outputs[addr]
		if amountValue <= 0 {
			return "", 0, fmt.Errorf("amount for %s must be > 0", addr)
		}
		pkScript, err := destinationScript(addr)
		if err != nil {
			return "", 0, err
		}
		totalAmount += amountValue
		extra = append(extra, wire.TxOut{Value: amountValue, PkScript: pkScript})
	}
	txid, err := w.sendWithSource(chain, pool, from, "", 0, fee, extra)
	if err != nil {
		return "", 0, err
	}
	return txid, totalAmount, nil
}

func (w *Wallet) SignRawTransaction(chain *blockchain.Chain, tx *wire.MsgTx) (*wire.MsgTx, bool, []map[string]any, error) {
	if err := w.requireUnlocked(); err != nil {
		return nil, false, nil, err
	}
	if tx == nil {
		return nil, false, nil, fmt.Errorf("nil transaction")
	}
	if chain == nil {
		return nil, false, nil, fmt.Errorf("nil chain")
	}
	signErrors := make([]map[string]any, 0)
	w.mu.RLock()
	defer w.mu.RUnlock()
	for i := range tx.TxIn {
		in := &tx.TxIn[i]
		if in.PreviousOutPoint.Index == ^uint32(0) && in.PreviousOutPoint.Hash == (chainhash.Hash{}) {
			signErrors = append(signErrors, map[string]any{
				"txid":  in.PreviousOutPoint.Hash.String(),
				"vout":  in.PreviousOutPoint.Index,
				"error": "coinbase input cannot be signed",
			})
			continue
		}
		prevTxID := in.PreviousOutPoint.Hash.String()
		entry, err := chain.UTXO(prevTxID, in.PreviousOutPoint.Index)
		if err != nil || entry == nil {
			signErrors = append(signErrors, map[string]any{
				"txid":  prevTxID,
				"vout":  in.PreviousOutPoint.Index,
				"error": "prevout not found in current UTXO set",
			})
			continue
		}
		prevScript, err := hex.DecodeString(entry.PkScript)
		if err != nil {
			signErrors = append(signErrors, map[string]any{
				"txid":  prevTxID,
				"vout":  in.PreviousOutPoint.Index,
				"error": "invalid prevout script",
			})
			continue
		}
		sighash, err := script.SignatureHash(tx, i, prevScript, script.SigHashAll)
		if err != nil {
			signErrors = append(signErrors, map[string]any{
				"txid":  prevTxID,
				"vout":  in.PreviousOutPoint.Index,
				"error": err.Error(),
			})
			continue
		}
		switch {
		case script.IsPayToPubKeyHash(prevScript):
			if len(prevScript) < 23 {
				signErrors = append(signErrors, map[string]any{
					"txid":  prevTxID,
					"vout":  in.PreviousOutPoint.Index,
					"error": "short P2PKH script",
				})
				continue
			}
			addr := address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, prevScript[3:23])
			hexKey, ok := w.keys[addr]
			if !ok {
				signErrors = append(signErrors, map[string]any{
					"txid":    prevTxID,
					"vout":    in.PreviousOutPoint.Index,
					"address": addr,
					"error":   "wallet key not found",
				})
				continue
			}
			keyBytes, err := hex.DecodeString(hexKey)
			if err != nil {
				signErrors = append(signErrors, map[string]any{
					"txid":    prevTxID,
					"vout":    in.PreviousOutPoint.Index,
					"address": addr,
					"error":   "invalid wallet key encoding",
				})
				continue
			}
			priv, _ := btcec.PrivKeyFromBytes(keyBytes)
			sig := btcecdsa.Sign(priv, sighash[:]).Serialize()
			sigScript, err := script.SignatureScript(sig, priv.PubKey().SerializeCompressed())
			if err != nil {
				signErrors = append(signErrors, map[string]any{
					"txid":    prevTxID,
					"vout":    in.PreviousOutPoint.Index,
					"address": addr,
					"error":   err.Error(),
				})
				continue
			}
			in.SignatureScript = sigScript
		case script.IsPayToHybridPubKeyHash(prevScript):
			if len(prevScript) < 23 {
				signErrors = append(signErrors, map[string]any{
					"txid":  prevTxID,
					"vout":  in.PreviousOutPoint.Index,
					"error": "short hybrid script",
				})
				continue
			}
			addr := address.HybridPrefix + address.EncodeBase58Check(address.HybridVersion, prevScript[3:23])
			hybridBytes, ok := w.hybridKeys[addr]
			if !ok {
				signErrors = append(signErrors, map[string]any{
					"txid":    prevTxID,
					"vout":    in.PreviousOutPoint.Index,
					"address": addr,
					"error":   "wallet hybrid key not found",
				})
				continue
			}
			hybridKey, err := pqc.HybridPrivateKeyFromBytes(hybridBytes)
			if err != nil {
				signErrors = append(signErrors, map[string]any{
					"txid":    prevTxID,
					"vout":    in.PreviousOutPoint.Index,
					"address": addr,
					"error":   "invalid hybrid key encoding",
				})
				continue
			}
			hybridSig, err := hybridKey.Sign(sighash[:])
			if err != nil {
				signErrors = append(signErrors, map[string]any{
					"txid":    prevTxID,
					"vout":    in.PreviousOutPoint.Index,
					"address": addr,
					"error":   err.Error(),
				})
				continue
			}
			sigScript, err := script.HybridSignatureScript(hybridSig, hybridKey.Public().Bytes())
			if err != nil {
				signErrors = append(signErrors, map[string]any{
					"txid":    prevTxID,
					"vout":    in.PreviousOutPoint.Index,
					"address": addr,
					"error":   err.Error(),
				})
				continue
			}
			in.SignatureScript = sigScript
		default:
			signErrors = append(signErrors, map[string]any{
				"txid":  prevTxID,
				"vout":  in.PreviousOutPoint.Index,
				"error": "unsupported script type",
			})
		}
	}
	return tx, len(signErrors) == 0, signErrors, nil
}

func (w *Wallet) SendTokenMarkers(chain *blockchain.Chain, pool *mempool.Pool, from string, markerScripts [][]byte, fee int64) (string, error) {
	if from == "" {
		return "", fmt.Errorf("bad source address")
	}
	if len(markerScripts) == 0 {
		return "", fmt.Errorf("missing token marker scripts")
	}
	extra := make([]wire.TxOut, 0, len(markerScripts))
	for _, pk := range markerScripts {
		if !script.IsPayToPubKeyHash(pk) {
			return "", fmt.Errorf("token marker script must be standard P2PKH")
		}
		extra = append(extra, wire.TxOut{Value: mempool.DustThreshold, PkScript: pk})
	}
	return w.sendWithSource(chain, pool, from, "", 0, fee, extra)
}

func (w *Wallet) SplitCoins(chain *blockchain.Chain, pool *mempool.Pool, from string, total int64, outputs int, fee int64) (string, error) {
	if from == "" {
		return "", fmt.Errorf("bad source address")
	}
	if outputs < 2 || outputs > 100 {
		return "", fmt.Errorf("split output count must be 2..100")
	}
	if total <= 0 || fee < 0 {
		return "", fmt.Errorf("bad amount or fee")
	}
	each := total / int64(outputs)
	if each < mempool.DustThreshold {
		return "", fmt.Errorf("split output amount is dust")
	}
	remainder := total - each*int64(outputs)
	var splitScript []byte
	if hybridHash, err := address.DecodeHybridAddress(from); err == nil {
		var scriptErr error
		splitScript, scriptErr = script.PayToHybridPubKeyHashScript(hybridHash)
		if scriptErr != nil {
			return "", scriptErr
		}
	} else {
		version, payload, err := address.DecodeBase58Check(from)
		if err != nil || version != chaincfg.PublicKeyHashVersion || len(payload) != 20 {
			return "", fmt.Errorf("bad source address")
		}
		splitScript, err = script.PayToPubKeyHashScript(payload)
		if err != nil {
			return "", err
		}
	}
	extra := make([]wire.TxOut, 0, outputs)
	for i := 0; i < outputs; i++ {
		value := each
		if i == outputs-1 {
			value += remainder
		}
		extra = append(extra, wire.TxOut{Value: value, PkScript: splitScript})
	}
	return w.sendWithSource(chain, pool, from, "", 0, fee, extra)
}

func (w *Wallet) sendWithSource(chain *blockchain.Chain, pool *mempool.Pool, from string, to string, amount int64, fee int64, extraOutputs []wire.TxOut) (string, error) {
	if err := w.requireUnlocked(); err != nil {
		return "", err
	}
	if pool == nil {
		return "", fmt.Errorf("mempool not initialized")
	}
	if amount < 0 || fee < 0 || (amount == 0 && len(extraOutputs) == 0) {
		return "", fmt.Errorf("bad amount or fee")
	}
	autoFee := fee <= 0
	if autoFee {
		fee = 0
	}
	var toScript []byte
	var err error
	if amount > 0 {
		toScript, err = destinationScript(to)
		if err != nil {
			return "", err
		}
	}
	target := amount + fee
	for _, out := range extraOutputs {
		if out.Value < mempool.DustThreshold {
			return "", fmt.Errorf("dust marker output")
		}
		target += out.Value
	}
	if !chaincfg.MoneyRange(target) {
		return "", fmt.Errorf("bad target amount")
	}
	unspent, err := w.ListUnspentForSpend(chain, pool)
	if err != nil {
		return "", err
	}
	type chosen struct {
		utxo       UTXOView
		classicKey *btcec.PrivateKey
		hybridKey  *pqc.HybridPrivateKey
	}
	selected := make([]chosen, 0)
	total := int64(0)
	w.mu.RLock()
	for _, u := range unspent {
		if u.Locked {
			continue
		}
		if u.Coinbase && u.Confirmations > 0 && u.Confirmations < int32(chaincfg.CoinbaseMaturity) {
			// Conservative wallet policy: avoid selecting immature coinbase outputs.
			continue
		}
		if from != "" && u.Address != from {
			continue
		}
		if hexKey, ok := w.keys[u.Address]; ok {
			keyBytes, err := hex.DecodeString(hexKey)
			if err != nil {
				continue
			}
			priv, _ := btcec.PrivKeyFromBytes(keyBytes)
			selected = append(selected, chosen{utxo: u, classicKey: priv})
			total += u.Value
			if total >= target {
				break
			}
			continue
		}
		if hb, ok := w.hybridKeys[u.Address]; ok {
			hk, err := pqc.HybridPrivateKeyFromBytes(hb)
			if err != nil {
				continue
			}
			selected = append(selected, chosen{utxo: u, hybridKey: hk})
			total += u.Value
			if total >= target {
				break
			}
		}
	}
	w.mu.RUnlock()
	if total < target {
		return "", fmt.Errorf("insufficient available funds: pending transactions already lock selected wallet inputs")
	}
	if autoFee {
		numOuts := len(extraOutputs)
		if amount > 0 {
			numOuts++
		}
		if total > target {
			numOuts++ // change output
		}
		estSize := 10 + len(selected)*148 + numOuts*34
		fee = (int64(estSize)*mempool.MinRelayFeePerKB + 999) / 1000
		if fee < mempool.MinRelayFeePerKB {
			fee = mempool.MinRelayFeePerKB
		}
		newTarget := amount + fee
		for _, out := range extraOutputs {
			newTarget += out.Value
		}
		if total < newTarget {
			return "", fmt.Errorf("insufficient funds for estimated fee")
		}
		target = newTarget
	}
	tx := &wire.MsgTx{Version: 1}
	for _, c := range selected {
		prevHash, err := blockchainHash(c.utxo.TxID)
		if err != nil {
			return "", err
		}
		tx.TxIn = append(tx.TxIn, wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: c.utxo.Vout},
			Sequence:         0xffffffff,
		})
	}
	if amount > 0 {
		tx.TxOut = append(tx.TxOut, wire.TxOut{Value: amount, PkScript: toScript})
	}
	tx.TxOut = append(tx.TxOut, extraOutputs...)
	change := total - target
	if change > 0 {
		changeAddr, err := w.NewAddress()
		if err != nil {
			return "", err
		}
		var changeScript []byte
		if hybridHash, err := address.DecodeHybridAddress(changeAddr); err == nil {
			changeScript, err = script.PayToHybridPubKeyHashScript(hybridHash)
			if err != nil {
				return "", err
			}
		} else {
			_, payload, err := address.DecodeBase58Check(changeAddr)
			if err != nil {
				return "", err
			}
			changeScript, err = script.PayToPubKeyHashScript(payload)
			if err != nil {
				return "", err
			}
		}
		tx.TxOut = append(tx.TxOut, wire.TxOut{Value: change, PkScript: changeScript})
	}
	for i, c := range selected {
		pkScriptHex := c.utxo.PkScriptHex
		if pkScriptHex == "" {
			entry, err := chain.UTXO(c.utxo.TxID, c.utxo.Vout)
			if err != nil {
				return "", err
			}
			pkScriptHex = entry.PkScript
		}
		prevScript, err := hex.DecodeString(pkScriptHex)
		if err != nil {
			return "", err
		}
		sighash, err := script.SignatureHash(tx, i, prevScript, script.SigHashAll)
		if err != nil {
			return "", err
		}
		var sigScript []byte
		switch {
		case script.IsPayToPubKeyHash(prevScript):
			if c.classicKey == nil {
				return "", fmt.Errorf("missing classic key for %s", c.utxo.Address)
			}
			sig := btcecdsa.Sign(c.classicKey, sighash[:]).Serialize()
			sigScript, err = script.SignatureScript(sig, c.classicKey.PubKey().SerializeCompressed())
			if err != nil {
				return "", err
			}
		case script.IsPayToHybridPubKeyHash(prevScript):
			if c.hybridKey == nil {
				return "", fmt.Errorf("missing hybrid key for %s", c.utxo.Address)
			}
			hsig, err := c.hybridKey.Sign(sighash[:])
			if err != nil {
				return "", err
			}
			sigScript, err = script.HybridSignatureScript(hsig, c.hybridKey.Public().Bytes())
			if err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("unsupported spend script for wallet input")
		}
		tx.TxIn[i].SignatureScript = sigScript
	}
	entry, err := pool.Add(chain, tx)
	if err != nil {
		return "", err
	}
	return entry.TxID, nil
}

func destinationScript(to string) ([]byte, error) {
	if toHash, derr := address.DecodeHybridAddress(to); derr == nil {
		return script.PayToHybridPubKeyHashScript(toHash)
	}
	version, toHash, err := address.DecodeBase58Check(to)
	if err != nil || version != chaincfg.PublicKeyHashVersion || len(toHash) != 20 {
		return nil, fmt.Errorf("bad destination address")
	}
	return script.PayToPubKeyHashScript(toHash)
}

func (w *Wallet) persist() error {
	w.mu.Lock()
	if w.encrypted {
		if w.locked {
			w.mu.Unlock()
			return fmt.Errorf("wallet locked")
		}
		w.refreshMetadataLocked()
		cipherHex, saltHex, nonceHex, err := encryptState(keyState{
			Keys:            w.keys,
			HybridKeys:      w.hybridKeys,
			SeedHex:         w.seedHex,
			Mnemonic:        w.mnemonic,
			NextIndex:       w.nextIndex,
			ClassicKeyCount: w.classicCount,
			HybridKeyCount:  w.hybridCount,
			HasHDSeed:       w.hasHDSeed,
		}, string(w.unlockPass))
		if err != nil {
			w.mu.Unlock()
			return err
		}
		w.cipherHex = cipherHex
		w.saltHex = saltHex
		w.nonceHex = nonceHex
		w.mu.Unlock()
		return w.persistLocked()
	}
	w.mu.Unlock()
	w.mu.RLock()
	s := stored{Keys: make(map[string]string, len(w.keys)), HybridKeys: make(map[string]pqc.HybridPrivateBytes, len(w.hybridKeys))}
	for k, v := range w.keys {
		s.Keys[k] = v
	}
	for k, v := range w.hybridKeys {
		s.HybridKeys[k] = v
	}
	s.Addresses = sortedAddressKeys(w.addresses)
	s.HybridAddresses = sortedAddressKeys(w.hybridAddrs)
	s.SeedHex = w.seedHex
	s.Mnemonic = encodeMnemonic(w.mnemonic)
	s.NextIndex = w.nextIndex
	s.ClassicKeyCount = uint32(len(w.keys))
	s.HybridKeyCount = uint32(len(w.hybridKeys))
	s.HasHDSeed = w.seedHex != ""
	w.mu.RUnlock()
	if err := os.MkdirAll(filepath.Dir(w.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(w.path, b, 0600)
}

func (w *Wallet) refreshMetadataLocked() {
	if w.addresses == nil {
		w.addresses = make(map[string]struct{})
	}
	if w.hybridAddrs == nil {
		w.hybridAddrs = make(map[string]struct{})
	}
	if len(w.keys) > 0 || !w.encrypted {
		w.addresses = make(map[string]struct{}, len(w.keys))
		for addr := range w.keys {
			w.addresses[addr] = struct{}{}
		}
	}
	if len(w.hybridKeys) > 0 || !w.encrypted {
		w.hybridAddrs = make(map[string]struct{}, len(w.hybridKeys))
		for addr := range w.hybridKeys {
			w.hybridAddrs[addr] = struct{}{}
		}
	}
	if len(w.addresses) > 0 {
		w.classicCount = uint32(len(w.addresses))
	} else {
		w.classicCount = uint32(len(w.keys))
	}
	if len(w.hybridAddrs) > 0 {
		w.hybridCount = uint32(len(w.hybridAddrs))
	} else {
		w.hybridCount = uint32(len(w.hybridKeys))
	}
	w.hasHDSeed = w.seedHex != ""
}

func (w *Wallet) loadAddressMetadataLocked(classic []string, hybrid []string) {
	if w.addresses == nil {
		w.addresses = make(map[string]struct{})
	}
	if w.hybridAddrs == nil {
		w.hybridAddrs = make(map[string]struct{})
	}
	for _, addr := range classic {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			w.addresses[addr] = struct{}{}
		}
	}
	for _, addr := range hybrid {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			w.hybridAddrs[addr] = struct{}{}
		}
	}
}

func sortedAddressKeys(in map[string]struct{}) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for addr := range in {
		if strings.TrimSpace(addr) != "" {
			out = append(out, addr)
		}
	}
	sort.Strings(out)
	return out
}

func (w *Wallet) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0700); err != nil {
		return err
	}
	w.mu.RLock()
	s := stored{
		Encrypted:       w.encrypted,
		Salt:            w.saltHex,
		Nonce:           w.nonceHex,
		Cipher:          w.cipherHex,
		Addresses:       sortedAddressKeys(w.addresses),
		HybridAddresses: sortedAddressKeys(w.hybridAddrs),
		NextIndex:       w.nextIndex,
		ClassicKeyCount: w.classicCount,
		HybridKeyCount:  w.hybridCount,
		HasHDSeed:       w.hasHDSeed,
	}
	w.mu.RUnlock()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(w.path, b, 0600)
}

func (w *Wallet) requireUnlocked() error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.encrypted && w.locked {
		return fmt.Errorf("wallet locked")
	}
	return nil
}

func (w *Wallet) VerifyPassphrase(passphrase string) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.encrypted {
		return nil
	}
	_, err := decryptState(w.cipherHex, w.saltHex, w.nonceHex, passphrase)
	return err
}

func encryptState(state keyState, passphrase string) (cipherHex string, saltHex string, nonceHex string, err error) {
	plain, err := json.Marshal(state)
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", "", "", err
	}
	passBytes := []byte(passphrase)
	defer func() {
		for i := range passBytes {
			passBytes[i] = 0
		}
	}()
	key, err := scrypt.Key(passBytes, salt, 65536, 8, 1, 32)
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, []byte("legacycoin-wallet-v1"))
	return hex.EncodeToString(ciphertext), hex.EncodeToString(salt), hex.EncodeToString(nonce), nil
}

func decryptState(cipherHex string, saltHex string, nonceHex string, passphrase string) (keyState, error) {
	var zero keyState
	ciphertext, err := hex.DecodeString(cipherHex)
	if err != nil {
		return zero, err
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return zero, err
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return zero, err
	}
	passBytes := []byte(passphrase)
	defer func() {
		for i := range passBytes {
			passBytes[i] = 0
		}
	}()
	key, err := scrypt.Key(passBytes, salt, 65536, 8, 1, 32)
	if err != nil {
		return zero, err
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return zero, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return zero, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte("legacycoin-wallet-v1"))
	if err != nil {
		return zero, fmt.Errorf("decrypt wallet: %w", err)
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	var state keyState
	if err := json.Unmarshal(plain, &state); err != nil {
		legacyKeys := make(map[string]string)
		if err2 := json.Unmarshal(plain, &legacyKeys); err2 != nil {
			return zero, err
		}
		state.Keys = legacyKeys
	}
	if state.Keys == nil {
		state.Keys = make(map[string]string)
	}
	return state, nil
}

func blockchainHash(s string) (chainhash.Hash, error) {
	return chainhash.FromString(s)
}

func (w *Wallet) deriveNextPrivateKeyLocked() (*btcec.PrivateKey, error) {
	seed, err := hex.DecodeString(w.seedHex)
	if err != nil || len(seed) == 0 {
		return nil, fmt.Errorf("invalid HD seed")
	}
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write([]byte("legacycoin-hd-v1"))
	idx := w.nextIndex
	// Safe conversion: uint32 fits in 4 bytes
	idxBytes := [4]byte{byte(idx & 0xff), byte((idx >> 8) & 0xff), byte((idx >> 16) & 0xff), byte((idx >> 24) & 0xff)}
	_, _ = mac.Write(idxBytes[:])
	sum := mac.Sum(nil)
	priv, _ := btcec.PrivKeyFromBytes(sum)
	w.nextIndex++
	return priv, nil
}

type MiningAddressInfo struct {
	Address       string `json:"address"`
	PubKeyHashHex string `json:"pubkey_hash_hex"`
}

func (w *Wallet) NewMiningAddress() (MiningAddressInfo, error) {
	addr, err := w.NewAddress()
	if err != nil {
		return MiningAddressInfo{}, err
	}
	version, payload, err := address.DecodeBase58Check(addr)
	if err != nil || version != chaincfg.PublicKeyHashVersion || len(payload) != 20 {
		return MiningAddressInfo{}, fmt.Errorf("created address is not a classic mining address")
	}
	return MiningAddressInfo{Address: addr, PubKeyHashHex: hex.EncodeToString(payload)}, nil
}
