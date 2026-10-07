package storage

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"legacycoin/legacy-go/internal/address"
	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/chainhash"
	"legacycoin/legacy-go/internal/fsutil"
	"legacycoin/legacy-go/internal/script"
	"legacycoin/legacy-go/internal/wire"
)

type FileStore struct {
	dir                 string
	txIndexEnabled      bool
	addressIndexEnabled bool
}

type journalOp string

const (
	journalConnect    journalOp = "connect"
	journalDisconnect journalOp = "disconnect"
)

type storeJournal struct {
	Op           journalOp              `json:"op"`
	Index        blockchain.BlockIndex  `json:"index,omitempty"`
	PrevTip      *blockchain.BlockIndex `json:"prev_tip,omitempty"`
	Adds         []blockchain.UTXOEntry `json:"adds,omitempty"`
	Spends       []string               `json:"spends,omitempty"`
	SpentEntries []blockchain.UTXOEntry `json:"spent_entries,omitempty"`
	Undo         *blockchain.UndoData   `json:"undo,omitempty"`
}

type addressUTXORecord struct {
	Address     string `json:"address"`
	TxID        string `json:"txid"`
	Vout        uint32 `json:"vout"`
	Value       int64  `json:"value"`
	Height      int32  `json:"height"`
	Coinbase    bool   `json:"coinbase"`
	PkScriptHex string `json:"script_pub_key"`
}

type addressHistoryRecord struct {
	Address     string `json:"address"`
	TxID        string `json:"txid"`
	Vout        uint32 `json:"vout"`
	Value       int64  `json:"value"`
	Height      int32  `json:"height"`
	Coinbase    bool   `json:"coinbase"`
	PkScriptHex string `json:"script_pub_key"`
	Spent       bool   `json:"spent"`
	SpendTxID   string `json:"spend_txid,omitempty"`
	SpendHeight int32  `json:"spend_height,omitempty"`
}

func NewFileStore(dir string) *FileStore {
	return &FileStore{dir: dir}
}

func (s *FileStore) SetIndexOptions(txIndex bool, addressIndex bool) {
	s.txIndexEnabled = txIndex
	s.addressIndexEnabled = addressIndex
}

func (s *FileStore) TxIndexEnabled() bool {
	return s.txIndexEnabled
}

func (s *FileStore) AddressIndexEnabled() bool {
	return s.addressIndexEnabled
}

func (s *FileStore) tipPath() string {
	return filepath.Join(s.dir, "chainstate.json")
}

func (s *FileStore) journalPath() string {
	return filepath.Join(s.dir, "chainstate.journal.json")
}

func (s *FileStore) blocksDir() string {
	return filepath.Join(s.dir, "blocks")
}

func (s *FileStore) indexDir() string {
	return filepath.Join(s.dir, "index")
}

func (s *FileStore) utxoDir() string {
	return filepath.Join(s.dir, "utxo")
}

func (s *FileStore) txIndexDir() string {
	return filepath.Join(s.indexDir(), "tx")
}

func (s *FileStore) addressIndexDir() string {
	return filepath.Join(s.indexDir(), "address")
}

func (s *FileStore) undoDir() string {
	return filepath.Join(s.dir, "undo")
}

func (s *FileStore) blockPath(hash string) string {
	return filepath.Join(s.blocksDir(), hash+".blk")
}

func (s *FileStore) hashIndexPath(hash string) string {
	return filepath.Join(s.indexDir(), "hash", hash+".json")
}

func (s *FileStore) heightIndexPath(height int32) string {
	return filepath.Join(s.indexDir(), "height", strconv.FormatInt(int64(height), 10)+".json")
}

func (s *FileStore) utxoPath(key string) string {
	return filepath.Join(s.utxoDir(), strings.ReplaceAll(key, ":", "_")+".json")
}

func (s *FileStore) undoPath(hash string) string {
	return filepath.Join(s.undoDir(), hash+".json")
}

func (s *FileStore) txIndexPath(txid string) string {
	return filepath.Join(s.txIndexDir(), strings.ToLower(strings.TrimSpace(txid))+".json")
}

func (s *FileStore) addressKey(address string) string {
	repl := strings.NewReplacer(":", "_", "/", "_", "\\", "_", " ", "_")
	return repl.Replace(strings.ToLower(strings.TrimSpace(address)))
}

func (s *FileStore) addressDir(address string) string {
	return filepath.Join(s.addressIndexDir(), s.addressKey(address))
}

func (s *FileStore) addressTxIDsPath(address string) string {
	return filepath.Join(s.addressDir(address), "txids.json")
}

func (s *FileStore) addressUTXODir(address string) string {
	return filepath.Join(s.addressDir(address), "utxos")
}

func (s *FileStore) addressUTXOPath(address string, key string) string {
	key = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), ":", "_")
	return filepath.Join(s.addressUTXODir(address), key+".json")
}

func (s *FileStore) addressHistoryDir(address string) string {
	return filepath.Join(s.addressDir(address), "history")
}

func (s *FileStore) addressHistoryPath(address string, key string) string {
	key = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), ":", "_")
	return filepath.Join(s.addressHistoryDir(address), key+".json")
}

func (s *FileStore) LoadTip() (*blockchain.BlockIndex, error) {
	if err := s.recoverJournal(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.tipPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var tip blockchain.BlockIndex
	if err := json.Unmarshal(b, &tip); err != nil {
		return nil, err
	}
	return &tip, nil
}

func (s *FileStore) SaveTip(tip blockchain.BlockIndex) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(tip, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.tipPath(), b, 0600)
}

func (s *FileStore) SaveBlock(block *wire.MsgBlock, idx blockchain.BlockIndex, adds []blockchain.UTXOEntry, spends []string, spentEntries []blockchain.UTXOEntry) error {
	blockBytes, err := block.Bytes()
	if err != nil {
		return err
	}
	if err := s.ensureDirs(); err != nil {
		return err
	}

	journal := storeJournal{
		Op:           journalConnect,
		Index:        idx,
		Adds:         adds,
		Spends:       spends,
		SpentEntries: spentEntries,
	}
	if err := s.writeJournal(journal); err != nil {
		return err
	}

	if err := fsutil.WriteFileAtomic(s.blockPath(idx.Hash), blockBytes, 0600); err != nil {
		return err
	}
	indexBytes, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(s.hashIndexPath(idx.Hash), indexBytes, 0600); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(s.heightIndexPath(idx.Height), indexBytes, 0600); err != nil {
		return err
	}
	for _, key := range spends {
		if err := os.Remove(s.utxoPath(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, entry := range adds {
		if err := s.writeUTXO(entry); err != nil {
			return err
		}
	}
	undo := blockchain.UndoData{AddedKeys: make([]string, 0, len(adds)), Spent: spentEntries}
	for _, add := range adds {
		undo.AddedKeys = append(undo.AddedKeys, add.Key)
	}
	undoBytes, err := json.MarshalIndent(undo, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(s.undoPath(idx.Hash), undoBytes, 0600); err != nil {
		return err
	}
	if s.txIndexEnabled {
		if err := s.indexBlockTransactions(block, idx); err != nil {
			return err
		}
	}
	if s.addressIndexEnabled {
		if err := s.indexAddressConnect(block, idx, adds, spentEntries); err != nil {
			return err
		}
	}
	if err := s.SaveTip(idx); err != nil {
		return err
	}
	return s.clearJournal()
}

func (s *FileStore) LoadUndo(hash string) (*blockchain.UndoData, error) {
	b, err := os.ReadFile(s.undoPath(hash))
	if err != nil {
		return nil, err
	}
	var undo blockchain.UndoData
	if err := json.Unmarshal(b, &undo); err != nil {
		return nil, err
	}
	return &undo, nil
}

func (s *FileStore) DisconnectBlock(hash string, prevTip *blockchain.BlockIndex, undo blockchain.UndoData) error {
	if prevTip == nil {
		return errors.New("nil previous tip")
	}
	if err := s.ensureDirs(); err != nil {
		return err
	}
	journal := storeJournal{
		Op:      journalDisconnect,
		Index:   blockchain.BlockIndex{Hash: hash, Height: prevTip.Height + 1},
		PrevTip: prevTip,
		Undo:    &undo,
	}
	if err := s.writeJournal(journal); err != nil {
		return err
	}
	if err := s.applyDisconnect(hash, prevTip, undo); err != nil {
		return err
	}
	return s.clearJournal()
}

func (s *FileStore) LoadBlock(hash string) (*wire.MsgBlock, *blockchain.BlockIndex, error) {
	idx, err := s.loadIndex(s.hashIndexPath(hash))
	if err != nil {
		return nil, nil, err
	}
	blockBytes, err := os.ReadFile(s.blockPath(hash))
	if err != nil {
		return nil, nil, err
	}
	block, err := wire.ReadBlock(bytes.NewReader(blockBytes))
	if err != nil {
		return nil, nil, err
	}
	return block, idx, nil
}

func (s *FileStore) LoadIndexByHeight(height int32) (*blockchain.BlockIndex, error) {
	idx, err := s.loadIndex(s.heightIndexPath(height))
	if err == nil {
		return idx, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s.repairHeightIndexFromTip(height)
}

func (s *FileStore) LoadUTXO(key string) (*blockchain.UTXOEntry, error) {
	b, err := os.ReadFile(s.utxoPath(key))
	if err != nil {
		return nil, err
	}
	var entry blockchain.UTXOEntry
	if err := json.Unmarshal(b, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (s *FileStore) UTXOStats() (blockchain.UTXOStats, error) {
	var stats blockchain.UTXOStats
	utxos, err := s.ListUTXO()
	if err != nil {
		return stats, err
	}
	for _, utxo := range utxos {
		stats.Count++
		stats.Total += utxo.Value
	}
	return stats, nil
}

func (s *FileStore) ListUTXO() ([]blockchain.UTXOEntry, error) {
	entries, err := os.ReadDir(s.utxoDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]blockchain.UTXOEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.utxoDir(), entry.Name()))
		if err != nil {
			return nil, err
		}
		var utxo blockchain.UTXOEntry
		if err := json.Unmarshal(b, &utxo); err != nil {
			return nil, err
		}
		out = append(out, utxo)
	}
	return out, nil
}

func (s *FileStore) ensureDirs() error {
	for _, dir := range []string{
		s.dir,
		s.blocksDir(),
		filepath.Dir(s.hashIndexPath("placeholder")),
		filepath.Dir(s.heightIndexPath(0)),
		s.utxoDir(),
		s.undoDir(),
		s.txIndexDir(),
		s.addressIndexDir(),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

func (s *FileStore) writeUTXO(entry blockchain.UTXOEntry) error {
	b, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.utxoPath(entry.Key), b, 0600)
}

func (s *FileStore) writeJournal(j storeJournal) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.journalPath(), b, 0600)
}

func (s *FileStore) clearJournal() error {
	if err := os.Remove(s.journalPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *FileStore) recoverJournal() error {
	b, err := os.ReadFile(s.journalPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var j storeJournal
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	switch j.Op {
	case journalConnect:
		return s.rollbackConnect(j)
	case journalDisconnect:
		if j.PrevTip == nil || j.Undo == nil {
			return errors.New("invalid disconnect journal")
		}
		if err := s.applyDisconnect(j.Index.Hash, j.PrevTip, *j.Undo); err != nil {
			return err
		}
		return s.clearJournal()
	default:
		return errors.New("unknown chainstate journal operation")
	}
}

func (s *FileStore) rollbackConnect(j storeJournal) error {
	// If the tip already points to the journaled block, the operation committed;
	// only the stale journal needs to be removed.
	if tip, err := s.readTipNoRecover(); err == nil && tip != nil && tip.Hash == j.Index.Hash {
		return s.clearJournal()
	}
	for _, entry := range j.Adds {
		if err := os.Remove(s.utxoPath(entry.Key)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, entry := range j.SpentEntries {
		if err := s.writeUTXO(entry); err != nil {
			return err
		}
	}
	for _, path := range []string{
		s.blockPath(j.Index.Hash),
		s.hashIndexPath(j.Index.Hash),
		s.heightIndexPath(j.Index.Height),
		s.undoPath(j.Index.Hash),
	} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return s.clearJournal()
}

func (s *FileStore) applyDisconnect(hash string, prevTip *blockchain.BlockIndex, undo blockchain.UndoData) error {
	disconnectedBlock, _, loadErr := s.LoadBlock(hash)
	if loadErr != nil {
		disconnectedBlock = nil
	}
	for _, key := range undo.AddedKeys {
		if err := os.Remove(s.utxoPath(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, entry := range undo.Spent {
		if err := s.writeUTXO(entry); err != nil {
			return err
		}
	}
	// Keep block bytes, hash index, and undo records so disconnected blocks
	// remain available as side-chain history and can be reconsidered later.
	if err := os.Remove(s.heightIndexPath(prevTip.Height + 1)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.SaveTip(*prevTip); err != nil {
		return err
	}
	if s.txIndexEnabled || s.addressIndexEnabled {
		if disconnectedBlock != nil {
			if s.txIndexEnabled {
				for _, tx := range disconnectedBlock.Transactions {
					h, err := tx.TxHash()
					if err != nil {
						continue
					}
					_ = os.Remove(s.txIndexPath(h.String()))
				}
			}
		}
		if err := s.rebuildOptionalIndexesFromActiveTip(); err != nil {
			return err
		}
	}
	return nil
}

func (s *FileStore) readTipNoRecover() (*blockchain.BlockIndex, error) {
	b, err := os.ReadFile(s.tipPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var tip blockchain.BlockIndex
	if err := json.Unmarshal(b, &tip); err != nil {
		return nil, err
	}
	return &tip, nil
}

func (s *FileStore) repairHeightIndexFromTip(height int32) (*blockchain.BlockIndex, error) {
	if height < 0 {
		return nil, os.ErrNotExist
	}
	tip, err := s.readTipNoRecover()
	if err != nil {
		return nil, err
	}
	if tip == nil || tip.Height < height || tip.Hash == "" {
		return nil, os.ErrNotExist
	}

	curHash := tip.Hash
	for {
		block, idx, err := s.LoadBlock(curHash)
		if err != nil {
			return nil, err
		}
		idxBytes, err := json.MarshalIndent(idx, "", "  ")
		if err != nil {
			return nil, err
		}
		// Recreate active-chain height index entries as we walk back from tip.
		if err := fsutil.WriteFileAtomic(s.heightIndexPath(idx.Height), idxBytes, 0600); err != nil {
			return nil, err
		}
		if idx.Height == height {
			return idx, nil
		}
		if idx.Height == 0 {
			break
		}
		curHash = block.Header.PrevBlock.String()
	}
	return nil, os.ErrNotExist
}

func (s *FileStore) RepairHeightIndex() error {
	tip, err := s.readTipNoRecover()
	if err != nil {
		return err
	}
	if tip == nil || tip.Hash == "" {
		return nil
	}
	_, err = s.repairHeightIndexFromTip(0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *FileStore) RepairIndexes() error {
	if err := s.RepairHeightIndex(); err != nil {
		return err
	}
	if err := s.rebuildHashIndexFromActiveTip(); err != nil {
		return err
	}
	// The UTXO set is not an optional index: gettxout, getaddressutxo and
	// gettxoutsetinfo all read it, so a partial or stale set silently answers
	// "block not found" for outputs that are in fact unspent. It is rebuilt from
	// the same block data the other indexes use.
	if err := s.rebuildUTXOFromActiveTip(); err != nil {
		return err
	}
	return s.rebuildOptionalIndexesFromActiveTip()
}

func (s *FileStore) rebuildHashIndexFromActiveTip() error {
	tip, err := s.readTipNoRecover()
	if err != nil {
		return err
	}
	if tip == nil || tip.Hash == "" || tip.Height < 0 {
		return nil
	}
	for h := int32(0); h <= tip.Height; h++ {
		idx, err := s.LoadIndexByHeight(h)
		if err != nil {
			return err
		}
		b, err := json.MarshalIndent(idx, "", "  ")
		if err != nil {
			return err
		}
		if err := fsutil.WriteFileAtomic(s.hashIndexPath(idx.Hash), b, 0600); err != nil {
			return err
		}
	}
	return nil
}

func (s *FileStore) rebuildUTXOFromActiveTip() error {
	tip, err := s.readTipNoRecover()
	if err != nil {
		return err
	}
	if tip == nil || tip.Hash == "" || tip.Height < 0 {
		return nil
	}
	if err := os.RemoveAll(s.utxoDir()); err != nil {
		return err
	}
	if err := os.MkdirAll(s.utxoDir(), 0700); err != nil {
		return err
	}
	for h := int32(0); h <= tip.Height; h++ {
		idx, err := s.LoadIndexByHeight(h)
		if err != nil {
			return err
		}
		block, _, err := s.LoadBlock(idx.Hash)
		if err != nil {
			return err
		}
		// Mirror connectBlockLocked: an output that is spent again inside the
		// same block is never written, so keep the per-block pending set and
		// only flush what survives the whole block. Spends of earlier blocks are
		// removed from disk immediately.
		pending := make(map[string]blockchain.UTXOEntry)
		for txIndex, tx := range block.Transactions {
			for _, in := range tx.TxIn {
				key := blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
				if _, fromSameBlock := pending[key]; fromSameBlock {
					delete(pending, key)
					continue
				}
				if err := os.Remove(s.utxoPath(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			txHash, err := tx.TxHash()
			if err != nil {
				return err
			}
			txID := txHash.String()
			for vout, out := range tx.TxOut {
				key := blockchain.OutPointKey(txID, uint32(vout))
				pending[key] = blockchain.UTXOEntry{
					Key:      key,
					TxID:     txID,
					Vout:     uint32(vout),
					Value:    out.Value,
					PkScript: hex.EncodeToString(out.PkScript),
					Height:   idx.Height,
					Coinbase: txIndex == 0,
				}
			}
		}
		for _, entry := range pending {
			if err := s.writeUTXO(entry); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeOutputAddressFromScript(pkScript []byte) string {
	switch {
	case script.IsPayToPubKeyHash(pkScript) && len(pkScript) >= 23:
		return address.EncodeBase58Check(chaincfg.PublicKeyHashVersion, pkScript[3:23])
	case script.IsPayToHybridPubKeyHash(pkScript) && len(pkScript) >= 23:
		return address.HybridPrefix + address.EncodeBase58Check(address.HybridVersion, pkScript[3:23])
	default:
		return ""
	}
}

func (s *FileStore) indexBlockTransactions(block *wire.MsgBlock, idx blockchain.BlockIndex) error {
	for txPos, tx := range block.Transactions {
		h, err := tx.TxHash()
		if err != nil {
			return err
		}
		rec := blockchain.TxIndexRecord{
			TxID:        h.String(),
			BlockHash:   idx.Hash,
			BlockHeight: idx.Height,
			TxPosition:  txPos,
		}
		b, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		if err := fsutil.WriteFileAtomic(s.txIndexPath(rec.TxID), b, 0600); err != nil {
			return err
		}
	}
	return nil
}

func (s *FileStore) readAddressTxIDs(address string) ([]string, error) {
	b, err := os.ReadFile(s.addressTxIDsPath(address))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	var txids []string
	if err := json.Unmarshal(b, &txids); err != nil {
		return nil, err
	}
	return txids, nil
}

func (s *FileStore) writeAddressTxIDs(address string, txids []string) error {
	if err := os.MkdirAll(s.addressDir(address), 0700); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(txids))
	out := make([]string, 0, len(txids))
	for _, txid := range txids {
		txid = strings.ToLower(strings.TrimSpace(txid))
		if txid == "" {
			continue
		}
		if _, ok := seen[txid]; ok {
			continue
		}
		seen[txid] = struct{}{}
		out = append(out, txid)
	}
	sort.Strings(out)
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.addressTxIDsPath(address), b, 0600)
}

func (s *FileStore) addAddressTxID(address string, txid string) error {
	txids, err := s.readAddressTxIDs(address)
	if err != nil {
		return err
	}
	txids = append(txids, txid)
	return s.writeAddressTxIDs(address, txids)
}

func (s *FileStore) writeAddressUTXO(rec addressUTXORecord) error {
	if err := os.MkdirAll(s.addressUTXODir(rec.Address), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.addressUTXOPath(rec.Address, blockchain.OutPointKey(rec.TxID, rec.Vout)), b, 0600)
}

func (s *FileStore) removeAddressUTXO(address string, txid string, vout uint32) error {
	path := s.addressUTXOPath(address, blockchain.OutPointKey(txid, vout))
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *FileStore) readAddressHistory(address string, txid string, vout uint32) (addressHistoryRecord, error) {
	var rec addressHistoryRecord
	b, err := os.ReadFile(s.addressHistoryPath(address, blockchain.OutPointKey(txid, vout)))
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, err
	}
	return rec, nil
}

func (s *FileStore) writeAddressHistory(rec addressHistoryRecord) error {
	if err := os.MkdirAll(s.addressHistoryDir(rec.Address), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.addressHistoryPath(rec.Address, blockchain.OutPointKey(rec.TxID, rec.Vout)), b, 0600)
}

func (s *FileStore) markAddressOutputSpent(address string, txid string, vout uint32, spendTxID string, spendHeight int32) error {
	rec, err := s.readAddressHistory(address, txid, vout)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	rec.Spent = true
	rec.SpendTxID = strings.ToLower(strings.TrimSpace(spendTxID))
	rec.SpendHeight = spendHeight
	return s.writeAddressHistory(rec)
}

func (s *FileStore) indexAddressConnect(block *wire.MsgBlock, idx blockchain.BlockIndex, adds []blockchain.UTXOEntry, spent []blockchain.UTXOEntry) error {
	spentByOutpoint := make(map[string]string)
	for _, tx := range block.Transactions {
		txHash, err := tx.TxHash()
		if err != nil {
			continue
		}
		isCoinbase := len(tx.TxIn) > 0 && tx.TxIn[0].PreviousOutPoint.Hash == (chainhash.Hash{}) && tx.TxIn[0].PreviousOutPoint.Index == ^uint32(0)
		if isCoinbase {
			continue
		}
		for _, in := range tx.TxIn {
			key := blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
			spentByOutpoint[key] = txHash.String()
		}
	}

	for _, sp := range spent {
		raw, err := hex.DecodeString(sp.PkScript)
		if err != nil {
			continue
		}
		addr := decodeOutputAddressFromScript(raw)
		if addr == "" {
			continue
		}
		if err := s.removeAddressUTXO(addr, sp.TxID, sp.Vout); err != nil {
			return err
		}
		outpoint := blockchain.OutPointKey(sp.TxID, sp.Vout)
		spendTxID := spentByOutpoint[outpoint]
		if spendTxID != "" {
			if err := s.addAddressTxID(addr, spendTxID); err != nil {
				return err
			}
		}
		if err := s.markAddressOutputSpent(addr, sp.TxID, sp.Vout, spendTxID, idx.Height); err != nil {
			return err
		}
	}
	for _, add := range adds {
		raw, err := hex.DecodeString(add.PkScript)
		if err != nil {
			continue
		}
		addr := decodeOutputAddressFromScript(raw)
		if addr == "" {
			continue
		}
		if err := s.addAddressTxID(addr, add.TxID); err != nil {
			return err
		}
		rec := addressUTXORecord{
			Address:     addr,
			TxID:        add.TxID,
			Vout:        add.Vout,
			Value:       add.Value,
			Height:      add.Height,
			Coinbase:    add.Coinbase,
			PkScriptHex: add.PkScript,
		}
		if err := s.writeAddressUTXO(rec); err != nil {
			return err
		}
		h := addressHistoryRecord{
			Address:     addr,
			TxID:        add.TxID,
			Vout:        add.Vout,
			Value:       add.Value,
			Height:      add.Height,
			Coinbase:    add.Coinbase,
			PkScriptHex: add.PkScript,
			Spent:       false,
			SpendTxID:   "",
			SpendHeight: 0,
		}
		if err := s.writeAddressHistory(h); err != nil {
			return err
		}
	}
	// Ensure outputs to indexed addresses are tracked even if the wallet UTXO set
	// did not retain them (e.g. same-block spends).
	for _, tx := range block.Transactions {
		txHash, err := tx.TxHash()
		if err != nil {
			continue
		}
		for _, out := range tx.TxOut {
			addr := decodeOutputAddressFromScript(out.PkScript)
			if addr == "" {
				continue
			}
			if err := s.addAddressTxID(addr, txHash.String()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *FileStore) rebuildOptionalIndexesFromActiveTip() error {
	if !s.txIndexEnabled && !s.addressIndexEnabled {
		return nil
	}
	tip, err := s.readTipNoRecover()
	if err != nil {
		return err
	}
	if tip == nil || tip.Hash == "" || tip.Height < 0 {
		return nil
	}
	if s.txIndexEnabled {
		if err := os.RemoveAll(s.txIndexDir()); err != nil {
			return err
		}
		if err := os.MkdirAll(s.txIndexDir(), 0700); err != nil {
			return err
		}
	}
	if s.addressIndexEnabled {
		if err := os.RemoveAll(s.addressIndexDir()); err != nil {
			return err
		}
		if err := os.MkdirAll(s.addressIndexDir(), 0700); err != nil {
			return err
		}
	}
	for h := int32(0); h <= tip.Height; h++ {
		idx, err := s.LoadIndexByHeight(h)
		if err != nil {
			return err
		}
		block, _, err := s.LoadBlock(idx.Hash)
		if err != nil {
			return err
		}
		if s.txIndexEnabled {
			if err := s.indexBlockTransactions(block, *idx); err != nil {
				return err
			}
		}
		if s.addressIndexEnabled {
			adds := make([]blockchain.UTXOEntry, 0)
			spent := make([]blockchain.UTXOEntry, 0)
			undo, _ := s.LoadUndo(idx.Hash)
			if undo != nil {
				spent = append(spent, undo.Spent...)
			}
			for _, tx := range block.Transactions {
				txHash, err := tx.TxHash()
				if err != nil {
					continue
				}
				for vout, out := range tx.TxOut {
					adds = append(adds, blockchain.UTXOEntry{
						Key:      blockchain.OutPointKey(txHash.String(), uint32(vout)),
						TxID:     txHash.String(),
						Vout:     uint32(vout),
						Value:    out.Value,
						PkScript: hex.EncodeToString(out.PkScript),
						Height:   idx.Height,
						Coinbase: len(tx.TxIn) > 0 && tx.TxIn[0].PreviousOutPoint.Hash == (chainhash.Hash{}) && tx.TxIn[0].PreviousOutPoint.Index == ^uint32(0),
					})
				}
			}
			if err := s.indexAddressConnect(block, *idx, adds, spent); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *FileStore) LookupTxIndex(txid string) (*blockchain.TxIndexRecord, error) {
	if !s.txIndexEnabled {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(s.txIndexPath(txid))
	if err != nil {
		return nil, err
	}
	var rec blockchain.TxIndexRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *FileStore) AddressTxIDs(address string) ([]string, error) {
	if !s.addressIndexEnabled {
		return nil, os.ErrNotExist
	}
	return s.readAddressTxIDs(address)
}

func (s *FileStore) AddressUTXOs(address string) ([]blockchain.AddressIndexUTXO, error) {
	if !s.addressIndexEnabled {
		return nil, os.ErrNotExist
	}
	entries, err := os.ReadDir(s.addressUTXODir(address))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []blockchain.AddressIndexUTXO{}, nil
		}
		return nil, err
	}
	out := make([]blockchain.AddressIndexUTXO, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.addressUTXODir(address), entry.Name()))
		if err != nil {
			return nil, err
		}
		var rec addressUTXORecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return nil, err
		}
		out = append(out, blockchain.AddressIndexUTXO{
			Address:     rec.Address,
			TxID:        rec.TxID,
			Vout:        rec.Vout,
			Value:       rec.Value,
			Height:      rec.Height,
			Coinbase:    rec.Coinbase,
			PkScriptHex: rec.PkScriptHex,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Height == out[j].Height {
			if out[i].TxID == out[j].TxID {
				return out[i].Vout < out[j].Vout
			}
			return out[i].TxID < out[j].TxID
		}
		return out[i].Height < out[j].Height
	})
	return out, nil
}

func (s *FileStore) AddressBalance(address string) (int64, int64, error) {
	utxos, err := s.AddressUTXOs(address)
	if err != nil {
		return 0, 0, err
	}
	var confirmed int64
	var total int64
	for _, u := range utxos {
		total += u.Value
		confirmed += u.Value
	}
	return confirmed, total, nil
}

func (s *FileStore) AddressHistory(address string) ([]blockchain.AddressHistoryEntry, error) {
	if !s.addressIndexEnabled {
		return nil, os.ErrNotExist
	}
	entries, err := os.ReadDir(s.addressHistoryDir(address))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []blockchain.AddressHistoryEntry{}, nil
		}
		return nil, err
	}
	out := make([]blockchain.AddressHistoryEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.addressHistoryDir(address), entry.Name()))
		if err != nil {
			return nil, err
		}
		var rec addressHistoryRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return nil, err
		}
		out = append(out, blockchain.AddressHistoryEntry{
			Address:     rec.Address,
			TxID:        rec.TxID,
			Vout:        rec.Vout,
			Value:       rec.Value,
			Height:      rec.Height,
			Coinbase:    rec.Coinbase,
			PkScriptHex: rec.PkScriptHex,
			Spent:       rec.Spent,
			SpendTxID:   rec.SpendTxID,
			SpendHeight: rec.SpendHeight,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Height == out[j].Height {
			if out[i].TxID == out[j].TxID {
				return out[i].Vout < out[j].Vout
			}
			return out[i].TxID < out[j].TxID
		}
		return out[i].Height < out[j].Height
	})
	return out, nil
}

func (s *FileStore) loadIndex(path string) (*blockchain.BlockIndex, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var idx blockchain.BlockIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, err
	}
	return &idx, nil
}
