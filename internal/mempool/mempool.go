package mempool

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/pqc"
	"legacycoin/legacy-go/internal/script"
	"legacycoin/legacy-go/internal/wire"
)

type Entry struct {
	Tx   *wire.MsgTx `json:"-"`
	TxID string      `json:"txid"`
	Fee  int64       `json:"fee"`
	Size int         `json:"size"`
}

type Pool struct {
	mu sync.RWMutex

	entries map[string]Entry
	spent   map[string]string
	parents map[string]map[string]struct{}
	childs  map[string]map[string]struct{}
	maxTx   int
	orphans map[string]*wire.MsgTx
	orphRef map[string]map[string]struct{}
	maxOrph int
}

const (
	rbfEnabled = false

	DefaultMaxTransactions       = 50_000
	MinRelayFeePerKB       int64 = 1_000
	IncrementalRelayFeeKB  int64 = 1_000
	DefaultMaxOrphans            = 100
	MaxAncestorDepth             = 25
	MaxStandardTxSize            = 100_000
	// Hybrid PQC signatures are significantly larger than legacy ECDSA scripts.
	MaxStandardSigScript       = 6_000
	DustThreshold        int64 = 546
)

var ErrOrphanTx = errors.New("orphan transaction")

func New() *Pool {
	return &Pool{
		entries: make(map[string]Entry),
		spent:   make(map[string]string),
		parents: make(map[string]map[string]struct{}),
		childs:  make(map[string]map[string]struct{}),
		maxTx:   DefaultMaxTransactions,
		orphans: make(map[string]*wire.MsgTx),
		orphRef: make(map[string]map[string]struct{}),
		maxOrph: DefaultMaxOrphans,
	}
}

func (p *Pool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

func (p *Pool) OrphanCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.orphans)
}

func (p *Pool) DependencyStats() (txWithParents int, txWithChildren int, orphanDeps int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, ps := range p.parents {
		if len(ps) > 0 {
			txWithParents++
		}
	}
	for _, cs := range p.childs {
		if len(cs) > 0 {
			txWithChildren++
		}
	}
	orphanDeps = len(p.orphRef)
	return
}

func (p *Pool) MaxAncestorDepthObserved() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	maxDepth := 0
	memo := make(map[string]int)
	for txid := range p.entries {
		d := p.ancestorDepthLocked(txid, memo)
		if d > maxDepth {
			maxDepth = d
		}
	}
	return maxDepth
}

func (p *Pool) Entries() []Entry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.entriesTopologicalLocked(0)
}

func (p *Pool) EntryDependencies(txid string) (parents []string, children []string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for parent := range p.parents[txid] {
		parents = append(parents, parent)
	}
	for child := range p.childs[txid] {
		children = append(children, child)
	}
	sort.Strings(parents)
	sort.Strings(children)
	return parents, children
}

func (p *Pool) entriesTopologicalLocked(limit int) []Entry {
	out := make([]Entry, 0, len(p.entries))
	ids := make([]string, 0, len(p.entries))
	for id := range p.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	seen := make(map[string]struct{}, len(ids))
	var visit func(string)
	visit = func(id string) {
		if _, ok := seen[id]; ok {
			return
		}
		parents := make([]string, 0, len(p.parents[id]))
		for parent := range p.parents[id] {
			if _, ok := p.entries[parent]; ok {
				parents = append(parents, parent)
			}
		}
		sort.Strings(parents)
		for _, parent := range parents {
			visit(parent)
		}
		seen[id] = struct{}{}
		if e, ok := p.entries[id]; ok {
			if limit <= 0 || len(out) < limit {
				out = append(out, e)
			}
		}
	}
	for _, id := range ids {
		visit(id)
	}
	return out
}

func (p *Pool) Transactions(limit int) []*wire.MsgTx {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entries := p.entriesTopologicalLocked(limit)
	out := make([]*wire.MsgTx, 0, limit)
	for _, e := range entries {
		out = append(out, e.Tx)
	}
	return out
}

// SpentOutpoints returns a snapshot of outpoints currently spent by mempool
// transactions, keyed with blockchain.OutPointKey(txid, vout). Wallet coin
// selection uses this to avoid building a second pending transaction from the
// same confirmed UTXO.
func (p *Pool) SpentOutpoints() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]string, len(p.spent))
	for k, v := range p.spent {
		out[k] = v
	}
	return out
}

func (p *Pool) Lookup(txid string) (*wire.MsgTx, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.entries[txid]
	if !ok {
		return nil, false
	}
	return entry.Tx, true
}

func (p *Pool) Add(chain *blockchain.Chain, tx *wire.MsgTx) (Entry, error) {
	txid, fee, missing, err := validateTransaction(chain, tx, p)
	if err != nil {
		if errors.Is(err, blockchain.ErrMissingTxOut) {
			p.addOrphan(tx, txid, missing)
			return Entry{}, ErrOrphanTx
		}
		return Entry{}, err
	}
	raw, err := tx.Bytes()
	if err != nil {
		return Entry{}, err
	}
	entry := Entry{Tx: tx, TxID: txid, Fee: fee, Size: len(raw)}
	if err := checkStandardness(tx, entry.Size); err != nil {
		return Entry{}, err
	}
	if !MeetsMinRelayFee(entry.Fee, entry.Size) {
		return Entry{}, fmt.Errorf("insufficient fee: fee=%d size=%d min_relay_fee_per_kb=%d", entry.Fee, entry.Size, MinRelayFeePerKB)
	}

	p.mu.Lock()
	p.deleteOrphanLocked(txid)
	if len(p.entries) >= p.maxTx {
		lowID, lowRate, ok := lowestEvictionCandidate(p.entries, p.childs)
		if !ok || feeRatePerKB(entry.Fee, entry.Size) <= lowRate {
			p.mu.Unlock()
			return Entry{}, fmt.Errorf("mempool full")
		}
		p.removeEntryLocked(lowID, true)
	}
	if _, ok := p.entries[txid]; ok {
		p.mu.Unlock()
		return Entry{}, fmt.Errorf("transaction already in mempool")
	}
	conflictSet := make(map[string]struct{})
	for _, in := range tx.TxIn {
		key := blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		if owner, ok := p.spent[key]; ok {
			conflictSet[owner] = struct{}{}
		}
	}
	if len(conflictSet) > 0 {
		conflicts := make([]Entry, 0, len(conflictSet))
		for id := range conflictSet {
			e, ok := p.entries[id]
			if !ok {
				p.mu.Unlock()
				return Entry{}, fmt.Errorf("input already spent by mempool transaction %s", id)
			}
			conflicts = append(conflicts, e)
		}
		if err := checkReplacementPolicy(tx, entry, conflicts, p.childs); err != nil {
			p.mu.Unlock()
			return Entry{}, err
		}
		for _, c := range conflicts {
			p.removeEntryLocked(c.TxID, false)
		}
	}
	if err := p.checkAncestorDepthLocked(tx); err != nil {
		p.mu.Unlock()
		return Entry{}, err
	}
	p.entries[txid] = entry
	if p.parents[txid] == nil {
		p.parents[txid] = make(map[string]struct{})
	}
	for _, in := range tx.TxIn {
		key := blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		p.spent[key] = txid
		parentTxID := in.PreviousOutPoint.Hash.String()
		if _, ok := p.entries[parentTxID]; ok {
			p.parents[txid][parentTxID] = struct{}{}
			if p.childs[parentTxID] == nil {
				p.childs[parentTxID] = make(map[string]struct{})
			}
			p.childs[parentTxID][txid] = struct{}{}
		}
	}
	p.mu.Unlock()
	p.promoteOrphans(chain, txid)
	return entry, nil
}

func (p *Pool) checkAncestorDepthLocked(tx *wire.MsgTx) error {
	parentTxIDs := make([]string, 0, len(tx.TxIn))
	for _, in := range tx.TxIn {
		parentTxIDs = append(parentTxIDs, in.PreviousOutPoint.Hash.String())
	}
	return p.checkAncestorDepthForParentsLocked(parentTxIDs)
}

func (p *Pool) checkAncestorDepthForParentsLocked(parentTxIDs []string) error {
	maxDepth := 0
	memo := make(map[string]int)
	for _, parentTxID := range parentTxIDs {
		if _, ok := p.entries[parentTxID]; !ok {
			continue
		}
		depth := 1 + p.ancestorDepthLocked(parentTxID, memo)
		if depth > maxDepth {
			maxDepth = depth
		}
		if maxDepth > MaxAncestorDepth {
			return fmt.Errorf("too-long-mempool-ancestor-chain: depth=%d max=%d", maxDepth, MaxAncestorDepth)
		}
	}
	return nil
}

func (p *Pool) ancestorDepthLocked(txid string, memo map[string]int) int {
	if d, ok := memo[txid]; ok {
		return d
	}
	maxParentDepth := 0
	for parent := range p.parents[txid] {
		d := 1 + p.ancestorDepthLocked(parent, memo)
		if d > maxParentDepth {
			maxParentDepth = d
		}
	}
	memo[txid] = maxParentDepth
	return maxParentDepth
}

func MeetsMinRelayFee(fee int64, size int) bool {
	if size <= 0 {
		return false
	}
	minFee := (int64(size)*MinRelayFeePerKB + 999) / 1000
	return fee >= minFee
}

func signalsOptInRBF(tx *wire.MsgTx) bool {
	for _, in := range tx.TxIn {
		if in.Sequence < 0xfffffffe {
			return true
		}
	}
	return false
}

func checkReplacementPolicy(candidateTx *wire.MsgTx, candidate Entry, conflicts []Entry, childs map[string]map[string]struct{}) error {
	if !rbfEnabled {
		return fmt.Errorf("mempool conflict: RBF replacement is disabled for this release")
	}
	if !signalsOptInRBF(candidateTx) {
		return fmt.Errorf("replacement requires opt-in rbf signaling")
	}
	var (
		totalConflictFee  int64
		totalConflictSize int
	)
	for _, c := range conflicts {
		if !signalsOptInRBF(c.Tx) {
			return fmt.Errorf("conflict %s does not signal opt-in rbf", c.TxID)
		}
		if len(childs[c.TxID]) > 0 {
			return fmt.Errorf("conflict %s has descendants; replacement not allowed", c.TxID)
		}
		totalConflictFee += c.Fee
		totalConflictSize += c.Size
	}
	if candidate.Fee <= totalConflictFee {
		return fmt.Errorf("replacement fee too low: candidate=%d conflicts=%d", candidate.Fee, totalConflictFee)
	}
	candidateRate := feeRatePerKB(candidate.Fee, candidate.Size)
	conflictRate := feeRatePerKB(totalConflictFee, totalConflictSize)
	if candidateRate <= conflictRate {
		return fmt.Errorf("replacement feerate too low: candidate=%d conflicts=%d", candidateRate, conflictRate)
	}
	minDelta := (int64(candidate.Size)*IncrementalRelayFeeKB + 999) / 1000
	if candidate.Fee-totalConflictFee < minDelta {
		return fmt.Errorf("replacement fee delta too low: delta=%d need>=%d", candidate.Fee-totalConflictFee, minDelta)
	}
	return nil
}

func checkStandardness(tx *wire.MsgTx, size int) error {
	if size <= 0 || size > MaxStandardTxSize {
		return fmt.Errorf("non-standard transaction size: %d", size)
	}
	for _, in := range tx.TxIn {
		if len(in.SignatureScript) == 0 || len(in.SignatureScript) > MaxStandardSigScript {
			return fmt.Errorf("non-standard signature script size: %d", len(in.SignatureScript))
		}
	}
	for _, out := range tx.TxOut {
		if out.Value < 0 || !chaincfg.MoneyRange(out.Value) {
			return fmt.Errorf("bad output value")
		}
		if err := script.ValidateScriptStructure(out.PkScript); err != nil {
			return fmt.Errorf("malformed scriptPubKey")
		}
		if out.Value < DustThreshold {
			return fmt.Errorf("dust output: %d", out.Value)
		}
		isStd := script.IsPayToPubKeyHash(out.PkScript) ||
			script.IsPayToPubKey(out.PkScript) ||
			script.IsPayToScriptHash(out.PkScript) ||
			script.IsPayToHybridPubKeyHash(out.PkScript)
		if !isStd && script.IsPayToMultiSig(out.PkScript) {
			if err := checkStandardBareMultiSig(out.PkScript); err == nil {
				isStd = true
			}
		}
		if !isStd {
			return fmt.Errorf("non-standard scriptPubKey")
		}
	}
	return nil
}

func feeRatePerKB(fee int64, size int) int64 {
	if size <= 0 {
		return 0
	}
	return (fee*1000 + int64(size) - 1) / int64(size)
}

func lowestFeeRateEntry(entries map[string]Entry) (string, Entry, bool) {
	var (
		lowID    string
		low      Entry
		lowRate  int64
		hasValue bool
	)
	for id, e := range entries {
		r := feeRatePerKB(e.Fee, e.Size)
		if !hasValue || r < lowRate {
			lowID, low, lowRate, hasValue = id, e, r, true
		}
	}
	return lowID, low, hasValue
}

func lowestEvictionCandidate(entries map[string]Entry, childs map[string]map[string]struct{}) (string, int64, bool) {
	var (
		lowID    string
		lowRate  int64
		hasValue bool
	)
	for id, e := range entries {
		// Prefer evicting leaves first to avoid breaking dependency chains.
		if len(childs[id]) > 0 {
			continue
		}
		r := feeRatePerKB(e.Fee, e.Size)
		if !hasValue || r < lowRate {
			lowID, lowRate, hasValue = id, r, true
		}
	}
	if hasValue {
		return lowID, lowRate, true
	}
	// Fallback: if every tx has descendants, use global lowest fee-rate tx.
	id, e, ok := lowestFeeRateEntry(entries)
	if !ok {
		return "", 0, false
	}
	return id, feeRatePerKB(e.Fee, e.Size), true
}

func (p *Pool) addOrphan(tx *wire.MsgTx, txid string, missing []string) {
	if txid == "" {
		txHash, err := tx.TxHash()
		if err != nil {
			return
		}
		txid = txHash.String()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.orphans[txid]; ok {
		return
	}
	if len(p.orphans) >= p.maxOrph {
		for id := range p.orphans {
			p.deleteOrphanLocked(id)
			break
		}
	}
	p.orphans[txid] = tx
	for _, dep := range missing {
		if p.orphRef[dep] == nil {
			p.orphRef[dep] = make(map[string]struct{})
		}
		p.orphRef[dep][txid] = struct{}{}
	}
}

func (p *Pool) deleteOrphanLocked(txid string) {
	tx, ok := p.orphans[txid]
	if !ok {
		return
	}
	delete(p.orphans, txid)
	for _, in := range tx.TxIn {
		key := blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		waiters := p.orphRef[key]
		if waiters == nil {
			continue
		}
		delete(waiters, txid)
		if len(waiters) == 0 {
			delete(p.orphRef, key)
		}
	}
}

func (p *Pool) removeEntryLocked(txid string, removeDesc bool) {
	entry, ok := p.entries[txid]
	if !ok {
		return
	}
	if removeDesc {
		for child := range p.childs[txid] {
			p.removeEntryLocked(child, true)
		}
	}
	for parent := range p.parents[txid] {
		if p.childs[parent] != nil {
			delete(p.childs[parent], txid)
			if len(p.childs[parent]) == 0 {
				delete(p.childs, parent)
			}
		}
	}
	delete(p.parents, txid)
	delete(p.childs, txid)
	for _, in := range entry.Tx.TxIn {
		key := blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		delete(p.spent, key)
	}
	delete(p.entries, txid)
}

func (p *Pool) promoteOrphans(chain *blockchain.Chain, parentTxID string) {
	queue := []string{parentTxID}
	seen := make(map[string]struct{})
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		prefix := parent + ":"
		p.mu.RLock()
		candidates := make([]string, 0)
		for dep, ids := range p.orphRef {
			if len(dep) >= len(prefix) && dep[:len(prefix)] == prefix {
				for id := range ids {
					if _, ok := seen[id]; ok {
						continue
					}
					candidates = append(candidates, id)
					seen[id] = struct{}{}
				}
			}
		}
		p.mu.RUnlock()
		for _, id := range candidates {
			p.mu.RLock()
			tx := p.orphans[id]
			p.mu.RUnlock()
			if tx == nil {
				continue
			}
			entry, err := p.Add(chain, tx)
			if err == nil {
				queue = append(queue, entry.TxID)
			}
		}
	}
}

// RemoveForBlock drops every mempool transaction the connected block made
// unbuildable: the transactions the block contains, the transactions that
// conflict with them by spending the same outpoints, and the descendants of
// all of them. Descendants must go as well, otherwise they stay in the mempool
// without a parent and every following block template is unminable.
func (p *Pool) RemoveForBlock(block *wire.MsgBlock) {
	spent := make(map[string]struct{})
	for _, tx := range block.Transactions {
		for _, in := range tx.TxIn {
			spent[blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)] = struct{}{}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tx := range block.Transactions {
		txHash, err := tx.TxHash()
		if err != nil {
			continue
		}
		p.removeEntryLocked(txHash.String(), true)
	}
	for txid, entry := range p.entries {
		for _, in := range entry.Tx.TxIn {
			key := blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
			if _, ok := spent[key]; !ok {
				continue
			}
			p.removeEntryLocked(txid, true)
			break
		}
	}
}

func validateTransaction(chain *blockchain.Chain, tx *wire.MsgTx, pool *Pool) (string, int64, []string, error) {
	if len(tx.TxIn) == 0 || len(tx.TxOut) == 0 {
		return "", 0, nil, fmt.Errorf("transaction has no inputs or outputs")
	}
	if len(tx.TxIn) == 1 && tx.TxIn[0].PreviousOutPoint.Hash.IsZero() {
		return "", 0, nil, fmt.Errorf("coinbase transaction rejected from mempool")
	}
	txHash, err := tx.TxHash()
	if err != nil {
		return "", 0, nil, err
	}
	txid := txHash.String()
	if chain.TxIndexEnabled() {
		if _, idx, _, err := chain.LookupTransactionByIndex(txid); err == nil && idx != nil {
			return "", 0, nil, fmt.Errorf("transaction already confirmed in block %s", idx.Hash)
		}
	}
	totalOut := int64(0)
	txSigOps := 0
	for _, out := range tx.TxOut {
		if !chaincfg.MoneyRange(out.Value) {
			return "", 0, nil, fmt.Errorf("bad output value")
		}
		totalOut += out.Value
		txSigOps += script.CountSigOps(out.PkScript)
		if !chaincfg.MoneyRange(totalOut) {
			return "", 0, nil, fmt.Errorf("bad output sum")
		}
	}
	totalIn := int64(0)
	seen := make(map[string]struct{})
	missing := make([]string, 0)
	nextHeight := int32(0)
	nextBlockTime := uint32(0)
	if tip := chain.Tip(); tip != nil {
		nextHeight = tip.Height + 1
		nextBlockTime = tip.Time
	}
	if !blockchain.IsFinalizedTx(tx, nextHeight, nextBlockTime) {
		return "", 0, nil, fmt.Errorf("non-final transaction")
	}
	for i, in := range tx.TxIn {
		key := blockchain.OutPointKey(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		if _, ok := seen[key]; ok {
			return "", 0, nil, fmt.Errorf("duplicate input spend")
		}
		seen[key] = struct{}{}
		pool.mu.RLock()
		owner, taken := pool.spent[key]
		pool.mu.RUnlock()
		if taken {
			return "", 0, nil, fmt.Errorf("input already spent by mempool transaction %s", owner)
		}
		prev, err := chain.UTXO(in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index)
		if err != nil {
			pool.mu.RLock()
			parent, ok := pool.entries[in.PreviousOutPoint.Hash.String()]
			pool.mu.RUnlock()
			if !ok || int(in.PreviousOutPoint.Index) >= len(parent.Tx.TxOut) {
				missing = append(missing, key)
				continue
			}
			parentOut := parent.Tx.TxOut[in.PreviousOutPoint.Index]
			prev = &blockchain.UTXOEntry{
				Key:      key,
				TxID:     in.PreviousOutPoint.Hash.String(),
				Vout:     in.PreviousOutPoint.Index,
				Value:    parentOut.Value,
				PkScript: hex.EncodeToString(parentOut.PkScript),
				Height:   nextHeight,
			}
		}
		if prev.Coinbase && nextHeight-prev.Height < int32(chaincfg.CoinbaseMaturity) {
			return "", 0, nil, fmt.Errorf("immature coinbase spend")
		}
		prevScript, err := hex.DecodeString(prev.PkScript)
		if err != nil {
			return "", 0, nil, err
		}
		ops, err := script.SigOpsForSpend(in.SignatureScript, prevScript)
		if err != nil {
			return "", 0, nil, err
		}
		txSigOps += ops
		if txSigOps > script.MaxTxSigOps {
			return "", 0, nil, fmt.Errorf("too many signature operations")
		}
		switch {
		case script.IsPayToPubKeyHash(prevScript):
			lowS, err := hasLowSSignature(in.SignatureScript)
			if err != nil {
				return "", 0, nil, err
			}
			if !lowS {
				return "", 0, nil, fmt.Errorf("non-standard high-S signature")
			}
			compressed, err := isCompressedP2PKHPubKey(in.SignatureScript)
			if err != nil {
				return "", 0, nil, err
			}
			if !compressed {
				return "", 0, nil, fmt.Errorf("non-standard uncompressed pubkey")
			}
		case script.IsPayToPubKey(prevScript):
			lowS, err := hasLowSSignature(in.SignatureScript)
			if err != nil {
				return "", 0, nil, err
			}
			if !lowS {
				return "", 0, nil, fmt.Errorf("non-standard high-S signature")
			}
		case script.IsPayToMultiSig(prevScript):
			if err := checkMultiSigPubKeysCompressed(prevScript); err != nil {
				return "", 0, nil, err
			}
			if err := checkMultiSigInputPolicy(in.SignatureScript); err != nil {
				return "", 0, nil, err
			}
		case script.IsPayToScriptHash(prevScript):
			if err := checkP2SHPolicy(in.SignatureScript); err != nil {
				return "", 0, nil, err
			}
		case script.IsPayToHybridPubKeyHash(prevScript):
			if err := checkHybridInputPolicy(in.SignatureScript); err != nil {
				return "", 0, nil, err
			}
		}
		if err := script.VerifyInput(tx, i, prevScript); err != nil {
			return "", 0, nil, err
		}
		totalIn += prev.Value
		if !chaincfg.MoneyRange(totalIn) {
			return "", 0, nil, fmt.Errorf("bad input sum")
		}
	}
	if len(missing) > 0 {
		return txid, 0, missing, blockchain.ErrMissingTxOut
	}
	if totalIn < totalOut {
		return "", 0, nil, fmt.Errorf("inputs less than outputs")
	}
	return txid, totalIn - totalOut, nil, nil
}

func isCompressedP2PKHPubKey(sigScript []byte) (bool, error) {
	r := bytes.NewReader(sigScript)
	sig, err := readScriptPushData(r)
	if err != nil || len(sig) == 0 {
		return false, fmt.Errorf("bad signature script")
	}
	pub, err := readScriptPushData(r)
	if err != nil {
		return false, fmt.Errorf("bad signature script")
	}
	if r.Len() != 0 {
		return false, fmt.Errorf("bad signature script")
	}
	if len(pub) != 33 {
		return false, nil
	}
	return pub[0] == 0x02 || pub[0] == 0x03, nil
}

func hasLowSSignature(sigScript []byte) (bool, error) {
	r := bytes.NewReader(sigScript)
	sigWithHashType, err := readScriptPushData(r)
	if err != nil || len(sigWithHashType) == 0 {
		return false, fmt.Errorf("bad signature script")
	}
	return hasLowSSignatureBytes(sigWithHashType)
}

func hasLowSSignatureBytes(sigWithHashType []byte) (bool, error) {
	if len(sigWithHashType) < 2 {
		return false, fmt.Errorf("bad signature script")
	}
	der := sigWithHashType[:len(sigWithHashType)-1]
	parsed, err := btcecdsa.ParseDERSignature(der)
	if err != nil {
		return false, err
	}
	canonical := parsed.Serialize()
	return bytes.Equal(canonical, der), nil
}

func readScriptPushData(r *bytes.Reader) ([]byte, error) {
	op, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	var size int
	switch {
	case op == script.OP_0:
		size = 0
	case op >= 1 && op <= 75:
		size = int(op)
	case op == script.OP_PUSHDATA1:
		n, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		size = int(n)
	case op == script.OP_PUSHDATA2:
		lo, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		hi, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		size = int(lo) | (int(hi) << 8)
	default:
		return nil, fmt.Errorf("unsupported push opcode")
	}
	if size > wire.MaxScriptSize || size > r.Len() {
		return nil, fmt.Errorf("bad push size")
	}
	data := make([]byte, size)
	if _, err := r.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

func parsePushOnlyScript(sigScript []byte) ([][]byte, error) {
	r := bytes.NewReader(sigScript)
	out := make([][]byte, 0)
	for r.Len() > 0 {
		d, err := readScriptPushData(r)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func checkP2SHPolicy(sigScript []byte) error {
	pushes, err := parsePushOnlyScript(sigScript)
	if err != nil || len(pushes) < 1 {
		return fmt.Errorf("bad p2sh scriptsig")
	}
	redeem := pushes[len(pushes)-1]
	if err := script.ValidateScriptStructure(redeem); err != nil {
		return fmt.Errorf("malformed redeem script")
	}
	args := pushes[:len(pushes)-1]
	switch {
	case script.IsPayToPubKeyHash(redeem):
		if len(args) != 2 {
			return fmt.Errorf("non-standard p2sh p2pkh args")
		}
		sigPush, err := encodePushData(args[0])
		if err != nil {
			return err
		}
		lowS, err := hasLowSSignature(sigPush)
		if err != nil {
			return err
		}
		if !lowS {
			return fmt.Errorf("non-standard high-S signature")
		}
		scriptSigLike, err := encodePushData(args[0])
		if err != nil {
			return err
		}
		pubPush, err := encodePushData(args[1])
		if err != nil {
			return err
		}
		scriptSigLike = append(scriptSigLike, pubPush...)
		compressed, err := isCompressedP2PKHPubKey(scriptSigLike)
		if err != nil {
			return err
		}
		if !compressed {
			return fmt.Errorf("non-standard uncompressed pubkey")
		}
	case script.IsPayToPubKey(redeem):
		if len(args) != 1 {
			return fmt.Errorf("non-standard p2sh p2pk args")
		}
		sigPush, err := encodePushData(args[0])
		if err != nil {
			return err
		}
		lowS, err := hasLowSSignature(sigPush)
		if err != nil {
			return err
		}
		if !lowS {
			return fmt.Errorf("non-standard high-S signature")
		}
	case script.IsPayToMultiSig(redeem):
		if err := checkStandardBareMultiSig(redeem); err != nil {
			return err
		}
		if err := checkMultiSigArgsLowS(args); err != nil {
			return err
		}
	default:
		return fmt.Errorf("non-standard p2sh redeem")
	}
	return nil
}

func checkMultiSigInputPolicy(sigScript []byte) error {
	pushes, err := parsePushOnlyScript(sigScript)
	if err != nil || len(pushes) < 1 {
		return fmt.Errorf("bad multisig scriptsig")
	}
	return checkMultiSigArgsLowS(pushes)
}

func checkMultiSigArgsLowS(args [][]byte) error {
	// CHECKMULTISIG dummy compatibility item.
	start := 0
	if len(args) > 0 && len(args[0]) == 0 {
		start = 1
	}
	if len(args)-start < 1 {
		return fmt.Errorf("non-standard multisig args")
	}
	for i := start; i < len(args); i++ {
		lowS, err := hasLowSSignatureBytes(args[i])
		if err != nil {
			return err
		}
		if !lowS {
			return fmt.Errorf("non-standard high-S signature")
		}
	}
	return nil
}

func checkMultiSigPubKeysCompressed(multisigScript []byte) error {
	pubKeys, ok := script.MultiSigPubKeys(multisigScript)
	if !ok {
		return fmt.Errorf("non-standard multisig template")
	}
	for _, pub := range pubKeys {
		if len(pub) != 33 {
			return fmt.Errorf("non-standard uncompressed pubkey")
		}
		if pub[0] != 0x02 && pub[0] != 0x03 {
			return fmt.Errorf("non-standard pubkey encoding")
		}
	}
	return nil
}

func checkStandardBareMultiSig(multisigScript []byte) error {
	m, n, ok := script.MultiSigParams(multisigScript)
	if !ok {
		return fmt.Errorf("non-standard multisig template")
	}
	// Conservative standardness policy.
	if m < 1 || n < 1 || n > 3 || m > n {
		return fmt.Errorf("non-standard multisig m-of-n")
	}
	return checkMultiSigPubKeysCompressed(multisigScript)
}

func checkHybridInputPolicy(sigScript []byte) error {
	pushes, err := parsePushOnlyScript(sigScript)
	if err != nil || len(pushes) != 4 {
		return fmt.Errorf("bad hybrid scriptsig")
	}
	// Enforce low-S on the classical signature field.
	lowS, err := hasLowSSignatureBytes(pushes[0])
	if err != nil {
		return err
	}
	if !lowS {
		return fmt.Errorf("non-standard high-S signature")
	}
	if len(pushes[2]) != 33 || (pushes[2][0] != 0x02 && pushes[2][0] != 0x03) {
		return fmt.Errorf("non-standard hybrid secp pubkey")
	}
	if len(pushes[1]) != pqc.MLDSASignatureSize {
		return fmt.Errorf("bad hybrid pq signature size")
	}
	if len(pushes[3]) != pqc.MLDSAPublicKeySize {
		return fmt.Errorf("bad hybrid pq pubkey size")
	}
	return nil
}

func encodePushData(data []byte) ([]byte, error) {
	if len(data) > wire.MaxScriptSize {
		return nil, fmt.Errorf("push too large")
	}
	if len(data) <= 75 {
		out := make([]byte, 1+len(data))
		out[0] = byte(len(data))
		copy(out[1:], data)
		return out, nil
	}
	if len(data) <= 255 {
		out := make([]byte, 2+len(data))
		out[0] = script.OP_PUSHDATA1
		out[1] = byte(len(data))
		copy(out[2:], data)
		return out, nil
	}
	out := make([]byte, 3+len(data))
	out[0] = script.OP_PUSHDATA2
	out[1] = byte(len(data))
	out[2] = byte(len(data) >> 8)
	copy(out[3:], data)
	return out, nil
}

func (p *Pool) Entry(txid string) (Entry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.entries[txid]
	return e, ok
}
