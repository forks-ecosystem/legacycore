package mining

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/chainhash"
	"legacycoin/legacy-go/internal/consensus"
	"legacycoin/legacy-go/internal/mempool"
	"legacycoin/legacy-go/internal/pow"
	"legacycoin/legacy-go/internal/script"
	"legacycoin/legacy-go/internal/wire"
)

var (
	lifecycleWorkersStarted  atomic.Int64
	lifecycleWorkersExited   atomic.Int64
	lifecycleSessionsStarted atomic.Int64
	lifecycleSessionsEnded   atomic.Int64
	lifecycleTCancels        atomic.Int64
	lifecycleHSCancels       atomic.Int64
	lifecyclePeerPauses      atomic.Int64
	lifecyclePeerResumes     atomic.Int64
)

// LifecycleCounters returns mining lifecycle diagnostic counters.
func LifecycleCounters() map[string]int64 {
	return map[string]int64{
		"workers_started":    lifecycleWorkersStarted.Load(),
		"workers_exited":     lifecycleWorkersExited.Load(),
		"workers_active":     lifecycleWorkersStarted.Load() - lifecycleWorkersExited.Load(),
		"sessions_started":   lifecycleSessionsStarted.Load(),
		"sessions_ended":     lifecycleSessionsEnded.Load(),
		"sessions_active":    lifecycleSessionsStarted.Load() - lifecycleSessionsEnded.Load(),
		"template_cancels":   lifecycleTCancels.Load(),
		"hard_stale_cancels": lifecycleHSCancels.Load(),
		"peer_pauses":        lifecyclePeerPauses.Load(),
		"peer_resumes":       lifecyclePeerResumes.Load(),
	}
}

type Progress struct {
	Attempts              uint64
	Nonce                 uint32
	Rate                  float64
	TemplateHeight        int32
	TemplatePrevHash      string
	TemplateAgeSeconds    float64
	TemplateFresh         bool
	TemplateRefreshDue    bool
	TemplateStaleReason   string
	TemplateRefreshReason string
}

type Result struct {
	Block  *wire.MsgBlock
	Hash   chainhash.Hash
	Height int32
}

type CoinbaseOutput struct {
	PubKeyHash []byte
	Value      int64
}

const (
	DefaultSoftTemplateRefreshAge = 2 * time.Minute
	DefaultHardTemplateStaleAge   = 2 * chaincfg.TargetSpacing
)

var ErrStaleTemplate = errors.New("stale mining template")
var ErrTemplateRefreshRequired = errors.New("mining template refresh required")

type TemplateStatus struct {
	CurrentTipHeight            int32
	CurrentTipHash              string
	ActiveTemplateHeight        int32
	ActiveTemplatePrevHash      string
	ActiveTemplateAgeSeconds    float64
	ActiveTemplateIsFresh       bool
	ActiveTemplateRefreshDue    bool
	ActiveTemplateStaleReason   string
	ActiveTemplateRefreshReason string
}

func CheckTemplateFreshness(chain *blockchain.Chain, template *wire.MsgBlock, height int32, createdAt time.Time, hardMaxAge time.Duration) TemplateStatus {
	status := TemplateStatus{
		CurrentTipHeight:            -1,
		ActiveTemplateHeight:        height,
		ActiveTemplateIsFresh:       false,
		ActiveTemplateRefreshDue:    true,
		ActiveTemplateStaleReason:   "template unavailable",
		ActiveTemplateRefreshReason: "template_stale: template unavailable",
	}
	if template == nil {
		return status
	}
	status.ActiveTemplatePrevHash = template.Header.PrevBlock.String()
	if !createdAt.IsZero() {
		status.ActiveTemplateAgeSeconds = time.Since(createdAt).Seconds()
	}
	if chain == nil {
		status.ActiveTemplateStaleReason = "chain unavailable"
		status.ActiveTemplateRefreshDue = true
		status.ActiveTemplateRefreshReason = "template_stale: chain unavailable"
		return status
	}
	tip := chain.Tip()
	if tip == nil || tip.Hash == "" {
		status.ActiveTemplateStaleReason = "chain tip unavailable"
		status.ActiveTemplateRefreshDue = true
		status.ActiveTemplateRefreshReason = "template_stale: chain tip unavailable"
		return status
	}
	status.CurrentTipHeight = tip.Height
	status.CurrentTipHash = tip.Hash
	if status.ActiveTemplatePrevHash != tip.Hash {
		status.ActiveTemplateStaleReason = "template prev hash does not match current tip"
		status.ActiveTemplateRefreshDue = true
		status.ActiveTemplateRefreshReason = "prev_hash_mismatch: template prev hash does not match current tip"
		return status
	}
	if height != tip.Height+1 {
		status.ActiveTemplateStaleReason = "template height is not current tip height + 1"
		status.ActiveTemplateRefreshDue = true
		status.ActiveTemplateRefreshReason = "height_mismatch: template height is not current tip height + 1"
		return status
	}
	if hardMaxAge <= 0 {
		hardMaxAge = DefaultHardTemplateStaleAge
	}
	if !createdAt.IsZero() && time.Since(createdAt) > hardMaxAge {
		status.ActiveTemplateStaleReason = "template age exceeds hard stale limit"
		status.ActiveTemplateRefreshDue = true
		status.ActiveTemplateRefreshReason = "hard_stale_template: template age exceeds hard stale limit"
		return status
	}
	status.ActiveTemplateIsFresh = true
	status.ActiveTemplateStaleReason = ""
	status.ActiveTemplateRefreshDue = false
	status.ActiveTemplateRefreshReason = ""
	if !createdAt.IsZero() && time.Since(createdAt) > DefaultSoftTemplateRefreshAge {
		status.ActiveTemplateRefreshDue = true
		status.ActiveTemplateRefreshReason = "template soft refresh age reached"
	}
	return status
}

func NewBlockTemplate(chain *blockchain.Chain, pool *mempool.Pool, pubKeyHash []byte) (*wire.MsgBlock, int32, error) {
	if len(pubKeyHash) != 20 {
		return nil, 0, fmt.Errorf("mining address hash must be 20 bytes")
	}
	tip := chain.Tip()
	if tip == nil || tip.Hash == "" {
		return nil, 0, fmt.Errorf("chain tip is not initialized")
	}
	prev, err := chainhash.FromString(tip.Hash)
	if err != nil {
		return nil, 0, err
	}
	bits, err := chain.NextRequiredBits()
	if err != nil {
		return nil, 0, err
	}
	height := tip.Height + 1
	totalFees := int64(0)
	selected := make([]*wire.MsgTx, 0)
	if pool != nil {
		entries := pool.Entries()
		// A mempool entry is only usable when all of its inputs still resolve,
		// either against the confirmed UTXO set or against a mempool
		// transaction already selected for this template. Entries that cannot be
		// built are skipped instead of being copied into the template verbatim:
		// a single unbuildable transaction would make the whole block
		// unminable (bad-txns-inputs-missingorspent) and stop the pool.
		included := make(map[string]struct{})
		for _, entry := range entries {
			if !templateTxIsBuildable(chain, entry.Tx, included, height) {
				continue
			}
			totalFees += entry.Fee
			selected = append(selected, entry.Tx)
			if txHash, err := entry.Tx.TxHash(); err == nil {
				included[txHash.String()] = struct{}{}
			}
		}
	}
	coinbase, err := NewCoinbaseTx(height, pubKeyHash, chaincfg.BlockSubsidy(height)+totalFees)
	if err != nil {
		return nil, 0, err
	}
	now := time.Now().Unix()
	// Safe conversion: check bounds before converting to uint32
	if now < 0 || now > 0xffffffff {
		return nil, 0, fmt.Errorf("timestamp out of range")
	}
	timestamp := uint32(now)
	if timestamp <= tip.Time {
		timestamp = tip.Time + 1
	}
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			PrevBlock: prev,
			Timestamp: timestamp,
			Bits:      bits,
		},
		Transactions: append([]*wire.MsgTx{coinbase}, selected...),
	}
	root, err := block.BuildMerkleRoot()
	if err != nil {
		return nil, 0, err
	}
	block.Header.MerkleRoot = root
	return block, height, nil
}

// templateTxIsBuildable reports whether tx can be included in a block on top of
// the current tip. Every input has to resolve to a confirmed UTXO that is
// spendable at the given height, or to a mempool transaction that was already
// selected for this template.
func templateTxIsBuildable(chain *blockchain.Chain, tx *wire.MsgTx, included map[string]struct{}, height int32) bool {
	if len(tx.TxIn) == 0 {
		return false
	}
	for _, in := range tx.TxIn {
		parentTxID := in.PreviousOutPoint.Hash.String()
		if _, ok := included[parentTxID]; ok {
			continue
		}
		prev, err := chain.UTXO(parentTxID, in.PreviousOutPoint.Index)
		if err != nil {
			return false
		}
		if prev.Coinbase && height-prev.Height < int32(chaincfg.CoinbaseMaturity) {
			return false
		}
	}
	return true
}

func NewCoinbaseTx(height int32, pubKeyHash []byte, value int64) (*wire.MsgTx, error) {
	return NewCoinbaseTxWithOutputs(height, []CoinbaseOutput{{PubKeyHash: pubKeyHash, Value: value}})
}

func NewCoinbaseTxWithOutputs(height int32, outputs []CoinbaseOutput) (*wire.MsgTx, error) {
	if len(outputs) == 0 {
		return nil, fmt.Errorf("coinbase requires at least one output")
	}
	// Safe conversion: height is always >= 0 for valid blocks, fits in uint32
	if height < 0 {
		return nil, fmt.Errorf("invalid negative height")
	}
	txOut := make([]wire.TxOut, 0, len(outputs))
	for _, output := range outputs {
		if len(output.PubKeyHash) != 20 {
			return nil, fmt.Errorf("coinbase output pubkey hash must be 20 bytes")
		}
		if output.Value < 0 {
			return nil, fmt.Errorf("coinbase output value cannot be negative")
		}
		pkScript, err := script.PayToPubKeyHashScript(output.PubKeyHash)
		if err != nil {
			return nil, err
		}
		txOut = append(txOut, wire.TxOut{
			Value:    output.Value,
			PkScript: pkScript,
		})
	}
	h := uint32(height)
	heightScript := []byte{byte(h & 0xff), byte((h >> 8) & 0xff), byte((h >> 16) & 0xff), byte((h >> 24) & 0xff)}
	sigScript := append([]byte{byte(len(heightScript))}, heightScript...)
	sigScript = append(sigScript, []byte("/Legacy-GO/")...)
	return &wire.MsgTx{
		Version: 1,
		TxIn: []wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: math.MaxUint32},
			SignatureScript:  sigScript,
			Sequence:         math.MaxUint32,
		}},
		TxOut: txOut,
	}, nil
}

func MineBlock(ctx context.Context, chain *blockchain.Chain, pool *mempool.Pool, hasher pow.Hasher, pubKeyHash []byte, workers int, progress func(Progress)) (Result, error) {
	if workers <= 0 {
		workers = 1
	}
	template, height, err := NewBlockTemplate(chain, pool, pubKeyHash)
	if err != nil {
		return Result{}, err
	}
	templateCreatedAt := time.Now()
	templateStatus := CheckTemplateFreshness(chain, template, height, templateCreatedAt, DefaultHardTemplateStaleAge)
	if !templateStatus.ActiveTemplateIsFresh {
		return Result{}, fmt.Errorf("%w: %s", ErrStaleTemplate, templateStatus.ActiveTemplateStaleReason)
	}
	if progress != nil {
		progress(Progress{
			Attempts:              0,
			Nonce:                 0,
			Rate:                  0,
			TemplateHeight:        height,
			TemplatePrevHash:      template.Header.PrevBlock.String(),
			TemplateAgeSeconds:    templateStatus.ActiveTemplateAgeSeconds,
			TemplateFresh:         templateStatus.ActiveTemplateIsFresh,
			TemplateRefreshDue:    templateStatus.ActiveTemplateRefreshDue,
			TemplateStaleReason:   templateStatus.ActiveTemplateStaleReason,
			TemplateRefreshReason: templateStatus.ActiveTemplateRefreshReason,
		})
	}
	parentCtx := ctx
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	type mineResult struct {
		block *wire.MsgBlock
		hash  chainhash.Hash
		err   error
	}
	resultc := make(chan mineResult, 1)
	var attempts atomic.Uint64
	var lastNonce atomic.Uint32
	var wg sync.WaitGroup
	start := time.Now()
	lifecycleSessionsStarted.Add(1)
	defer lifecycleSessionsEnded.Add(1)
	templatePrevHash := template.Header.PrevBlock.String()
	handleResult := func(res mineResult) (Result, error) {
		if res.err != nil {
			return Result{}, res.err
		}
		if status := CheckTemplateFreshness(chain, res.block, height, templateCreatedAt, DefaultHardTemplateStaleAge); !status.ActiveTemplateIsFresh {
			return Result{}, fmt.Errorf("%w: %s", ErrStaleTemplate, status.ActiveTemplateStaleReason)
		}
		if err := chain.ConnectBlock(res.block); err != nil {
			return Result{}, err
		}
		if pool != nil {
			pool.RemoveForBlock(res.block)
		}
		return Result{Block: res.block, Hash: res.hash, Height: height}, nil
	}

	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			defer lifecycleWorkersExited.Add(1)
			var hCtx pow.HasherContext
			if ch, ok := hasher.(pow.ContextHasher); ok {
				hCtx = ch.NewContext()
				pow.RecordWorkerContextInit()
				defer func() { pow.RecordWorkerContextFree(); hCtx.Close() }()
			}
			lifecycleWorkersStarted.Add(1)
			block := *template
			block.Transactions = template.Transactions
			step := uint32(workers)
			var yieldCounter uint32
			for nonce := uint32(worker); ; nonce += step {
				select {
				case <-ctx.Done():
					return
				default:
				}
				block.Header.Nonce = nonce
				var hash chainhash.Hash
				var err error
				if hCtx != nil {
					hash, err = pow.HashWithContext(hasher, hCtx, block.Header)
				} else {
					hash, err = hasher.HashHeader(block.Header)
				}
				if err != nil {
					select {
					case resultc <- mineResult{err: err}:
						cancel()
					default:
					}
					return
				}
				attempts.Add(1)
				lastNonce.Store(nonce)
				yieldCounter++
				if yieldCounter&0x3f == 0 {
					runtime.Gosched()
				}
				if consensus.CheckProofOfWork(hash, block.Header.Bits) == nil {
					found := block
					select {
					case resultc <- mineResult{block: &found, hash: hash}:
						cancel()
					default:
					}
					return
				}
				if nonce > math.MaxUint32-step {
					return
				}
			}
		}(worker)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	staleTicker := time.NewTicker(time.Second)
	defer staleTicker.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case res := <-resultc:
			wg.Wait()
			return handleResult(res)
		case <-ticker.C:
			if progress != nil {
				elapsed := time.Since(start).Seconds()
				count := attempts.Load()
				rate := float64(0)
				if elapsed > 0 {
					rate = float64(count) / elapsed
				}
				status := CheckTemplateFreshness(chain, template, height, templateCreatedAt, DefaultHardTemplateStaleAge)
				progress(Progress{
					Attempts:              count,
					Nonce:                 lastNonce.Load(),
					Rate:                  rate,
					TemplateHeight:        height,
					TemplatePrevHash:      templatePrevHash,
					TemplateAgeSeconds:    status.ActiveTemplateAgeSeconds,
					TemplateFresh:         status.ActiveTemplateIsFresh,
					TemplateRefreshDue:    status.ActiveTemplateRefreshDue,
					TemplateStaleReason:   status.ActiveTemplateStaleReason,
					TemplateRefreshReason: status.ActiveTemplateRefreshReason,
				})
			}
		case <-staleTicker.C:
			status := CheckTemplateFreshness(chain, template, height, templateCreatedAt, DefaultHardTemplateStaleAge)
			if !status.ActiveTemplateIsFresh {
				select {
				case resultc <- mineResult{err: fmt.Errorf("%w: %s", ErrStaleTemplate, status.ActiveTemplateStaleReason)}:
				default:
				}
				lifecycleHSCancels.Add(1)
				cancel()
			} else if status.ActiveTemplateRefreshDue {
				select {
				case resultc <- mineResult{err: fmt.Errorf("%w: %s", ErrTemplateRefreshRequired, status.ActiveTemplateRefreshReason)}:
				default:
				}
				lifecycleTCancels.Add(1)
				cancel()
			}
		case <-done:
			select {
			case res := <-resultc:
				return handleResult(res)
			default:
				return Result{}, fmt.Errorf("block nonce not found")
			}
		case <-ctx.Done():
			wg.Wait()
			if parentCtx.Err() != nil {
				return Result{}, parentCtx.Err()
			}
			select {
			case res := <-resultc:
				return handleResult(res)
			default:
				return Result{}, fmt.Errorf("miner worker epoch cancelled without result")
			}
		}
	}
}

type BenchmarkResult struct {
	DurationSeconds int64
	Threads         int
	Hashes          uint64
	HashPS          float64
	HashesPerThread float64
	LastNonce       uint32
	CurrentBits     uint32
}

func BenchmarkHashrate(ctx context.Context, chain *blockchain.Chain, pool *mempool.Pool, hasher pow.Hasher, pubKeyHash []byte, workers int, duration time.Duration) (BenchmarkResult, error) {
	if workers <= 0 {
		workers = 1
	}
	if duration <= 0 {
		duration = 10 * time.Second
	}
	template, _, err := NewBlockTemplate(chain, pool, pubKeyHash)
	if err != nil {
		return BenchmarkResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	var attempts atomic.Uint64
	var lastNonce atomic.Uint32
	var wg sync.WaitGroup
	start := time.Now()
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			defer lifecycleWorkersExited.Add(1)
			var hCtx pow.HasherContext
			if ch, ok := hasher.(pow.ContextHasher); ok {
				hCtx = ch.NewContext()
				pow.RecordWorkerContextInit()
				defer func() { pow.RecordWorkerContextFree(); hCtx.Close() }()
			}
			lifecycleWorkersStarted.Add(1)
			block := *template
			block.Transactions = template.Transactions
			step := uint32(workers)
			var yieldCounter uint32
			for nonce := uint32(worker); ; nonce += step {
				select {
				case <-ctx.Done():
					return
				default:
				}
				block.Header.Nonce = nonce
				if hCtx != nil {
					_, err := pow.HashWithContext(hasher, hCtx, block.Header)
					if err != nil {
						return
					}
				} else {
					_, err := hasher.HashHeader(block.Header)
					if err != nil {
						return
					}
				}
				attempts.Add(1)
				lastNonce.Store(nonce)
				yieldCounter++
				if yieldCounter&0xff == 0 {
					runtime.Gosched()
				}
				if nonce > math.MaxUint32-step {
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	hashes := attempts.Load()
	hps := float64(0)
	if elapsed > 0 {
		hps = float64(hashes) / elapsed
	}
	return BenchmarkResult{
		DurationSeconds: int64(elapsed),
		Threads:         workers,
		Hashes:          hashes,
		HashPS:          hps,
		HashesPerThread: hashesPerThreadMining(hps, workers),
		LastNonce:       lastNonce.Load(),
		CurrentBits:     template.Header.Bits,
	}, nil
}

func hashesPerThreadMining(total float64, threads int) float64 {
	if threads <= 0 {
		return 0
	}
	return total / float64(threads)
}
