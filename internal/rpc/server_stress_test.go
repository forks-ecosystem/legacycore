package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/config"
	"legacycoin/legacy-go/internal/mempool"
	"legacycoin/legacy-go/internal/mining"
	"legacycoin/legacy-go/internal/pow"
	"legacycoin/legacy-go/internal/storage"
	"legacycoin/legacy-go/internal/wallet"
)

func TestSustainedRPCResponsiveness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sustained RPC stress test in short mode")
	}
	chain, err := blockchain.New(chaincfg.MainNet, safetyTestHasher{}, storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := safetyTestGenesisBlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.ProcessBlock(genesis); err != nil {
		t.Fatal(err)
	}
	s := &Server{chain: chain, disableRateLimit: true}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				http.Error(w, fmt.Sprintf("internal panic: %v", v), http.StatusInternalServerError)
			}
		}()
		s.handle(w, r)
	})

	methods := []string{"help"}

	goroutinesBefore := runtime.NumGoroutine()

	totalReqs, failures, avgLat, maxLat, p95Lat, maxActive, _ := sustainedRPCStressTest(
		t, handler, 5, 5*time.Second, methods,
	)

	goroutinesAfter := runtime.NumGoroutine()
	failRate := float64(0)
	if totalReqs > 0 {
		failRate = float64(failures) / float64(totalReqs) * 100
	}

	t.Logf("RPC stress test results (5 concurrent clients, 5s)")
	t.Logf("  total requests:       %d", totalReqs)
	t.Logf("  failures/timeouts:    %d (%.1f%%)", failures, failRate)
	t.Logf("  average latency:      %v", avgLat)
	t.Logf("  maximum latency:      %v", maxLat)
	t.Logf("  p95 latency:          %v", p95Lat)
	t.Logf("  highest active reqs:  %d", maxActive)
	t.Logf("  goroutines (before):  %d", goroutinesBefore)
	t.Logf("  goroutines (after):   %d", goroutinesAfter)

	s.rpcDiagMu.Lock()
	rpcActive := s.rpcActiveRequests
	rpcTotal := s.rpcTotalCalls
	rpcDuration := s.rpcTotalDuration
	rpcTimeout := s.rpcTimeoutCount
	rpcError := s.rpcErrorCount
	s.rpcDiagMu.Unlock()
	t.Logf("  RPC diagnostics: active=%d, total=%d, duration=%.1fs, timeouts=%d, errors=%d",
		rpcActive, rpcTotal, rpcDuration.Seconds(), rpcTimeout, rpcError)

	// Verify goroutines are stable (no leaks)
	if goroutinesAfter > goroutinesBefore+10 {
		t.Fatalf("possible goroutine leak: before=%d after=%d", goroutinesBefore, goroutinesAfter)
	}
	// Accept up to 50% connection-level failures under high concurrency
	if failures > 0 && failRate > 50.0 {
		t.Fatalf("RPC stress test failure rate %.1f%% exceeds 50%% threshold", failRate)
	}
}

func sustainedRPCStressTest(
	t testing.TB,
	handler http.Handler,
	concurrency int,
	duration time.Duration,
	pollMethods []string,
) (totalRequests int64, failures int64, avgLatency time.Duration, maxLatency time.Duration, p95Latency time.Duration, maxActive int64, allLatencies []time.Duration) {
	server := httptest.NewServer(handler)
	defer server.Close()

	var (
		wg             sync.WaitGroup
		totalReqs      int64
		totalFailures  int64
		latencySum     int64
		latencyMax     int64
		activeReqCount int64
		maxActiveReqs  int64
		stopMu         sync.Mutex
		stopped        bool
		latMu          sync.Mutex
		latencies      []time.Duration
	)

	stop := func() bool {
		stopMu.Lock()
		defer stopMu.Unlock()
		return stopped
	}

	worker := func() {
		defer wg.Done()
		client := &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		}
		var methodIndex int
		for {
			if stop() {
				return
			}
			method := pollMethods[methodIndex%len(pollMethods)]
			methodIndex++
			body, _ := json.Marshal(map[string]any{
				"jsonrpc": "1.0",
				"id":      fmt.Sprintf("stress-%d", methodIndex),
				"method":  method,
				"params":  []any{},
			})
			start := time.Now()
			active := atomic.AddInt64(&activeReqCount, 1)
			for {
				cur := atomic.LoadInt64(&maxActiveReqs)
				if active <= cur {
					break
				}
				if atomic.CompareAndSwapInt64(&maxActiveReqs, cur, active) {
					break
				}
			}
			resp, err := client.Post(server.URL, "application/json", bytes.NewReader(body))
			elapsed := time.Since(start)
			atomic.AddInt64(&totalReqs, 1)
			atomic.AddInt64(&latencySum, int64(elapsed))
			atomic.AddInt64(&activeReqCount, -1)
			latMu.Lock()
			latencies = append(latencies, elapsed)
			latMu.Unlock()
			if err != nil {
				atomic.AddInt64(&totalFailures, 1)
				continue
			}
			_, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				atomic.AddInt64(&totalFailures, 1)
				continue
			}
			for {
				cur := atomic.LoadInt64(&latencyMax)
				if int64(elapsed) <= cur {
					break
				}
				if atomic.CompareAndSwapInt64(&latencyMax, cur, int64(elapsed)) {
					break
				}
			}
		}
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}

	time.Sleep(duration)
	stopMu.Lock()
	stopped = true
	stopMu.Unlock()
	wg.Wait()

	totalRequests = atomic.LoadInt64(&totalReqs)
	failures = atomic.LoadInt64(&totalFailures)
	if totalRequests > 0 {
		avgLatency = time.Duration(atomic.LoadInt64(&latencySum) / totalRequests)
	}
	maxLatency = time.Duration(atomic.LoadInt64(&latencyMax))
	maxActive = atomic.LoadInt64(&maxActiveReqs)

	// Compute p95
	latMu.Lock()
	if len(latencies) > 0 {
		sorted := make([]time.Duration, len(latencies))
		copy(sorted, latencies)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		idx := len(sorted) * 95 / 100
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		p95Latency = sorted[idx]
		allLatencies = sorted
	}
	latMu.Unlock()

	return
}

func BenchmarkRPCMethodPoll(b *testing.B) {
	chain, err := blockchain.New(chaincfg.MainNet, safetyTestHasher{}, storage.NewFileStore(b.TempDir()))
	if err != nil {
		b.Fatal(err)
	}
	genesis, err := safetyTestGenesisBlock()
	if err != nil {
		b.Fatal(err)
	}
	if err := chain.ProcessBlock(genesis); err != nil {
		b.Fatal(err)
	}
	s := &Server{chain: chain, disableRateLimit: true}
	methods := []string{
		"help",
		"getchainparams",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		method := methods[i%len(methods)]
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "1.0",
			"id":      fmt.Sprintf("bench-%d", i),
			"method":  method,
			"params":  []any{},
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		s.handle(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status=%d method=%s", rec.Code, method)
		}
	}
}

func benchMinerYield(b *testing.B, threads int, interval uint32) {
	var counter uint64
	done := make(chan struct{})
	var mu sync.Mutex
	var totalIterations int64

	b.SetParallelism(1)
	b.ResetTimer()

	var wg sync.WaitGroup
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localCount := int64(0)
			var yieldCounter uint32
			mask := interval - 1
			for {
				select {
				case <-done:
					mu.Lock()
					totalIterations += localCount
					mu.Unlock()
					return
				default:
				}
				counter++
				localCount++
				yieldCounter++
				if yieldCounter&mask == 0 {
					runtime.Gosched()
				}
			}
		}()
	}

	time.Sleep(time.Duration(b.N) * time.Microsecond)
	close(done)
	wg.Wait()

	b.ReportMetric(float64(totalIterations)/float64(b.N)*1e6, "iterations/sec")
}

func BenchmarkMinerYield1Thread(b *testing.B)   { benchMinerYield(b, 1, 64) }
func BenchmarkMinerYield4Threads(b *testing.B)  { benchMinerYield(b, 4, 64) }
func BenchmarkMinerYield10Threads(b *testing.B) { benchMinerYield(b, 10, 64) }

func BenchmarkMinerYieldOld1Thread(b *testing.B)   { benchMinerYield(b, 1, 256) }
func BenchmarkMinerYieldOld4Threads(b *testing.B)  { benchMinerYield(b, 4, 256) }
func BenchmarkMinerYieldOld10Threads(b *testing.B) { benchMinerYield(b, 10, 256) }

func TestMinerLifecycleWorkerGoroutineStability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping lifecycle stress test in short mode")
	}
	if pow.BackendName() != "cgo-c-reference" {
		t.Skipf("requires production yespower backend, got %q", pow.BackendName())
	}

	dir := t.TempDir()
	chain, err := blockchain.New(chaincfg.MainNet, pow.YespowerHasher{Personalization: chaincfg.MainNet.YespowerPers}, storage.NewFileStore(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.EnsureGenesis(); err != nil {
		t.Fatal(err)
	}

	threads := 4
	cycles := 50
	pubHash := bytes.Repeat([]byte{0x55}, 20)

	type sample struct {
		goroutines int
		started    int
		exited     int
		pending    int
	}
	samples := make([]sample, 0, cycles+1)

	var started, exited atomic.Int64
	var activeWorkers atomic.Int64

	runWorkers := func(ctx context.Context) {
		var wg sync.WaitGroup
		for worker := 0; worker < threads; worker++ {
			wg.Add(1)
			started.Add(1)
			activeWorkers.Add(1)
			go func() {
				defer wg.Done()
				defer activeWorkers.Add(-1)
				defer exited.Add(1)
				template, _, err := mining.NewBlockTemplate(chain, mempool.New(), pubHash)
				if err != nil {
					return
				}
				hasher := pow.YespowerHasher{Personalization: chaincfg.MainNet.YespowerPers}
				block := *template
				block.Transactions = template.Transactions
				var yieldCounter uint32
				for nonce := uint32(0); ; nonce++ {
					select {
					case <-ctx.Done():
						return
					default:
					}
					block.Header.Nonce = nonce
					hasher.HashHeader(block.Header)
					yieldCounter++
					if yieldCounter&0x3f == 0 {
						runtime.Gosched()
					}
					if nonce > 5000 {
						return
					}
				}
			}()
		}
		wg.Wait()
	}

	samples = append(samples, sample{
		goroutines: runtime.NumGoroutine(),
		started:    int(started.Load()),
		exited:     int(exited.Load()),
		pending:    int(activeWorkers.Load()),
	})

	for cycle := 0; cycle < cycles; cycle++ {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		runWorkers(ctx)
		cancel()
		samples = append(samples, sample{
			goroutines: runtime.NumGoroutine(),
			started:    int(started.Load()),
			exited:     int(exited.Load()),
			pending:    int(activeWorkers.Load()),
		})
	}

	time.Sleep(500 * time.Millisecond)
	time.Sleep(500 * time.Millisecond)

	endGoroutines := runtime.NumGoroutine()
	endActive := int(activeWorkers.Load())

	t.Logf("  cycles=%d  goroutines(start=%d end=%d)  workers(started=%d exited=%d pending=%d)",
		cycles, samples[0].goroutines, endGoroutines, started.Load(), exited.Load(), endActive)

	if endActive != 0 {
		t.Fatalf("all workers must exit: got %d active", endActive)
	}
	if started.Load() != exited.Load() {
		t.Fatalf("started(%d) != exited(%d) — goroutine leak", started.Load(), exited.Load())
	}

	for i, s := range samples {
		if s.pending > threads+2 {
			t.Fatalf("cycle %d: too many active workers (%d)", i, s.pending)
		}
	}
}

func TestCheckSafeToMineIdleGoroutineStability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping idle goroutine stability test in short mode")
	}
	chain, err := blockchain.New(chaincfg.MainNet, safetyTestHasher{}, storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := safetyTestGenesisBlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.ProcessBlock(genesis); err != nil {
		t.Fatal(err)
	}
	s := &Server{chain: chain}
	s.minerMu.Lock()
	s.minerActive = false
	s.minerHashing = false
	s.minerMu.Unlock()

	startG := runtime.NumGoroutine()
	maxG := startG
	callCount := 250

	cfg := config.MiningConfig{}
	for i := 0; i < callCount; i++ {
		_ = s.checkSafeToMine(s.defaultWallet(), cfg, false)
		if g := runtime.NumGoroutine(); g > maxG {
			maxG = g
		}
	}
	time.Sleep(100 * time.Millisecond)
	endG := runtime.NumGoroutine()
	t.Logf("idle checkSafeToMine: calls=%d goroutines(start=%d max=%d end=%d)", callCount, startG, maxG, endG)
	if endG > startG+50 {
		t.Fatalf("goroutine growth during idle safety checks: start=%d end=%d max=%d", startG, endG, maxG)
	}
}

func TestFullMinerStatusHandlerIdleStability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full handler stability test in short mode")
	}
	dir := t.TempDir()
	wal, err := wallet.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := blockchain.New(chaincfg.MainNet, safetyTestHasher{}, storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := safetyTestGenesisBlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.ProcessBlock(genesis); err != nil {
		t.Fatal(err)
	}
	s := &Server{chain: chain, wallet: wal}
	s.minerMu.Lock()
	s.minerActive = false
	s.minerHashing = false
	s.minerMu.Unlock()
	cfg := config.MiningConfig{}

	startG := runtime.NumGoroutine()
	maxG := startG
	callCount := 500

	var createBefore int
	if p := pprof.Lookup("threadcreate"); p != nil {
		createBefore = p.Count()
	}

	for i := 0; i < callCount; i++ {
		_ = s.minerStatus(wal, cfg, nil, false)
		if g := runtime.NumGoroutine(); g > maxG {
			maxG = g
		}
		if callCount <= 20 || i%(callCount/10) == 0 {
			createAfter := 0
			if p := pprof.Lookup("threadcreate"); p != nil {
				createAfter = p.Count()
			}
			t.Logf("  call %4d: goroutines=%d threads_created=%d", i, runtime.NumGoroutine(), createAfter)
		}
	}
	time.Sleep(200 * time.Millisecond)
	endG := runtime.NumGoroutine()

	var createAfter int
	if p := pprof.Lookup("threadcreate"); p != nil {
		createAfter = p.Count()
	}

	t.Logf("FULL minerStatus: calls=%d goroutines(start=%d max=%d end=%d) threads_created(before=%d after=%d delta=%d)",
		callCount, startG, maxG, endG, createBefore, createAfter, createAfter-createBefore)

	if endG > startG+100 {
		t.Fatalf("goroutine growth: start=%d end=%d max=%d", startG, endG, maxG)
	}
	if createAfter-createBefore > 10 {
		t.Fatalf("OS thread creation during idle handler: %d new threads (expected <=10)", createAfter-createBefore)
	}
}

func TestMinerStatusSnapshotConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping snapshot consistency test in short mode")
	}
	chain, err := blockchain.New(chaincfg.MainNet, safetyTestHasher{}, storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := safetyTestGenesisBlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.ProcessBlock(genesis); err != nil {
		t.Fatal(err)
	}
	s := &Server{chain: chain}
	w, err := wallet.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.wallet = w

	cfg := config.MiningConfig{}
	for i := 0; i < 100; i++ {
		out := s.minerStatus(w, cfg, nil, false)

		gen, _ := out["miner_state_generation"].(int64)
		consistent, _ := out["snapshot_consistent"].(bool)

		if !consistent {
			t.Logf("snapshot %d inconsistent (transitional), generation=%d", i, gen)
			continue
		}

		minerActive, _ := out["active_mining"].(bool)
		workerActive := out["yespower_worker_contexts_active"]
		cgoActive := out["yespower_cgo_calls_active"]
		wActive, _ := workerActive.(int64)

		if minerActive && wActive >= 1 && fmt.Sprint(cgoActive) == "0" {
			t.Logf("snapshot %d: active_mining=true, worker_ctx=%d, cgo=%v — workers may be starting", i, wActive, cgoActive)
		}
		if !minerActive && wActive > 0 {
			t.Fatalf("snapshot %d: active_mining=false but worker_contexts_active=%d", i, wActive)
		}
	}
}

func TestForcedPauseResumeTransitionsConsistent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping transition stress test in short mode")
	}
	if pow.BackendName() != "cgo-c-reference" {
		t.Skipf("requires production yespower backend")
	}
	chain, err := blockchain.New(chaincfg.MainNet, pow.YespowerHasher{Personalization: chaincfg.MainNet.YespowerPers}, storage.NewFileStore(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.EnsureGenesis(); err != nil {
		t.Fatal(err)
	}

	w, err := wallet.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{chain: chain, wallet: w}

	cfg := config.MiningConfig{}
	cycles := 200
	var wg sync.WaitGroup
	var mixedPaused, mixedStopped atomic.Int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < cycles; i++ {
			s.minerMu.Lock()
			s.minerActive = true
			s.minerHashing = true
			s.minerThreads = 4
			s.minerStateGen++
			s.minerMu.Unlock()
			time.Sleep(time.Millisecond)

			s.minerMu.Lock()
			s.minerActive = true
			s.minerHashing = false
			s.minerPausedReason = "peer_unsafe_test"
			s.minerStateGen++
			s.minerMu.Unlock()
			time.Sleep(time.Millisecond)

			s.minerMu.Lock()
			s.minerActive = true
			s.minerHashing = true
			s.minerPausedReason = ""
			s.minerStateGen++
			s.minerMu.Unlock()
			time.Sleep(time.Millisecond)

			s.minerMu.Lock()
			s.minerActive = false
			s.minerHashing = false
			s.minerPausedReason = ""
			s.minerStateGen++
			s.minerMu.Unlock()
			time.Sleep(time.Millisecond * 5)
		}
	}()

	for p := 0; p < 6; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < cycles; i++ {
				out := s.minerStatus(w, cfg, nil, false)
				cons, _ := out["snapshot_consistent"].(bool)
				active, _ := out["active_mining"].(bool)
				wActive := intVal(out, "yespower_worker_contexts_active")
				threads := intVal(out, "active_threads")
				cgo := intVal(out, "yespower_cgo_calls_active")

				if !cons {
					continue
				}
				if !active && wActive > 0 {
					mixedStopped.Add(1)
					t.Errorf("stopped+workers: threads=%d workers=%d cgo=%d", threads, wActive, cgo)
				}
				if active && wActive > 0 && threads == 0 {
					mixedPaused.Add(1)
					t.Errorf("paused+active-workers: threads=%d workers=%d cgo=%d", threads, wActive, cgo)
				}
				time.Sleep(time.Millisecond)
				_ = i
			}
		}()
	}
	wg.Wait()

	if mp := mixedPaused.Load(); mp > 0 {
		t.Fatalf("FAIL: %d mixed paused-plus-active-worker snapshots", mp)
	}
	if ms := mixedStopped.Load(); ms > 0 {
		t.Fatalf("FAIL: %d mixed stopped-plus-active-worker snapshots", ms)
	}
}

func intVal(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	case int:
		return int64(n)
	}
	return 0
}
