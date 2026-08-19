package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"

	"legacycoin/legacy-go/internal/blockchain"
	"legacycoin/legacy-go/internal/chaincfg"
	"legacycoin/legacy-go/internal/config"
	"legacycoin/legacy-go/internal/genesis"
	"legacycoin/legacy-go/internal/mempool"
	"legacycoin/legacy-go/internal/mining"
	"legacycoin/legacy-go/internal/node"
	"legacycoin/legacy-go/internal/pow"
	"legacycoin/legacy-go/internal/pqc"
	"legacycoin/legacy-go/internal/script"
	"legacycoin/legacy-go/internal/storage"
	"legacycoin/legacy-go/internal/wallet"
)

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = strings.ToLower(os.Args[1])
	}
	switch cmd {
	case "help", "-h", "--help":
		printUsage()
	case "params":
		printParams()
	case "genesis":
		runGenesis()
	case "pqc-demo":
		runPQCDemo()
	case "mining-address":
		runMiningAddress()
	case "mineblock":
		runMineBlock()
	case "reindex":
		runReindex()
	case "run", "server", "daemon":
		runNode()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Println(`legacycoind - Legacy Coin Go node

Usage:
  legacycoind help
  legacycoind run [-seednode] [-addnode ip:port] [-connect ip:port] [-noseednode] [-seed-peers] [-datadir path] [-wallet name] [-p2pport port] [-rpcport port]
  legacycoind params
  legacycoind genesis [threads]
  legacycoind reindex [-datadir path]
  legacycoind pqc-demo
  legacycoind mining-address
  legacycoind mineblock [threads] [pubkeyhash-hex]

RPC:
  getinfo
  gethealth
  getreadiness
  getselfcheck
  getchainparams
  getbootstrapinfo
  getnodeconfig
  getscriptstatus
  getlaunchchecklist
  getpolicy
  getlaunchstatus
  getblockcount
  getbestblockhash
  getblockhash
  getblock
  getblockheader
  getblocktemplate
  submitblock
  disconnecttip
  generate
  setupwallet
  getwalletsummary
  getminingaddress
  startminer
  stopminer
  restartminer
  setminerthreads
  doctor
  checkstorage
  reindex
  getnetworkinfo
  getpeerinfo
  getconnectioncount
  addnode
  disconnectnode
  getnetworkhashps
  getchaintiming
  getdifficulty
  getblocklocator
  gettxout
  gettxoutsetinfo
  getrawtransaction
  getaddresstxids
  getaddressutxos
  getaddressbalance
  getaddresshistory
  gettransaction
  decoderawtransaction
  getnewaddress
  getnewhybridaddress
  getrawchangeaddress
  listaddresses
  listunspent
  listtransactions
  listsinceblock
  getreceivedbyaddress
  getaddressinfo
  backupwallet
  dumpwallet
  dumpprivkey
  importprivkey
  sendtoaddress     (human LBTC amounts by default, e.g. 1 = 1 LBTC)
  sendtoaddressraw  (developer base-unit mode)
  sendfromaddress    (human LBTC amounts by default)
  sendfromaddressraw (developer base-unit mode)
  sendmany
  sendmanyraw
  settxfee
  signrawtransactionwithwallet
  tobaseunits
  frombaseunits
  encryptwallet
  walletpassphrase
  walletpassphrasechange
  walletlock
  getwalletinfo
  sethdseed
  sendrawtransaction
  getrawmempool
  getmempoolinfo
  getmempoolentry
  stop`)
}

func printParams() {
	p := chaincfg.MainNet
	fmt.Printf("coin: %s (%s)\n", p.CoinName, p.Ticker)
	fmt.Printf("p2p port: %d\n", p.DefaultPort)
	fmt.Printf("rpc port: %d\n", p.RPCPort)
	fmt.Printf("message start: % x\n", p.MessageStart)
	fmt.Printf("address version: %d\n", chaincfg.PublicKeyHashVersion)
	fmt.Printf("wif version: %d\n", chaincfg.PrivateKeyVersion)
	fmt.Printf("yespower personalization: %s\n", p.YespowerPers)
	fmt.Printf("yespower backend: %s\n", pow.BackendName())
	fmt.Printf("genesis time: %d\n", p.GenesisTime)
	fmt.Printf("genesis bits: %08x\n", p.GenesisBits)
	fmt.Printf("post-genesis launch bits: %08x\n", p.PostGenesisBits)
	fmt.Printf("genesis nonce: %d\n", p.GenesisNonce)
	fmt.Printf("genesis hash: %s\n", p.GenesisHash)
	fmt.Printf("data dir: %s\n", config.DefaultDataDir())
	fmt.Printf("config: %s\n", config.DefaultConfigPath())
	fmt.Printf("dns seeds: %s\n", strings.Join(p.DNSSeeds, ", "))
	fmt.Printf("fixed seeds: %s\n", strings.Join(p.FixedSeeds, ", "))
}

func runGenesis() {
	desc, err := genesis.Describe(chaincfg.MainNet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create genesis template: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(desc)
	threads := runtime.NumCPU()
	if len(os.Args) > 2 {
		parsed, err := strconv.Atoi(os.Args[2])
		if err != nil || parsed <= 0 {
			fmt.Fprintf(os.Stderr, "invalid thread count: %q\n", os.Args[2])
			os.Exit(2)
		}
		threads = parsed
	}
	fmt.Printf("mining genesis with %d threads...\n", threads)
	block, hash, err := genesis.MineParallel(context.Background(), chaincfg.MainNet, pow.YespowerHasher{Personalization: chaincfg.MainNet.YespowerPers}, threads, func(p genesis.MineProgress) {
		fmt.Printf("attempts=%d nonce=%d rate=%.2f h/s\n", p.Attempts, p.Nonce, p.Rate)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mine genesis: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("mined nonce=%d time=%d hash=%s\n", block.Header.Nonce, block.Header.Timestamp, hash.String())
}

func runPQCDemo() {
	key, err := pqc.GenerateHybridKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate hybrid key: %v\n", err)
		os.Exit(1)
	}
	pub := key.Public()
	msg := []byte("Legacy Coin PQC hybrid wallet demo")
	sig, err := key.Sign(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign hybrid message: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("algorithm: %s\n", pqc.HybridAlgorithm)
	fmt.Printf("address: %s\n", pub.Address())
	fmt.Printf("secp256k1 pubkey bytes: %d\n", len(pub.Bytes().SecpCompressed))
	fmt.Printf("ML-DSA-65 pubkey bytes: %d\n", len(pub.Bytes().MLDSA65))
	fmt.Printf("ECDSA signature bytes: %d\n", len(sig.ECDSADER))
	fmt.Printf("ML-DSA-65 signature bytes: %d\n", len(sig.MLDSA65))
	fmt.Printf("message hex: %s\n", hex.EncodeToString(msg))
	fmt.Printf("verified: %t\n", pub.Verify(msg, sig))
}

func runMiningAddress() {
	w, err := wallet.Open(config.DefaultDataDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "open wallet: %v\n", err)
		os.Exit(1)
	}
	info, err := w.NewMiningAddress()
	if err != nil {
		fmt.Fprintf(os.Stderr, "create wallet-owned mining address: %v\n", err)
		fmt.Fprintf(os.Stderr, "hint: if the wallet is encrypted, unlock it first with walletpassphrase over RPC or use setupwallet.\n")
		os.Exit(1)
	}
	fmt.Println("wallet_owned: true")
	fmt.Printf("address: %s\n", info.Address)
	fmt.Printf("pubkey_hash_hex: %s\n", info.PubKeyHashHex)
}

func runMineBlock() {
	threads := runtime.NumCPU()
	if len(os.Args) > 2 {
		parsed, err := strconv.Atoi(os.Args[2])
		if err != nil || parsed <= 0 {
			fmt.Fprintf(os.Stderr, "invalid thread count: %q\n", os.Args[2])
			os.Exit(2)
		}
		threads = parsed
	}
	var pubHash []byte
	if len(os.Args) > 3 {
		decoded, err := hex.DecodeString(os.Args[3])
		if err != nil || len(decoded) != 20 {
			fmt.Fprintf(os.Stderr, "invalid pubkey hash: %q\n", os.Args[3])
			os.Exit(2)
		}
		pubHash = decoded
	} else {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate mining key: %v\n", err)
			os.Exit(1)
		}
		pubHash = script.Hash160(priv.PubKey().SerializeCompressed())
		if shouldShowSecrets() {
			fmt.Printf("generated mining private key hex: %x\n", priv.Serialize())
		} else {
			fmt.Println("generated mining private key hex: <hidden> (set LEGACYCOIN_SHOW_SECRETS=1 to print)")
		}
		fmt.Printf("generated mining pubkey hash hex: %x\n", pubHash)
	}
	store := storage.NewFileStore(config.DefaultDataDir())
	chain, err := blockchain.New(chaincfg.MainNet, pow.YespowerHasher{Personalization: chaincfg.MainNet.YespowerPers}, store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create chain: %v\n", err)
		os.Exit(1)
	}
	if err := chain.EnsureGenesis(); err != nil {
		fmt.Fprintf(os.Stderr, "initialize genesis: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("mining block with %d threads...\n", threads)
	result, err := mining.MineBlock(context.Background(), chain, mempool.New(), pow.YespowerHasher{Personalization: chaincfg.MainNet.YespowerPers}, pubHash, threads, func(p mining.Progress) {
		fmt.Printf("attempts=%d nonce=%d rate=%.2f h/s\n", p.Attempts, p.Nonce, p.Rate)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mine block: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("mined height=%d nonce=%d hash=%s\n", result.Height, result.Block.Header.Nonce, result.Hash.String())
}

func applyRuntimeNodeFlags(args []string) error {
	if err := applyDataDirOverride(args); err != nil {
		return err
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		key, val, hasEq := strings.Cut(arg, "=")
		switch key {
		case "-datadir", "--datadir":
			if !hasEq {
				i++
				if i >= len(args) {
					return fmt.Errorf("%s requires value", key)
				}
				val = args[i]
			}
			_ = strings.TrimSpace(val)
		case "-addnode", "--addnode":
			if !hasEq {
				i++
				if i >= len(args) {
					return fmt.Errorf("%s requires value", key)
				}
				val = args[i]
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "addnode", val); err != nil {
				return err
			}
		case "-connect", "--connect":
			if !hasEq {
				i++
				if i >= len(args) {
					return fmt.Errorf("%s requires value", key)
				}
				val = args[i]
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "connect", val); err != nil {
				return err
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "noseednode", "true"); err != nil {
				return err
			}
		case "-noseednode", "--noseednode":
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "noseednode", "true"); err != nil {
				return err
			}
		case "-seed-peers", "--seed-peers":
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "noseednode", "false"); err != nil {
				return err
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "seed_peers", "true"); err != nil {
				return err
			}
		case "-seednode", "--seednode":
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "node_role", "seed"); err != nil {
				return err
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "seednode", "true"); err != nil {
				return err
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "seed_peers", "true"); err != nil {
				return err
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "noseednode", "false"); err != nil {
				return err
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "rpcbind", "127.0.0.1"); err != nil {
				return err
			}
		case "-p2pport", "--p2pport", "-port", "--port":
			if !hasEq {
				i++
				if i >= len(args) {
					return fmt.Errorf("%s requires value", key)
				}
				val = args[i]
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "p2pport", strings.TrimSpace(val)); err != nil {
				return err
			}
		case "-rpcport", "--rpcport":
			if !hasEq {
				i++
				if i >= len(args) {
					return fmt.Errorf("%s requires value", key)
				}
				val = args[i]
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "rpcport", strings.TrimSpace(val)); err != nil {
				return err
			}
		case "-stratum", "--stratum":
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "stratum", "true"); err != nil {
				return err
			}
		case "-stratumport", "--stratumport":
			if !hasEq {
				i++
				if i >= len(args) {
					return fmt.Errorf("%s requires value", key)
				}
				val = args[i]
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "stratum_port", strings.TrimSpace(val)); err != nil {
				return err
			}
		case "-stratumdiff", "--stratumdiff":
			if !hasEq {
				i++
				if i >= len(args) {
					return fmt.Errorf("%s requires value", key)
				}
				val = args[i]
			}
			if err := config.AppendConfigLine(config.DefaultConfigPath(), "stratum_diff", strings.TrimSpace(val)); err != nil {
				return err
			}
		case "-wallet", "--wallet":
			if !hasEq {
				i++
				if i >= len(args) {
					return fmt.Errorf("%s requires value", key)
				}
				val = args[i]
			}
			if err := os.Setenv("LEGACYCOIN_WALLET", strings.TrimSpace(val)); err != nil {
				return err
			}
		case "":
			continue
		default:
			return fmt.Errorf("unknown run flag %q", arg)
		}
	}
	return nil
}

func applyDataDirOverride(args []string) error {
	dataDir := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		key, val, hasEq := strings.Cut(arg, "=")
		if key != "-datadir" && key != "--datadir" {
			continue
		}
		if !hasEq {
			i++
			if i >= len(args) {
				return fmt.Errorf("%s requires value", key)
			}
			val = args[i]
		}
		dataDir = strings.TrimSpace(val)
	}
	if dataDir != "" {
		if err := os.Setenv("LEGACYCOIN_DATADIR", dataDir); err != nil {
			return err
		}
	}
	return nil
}

func shouldShowSecrets() bool {
	return strings.TrimSpace(os.Getenv("LEGACYCOIN_SHOW_SECRETS")) == "1"
}

func runNode() {
	if err := applyRuntimeNodeFlags(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "node flags: %v\n", err)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := node.Options{Paths: config.DefaultRuntimePaths()}
	if walletName := os.Getenv("LEGACYCOIN_WALLET"); walletName != "" {
		opts.WalletNames = []string{walletName}
	}
	n, err := node.NewWithOptions(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create node: %v\n", err)
		os.Exit(1)
	}
	if err := n.Run(ctx, cancel); err != nil {
		fmt.Fprintf(os.Stderr, "run node: %v\n", err)
		n.Chain().Close()
		os.Exit(1)
	}
	n.Chain().Close()
}

func runReindex() {
	if err := applyDataDirOverride(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "reindex flags: %v\n", err)
		os.Exit(2)
	}
	store := storage.NewFileStore(config.DefaultDataDir())
	indexCfg, err := config.LoadIndexConfig(config.DefaultConfigPath())
	if err == nil {
		store.SetIndexOptions(indexCfg.TxIndex, indexCfg.AddressIndex)
	}
	if err := store.RepairIndexes(); err != nil {
		fmt.Fprintf(os.Stderr, "reindex failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("reindex complete: active-chain indexes repaired from current tip")
}
