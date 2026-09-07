/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loxinet

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
extern int lxb_trace_enable(void);
extern int lxb_trace_disable(void);
extern int lxb_trace_is_enabled(void);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	apiserver "github.com/loxilb-io/loxilb/api"
	k8s "github.com/loxilb-io/loxilb/api/k8s"
	nlp "github.com/loxilb-io/loxilb/api/loxinlp"
	prometheus "github.com/loxilb-io/loxilb/api/prometheus"
	"github.com/loxilb-io/loxilb/api/restapi/handler"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/aikey"
	"github.com/loxilb-io/loxilb/pkg/llamafirewall"
	"github.com/loxilb-io/loxilb/pkg/logrotate"
	"github.com/loxilb-io/loxilb/pkg/loxilog"
	"github.com/loxilb-io/loxilb/pkg/presidio"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
	"github.com/loxilb-io/loxilb/pkg/user"
	utils "github.com/loxilb-io/loxilb/pkg/utils"
	tk "github.com/loxilb-io/loxilib"
	logrus "github.com/sirupsen/logrus"
)

// string constant representing root security zone
const (
	RootZone = "root"
)

// constants
const (
	LoxinetTiVal   = 10
	GoBGPInitTiVal = 5
	KAInitTiVal    = 5
)

// utility variables
const (
	MkfsScript     = "/usr/local/sbin/mkllb_bpffs"
	BpfFsCheckFile = "/opt/loxilb/dp/bpf/intf_map"
	MkMountCG2     = "/usr/local/sbin/mkllb_cgroup 1"
)

type loxiNetH struct {
	dpEbpf             *DpEbpfH
	dp                 *DpH
	zn                 *ZoneH
	zr                 *Zone
	mtx                sync.RWMutex
	ticker             *time.Ticker
	tDone              chan bool
	sigCh              chan os.Signal
	wg                 sync.WaitGroup
	bgp                *GoBgpH
	sumDis             bool
	pProbe             bool
	has                *CIStateH
	logger             *tk.Logger
	ready              bool
	self               int
	rssEn              bool
	eHooks             bool
	lSockPolicy        bool
	sockMapEn          bool
	ktlsEn             bool
	cloudLabel         string
	cloudHook          CloudHookInterface
	cloudInst          string
	disBPF             bool
	pFile              *os.File
	UserService        *user.UserService
	OauthUserService   *user.OauthUserService
	securityRateConfig cmn.SecurityRateConfig // Unified security rate limiting configuration (P0-5 + P0-6)

	// AIKeyService is the data-plane API-key store. It is a separate object
	// from UserService on purpose: the two planes share no store, no cache and
	// no enable switch. Nil means no key store is configured.
	AIKeyService *aikey.Service

	// HTTP/HTTPS Protocol Analyzer (Distributed Tracing)
	tracingEnabled bool           // Whether tracing is enabled
	ringConsumer   *RingConsumer  // Ring buffer consumer
	spanAssembler  *SpanAssembler // Span correlation engine
	otlpExporter   *OTLPExporter  // OTLP exporter with circuit breaker

	// L4 Connection Tracing (TCP/SCTP)
	l4TracingEnabled bool             // Whether L4 tracing is enabled
	l4TracingMtx     sync.Mutex       // Protects lazy initialization of L4 tracing
	l4RingConsumer   *L4RingConsumer  // L4 ring buffer consumer
	l4SpanAssembler  *L4SpanAssembler // L4 span correlation engine

	// IPsec strongSwan Integration (TASK_18)
	ipsec *IPsecH // IPsec handler for tunnel management

	// DPU Plugin Manager
	dpuMgr *DpuManager

	// shutdown context threaded into long-lived
	// goroutines so the workers stage of the layered shutdown sequencer
	// can broadcast cancellation in O(1) before the per-stage
	// 1s deadline starts. Constructed in loxiNetInit BEFORE any goroutine
	// is spawned. Cancelled exactly once by the SIGINT handler.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	// shutdownInProgress is set on the FIRST
	// SIGINT/SIGTERM via atomic.Swap(true). The second signal sees true
	// and escalates to a bounded eBPF cleanup + os.Exit(1), beating the
	// go-swagger apiserver's "Server already shutting down" guard race
	// (D-B1-02).
	shutdownInProgress atomic.Bool

	// sockproxy HA state-sync coordinator. Initialised lazily on
	// first CGO emit-event arrival (via NewSockproxySync), but stored here
	// so cluster.go BFDSessionNotify can reach it. nil-safe at start so the
	// existing CT-sync hook continues to work unchanged.
	sockproxySync *SockproxySync
}

// NodeWalker - an implementation of node walker interface
func (mh *loxiNetH) NodeWalker(b string) {
	tk.LogIt(tk.LogDebug, "%s\n", b)
}

// PrometheusInit - Initialize the Prometheus subsystem
func (mh *loxiNetH) PrometheusInit() error {
	prometheus.PrometheusRegister(NetAPIInit(opts.Opts.BgpPeerMode))
	prometheus.Init()
	return nil
}

// ParamSet - Set Loxinet Params
func (mh *loxiNetH) ParamSet(param cmn.ParamMod) (int, error) {
	logLevel := LogString2Level(param.LogLevel)

	if mh.logger != nil {
		mh.logger.LogItSetLevel(logLevel)
	}

	DpEbpfSetLogLevel(logLevel)

	return 0, nil
}

// ParamGet - Get Loxinet Params
func (mh *loxiNetH) ParamGet(param *cmn.ParamMod) (int, error) {
	logLevel := "n/a"
	switch mh.logger.CurrLogLevel {
	case tk.LogTrace:
		logLevel = "trace"
	case tk.LogDebug:
		logLevel = "debug"
	case tk.LogInfo:
		logLevel = "info"
	case tk.LogError:
		logLevel = "error"
	case tk.LogNotice:
		logLevel = "notice"
	case tk.LogWarning:
		logLevel = "warning"
	case tk.LogAlert:
		logLevel = "alert"
	case tk.LogCritical:
		logLevel = "critical"
	case tk.LogEmerg:
		logLevel = "emergency"
	default:
		param.LogLevel = logLevel
		return -1, errors.New("unknown log level")
	}

	param.LogLevel = logLevel
	return 0, nil
}

// loxiNetTicker - this ticker routine runs every LOXINET_TIVAL seconds
func loxiNetTicker(bgpPeerMode bool) {

	defer func() {
		if e := recover(); e != nil {
			tk.LogIt(tk.LogCritical, "%s: %s", e, debug.Stack())
		}
		if mh.dp != nil {
			mh.dp.DpHooks.DpEbpfUnInit()
		}
		os.Exit(1)
	}()

	for {
		select {
		case <-mh.tDone:
			return
		case sig := <-mh.sigCh:
			if sig == syscall.SIGCHLD {
				var ws syscall.WaitStatus
				var ru syscall.Rusage
				wpid := 1
				try := 0
				for wpid >= 0 && try < 100 {
					wpid, _ = syscall.Wait4(-1, &ws, syscall.WNOHANG, &ru)
					try++
				}
			} else if sig == syscall.SIGHUP {
				tk.LogIt(tk.LogCritical, "SIGHUP received\n")
				pprof.StopCPUProfile()
			} else if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				// layered shutdown sequencer
				// (D-B1-01) replaces the legacy "TODO - More subsystem
				// cleanup TBD" block. Each stage is bounded by its own
				// context.WithTimeout via runShutdownStage so the wedge
				// documented in EVIDENCE cannot recur. Second
				// SIGINT escalates to a bounded eBPF cleanup + os.Exit(1)
				// (D-B1-02), beating the go-swagger apiserver's
				// "Server already shutting down" guard race via the
				// atomic.Swap precedence rule documented at the top of
				// shutdown_sequencer.go.
				if mh.shutdownInProgress.Swap(true) {
					// SECOND signal — escalate.
					tk.LogIt(tk.LogCritical, "[shutdown] hard exit requested -- cleaning eBPF then exiting\n")
					ebpfCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
					done := make(chan struct{})
					go func() {
						if mh.dpEbpf != nil {
							mh.dpEbpf.DpEbpfUnInit()
						}
						close(done)
					}()
					select {
					case <-done:
					case <-ebpfCtx.Done():
						tk.LogIt(tk.LogCritical, "[shutdown] eBPF cleanup timed out -- orphaned TC progs may remain\n")
					}
					cancel()
					os.Exit(1)
				}

				tk.LogIt(tk.LogCritical, "Shutdown on sig %v\n", sig)
				// Shutdown tracing subsystem first
				mh.shutdownTracing()

				// D-B1-04 cancel-before-destroy: broadcast cancellation
				// to all ctx-aware workers BEFORE the staged sequencer
				// runs, so the workers stage's 1s deadline is the time
				// for them to *drain*, not the time for the cancel
				// message to propagate.
				if mh.shutdownCancel != nil {
					mh.shutdownCancel()
				}

				runShutdownStage("rest", 1*time.Second, shutdownRESTFn)
				runShutdownStage("workers", 1*time.Second, shutdownWorkersFn)
				runShutdownStage("doca", 2*time.Second, shutdownDocaFn)
				runShutdownStage("ebpf", 1*time.Second, shutdownEbpfFn)

				// Existing post-stage cleanup that is NOT in any stage
				// (preserved verbatim from the pre- handler).
				mh.zr.Rules.RuleDestructAll()
				if mh.cloudHook != nil {
					// Cleanup any cloud resources
					ciState, _ := mh.has.CIStateGetInst(cmn.CIDefault)
					if ciState == cmn.CIMasterStateString {
						bfdSessions, err := mh.has.CIBFDSessionGet()
						if err == nil {
							cleanCloudResources := true
							for _, bfdSession := range bfdSessions {
								if bfdSession.State != "BFDDown" {
									cleanCloudResources = false
									break
								}
							}
							if cleanCloudResources {
								mh.cloudHook.CloudDestroyVIPNetWork()
							}
						}
					}
				}
				mh.has.CIDestroy()
				// Release tokenizer backend resources (Rust CGO objects must be freed before exit)
				KvTokenizerClose()
				// Flush and close structured logger last (captures shutdown log messages from other subsystems)
				loxilog.Close()
				apiserver.ApiServerShutOk()
				return
			}
		case t := <-mh.ticker.C:
			tk.LogIt(-1, "Tick at %v\n", t)
			if !bgpPeerMode {
				// Do any housekeeping activities for security zones
				mh.zn.ZoneTicker()
				mh.has.CITicker()
				if opts.Opts.UserServiceEnable {
					mh.UserService.UserServiceTicker()
				}
				// Independent of the management plane: the key store has its
				// own connection, and a service that started degraded heals
				// here whatever --userservice is set to.
				mh.AIKeyService.Ticker()
			}
		}
	}
}

var mh loxiNetH

func sysctlInit() {
	utils.WriteFile("/proc/sys/net/ipv4/conf/all/arp_accept", "1")
	utils.WriteFile("/proc/sys/net/ipv4/conf/default/arp_accept", "1")
	utils.WriteFile("/proc/sys/net/ipv4/ip_forward", "1")
}

func sysctlPostInit() {
	utils.WriteFile("/proc/sys/net/ipv4/conf/llb0/rp_filter", "0")
}

func loxiNetInit() {
	var rpcMode int

	// Initialize logger and specify the log file.
	// Fall back to /tmp if /var/log/ is not writable (e.g. running tests as
	// a non-root user on the CI/testbed).
	logDir := "/var/log/"
	if f, err := os.OpenFile(logDir+".loxilb_write_test", os.O_CREATE|os.O_WRONLY, 0600); err == nil {
		f.Close()
		os.Remove(logDir + ".loxilb_write_test")
	} else {
		logDir = "/tmp/"
	}
	logfile := fmt.Sprintf("%sloxilb%s.log", logDir, os.Getenv("HOSTNAME"))
	logLevel := LogString2Level(opts.Opts.LogLevel)
	mh.logger = tk.LogItInit(logfile, logLevel, true)

	// Size-rotate every log this process writes — unrotated (default
	// debug-level) log files are a disk-starvation risk in production.
	// loxilib's LogItInit opens a plain append-only file, so re-point all
	// level writers at a rotating writer for the same path (the fd LogItInit
	// opened stays unused for the process lifetime).
	rotCfg := logrotate.Config{
		MaxSizeMB:  opts.Opts.LogMaxSize,
		MaxBackups: opts.Opts.LogMaxBackups,
		MaxAgeDays: opts.Opts.LogMaxAge,
		Compress:   !opts.Opts.LogNoCompress,
	}
	if rw, err := logrotate.New(logfile, rotCfg); err == nil {
		for _, lg := range []*log.Logger{
			mh.logger.LogItEmer, mh.logger.LogItAlert, mh.logger.LogItCrit,
			mh.logger.LogItErr, mh.logger.LogItWarn, mh.logger.LogItNotice,
			mh.logger.LogItInfo, mh.logger.LogItDebug, mh.logger.LogItTrace,
		} {
			lg.SetOutput(rw)
		}
		// The AI subsystems (KV attest/subscriber, adapters) log through
		// sirupsen/logrus, which writes to stderr only. Under any launcher
		// that discards the process's stderr (docker exec -dt, detached
		// supervisors) those lines vanish entirely. Tee them into the same
		// rotated file the level writers use so /var/log/loxilb<host>.log
		// carries the whole story regardless of how stderr is wired.
		logrus.SetOutput(io.MultiWriter(os.Stderr, rw))
	} else {
		tk.LogIt(tk.LogWarning, "log rotation disabled for %s: %v\n", logfile, err)
	}
	// The eBPF data-plane C library appends to /var/log/loxilbdp.log with a
	// FILE* we cannot wrap — rotate it copy-truncate style from a sweeper.
	logrotate.StartSweeper("/var/log/loxilbdp.log", rotCfg, time.Minute)

	// Initialize structured audit logging (coexists with tk.LogIt during-4 migration)
	loxilogCfg := loxilog.Config{
		LogDir:    opts.Opts.LogDir,
		LogFormat: opts.Opts.LogFormat,
		LogLevel:  opts.Opts.LogLevel,
		Rotate:    rotCfg,
	}
	if err := loxilog.Init(loxilogCfg); err != nil {
		tk.LogIt(tk.LogWarning, "loxilog init failed: %v, continuing with tk.LogIt only\n", err)
	}

	// Initialize Presidio PII detection configuration manager
	if _, err := presidio.NewPresidioConfigManager(); err != nil {
		tk.LogIt(tk.LogWarning, "[Presidio] Failed to initialize config manager: %v\n", err)
	}

	// Initialize LlamaFirewall AI security configuration manager
	if _, err := llamafirewall.NewLlamaFirewallConfigManager(); err != nil {
		tk.LogIt(tk.LogWarning, "[LlamaFirewall] Failed to initialize config manager: %v\n", err)
	}

	// Register HuggingFace tokenizer backend for KV cache Tier-1.5 routing (Phase K).
	// Reads tokenizer.json from /etc/loxilb/tokenizers/<model-slug>/tokenizer.json.
	// Without this, llb_ai_kv_tokenize always returns -1 and Tier-1.5 is permanently disabled.
	KvRegisterTokenizerBackend(NewHFTokenizerBackend())

	// Publish the model-profile registry if one is staged. A broken registry
	// keeps the gateway up on legacy profile-less behavior (rules that
	// REQUIRE a profile fail closed at admission instead), but the failure
	// must be loud: silent profile loss would silently change how requests
	// tokenize.
	if err := KvProfileRegistryLoad(); err != nil {
		tk.LogIt(tk.LogError, "[KV] model-profile registry load failed (profiles unavailable): %v\n", err)
	}

	// Register the compiled engine-contract registry as the process's
	// contract source: strict KV-exact rules resolve their engine-contract
	// reference against it (before this, every strict admission failed
	// closed on the nil source). A broken registration keeps that
	// fail-closed posture — loudly.
	if err := KvContractSourceInit(); err != nil {
		tk.LogIt(tk.LogError, "[KV] engine-contract source init failed (strict rules stay closed): %v\n", err)
	}

	kaArgs := KAString2Mode(opts.Opts.Ka, opts.Opts.ClusterInterface)
	clusterMode := false
	if opts.Opts.ClusterNodes != "none" {
		clusterMode = true
	}
	// DPU offload needs CT map tracing (have_mtrace) to observe
	// established flows and trigger DOCA shadow offload
	dpuMtraceEn := opts.Opts.DpuPlugin != ""

	// Initialize the clustering subsystem
	if mh.has = CIInit(kaArgs); mh.has == nil {
		tk.LogIt(tk.LogError, "cluster init failed\n")
		os.Exit(1)
	}

	// It is important to make sure loxilb's eBPF filesystem
	// is in place and mounted to make sure maps are pinned properly
	if !opts.Opts.ProxyModeOnly {
		if !utils.FileExists(BpfFsCheckFile) {
			if utils.FileExists(MkfsScript) {
				RunCommand(MkfsScript, true)
			}

		}
		utils.MkTunFsIfNotExist()
		SysctlInit()
	}

	mh.self = opts.Opts.ClusterSelf
	mh.rssEn = opts.Opts.RssEnable
	mh.eHooks = opts.Opts.EgrHooks
	mh.sumDis = opts.Opts.CRC32SumDisable
	mh.pProbe = opts.Opts.PassiveEPProbe
	mh.lSockPolicy = opts.Opts.LocalSockPolicy
	mh.sockMapEn = opts.Opts.SockMapSupport
	mh.ktlsEn = opts.Opts.KtlsSupport
	mh.cloudLabel = opts.Opts.Cloud
	mh.cloudHook = CloudHookNew(mh.cloudLabel)
	mh.cloudInst = opts.Opts.CloudInstance
	mh.disBPF = opts.Opts.ProxyModeOnly
	mh.sigCh = make(chan os.Signal, 5)
	// B1 D-B1-02: Loxinet owns the SIGINT escalation path; the apiserver's
	// internal handleInterrupt may also fire but loxinet's os.Exit(1) wins
	// via shutdownInProgress.Swap (see). The signal.Notify
	// below MUST stay before apiserver.RunAPIServer so loxinet has its
	// channel registered first.
	signal.Notify(mh.sigCh, os.Interrupt, syscall.SIGCHLD, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	// shutdown ctx, constructed BEFORE any
	// long-lived goroutine is spawned so all of them can be wired to it.
	mh.shutdownCtx, mh.shutdownCancel = context.WithCancel(context.Background())

	// global AI-controller applier start — env-gated
	// (LOXILB_AI_CTRL_ADDR unset ⇒ returns immediately: no goroutine, no
	// dial, no allocation — G3). GLOBAL, not per-rule (contrast the
	// rules.go:3423 per-rule scraper): one controller stream per loxilb;
	// snapshots carry service identity for the bridge walk.
	AiCtrlApplierStart(mh.shutdownCtx)

	if mh.cloudHook != nil {
		err := mh.cloudHook.CloudAPIInit(opts.Opts.CloudCIDRBlock)
		if err != nil {
			os.Exit(1)
		}
	}

	// Check if profiling is enabled
	if opts.Opts.CPUProfile != "none" {
		var err error
		mh.pFile, err = os.Create(opts.Opts.CPUProfile)
		if err != nil {
			tk.LogIt(tk.LogNotice, "profile file create failed\n")
			return
		}
		err = pprof.StartCPUProfile(mh.pFile)
		if err != nil {
			tk.LogIt(tk.LogNotice, "CPU profiler start failed\n")
			return
		}
	}
	if opts.Opts.RPC == "netrpc" {
		rpcMode = RPCTypeNetRPC
	} else {
		rpcMode = RPCTypeGRPC
	}

	if !opts.Opts.BgpPeerMode {
		if mh.lSockPolicy {
			RunCommand(MkMountCG2, false)
		}

		// CRITICAL FIX: Clean up stale ring buffer files before eBPF initialization
		// This prevents SIGBUS crashes when restarting loxilb after crash/kill
		if os.Getenv("LOXILB_HTTP_TRACE_ENABLED") == "1" {
			if cleaned, err := CleanupStaleRingFiles(); err != nil {
				tk.LogIt(tk.LogWarning, "[Tracing] Ring file cleanup failed: %v\n", err)
			} else if cleaned > 0 {
				tk.LogIt(tk.LogInfo, "[Tracing] Cleaned up %d stale ring file(s)\n", cleaned)
			}

			// Also clean up stale body files (from previous crashes)
			if cleaned, err := CleanupStaleBodyFiles(); err != nil {
				tk.LogIt(tk.LogWarning, "[Tracing] Body file cleanup failed: %v\n", err)
			} else if cleaned > 0 {
				tk.LogIt(tk.LogInfo, "[Tracing] Cleaned up %d stale body file(s)\n", cleaned)
			}
		}

		// Initialize the ebpf datapath subsystem
		mh.dpEbpf = DpEbpfInit(clusterMode, mh.rssEn, mh.eHooks, mh.lSockPolicy, mh.sockMapEn, mh.ktlsEn, mh.self, mh.disBPF, logLevel, dpuMtraceEn)
		mh.dp = DpBrokerInit(mh.dpEbpf, rpcMode)

		// Initialize DPU plugin manager (: resilient lifecycle)
		mh.dpuMgr = DpuManagerInit()
		// P49-R1: register through adapter so DpuManager satisfies
		// the extended handler.DpuDebugProvider interface (AllFdbHwStats /
		// AllRouteHwStats / AllAclHwStats return handler-package entry types
		// while pkg/loxinet keeps its internal slice types).
		handler.SetDpuDebugProvider(newDpuDebugProviderAdapter(mh.dpuMgr))

		// register KV inventory Admin API provider
		// (serves GET /netlox/v1/config/ai/kv/inventory for the parity harness)
		RegisterKvInventoryProvider()
		if opts.Opts.DpuPlugin == "doca-bf2" {
			if bf2, ok := docaInitAndRegister(); ok {
				go docaHeartbeatWatchdog(bf2.Bridge())
			}
			// On failure, docaInitAndRegister now starts its own re-init goroutine (CGO-05)
		}

		// Initialize the security zone subsystem
		mh.zn = ZoneInit()

		// Add a root zone by default
		mh.zn.ZoneAdd(RootZone)
		mh.zr, _ = mh.zn.Zonefind(RootZone)
		if mh.zr == nil {
			tk.LogIt(tk.LogError, "root zone not found\n")
			return
		}

		if clusterMode {
			if opts.Opts.Bgp {
				tk.LogIt(tk.LogInfo, "init-wait cluster mode\n")
				time.Sleep(10 * time.Second)
			}
			// Add cluster nodes if specified
			cNodes := strings.Split(opts.Opts.ClusterNodes, ",")
			for _, cNode := range cNodes {
				addr := net.ParseIP(cNode)
				if addr == nil {
					continue
				}
				mh.has.ClusterNodeAdd(cmn.ClusterNodeMod{Addr: addr})
			}
		}

		// : wire the sockproxy HA state-sync coordinator
		// into the production startup path. Without this assignment the
		// gate at cluster.go:548 (`if mh.sockproxySync != nil`) is always
		// false, so the entire HA push surface is dead code and the
		// Phase L AWS testbed measured 0/100 restore_rate for L1/L2.
		//
		// The peersFn closure composes two authorities per CONTEXT :
		//   1. Role gate: walk mh.has.ClusterMap; return nil unless at
		//      least one ClusterInstance is in MASTER state. A backup
		//      loxilb has nothing to push.
		//   2. Peer enumeration: take mh.dp.SyncMtx.RLock and copy
		// mh.dp.Peers into a fresh slice (: slice headers
		//      are not atomic; SyncMtx is the established read lock for
		//      mh.dp.Peers writers — see DpWorkOnPeerOp at dpbroker.go:
		// 86).
		//
		// The assignment runs unconditionally (NOT only when clusterMode
		// is true) so a single-node loxilb without cluster mode still
		// initialises a no-op SockproxySync — peersFn returns nil
		// (no MASTER instance in an empty ClusterMap), drainLoop runs,
		// per-peer consumers never spawn. No panic, no startup-order risk.
		mh.sockproxySync = NewSockproxySync()
		peersFn := func() []DpPeer {
			// Role gate: only the MASTER pushes (CONTEXT). Mirrors
			// the master-count idiom at sockproxy_sync.go:344-358
			// — same lock discipline (mh.mtx.RLock + range ClusterMap +
			// CIMasterStateString check) but sets a boolean instead of
			// counting instances. mh.has nil-guard matches OnStateChange.
			isMaster := false
			if mh.has != nil {
				mh.mtx.RLock()
				for _, ci := range mh.has.ClusterMap {
					if ci.StateStr == cmn.CIMasterStateString {
						isMaster = true
						break
					}
				}
				mh.mtx.RUnlock()
			}
			if !isMaster {
				return nil
			}
			// Peer enumeration under the canonical mh.dp.SyncMtx RLock.
			// Writer is DpWorkOnPeerOp which takes the exclusive Lock
			// (see DpXsyncRPCReset at dpbroker.go:55 for the
			// mirroring read pattern). copy into a fresh slice so the
			// returned value cannot race with a subsequent peer add/
			// remove after RUnlock.
			mh.dp.SyncMtx.RLock()
			defer mh.dp.SyncMtx.RUnlock()
			out := make([]DpPeer, len(mh.dp.Peers))
			copy(out, mh.dp.Peers)
			return out
		}
		mh.sockproxySync.Start(peersFn)

		// Bug Fix: CT-sync uses net/rpc and sets
		// pe.Client = *rpc.Client via DpXsyncRPC→RPCHooks.RPCConnect.
		// The sockproxy xSync consumerLoop must NOT share that field —
		// its clientFn type-asserts to gRPCClient which always fails
		// against *rpc.Client → nil → all batches silently dropped.
		// Fix: dial a dedicated gRPC connection via DialXSyncGRPC and
		// cache the XSyncClient in spClients (separate from pe.Client).
		mh.sockproxySync.SetConnectFn(func(peerKey string) {
			xclient, err := DialXSyncGRPC(peerKey)
			if err != nil {
				tk.LogIt(tk.LogWarning, "[XSYNC] gRPC dial sockproxy to %s failed: %v\n", peerKey, err)
				return
			}
			mh.sockproxySync.StoreGRPCClient(peerKey, xclient)
			tk.LogIt(tk.LogInfo, "[XSYNC] gRPCConnect sockproxy to %s ok\n", peerKey)
		})
	} else {
		// If bgp peer mode is enabled then bgp flag has to be set by default
		opts.Opts.Bgp = true
		//opts.Opts.NoNlp = true
		opts.Opts.Prometheus = false
	}

	// Initialize goBgp client
	if opts.Opts.Bgp {
		mh.bgp = GoBgpInit(opts.Opts.BgpPeerMode)
	}

	// + -05 (NLP-vs-Init startup race): bulk-load
	// loxilb-owned IPs into the SelfIPCache BEFORE the REST API and NLP
	// subscriber come online. Otherwise, an NLP NetAddrDel arriving in the
	// window between NlpInit and Init would call Del on an empty cache
	// (silent no-op) and the subsequent Init would re-add that IP from a
	// stale kernel snapshot, resurrecting an entry the operator just
	// deleted. AddrList is a synchronous netlink RTM_GETADDR call with no
	// dependency on either subsystem (verified: self_ip_cache.go Init only
	// uses netlink.AddrList; no mh.zr / mh.has / apiserver / NLP state is
	// touched). Non-fatal: cache will still populate via the
	// NetAddrAdd/NetAddrDel hooks (apiclient.go) if Init fails.
	if err := SelfIPCache.Init(); err != nil {
		tk.LogIt(tk.LogWarning, "self-ip cache init failed: %v\n", err)
	}

	// The node secret for snapshot secret-value encryption must exist
	// before any capture or restore runs (the boot replay included):
	// without it, captures fail closed rather than ever persisting a
	// plaintext secret. Init failure is loud but non-fatal -- a node that
	// cannot provision the secret still serves traffic; only snapshot
	// operations touching secret values will error.
	if err := snapshot.InitNodeSecret(opts.Opts.ConfigPath); err != nil {
		tk.LogIt(tk.LogError, "snapshot node secret init failed: %v\n", err)
	}

	// The boot-config gate: mutating REST calls are held (503) while the
	// boot config replay is pending, because a write racing the replay can
	// make the restore fail on state it did not create, roll back the whole
	// boot config, and then auto-persist the empty result. Decide BEFORE
	// the API server starts: only a node that actually has something to
	// replay (snapshot.json or legacy *.txt) gets a freeze window -- a
	// fresh node, or a mode that never replays (no-NLP, BGP-peer), accepts
	// writes immediately. If a client write lands on a fresh node and
	// auto-persists just before LbSessionGet stats the disk, the replay it
	// triggers re-applies the same items and skips them as idempotent
	// duplicates -- benign by design.
	if opts.Opts.NoNlp || opts.Opts.BgpPeerMode || !nlp.BootReplayExpected() {
		snapshot.MarkBootConfigSettled()
	}

	// Re-register managed TLS material from disk BEFORE the API server
	// (and with it the boot snapshot replay) starts: a reboot used to
	// orphan every uploaded certificate -- the SNI store came up empty
	// while the material sat on disk, invisible to and undeletable via
	// the API. Needs the sockproxy datapath (skip on BGP-only nodes).
	if !opts.Opts.BgpPeerMode && mh.dpEbpf != nil {
		handler.CertBootReconcile()
	}

	// Initialize and spawn the api server subsystem
	if !opts.Opts.NoAPI {
		apiserver.RegisterAPIHooks(NetAPIInit(opts.Opts.BgpPeerMode))
		go apiserver.RunAPIServer()
		apiserver.WaitAPIServerReady()
	}

	// Initialize the nlp subsystem
	if !opts.Opts.NoNlp {
		nlp.NlpRegister(NetAPIInit(opts.Opts.BgpPeerMode))
		nlp.NlpInit(opts.Opts.BgpPeerMode, opts.Opts.BlackList, opts.Opts.WhiteList, opts.Opts.IPVSCompat)
	}

	// Initialize the k8s subsystem
	if opts.Opts.K8sAPI != "none" {
		k8s.K8sApiInit(opts.Opts.K8sAPI, NetAPIInit(opts.Opts.BgpPeerMode))
	}

	// Initialize the Prometheus subsystem
	if opts.Opts.Prometheus {
		mh.PrometheusInit()
	}

	if !opts.Opts.BgpPeerMode {
		// Spawn CI maintenance application
		mh.has.CISpawn()
	}

	// Initialize the user service subsystem
	if opts.Opts.UserServiceEnable {
		tk.LogIt(tk.LogInfo, "User service enabled\n")
		// The first dial completes in the background: against a store that is
		// down it blocks for over a minute, and everything ordered below —
		// including the boot snapshot restore waiting on those subsystems —
		// must not inherit the management store's outage. Until the dial
		// lands, auth requests get 503 and the datapath fails closed; the
		// ticker keeps reconnecting on persistent failure.
		mh.UserService = user.NewUserService()
		// A session revoked here — by deleting the user, or by changing their
		// password or role — must stop authenticating on the peers before
		// their cached copy expires. Without this the revocation stops at this
		// gateway's edge and a deleted administrator keeps administering
		// elsewhere. The message names the management plane, so a receiver
		// touches only the management cache.
		if coord := mh.sockproxySync; coord != nil {
			mh.UserService.SetTokenSink(func(hashes []string) {
				coord.BroadcastTokenInvalidation(hashes)
			})
		}
	}

	// Initialize the data-plane API-key store. Deliberately parallel to the
	// user service rather than nested inside it: availability of the key store
	// follows from its own connection options, and enforcement follows from
	// per-service policy. Neither is a function of --userservice.
	if opts.Opts.AIKeyDBHost != "" {
		// Publish the service before dialling, not after. Connect retries with
		// a doubling backoff and takes tens of seconds against a store that is
		// down; assigning the pointer only afterwards leaves every reader
		// seeing nil for the whole of that window, and nil means "no store was
		// configured" — the opposite of what is true here. The visible cost of
		// getting this backwards is a key API that tells an operator they
		// configured nothing while it is busy dialling what they configured.
		svc := aikey.New()
		mh.AIKeyService = svc
		// The dial runs in the background for the same reason the service is
		// published before it: Connect retries with a doubling backoff and
		// takes tens of seconds against a store that is down, and blocking
		// init here handed that outage to every subsystem ordered below —
		// observed as the boot snapshot restore giving up (quarantining the
		// data plane's persisted config) while init was still dialling.
		go func() {
			if akErr := svc.Connect(); akErr != nil {
				// Degraded start. The service stays usable: its store-backed
				// calls report unavailable, so the key lifecycle API answers
				// 503 and the reconnect tick keeps trying. The DSN is logged
				// redacted — it carries the store password.
				tk.LogIt(tk.LogCritical, "AI key store starting degraded: %v\n", akErr)
			}
		}()
		// A key revoked here must stop authenticating on the peers before
		// their cached copy expires. Without this the store evicts locally and
		// the revocation stops at this gateway's edge.
		if coord := mh.sockproxySync; coord != nil {
			mh.AIKeyService.SetInvalidationSink(func(inv aikey.KeyInvalidation) {
				coord.BroadcastKeyInvalidation(inv.KeyHash, inv.KeyID)
			})
		}
	}

	// Initialize the Oauth user service subsystem
	if opts.Opts.Oauth2Enable {
		tk.LogIt(tk.LogInfo, "Ouath User service enabled\n")
		mh.OauthUserService = user.NewOauthUserService()
	}

	// Initialize IPsec strongSwan Integration (TASK_18)
	tk.LogIt(tk.LogInfo, "[IPsec] Initializing strongSwan integration\n")
	mh.ipsec = NewIPsecH()
	tk.LogIt(tk.LogInfo, "[IPsec] Initialized successfully\n")

	// Initialize the loxinet global ticker(s)
	mh.tDone = make(chan bool)
	mh.ticker = time.NewTicker(LoxinetTiVal * time.Second)
	mh.wg.Add(1)
	go loxiNetTicker(opts.Opts.BgpPeerMode)

	SysctlPostInit()

	// Initialize HTTP/HTTPS Protocol Analyzer (Distributed Tracing)
	if os.Getenv("LOXILB_HTTP_TRACE_ENABLED") == "1" {
		tk.LogIt(tk.LogInfo, "[Tracing] Initializing HTTP/HTTPS Protocol Analyzer\n")
		if err := mh.initTracing(); err != nil {
			tk.LogIt(tk.LogError, "[Tracing] Failed to initialize: %v\n", err)
			// Non-fatal: Continue without tracing
		} else {
			tk.LogIt(tk.LogInfo, "[Tracing] Initialized successfully\n")
		}
	} else {
		// Register lazy initialization callback for on-demand tracing activation
		handler.InitTracingCallback = mh.initTracing
		handler.IsTracingInitialized = func() bool { return mh.tracingEnabled }
		tk.LogIt(tk.LogInfo, "[Tracing] Lazy initialization registered (enable via API)\n")
	}

	// Initialize L4 Connection Tracing (TCP/SCTP)
	if os.Getenv("LOXILB_L4_TRACE_ENABLED") == "1" {
		tk.LogIt(tk.LogInfo, "[L4Trace] Initializing L4 Connection Tracing\n")
		if err := mh.initL4Tracing(); err != nil {
			tk.LogIt(tk.LogError, "[L4Trace] Failed to initialize: %v\n", err)
			// Non-fatal: Continue without L4 tracing
		} else {
			tk.LogIt(tk.LogInfo, "[L4Trace] Initialized successfully\n")
		}
	}

	mh.ready = true
}

// initTracing initializes the HTTP/HTTPS Protocol Analyzer subsystem
//
// Architecture:
// 1. Create OTLP exporter (retrieves config from REST API)
// 2. Create ring buffer consumer (mmap + epoll)
// 3. Create span assembler (event correlation)
// 4. Start consumer → assembler pipeline
//
// Returns error if initialization fails (non-fatal, tracing will be disabled).
func (mh *loxiNetH) initTracing() error {
	// 0. Enable tracing in C layer (sockproxy.c)
	ret := C.lxb_trace_enable()
	if ret != 0 {
		tk.LogIt(tk.LogError, "[Tracing] Failed to enable C tracing layer: ret=%d\n", ret)
		return fmt.Errorf("C tracing layer enable failed: %d", ret)
	}
	tk.LogIt(tk.LogInfo, "[Tracing] C tracing layer enabled successfully\n")

	// 1. Create OTLP exporter (connects to Jaeger)
	otlpExporter, err := NewOTLPExporter()
	if err != nil {
		return fmt.Errorf("OTLP exporter creation failed: %w", err)
	}
	mh.otlpExporter = otlpExporter

	// 2. Create ring buffer consumer
	ringConsumer, err := NewRingConsumer()
	if err != nil {
		return fmt.Errorf("ring consumer creation failed: %w", err)
	}
	mh.ringConsumer = ringConsumer

	// 3. Connect parser registry to catalog sync manager for dynamic parser selection
	// This enables YAML parser_type field to control parser routing at runtime
	if mh.dpEbpf != nil && mh.dpEbpf.catalogSyncManager != nil && ringConsumer.GetParserRegistry() != nil {
		mh.dpEbpf.catalogSyncManager.SetParserRegistry(ringConsumer.GetParserRegistry())
	}

	// 4. Create span assembler (pass tracing catalog manager for deep inspection)
	tracingCatalogMgr := mh.dpEbpf.tracingCatalogManager
	tracer := otlpExporter.GetTracer("loxilb")
	parserRegistry := ringConsumer.GetParserRegistry()
	spanAssembler := NewSpanAssembler(tracer, LoadTraceConfig(), tracingCatalogMgr, parserRegistry)
	mh.spanAssembler = spanAssembler

	// 6. Start consumer → assembler pipeline
	if err := ringConsumer.Start(); err != nil {
		return fmt.Errorf("ring consumer start failed: %w", err)
	}

	// Start event processing goroutine
	mh.wg.Add(1)
	go mh.traceEventProcessor()

	mh.tracingEnabled = true

	// Register callbacks with handler package (avoids import cycle)
	handler.ReconnectOTLPCallback = mh.ReconnectOTLPExporter
	handler.IsTracingInitialized = func() bool { return mh.tracingEnabled }

	return nil
}

// traceEventProcessor processes events from ring consumer to span assembler
func (mh *loxiNetH) traceEventProcessor() {
	defer mh.wg.Done()
	defer func() {
		if e := recover(); e != nil {
			tk.LogIt(tk.LogCritical, "[Tracing] Panic in event processor: %s: %s", e, debug.Stack())
		}
	}()

	tk.LogIt(tk.LogInfo, "[Tracing] Event processor started\n")

	for evt := range mh.ringConsumer.EventChan {
		mh.spanAssembler.ProcessEvent(evt)
	}

	tk.LogIt(tk.LogInfo, "[Tracing] Event processor stopped\n")
}

// ReconnectOTLPExporter recreates OTLP exporter with new configuration (for both L4 and L7)
//
// This method is called when the OTLP endpoint configuration changes via REST API.
// It gracefully shuts down the old exporter and creates a new one, then updates
// both L4 and L7 span assemblers with the new tracer.
//
// Thread-safe: Can be called concurrently with span assembly operations.
func (mh *loxiNetH) ReconnectOTLPExporter() error {
	// Shutdown old exporter if it exists
	if mh.otlpExporter != nil {
		tk.LogIt(tk.LogInfo, "[OTLP_RECONNECT] Shutting down old exporter\n")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := mh.otlpExporter.Shutdown(ctx); err != nil {
			tk.LogIt(tk.LogWarning, "[OTLP_RECONNECT] Old exporter shutdown error (continuing): %v\n", err)
		}
		cancel()
	}

	// Create new exporter with updated configuration
	tk.LogIt(tk.LogInfo, "[OTLP_RECONNECT] Creating new exporter with updated config\n")
	otlpExporter, err := NewOTLPExporter()
	if err != nil {
		return fmt.Errorf("OTLP exporter reconnection failed: %w", err)
	}
	mh.otlpExporter = otlpExporter

	// Get new tracer
	tracer := otlpExporter.GetTracer("loxilb")

	// Update L7 (HTTP/HTTPS) span assembler if it exists
	if mh.spanAssembler != nil {
		mh.spanAssembler.SetTracer(tracer)
		tk.LogIt(tk.LogInfo, "[OTLP_RECONNECT] L7 span assembler updated\n")
	}

	// Update L4 (TCP/SCTP) span assembler if it exists
	if mh.l4SpanAssembler != nil {
		mh.l4SpanAssembler.SetTracer(tracer)
		tk.LogIt(tk.LogInfo, "[OTLP_RECONNECT] L4 span assembler updated\n")
	}

	tk.LogIt(tk.LogInfo, "[OTLP_RECONNECT] Successfully reconnected OTLP exporter\n")
	return nil
}

// GetLoxiNetH returns a pointer to the global loxiNetH instance
// This is used by REST API handlers to trigger OTLP reconnection
func GetLoxiNetH() *loxiNetH {
	return &mh
}

// shutdownTracing gracefully shuts down tracing subsystem
func (mh *loxiNetH) shutdownTracing() {
	if !mh.tracingEnabled {
		return
	}

	tk.LogIt(tk.LogInfo, "[Tracing] Shutting down tracing subsystem\n")

	// CRITICAL: Stop in reverse order of initialization to prevent deadlocks
	// IMPORTANT: Get stats BEFORE calling Stop to avoid accessing unmapped memory

	// 0. Capture stats before stopping (ring buffer memory still mapped)
	var ringStats []RingStats
	if mh.ringConsumer != nil {
		ringStats = mh.ringConsumer.GetStats()
	}

	// 1. Stop ring consumer first (stops new events, closes EventChan)
	//    This will cause traceEventProcessor to exit when EventChan is closed
	if mh.ringConsumer != nil {
		tk.LogIt(tk.LogDebug, "[Tracing] Stopping ring consumer\n")
		mh.ringConsumer.Stop()
	}

	// 1.5. CRITICAL FIX: Manually call C cleanup to delete shm files
	// os.Exit doesn't trigger atexit handlers, so we must call explicitly
	// This MUST happen AFTER ringConsumer.Stop (munmap) but BEFORE process exit
	if mh.ringConsumer != nil {
		tk.LogIt(tk.LogDebug, "[Tracing] Calling C ring cleanup to remove shm files\n")
		mh.ringConsumer.CleanupCRings()
	}

	// 1.6. CRITICAL FIX: L4 tracing cleanup (BPF ring buffers)
	//      Same issue as HTTP tracing - BPF ring buffers need explicit cleanup
	if mh.l4TracingEnabled && mh.l4RingConsumer != nil {
		tk.LogIt(tk.LogDebug, "[L4Trace] Stopping L4 ring consumer\n")
		mh.l4RingConsumer.Stop()
		// Note: BPF ring buffers clean themselves up via kernel on unmap
		// No explicit shm_unlink needed (they're in /sys/fs/bpf, not /dev/shm)
	}

	// 1.7. L4 span assembler cleanup
	if mh.l4SpanAssembler != nil {
		tk.LogIt(tk.LogDebug, "[L4Trace] Stopping L4 span assembler\n")
		mh.l4SpanAssembler.Stop()
	}

	// 2. Wait for event processor goroutine to exit
	//    This ensures no more events are being sent to span assembler
	tk.LogIt(tk.LogDebug, "[Tracing] Waiting for event processor to stop\n")
	// Note: wg.Wait in loxiNetRun will handle this

	// 3. Stop span assembler (force close pending spans)
	//    This will flush all in-flight spans to OTLP exporter
	if mh.spanAssembler != nil {
		tk.LogIt(tk.LogDebug, "[Tracing] Stopping span assembler\n")
		mh.spanAssembler.Stop()
	}

	// 3.5. Clean up all remaining body files (after consumers stopped, before exporter)
	//      This ensures no body files are left behind from unprocessed events
	if cleaned, err := CleanupAllBodyFiles(); err != nil {
		tk.LogIt(tk.LogWarning, "[Tracing] Body file cleanup failed: %v\n", err)
	} else if cleaned > 0 {
		tk.LogIt(tk.LogInfo, "[Tracing] Cleaned up %d body file(s) on shutdown\n", cleaned)
	}

	// 4. Shutdown OTLP exporter last (flush remaining spans to Jaeger)
	if mh.otlpExporter != nil {
		tk.LogIt(tk.LogDebug, "[Tracing] Shutting down OTLP exporter\n")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := mh.otlpExporter.Shutdown(ctx); err != nil {
			tk.LogIt(tk.LogError, "[Tracing] OTLP exporter shutdown error: %v\n", err)
		} else {
			tk.LogIt(tk.LogDebug, "[Tracing] OTLP exporter shut down successfully\n")
		}
	}

	// 5. Log final statistics (using captured data from before Stop)
	if mh.otlpExporter != nil {
		stats := mh.otlpExporter.GetStats()
		circuitState := "unknown"
		switch stats.CircuitState {
		case 0:
			circuitState = "closed"
		case 1:
			circuitState = "open"
		case 2:
			circuitState = "half-open"
		}
		tk.LogIt(tk.LogInfo, "[Tracing] Final stats: exported=%d failed=%d dropped=%d circuit=%s\n",
			stats.SpansExported, stats.SpansFailed, stats.SpansDropped, circuitState)
	}

	for _, rs := range ringStats {
		tk.LogIt(tk.LogInfo, "[Tracing] Ring[%d] stats: drained=%d pending=%d dropped=%d fill=%.1f%%\n",
			rs.WorkerID, rs.Drained, rs.Pending, rs.Dropped, rs.FillRatio*100)
	}

	// 6. Clear references to prevent use-after-free and memory leaks
	mh.ringConsumer = nil
	mh.spanAssembler = nil
	mh.l4RingConsumer = nil
	mh.l4SpanAssembler = nil
	mh.otlpExporter = nil
	mh.tracingEnabled = false
	mh.l4TracingEnabled = false

	tk.LogIt(tk.LogInfo, "[Tracing] Shutdown complete (both HTTP and L4)\n")
}

// loxiNetRun - This routine will not return
func loxiNetRun() {
	// Stack trace logger
	defer func() {
		if e := recover(); e != nil {
			tk.LogIt(tk.LogCritical, "%s: %s", e, debug.Stack())
		}
		if mh.dp != nil {
			mh.dp.DpHooks.DpEbpfUnInit()
		}
		os.Exit(1)
	}()
	mh.wg.Wait()
}

// docaDefaultConfig builds the standard DpuConfig for BF2 DOCA from environment.
func docaDefaultConfig() DpuConfig {
	cfg := DpuConfig{
		PciAddr:  os.Getenv("BF2_PCI_ADDR"),
		Mode:     "doca-bf2",
		LogLevel: opts.Opts.LogLevel,
		Extras:   make(map[string]string),
	}
	// BF2_NUM_REPR overrides auto-detection when explicitly set.
	// If unset, detectSriovVFs auto-detects from sysfs/representors.
	if numRepr := os.Getenv("BF2_NUM_REPR"); numRepr != "" {
		cfg.Extras["num_repr"] = numRepr
	}
	return cfg
}

// docaInitAndRegister attempts to create and register a DpDocaBf2 plugin.
// Returns (bf2, true) on success, (bf2, false) on failure (re-init loop started).
func docaInitAndRegister() (*DpDocaBf2, bool) {
	bf2 := NewDpDocaBf2()
	if bf2 == nil {
		return nil, false
	}
	cfg := docaDefaultConfig()
	if err := bf2.Init(cfg); err != nil {
		tk.LogIt(tk.LogWarning, "DPU BF2 plugin init failed (attempt 1/%d), starting re-init loop: %v\n", docaMaxInitAttempts, err)
		// CGO-05: return bf2 with nil bridge -- fail-open via nil guards
		// Start background re-init goroutine (1 attempt already consumed)
		go docaReInitLoop(bf2, cfg, 1)
		return bf2, false
	}
	mh.dpuMgr.Register(bf2)
	tk.LogIt(tk.LogInfo, "DPU BF2 plugin registered successfully\n")

	// Replay routes from route table to DOCA LPM pipes
	if mh.zr != nil && mh.zr.Rt != nil {
		for _, rt := range mh.zr.Rt.RtMap {
			if len(rt.NextHops) == 0 {
				continue
			}
			_, rtNet, err := net.ParseCIDR(rt.Key.RtCidr)
			if err != nil || !tk.IsNetIPv4(rtNet.IP.String()) {
				continue
			}
			rtWq := &RouteDpWorkQ{
				Work:    DpCreate,
				ZoneNum: rt.ZoneNum,
				Dst:     *rtNet,
				NMax:    len(rt.NextHops),
			}
			for i := range rt.NextHops {
				if i < len(rtWq.NMark) {
					rtWq.NMark[i] = int(rt.RtGetNhMark(i))
				}
			}
			if err := bf2.RouteAdd(rtWq); err != nil {
				tk.LogIt(tk.LogDebug, "doca-bf2: route replay failed for %s (fire-and-forget): %v\n", rt.Key.RtCidr, err)
			}
		}
	}

	return bf2, true
}

// CGO-05: re-init constants
const (
	docaReInitInterval  = 60 * time.Second
	docaMaxInitAttempts = 3 // total including initial attempt
)

// docaReInitLoop retries DOCA initialization periodically when initial init fails.
// attemptsSoFar is how many attempts have already been made (including initial).
// Stops after docaMaxInitAttempts total or on success.
//
// respects mh.shutdownCtx so the workers stage of
// the layered shutdown sequencer can cancel a pending re-init early
// instead of blocking up to 60s for the next ticker fire.
func docaReInitLoop(doca *DpDocaBf2, cfg DpuConfig, attemptsSoFar int) {
	ticker := time.NewTicker(docaReInitInterval)
	defer ticker.Stop()

	attempts := attemptsSoFar
	for {
		select {
		case <-mh.shutdownCtx.Done():
			tk.LogIt(tk.LogInfo, "doca-bf2: re-init loop exiting on shutdown\n")
			return
		case <-ticker.C:
		}
		attempts++
		if attempts > docaMaxInitAttempts {
			tk.LogIt(tk.LogError, "doca-bf2: re-init failed after %d total attempts -- DOCA permanently unavailable\n", docaMaxInitAttempts)
			return
		}

		tk.LogIt(tk.LogInfo, "doca-bf2: re-init attempt %d/%d\n", attempts, docaMaxInitAttempts)
		err := doca.Init(cfg)
		if err != nil {
			tk.LogIt(tk.LogWarning, "doca-bf2: re-init attempt %d/%d failed: %v\n", attempts, docaMaxInitAttempts, err)
			continue
		}

		tk.LogIt(tk.LogInfo, "doca-bf2: re-init succeeded -- DOCA bridge now available\n")
		mh.dpuMgr.Register(doca)
		go docaHeartbeatWatchdog(doca.Bridge())
		return
	}
}

// docaHeartbeatWatchdog monitors DOCA worker liveness by submitting a no-op
// with a timeout. After 3 consecutive failures, it unregisters the plugin
// and restarts the retry loop.
func docaHeartbeatWatchdog(bridge *DocaBridge) {
	const (
		heartbeatInterval = 30 * time.Second
		heartbeatTimeout  = 5 * time.Second
		maxFailures       = 3
	)

	if bridge == nil {
		// CGO-05: report degraded instead of panicking
		tk.LogIt(tk.LogWarning, "doca-bf2: heartbeat reports DOCA unavailable (degraded) -- eBPF handling all traffic\n")
		return
	}

	failures := 0
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		// ctx-aware select so the workers stage
		// of the layered shutdown sequencer can cancel the heartbeat
		// without waiting up to 30s for the next tick.
		select {
		case <-mh.shutdownCtx.Done():
			tk.LogIt(tk.LogInfo, "doca-bf2: heartbeat exiting on shutdown\n")
			return
		case <-ticker.C:
		}
		if !mh.dpuMgr.IsEnabled() {
			continue // plugin was unregistered externally; skip checks
		}

		err := bridge.submitWithTimeout(func() error { return nil }, heartbeatTimeout)
		if err != nil {
			failures++
			tk.LogIt(tk.LogWarning, "DOCA heartbeat failed (%d/%d): %v\n", failures, maxFailures, err)
			if failures >= maxFailures {
				tk.LogIt(tk.LogError, "DOCA worker unresponsive after %d failures, unregistering plugin\n", maxFailures)
				mh.dpuMgr.Unregister("doca-bf2")
				failures = 0
				// Create fresh instance and start re-init loop
				freshBf2 := NewDpDocaBf2()
				if freshBf2 != nil {
					freshCfg := docaDefaultConfig()
					go docaReInitLoop(freshBf2, freshCfg, 0)
				}
				return // this watchdog exits; a new one starts after successful retry
			}
		} else {
			if failures > 0 {
				tk.LogIt(tk.LogInfo, "DOCA heartbeat recovered after %d failures\n", failures)
			}
			failures = 0
		}
	}
}

// Main -  main routine of loxinet
func Main() {
	loxiNetInit()
	loxiNetRun()
}
