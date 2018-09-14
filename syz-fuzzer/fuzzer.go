// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	_ "sync/atomic"
	_ "time"
	"path/filepath"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
	"github.com/CvvT/syzkaller/pkg/mgrconfig"
)

type Fuzzer struct {
	cfg         *mgrconfig.Config
	name        string
	outputType  OutputType
	config      *ipc.Config
	execOpts    *ipc.ExecOpts
	procs       []*Proc
	gate        *ipc.Gate
	workQueue   *WorkQueue
	needPoll    chan struct{}
	choiceTable *prog.ChoiceTable
	stats       [StatCount]uint64
	manager     *rpctype.RPCClient
	target      *prog.Target

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	logMu sync.Mutex
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func main() {
	debug.SetGCPercent(50)

	var (
		flagConfig  = flag.String("config", "", "configuration file")
		flagName    = flag.String("name", "test", "unique name for manager")
		flagOS      = flag.String("os", runtime.GOOS, "target OS")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager = flag.String("manager", "", "manager rpc address")
		flagProcs   = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput  = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagPprof   = flag.String("pprof", "", "address to serve pprof profiles")
		flagTest    = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
	)
	flag.Parse()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var enabledSyscalls []int
	for c := range syscalls {
		enabledSyscalls = append(enabledSyscalls, c)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	sandbox := "none"
	if config.Flags&ipc.FlagSandboxSetuid != 0 {
		sandbox = "setuid"
	} else if config.Flags&ipc.FlagSandboxNamespace != 0 {
		sandbox = "namespace"
	}

	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:      target,
		sandbox:     sandbox,
		ipcConfig:   config,
		ipcExecOpts: execOpts,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	if *flagPprof != "" {
		go func() {
			err := http.ListenAndServe(*flagPprof, nil)
			log.Fatalf("failed to serve pprof profiles: %v", err)
		}()
	} else {
		runtime.MemProfileRate = 0
	}

	r := &rpctype.ConnectRes{}
	if *flagManager != "" {
		log.Logf(0, "dialing manager at %v", *flagManager)
		manager, err := rpctype.NewRPCClient(*flagManager)
		if err != nil {
			log.Fatalf("failed to connect to manager: %v ", err)
		}

		a := &rpctype.ConnectArgs{Name: *flagName}
		if err := manager.Call("Manager.Connect", a, r); err != nil {
			log.Fatalf("failed to connect to manager: %v ", err)
		}
	
		if r.CheckResult == nil {
			checkArgs.gitRevision = r.GitRevision
			checkArgs.targetRevision = r.TargetRevision
			checkArgs.enabledCalls = r.EnabledCalls
			checkArgs.allSandboxes = r.AllSandboxes
			r.CheckResult, err = checkMachine(checkArgs)
			if err != nil {
				r.CheckResult = &rpctype.CheckArgs{
					Error: err.Error(),
				}
			}
			r.CheckResult.Name = *flagName
			if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
				log.Fatalf("Manager.Check call failed: %v", err)
			}
			if r.CheckResult.Error != "" {
				log.Fatalf("%v", r.CheckResult.Error)
			}
		}
	} else {
		checkArgs.gitRevision = sys.GitRevision
		checkArgs.targetRevision = target.Revision
		checkArgs.enabledCalls = enabledSyscalls
		checkArgs.allSandboxes = true
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			r.CheckResult = &rpctype.CheckArgs{
				Error: err.Error(),
			}
		}
		r.CheckResult.Name = *flagName
	}

	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls))
	for _, feat := range r.CheckResult.Features {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	periodicCallback, err := host.Setup(target, r.CheckResult.Features)
	if err != nil {
		log.Fatalf("BUG: %v", err)
	}
	if r.CheckResult.Features[host.FeatureNetworkInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if r.CheckResult.Features[host.FeatureNetworkDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	if r.CheckResult.Features[host.FeatureFaultInjection].Enabled {
		config.Flags |= ipc.FlagEnableFault
	}

	if *flagRunTest {
		// runTest(target, manager, *flagName, config.Executor)
		return
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		gate:                     ipc.NewGate(2**flagProcs, periodicCallback),
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  nil, //manager,
		target:                   target,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFaultInjection].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		corpusHashes:             make(map[hash.Sig]struct{}),
	}
	for i := 0; fuzzer.poll(r.CheckResult); i++ {
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}
	prios := target.CalculatePriorities(fuzzer.corpus)
	fuzzer.choiceTable = target.BuildChoiceTable(prios, calls)

	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}
}

func (fuzzer *Fuzzer) poll(args *rpctype.CheckArgs) bool {
	
	Candidates := fuzzer.loadcorpus(fuzzer.cfg, args)

	for _, candidate := range *Candidates {
		p, err := fuzzer.target.Deserialize(candidate.Prog)
		if err != nil {
			log.Fatalf("failed to parse program from manager: %v", err)
		}
		flags := ProgCandidate
		if candidate.Minimized {
			flags |= ProgMinimized
		}
		if candidate.Smashed {
			flags |= ProgSmashed
		}
		fuzzer.workQueue.enqueue(&WorkCandidate{
			p:     p,
			flags: flags,
		})

		// Add candidates to corpus
		sig := hash.Hash(candidate.Prog)
		fuzzer.addInputToCorpusRaw(p, sig)
	}
	return len(*Candidates) != 0 
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.RPCInput) {
	a := &rpctype.NewInputArgs{
		Name:     fuzzer.name,
		RPCInput: inp,
	}
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.RPCInput) {
	p, err := fuzzer.target.Deserialize(inp.Prog)
	if err != nil {
		log.Fatalf("failed to deserialize prog from another fuzzer: %v", err)
	}
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	fuzzer.addInputToCorpus(p, sign, sig)
}

func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) addInputToCorpusRaw(p *prog.Prog, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
	}
	fuzzer.corpusMu.Unlock()
}

func (fuzzer *Fuzzer) corpusSnapshot() []*prog.Prog {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return fuzzer.corpus
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info []ipc.CallInfo) (calls []int) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	for i, inf := range info {
		diff := fuzzer.maxSignal.DiffRaw(inf.Signal, signalPrio(p.Target, p.Calls[i], &inf))
		if diff.Empty() {
			continue
		}
		calls = append(calls, i)
		fuzzer.signalMu.RUnlock()
		fuzzer.signalMu.Lock()
		fuzzer.maxSignal.Merge(diff)
		fuzzer.newSignal.Merge(diff)
		fuzzer.signalMu.Unlock()
		fuzzer.signalMu.RLock()
	}
	return
}

func signalPrio(target *prog.Target, c *prog.Call, ci *ipc.CallInfo) (prio uint8) {
	if ci.Errno == 0 {
		prio |= 1 << 1
	}
	if !target.CallContainsAny(c) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}

const currentDBVersion = 3

func (fuzzer *Fuzzer) loadcorpus(cfg *mgrconfig.Config, args *rpctype.CheckArgs) *[]rpctype.RPCCandidate {
	log.Logf(0, "loading corpus...")
	corpusDB, err := db.Open(filepath.Join(cfg.Workdir, "corpus.db"))
	if err != nil {
		log.Fatalf("failed to open corpus database: %v", err)
	}

	candidates := make([]rpctype.RPCCandidate, 0)
	// By default we don't re-minimize/re-smash programs from corpus,
	// it takes lots of time on start and is unnecessary.
	// However, on version bumps we can selectively re-minimize/re-smash.
	minimized, smashed := true, true
	switch corpusDB.Version {
	case 0:
		// Version 0 had broken minimization, so we need to re-minimize.
		minimized = false
		fallthrough
	case 1:
		// Version 1->2: memory is preallocated so lots of mmaps become unnecessary.
		minimized = false
		fallthrough
	case 2:
		// Version 2->3: big-endian hints.
		smashed = false
		fallthrough
	case currentDBVersion:
	}
	syscalls := make(map[int]bool)
	for _, id := range args.EnabledCalls[cfg.Sandbox] {
		syscalls[id] = true
	}
	deleted := 0
	for key, rec := range corpusDB.Records {
		p, err := fuzzer.target.Deserialize(rec.Val)
		if err != nil {
			if deleted < 10 {
				log.Logf(0, "deleting broken program: %v\n%s", err, rec.Val)
			}
			corpusDB.Delete(key)
			deleted++
			continue
		}
		disabled := false
		for _, c := range p.Calls {
			if !syscalls[c.Meta.ID] {
				disabled = true
				break
			}
		}
		if disabled {
			// This program contains a disabled syscall.
			// We won't execute it, but remember its hash so
			// it is not deleted during minimization.
			// mgr.disabledHashes[hash.String(rec.Val)] = struct{}{}
			continue
		}
		candidates = append(candidates, rpctype.RPCCandidate{
			Prog:      rec.Val,
			Minimized: minimized,
			Smashed:   smashed,
		})
	}
	log.Logf(0, "%-24v: %v (%v deleted)", "corpus", len(candidates), deleted)
	return &candidates
}
