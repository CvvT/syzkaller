// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"math/rand"
	"path/filepath"
	"sync"
	"time"

	"github.com/CvvT/syzkaller/dashboard/dashapi"
	"github.com/CvvT/syzkaller/pkg/cover"
	"github.com/CvvT/syzkaller/pkg/db"
	"github.com/CvvT/syzkaller/pkg/hash"
	"github.com/CvvT/syzkaller/pkg/log"
	"github.com/CvvT/syzkaller/pkg/mgrconfig"
	"github.com/CvvT/syzkaller/pkg/report"
	"github.com/CvvT/syzkaller/pkg/repro"
	"github.com/CvvT/syzkaller/pkg/rpctype"
	"github.com/CvvT/syzkaller/pkg/signal"
	"github.com/CvvT/syzkaller/prog"
	_ "github.com/CvvT/syzkaller/sys"
	"github.com/CvvT/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagDebug  = flag.Bool("debug", false, "dump all VM output to console")
	flagBench  = flag.String("bench", "", "write execution statistics into this file periodically")
)

type Manager struct {
	cfg          *mgrconfig.Config
	vmPool       *vm.Pool
	target       *prog.Target
	reporter     report.Reporter
	crashdir     string
	port         int
	corpusDB     *db.DB
	startTime    time.Time
	firstConnect time.Time
	fuzzingTime  time.Duration
	// stats          *Stats
	fuzzerStats    map[string]uint64
	crashTypes     map[string]bool
	vmStop         chan bool
	checkResult    *rpctype.CheckArgs
	fresh          bool
	numFuzzing     uint32
	numReproducing uint32

	dash *dashapi.Dashboard

	mu              sync.Mutex
	phase           int
	enabledSyscalls []int

	candidates     []rpctype.RPCCandidate // untriaged inputs from corpus and hub
	disabledHashes map[string]struct{}
	corpus         map[string]rpctype.RPCInput
	corpusCover    cover.Cover
	corpusSignal   signal.Signal
	maxSignal      signal.Signal
	prios          [][]float32
	newRepros      [][]byte

	fuzzers        map[string]*Fuzzer
	needMoreRepros chan chan bool
	hubReproQueue  chan *Crash
	reproRequest   chan chan map[string]bool

	// For checking that files that we are using are not changing under us.
	// Maps file name to modification time.
	usedFiles map[string]time.Time
}

const (
	// Just started, nothing done yet.
	phaseInit = iota
	// Corpus is loaded and machine is checked.
	phaseLoadedCorpus
	// Triaged all inputs from corpus.
	// This is when we start querying hub and minimizing persistent corpus.
	phaseTriagedCorpus
	// Done the first request to hub.
	phaseQueriedHub
	// Triaged all new inputs from hub.
	// This is when we start reproducing crashes.
	phaseTriagedHub
)

const currentDBVersion = 3

type Fuzzer struct {
	name       string
	inputs     []rpctype.RPCInput
	annotation [][]int
	// all inputs are associated with the same annotation, since all inputs are the
	// same in terms of syscall sequence
	newMaxSignal    signal.Signal
	firstConnect    bool // indicate whether this fuzzer has connected to the manager
	rnd             *rand.Rand
	callIdx, argIdx int
}

type Crash struct {
	vmIndex int
	hub     bool // this crash was created based on a repro from hub
	*report.Report
}

func main() {
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls)
	if err != nil {
		log.Fatalf("%v", err)
	}
	RunManager(cfg, target, syscalls)
}

func RunManager(cfg *mgrconfig.Config, target *prog.Target, syscalls map[int]bool) {

	var enabledSyscalls []int
	for c := range syscalls {
		enabledSyscalls = append(enabledSyscalls, c)
	}

	mgr := &Manager{
		cfg: cfg,
		//vmPool:    vmPool,
		target: target,
		//reporter:  reporter,
		//crashdir:  crashdir,
		startTime: time.Now(),
		// stats:           new(Stats),
		fuzzerStats:     make(map[string]uint64),
		crashTypes:      make(map[string]bool),
		enabledSyscalls: enabledSyscalls,
		corpus:          make(map[string]rpctype.RPCInput),
		disabledHashes:  make(map[string]struct{}),
		fuzzers:         make(map[string]*Fuzzer),
		fresh:           true,
		vmStop:          make(chan bool),
		hubReproQueue:   make(chan *Crash, 10),
		needMoreRepros:  make(chan chan bool),
		reproRequest:    make(chan chan map[string]bool),
		usedFiles:       make(map[string]time.Time),
	}

	var err error
	log.Logf(0, "loading corpus...")
	mgr.corpusDB, err = db.Open(filepath.Join(cfg.Workdir, "corpus.db"))
	if err != nil {
		log.Fatalf("failed to open corpus database: %v", err)
	}

	mgr.vmLoop()
}

type RunResult struct {
	idx   int
	crash *Crash
	err   error
}

type ReproResult struct {
	instances []int
	title0    string
	res       *repro.Result
	stats     *repro.Stats
	err       error
	hub       bool // repro came from hub
}

// Manager needs to be refactored (#605).
// nolint: gocyclo
func (mgr *Manager) vmLoop() {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	corpus := []*prog.Prog{}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range mgr.enabledSyscalls {
		calls[mgr.target.Syscalls[id]] = true
	}
	prios := mgr.target.CalculatePriorities(corpus)
	choiceTable := mgr.target.BuildChoiceTable(prios, calls)
	f := &Fuzzer{
		name:    "a.Name",
		rnd:     rand.New(rand.NewSource(time.Now().UnixNano())),
		callIdx: -1,
		argIdx:  -1,
	}
	for _, rec := range mgr.corpusDB.Records {
		p, err := mgr.target.Deserialize(rec.Val)
		if err != nil {
			continue
		}
		log.Logf(0, "Original Prog: %s", p.Serialize())

		newprog := p.Clone()

		p.Target = mgr.target
		for _, num := range p.NumArgs() {
			f.annotation = append(f.annotation, make([]int, num))
		}

		log.Logf(0, "Annotation %v", f.annotation)
		pos := make([]int, 2)
		newprog.RMutate(rnd, 30, choiceTable, corpus, f.annotation, &pos)
		res := newprog.RMutate(rnd, 30, nil, corpus, f.annotation, &pos)
		pos = nil
		log.Logf(0, "%v New Prog: %s", res, newprog.Serialize())
	}

}

func (mgr *Manager) loadCorpus() {
	// By default we don't re-minimize/re-smash programs from corpus,
	// it takes lots of time on start and is unnecessary.
	// However, on version bumps we can selectively re-minimize/re-smash.
	minimized, smashed := true, true
	switch mgr.corpusDB.Version {
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
	for _, id := range mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox] {
		syscalls[id] = true
	}
	deleted := 0
	for key, rec := range mgr.corpusDB.Records {
		p, err := mgr.target.Deserialize(rec.Val)
		if err != nil {
			if deleted < 10 {
				log.Logf(0, "deleting broken program: %v\n%s", err, rec.Val)
			}
			mgr.corpusDB.Delete(key)
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
			mgr.disabledHashes[hash.String(rec.Val)] = struct{}{}
			continue
		}
		mgr.candidates = append(mgr.candidates, rpctype.RPCCandidate{
			Prog:      rec.Val,
			Minimized: minimized,
			Smashed:   smashed,
		})
	}
	mgr.fresh = len(mgr.corpusDB.Records) == 0
	log.Logf(0, "%-24v: %v (%v deleted)", "corpus", len(mgr.candidates), deleted)

}
