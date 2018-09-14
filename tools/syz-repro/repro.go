// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/CvvT/syzkaller/pkg/csource"
	"github.com/CvvT/syzkaller/pkg/log"
	"github.com/CvvT/syzkaller/pkg/mgrconfig"
	"github.com/CvvT/syzkaller/pkg/osutil"
	"github.com/CvvT/syzkaller/pkg/report"
	"github.com/CvvT/syzkaller/pkg/repro"
	"github.com/CvvT/syzkaller/prog"
	"github.com/CvvT/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagCount  = flag.Int("count", 0, "number of VMs to use (overrides config count param)")
	flagDebug  = flag.Bool("debug", false, "print debug output")
)

func main() {
	os.Args = append(append([]string{}, os.Args[0], "-v=10"), os.Args[1:]...)
	flag.Parse()
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if len(flag.Args()) != 1 {
		log.Fatalf("usage: syz-repro -config=config.file execution.log")
	}
	data, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	if _, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch); err != nil {
		log.Fatalf("%v", err)
	}
	vmPool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatalf("%v", err)
	}
	vmCount := vmPool.Count()
	if *flagCount > 0 && *flagCount < vmCount {
		vmCount = *flagCount
	}
	if vmCount > 4 {
		vmCount = 4
	}
	vmIndexes := make([]int, vmCount)
	for i := range vmIndexes {
		vmIndexes[i] = i
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}
	osutil.HandleInterrupts(vm.Shutdown)

	res, stats, err := repro.Run(data, cfg, reporter, vmPool, vmIndexes)
	if err != nil {
		log.Logf(0, "reproduction failed: %v", err)
	}
	if stats != nil {
		fmt.Printf("Extracting prog: %v\n", stats.ExtractProgTime)
		fmt.Printf("Minimizing prog: %v\n", stats.MinimizeProgTime)
		fmt.Printf("Simplifying prog options: %v\n", stats.SimplifyProgTime)
		fmt.Printf("Extracting C: %v\n", stats.ExtractCTime)
		fmt.Printf("Simplifying C: %v\n", stats.SimplifyCTime)
	}
	if res == nil {
		return
	}

	fmt.Printf("opts: %+v crepro: %v\n\n", res.Opts, res.CRepro)
	fmt.Printf("%s\n", res.Prog.Serialize())
	if res.CRepro {
		src, err := csource.Write(res.Prog, res.Opts)
		if err != nil {
			log.Fatalf("failed to generate C repro: %v", err)
		}
		if formatted, err := csource.Format(src); err == nil {
			src = formatted
		}
		fmt.Printf("%s\n", src)
	}
}
