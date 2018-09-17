// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CvvT/syzkaller/pkg/compiler"
)

type netbsd struct{}

func (*netbsd) prepare(sourcedir string, build bool, arches []string) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	if !build {
		return fmt.Errorf("netbsd requires -build flag")
	}
	return nil
}

func (*netbsd) prepareArch(arch *Arch) error {
	links := [][2]string{
		{"amd64", "machine"},
		{"amd64", "amd64"},
		{"x86", "x86"},
	}
	for _, v := range links {
		if err := machineLink(arch, v[0], v[1]); err != nil {
			return err
		}
	}
	return nil
}

func machineLink(arch *Arch, machine string, dest string) error {
	if err := os.Symlink(machineInclude(arch, machine),
		filepath.Join(arch.buildDir, dest)); err != nil {
		return fmt.Errorf("failed to create link: %v", err)
	}
	return nil
}

func machineInclude(arch *Arch, machine string) string {
	return filepath.Join(arch.sourceDir, "sys", "arch", machine, "include")
}

func (*netbsd) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	args := []string{
		"-fmessage-length=0",
		"-nostdinc",
		"-D_KERNEL",
		"-D__BSD_VISIBLE=1",
		"-I", filepath.Join(arch.sourceDir, "sys"),
		"-I", filepath.Join(arch.sourceDir, "sys", "sys"),
		"-I", filepath.Join(arch.sourceDir, "sys", "arch", "amd64"),
		"-I", filepath.Join(arch.sourceDir, "common", "include"),
		"-I", filepath.Join(arch.sourceDir, "sys", "compat", "linux", "common"),
		"-I", arch.buildDir,
	}
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+filepath.Join(arch.sourceDir, incdir))
	}
	// Syscall consts on netbsd have weird prefixes sometimes,
	// try to extract consts with these prefixes as well.
	compatNames := make(map[string][]string)
	for _, val := range info.Consts {
		const SYS = "SYS_"
		if strings.HasPrefix(val, SYS) {
			for _, prefix := range []string{"_", "__", "___"} {
				for _, suffix := range []string{"30", "50"} {
					compat := SYS + prefix + val[len(SYS):] + suffix
					compatNames[val] = append(compatNames[val], compat)
					info.Consts = append(info.Consts, compat)
				}
			}
		} else {
			compat := "LINUX_" + val
			compatNames[val] = append(compatNames[val], compat)
			info.Consts = append(info.Consts, compat)
		}
	}
	res, undeclared, err := extract(info, "gcc", args, "#include <sys/syscall.h>", false)
	for orig, compats := range compatNames {
		for _, compat := range compats {
			if undeclared[orig] && !undeclared[compat] {
				res[orig] = res[compat]
				delete(res, compat)
				delete(undeclared, orig)
			}
			delete(undeclared, compat)
		}
	}
	return res, undeclared, err
}
