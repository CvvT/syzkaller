// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package freebsd

import (
	"github.com/CvvT/syzkaller/prog"
	"github.com/CvvT/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
	arch := &arch{
		unix: targets.MakeUnixSanitizer(target),
	}

	target.MakeMmap = targets.MakePosixMmap(target)
	target.SanitizeCall = arch.unix.SanitizeCall
}

type arch struct {
	unix *targets.UnixSanitizer
}
