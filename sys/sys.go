// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	// Import all targets, so that users only need to import sys.
	_ "github.com/CvvT/syzkaller/sys/akaros/gen"
	_ "github.com/CvvT/syzkaller/sys/freebsd/gen"
	_ "github.com/CvvT/syzkaller/sys/fuchsia/gen"
	_ "github.com/CvvT/syzkaller/sys/linux/gen"
	_ "github.com/CvvT/syzkaller/sys/netbsd/gen"
	_ "github.com/CvvT/syzkaller/sys/openbsd/gen"
	_ "github.com/CvvT/syzkaller/sys/test/gen"
	_ "github.com/CvvT/syzkaller/sys/windows/gen"
)

// Emitted by Makefile.
var GitRevision string
