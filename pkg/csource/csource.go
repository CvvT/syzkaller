// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package csource generates [almost] equivalent C programs from syzkaller programs.
package csource

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/CvvT/syzkaller/prog"
	"github.com/CvvT/syzkaller/sys/targets"
)

func Write(p *prog.Prog, opts Options) ([]byte, error) {
	if err := opts.Check(p.Target.OS); err != nil {
		return nil, fmt.Errorf("csource: invalid opts: %v", err)
	}
	ctx := &context{
		p:         p,
		opts:      opts,
		target:    p.Target,
		sysTarget: targets.Get(p.Target.OS, p.Target.Arch),
		calls:     make(map[string]uint64),
		num_vars:  0,
	}

	calls, vars, err := ctx.generateProgCalls(ctx.p, opts.Trace)
	if err != nil {
		return nil, err
	}

	mmapProg := p.Target.GenerateUberMmapProg()
	mmapCalls, _, err := ctx.generateProgCalls(mmapProg, false)
	if err != nil {
		return nil, err
	}

	for _, c := range append(mmapProg.Calls, p.Calls...) {
		ctx.calls[c.Meta.CallName] = c.Meta.NR
	}

	varsBuf := new(bytes.Buffer)
	if len(vars) != 0 {
		fmt.Fprintf(varsBuf, "uint64 r[%v] = {", len(vars))
		for i, v := range vars {
			if i != 0 {
				fmt.Fprintf(varsBuf, ", ")
			}
			fmt.Fprintf(varsBuf, "0x%x", v)
		}
		fmt.Fprintf(varsBuf, "};\n")
	}

	sandboxFunc := "loop();"
	if opts.Sandbox != "" {
		sandboxFunc = "do_sandbox_" + opts.Sandbox + "();"
	}
	replacements := map[string]string{
		"PROCS":           fmt.Sprint(opts.Procs),
		"REPEAT_TIMES":    fmt.Sprint(opts.RepeatTimes),
		"NUM_CALLS":       fmt.Sprint(len(p.Calls)),
		"MMAP_DATA":       strings.Join(mmapCalls, ""),
		"SYSCALL_DEFINES": ctx.generateSyscallDefines(),
		"SANDBOX_FUNC":    sandboxFunc,
		"RESULTS":         varsBuf.String(),
		"SYSCALLS":        ctx.generateSyscalls(calls, len(vars) != 0),
	}
	if !opts.Threaded && !opts.Repeat && opts.Sandbox == "" {
		// This inlines syscalls right into main for the simplest case.
		replacements["SANDBOX_FUNC"] = replacements["SYSCALLS"]
		replacements["SYSCALLS"] = "unused"
	}
	result, err := createCommonHeader(p, mmapProg, replacements, opts)
	if err != nil {
		return nil, err
	}
	const header = "// autogenerated by syzkaller (https://github.com/CvvT/syzkaller)\n\n"
	result = append([]byte(header), result...)
	// Add header required by S2E
	if (opts.S2E) {
		result = append(result, []byte("\n#include <s2e.h>\n")...)
	}
	result = ctx.postProcess(result)
	return result, nil
}

type context struct {
	p         *prog.Prog
	opts      Options
	target    *prog.Target
	sysTarget *targets.Target
	calls     map[string]uint64 // CallName -> NR
	num_vars  uint32
}

func (ctx *context) generateSyscalls(calls []string, hasVars bool) string {
	opts := ctx.opts
	buf := new(bytes.Buffer)
	if !opts.Threaded && !opts.Collide {
		if hasVars || opts.Trace {
			fmt.Fprintf(buf, "\tlong res = 0;\n")
		}
		if opts.Repro {
			fmt.Fprintf(buf, "\tif (write(1, \"executing program\\n\", sizeof(\"executing program\\n\") - 1)) {}\n")
		}
		if opts.Trace {
			fmt.Fprintf(buf, "\tprintf(\"### start\\n\");\n")
		}
		for _, c := range calls {
			fmt.Fprintf(buf, "%s", c)
		}
	} else {
		if hasVars || opts.Trace {
			fmt.Fprintf(buf, "\tlong res;")
		}
		fmt.Fprintf(buf, "\tswitch (call) {\n")
		for i, c := range calls {
			fmt.Fprintf(buf, "\tcase %v:\n", i)
			fmt.Fprintf(buf, "%s", strings.Replace(c, "\t", "\t\t", -1))
			fmt.Fprintf(buf, "\t\tbreak;\n")
		}
		fmt.Fprintf(buf, "\t}\n")
	}
	return buf.String()
}

func (ctx *context) generateSyscallDefines() string {
	var calls []string
	for name, nr := range ctx.calls {
		if !ctx.sysTarget.SyscallNumbers ||
			strings.HasPrefix(name, "syz_") || !ctx.sysTarget.NeedSyscallDefine(nr) {
			continue
		}
		calls = append(calls, name)
	}
	sort.Strings(calls)
	buf := new(bytes.Buffer)
	prefix := ctx.sysTarget.SyscallPrefix
	for _, name := range calls {
		fmt.Fprintf(buf, "#ifndef %v%v\n", prefix, name)
		fmt.Fprintf(buf, "#define %v%v %v\n", prefix, name, ctx.calls[name])
		fmt.Fprintf(buf, "#endif\n")
	}
	if ctx.target.OS == "linux" && ctx.target.PtrSize == 4 {
		// This is a dirty hack.
		// On 32-bit linux mmap translated to old_mmap syscall which has a different signature.
		// mmap2 has the right signature. syz-extract translates mmap to mmap2, do the same here.
		fmt.Fprintf(buf, "#undef __NR_mmap\n")
		fmt.Fprintf(buf, "#define __NR_mmap __NR_mmap2\n")
	}
	return buf.String()
}

func (ctx *context) generateProgCalls(p *prog.Prog, trace bool) ([]string, []uint64, error) {
	exec := make([]byte, prog.ExecBufferSize)
	progSize, err := p.SerializeForExec(exec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize program: %v", err)
	}
	decoded, err := ctx.target.DeserializeExec(exec[:progSize])
	if err != nil {
		return nil, nil, err
	}
	calls, vars := ctx.generateCalls(decoded, trace)
	return calls, vars, nil
}

func (ctx *context) generateCalls(p prog.ExecProg, trace bool) ([]string, []uint64) {
	var calls []string
	csumSeq := 0
	for ci, call := range p.Calls {
		// Retrieve the type information of the system call
		s2e_call := ctx.p.Calls[ci]
		
		w := new(bytes.Buffer)
		// Copyin.
		for _, copyin := range call.Copyin {
			ctx.copyin(w, &csumSeq, copyin)
		}

		if ctx.opts.Fault && ctx.opts.FaultCall == ci {
			fmt.Fprintf(w, "\twrite_file(\"/sys/kernel/debug/failslab/ignore-gfp-wait\", \"N\");\n")
			fmt.Fprintf(w, "\twrite_file(\"/sys/kernel/debug/fail_futex/ignore-private\", \"N\");\n")
			fmt.Fprintf(w, "\tinject_fault(%v);\n", ctx.opts.FaultNth)
		}
		// Call itself.
		callName := call.Meta.CallName
		resCopyout := call.Index != prog.ExecNoCopyout
		argCopyout := len(call.Copyout) != 0
		emitCall := ctx.opts.EnableTun ||
			callName != "syz_emit_ethernet" &&
				callName != "syz_extract_tcp_res"
		// TODO: if we don't emit the call we must also not emit copyin, copyout and fault injection.
		// However, simply skipping whole iteration breaks tests due to unused static functions.
		if emitCall {
			fmt.Printf("res: %v, arg: %v, call: %s\n", resCopyout, argCopyout, call.Meta.CallName)
			// Local variables we need to define
			vars := ctx.emitCall(w, call, ci, resCopyout || argCopyout, trace, *s2e_call)
			calls = append(vars, calls...)
		} else if trace {
			fmt.Fprintf(w, "\t(void)res;\n")
		}

		// Copyout.
		if resCopyout || argCopyout {
			ctx.copyout(w, call, resCopyout)
		}

		calls = append(calls, w.String())
		fmt.Printf("1: %s\n", w.String())
	}
	return calls, p.Vars
}

func (ctx *context) emitCall(ow *bytes.Buffer, call prog.ExecCall, ci int, haveCopyout, trace bool, s2e_call prog.Call) ([]string) {
	var local_vars []string
	w := new(bytes.Buffer)

	callName := call.Meta.CallName
	native := ctx.sysTarget.SyscallNumbers && !strings.HasPrefix(callName, "syz_")
	fmt.Fprintf(w, "\t")
	if haveCopyout || trace {
		fmt.Fprintf(w, "res = ")
	}
	if native {
		fmt.Fprintf(w, "syscall(%v%v", ctx.sysTarget.SyscallPrefix, callName)
	} else if strings.HasPrefix(callName, "syz_") {
		fmt.Fprintf(w, "%v(", callName)
	} else {
		args := strings.Repeat(",long", len(call.Args))
		if args != "" {
			args = args[1:]
		}
		fmt.Fprintf(w, "((long(*)(%v))CAST(%v))(", args, callName)
	}
	for ai, arg := range call.Args {
		if native || ai > 0 {
			fmt.Fprintf(w, ", ")
		}

		if ctx.opts.S2E {
			// Retrieve corresponding argument
			if (callName != "mmap") {
				s2e_arg := s2e_call.Args[ai]
				switch arg:= arg.(type) {
				case prog.ExecArgConst:
					if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
						panic("sring format in syscall argument")
					}
					// vars: local variable definition; val: local variable or real value 
					var_def, val, size := ctx.constArgToVar(arg, s2e_arg, s2e_call.Args)
					if var_def != "" { // we got a meaningful variable 
						local_vars = append(local_vars, var_def)
					}
					if size != "" { // make something symbolic
						switch {
						case strings.HasPrefix(val, "local"):
							fmt.Fprintf(ow, "\ts2e_make_concolic(&%s, %s, \"%s\");\n", val, size, val)
						case strings.HasPrefix(val, "0x"):
							fmt.Fprintf(ow, "\ts2e_make_concolic((void*)%s, %s, \"ptr_%s\");", val, size, val)
						default:
						}
					}
					fmt.Fprintf(w, "%v", val)
				case prog.ExecArgResult:
					if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
						panic("sring format in syscall argument")
					}
					val := ctx.resultArgToStr(arg)
					if native && ctx.target.PtrSize == 4 {
						// syscall accepts args as ellipsis, resources are uint64
						// and take 2 slots without the cast, which would be wrong.
						val = "(long)" + val
					}
					fmt.Fprintf(w, "%v", val)
				default:
					panic(fmt.Sprintf("unknown arg type: %+v", arg))
				}

				continue;
			}
		}

		
		switch arg := arg.(type) {
		case prog.ExecArgConst:
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("sring format in syscall argument")
			}

			fmt.Fprintf(w, "%v", ctx.constArgToStr(arg))
		case prog.ExecArgResult:
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("sring format in syscall argument")
			}
			val := ctx.resultArgToStr(arg)
			if native && ctx.target.PtrSize == 4 {
				// syscall accepts args as ellipsis, resources are uint64
				// and take 2 slots without the cast, which would be wrong.
				val = "(long)" + val
			}
			fmt.Fprintf(w, "%v", val)
		default:
			panic(fmt.Sprintf("unknown arg type: %+v", arg))
		}
	}
	fmt.Fprintf(w, ");\n")
	if trace {
		fmt.Fprintf(w, "\tprintf(\"### call=%v errno=%%u\\n\", res == -1 ? errno : 0);\n", ci)
	}

	fmt.Fprintf(ow, w.String())
	return local_vars
}

func (ctx *context) generateCsumInet(w *bytes.Buffer, addr uint64, arg prog.ExecArgCsum, csumSeq int) {
	fmt.Fprintf(w, "\tstruct csum_inet csum_%d;\n", csumSeq)
	fmt.Fprintf(w, "\tcsum_inet_init(&csum_%d);\n", csumSeq)
	for i, chunk := range arg.Chunks {
		switch chunk.Kind {
		case prog.ExecArgCsumChunkData:
			fmt.Fprintf(w, "\tNONFAILING(csum_inet_update(&csum_%d, (const uint8*)0x%x, %d));\n",
				csumSeq, chunk.Value, chunk.Size)
		case prog.ExecArgCsumChunkConst:
			fmt.Fprintf(w, "\tuint%d csum_%d_chunk_%d = 0x%x;\n",
				chunk.Size*8, csumSeq, i, chunk.Value)
			fmt.Fprintf(w, "\tcsum_inet_update(&csum_%d, (const uint8*)&csum_%d_chunk_%d, %d);\n",
				csumSeq, csumSeq, i, chunk.Size)
		default:
			panic(fmt.Sprintf("unknown checksum chunk kind %v", chunk.Kind))
		}
	}
	fmt.Fprintf(w, "\tNONFAILING(*(uint16*)0x%x = csum_inet_digest(&csum_%d));\n",
		addr, csumSeq)
}

func (ctx *context) copyin(w *bytes.Buffer, csumSeq *int, copyin prog.ExecCopyin) {
	switch arg := copyin.Arg.(type) {
	case prog.ExecArgConst:
		if arg.BitfieldOffset == 0 && arg.BitfieldLength == 0 {
			ctx.copyinVal(w, copyin.Addr, arg.Size, ctx.constArgToStr(arg), arg.Format)
		} else {
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("bitfield+string format")
			}
			fmt.Fprintf(w, "\tNONFAILING(STORE_BY_BITMASK(uint%v, 0x%x, %v, %v, %v));\n",
				arg.Size*8, copyin.Addr, ctx.constArgToStr(arg),
				arg.BitfieldOffset, arg.BitfieldLength)
		}
	case prog.ExecArgResult:
		ctx.copyinVal(w, copyin.Addr, arg.Size, ctx.resultArgToStr(arg), arg.Format)
	case prog.ExecArgData:
		fmt.Fprintf(w, "\tNONFAILING(memcpy((void*)0x%x, \"%s\", %v));\n",
			copyin.Addr, toCString(arg.Data), len(arg.Data))
	case prog.ExecArgCsum:
		switch arg.Kind {
		case prog.ExecArgCsumInet:
			*csumSeq++
			ctx.generateCsumInet(w, copyin.Addr, arg, *csumSeq)
		default:
			panic(fmt.Sprintf("unknown csum kind %v", arg.Kind))
		}
	default:
		panic(fmt.Sprintf("bad argument type: %+v", arg))
	}
}

func (ctx *context) copyinVal(w *bytes.Buffer, addr, size uint64, val string, bf prog.BinaryFormat) {
	switch bf {
	case prog.FormatNative, prog.FormatBigEndian:
		fmt.Fprintf(w, "\tNONFAILING(*(uint%v*)0x%x = %v);\n", size*8, addr, val)
	case prog.FormatStrDec:
		if size != 20 {
			panic("bad strdec size")
		}
		fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)0x%x, \"%%020llu\", (long long)%v));\n", addr, val)
	case prog.FormatStrHex:
		if size != 18 {
			panic("bad strdec size")
		}
		fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)0x%x, \"0x%%016llx\", (long long)%v));\n", addr, val)
	case prog.FormatStrOct:
		if size != 23 {
			panic("bad strdec size")
		}
		fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)0x%x, \"%%023llo\", (long long)%v));\n", addr, val)
	default:
		panic("unknown binary format")
	}
}

func (ctx *context) copyout(w *bytes.Buffer, call prog.ExecCall, resCopyout bool) {
	if ctx.sysTarget.OS == "fuchsia" {
		// On fuchsia we have real system calls that return ZX_OK on success,
		// and libc calls that are casted to function returning long,
		// as the result int -1 is returned as 0x00000000ffffffff rather than full -1.
		if strings.HasPrefix(call.Meta.CallName, "zx_") {
			fmt.Fprintf(w, "\tif (res == ZX_OK)")
		} else {
			fmt.Fprintf(w, "\tif ((int)res != -1)")
		}
	} else {
		fmt.Fprintf(w, "\tif (res != -1)")
	}
	copyoutMultiple := len(call.Copyout) > 1 || resCopyout && len(call.Copyout) > 0
	if copyoutMultiple {
		fmt.Fprintf(w, " {")
	}
	fmt.Fprintf(w, "\n")
	if resCopyout {
		fmt.Fprintf(w, "\t\tr[%v] = res;\n", call.Index)
	}
	for _, copyout := range call.Copyout {
		fmt.Fprintf(w, "\t\tNONFAILING(r[%v] = *(uint%v*)0x%x);\n",
			copyout.Index, copyout.Size*8, copyout.Addr)
	}
	if copyoutMultiple {
		fmt.Fprintf(w, "\t}\n")
	}
}

func (ctx *context) constArgToStr(arg prog.ExecArgConst) string {
	mask := (uint64(1) << (arg.Size * 8)) - 1
	v := arg.Value & mask
	val := fmt.Sprintf("%v", v)
	if v == ^uint64(0)&mask {
		val = "-1"
	} else if v >= 10 {
		val = fmt.Sprintf("0x%x", v)
	}
	if ctx.opts.Procs > 1 && arg.PidStride != 0 {
		val += fmt.Sprintf(" + procid*%v", arg.PidStride)
	}
	if arg.Format == prog.FormatBigEndian {
		val = fmt.Sprintf("htobe%v(%v)", arg.Size*8, val)
	}
	return val
}

func (ctx *context) symoblicSize(s2e_arg *prog.LenType, parent []prog.Arg) (bool) {
	for _, field := range parent {
		if s2e_arg.Buf != field.Type().FieldName() {
			continue
		}
		if inner := prog.InnerArg(field); inner != nil {
			switch targetType := inner.Type().(type) {
			case *prog.BufferType:
				fmt.Printf("BufferType type\n")
				return true
			default:
				fmt.Printf("Type: %v\n", targetType);
			}
		}
	}
	return false
}

func (ctx *context) constArgToVar(arg prog.ExecArgConst, s2e_arg prog.Arg, parent []prog.Arg) (string, string, string) {
	var_name, def, size := "", "", ""
	val := ctx.constArgToStr(arg)

	switch mytype := s2e_arg.Type().(type) {
	// case *prog.StructType:
	// case *prog.UnionType:
	// case *prog.ArrayType:
	// case *prog.CsumType:
	case *prog.ConstType:
		fmt.Printf("Const: %v\n", mytype);
	// case *prog.BufferType:
	// case *VmaType:
	// case *ProcType:
	case *prog.LenType:
		fmt.Printf("Len: %v\n", mytype)
		if (!ctx.symoblicSize(mytype, parent)) {
			break
		}
		var_name = ctx.assignVar()
		def = fmt.Sprintf("\t%s %s = %s;", ctx.gettype(arg), var_name, val)
		val = var_name
		size = ctx.getsize(arg)
	case *prog.ResourceType:
		fmt.Printf("Resource: %v\n", mytype)		
	case *prog.PtrType:
		fmt.Printf("Pointer: %v\n", mytype)
		if mytype.Dir() == prog.DirOut {
			fmt.Printf("Dir: out\n")
			break
		}
		a := s2e_arg.(*prog.PointerArg)
		// Might we need analyse a.Res further. If a.Res is a buffer,
		// it needs special process.
		if a.Res.Size() != 0 {
			size = fmt.Sprintf("%v", a.Res.Size())
		} else {
			size = "32"
		}
	case *prog.FlagsType:
		fmt.Printf("Flags: %v\n", mytype)
	default:
		fmt.Printf("unknown: %v\n", mytype)
	}
	return def, val, size
}

func (ctx *context) assignVar() string {
	ctx.num_vars += 1
	return fmt.Sprintf("local_%d", ctx.num_vars)
}

func (ctx *context) gettype(arg prog.ExecArgConst) string {
	switch arg.Size {
	case 1: return "uint8"
	case 2: return "uint16"
	case 4: return "uint32"
	case 8: return "uint64" //is it ok to use 32bit integer?
	default:
		panic("unknown size")
		return ""
	}
}

func (ctx *context) getsize(arg prog.ExecArgConst) string {
	switch arg.Size {
	case 1: return  "1"
	case 2: return "2"
	case 4: return "4"
	case 8: return "8" //is it ok to use 32bit integer?
	default:
		panic("unknown size")
		return ""
	}
}

func (ctx *context) resultArgToStr(arg prog.ExecArgResult) string {
	res := fmt.Sprintf("r[%v]", arg.Index)
	if arg.DivOp != 0 {
		res = fmt.Sprintf("%v/%v", res, arg.DivOp)
	}
	if arg.AddOp != 0 {
		res = fmt.Sprintf("%v+%v", res, arg.AddOp)
	}
	if arg.Format == prog.FormatBigEndian {
		res = fmt.Sprintf("htobe%v(%v)", arg.Size*8, res)
	}
	return res
}

func (ctx *context) postProcess(result []byte) []byte {
	// Remove NONFAILING, debug, fail, etc calls.
	if !ctx.opts.HandleSegv {
		result = regexp.MustCompile(`\t*NONFAILING\((.*)\);\n`).ReplaceAll(result, []byte("$1;\n"))
	}
	result = bytes.Replace(result, []byte("NORETURN"), nil, -1)
	result = bytes.Replace(result, []byte("PRINTF"), nil, -1)
	result = bytes.Replace(result, []byte("doexit("), []byte("exit("), -1)
	result = regexp.MustCompile(`\t*debug\((.*\n)*?.*\);\n`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*debug_dump_data\((.*\n)*?.*\);\n`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*exitf\((.*\n)*?.*\);\n`).ReplaceAll(result, []byte("\texit(1);\n"))
	result = regexp.MustCompile(`\t*fail\((.*\n)*?.*\);\n`).ReplaceAll(result, []byte("\texit(1);\n"))
	result = regexp.MustCompile(`\t*error\((.*\n)*?.*\);\n`).ReplaceAll(result, []byte("\texit(1);\n"))

	result = ctx.hoistIncludes(result)
	result = ctx.removeEmptyLines(result)
	return result
}

// hoistIncludes moves all includes to the top, removes dups and sorts.
func (ctx *context) hoistIncludes(result []byte) []byte {
	includesStart := bytes.Index(result, []byte("#include"))
	if includesStart == -1 {
		return result
	}
	includes := make(map[string]bool)
	includeRe := regexp.MustCompile("#include <.*>\n")
	for _, match := range includeRe.FindAll(result, -1) {
		includes[string(match)] = true
	}
	result = includeRe.ReplaceAll(result, nil)
	// Linux headers are broken, so we have to move all linux includes to the bottom.
	var sorted, sortedLinux []string
	for include := range includes {
		if strings.Contains(include, "<linux/") {
			sortedLinux = append(sortedLinux, include)
		} else {
			sorted = append(sorted, include)
		}
	}
	sort.Strings(sorted)
	sort.Strings(sortedLinux)
	newResult := append([]byte{}, result[:includesStart]...)
	newResult = append(newResult, strings.Join(sorted, "")...)
	newResult = append(newResult, '\n')
	newResult = append(newResult, strings.Join(sortedLinux, "")...)
	newResult = append(newResult, result[includesStart:]...)
	return newResult
}

// removeEmptyLines removes duplicate new lines.
func (ctx *context) removeEmptyLines(result []byte) []byte {
	for {
		newResult := bytes.Replace(result, []byte{'\n', '\n', '\n'}, []byte{'\n', '\n'}, -1)
		newResult = bytes.Replace(newResult, []byte{'\n', '\n', '\t'}, []byte{'\n', '\t'}, -1)
		newResult = bytes.Replace(newResult, []byte{'\n', '\n', ' '}, []byte{'\n', ' '}, -1)
		if len(newResult) == len(result) {
			return result
		}
		result = newResult
	}
}

func toCString(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	readable := true
	for i, v := range data {
		// Allow 0 only as last byte.
		if !isReadable(v) && (i != len(data)-1 || v != 0) {
			readable = false
			break
		}
	}
	if !readable {
		buf := new(bytes.Buffer)
		for _, v := range data {
			buf.Write([]byte{'\\', 'x', toHex(v >> 4), toHex(v << 4 >> 4)})
		}
		return buf.Bytes()
	}
	if data[len(data)-1] == 0 {
		// Don't serialize last 0, C strings are 0-terminated anyway.
		data = data[:len(data)-1]
	}
	buf := new(bytes.Buffer)
	for _, v := range data {
		switch v {
		case '\t':
			buf.Write([]byte{'\\', 't'})
		case '\r':
			buf.Write([]byte{'\\', 'r'})
		case '\n':
			buf.Write([]byte{'\\', 'n'})
		case '\\':
			buf.Write([]byte{'\\', '\\'})
		case '"':
			buf.Write([]byte{'\\', '"'})
		default:
			if v < 0x20 || v >= 0x7f {
				panic("unexpected char during data serialization")
			}
			buf.WriteByte(v)
		}
	}
	return buf.Bytes()
}

func isReadable(v byte) bool {
	return v >= 0x20 && v < 0x7f || v == '\t' || v == '\r' || v == '\n'
}

func toHex(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'a' + v - 10
}
