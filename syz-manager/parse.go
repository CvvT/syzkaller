package main

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"strconv"

	"github.com/CvvT/syzkaller/prog"
	_ "github.com/CvvT/syzkaller/sys" //init

)

type Mem struct {
	mems []Obj
	root *Node
}

type Node struct {
	mem   Obj
	left  *Node
	right *Node
}

type Obj struct {
	operation  string
	start_addr uint64
	size       uint64
	base_addr  uint64
}


func AnalyzeReport(data []byte) ([]Obj) {

	target, err := prog.GetTarget("linux", runtime.GOARCH)
	if err != nil {
		fmt.Printf("%v", err)
	}

	// Extract executed program
	var entries []*prog.LogEntry
	entries = target.ParseLog(data)
	// The last one is what we want
	if (len(entries) != 0) {
		fmt.Printf("Prog %s", entries[len(entries)-1].P.Serialize())
	}

	cont := string(data)
	writes := &Mem{make([]Obj, 0), nil}
	pieces := strings.Split(cont, "==================================================================")
	for _, each := range pieces[1:] {
		analyze(each, writes)
	}

	// for _, each := range writes.mems {
	// 	fmt.Printf("%s %x %d\n", each.operation, each.start_addr, each.size)
	// }

	writes.insert()
	// writes.root.print()
	// fmt.Printf("-------------\n")

	writes.merge()
	writes.root.print()
	// writes.root.singleprint()

	results := make([]Obj, 0)
	writes.root.collect(&results)
	// fmt.Printf("%v", results)
	return results
}

func analyze(block string, results *Mem) (string) {
	lines := strings.Split(block, "\n")
	length := len(lines)
	if length <= 5 {
		return ""
	}
	// fmt.Printf("Analyze One Block\n")
	base_addr := getObject(block)
	
	// fmt.Printf("Cause: %s\n", lines[1])
	cause, addr := getcause(lines[1])
	// fmt.Printf("%s , %x\n", cause, addr)
	if addr == 0 {
		fmt.Printf("Warn: %s\n", lines[1])
	}

	operation, size := getsize(lines[2])
	// fmt.Printf("%s , %x\n", operation, size)
	if size == 0 {
		fmt.Printf("Warn: %s\n", lines[2])
	}
	if operation == "Write" {
		results.mems = append(results.mems, Obj{operation, addr, size, base_addr})
	}
	// fmt.Printf("Size: %s\n", lines[2])
	return cause
}

func getObject(block string) (uint64) {
	r, err := regexp.Compile("Object at ([a-f0-9]+)")
	if err != nil {
		fmt.Print("Compile error")
		return 0
	}
	match := r.FindStringSubmatch(block)
	if len(match) < 2 {
		return 0
	}
	addr, err := strconv.ParseUint(match[1], 16, 64)
	if err != nil {
		fmt.Printf("ParseInt error %s\n", err)
		return 0
	}
	// fmt.Printf("Object: %x\n", addr)
	return addr
}

func getcause(line string) (string, uint64) {
	r, err := regexp.Compile("BUG: KASAN: ([a-z-]+) .+ addr ([a-f0-9]+)")
	if err != nil {
		fmt.Print("Compile error")
		return "", 0
	}
	match := r.FindStringSubmatch(line)
	if len(match) <= 2 {
		return "", 0
	}
	addr, err := strconv.ParseUint(match[2], 16, 64)
	if err != nil {
		fmt.Printf("ParseInt error %s\n", err)
		return "", 0
	}
	return match[1], addr

}

func getsize(line string) (string, uint64) {
	r, err := regexp.Compile("(Write|Read) of size (\\d+)")
	if err != nil {
		fmt.Print("Compile error")
		return "", 0
	}
	match := r.FindStringSubmatch(line)
	if len(match) <= 2 {
		return "", 0
	}
	size, err := strconv.ParseUint(match[2], 10, 64)
	if err != nil {
		fmt.Printf("ParseInt error %s\n", err)
		return "", 0
	}
	return match[1], size
}

func (M *Mem) insert() {
	for _, obj := range M.mems {
		if M.root == nil {
			M.root = &Node{obj, nil, nil}
		} else {
			M.root.insert(obj)
		}
	}
}

func (M *Mem) merge() {
	if M.root != nil {
		M.root.merge()
	}
}


func (node *Node) insert(obj Obj) (*Node) {
	if node == nil {
		return &Node{obj, nil, nil}
	}

	switch root := &node.mem; true {
	case root.start_addr == obj.start_addr + obj.size:
		root.start_addr = obj.start_addr
		root.size += obj.size
	case obj.start_addr == root.start_addr + root.size:
		root.size += obj.size
	case root.start_addr > obj.start_addr + obj.size:
		node.left = node.left.insert(obj)
	case obj.start_addr > root.start_addr + root.size:
		node.right = node.right.insert(obj)
	}
	return node
}

func (node *Node) merge() {
	if node == nil {
		return
	}

	if node.left != nil {
		left := node.left
		left.merge()
		if left.mem.start_addr + left.mem.size == node.mem.start_addr {
			node.mem.start_addr = left.mem.start_addr
			node.mem.size += left.mem.size
			node.left = left.left
		} else {
			right := left.right
			parent := left
			for right != nil {
				if right.mem.start_addr + right.mem.size == node.mem.start_addr {
					node.mem.start_addr = right.mem.start_addr
					node.mem.size += right.mem.size
					parent.right = right.left
					break
				}
				parent = right
				right = right.right
			}
		}
	}

	if node.right != nil {
		right := node.right
		right.merge()
		if node.mem.start_addr + node.mem.size == right.mem.start_addr {
			node.mem.size += right.mem.size
			node.right = right.right
		} else {
			left := right.left
			parent := right
			for left != nil {
				if node.mem.start_addr + node.mem.size == left.mem.start_addr {
					node.mem.size += left.mem.size
					parent.left = left.right
					break
				}
				parent = left
				left = left.left
			}
		}
	}
}

func (node *Node) collect(results *[]Obj) {
	if node == nil {
		return
	}

	node.left.collect(results)
	*results = append(*results, node.mem)
	node.right.collect(results)
}

func (node *Node) print() {
	if node == nil {
		return
	}

	node.left.print()
	fmt.Printf("addr:%x size: %d base: %x\n", node.mem.start_addr, node.mem.size, node.mem.base_addr)
	node.right.print()
}

func (node *Node) singleprint() {
	fmt.Printf("[+]addr:%x size: %d base: %x\n", node.mem.start_addr, node.mem.size, node.mem.base_addr)
}

func CompareReport(a []Obj, b []Obj) (bool) {
	var atotal, btotal uint64 
	for _, mem := range a {
		atotal += mem.size
	}

	for _, mem := range b {
		btotal += mem.size
	}

	fmt.Printf("Compare %d %d\n", atotal, btotal)
	return atotal == btotal
}