package csource 

import (
	"strings"
	"strconv"
)
// size, allocation site, dereference site
type Fengshui struct {
	HeapObj []HeapObject `json:"heapobj"`
}

type HeapObject struct {
	Sizes     map[string]string	`json:"sizes"`
	VarLen	  bool				`json:"varlen"`
	Name	  string			`json:"name"`
	Allocator string 			`json:"allocator"`
}

type HeapExploit struct {
	Answer	  	string	`json:"answer"`
	Directory	string	`json:"fengshui"`
	VulSize		int		`json:"vulsize"`
	VulAlloc	string	`json:"vulalloc"`
	TgtSize		int		`json:"tgtsize"`
	TgtAlloc	string 	`json:"tgtalloc"`
	Version 	string  `json:"version"`
}

func getVersion(version string) []int {
	var nums []int
	vers := strings.Split(version, ".")
	if len(vers) != 3 {
		panic("Wrong version configuration")
	}
	for _, each := range vers {
		num, err := strconv.Atoi(each)
		if err != nil {
			panic("Wrong version")
		}
		nums = append(nums, num)
	}
	return nums
}

// a less than or equal to b
func compareVersion(a []int, b []int) bool {
	for i := 0; i < 3; i++ {
		if a[i] > b[i] {
			return false
		}
	}
	return true
}