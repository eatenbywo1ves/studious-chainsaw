// test_nested_types.go - Test nested type resolution and circular references
// Tests: nested structs, pointers, circular references
package main

import "fmt"

// Node - Linked list node (circular reference)
type Node struct {
	Data int
	Next *Node
}

// Tree - Binary tree node (circular reference)
type Tree struct {
	Value int
	Left  *Tree
	Right *Tree
}

// Company - Nested struct with multiple levels
type Company struct {
	Name      string
	Employees []Employee
	CEO       *Employee
}

// Employee - Referenced by Company
type Employee struct {
	ID        int
	Name      string
	Manager   *Employee // Self-reference
	Team      *Team
	Projects  []*Project
}

// Team - Nested in Employee
type Team struct {
	Name    string
	Lead    *Employee
	Members []*Employee
}

// Project - Referenced by Employee
type Project struct {
	Name     string
	Owner    *Employee
	Duration int
}

// Container - Various pointer and slice types
type Container struct {
	IntPtr      *int
	StrPtr      *string
	IntSlice    []int
	StrSlice    []string
	PtrSlice    []*Node
	NestedSlice [][]int
}

func main() {
	// Create linked list
	node1 := &Node{Data: 1}
	node2 := &Node{Data: 2}
	node3 := &Node{Data: 3}
	node1.Next = node2
	node2.Next = node3

	// Create tree
	tree := &Tree{
		Value: 10,
		Left:  &Tree{Value: 5},
		Right: &Tree{Value: 15},
	}

	// Create company structure
	ceo := &Employee{ID: 1, Name: "Alice"}
	company := Company{
		Name: "Tech Corp",
		CEO:  ceo,
	}

	fmt.Printf("Node: %+v\n", node1)
	fmt.Printf("Tree: %+v\n", tree)
	fmt.Printf("Company: %+v\n", company)
}
