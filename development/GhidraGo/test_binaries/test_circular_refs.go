package main

import "fmt"

// Test 1: Linked list (simple circular reference)
type Node struct {
	Data int
	Next *Node
}

// Test 2: Doubly linked list (bi-directional circular reference)
type DNode struct {
	Data int
	Next *DNode
	Prev *DNode
}

// Test 3: Binary tree (self-referential with two pointers)
type TreeNode struct {
	Value int
	Left  *TreeNode
	Right *TreeNode
}

// Test 4: Mutual circular reference (A -> B -> A)
type TypeA struct {
	ID   int
	RefB *TypeB
}

type TypeB struct {
	Name string
	RefA *TypeA
}

// Test 5: Circular reference through slice
type Graph struct {
	ID        int
	Neighbors []*Graph
}

// Test 6: Complex nested circular reference
type Parent struct {
	Name     string
	Children []*Child
}

type Child struct {
	Name   string
	Parent *Parent
}

// Test 7: Self-referential interface
type TreeInterface interface {
	GetValue() int
	GetLeft() TreeInterface
	GetRight() TreeInterface
}

type TreeImpl struct {
	Value int
	Left  TreeInterface
	Right TreeInterface
}

func (t *TreeImpl) GetValue() int {
	return t.Value
}

func (t *TreeImpl) GetLeft() TreeInterface {
	return t.Left
}

func (t *TreeImpl) GetRight() TreeInterface {
	return t.Right
}

func main() {
	// Create linked list
	node1 := &Node{Data: 1}
	node2 := &Node{Data: 2}
	node3 := &Node{Data: 3}
	node1.Next = node2
	node2.Next = node3
	// Create cycle
	node3.Next = node1

	fmt.Printf("Linked list with cycle: %d -> %d -> %d -> ...\n",
		node1.Data, node1.Next.Data, node1.Next.Next.Data)

	// Create binary tree
	root := &TreeNode{Value: 10}
	root.Left = &TreeNode{Value: 5}
	root.Right = &TreeNode{Value: 15}

	fmt.Printf("Tree root: %d\n", root.Value)

	// Mutual reference
	a := &TypeA{ID: 1}
	b := &TypeB{Name: "B"}
	a.RefB = b
	b.RefA = a

	fmt.Printf("Mutual ref: A.ID=%d, B.Name=%s\n", a.ID, b.Name)

	// Graph with cycles
	g1 := &Graph{ID: 1}
	g2 := &Graph{ID: 2}
	g3 := &Graph{ID: 3}
	g1.Neighbors = []*Graph{g2, g3}
	g2.Neighbors = []*Graph{g1, g3}
	g3.Neighbors = []*Graph{g1, g2}

	fmt.Printf("Graph with %d nodes\n", len(g1.Neighbors))

	// Parent-child
	parent := &Parent{Name: "Parent"}
	child1 := &Child{Name: "Child1", Parent: parent}
	child2 := &Child{Name: "Child2", Parent: parent}
	parent.Children = []*Child{child1, child2}

	fmt.Printf("Parent with %d children\n", len(parent.Children))
}
