package main

import "fmt"

// Test 1: Simple struct with primitive fields
type SimpleStruct struct {
	ID      int
	Count   int32
	Flag    bool
	Value   float64
}

// Test 2: Struct with string field
type WithString struct {
	Name string
	Age  int
}

// Test 3: Struct with pointer fields
type WithPointers struct {
	IntPtr    *int
	StringPtr *string
	StructPtr *SimpleStruct
}

// Test 4: Struct with slice fields
type WithSlices struct {
	Numbers []int
	Names   []string
	Structs []SimpleStruct
}

// Test 5: Struct with array fields
type WithArrays struct {
	FixedInts    [10]int
	FixedStrings [5]string
}

func main() {
	// Create instances to ensure types are used
	s1 := SimpleStruct{ID: 1, Count: 100, Flag: true, Value: 3.14}
	s2 := WithString{Name: "Alice", Age: 30}

	num := 42
	str := "test"
	s3 := WithPointers{IntPtr: &num, StringPtr: &str, StructPtr: &s1}

	s4 := WithSlices{
		Numbers: []int{1, 2, 3},
		Names:   []string{"a", "b"},
		Structs: []SimpleStruct{s1},
	}

	s5 := WithArrays{
		FixedInts:    [10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		FixedStrings: [5]string{"a", "b", "c", "d", "e"},
	}

	fmt.Printf("s1=%v, s2=%v, s3=%v, s4=%v, s5=%v\n", s1, s2, s3, s4, s5)
}
