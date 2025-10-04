package main

import "fmt"

// Test 1: Simple interface
type Reader interface {
	Read(p []byte) (n int, err error)
}

// Test 2: Interface with multiple methods
type Writer interface {
	Write(p []byte) (n int, err error)
	Flush() error
	Close() error
}

// Test 3: Embedded interfaces
type ReadWriter interface {
	Reader
	Writer
}

// Test 4: Interface with various parameter types
type DataStore interface {
	Get(key string) (value interface{}, found bool)
	Set(key string, value interface{}) error
	Delete(key string) error
	Keys() []string
}

// Test 5: Interface with struct parameters
type Point struct {
	X, Y int
}

type Shape interface {
	Area() float64
	Perimeter() float64
	Contains(p Point) bool
	Move(dx, dy int)
}

// Test 6: Empty interface (interface{})
type Container struct {
	Data interface{}
}

// Concrete implementations
type Buffer struct {
	data []byte
	pos  int
}

func (b *Buffer) Read(p []byte) (int, error) {
	return 0, nil
}

func (b *Buffer) Write(p []byte) (int, error) {
	return 0, nil
}

func (b *Buffer) Flush() error {
	return nil
}

func (b *Buffer) Close() error {
	return nil
}

type Rectangle struct {
	Width  float64
	Height float64
}

func (r *Rectangle) Area() float64 {
	return r.Width * r.Height
}

func (r *Rectangle) Perimeter() float64 {
	return 2 * (r.Width + r.Height)
}

func (r *Rectangle) Contains(p Point) bool {
	return false
}

func (r *Rectangle) Move(dx, dy int) {
}

func main() {
	// Use interfaces
	var reader Reader = &Buffer{}
	var writer Writer = &Buffer{}
	var rw ReadWriter = &Buffer{}
	var shape Shape = &Rectangle{Width: 10, Height: 20}

	fmt.Printf("Reader: %v\n", reader)
	fmt.Printf("Writer: %v\n", writer)
	fmt.Printf("ReadWriter: %v\n", rw)
	fmt.Printf("Shape area: %v\n", shape.Area())

	// Empty interface
	container := Container{Data: "anything"}
	fmt.Printf("Container: %+v\n", container)
}
