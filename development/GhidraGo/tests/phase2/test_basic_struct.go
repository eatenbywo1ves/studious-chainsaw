// test_basic_struct.go - Test basic struct field parsing
// Tests: field names, types, offsets, tags
package main

import "fmt"

// User struct with various field types and tags
type User struct {
	ID       int64  `json:"id" db:"user_id"`
	Name     string `json:"name"`
	Age      int    `json:"age"`
	Active   bool   `json:"active"`
	Balance  float64
	Password []byte
}

// Point struct with primitive types
type Point struct {
	X int32
	Y int32
}

// Config struct with nested struct
type Config struct {
	Host     string
	Port     int
	Location Point
}

func main() {
	user := User{
		ID:      1,
		Name:    "Alice",
		Age:     30,
		Active:  true,
		Balance: 1000.50,
	}

	config := Config{
		Host: "localhost",
		Port: 8080,
		Location: Point{
			X: 100,
			Y: 200,
		},
	}

	fmt.Printf("User: %+v\n", user)
	fmt.Printf("Config: %+v\n", config)
}
