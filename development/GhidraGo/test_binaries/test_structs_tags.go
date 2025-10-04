package main

import (
	"encoding/json"
	"fmt"
)

// Test 1: Struct with JSON tags
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Active   bool   `json:"active"`
}

// Test 2: Struct with multiple tag types
type ComplexTags struct {
	Field1 string `json:"field1" xml:"field1" db:"field1"`
	Field2 int    `json:"field2,omitempty" xml:"field2,attr"`
	Field3 bool   `json:"-" xml:"field3"`
}

// Test 3: Nested struct with tags
type Address struct {
	Street  string `json:"street"`
	City    string `json:"city"`
	ZipCode string `json:"zip_code"`
}

type UserWithAddress struct {
	ID      int      `json:"id"`
	Name    string   `json:"name"`
	Address *Address `json:"address,omitempty"`
}

// Test 4: Struct with validation tags (common in libraries)
type ValidatedStruct struct {
	Email    string `json:"email" validate:"required,email"`
	Age      int    `json:"age" validate:"gte=0,lte=150"`
	Username string `json:"username" validate:"required,min=3,max=32"`
}

func main() {
	user := User{
		ID:       1,
		Username: "alice",
		Email:    "alice@example.com",
		Active:   true,
	}

	addr := Address{
		Street:  "123 Main St",
		City:    "Springfield",
		ZipCode: "12345",
	}

	userAddr := UserWithAddress{
		ID:      2,
		Name:    "Bob",
		Address: &addr,
	}

	validated := ValidatedStruct{
		Email:    "test@example.com",
		Age:      25,
		Username: "testuser",
	}

	// Use JSON encoding to ensure tags are preserved in binary
	jsonData, _ := json.Marshal(user)
	fmt.Printf("User JSON: %s\n", jsonData)

	jsonData2, _ := json.Marshal(userAddr)
	fmt.Printf("UserWithAddress JSON: %s\n", jsonData2)

	fmt.Printf("Validated: %+v\n", validated)
}
