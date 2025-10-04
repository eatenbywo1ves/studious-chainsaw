package main

import "fmt"

// Test 1: Simple embedded field
type Base struct {
	ID   int
	Name string
}

type Derived struct {
	Base  // Embedded field (anonymous)
	Extra string
}

// Test 2: Multiple embedded fields
type Timestamp struct {
	CreatedAt int64
	UpdatedAt int64
}

type Metadata struct {
	Version int
	Author  string
}

type Document struct {
	Timestamp // Embedded
	Metadata  // Embedded
	Content   string
}

// Test 3: Embedded pointer field
type Logger struct {
	Level string
}

type Service struct {
	*Logger // Embedded pointer
	Name    string
	Port    int
}

// Test 4: Mix of embedded and regular fields
type Entity struct {
	ID int
}

type AuditInfo struct {
	CreatedBy string
	UpdatedBy string
}

type MixedEntity struct {
	Entity    // Embedded
	AuditInfo // Embedded
	Data      string
	Count     int
}

// Test 5: Nested embedded fields
type Level1 struct {
	L1Field string
}

type Level2 struct {
	Level1  // Embedded
	L2Field string
}

type Level3 struct {
	Level2  // Embedded (contains embedded Level1)
	L3Field string
}

func main() {
	// Test simple embedding
	d := Derived{
		Base:  Base{ID: 1, Name: "test"},
		Extra: "extra",
	}
	fmt.Printf("Derived: ID=%d, Name=%s, Extra=%s\n", d.ID, d.Name, d.Extra)

	// Test multiple embedding
	doc := Document{
		Timestamp: Timestamp{CreatedAt: 1000, UpdatedAt: 2000},
		Metadata:  Metadata{Version: 1, Author: "Alice"},
		Content:   "Hello",
	}
	fmt.Printf("Document: %+v\n", doc)

	// Test embedded pointer
	logger := &Logger{Level: "INFO"}
	svc := Service{
		Logger: logger,
		Name:   "api",
		Port:   8080,
	}
	fmt.Printf("Service: %+v\n", svc)

	// Test mixed
	mixed := MixedEntity{
		Entity:    Entity{ID: 42},
		AuditInfo: AuditInfo{CreatedBy: "admin", UpdatedBy: "user"},
		Data:      "data",
		Count:     10,
	}
	fmt.Printf("Mixed: %+v\n", mixed)

	// Test nested
	l3 := Level3{
		Level2:  Level2{Level1: Level1{L1Field: "L1"}, L2Field: "L2"},
		L3Field: "L3",
	}
	fmt.Printf("Level3: %+v\n", l3)
}
