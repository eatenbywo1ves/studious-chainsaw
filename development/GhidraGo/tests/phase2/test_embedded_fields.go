// test_embedded_fields.go - Test embedded struct fields
// Tests: embedded fields, field promotion
package main

import "fmt"

// Base struct to be embedded
type Base struct {
	ID        int64
	CreatedAt string
	UpdatedAt string
}

// Metadata to be embedded
type Metadata struct {
	Tags    []string
	Version int
}

// Article with embedded fields
type Article struct {
	Base              // Embedded - fields promoted
	Metadata          // Embedded - fields promoted
	Title      string
	Content    string
	Author     *User
}

// User referenced by Article
type User struct {
	Base          // Embedded Base
	Username string
	Email    string
}

// TimestampMixin - Another embeddable type
type TimestampMixin struct {
	Created int64
	Updated int64
}

// Product with multiple embedded types
type Product struct {
	TimestampMixin    // Embedded
	Name        string
	Price       float64
	Category    string
	InStock     bool
}

// Address - To be embedded in Customer
type Address struct {
	Street  string
	City    string
	ZipCode string
}

// Customer with named embedded field
type Customer struct {
	ID              int
	Name            string
	ShippingAddress Address // Named, not promoted
	BillingAddress  Address // Named, not promoted
}

func main() {
	article := Article{
		Base: Base{
			ID:        1,
			CreatedAt: "2024-01-01",
		},
		Metadata: Metadata{
			Tags:    []string{"tech", "golang"},
			Version: 1,
		},
		Title:   "Go Type Extraction",
		Content: "...",
	}

	product := Product{
		TimestampMixin: TimestampMixin{
			Created: 1234567890,
			Updated: 1234567900,
		},
		Name:     "Widget",
		Price:    99.99,
		InStock:  true,
	}

	fmt.Printf("Article: %+v\n", article)
	fmt.Printf("Product: %+v\n", product)
}
