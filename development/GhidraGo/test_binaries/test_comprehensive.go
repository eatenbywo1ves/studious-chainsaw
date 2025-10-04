package main

import (
	"encoding/json"
	"fmt"
)

// Comprehensive test combining all Phase 2 features

// 1. Simple structs with primitives
type Config struct {
	Port    int    `json:"port"`
	Host    string `json:"host"`
	Enabled bool   `json:"enabled"`
}

// 2. Nested structs with tags
type Address struct {
	Street  string `json:"street"`
	City    string `json:"city"`
	ZipCode string `json:"zip_code"`
	Country string `json:"country,omitempty"`
}

type ContactInfo struct {
	Email   string   `json:"email" validate:"required,email"`
	Phone   string   `json:"phone"`
	Address *Address `json:"address,omitempty"`
}

// 3. Struct with embedded fields and tags
type Timestamps struct {
	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

type User struct {
	Timestamps          // Embedded
	ID         int      `json:"id"`
	Username   string   `json:"username"`
	Contact    *ContactInfo `json:"contact,omitempty"`
	Roles      []string `json:"roles"`
}

// 4. Circular references (linked data structures)
type TreeNode struct {
	Value    int
	Children []*TreeNode
	Parent   *TreeNode
}

// 5. Complex interfaces
type Repository interface {
	Get(id int) (interface{}, error)
	Save(entity interface{}) error
	Delete(id int) error
	List() []interface{}
}

type Validator interface {
	Validate() error
	IsValid() bool
}

// 6. Struct implementing interfaces
type UserRepository struct {
	Data map[int]*User
}

func (r *UserRepository) Get(id int) (interface{}, error) {
	return r.Data[id], nil
}

func (r *UserRepository) Save(entity interface{}) error {
	return nil
}

func (r *UserRepository) Delete(id int) error {
	delete(r.Data, id)
	return nil
}

func (r *UserRepository) List() []interface{} {
	return nil
}

// 7. Complex nested structure with all features
type Application struct {
	Timestamps                   // Embedded with tags
	Config     Config            `json:"config"`
	Users      map[int]*User     `json:"users"`
	Repository Repository         `json:"-"`
	RootNode   *TreeNode         `json:"tree,omitempty"`
	Metadata   map[string]string `json:"metadata"`
}

// 8. Struct with slices of various types
type DataCollection struct {
	Integers   []int            `json:"integers"`
	Strings    []string         `json:"strings"`
	Users      []*User          `json:"users"`
	Addresses  []Address        `json:"addresses"`
	Interfaces []interface{}    `json:"interfaces"`
	ByteData   []byte           `json:"byte_data"`
}

// 9. Struct with maps
type Cache struct {
	StringMap  map[string]string      `json:"string_map"`
	IntMap     map[int]int            `json:"int_map"`
	StructMap  map[string]*User       `json:"struct_map"`
	InterfaceMap map[string]interface{} `json:"interface_map"`
}

// 10. Struct with function fields (for advanced testing)
type Callbacks struct {
	OnStart  func() error
	OnStop   func() error
	OnUpdate func(data interface{}) error
}

func main() {
	// Create comprehensive test data
	addr := &Address{
		Street:  "123 Main St",
		City:    "Springfield",
		ZipCode: "12345",
		Country: "USA",
	}

	contact := &ContactInfo{
		Email:   "alice@example.com",
		Phone:   "555-1234",
		Address: addr,
	}

	user := &User{
		Timestamps: Timestamps{CreatedAt: 1000, UpdatedAt: 2000},
		ID:         1,
		Username:   "alice",
		Contact:    contact,
		Roles:      []string{"admin", "user"},
	}

	config := Config{
		Port:    8080,
		Host:    "localhost",
		Enabled: true,
	}

	repo := &UserRepository{
		Data: make(map[int]*User),
	}
	repo.Data[1] = user

	tree := &TreeNode{Value: 10}
	tree.Children = []*TreeNode{
		{Value: 5, Parent: tree},
		{Value: 15, Parent: tree},
	}

	app := &Application{
		Timestamps: Timestamps{CreatedAt: 5000, UpdatedAt: 6000},
		Config:     config,
		Users:      repo.Data,
		Repository: repo,
		RootNode:   tree,
		Metadata:   map[string]string{"version": "1.0", "env": "production"},
	}

	collection := &DataCollection{
		Integers:  []int{1, 2, 3, 4, 5},
		Strings:   []string{"a", "b", "c"},
		Users:     []*User{user},
		Addresses: []Address{*addr},
		Interfaces: []interface{}{"string", 42, true},
		ByteData:  []byte{0x01, 0x02, 0x03},
	}

	cache := &Cache{
		StringMap:    map[string]string{"key1": "value1"},
		IntMap:       map[int]int{1: 100, 2: 200},
		StructMap:    map[string]*User{"alice": user},
		InterfaceMap: map[string]interface{}{"mixed": "data"},
	}

	// Output JSON to preserve tags in binary
	jsonData, _ := json.MarshalIndent(app, "", "  ")
	fmt.Printf("Application:\n%s\n", jsonData)

	fmt.Printf("\nCollection: %d items\n", len(collection.Integers))
	fmt.Printf("Cache: %d string entries\n", len(cache.StringMap))

	// Use interfaces to ensure they're in the binary
	var validator Validator
	fmt.Printf("Validator: %v\n", validator)

	// Ensure all types are referenced
	_ = app
	_ = collection
	_ = cache
	_ = tree
	_ = contact
}
