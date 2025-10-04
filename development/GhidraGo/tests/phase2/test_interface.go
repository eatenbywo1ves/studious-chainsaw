// test_interface.go - Test interface method parsing
// Tests: interface methods, method signatures
package main

import "fmt"

// Handler interface with multiple methods
type Handler interface {
	ServeHTTP(req *Request) Response
	Close() error
	Status() int
}

// Reader interface
type Reader interface {
	Read(p []byte) (n int, err error)
}

// Writer interface
type Writer interface {
	Write(p []byte) (n int, err error)
}

// ReadWriter embedded interfaces
type ReadWriter interface {
	Reader
	Writer
}

// Request struct used in Handler
type Request struct {
	Method string
	URL    string
	Body   []byte
}

// Response struct used in Handler
type Response struct {
	Status int
	Body   []byte
}

// HTTPHandler implements Handler interface
type HTTPHandler struct {
	name string
}

func (h *HTTPHandler) ServeHTTP(req *Request) Response {
	return Response{Status: 200, Body: []byte("OK")}
}

func (h *HTTPHandler) Close() error {
	return nil
}

func (h *HTTPHandler) Status() int {
	return 200
}

func main() {
	handler := &HTTPHandler{name: "test"}
	req := &Request{Method: "GET", URL: "/", Body: nil}
	resp := handler.ServeHTTP(req)

	fmt.Printf("Response: %+v\n", resp)
}
