# Test Binary Compilation Instructions

## Prerequisites

**Go Compiler Required**
- Download from: https://golang.org/dl/
- Recommended version: Go 1.20 or later
- Ensure `go` is in your PATH

## Quick Start

### Option 1: Automated Build (Windows)
```batch
cd C:\Users\Corbin\development\GhidraGo\test_binaries
build_tests.bat
```

This will compile all 6 test programs for both Windows and Linux (amd64).

### Option 2: Manual Compilation

**Compile for Windows (amd64):**
```batch
set GOOS=windows
set GOARCH=amd64

go build -o windows_amd64\test_structs_simple.exe test_structs_simple.go
go build -o windows_amd64\test_structs_tags.exe test_structs_tags.go
go build -o windows_amd64\test_embedded_fields.exe test_embedded_fields.go
go build -o windows_amd64\test_interfaces.exe test_interfaces.go
go build -o windows_amd64\test_circular_refs.exe test_circular_refs.go
go build -o windows_amd64\test_comprehensive.exe test_comprehensive.go
```

**Compile for Linux (amd64):**
```batch
set GOOS=linux
set GOARCH=amd64

go build -o linux_amd64\test_structs_simple test_structs_simple.go
go build -o linux_amd64\test_structs_tags test_structs_tags.go
go build -o linux_amd64\test_embedded_fields test_embedded_fields.go
go build -o linux_amd64\test_interfaces test_interfaces.go
go build -o linux_amd64\test_circular_refs test_circular_refs.go
go build -o linux_amd64\test_comprehensive test_comprehensive.go
```

### Option 3: Compile on Linux/macOS

**Linux/macOS:**
```bash
# Create output directories
mkdir -p windows_amd64 linux_amd64

# Compile for Linux
GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_structs_simple test_structs_simple.go
GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_structs_tags test_structs_tags.go
GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_embedded_fields test_embedded_fields.go
GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_interfaces test_interfaces.go
GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_circular_refs test_circular_refs.go
GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_comprehensive test_comprehensive.go

# Compile for Windows
GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_structs_simple.exe test_structs_simple.go
GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_structs_tags.exe test_structs_tags.go
GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_embedded_fields.exe test_embedded_fields.go
GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_interfaces.exe test_interfaces.go
GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_circular_refs.exe test_circular_refs.go
GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_comprehensive.exe test_comprehensive.go
```

## Installation Instructions

### Install Go on Windows

1. **Download Go installer**:
   - Visit https://golang.org/dl/
   - Download `go1.21.x.windows-amd64.msi` (or latest)

2. **Run installer**:
   - Double-click the .msi file
   - Follow installation wizard
   - Default location: `C:\Program Files\Go`

3. **Verify installation**:
   ```batch
   go version
   ```
   Should output: `go version go1.21.x windows/amd64`

4. **Compile test binaries**:
   ```batch
   cd C:\Users\Corbin\development\GhidraGo\test_binaries
   build_tests.bat
   ```

### Install Go on Linux

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install golang-go

# Or download latest from golang.org
wget https://go.dev/dl/go1.21.x.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.x.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Verify
go version
```

### Install Go on macOS

```bash
# Using Homebrew
brew install go

# Or download from golang.org
curl -O https://go.dev/dl/go1.21.x.darwin-amd64.pkg
sudo installer -pkg go1.21.x.darwin-amd64.pkg -target /

# Verify
go version
```

## Alternative: Use Existing Go Binaries

If you have other Go binaries available, you can test GhidraGo Phase 2 on those instead:

**Popular Go projects for testing:**
- Docker: https://github.com/moby/moby
- Kubernetes: https://github.com/kubernetes/kubernetes
- Hugo: https://github.com/gohugoio/hugo
- Terraform: https://github.com/hashicorp/terraform
- Prometheus: https://github.com/prometheus/prometheus

**Download pre-built binaries:**
Many Go projects provide pre-built binaries in their releases. For example:
- Docker: https://download.docker.com/
- Hugo: https://github.com/gohugoio/hugo/releases

## Troubleshooting

**Error: "go: command not found"**
- Solution: Install Go compiler (see above)
- Or add Go to PATH: `set PATH=%PATH%;C:\Program Files\Go\bin`

**Error: "GOOS/GOARCH not recognized"**
- Solution: Use `set` on Windows, `export` on Linux/macOS

**Error: "cannot find package"**
- Solution: Test programs have no dependencies, check file paths

**Error: "permission denied" (Linux)**
- Solution: Run with `sudo` or change output directory permissions

## Build Verification

After compilation, verify binaries were created:

**Windows:**
```batch
dir windows_amd64
dir linux_amd64
```

**Linux/macOS:**
```bash
ls -lh windows_amd64/
ls -lh linux_amd64/
```

**Expected output:**
```
windows_amd64/
  test_structs_simple.exe (~2MB)
  test_structs_tags.exe (~2MB)
  test_embedded_fields.exe (~2MB)
  test_interfaces.exe (~2MB)
  test_circular_refs.exe (~2MB)
  test_comprehensive.exe (~3MB)

linux_amd64/
  test_structs_simple (~2MB)
  test_structs_tags (~2MB)
  test_embedded_fields (~2MB)
  test_interfaces (~2MB)
  test_circular_refs (~2MB)
  test_comprehensive (~3MB)
```

## Next Steps After Compilation

1. **Load binary into Ghidra**
2. **Run RecoverGoFunctionsAndTypes.py**
3. **Check Data Type Manager** for recovered types
4. **Verify struct fields, tags, interfaces** (see README.md)

## Docker Alternative (No Go Installation Required)

If you don't want to install Go locally, use Docker:

```bash
# Build test binaries using Go Docker image
docker run --rm -v "%cd%":/src -w /src golang:1.21 bash -c "\
  GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_structs_simple.exe test_structs_simple.go && \
  GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_structs_tags.exe test_structs_tags.go && \
  GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_embedded_fields.exe test_embedded_fields.go && \
  GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_interfaces.exe test_interfaces.go && \
  GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_circular_refs.exe test_circular_refs.go && \
  GOOS=windows GOARCH=amd64 go build -o windows_amd64/test_comprehensive.exe test_comprehensive.go && \
  GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_structs_simple test_structs_simple.go && \
  GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_structs_tags test_structs_tags.go && \
  GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_embedded_fields test_embedded_fields.go && \
  GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_interfaces test_interfaces.go && \
  GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_circular_refs test_circular_refs.go && \
  GOOS=linux GOARCH=amd64 go build -o linux_amd64/test_comprehensive test_comprehensive.go"
```

This uses the official Go Docker image to compile without installing Go locally.
