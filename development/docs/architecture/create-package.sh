#!/bin/bash
# Architecture Documentation - Package Builder (Bash version)
# Creates a complete deliverable package of all architecture documentation

set -e

# Color codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Default values
OUTPUT_DIR="./package"
INCLUDE_RENDERED=false
RENDER_FIRST=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --include-rendered)
            INCLUDE_RENDERED=true
            shift
            ;;
        --render-first)
            RENDER_FIRST=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--output-dir DIR] [--include-rendered] [--render-first]"
            exit 1
            ;;
    esac
done

ARCH_DIR=$(pwd)

echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}Architecture Documentation Packager${NC}"
echo -e "${CYAN}========================================${NC}\n"

echo -e "📦 Building documentation package..."
echo -e "   Source: $ARCH_DIR"
echo -e "   Output: $OUTPUT_DIR\n"

# Create output directory
if [ -d "$OUTPUT_DIR" ]; then
    echo -e "${YELLOW}⚠️  Output directory exists. Cleaning...${NC}"
    rm -rf "$OUTPUT_DIR"
fi

mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}✅ Created output directory: $OUTPUT_DIR${NC}\n"

# Render diagrams if requested
if [ "$RENDER_FIRST" = true ]; then
    echo -e "${YELLOW}🎨 Rendering diagrams first...${NC}\n"

    if [ -f "./render-diagrams.sh" ]; then
        bash ./render-diagrams.sh
        echo ""
    else
        echo -e "${YELLOW}⚠️  render-diagrams.sh not found. Skipping diagram rendering.${NC}\n"
    fi
fi

# Define files to include
FOUNDATION_FILES=(
    "00-executive-summary.md"
    "README-COMPREHENSIVE.md"
    "IMPLEMENTATION_STATUS.md"
    "INDEX.md"
    "USAGE_GUIDE.md"
)

UTILITY_FILES=(
    "print-browser.html"
    "open-all-for-print.bat"
    "render-diagrams.ps1"
    "render-diagrams.sh"
)

DIRECTORIES=(
    "01-system-context"
    "02-container-architecture"
    "03-component-architecture"
    "04-code-architecture"
    "05-arc42"
    "06-cross-cutting"
    "07-deployment"
    "08-data"
    "09-integration"
    "10-adrs"
)

# Copy foundation files
echo -e "${CYAN}📄 Copying foundation files...${NC}"
COPIED_COUNT=0

for file in "${FOUNDATION_FILES[@]}"; do
    if [ -f "$file" ]; then
        cp "$file" "$OUTPUT_DIR/"
        echo -e "${GREEN}   ✅ $file${NC}"
        ((COPIED_COUNT++))
    else
        echo -e "${YELLOW}   ⚠️  $file not found${NC}"
    fi
done

echo -e "${GRAY}   Copied $COPIED_COUNT/${#FOUNDATION_FILES[@]} foundation files${NC}\n"

# Copy utility files
echo -e "${CYAN}🛠️  Copying utility files...${NC}"
COPIED_COUNT=0

for file in "${UTILITY_FILES[@]}"; do
    if [ -f "$file" ]; then
        cp "$file" "$OUTPUT_DIR/"
        echo -e "${GREEN}   ✅ $file${NC}"
        ((COPIED_COUNT++))
    else
        echo -e "${YELLOW}   ⚠️  $file not found${NC}"
    fi
done

echo -e "${GRAY}   Copied $COPIED_COUNT/${#UTILITY_FILES[@]} utility files${NC}\n"

# Copy directories
echo -e "${CYAN}📁 Copying documentation directories...${NC}"
TOTAL_FILES=0

for dir in "${DIRECTORIES[@]}"; do
    if [ -d "$dir" ]; then
        cp -r "$dir" "$OUTPUT_DIR/"
        FILE_COUNT=$(find "$OUTPUT_DIR/$dir" -type f | wc -l)
        TOTAL_FILES=$((TOTAL_FILES + FILE_COUNT))
        echo -e "${GREEN}   ✅ $dir ($FILE_COUNT files)${NC}"
    else
        echo -e "${YELLOW}   ⚠️  $dir not found${NC}"
    fi
done

echo -e "${GRAY}   Copied $TOTAL_FILES files from ${#DIRECTORIES[@]} directories${NC}\n"

# Remove rendered diagrams if not requested
if [ "$INCLUDE_RENDERED" = false ]; then
    echo -e "${YELLOW}🗑️  Removing rendered diagrams (keeping .puml sources)...${NC}"

    REMOVED=$(find "$OUTPUT_DIR" -type f \( -name "*.png" -o -name "*.svg" \) -delete -print | wc -l)

    if [ $REMOVED -gt 0 ]; then
        echo -e "${GRAY}   Removed $REMOVED rendered diagram(s)${NC}"
        echo -e "${GRAY}   (Run with --include-rendered to include them)${NC}\n"
    else
        echo -e "${GRAY}   No rendered diagrams found${NC}\n"
    fi
fi

# Create README for the package
cat > "$OUTPUT_DIR/README.md" << 'EOF'
# Catalytic Computing Platform - Architecture Documentation Package

**Version**: 2.0
**Package Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Status**: Production-Ready ✅

---

## Package Contents

This package contains the complete architecture documentation for the Catalytic Computing Platform.

### Files Included

- **Foundation Documents** (5 files):
  - `00-executive-summary.md` - Comprehensive platform overview
  - `README-COMPREHENSIVE.md` - Navigation guide
  - `IMPLEMENTATION_STATUS.md` - Completion tracking
  - `INDEX.md` - Complete file inventory
  - `USAGE_GUIDE.md` - Maintenance and usage instructions

- **C4 Model Diagrams**:
  - Level 1: System Context (3 files)
  - Level 2: Container Architecture (5 files)
  - Level 3: Component Architecture (6 files)
  - Level 4: Code Architecture (5 files)

- **Arc42 Template** (12 sections):
  - Complete architectural template covering all aspects

- **Architecture Decision Records**:
  - 15 ADRs + template (16 files total)
  - Documents all major technology and architecture decisions

- **Cross-Cutting Concerns** (3 files):
  - Security, Observability, Error Handling

- **Specialized Documentation**:
  - Deployment, Data, Integration architecture

- **Utilities**:
  - Diagram rendering scripts (PowerShell and Bash)
  - Print-friendly HTML summary
  - Batch printing launcher

---

## Getting Started

1. **First-Time Readers**: Start with `README-COMPREHENSIVE.md`
2. **Executive Overview**: Read `00-executive-summary.md`
3. **Find Specific Info**: Use `INDEX.md` for navigation
4. **Maintenance**: Review `USAGE_GUIDE.md`

---

## Rendering Diagrams

PlantUML diagrams (.puml files) need to be rendered before viewing:

**Windows**:
```powershell
.\render-diagrams.ps1
```

**Linux/Mac**:
```bash
./render-diagrams.sh
```

See `USAGE_GUIDE.md` for detailed instructions.

---

## Documentation Frameworks Used

- **C4 Model**: 4-level architecture visualization
- **Arc42**: 12-section comprehensive template
- **ADRs**: Architecture decision records with rationale

---

## Key Metrics Documented

- 649x GPU speedup (CuPy over CPU)
- 99.29% success at 10,000 concurrent users
- <100ms p50 API latency
- 12 D3FEND security techniques implemented
- 7.24 TFLOPS sustained GPU performance

---

## Technology Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy
- **Database**: PostgreSQL 15 (RLS), Redis 7
- **GPU**: PyTorch 2.0+, CuPy 12.1, Numba, CUDA 12.1
- **Security**: HashiCorp Vault, JWT RS256, D3FEND
- **Infrastructure**: Kubernetes, Docker Compose, Prometheus, Grafana
- **Integrations**: Stripe, SendGrid, Ghidra

---

## Support

For questions or updates:
- Review `USAGE_GUIDE.md` for maintenance procedures
- Check `INDEX.md` for quick navigation
- Contact Architecture Team via internal channels

---

**Package Created**: $(date '+%Y-%m-%d %H:%M:%S')
EOF

# Add dynamic package stats to README
TOTAL_FILES=$(find "$OUTPUT_DIR" -type f | wc -l)
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" | cut -f1)
echo "**Total Files**: $TOTAL_FILES" >> "$OUTPUT_DIR/README.md"
echo "**Package Size**: $TOTAL_SIZE" >> "$OUTPUT_DIR/README.md"

echo -e "${GREEN}📝 Created package README.md${NC}\n"

# Create manifest file
MANIFEST_PATH="$OUTPUT_DIR/MANIFEST.txt"

cat > "$MANIFEST_PATH" << EOF
CATALYTIC COMPUTING PLATFORM - ARCHITECTURE DOCUMENTATION PACKAGE
================================================================

Package Version: 2.0
Creation Date: $(date '+%Y-%m-%d %H:%M:%S')
Source Location: $ARCH_DIR

FILE MANIFEST
=============

EOF

find "$OUTPUT_DIR" -type f -printf "%P (%s bytes)\n" >> "$MANIFEST_PATH"

echo -e "${GREEN}📋 Created manifest file: MANIFEST.txt${NC}\n"

# Generate package statistics
TOTAL_FILES=$(find "$OUTPUT_DIR" -type f | wc -l)
MARKDOWN_FILES=$(find "$OUTPUT_DIR" -type f -name "*.md" | wc -l)
PLANTUML_FILES=$(find "$OUTPUT_DIR" -type f -name "*.puml" | wc -l)
RENDERED_DIAGRAMS=$(find "$OUTPUT_DIR" -type f \( -name "*.png" -o -name "*.svg" \) | wc -l)
TOTAL_DIRS=$(find "$OUTPUT_DIR" -type d | wc -l)
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" | cut -f1)

# Final summary
echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}Package Build Complete!${NC}"
echo -e "${CYAN}========================================${NC}\n"

echo -e "${YELLOW}📊 Package Statistics:${NC}"
echo -e "${GRAY}   Total Files: $TOTAL_FILES${NC}"
echo -e "${GRAY}   Markdown Files: $MARKDOWN_FILES${NC}"
echo -e "${GRAY}   PlantUML Diagrams: $PLANTUML_FILES${NC}"
echo -e "${GRAY}   Rendered Diagrams: $RENDERED_DIAGRAMS${NC}"
echo -e "${GRAY}   Directories: $TOTAL_DIRS${NC}"
echo -e "${GRAY}   Total Size: $TOTAL_SIZE${NC}\n"

echo -e "${GREEN}📁 Package Location: $OUTPUT_DIR${NC}"
echo -e "${GRAY}   - README.md (start here)${NC}"
echo -e "${GRAY}   - MANIFEST.txt (complete file listing)${NC}\n"

# Suggest next steps
echo -e "${YELLOW}Next Steps:${NC}"

if [ $RENDERED_DIAGRAMS -eq 0 ]; then
    echo -e "${GRAY}   1. Render diagrams: cd $OUTPUT_DIR && ./render-diagrams.sh${NC}"
else
    echo -e "${GREEN}   1. ✅ Diagrams already rendered ($RENDERED_DIAGRAMS files)${NC}"
fi

echo -e "${GRAY}   2. Review package: cd $OUTPUT_DIR && cat README.md${NC}"
echo -e "${GRAY}   3. Archive package: tar -czf architecture-docs-v2.0.tar.gz $OUTPUT_DIR${NC}"
echo -e "${GRAY}   4. Share or distribute the package as needed${NC}\n"

echo -e "${GREEN}✅ Package build complete!${NC}\n"
