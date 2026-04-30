#!/bin/bash
# Architecture Documentation - PlantUML Diagram Renderer (Bash version)
# Automatically renders all .puml diagrams to PNG and SVG formats

set -e

# Color codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Parse arguments
PNG_ONLY=false
SVG_ONLY=false
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --png-only)
            PNG_ONLY=true
            shift
            ;;
        --svg-only)
            SVG_ONLY=true
            shift
            ;;
        --check-only)
            CHECK_ONLY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--png-only] [--svg-only] [--check-only]"
            exit 1
            ;;
    esac
done

echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}PlantUML Diagram Rendering Automation${NC}"
echo -e "${CYAN}========================================${NC}\n"

# Check if PlantUML is installed
if ! command -v plantuml &> /dev/null; then
    echo -e "${RED}❌ PlantUML not found!${NC}\n"
    echo -e "${YELLOW}PlantUML Installation Options:${NC}\n"

    echo -e "${GREEN}Option 1: Install via apt (Ubuntu/Debian)${NC}"
    echo -e "${GRAY}  sudo apt-get install plantuml${NC}\n"

    echo -e "${GREEN}Option 2: Install via brew (macOS)${NC}"
    echo -e "${GRAY}  brew install plantuml${NC}\n"

    echo -e "${GREEN}Option 3: Install via package manager (Fedora/RHEL)${NC}"
    echo -e "${GRAY}  sudo dnf install plantuml${NC}\n"

    echo -e "${GREEN}Option 4: Download JAR manually${NC}"
    echo -e "${GRAY}  1. Download from: https://plantuml.com/download${NC}"
    echo -e "${GRAY}  2. Save plantuml.jar to: ~/bin/plantuml.jar${NC}"
    echo -e "${GRAY}  3. Create alias: alias plantuml='java -jar ~/bin/plantuml.jar'${NC}\n"

    echo -e "${YELLOW}After installation, run this script again.${NC}\n"
    exit 1
fi

echo -e "${GREEN}✅ PlantUML found: $(which plantuml)${NC}\n"

# Find all .puml files
mapfile -t PUML_FILES < <(find . -name "*.puml" -type f)
FILE_COUNT=${#PUML_FILES[@]}

echo -e "${CYAN}Found $FILE_COUNT PlantUML diagram(s):${NC}\n"

INDEX=1
for file in "${PUML_FILES[@]}"; do
    echo -e "${GRAY}  $INDEX. $file${NC}"
    ((INDEX++))
done
echo ""

if [ "$CHECK_ONLY" = true ]; then
    echo -e "${GREEN}✅ Check complete. PlantUML is installed and ready to render $FILE_COUNT diagrams.${NC}\n"
    exit 0
fi

# Rendering function
render_diagrams() {
    local format=$1
    echo -e "${YELLOW}Rendering to $format format...${NC}\n"

    local success_count=0
    local fail_count=0

    for file in "${PUML_FILES[@]}"; do
        echo -e "${GRAY}  Processing: $file${NC}"

        if plantuml -t$format "$file" > /dev/null 2>&1; then
            local dir=$(dirname "$file")
            local base=$(basename "$file" .puml)
            echo -e "${GREEN}    ✅ Rendered to $dir/$base.$format${NC}"
            ((success_count++))
        else
            echo -e "${RED}    ❌ Failed to render $file${NC}"
            ((fail_count++))
        fi
    done

    echo -e "\n${CYAN}  Summary: $success_count/$FILE_COUNT diagrams rendered successfully${NC}"
    if [ $fail_count -gt 0 ]; then
        echo -e "${RED}  Failures: $fail_count${NC}"
    fi
    echo ""

    return $success_count
}

# Render diagrams based on parameters
TOTAL_SUCCESS=0

if [ "$SVG_ONLY" = false ]; then
    echo -e "\n${CYAN}--- Rendering PNG (for presentations) ---${NC}\n"
    render_diagrams "png"
    TOTAL_SUCCESS=$((TOTAL_SUCCESS + $?))
fi

if [ "$PNG_ONLY" = false ]; then
    echo -e "\n${CYAN}--- Rendering SVG (for documentation) ---${NC}\n"
    render_diagrams "svg"
    TOTAL_SUCCESS=$((TOTAL_SUCCESS + $?))
fi

# Final summary
echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}Rendering Complete!${NC}"
echo -e "${CYAN}========================================${NC}\n"

echo -e "${GREEN}Diagrams rendered: $TOTAL_SUCCESS${NC}"
echo -e "${YELLOW}Output locations:${NC}\n"

for file in "${PUML_FILES[@]}"; do
    dir=$(dirname "$file")
    base=$(basename "$file" .puml)

    if [ "$SVG_ONLY" = false ] && [ -f "$dir/$base.png" ]; then
        echo -e "${GRAY}  📄 $dir/$base.png${NC}"
    fi
    if [ "$PNG_ONLY" = false ] && [ -f "$dir/$base.svg" ]; then
        echo -e "${GRAY}  📄 $dir/$base.svg${NC}"
    fi
done

echo -e "\n${YELLOW}Next steps:${NC}"
echo -e "${GRAY}  1. Review rendered diagrams in their respective directories${NC}"
echo -e "${GRAY}  2. Embed diagrams in documentation using markdown:${NC}"
echo -e "${GRAY}     ![Diagram Title](./path/to/diagram.svg)${NC}"
echo -e "${GRAY}  3. Commit both .puml source and rendered images to version control${NC}\n"

echo -e "${GREEN}✅ All done!${NC}\n"
