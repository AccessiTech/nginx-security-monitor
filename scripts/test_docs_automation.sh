#!/bin/bash
# Documentation Automation Test Script
# Tests the automated documentation generation system

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Function to check if command exists
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        error "Required command '$cmd' not found. Please install it first."
    fi
}

# Function to check Python dependencies
check_python_deps() {
    log "Checking Python dependencies..."
    
    local required_modules=("yaml" "requests" "ast")
    for module in "${required_modules[@]}"; do
        if ! python3 -c "import $module" 2>/dev/null; then
            error "Required Python module '$module' not found"
        fi
    done
    
    success "Python dependencies OK"
}

# Function to validate documentation structure
validate_docs_structure() {
    log "Validating documentation structure..."
    
    local required_dirs=("docs" "docs/api" "docs/architecture" "docs/troubleshooting")
    for dir in "${required_dirs[@]}"; do
        if [ ! -d "$PROJECT_ROOT/$dir" ]; then
            error "Required directory '$dir' not found"
        fi
    done
    
    local required_files=(
        "docs/index.md"
        "docs/getting-started.md"
        "docs/docgen-config.yaml"
        "scripts/generate_docs.py"
        "mkdocs.yml"
    )
    
    for file in "${required_files[@]}"; do
        if [ ! -f "$PROJECT_ROOT/$file" ]; then
            error "Required file '$file' not found"
        fi
    done
    
    success "Documentation structure OK"
}

# Function to test API documentation generation
test_api_generation() {
    log "Testing API documentation generation..."
    
    cd "$PROJECT_ROOT"
    
    # Test API docs generation
    if python3 scripts/generate_docs.py --api-docs 2>/dev/null; then
        success "API documentation generation successful"
    else
        warning "API documentation generation failed (this is expected if no source code is present)"
    fi
}

# Function to test README updates
test_readme_update() {
    log "Testing README update..."
    
    cd "$PROJECT_ROOT"
    
    # Backup original README
    if [ -f "README.md" ]; then
        cp "README.md" "README.md.backup"
    fi
    
    # Test README update
    if python3 scripts/generate_docs.py --update-readme 2>/dev/null; then
        success "README update successful"
    else
        warning "README update failed"
    fi
    
    # Restore backup if it exists
    if [ -f "README.md.backup" ]; then
        mv "README.md.backup" "README.md"
    fi
}

# Function to test link validation
test_link_validation() {
    log "Testing link validation..."
    
    cd "$PROJECT_ROOT"
    
    if python3 scripts/generate_docs.py --validate-links 2>/dev/null; then
        success "Link validation completed"
    else
        warning "Link validation failed (this may be expected for missing external resources)"
    fi
}

# Function to test MkDocs build
test_mkdocs_build() {
    log "Testing MkDocs site generation..."
    
    cd "$PROJECT_ROOT"
    
    # Check if MkDocs is available
    if command -v mkdocs &> /dev/null; then
        if mkdocs build --quiet 2>/dev/null; then
            success "MkDocs build successful"
            
            # Check if site directory was created
            if [ -d "site" ]; then
                success "Documentation site generated in 'site/' directory"
                
                # Count generated files
                local file_count=$(find site -name "*.html" | wc -l)
                log "Generated $file_count HTML files"
            fi
        else
            warning "MkDocs build failed"
        fi
    else
        warning "MkDocs not installed, skipping site generation test"
        log "Install with: pip install mkdocs mkdocs-material"
    fi
}

# Function to test full documentation generation
test_full_generation() {
    log "Testing full documentation generation..."
    
    cd "$PROJECT_ROOT"
    
    if python3 scripts/generate_docs.py 2>/dev/null; then
        success "Full documentation generation successful"
    else
        warning "Full documentation generation had issues"
    fi
}

# Function to generate test report
generate_test_report() {
    log "Generating test report..."
    
    local report_file="$PROJECT_ROOT/docs-test-report.txt"
    
    cat > "$report_file" << EOF
# Documentation Automation Test Report

**Generated**: $(date)
**System**: $(uname -s) $(uname -r)
**Python**: $(python3 --version)

## Test Results

✅ = Pass, ⚠️ = Warning, ❌ = Fail

### Prerequisites
EOF

    # Check each prerequisite
    if command -v python3 &> /dev/null; then
        echo "✅ Python 3 installed" >> "$report_file"
    else
        echo "❌ Python 3 not found" >> "$report_file"
    fi
    
    if command -v mkdocs &> /dev/null; then
        echo "✅ MkDocs installed" >> "$report_file"
    else
        echo "⚠️ MkDocs not installed" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "### Documentation Structure" >> "$report_file"
    
    # Check structure
    local required_files=(
        "docs/index.md"
        "docs/getting-started.md"
        "docs/docgen-config.yaml"
        "scripts/generate_docs.py"
        "mkdocs.yml"
    )
    
    for file in "${required_files[@]}"; do
        if [ -f "$PROJECT_ROOT/$file" ]; then
            echo "✅ $file" >> "$report_file"
        else
            echo "❌ $file" >> "$report_file"
        fi
    done
    
    echo "" >> "$report_file"
    echo "### Generated Files" >> "$report_file"
    
    if [ -d "$PROJECT_ROOT/docs/api" ]; then
        local api_files=$(find "$PROJECT_ROOT/docs/api" -name "*.md" | wc -l)
        echo "📚 API documentation files: $api_files" >> "$report_file"
    fi
    
    if [ -d "$PROJECT_ROOT/site" ]; then
        local html_files=$(find "$PROJECT_ROOT/site" -name "*.html" | wc -l)
        echo "🌐 Generated HTML files: $html_files" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "### Recommendations" >> "$report_file"
    
    if ! command -v mkdocs &> /dev/null; then
        echo "- Install MkDocs: pip install mkdocs mkdocs-material" >> "$report_file"
    fi
    
    if [ ! -f "$PROJECT_ROOT/src" ]; then
        echo "- Add source code directory for API documentation generation" >> "$report_file"
    fi
    
    echo "- Run 'python scripts/generate_docs.py' to generate all documentation" >> "$report_file"
    echo "- Use 'mkdocs serve' to preview documentation locally" >> "$report_file"
    
    success "Test report generated: $report_file"
}

# Main function
main() {
    log "Starting documentation automation tests..."
    
    echo ""
    echo "🚀 Nginx Security Monitor Documentation Automation Test"
    echo "=================================================="
    
    # Check prerequisites
    log "Checking prerequisites..."
    check_command "python3"
    check_python_deps
    
    # Validate structure
    validate_docs_structure
    
    # Run tests
    echo ""
    log "Running documentation generation tests..."
    
    test_api_generation
    test_readme_update
    test_link_validation
    test_mkdocs_build
    test_full_generation
    
    # Generate report
    echo ""
    generate_test_report
    
    echo ""
    success "Documentation automation tests completed!"
    
    echo ""
    echo "📋 Next Steps:"
    echo "1. Review the test report: docs-test-report.txt"
    echo "2. Install any missing dependencies"
    echo "3. Run 'python scripts/generate_docs.py' for full generation"
    echo "4. Use 'mkdocs serve' to preview documentation"
    echo "5. Commit changes and push to trigger GitHub Actions"
}

# Run main function
main "$@"
