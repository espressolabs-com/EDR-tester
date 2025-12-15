#!/bin/bash

# EDR Tester - macOS Installation and Execution Script
# This script installs Node.js/npm if missing and runs the EDR test suite

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JS_SCRIPT="${SCRIPT_DIR}/basic_tests.js"

# Display help message
show_help() {
    cat << EOF
EDR Tester - macOS Runner Script
================================

DESCRIPTION:
    This script automatically installs Node.js and npm (if missing) and runs
    the EDR validation test suite on macOS.

USAGE:
    ./run-macos.sh [OPTIONS]

OPTIONS:
    --help, -h          Show this help message
    --skip-install      Skip dependency installation (assumes Node.js is already installed)
    --version           Show script version

EXAMPLES:
    ./run-macos.sh                    # Install dependencies and run tests
    ./run-macos.sh --skip-install     # Run tests without installing dependencies

DEPENDENCIES:
    - Homebrew (brew) - Will be installed automatically if missing
    - Node.js 18+ - Will be installed automatically if missing

OUTPUT:
    Test results are saved to a JSON report in the system temp directory.
    The report path is displayed at the end of execution.

NOTES:
    - This script requires administrator privileges for Homebrew installation
    - The script will prompt for your password if Homebrew needs to be installed
    - All tests are safe and non-destructive

For more information, visit: https://github.com/your-repo/EDR-tester
EOF
    exit 0
}

# Check if Node.js is installed and meets version requirement
check_nodejs() {
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node -v | sed 's/v//')
        NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
        
        if [ "$NODE_MAJOR" -ge 18 ]; then
            echo "[INFO] Node.js $NODE_VERSION is installed (meets requirement: 18+)"
            return 0
        else
            echo "[WARN] Node.js $NODE_VERSION is installed but version 18+ is required"
            return 1
        fi
    else
        echo "[INFO] Node.js is not installed"
        return 1
    fi
}

# Install Homebrew if not present
install_homebrew() {
    if command -v brew &> /dev/null; then
        echo "[INFO] Homebrew is already installed"
        return 0
    fi
    
    echo "[INFO] Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH for Apple Silicon Macs
    if [ -f "/opt/homebrew/bin/brew" ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -f "/usr/local/bin/brew" ]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi
}

# Install Node.js using Homebrew
install_nodejs() {
    echo "[INFO] Installing Node.js via Homebrew..."
    brew install node
    
    # Verify installation
    if check_nodejs; then
        echo "[SUCCESS] Node.js installed successfully"
    else
        echo "[ERROR] Failed to install Node.js"
        exit 1
    fi
}

# Main execution function
main() {
    # Parse command line arguments
    SKIP_INSTALL=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                ;;
            --skip-install)
                SKIP_INSTALL=true
                shift
                ;;
            --version)
                echo "EDR Tester macOS Runner v1.0.0"
                exit 0
                ;;
            *)
                echo "[ERROR] Unknown option: $1"
                echo "Run './run-macos.sh --help' for usage information"
                exit 1
                ;;
        esac
    done
    
    echo "=========================================="
    echo "EDR Tester - macOS Runner"
    echo "=========================================="
    echo ""
    
    # Check if JS script exists
    if [ ! -f "$JS_SCRIPT" ]; then
        echo "[ERROR] Test script not found: $JS_SCRIPT"
        exit 1
    fi
    
    # Install dependencies if needed
    if [ "$SKIP_INSTALL" = false ]; then
        if ! check_nodejs; then
            install_homebrew
            install_nodejs
        fi
    else
        if ! check_nodejs; then
            echo "[ERROR] Node.js 18+ is required but not found. Install it manually or run without --skip-install"
            exit 1
        fi
    fi
    
    # Verify npm is available
    if ! command -v npm &> /dev/null; then
        echo "[ERROR] npm is not available. Please install Node.js."
        exit 1
    fi
    
    echo ""
    echo "[INFO] Starting EDR test suite..."
    echo "[INFO] Script: $JS_SCRIPT"
    echo ""
    
    # Run the test script
    node "$JS_SCRIPT"
    
    echo ""
    echo "[SUCCESS] Test execution completed!"
}

# Run main function
main "$@"

