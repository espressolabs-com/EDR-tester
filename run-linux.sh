#!/bin/bash

# EDR Tester - Linux Installation and Execution Script
# This script installs Node.js/npm if missing and runs the EDR test suite
# Supports: Ubuntu, Debian, CentOS, RHEL, Fedora, and other common Linux distributions

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JS_SCRIPT="${SCRIPT_DIR}/basic_tests.js"

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi
}

# Display help message
show_help() {
    cat << EOF
EDR Tester - Linux Runner Script
=================================

DESCRIPTION:
    This script automatically installs Node.js and npm (if missing) and runs
    the EDR validation test suite on Linux systems.

USAGE:
    ./run-linux.sh [OPTIONS]

OPTIONS:
    --help, -h          Show this help message
    --skip-install      Skip dependency installation (assumes Node.js is already installed)
    --version           Show script version

EXAMPLES:
    ./run-linux.sh                    # Install dependencies and run tests
    ./run-linux.sh --skip-install     # Run tests without installing dependencies

DEPENDENCIES:
    - curl or wget - Required for downloading Node.js installer
    - sudo - Required for package installation (script will prompt for password)
    - Node.js 18+ - Will be installed automatically if missing

SUPPORTED DISTRIBUTIONS:
    - Ubuntu 20.04+
    - Debian 10+
    - CentOS/RHEL 7+
    - Fedora 30+
    - Other distributions with apt, yum, or dnf package managers

OUTPUT:
    Test results are saved to a JSON report in the system temp directory.
    The report path is displayed at the end of execution.

NOTES:
    - This script requires sudo privileges for package installation
    - The script will prompt for your password if packages need to be installed
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

# Install Node.js using NodeSource repository (recommended method)
install_nodejs_nodesource() {
    detect_distro
    
    echo "[INFO] Installing Node.js via NodeSource repository..."
    
    # Check for curl or wget
    if command -v curl &> /dev/null; then
        DOWNLOAD_CMD="curl -fsSL"
    elif command -v wget &> /dev/null; then
        DOWNLOAD_CMD="wget -qO-"
    else
        echo "[ERROR] Neither curl nor wget is available. Please install one of them."
        exit 1
    fi
    
    # Install NodeSource setup script and Node.js 18.x
    $DOWNLOAD_CMD https://deb.nodesource.com/setup_18.x | sudo -E bash -
    
    # Install Node.js
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y nodejs
    elif command -v yum &> /dev/null; then
        sudo yum install -y nodejs
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y nodejs
    else
        echo "[ERROR] Unsupported package manager. Please install Node.js manually."
        exit 1
    fi
    
    # Verify installation
    if check_nodejs; then
        echo "[SUCCESS] Node.js installed successfully"
    else
        echo "[ERROR] Failed to install Node.js"
        exit 1
    fi
}

# Install Node.js using package manager (fallback method)
install_nodejs_package_manager() {
    detect_distro
    
    echo "[INFO] Installing Node.js via system package manager..."
    
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y nodejs npm
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL
        sudo yum install -y nodejs npm
    elif command -v dnf &> /dev/null; then
        # Fedora
        sudo dnf install -y nodejs npm
    else
        echo "[ERROR] Unsupported package manager. Please install Node.js manually."
        exit 1
    fi
    
    # Verify installation
    if check_nodejs; then
        echo "[SUCCESS] Node.js installed successfully"
    else
        echo "[WARN] Installed Node.js may not meet version requirement. Trying NodeSource method..."
        install_nodejs_nodesource
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
                echo "EDR Tester Linux Runner v1.0.0"
                exit 0
                ;;
            *)
                echo "[ERROR] Unknown option: $1"
                echo "Run './run-linux.sh --help' for usage information"
                exit 1
                ;;
        esac
    done
    
    echo "=========================================="
    echo "EDR Tester - Linux Runner"
    echo "=========================================="
    echo ""
    
    # Detect distribution
    detect_distro
    echo "[INFO] Detected distribution: $DISTRO"
    echo ""
    
    # Check if JS script exists
    if [ ! -f "$JS_SCRIPT" ]; then
        echo "[ERROR] Test script not found: $JS_SCRIPT"
        exit 1
    fi
    
    # Install dependencies if needed
    if [ "$SKIP_INSTALL" = false ]; then
        if ! check_nodejs; then
            # Try NodeSource method first (more reliable for version 18+)
            install_nodejs_nodesource || install_nodejs_package_manager
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

