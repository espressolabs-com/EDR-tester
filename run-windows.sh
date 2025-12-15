#!/bin/bash

# EDR Tester - Windows Installation and Execution Script
# This script installs Node.js/npm if missing and runs the EDR test suite
# Note: This script is designed to run in Git Bash, WSL, or Cygwin on Windows

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JS_SCRIPT="${SCRIPT_DIR}/basic_tests.js"

# Detect if running in WSL
is_wsl() {
    if [ -f /proc/version ] && grep -qi microsoft /proc/version; then
        return 0
    else
        return 1
    fi
}

# Display help message
show_help() {
    cat << EOF
EDR Tester - Windows Runner Script
===================================

DESCRIPTION:
    This script automatically installs Node.js and npm (if missing) and runs
    the EDR validation test suite on Windows systems.

USAGE:
    ./run-windows.sh [OPTIONS]

OPTIONS:
    --help, -h          Show this help message
    --skip-install      Skip dependency installation (assumes Node.js is already installed)
    --version           Show script version

EXAMPLES:
    ./run-windows.sh                    # Install dependencies and run tests
    ./run-windows.sh --skip-install     # Run tests without installing dependencies

ENVIRONMENTS:
    This script works in the following Windows environments:
    - Git Bash (Git for Windows)
    - WSL (Windows Subsystem for Linux) - Uses Linux installation method
    - Cygwin
    - MSYS2

DEPENDENCIES:
    - Node.js 18+ - Will be installed automatically if missing
    - For native Windows: Chocolatey or manual Node.js installer
    - For WSL: Uses Linux package manager (apt/yum/dnf)

INSTALLATION METHODS:
    - WSL: Uses Linux package manager (recommended for WSL users)
    - Git Bash/Cygwin: Downloads and installs Node.js for Windows
    - Chocolatey: Uses Chocolatey package manager if available

OUTPUT:
    Test results are saved to a JSON report in the system temp directory.
    The report path is displayed at the end of execution.

NOTES:
    - If running in WSL, this script will use Linux installation methods
    - For native Windows, administrator privileges may be required
    - All tests are safe and non-destructive
    - If Node.js installation fails, please install manually from nodejs.org

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

# Install Node.js in WSL (uses Linux method)
install_nodejs_wsl() {
    echo "[INFO] Detected WSL environment, using Linux installation method..."
    
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
        echo "[ERROR] Unsupported package manager in WSL. Please install Node.js manually."
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

# Install Node.js using Chocolatey (Windows package manager)
install_nodejs_chocolatey() {
    if ! command -v choco &> /dev/null; then
        echo "[INFO] Chocolatey is not installed. Attempting to install Chocolatey..."
        echo "[INFO] This requires administrator privileges."
        
        # Try to install Chocolatey
        if [ -f /proc/version ] && grep -qi microsoft /proc/version; then
            # WSL - can't install Chocolatey directly
            echo "[ERROR] Chocolatey installation not supported in WSL. Please install Node.js manually."
            exit 1
        else
            # Git Bash - try to run PowerShell as admin
            echo "[INFO] Please run PowerShell as Administrator and execute:"
            echo "       Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
            echo ""
            echo "[INFO] After installing Chocolatey, run this script again."
            exit 1
        fi
    fi
    
    echo "[INFO] Installing Node.js via Chocolatey..."
    choco install nodejs -y
    
    # Refresh PATH
    export PATH="/c/ProgramData/chocolatey/bin:$PATH"
    
    # Verify installation
    if check_nodejs; then
        echo "[SUCCESS] Node.js installed successfully"
    else
        echo "[ERROR] Failed to install Node.js"
        exit 1
    fi
}

# Download and install Node.js manually (fallback)
install_nodejs_manual() {
    echo "[INFO] Attempting to download Node.js installer..."
    
    # Check for curl or wget
    if command -v curl &> /dev/null; then
        DOWNLOAD_CMD="curl -L -o"
    elif command -v wget &> /dev/null; then
        DOWNLOAD_CMD="wget -O"
    else
        echo "[ERROR] Neither curl nor wget is available. Please install one of them."
        exit 1
    fi
    
    INSTALLER_PATH="/tmp/nodejs-installer.msi"
    NODE_URL="https://nodejs.org/dist/v18.20.4/node-v18.20.4-x64.msi"
    
    echo "[INFO] Downloading Node.js installer..."
    $DOWNLOAD_CMD "$INSTALLER_PATH" "$NODE_URL"
    
    echo "[INFO] Please run the installer manually: $INSTALLER_PATH"
    echo "[INFO] After installation, restart your terminal and run this script again."
    echo ""
    echo "[INFO] Or download manually from: https://nodejs.org/"
    exit 1
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
                echo "EDR Tester Windows Runner v1.0.0"
                exit 0
                ;;
            *)
                echo "[ERROR] Unknown option: $1"
                echo "Run './run-windows.sh --help' for usage information"
                exit 1
                ;;
        esac
    done
    
    echo "=========================================="
    echo "EDR Tester - Windows Runner"
    echo "=========================================="
    echo ""
    
    # Detect environment
    if is_wsl; then
        echo "[INFO] Detected WSL environment"
    else
        echo "[INFO] Detected Git Bash/Cygwin/MSYS2 environment"
    fi
    echo ""
    
    # Check if JS script exists
    if [ ! -f "$JS_SCRIPT" ]; then
        echo "[ERROR] Test script not found: $JS_SCRIPT"
        exit 1
    fi
    
    # Install dependencies if needed
    if [ "$SKIP_INSTALL" = false ]; then
        if ! check_nodejs; then
            if is_wsl; then
                install_nodejs_wsl
            elif command -v choco &> /dev/null; then
                install_nodejs_chocolatey
            else
                echo "[INFO] Chocolatey not found. Attempting manual installation..."
                install_nodejs_manual
            fi
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

