#!/bin/bash

# Unified Local Development Setup and Deployment Script for Buttercup CRS
# This script automates the entire process of setting up and deploying Buttercup locally.

set -e

# --- Color definitions for output ---
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# --- Prerequisite Checks ---

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_prerequisites() {
    print_status "Checking for required command-line tools..."
    local missing_tools=0

    local required_tools=("make" "git" "curl" "docker" "minikube" "kubectl" "uv")

    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            print_error "Required tool '$tool' is not installed. Please install it before proceeding."
            missing_tools=$((missing_tools + 1))
        fi
    done

    if [ $missing_tools -gt 0 ]; then
        print_error "Please install the missing tools and run this script again."
        exit 1
    fi

    if [ ! -f "external/aixcc-cscope/configure.ac" ]; then
        print_error "Git submodules are not initialized."
        print_error "Please run 'git submodule update --init --recursive' first."
        exit 1
    fi

    print_success "All required tools are available."
}

# --- Main Script Logic ---

main() {
    echo
    print_status "Starting Buttercup CRS Local Setup and Deployment..."
    echo "======================================================"

    # 1. Check for all prerequisites
    check_prerequisites

    # 2. Run the interactive setup for configuration
    print_status "Running 'make setup-local' for dependency installation and configuration..."
    echo "This step will guide you through setting up API keys and other configurations."
    make setup-local

    # 3. Run the local deployment
    print_status "Running 'make deploy-local' to build and deploy the system..."
    echo "This may take a while as it builds containers and starts the Kubernetes cluster."
    make deploy-local

    echo
    echo "======================================================"
    print_success "Buttercup CRS has been deployed locally!"
    echo

    # 4. Display next steps
    print_status "You can now interact with your local Buttercup instance:"
    echo "  - To check the status of all components, run: make status"
    echo "  - To open the web UI, run: make web-ui"
    echo "  - To send a test task, run: make send-libpng-task"
    echo "  - To view logs and traces, run: make signoz-ui"
    echo "  - To shut down the system, run: make undeploy"
    echo
}

# --- Execute Main Function ---
main
