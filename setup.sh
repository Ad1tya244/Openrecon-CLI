#!/usr/bin/env bash

# Exit on error
set -e

echo ""
echo "OpenRecon Setup"
echo "─────────────────────────────────"

# Helper to check command existence
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Detect OS and package manager
detect_package_manager() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if has_cmd brew; then
            echo "brew"
        else
            echo "none"
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if has_cmd apt-get; then
            echo "apt"
        elif has_cmd dnf; then
            echo "dnf"
        elif has_cmd pacman; then
            echo "pacman"
        else
            echo "none"
        fi
    else
        echo "none"
    fi
}

PM=$(detect_package_manager)

# Helper to prompt user for installing missing dependency
ask_install() {
    local dep_name="$1"
    local pm="$2"
    
    if [ "$pm" = "none" ]; then
        echo "⚠ $dep_name is not installed."
        echo "No supported package manager found (apt, dnf, pacman, or Homebrew)."
        echo "Please install $dep_name manually and re-run this setup."
        exit 1
    fi
    
    read -p "⚠ $dep_name is not installed. Install $dep_name using $pm? [y/N]: " choice
    case "$choice" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            echo ""
            echo "$dep_name is required to run OpenRecon."
            echo "Setup cannot continue."
            exit 1
            ;;
    esac
}

# Helper to run a command with sudo and explicit prompt
run_with_sudo() {
    local cmd="$1"
    echo "This installation requires administrator privileges."
    read -p "Run 'sudo $cmd'? [y/N]: " sudo_choice
    case "$sudo_choice" in
        [yY][eE][sS]|[yY])
            sudo sh -c "$cmd"
            ;;
        *)
            echo "Action declined. Setup cannot continue."
            exit 1
            ;;
    esac
}

# 1. Check Python 3
if has_cmd python3; then
    echo "✓ Python 3 detected"
else
    ask_install "Python 3" "$PM"
    if [ "$PM" = "brew" ]; then
        brew install python
    elif [ "$PM" = "apt" ]; then
        run_with_sudo "apt-get update && apt-get install -y python3 python3-venv"
    elif [ "$PM" = "dnf" ]; then
        run_with_sudo "dnf install -y python3"
    elif [ "$PM" = "pacman" ]; then
        run_with_sudo "pacman -Sy --noconfirm python"
    fi
    echo "✓ Python 3 installed"
fi

# 2. Check pip
if python3 -m pip --version >/dev/null 2>&1; then
    echo "✓ pip detected"
else
    ask_install "pip" "$PM"
    if [ "$PM" = "brew" ]; then
        python3 -m ensurepip --default-pip || brew install python
    elif [ "$PM" = "apt" ]; then
        run_with_sudo "apt-get install -y python3-pip"
    elif [ "$PM" = "dnf" ]; then
        run_with_sudo "dnf install -y python3-pip"
    elif [ "$PM" = "pacman" ]; then
        run_with_sudo "pacman -Sy --noconfirm python-pip"
    fi
    echo "✓ pip installed"
fi

# 3. Check Node.js
if has_cmd node; then
    echo "✓ Node.js detected"
else
    ask_install "Node.js" "$PM"
    if [ "$PM" = "brew" ]; then
        brew install node
    elif [ "$PM" = "apt" ]; then
        run_with_sudo "apt-get install -y nodejs"
    elif [ "$PM" = "dnf" ]; then
        run_with_sudo "dnf install -y nodejs"
    elif [ "$PM" = "pacman" ]; then
        run_with_sudo "pacman -Sy --noconfirm nodejs"
    fi
    echo "✓ Node.js installed"
fi

# 4. Check npm
if has_cmd npm; then
    echo "✓ npm detected"
else
    ask_install "npm" "$PM"
    if [ "$PM" = "brew" ]; then
        brew install node
    elif [ "$PM" = "apt" ]; then
        run_with_sudo "apt-get update && apt-get install -y npm"
    elif [ "$PM" = "dnf" ]; then
        run_with_sudo "dnf install -y npm"
    elif [ "$PM" = "pacman" ]; then
        run_with_sudo "pacman -Sy --noconfirm npm"
    fi
    echo "✓ npm installed"
fi

echo ""

# 5. Virtual Environment
if [ -d "venv" ]; then
    echo "✓ Virtual environment detected"
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment ready"
fi

# 6. Install OpenRecon Python dependencies
echo "Installing OpenRecon..."
venv/bin/pip install -e .
echo "✓ Python dependencies installed"

# 7. Install JavaScript dependencies
echo "Installing JavaScript dependencies..."
npm install
echo "✓ JavaScript dependencies installed"

# 8. Verify JavaScript dependencies load
echo "Verifying JavaScript dependencies..."
if node -e "require('./openrecon/modules/technology_engine.js'); require('jsdom');" >/dev/null 2>&1; then
    echo "✓ JavaScript dependencies verified"
else
    echo "✖ Verification failed: JavaScript dependencies could not be loaded."
    exit 1
fi

echo ""
echo "OpenRecon setup completed successfully."
echo ""
echo "Run:"
echo "  source venv/bin/activate"
echo "  openrecon"
echo ""
