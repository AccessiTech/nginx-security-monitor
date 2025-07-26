#!/bin/bash

# NGINX Security Monitor Installation Script
# This script installs and configures the NGINX Security Monitor as a systemd service

set -e

# Configuration
SERVICE_NAME="nginx-security-monitor"
INSTALL_DIR="/opt/${SERVICE_NAME}"
CONFIG_DIR="/etc/${SERVICE_NAME}"
LOG_DIR="/var/log/${SERVICE_NAME}"
SERVICE_USER="nginx-monitor"
SERVICE_GROUP="nginx-monitor"
SYSTEMD_DIR="/etc/systemd/system"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Create service user and group
create_service_user() {
    print_status "Creating service user and group..."
    
    if ! getent group "$SERVICE_GROUP" > /dev/null 2>&1; then
        groupadd --system "$SERVICE_GROUP"
        print_status "Created group: $SERVICE_GROUP"
    fi
    
    if ! getent passwd "$SERVICE_USER" > /dev/null 2>&1; then
        useradd --system --gid "$SERVICE_GROUP" --home-dir "$INSTALL_DIR" \
                --shell /bin/false --comment "NGINX Security Monitor" "$SERVICE_USER"
        print_status "Created user: $SERVICE_USER"
    fi
}

# Create directories
create_directories() {
    print_status "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "/var/lib/${SERVICE_NAME}"
    
    print_status "Created directories"
}

# Install dependencies
install_dependencies() {
    print_status "Installing system dependencies..."
    
    # Update package list
    apt-get update
    
    # Install Python and pip if not already installed
    apt-get install -y python3 python3-pip python3-venv
    
    print_status "System dependencies installed"
}

# Setup Python virtual environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."

    cd "$INSTALL_DIR"
    python3 -m venv venv
    source venv/bin/activate

    # Install Poetry if not already installed
    if ! command -v poetry > /dev/null; then
        curl -sSL https://install.python-poetry.org | python3 -
        export PATH="$HOME/.local/bin:$PATH"
    fi

    # Install project dependencies with Poetry
    poetry install --no-interaction

    print_status "Python environment setup complete (Poetry)"
}

# Copy application files
copy_application() {
    print_status "Copying application files..."
    
    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Copy source files
    cp -r "$SCRIPT_DIR/src" "$INSTALL_DIR/"
    cp -r "$SCRIPT_DIR/config" "$INSTALL_DIR/"
    
    # Copy configuration files to system config directory
    cp "$SCRIPT_DIR/config/service-settings.yaml" "$CONFIG_DIR/settings.yaml"
    
    print_status "Application files copied"
}

# Install systemd service
install_systemd_service() {
    print_status "Installing systemd service..."
    
    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Copy service file
    cp "$SCRIPT_DIR/systemd/${SERVICE_NAME}.service" "$SYSTEMD_DIR/"
    
    # Reload systemd
    systemctl daemon-reload
    
    print_status "Systemd service installed"
}

# Set permissions
set_permissions() {
    print_status "Setting permissions..."
    
    # Set ownership
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$LOG_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "/var/lib/${SERVICE_NAME}"
    
    # Set executable permissions
    chmod +x "$INSTALL_DIR/src/monitor_service.py"
    
    # Set proper permissions for config files
    chmod 640 "$CONFIG_DIR/settings.yaml"
    
    print_status "Permissions set"
}

# Configure log rotation
setup_log_rotation() {
    print_status "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/${SERVICE_NAME}" << EOF
${LOG_DIR}/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su ${SERVICE_USER} ${SERVICE_GROUP}
}
EOF
    
    print_status "Log rotation configured"
}

# Main installation function
main() {
    DEV_MODE=0
    for arg in "$@"; do
        if [[ "$arg" == "--dev" ]]; then
            DEV_MODE=1
        fi
    done

    print_status "Starting NGINX Security Monitor installation..."

    check_root
    create_service_user
    create_directories
    install_dependencies

    # Pass dev mode to setup_python_env
    setup_python_env $DEV_MODE
    copy_application
    install_systemd_service
    set_permissions
    setup_log_rotation

    print_status "Installation completed successfully!"
    echo
    print_warning "Next steps:"
    echo "1. Edit the configuration file: $CONFIG_DIR/settings.yaml"
    echo "2. Enable the service: systemctl enable $SERVICE_NAME"
    echo "3. Start the service: systemctl start $SERVICE_NAME"
    echo "4. Check service status: systemctl status $SERVICE_NAME"
    echo "5. View logs: journalctl -u $SERVICE_NAME -f"
    echo
}

# Update setup_python_env to accept dev mode
setup_python_env() {
    print_status "Setting up Python virtual environment..."

    cd "$INSTALL_DIR"
    python3 -m venv venv
    source venv/bin/activate

    # Install Poetry if not already installed
    if ! command -v poetry > /dev/null; then
        curl -sSL https://install.python-poetry.org | python3 -
        export PATH="$HOME/.local/bin:$PATH"
    fi

    # Install project dependencies with Poetry
    if [[ "$1" == "1" ]]; then
        poetry install --no-interaction --with dev
    else
        poetry install --no-interaction
    fi

    print_status "Python environment setup complete (Poetry)"
}

# Run main function
main "$@"
