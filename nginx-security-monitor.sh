#!/bin/bash

# NGINX Security Monitor Management Script
# Provides easy management of the NGINX Security Monitor service

SERVICE_NAME="nginx-security-monitor"
CONFIG_FILE="/etc/${SERVICE_NAME}/settings.yaml"
LOG_FILE="/var/log/${SERVICE_NAME}/${SERVICE_NAME}.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 {start|stop|restart|status|logs|config|install|uninstall|update}"
    echo
    echo "Commands:"
    echo "  start      - Start the service"
    echo "  stop       - Stop the service"
    echo "  restart    - Restart the service"
    echo "  status     - Show service status"
    echo "  logs       - Show recent logs"
    echo "  config     - Edit configuration"
    echo "  install    - Install the service"
    echo "  uninstall  - Uninstall the service"
    echo "  update     - Update the service"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== NGINX Security Monitor - $1 ===${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This operation requires root privileges (use sudo)"
        exit 1
    fi
}

service_start() {
    print_header "Starting Service"
    check_root
    
    systemctl start "$SERVICE_NAME"
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Service started successfully"
    else
        print_error "Failed to start service"
        exit 1
    fi
}

service_stop() {
    print_header "Stopping Service"
    check_root
    
    systemctl stop "$SERVICE_NAME"
    
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Service stopped successfully"
    else
        print_error "Failed to stop service"
        exit 1
    fi
}

service_restart() {
    print_header "Restarting Service"
    check_root
    
    systemctl restart "$SERVICE_NAME"
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Service restarted successfully"
    else
        print_error "Failed to restart service"
        exit 1
    fi
}

service_status() {
    print_header "Service Status"
    
    echo "Service Status:"
    systemctl status "$SERVICE_NAME" --no-pager -l
    
    echo
    echo "Service Logs (last 10 lines):"
    journalctl -u "$SERVICE_NAME" --no-pager -l -n 10
}

service_logs() {
    print_header "Service Logs"
    
    echo "Following service logs (Press Ctrl+C to exit):"
    journalctl -u "$SERVICE_NAME" -f
}

edit_config() {
    print_header "Edit Configuration"
    check_root
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Create backup
    cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    print_status "Configuration backup created"
    
    # Open editor
    if command -v nano > /dev/null; then
        nano "$CONFIG_FILE"
    elif command -v vi > /dev/null; then
        vi "$CONFIG_FILE"
    else
        print_error "No suitable editor found (nano or vi)"
        exit 1
    fi
    
    # Validate configuration
    python3 -c "import yaml; yaml.safe_load(open('$CONFIG_FILE'))" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "Configuration syntax is valid"
        
        read -p "Restart service to apply changes? [y/N]: " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            service_restart
        fi
    else
        print_error "Configuration syntax error detected!"
        read -p "Restore backup? [Y/n]: " -r
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            echo "Please fix the configuration manually"
        else
            mv "${CONFIG_FILE}.backup."* "$CONFIG_FILE"
            print_status "Configuration restored from backup"
        fi
    fi
}

install_service() {
    print_header "Installing Service"
    
    # Get script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    if [[ -f "$SCRIPT_DIR/install.sh" ]]; then
        bash "$SCRIPT_DIR/install.sh"
    else
        print_error "install.sh not found in script directory"
        exit 1
    fi
}

uninstall_service() {
    print_header "Uninstalling Service"
    check_root
    
    read -p "Are you sure you want to uninstall NGINX Security Monitor? [y/N]: " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Uninstall cancelled"
        exit 0
    fi
    
    # Stop and disable service
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    
    # Remove service file
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    
    # Remove application files
    rm -rf "/opt/${SERVICE_NAME}"
    rm -rf "/etc/${SERVICE_NAME}"
    rm -rf "/var/log/${SERVICE_NAME}"
    rm -rf "/var/lib/${SERVICE_NAME}"
    
    # Remove user and group
    userdel nginx-monitor 2>/dev/null || true
    groupdel nginx-monitor 2>/dev/null || true
    
    # Remove log rotation
    rm -f "/etc/logrotate.d/${SERVICE_NAME}"
    
    print_status "Service uninstalled successfully"
}

update_service() {
    print_header "Updating Service"
    check_root
    
    print_warning "This will update the service code but preserve configuration"
    read -p "Continue? [y/N]: " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Update cancelled"
        exit 0
    fi
    
    # Stop service
    systemctl stop "$SERVICE_NAME"
    
    # Backup current installation
    cp -r "/opt/${SERVICE_NAME}" "/opt/${SERVICE_NAME}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Get script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Update source files
    cp -r "$SCRIPT_DIR/src" "/opt/${SERVICE_NAME}/"
    
    # Set permissions
    chown -R nginx-monitor:nginx-monitor "/opt/${SERVICE_NAME}"
    chmod +x "/opt/${SERVICE_NAME}/src/monitor_service.py"
    
    # Start service
    systemctl start "$SERVICE_NAME"
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Service updated and started successfully"
    else
        print_error "Service update completed but failed to start"
        print_status "Check logs: journalctl -u $SERVICE_NAME"
    fi
}

# Main script logic
case "$1" in
    start)
        service_start
        ;;
    stop)
        service_stop
        ;;
    restart)
        service_restart
        ;;
    status)
        service_status
        ;;
    logs)
        service_logs
        ;;
    config)
        edit_config
        ;;
    install)
        install_service
        ;;
    uninstall)
        uninstall_service
        ;;
    update)
        update_service
        ;;
    *)
        print_usage
        exit 1
        ;;
esac
