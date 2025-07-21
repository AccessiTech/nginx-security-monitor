#!/bin/bash

# NGINX Security Monitor Hardening Script
# Implements additional security measures to protect the service itself

set -e

# Configuration
SERVICE_NAME="nginx-security-monitor"
SERVICE_USER="nginx-monitor"
SERVICE_GROUP="nginx-monitor"
INSTALL_DIR="/opt/${SERVICE_NAME}"
CONFIG_DIR="/etc/${SERVICE_NAME}"
LOG_DIR="/var/log/${SERVICE_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Harden file permissions
harden_file_permissions() {
    print_header "Hardening File Permissions"
    
    # Configuration files - only service user should read
    if [[ -d "$CONFIG_DIR" ]]; then
        chmod 750 "$CONFIG_DIR"
        find "$CONFIG_DIR" -name "*.yaml" -exec chmod 640 {} \;
        find "$CONFIG_DIR" -name "*.yml" -exec chmod 640 {} \;
        find "$CONFIG_DIR" -name ".salt" -exec chmod 600 {} \;
        chown -R root:"$SERVICE_GROUP" "$CONFIG_DIR"
        print_status "Configuration directory permissions hardened"
    fi
    
    # Application files - read-only for service user
    if [[ -d "$INSTALL_DIR" ]]; then
        chmod 755 "$INSTALL_DIR"
        find "$INSTALL_DIR/src" -name "*.py" -exec chmod 644 {} \;
        chmod 755 "$INSTALL_DIR/src/monitor_service.py"  # Main script needs execute
        chown -R root:"$SERVICE_GROUP" "$INSTALL_DIR"
        print_status "Application directory permissions hardened"
    fi
    
    # Log directory - service user can write
    if [[ -d "$LOG_DIR" ]]; then
        chmod 750 "$LOG_DIR"
        touch "$LOG_DIR/${SERVICE_NAME}.log"
        chmod 640 "$LOG_DIR/${SERVICE_NAME}.log"
        chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$LOG_DIR"
        print_status "Log directory permissions hardened"
    fi
    
    # Plugin directories - restrict access
    for plugin_dir in "$CONFIG_DIR/plugins" "$INSTALL_DIR/custom_plugins"; do
        if [[ -d "$plugin_dir" ]]; then
            chmod 750 "$plugin_dir"
            find "$plugin_dir" -name "*.py" -exec chmod 640 {} \;
            chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$plugin_dir"
            print_status "Plugin directory permissions hardened: $plugin_dir"
        fi
    done
}

# Setup firewall rules
setup_firewall_rules() {
    print_header "Setting Up Firewall Rules"
    
    # Check if iptables is available
    if ! command -v iptables > /dev/null; then
        print_warning "iptables not found, skipping firewall setup"
        return
    fi
    
    # Create custom chain for nginx-monitor rules
    if ! iptables -L NGINX_MONITOR_CHAIN > /dev/null 2>&1; then
        iptables -N NGINX_MONITOR_CHAIN
        iptables -A INPUT -j NGINX_MONITOR_CHAIN
        print_status "Created custom firewall chain"
    fi
    
    # Block common attack ports from affecting our service
    declare -a attack_ports=("1433" "3389" "5432" "6379" "27017")
    
    for port in "${attack_ports[@]}"; do
        if ! iptables -C NGINX_MONITOR_CHAIN -p tcp --dport "$port" -j DROP 2>/dev/null; then
            iptables -A NGINX_MONITOR_CHAIN -p tcp --dport "$port" -j DROP
            print_status "Blocked common attack port: $port"
        fi
    done
    
    # Rate limit SSH connections to protect the host
    if ! iptables -C INPUT -p tcp --dport 22 -m state --state NEW -m recent --set 2>/dev/null; then
        iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
        iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
        print_status "SSH rate limiting enabled"
    fi
    
    # Save firewall rules (method varies by distribution)
    if command -v netfilter-persistent > /dev/null; then
        netfilter-persistent save
        print_status "Firewall rules saved with netfilter-persistent"
    elif command -v iptables-save > /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null || \
        print_warning "Could not save iptables rules automatically"
    fi
}

# Setup system monitoring
setup_monitoring() {
    print_header "Setting Up System Monitoring"
    
    # Create logrotate configuration for our logs
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
    postrotate
        systemctl reload ${SERVICE_NAME} 2>/dev/null || true
    endscript
}
EOF
    print_status "Log rotation configured"
    
    # Setup log monitoring with rsyslog (if available)
    if command -v rsyslogd > /dev/null; then
        cat > "/etc/rsyslog.d/10-${SERVICE_NAME}.conf" << EOF
# NGINX Security Monitor logging
if \$programname == '${SERVICE_NAME}' then /var/log/${SERVICE_NAME}/${SERVICE_NAME}.log
& stop
EOF
        systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null || true
        print_status "Rsyslog configuration added"
    fi
}

# Harden systemd service
harden_systemd_service() {
    print_header "Hardening Systemd Service"
    
    # Backup original service file
    cp "/etc/systemd/system/${SERVICE_NAME}.service" "/etc/systemd/system/${SERVICE_NAME}.service.backup"
    
    # Add additional security restrictions
    cat >> "/etc/systemd/system/${SERVICE_NAME}.service" << EOF

# Additional security hardening
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
PrivateMounts=yes

# Network restrictions
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressAllow=localhost 127.0.0.0/8 ::1/128

# File system restrictions
ReadWritePaths=${LOG_DIR} ${CONFIG_DIR} /var/lib/${SERVICE_NAME}
ReadOnlyPaths=${INSTALL_DIR}
InaccessiblePaths=/proc/sys /proc/sysrq-trigger /proc/latency_stats /proc/acpi /proc/timer_stats /proc/fs

# System call restrictions
SystemCallFilter=@system-service
SystemCallFilter=~@debug @mount @cpu-emulation @obsolete @privileged @reboot @swap @raw-io
SystemCallErrorNumber=EPERM
EOF

    systemctl daemon-reload
    print_status "Systemd service hardened"
}

# Setup integrity monitoring
setup_integrity_monitoring() {
    print_header "Setting Up Integrity Monitoring"
    
    # Install AIDE if available (Advanced Intrusion Detection Environment)
    if command -v apt-get > /dev/null; then
        apt-get update -qq
        if apt-get install -y aide 2>/dev/null; then
            print_status "AIDE installed for file integrity monitoring"
            
            # Add our directories to AIDE monitoring
            cat >> /etc/aide/aide.conf << EOF

# NGINX Security Monitor integrity monitoring
${INSTALL_DIR}/src PERMS
${CONFIG_DIR} PERMS
/etc/systemd/system/${SERVICE_NAME}.service PERMS
EOF
            
            # Initialize AIDE database
            aide --init 2>/dev/null && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            
            # Setup daily AIDE check
            cat > "/etc/cron.daily/aide-${SERVICE_NAME}" << EOF
#!/bin/bash
aide --check 2>/dev/null | grep -E "${SERVICE_NAME}|${INSTALL_DIR}|${CONFIG_DIR}" | mail -s "AIDE Report for NGINX Security Monitor" root 2>/dev/null || true
EOF
            chmod +x "/etc/cron.daily/aide-${SERVICE_NAME}"
            print_status "AIDE integrity monitoring configured"
        fi
    elif command -v yum > /dev/null; then
        if yum install -y aide 2>/dev/null; then
            print_status "AIDE installed for file integrity monitoring"
        fi
    fi
}

# Setup attack surface reduction
reduce_attack_surface() {
    print_header "Reducing Attack Surface"
    
    # Disable unnecessary services that could be attack vectors
    declare -a services_to_disable=("telnet" "rsh" "rlogin" "finger" "talk" "ntalk")
    
    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" 2>/dev/null | grep -q enabled; then
            systemctl disable "$service" 2>/dev/null || true
            print_status "Disabled unnecessary service: $service"
        fi
    done
    
    # Remove unnecessary packages that could be exploited
    if command -v apt-get > /dev/null; then
        declare -a packages_to_remove=("telnet" "rsh-client" "talk" "finger")
        for package in "${packages_to_remove[@]}"; do
            if dpkg -l | grep -q "^ii.*$package"; then
                apt-get remove -y "$package" 2>/dev/null || true
                print_status "Removed unnecessary package: $package"
            fi
        done
    fi
    
    # Disable IPv6 if not needed (reduces attack surface)
    read -p "Disable IPv6 to reduce attack surface? [y/N]: " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
        sysctl -p
        print_status "IPv6 disabled"
    fi
}

# Setup security monitoring
setup_security_monitoring() {
    print_header "Setting Up Security Monitoring"
    
    # Create security monitoring script
    cat > "/usr/local/bin/${SERVICE_NAME}-security-check" << 'EOF'
#!/bin/bash

# Security check script for NGINX Security Monitor
SERVICE_NAME="nginx-security-monitor"
LOG_FILE="/var/log/${SERVICE_NAME}/${SERVICE_NAME}-security.log"

echo "$(date): Starting security check" >> "$LOG_FILE"

# Check for unusual network connections
netstat -tuln | grep -v "127.0.0.1\|::1" | grep LISTEN >> "$LOG_FILE" 2>/dev/null || true

# Check for failed login attempts
grep "Failed password" /var/log/auth.log | tail -10 >> "$LOG_FILE" 2>/dev/null || true

# Check service status
systemctl status "$SERVICE_NAME" --no-pager >> "$LOG_FILE" 2>/dev/null || true

# Check for high resource usage
top -b -n1 | head -20 >> "$LOG_FILE" 2>/dev/null || true

echo "$(date): Security check completed" >> "$LOG_FILE"
EOF
    
    chmod +x "/usr/local/bin/${SERVICE_NAME}-security-check"
    
    # Setup cron job for regular security checks
    cat > "/etc/cron.d/${SERVICE_NAME}-security" << EOF
# NGINX Security Monitor security checks
*/15 * * * * root /usr/local/bin/${SERVICE_NAME}-security-check
EOF
    
    print_status "Security monitoring script installed"
}

# Main function
main() {
    print_header "NGINX Security Monitor Service Hardening"
    
    check_root
    
    echo "This script will implement additional security measures to protect the"
    echo "NGINX Security Monitor service itself from attacks."
    echo
    read -p "Continue with hardening? [y/N]: " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Hardening cancelled"
        exit 0
    fi
    
    harden_file_permissions
    setup_firewall_rules
    setup_monitoring
    harden_systemd_service
    setup_integrity_monitoring
    reduce_attack_surface
    setup_security_monitoring
    
    print_status "Service hardening completed!"
    echo
    print_warning "Next steps:"
    echo "1. Restart the service: systemctl restart $SERVICE_NAME"
    echo "2. Review firewall rules: iptables -L"
    echo "3. Monitor logs: journalctl -u $SERVICE_NAME -f"
    echo "4. Test the service functionality"
    echo "5. Review security monitoring: /var/log/${SERVICE_NAME}/${SERVICE_NAME}-security.log"
    echo
}

# Run main function
main "$@"
