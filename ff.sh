#!/bin/bash

# Plesk Ubuntu 22.04 System Optimization Script
# Version: 2025.1
# Author: System Administrator
# Description: Professional optimization script for Plesk on Ubuntu 22.04

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Check Ubuntu version
if ! grep -q "22.04" /etc/os-release; then
    error "This script is designed for Ubuntu 22.04 LTS"
fi

log "Starting Plesk Ubuntu 22.04 Professional Optimization..."

# Update system
log "Updating system packages..."
apt update && apt upgrade -y

# Install essential packages
log "Installing essential optimization packages..."
apt install -y htop iotop sysstat curl wget git vim ufw fail2ban logrotate

# 1. KERNEL PARAMETERS OPTIMIZATION
log "Optimizing kernel parameters..."
cat > /etc/sysctl.conf << 'EOF'
# Network Performance Tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 16384 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 30000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Security
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# File System
fs.file-max = 2097152
fs.nr_open = 1048576

# Memory Management
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1
vm.min_free_kbytes = 65536

# Connection Tracking
net.netfilter.nf_conntrack_max = 262144
net.ipv4.netfilter.ip_conntrack_tcp_timeout_established = 7200

# TCP Optimization
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_tw_buckets = 400000
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
EOF

# Apply sysctl settings
sysctl -p

# 2. SYSTEM LIMITS OPTIMIZATION
log "Optimizing system limits..."
cat > /etc/security/limits.conf << 'EOF'
# System Limits for Plesk Optimization
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
* soft memlock unlimited
* hard memlock unlimited

# Web server specific
www-data soft nofile 65536
www-data hard nofile 65536
psaadm soft nofile 65536
psaadm hard nofile 65536
psacln soft nofile 65536
psacln hard nofile 65536

# Database
mysql soft nofile 65536
mysql hard nofile 65536
postgres soft nofile 65536
postgres hard nofile 65536
EOF

# Add to systemd
echo "DefaultLimitNOFILE=65536" >> /etc/systemd/system.conf
echo "DefaultLimitNPROC=32768" >> /etc/systemd/system.conf

# 3. CPU OPTIMIZATION
log "Optimizing CPU settings..."
# Set CPU governor to performance
echo 'GOVERNOR="performance"' > /etc/default/cpufrequtils
cpupower frequency-set -g performance 2>/dev/null || true

# Disable transparent huge pages
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag

# Make permanent
cat > /etc/systemd/system/disable-thp.service << 'EOF'
[Unit]
Description=Disable Transparent Huge Pages (THP)
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=basic.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled && echo never > /sys/kernel/mm/transparent_hugepage/defrag'

[Install]
WantedBy=basic.target
EOF

systemctl enable disable-thp
systemctl start disable-thp

# 4. DISK I/O OPTIMIZATION
log "Optimizing disk I/O..."
# Update fstab with optimized mount options
cp /etc/fstab /etc/fstab.backup
sed -i 's/errors=remount-ro/errors=remount-ro,noatime,nodiratime/' /etc/fstab

# Set I/O scheduler
echo 'ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/scheduler}="deadline"' > /etc/udev/rules.d/60-io-scheduler.rules
echo 'ACTION=="add|change", KERNEL=="nvme[0-9]*", ATTR{queue/scheduler}="none"' >> /etc/udev/rules.d/60-io-scheduler.rules

# 5. MEMORY OPTIMIZATION
log "Optimizing memory settings..."
# Configure swap
echo 'vm.swappiness=10' >> /etc/sysctl.conf
echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.conf

# 6. NETWORK OPTIMIZATION
log "Optimizing network stack..."
# Enable BBR congestion control
modprobe tcp_bbr
echo 'tcp_bbr' >> /etc/modules-load.d/modules.conf

# 7. SECURITY OPTIMIZATIONS
log "Configuring security settings..."
# Configure UFW
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 53
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8880/tcp
ufw allow 8443/tcp

# Configure fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[plesk-panel]
enabled = true
port = 8880,8443
filter = plesk-panel
logpath = /var/log/plesk/panel.log
maxretry = 3

[plesk-postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 3

[plesk-dovecot]
enabled = true
port = pop3,pop3s,imap,imaps
filter = dovecot
logpath = /var/log/mail.log
maxretry = 3
EOF

# Create Plesk panel filter
cat > /etc/fail2ban/filter.d/plesk-panel.conf << 'EOF'
[Definition]
failregex = ^.*: .*Login failed.*client IP.*<HOST>.*$
            ^.*: Authentication failed.*from.*<HOST>.*$
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# 8. PLESK SPECIFIC OPTIMIZATIONS
log "Applying Plesk-specific optimizations..."

# Check if Plesk is installed
if [ -d "/usr/local/psa" ]; then
    # Configure Plesk panel.ini
    cat > /usr/local/psa/admin/conf/panel.ini << 'EOF'
[environment]
debug = false
development = false

[database]
connections_limit = 40

[auth]
lifetime = 3600
unlock_admin_account_timeout = 600

[ui]
max_input_vars = 10000

[apache]
MaxClients = 150
StartServers = 5
MinSpareServers = 5
MaxSpareServers = 10
MaxRequestsPerChild = 1000

[nginx]
worker_processes = auto
worker_connections = 1024
keepalive_timeout = 60
client_max_body_size = 128M
EOF

    # Optimize MySQL/MariaDB if exists
    if [ -f "/etc/mysql/my.cnf" ] || [ -f "/etc/mysql/mariadb.conf.d/50-server.cnf" ]; then
        log "Optimizing MySQL/MariaDB configuration..."
        
        # Calculate optimal values based on system RAM
        TOTAL_RAM=$(free -m | awk 'NR==2{print $2}')
        INNODB_BUFFER_POOL=$((TOTAL_RAM * 70 / 100))
        MAX_CONNECTIONS=100
        
        if [ $TOTAL_RAM -gt 8192 ]; then
            MAX_CONNECTIONS=200
        fi
        
        cat > /etc/mysql/conf.d/plesk-optimization.cnf << EOF
[mysql]
max_allowed_packet = 256M

[mysqld]
# Performance Optimization
innodb_buffer_pool_size = ${INNODB_BUFFER_POOL}M
innodb_log_file_size = 256M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
query_cache_type = 1
query_cache_size = 128M
query_cache_limit = 4M
tmp_table_size = 256M
max_heap_table_size = 256M
max_connections = $MAX_CONNECTIONS
thread_cache_size = 16
table_open_cache = 4096
key_buffer_size = 256M
sort_buffer_size = 2M
read_buffer_size = 2M
read_rnd_buffer_size = 2M
myisam_sort_buffer_size = 64M

# Binary Logging
log_bin = mysql-bin
binlog_format = ROW
expire_logs_days = 7
max_binlog_size = 100M

# InnoDB Optimization
innodb_lock_wait_timeout = 50
innodb_io_capacity = 200
innodb_read_io_threads = 4
innodb_write_io_threads = 4
innodb_purge_threads = 1
innodb_thread_concurrency = 0
EOF
    fi
    
    # Restart Plesk services
    log "Restarting Plesk services..."
    systemctl restart plesk-php*-fpm 2>/dev/null || true
    systemctl restart plesk-web-socket 2>/dev/null || true
    systemctl restart sw-engine 2>/dev/null || true
    systemctl restart mariadb 2>/dev/null || systemctl restart mysql 2>/dev/null || true
else
    warning "Plesk not detected. Skipping Plesk-specific optimizations."
fi

# 9. LOG ROTATION OPTIMIZATION
log "Configuring log rotation..."
cat > /etc/logrotate.d/plesk-optimization << 'EOF'
/var/log/plesk/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    postrotate
        /usr/local/psa/admin/bin/httpdmng --reconfigure-all
    endscript
}
EOF

# 10. CRON OPTIMIZATIONS
log "Setting up maintenance cron jobs..."
cat > /etc/cron.d/plesk-optimization << 'EOF'
# Plesk System Optimization Maintenance Jobs
0 2 * * 0 root /usr/bin/find /tmp -type f -atime +7 -delete
30 2 * * 0 root /usr/bin/find /var/tmp -type f -atime +7 -delete
0 3 * * 0 root /usr/sbin/logrotate /etc/logrotate.conf
30 3 * * * root /bin/sync && echo 3 > /proc/sys/vm/drop_caches
0 4 * * 0 root /usr/bin/apt autoremove -y && /usr/bin/apt autoclean
EOF

# 11. FINAL SYSTEM TWEAKS
log "Applying final system tweaks..."

# Disable unnecessary services
systemctl disable apport 2>/dev/null || true
systemctl disable whoopsie 2>/dev/null || true

# Enable useful services
systemctl enable ufw
systemctl enable fail2ban

# Create optimization status file
cat > /root/plesk-optimization-status.txt << 'EOF'
Plesk Ubuntu 22.04 Optimization Applied
=======================================
Date: $(date)
Script Version: 2025.1

Optimizations Applied:
- Kernel parameters tuned
- System limits increased
- CPU performance mode enabled
- Disk I/O optimized
- Memory management improved
- Network stack optimized (BBR enabled)
- Security hardened (UFW, Fail2ban)
- Plesk-specific optimizations
- Log rotation configured
- Maintenance cron jobs added

Next Steps:
1. Reboot the server to apply all changes
2. Monitor system performance with htop, iotop
3. Check logs in /var/log/ for any issues
4. Review Plesk performance in panel

Monitoring Commands:
- htop (CPU/Memory usage)
- iotop (Disk I/O)
- ss -tuln (Network connections)
- fail2ban-client status (Security status)
EOF

log "Optimization completed successfully!"
echo
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}  PLESK OPTIMIZATION COMPLETED!${NC}"
echo -e "${YELLOW}========================================${NC}"
echo
echo -e "${GREEN}Next steps:${NC}"
echo "1. Reboot your server: ${BLUE}reboot${NC}"
echo "2. Check optimization status: ${BLUE}cat /root/plesk-optimization-status.txt${NC}"
echo "3. Monitor performance with: ${BLUE}htop${NC} and ${BLUE}iotop${NC}"
echo
echo -e "${YELLOW}IMPORTANT: Please reboot your server now to apply all optimizations!${NC}"
echo
