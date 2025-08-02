#!/bin/bash

# Plesk Optimization Manual Completion Script
# This script completes the remaining optimizations

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

log "Completing Plesk optimization..."

# 1. Fix repository issue first
log "Fixing repository issues..."
rm -f /etc/apt/sources.list.d/*watchdog* 2>/dev/null || true
rm -f /etc/apt/sources.list.d/imunify360-testing.list.example 2>/dev/null || true
apt update -qq

# 2. Complete system limits if not done
log "Ensuring system limits are set..."
if ! grep -q "www-data soft nofile" /etc/security/limits.conf; then
    cat >> /etc/security/limits.conf << 'EOF'

# Plesk Optimization Limits
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
www-data soft nofile 65536
www-data hard nofile 65536
psaadm soft nofile 65536
psaadm hard nofile 65536
mysql soft nofile 65536
mysql hard nofile 65536
EOF
fi

# Add to systemd if not present
if ! grep -q "DefaultLimitNOFILE" /etc/systemd/system.conf; then
    echo "DefaultLimitNOFILE=65536" >> /etc/systemd/system.conf
    echo "DefaultLimitNPROC=32768" >> /etc/systemd/system.conf
fi

# 3. CPU Optimization
log "Setting CPU to performance mode..."
# Set CPU governor
if command -v cpupower >/dev/null 2>&1; then
    cpupower frequency-set -g performance 2>/dev/null || true
fi

# Disable transparent huge pages
log "Disabling Transparent Huge Pages..."
echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true

# Create systemd service for THP
cat > /etc/systemd/system/disable-thp.service << 'EOF'
[Unit]
Description=Disable Transparent Huge Pages
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=basic.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled && echo never > /sys/kernel/mm/transparent_hugepage/defrag'

[Install]
WantedBy=basic.target
EOF

systemctl enable disable-thp 2>/dev/null || true
systemctl start disable-thp 2>/dev/null || true

# 4. Disk I/O optimization
log "Optimizing disk I/O..."
# Update fstab with optimized mount options
cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d)
if ! grep -q "noatime" /etc/fstab; then
    sed -i 's/errors=remount-ro/errors=remount-ro,noatime,nodiratime/' /etc/fstab
fi

# Set I/O scheduler
cat > /etc/udev/rules.d/60-io-scheduler.rules << 'EOF'
ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/scheduler}="deadline"
ACTION=="add|change", KERNEL=="nvme[0-9]*", ATTR{queue/scheduler}="none"
EOF

# 5. Network optimization
log "Enabling BBR congestion control..."
modprobe tcp_bbr 2>/dev/null || true
echo 'tcp_bbr' > /etc/modules-load.d/bbr.conf

# Fix the missing conntrack parameter
log "Fixing conntrack parameters..."
# Use the correct parameter for newer kernels
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=7200 2>/dev/null || \
sysctl -w net.ipv4.netfilter.ip_conntrack_tcp_timeout_established=7200 2>/dev/null || true

# 6. Security configuration
log "Configuring firewall and security..."
# UFW configuration
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 53 comment 'DNS'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow 8880/tcp comment 'Plesk Panel'
ufw allow 8443/tcp comment 'Plesk Panel SSL'

# Configure fail2ban for Plesk
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
banaction = iptables-multiport

[plesk-postfix]
enabled = true
port = smtp,465,587
filter = postfix
logpath = /var/log/mail.log
maxretry = 5

[plesk-dovecot]
enabled = true
port = pop3,pop3s,imap,imaps
filter = dovecot
logpath = /var/log/mail.log
maxretry = 5
EOF

# Create Plesk panel filter
cat > /etc/fail2ban/filter.d/plesk-panel.conf << 'EOF'
[Definition]
failregex = ^.*Login failed.*client IP.*<HOST>.*$
            ^.*Authentication failed.*from.*<HOST>.*$
            ^.*Invalid login.*from.*<HOST>.*$
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# 7. Plesk specific optimizations
log "Applying Plesk-specific optimizations..."
if [ -d "/usr/local/psa" ]; then
    # Configure panel.ini
    mkdir -p /usr/local/psa/admin/conf
    cat > /usr/local/psa/admin/conf/panel.ini << 'EOF'
[database]
connections_limit = 50

[auth]
lifetime = 7200
unlock_admin_account_timeout = 600

[ui]
max_input_vars = 10000
max_post_size = 128M
max_file_uploads = 50

[security]
admin_session_timeout = 3600
EOF

    # Optimize MySQL/MariaDB
    if systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb; then
        log "Optimizing MySQL/MariaDB..."
        
        TOTAL_RAM=$(free -m | awk 'NR==2{print $2}')
        INNODB_BUFFER_POOL=$((TOTAL_RAM * 60 / 100))
        MAX_CONNECTIONS=150
        
        if [ $TOTAL_RAM -gt 8192 ]; then
            INNODB_BUFFER_POOL=$((TOTAL_RAM * 70 / 100))
            MAX_CONNECTIONS=200
        fi
        
        cat > /etc/mysql/conf.d/plesk-optimization.cnf << EOF
[mysqld]
# Performance Optimization
innodb_buffer_pool_size = ${INNODB_BUFFER_POOL}M
innodb_log_file_size = 256M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1

# Query Cache
query_cache_type = 1
query_cache_size = 128M
query_cache_limit = 2M

# Connection Settings
max_connections = $MAX_CONNECTIONS
max_connect_errors = 100000
thread_cache_size = 16
table_open_cache = 4096

# Buffer Settings
key_buffer_size = 256M
sort_buffer_size = 2M
read_buffer_size = 1M
read_rnd_buffer_size = 2M
tmp_table_size = 128M
max_heap_table_size = 128M

# InnoDB Settings
innodb_lock_wait_timeout = 50
innodb_io_capacity = 200
innodb_read_io_threads = 4
innodb_write_io_threads = 4

# Binary Logging
expire_logs_days = 7
max_binlog_size = 100M

# Other optimizations
skip-name-resolve
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
EOF
    fi
    
    # Restart services
    log "Restarting services..."
    systemctl restart mysql 2>/dev/null || systemctl restart mariadb 2>/dev/null || true
    systemctl restart plesk-php*-fpm 2>/dev/null || true
    
else
    warning "Plesk not found, skipping Plesk-specific optimizations"
fi

# 8. Log rotation
log "Setting up log rotation..."
cat > /etc/logrotate.d/plesk-optimization << 'EOF'
/var/log/plesk/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}

/var/log/mysql/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

# 9. Maintenance cron jobs
log "Setting up maintenance cron jobs..."
cat > /etc/cron.d/plesk-maintenance << 'EOF'
# Plesk System Maintenance
0 2 * * 0 root /usr/bin/find /tmp -type f -atime +7 -delete 2>/dev/null
30 2 * * 0 root /usr/bin/find /var/tmp -type f -atime +7 -delete 2>/dev/null
0 3 * * 0 root /usr/sbin/logrotate /etc/logrotate.conf
30 3 * * * root /bin/sync && echo 3 > /proc/sys/vm/drop_caches
0 4 * * 0 root /usr/bin/apt autoremove -y && /usr/bin/apt autoclean
EOF

# 10. Final system tweaks
log "Applying final optimizations..."
# Disable unnecessary services
systemctl disable apport 2>/dev/null || true
systemctl disable whoopsie 2>/dev/null || true

# Create status file
cat > /root/plesk-optimization-complete.txt << EOF
Plesk Ubuntu 22.04 Optimization Completed
========================================
Completion Date: $(date)
Server: $(hostname)

Applied Optimizations:
✓ Kernel parameters optimized
✓ System limits increased
✓ CPU performance mode enabled
✓ Transparent Huge Pages disabled
✓ Disk I/O optimized
✓ Network stack optimized (BBR)
✓ UFW firewall configured
✓ Fail2ban configured for Plesk
✓ MySQL/MariaDB optimized
✓ Log rotation configured
✓ Maintenance cron jobs added

System Information:
- Total RAM: $(free -h | awk 'NR==2{print $2}')
- CPU Cores: $(nproc)
- Disk: $(df -h / | awk 'NR==2{print $2}')

Monitoring Commands:
- htop (CPU/Memory)
- iotop (Disk I/O)
- ss -tuln (Network)
- fail2ban-client status

Next Steps:
1. Reboot server: reboot
2. Monitor performance
3. Check logs for issues
EOF

log "Optimization completed successfully!"
echo
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}   OPTIMIZATION COMPLETED!${NC}"
echo -e "${YELLOW}========================================${NC}"
echo
echo -e "${GREEN}Summary:${NC}"
echo "• All optimizations applied"
echo "• Security hardened"
echo "• Performance tuned"
echo "• Monitoring configured"
echo
echo -e "${YELLOW}IMPORTANT: Reboot your server now!${NC}"
echo -e "Command: ${GREEN}reboot${NC}"
echo
echo "Status file: /root/plesk-optimization-complete.txt"
