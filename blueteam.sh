#!/bin/bash

# ============================================================
# Linux Blue Team Triage / Host Information Collector
# ============================================================
#
# Purpose:
#   Collect security-relevant information from a Linux host.
#
# Design:
#   - Read-only collection
#   - Does not modify system configuration
#   - Creates a timestamped report
#   - Handles missing utilities gracefully
#
# Recommended:
#   Run as root for maximum visibility:
#       sudo ./blueteam.sh
#
# ============================================================

set -o pipefail

# Do not allow other users to read generated reports.
umask 077

VERSION="1.0"
HOSTNAME="$(hostname 2>/dev/null || echo unknown)"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"

# ============================================================
# Helper functions
# ============================================================

command_exists()
{
    command -v "$1" >/dev/null 2>&1
}

section()
{
    echo ""
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

subsection()
{
    echo ""
    echo "-------------------- $1 --------------------"
}

run_cmd()
{
    if command_exists "$1"; then
        "$@"
    else
        echo "[!] Command not available: $1"
    fi
}

# ============================================================
# System information
# ============================================================

sysinfo()
{
    section "SYSTEM INFORMATION"

    echo "Collector version : $VERSION"
    echo "Collection time   : $(date)"
    echo "Hostname          : $HOSTNAME"
    echo "Kernel            : $(uname -a)"

    subsection "Hostname / OS"

    if command_exists hostnamectl; then
        hostnamectl
    fi

    if [ -f /etc/os-release ]; then
        cat /etc/os-release
    fi

    subsection "Uptime"
    uptime

    subsection "CPU"
    run_cmd lscpu

    subsection "Memory"
    free -h

    subsection "Disk usage"
    df -h

    subsection "Block devices"

    if command_exists lsblk; then
        lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL
    fi

    subsection "Processes"
    ps auxww

    subsection "Services"

    if command_exists systemctl; then
        systemctl --type=service --no-pager
    fi
}

# ============================================================
# Network information
# ============================================================

networkinfo()
{
    section "NETWORK INFORMATION"

    subsection "IP addresses"
    ip addr

    subsection "Routing table"
    ip route

    subsection "Listening sockets"

    if command_exists ss; then
        ss -tulnp
    fi

    subsection "Established connections"

    if command_exists ss; then
        ss -tunap
    fi

    subsection "ARP / Neighbor table"

    if command_exists ip; then
        ip neigh
    fi

    subsection "DNS configuration"

    if [ -f /etc/resolv.conf ]; then
        cat /etc/resolv.conf
    fi

    subsection "Firewall"

    if command_exists ufw; then
        echo "[UFW]"
        ufw status verbose 2>&1
    fi

    if command_exists firewall-cmd; then
        echo "[firewalld]"
        firewall-cmd --state 2>&1
        firewall-cmd --list-all 2>&1
    fi

    if command_exists nft; then
        echo "[nftables]"
        nft list ruleset 2>&1
    fi

    if command_exists iptables; then
        echo "[iptables]"
        iptables -L -n -v 2>&1
    fi
}

# ============================================================
# Users and authentication
# ============================================================

useraudit()
{
    section "USER / ACCOUNT AUDIT"

    subsection "Logged-in users"
    who

    subsection "Currently active sessions"
    w

    subsection "User accounts"
    cat /etc/passwd

    subsection "UID 0 accounts"

    awk -F: '$3 == 0 {
        print $1 ":" $3 ":" $6 ":" $7
    }' /etc/passwd

    subsection "Accounts with login shells"

    awk -F: '$7 !~ /(nologin|false)$/ {
        print $1 ":" $6 ":" $7
    }' /etc/passwd

    subsection "Password aging information"

    if command_exists chage; then
        while IFS=: read -r username _ uid _ _ _ shell; do
            if [ "$uid" -ge 1000 ] 2>/dev/null || [ "$uid" -eq 0 ] 2>/dev/null; then
                echo "--- $username ---"
                chage -l "$username" 2>/dev/null
            fi
        done < /etc/passwd
    fi

    subsection "Recent logins"

    if command_exists last; then
        last -a
    fi

    subsection "Failed logins"

    if command_exists lastb; then
        lastb -a 2>/dev/null
    else
        echo "lastb unavailable or access denied."
    fi
}

# ============================================================
# SSH audit
# ============================================================

sshaudit()
{
    section "SSH SECURITY AUDIT"

    subsection "SSH service"

    if command_exists systemctl; then
        systemctl status ssh --no-pager 2>&1
        systemctl status sshd --no-pager 2>&1
    fi

    subsection "SSH configuration"

    if [ -f /etc/ssh/sshd_config ]; then
        echo "--- /etc/ssh/sshd_config ---"
        cat /etc/ssh/sshd_config
    fi

    if [ -d /etc/ssh/sshd_config.d ]; then
        echo "--- /etc/ssh/sshd_config.d ---"
        find /etc/ssh/sshd_config.d \
            -type f \
            -maxdepth 1 \
            -print \
            -exec cat {} \; 2>/dev/null
    fi

    subsection "Authorized SSH keys"

    while IFS=: read -r username _ uid _ _ home shell; do

        if [ -d "$home/.ssh" ]; then

            echo "--- User: $username ---"
            echo "Home: $home"

            find "$home/.ssh" \
                -maxdepth 1 \
                -type f \
                \( -name "authorized_keys" -o -name "authorized_keys2" \) \
                -print \
                -exec cat {} \; 2>/dev/null
        fi

    done < /etc/passwd
}

# ============================================================
# Persistence mechanisms
# ============================================================

persistence()
{
    section "PERSISTENCE MECHANISMS"

    subsection "Systemd enabled services"

    if command_exists systemctl; then
        systemctl list-unit-files \
            --type=service \
            --state=enabled \
            --no-pager
    fi

    subsection "Systemd timers"

    if command_exists systemctl; then
        systemctl list-timers --all --no-pager
    fi

    subsection "Cron directories"

    for directory in \
        /etc/cron.d \
        /etc/cron.daily \
        /etc/cron.hourly \
        /etc/cron.monthly \
        /etc/cron.weekly
    do
        if [ -d "$directory" ]; then
            echo "--- $directory ---"
            find "$directory" -maxdepth 1 -type f -ls
        fi
    done

    subsection "System crontab"

    if [ -f /etc/crontab ]; then
        cat /etc/crontab
    fi

    subsection "User crontabs"

    if command_exists crontab; then
        while IFS=: read -r username _ uid _ _ _ shell; do
            echo "--- $username ---"

            crontab -u "$username" -l 2>/dev/null || \
                echo "No crontab or access denied."

        done < /etc/passwd
    fi

    subsection "Shell startup files"

    for file in \
        /etc/profile \
        /etc/bash.bashrc \
        /etc/profile.d/*.sh
    do
        if [ -f "$file" ]; then
            echo "--- $file ---"
            cat "$file"
        fi
    done

    subsection "User shell startup files"

    while IFS=: read -r username _ uid _ _ home shell; do

        for file in \
            "$home/.bashrc" \
            "$home/.bash_profile" \
            "$home/.profile"
        do
            if [ -f "$file" ]; then
                echo "--- $file ---"
                cat "$file"
            fi
        done

    done < /etc/passwd
}

# ============================================================
# Security logs
# ============================================================

logaudit()
{
    section "SECURITY / AUTHENTICATION LOGS"

    subsection "Journal - authentication related"

    if command_exists journalctl; then

        echo "--- SSH events ---"
        journalctl \
            --no-pager \
            --since "24 hours ago" \
            | grep -Ei \
            'sshd|ssh|authentication|failed|invalid user|accepted|sudo' \
            | tail -n 500

    else
        echo "journalctl unavailable."
    fi

    subsection "Authentication log files"

    for logfile in \
        /var/log/auth.log \
        /var/log/secure
    do
        if [ -f "$logfile" ]; then
            echo "--- $logfile ---"
            tail -n 500 "$logfile"
        fi
    done

    subsection "Kernel messages"

    if command_exists dmesg; then
        dmesg --color=never 2>/dev/null | tail -n 500
    fi
}

# ============================================================
# Process investigation
# ============================================================

processaudit()
{
    section "PROCESS SECURITY AUDIT"

    subsection "Running processes"

    ps auxww

    subsection "Process tree"

    if command_exists pstree; then
        pstree -alp
    else
        ps -ef --forest
    fi

    subsection "Processes with deleted executables"

    if [ -d /proc ]; then
        for pid in /proc/[0-9]*; do

            exe=$(readlink "$pid/exe" 2>/dev/null)

            if [[ "$exe" == *"(deleted)"* ]]; then
                echo "$pid -> $exe"
            fi

        done
    fi

    subsection "Processes listening on network sockets"

    if command_exists ss; then
        ss -lntup
    fi

    subsection "Open files for suspicious temporary locations"

    if command_exists lsof; then
        lsof +D /tmp 2>/dev/null
        lsof +D /var/tmp 2>/dev/null
        lsof +D /dev/shm 2>/dev/null
    else
        echo "lsof is not installed."
    fi
}

# ============================================================
# Temporary files / suspicious locations
# ============================================================

fileaudit()
{
    section "FILE SYSTEM TRIAGE"

    subsection "Recently modified files in temporary directories"

    for directory in /tmp /var/tmp /dev/shm; do

        if [ -d "$directory" ]; then

            echo "--- $directory ---"

            find "$directory" \
                -xdev \
                -type f \
                -mtime -1 \
                -ls 2>/dev/null

        fi

    done

    subsection "World-writable files in temporary directories"

    for directory in /tmp /var/tmp /dev/shm; do

        if [ -d "$directory" ]; then

            echo "--- $directory ---"

            find "$directory" \
                -xdev \
                -type f \
                -perm -0002 \
                -ls 2>/dev/null

        fi

    done

    subsection "SUID files"

    find / \
        -xdev \
        -type f \
        -perm -4000 \
        -ls 2>/dev/null

    subsection "SGID files"

    find / \
        -xdev \
        -type f \
        -perm -2000 \
        -ls 2>/dev/null
}

# ============================================================
# Kernel / security controls
# ============================================================

securitycontrols()
{
    section "SECURITY CONTROLS"

    subsection "Loaded kernel modules"

    if command_exists lsmod; then
        lsmod
    fi

    subsection "SELinux"

    if command_exists getenforce; then
        getenforce
    elif command_exists sestatus; then
        sestatus
    else
        echo "SELinux tools unavailable."
    fi

    subsection "AppArmor"

    if command_exists aa-status; then
        aa-status 2>&1
    elif [ -d /sys/kernel/security/apparmor ]; then
        echo "AppArmor filesystem detected."
    else
        echo "AppArmor not detected."
    fi

    subsection "Kernel security parameters"

    if [ -f /proc/sys/kernel/randomize_va_space ]; then
        echo -n "ASLR: "
        cat /proc/sys/kernel/randomize_va_space
    fi

    subsection "Secure Boot"

    if command_exists mokutil; then
        mokutil --sb-state 2>&1
    else
        echo "mokutil unavailable."
    fi
}

# ============================================================
# Package information
# ============================================================

packageaudit()
{
    section "PACKAGE INFORMATION"

    subsection "Recently installed packages"

    if command_exists dpkg-query; then

        dpkg-query \
            -W \
            -f='${binary:Package}\t${Version}\n' \
            2>/dev/null

    elif command_exists rpm; then

        rpm -qa

    elif command_exists pacman; then

        pacman -Q

    else
        echo "No supported package manager detected."
    fi
}

# ============================================================
# Containers
# ============================================================

containeraudit()
{
    section "CONTAINER ENVIRONMENT"

    subsection "Docker"

    if command_exists docker; then
        docker ps -a 2>&1
    else
        echo "Docker not installed."
    fi

    subsection "Podman"

    if command_exists podman; then
        podman ps -a 2>&1
    else
        echo "Podman not installed."
    fi
}

# ============================================================
# Hardware health
# ============================================================

healthcheck()
{
    section "HARDWARE HEALTH"

    subsection "Sensors"

    if command_exists sensors; then
        sensors
    else
        echo "lm-sensors is not installed."
    fi

    subsection "SMART disk health"

    if command_exists smartctl; then

        for disk in /dev/sd? /dev/nvme?n1; do

            if [ -b "$disk" ]; then

                echo "--- $disk ---"

                smartctl -H "$disk" 2>&1

            fi

        done

    else
        echo "smartctl is not installed."
    fi

    subsection "BIOS"

    if command_exists dmidecode; then

        if [ "$EUID" -eq 0 ]; then
            dmidecode -t bios
        else
            echo "Run as root for BIOS information."
        fi

    else
        echo "dmidecode is not installed."
    fi

    subsection "GPU"

    if command_exists lspci; then
        lspci | grep -Ei 'vga|3d|display'
    fi
}

# ============================================================
# Summary
# ============================================================

summary()
{
    local filename
    local hashfile

    filename="blueteam_${HOSTNAME}_${TIMESTAMP}.txt"
    hashfile="${filename}.sha256"

    echo "Creating Blue Team report..."
    echo "File: $filename"

    {
        echo "============================================================"
        echo "LINUX BLUE TEAM TRIAGE REPORT"
        echo "============================================================"
        echo "Collector version : $VERSION"
        echo "Hostname          : $HOSTNAME"
        echo "Collection time   : $(date)"
        echo "Kernel            : $(uname -a)"
        echo ""

        sysinfo
        networkinfo
        useraudit
        sshaudit
        persistence
        logaudit
        processaudit
        fileaudit
        securitycontrols
        packageaudit
        containeraudit
        healthcheck

        section "COLLECTION COMPLETE"

        echo "Finished: $(date)"

    } > "$filename" 2>&1

    if [ $? -eq 0 ]; then

        if command_exists sha256sum; then

            sha256sum "$filename" > "$hashfile"

            echo ""
            echo -e "\e[32mReport saved successfully.\e[0m"
            echo "Report : $PWD/$filename"
            echo "SHA256 : $PWD/$hashfile"

        else

            echo -e "\e[32mReport saved successfully.\e[0m"
            echo "Report : $PWD/$filename"
            echo "sha256sum is not available."

        fi

    else

        echo -e "\e[31mFailed to create report.\e[0m"

    fi
}

# ============================================================
# Main menu
# ============================================================

while true; do

    echo ""
    echo "============================================================"
    echo "             LINUX BLUE TEAM TRIAGE TOOL"
    echo "============================================================"
    echo ""
    echo "1. System information"
    echo "2. Network information"
    echo "3. Hardware health check"
    echo "4. User / authentication audit"
    echo "5. SSH security audit"
    echo "6. Persistence audit"
    echo "7. Process security audit"
    echo "8. File system triage"
    echo "9. Security controls"
    echo "10. Security / authentication logs"
    echo "11. Package information"
    echo "12. Container audit"
    echo "13. Save complete Blue Team report"
    echo "14. Exit"
    echo ""
    read -r -p "Select an option: " option

    case "$option" in

        1)
            sysinfo
            ;;

        2)
            networkinfo
            ;;

        3)
            healthcheck
            ;;

        4)
            useraudit
            ;;

        5)
            sshaudit
            ;;

        6)
            persistence
            ;;

        7)
            processaudit
            ;;

        8)
            fileaudit
            ;;

        9)
            securitycontrols
            ;;

        10)
            logaudit
            ;;

        11)
            packageaudit
            ;;

        12)
            containeraudit
            ;;

        13)
            summary
            ;;

        14)
            echo "Exiting..."
            exit 0
            ;;

        *)
            echo -e "\e[31mInvalid option.\e[0m"
            ;;

    esac

done