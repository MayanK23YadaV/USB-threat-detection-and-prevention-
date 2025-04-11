#!/bin/bash
# restrict_usb.sh

# Unified paths with environment variable overrides
CONFIG_DIR="${USB_THREAT_DIR:-/etc/usb_threat}"
LOG_DIR="${USB_THREAT_LOG_DIR:-/var/log/usb_threat}"
WHITELIST_FILE="${WHITELIST_FILE:-$CONFIG_DIR/whitelist.conf}"
LOG_FILE="$LOG_DIR/restrict_usb.log"

# Create directories if missing
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chmod 700 "$CONFIG_DIR"
chmod 700 "$LOG_DIR"  # More restrictive permissions

# Check if usb_analyzer.py is running
if pgrep -f "python.*usb_analyzer.py" > /dev/null; then
    log "INFO" "usb_analyzer.py is running, exiting to avoid overlap" "system"
    exit 0
fi

# Sanitize input parameters
DEVICE=$(echo "$1" | sed 's/[^a-zA-Z0-9_.-]//g')  # Only allow alphanumeric, dots, underscores, and hyphens
ACTION=$(echo "$2" | sed 's/[^a-zA-Z0-9_]//g')    # Only allow alphanumeric and underscores
VID=$(echo "$3" | sed 's/[^0-9a-fA-F]//g')        # Only allow hex characters
PID=$(echo "$4" | sed 's/[^0-9a-fA-F]//g')        # Only allow hex characters
SERIAL=$(echo "$5" | sed 's/[^a-zA-Z0-9_.-]//g')  # Only allow alphanumeric, dots, underscores, and hyphens

# Standardize logging with ISO 8601 timestamp
log() {
    local level="$1"
    local message="$2"
    local device="$3"
    local timestamp=$(date -Iseconds)
    echo "{\"timestamp\": \"$timestamp\", \"level\": \"$level\", \"message\": \"$message\", \"device\": \"$device\"}" >> "$LOG_FILE"
}

# Check input
if [ -z "$DEVICE" ] || [ -z "$ACTION" ]; then
    log "ERROR" "Missing required parameters" "unknown"
    exit 1
fi

# Validate VID/PID format to prevent command injection
if [ "$ACTION" = "check_whitelist" ] || [ "$ACTION" = "block" ]; then
    if [[ ! "$VID" =~ ^[0-9a-fA-F]{4}$ ]] || [[ ! "$PID" =~ ^[0-9a-fA-F]{4}$ ]]; then
        log "ERROR" "Invalid VID/PID format" "/dev/$DEVICE"
        exit 1
    fi
fi

# Ensure whitelist directory exists with proper permissions
if [ ! -d "$CONFIG_DIR" ]; then
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    log "INFO" "Created whitelist directory" "all"
fi

# Ensure whitelist file exists and has correct permissions
if [ ! -f "$WHITELIST_FILE" ]; then
    touch "$WHITELIST_FILE"
    chmod 600 "$WHITELIST_FILE"
    log "INFO" "Created whitelist file" "all"
fi

# udev rule to block unauthorized devices
UDEV_RULE="/etc/udev/rules.d/99-usb-restrict.rules"
if [ ! -f "$UDEV_RULE" ] || ! grep -q 'RUN+="/usr/local/bin/restrict_usb.sh check_whitelist' "$UDEV_RULE"; then
    # Create a temporary file with the new rule
    TMP_RULE=$(mktemp)
    echo 'ACTION=="add", SUBSYSTEM=="usb", ENV{ID_VENDOR_ID}!="", ENV{ID_MODEL_ID}!="", RUN+="/usr/local/bin/restrict_usb.sh check_whitelist $env{ID_VENDOR_ID} $env{ID_MODEL_ID} $env{ID_SERIAL_SHORT}"' > "$TMP_RULE"
    
    # Check if the rule already exists to avoid duplicates
    if ! grep -q 'RUN+="/usr/local/bin/restrict_usb.sh check_whitelist' "$UDEV_RULE" 2>/dev/null; then
        # Append the new rule to the existing file or create a new one
        cat "$TMP_RULE" >> "$UDEV_RULE"
        udevadm control --reload-rules || log "ERROR" "Failed to reload udev rules" "all"
        udevadm trigger || log "ERROR" "Failed to trigger udev rules" "all"
        log "INFO" "udev rule created and reloaded" "all"
    fi
    rm -f "$TMP_RULE"
fi

# Improve unmount reliability
if mount | grep -q "/dev/$DEVICE"; then
    # Check for processes using the device
    if lsof "/dev/$DEVICE" > /dev/null 2>&1; then
        log "WARNING" "Device is in use, attempting to kill processes" "/dev/$DEVICE"
        fuser -k "/dev/$DEVICE" > /dev/null 2>&1
    fi
    /bin/umount "/dev/$DEVICE" 2>/dev/null
    if [ $? -eq 0 ]; then
        log "INFO" "Device unmounted successfully" "/dev/$DEVICE"
    else
        log "ERROR" "Failed to unmount device" "/dev/$DEVICE"
    fi
else
    log "INFO" "Device is not mounted" "/dev/$DEVICE"
fi

# Enhance permission-based blocking
chattr +i "/dev/$DEVICE" 2>/dev/null
if [ $? -eq 0 ]; then
    log "INFO" "Device access restricted using chattr" "/dev/$DEVICE"
else
    log "WARNING" "Failed to restrict access using chattr" "/dev/$DEVICE"
fi

# Block USB ports using kernel module blacklisting - only if not already blacklisted
BLACKLIST_FILE="/etc/modprobe.d/blacklist-usb.conf"
if [ ! -f "$BLACKLIST_FILE" ] || ! grep -q "blacklist usb_storage" "$BLACKLIST_FILE"; then
    # Create a backup of the existing file if it exists
    if [ -f "$BLACKLIST_FILE" ]; then
        cp "$BLACKLIST_FILE" "${BLACKLIST_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    fi
    
    # Append our blacklist entries
    {
        echo "# USB threat prevention blacklist"
        echo "blacklist usb_storage"
        echo "blacklist usbhid"
        echo "blacklist usbnet"
    } >> "$BLACKLIST_FILE"
    
    # Check if modules are in use before unloading
    if ! lsmod | grep -q "usb_storage" || ! lsof | grep -q "usb_storage"; then
        modprobe -r usb_storage 2>/dev/null || log "WARNING" "Failed to unload usb_storage module" "all"
    else
        log "WARNING" "usb_storage module is in use, skipping unload" "all"
    fi
    
    if ! lsmod | grep -q "usbhid" || ! lsof | grep -q "usbhid"; then
        modprobe -r usbhid 2>/dev/null || log "WARNING" "Failed to unload usbhid module" "all"
    else
        log "WARNING" "usbhid module is in use, skipping unload" "all"
    fi
    
    if ! lsmod | grep -q "usbnet" || ! lsof | grep -q "usbnet"; then
        modprobe -r usbnet 2>/dev/null || log "WARNING" "Failed to unload usbnet module" "all"
    else
        log "WARNING" "usbnet module is in use, skipping unload" "all"
    fi
    
    # Update initramfs with backup
    if command -v update-initramfs >/dev/null 2>&1; then
        # Create a backup of the current initramfs
        INITRAMFS_BACKUP="/boot/initramfs-$(uname -r).bak.$(date +%Y%m%d%H%M%S)"
        cp "/boot/initramfs-$(uname -r)" "$INITRAMFS_BACKUP" 2>/dev/null
        
        # Update initramfs
        update-initramfs -u || log "ERROR" "Failed to update initramfs" "all"
        
        # Log the action
        log "INFO" "USB ports blocked via kernel module blacklisting" "all"
    else
        log "WARNING" "update-initramfs not found, skipping initramfs update" "all"
    fi
else
    log "INFO" "USB blacklist already configured" "all"
fi

# Block function
block() {
    local vid=$1 pid=$2 serial=$3
    log "INFO" "Blocking USB device VID:$vid PID:$pid SERIAL:$serial" "/dev/$DEVICE"
    
    # Block device access
    chmod 000 "/dev/$DEVICE" 2>/dev/null
    if [ $? -eq 0 ]; then
        log "INFO" "USB access restricted" "/dev/$DEVICE"
    else
        log "ERROR" "Failed to restrict access" "/dev/$DEVICE"
    fi
    
    # Log kernel messages
    dmesg | grep -i "usb.*$DEVICE" | tail -n 5 >> "$LOG_FILE"
    
    # Reload udev rules to ensure changes take effect
    /sbin/udevadm control --reload-rules || log "ERROR" "Failed to reload udev rules" "/dev/$DEVICE"
    /sbin/udevadm trigger || log "ERROR" "Failed to trigger udev rules" "/dev/$DEVICE"
}

# Execute based on action
case "$ACTION" in
    "check_whitelist")
        # Check both VID/PID and serial number if provided
        if [ -n "$SERIAL" ]; then
            if ! grep -q "VID_$VID:PID_$PID" "$WHITELIST_FILE" && ! grep -q "SERIAL_$SERIAL" "$WHITELIST_FILE"; then
                block "$VID" "$PID" "$SERIAL"
            else
                log "INFO" "Device VID:$VID PID:$PID SERIAL:$SERIAL is whitelisted" "/dev/$DEVICE"
            fi
        else
            if ! grep -q "VID_$VID:PID_$PID" "$WHITELIST_FILE"; then
                block "$VID" "$PID" "$SERIAL"
            else
                log "INFO" "Device VID:$VID PID:$PID is whitelisted" "/dev/$DEVICE"
            fi
        fi
        ;;
    "block")
        block "$VID" "$PID" "$SERIAL"
        ;;
    *)
        log "ERROR" "Unknown action: $ACTION" "/dev/$DEVICE"
        exit 1
        ;;
esac

exit 0