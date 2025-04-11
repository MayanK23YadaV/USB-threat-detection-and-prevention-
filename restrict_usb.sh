#!/bin/bash
# restrict_usb.sh

LOG_FILE="/var/log/usb_threat/restrict_usb.log"
WHITELIST_DIR="/etc/usb_threat"
# Allow overriding whitelist file location via environment variable
WHITELIST_FILE="${WHITELIST_FILE:-$WHITELIST_DIR/whitelist.conf}"
DEVICE=$1
ACTION=$2
VID=$3
PID=$4
SERIAL=$5

# Standardize logging with ISO 8601 timestamp
log() {
    echo "{\"timestamp\": \"$(date -Iseconds)\", \"level\": \"$1\", \"message\": \"$2\", \"device\": \"$3\"}" >> "$LOG_FILE"
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
if [ ! -d "$WHITELIST_DIR" ]; then
    mkdir -p "$WHITELIST_DIR"
    chmod 700 "$WHITELIST_DIR"
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
if [ ! -f "$UDEV_RULE" ]; then
    # Create udev rule with dynamic VID/PID checking
    echo 'ACTION=="add", SUBSYSTEM=="usb", ENV{ID_VENDOR_ID}!="", ENV{ID_MODEL_ID}!="", RUN+="/usr/local/bin/restrict_usb.sh check_whitelist $env{ID_VENDOR_ID} $env{ID_MODEL_ID} $env{ID_SERIAL_SHORT}"' > "$UDEV_RULE"
    udevadm control --reload-rules
    udevadm trigger
    log "INFO" "udev rule created and reloaded" "all"
fi

# Block function
block() {
    local vid=$1 pid=$2 serial=$3
    log "INFO" "Blocking USB device VID:$vid PID:$pid SERIAL:$serial" "/dev/$DEVICE"
    
    # Unmount device
    /bin/umount /dev/"$DEVICE" 2>/dev/null
    if [ $? -eq 0 ]; then
        log "INFO" "Device unmounted successfully" "/dev/$DEVICE"
    else
        log "ERROR" "Failed to unmount device" "/dev/$DEVICE"
    fi
    
    # Block device access
    chmod 000 /dev/"$DEVICE" 2>/dev/null
    if [ $? -eq 0 ]; then
        log "INFO" "USB access restricted" "/dev/$DEVICE"
    else
        log "ERROR" "Failed to restrict access" "/dev/$DEVICE"
    fi
    
    # Log kernel messages
    dmesg | tail -n 10 >> "$LOG_FILE"
    
    # Reload udev rules to ensure changes take effect
    udevadm control --reload-rules
    udevadm trigger
}

# Execute based on action
case "$ACTION" in
    "check_whitelist")
        if ! grep -q "VID_$VID:PID_$PID" "$WHITELIST_FILE"; then
            block "$VID" "$PID" "$SERIAL"
        else
            log "INFO" "Device VID:$VID PID:$PID is whitelisted" "/dev/$DEVICE"
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