#!/bin/bash

# Kindworks Sanitize - A script to securely wipe disks based on NIST 800-88 guidelines.
#
# This script identifies connected drives, determines the best hardware-based sanitization
# method, and provides a user interface to execute the wipe and generate a certificate.

# --- Configuration ---
# Password for ATA Security Erase commands. Can be any string.
ATA_PASSWORD="Kindworks"

# --- Functions ---

# Check for root privileges and required dependencies.
check_requirements() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "This script must be run as root. Please use sudo."
        exit 1
    fi

    # Add 'bc' for floating point math in size calculation
    for cmd in lsblk jq hdparm nvme bc; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "Error: Required command '$cmd' is not found."
            echo "Please install it to continue (e.g., 'sudo apt-get install $cmd')."
            exit 1
        fi
    done
}

# Scan for drives and populate arrays with their information.
# This version is more robust, reading data into a variable before processing.
scan_drives() {
    echo "Scanning for drives..."
    
    # A more robust jq filter that outputs Tab-Separated Values.
    local jq_filter='.blockdevices[] | select(.type == "disk") | "\(.name)\t\(.model)\t\(.size)\t\(.rota)\t\(.type)"'
    
    local drive_data
    drive_data=$(lsblk -d -b -o NAME,MODEL,SIZE,ROTA,TYPE -J | jq -r "$jq_filter")
    
    # Use a "here string" to feed the data to the loop. This is safer than process substitution.
    while IFS=$'\t' read -r name model size rota type; do
        drives_name+=("/dev/$name")
        drives_model+=("$model")
        # Calculate size in GB using bc for floating point math
        drives_size_gb+=($(printf "%.2f" $(echo "$size / (1024*1024*1024)" | bc -l)))
        
        # Determine drive type and find the best wipe method
        if [[ "$name" == nvme* ]]; then
            drives_type+=("NVMe")
            determine_nvme_method "/dev/$name"
        else
            if [[ "$rota" == "true" ]]; then
                drives_type+=("HDD")
            else
                drives_type+=("SSD")
            fi
            determine_sata_method "/dev/$name"
        fi
    done <<< "$drive_data"
}

# Determine the best sanitization method for an NVMe drive.
determine_nvme_method() {
    local dev_name="$1"
    local id_ctrl_output
    id_ctrl_output=$(nvme id-ctrl "$dev_name" 2>/dev/null)

    if [[ -z "$id_ctrl_output" ]]; then
        drives_method+=("Failed to query NVMe drive.")
        drives_command+=("not_supported")
        return
    fi

    # Prefer Cryptographic Erase (-s2) if supported
    if echo "$id_ctrl_output" | grep -q "Crypto Erase Supported"; then
        drives_method+=("NIST 800-88 Purge: NVMe Cryptographic Erase")
        drives_command+=("nvme format '$dev_name' -s 2")
    # Fallback to User Data Erase (-s1)
    elif echo "$id_ctrl_output" | grep -q "Format NVM Attributes"; then
        drives_method+=("NIST 800-88 Purge: NVMe User Data Erase")
        drives_command+=("nvme format '$dev_name' -s 1")
    else
        drives_method+=("No hardware format support found. Use software wipe.")
        drives_command+=("not_supported")
    fi
}

# Determine the best sanitization method for a SATA (HDD/SSD) drive.
determine_sata_method() {
    local dev_name="$1"
    local hdparm_output
    hdparm_output=$(hdparm -I "$dev_name" 2>/dev/null)

    if [[ -z "$hdparm_output" ]]; then
        drives_method+=("Failed to query SATA drive with hdparm.")
        drives_command+=("not_supported")
        return
    fi

    # Prefer SANITIZE command
    if echo "$hdparm_output" | grep -q "SANITIZE feature set"; then
        drives_method+=("NIST 800-88 Purge: ATA SANITIZE")
        drives_command+=("hdparm --user-master u --security-set-pass '$ATA_PASSWORD' '$dev_name' && hdparm --user-master u --sanitize-block-erase '$ATA_PASSWORD' '$dev_name'")
    # Fallback to Enhanced Security Erase
    elif echo "$hdparm_output" | grep -q "supported: enhanced erase"; then
        drives_method+=("NIST 800-88 Purge: ATA Enhanced Security Erase")
        drives_command+=("hdparm --user-master u --security-set-pass '$ATA_PASSWORD' '$dev_name' && hdparm --user-master u --security-erase-enhanced '$ATA_PASSWORD' '$dev_name'")
    # Fallback to Security Erase
    elif echo "$hdparm_output" | grep -q "Security erase unit"; then
        drives_method+=("NIST 800-88 Purge: ATA Security Erase")
        drives_command+=("hdparm --user-master u --security-set-pass '$ATA_PASSWORD' '$dev_name' && hdparm --user-master u --security-erase '$ATA_PASSWORD' '$dev_name'")
    else
        drives_method+=("No hardware wipe support found. Use software wipe (nwipe).")
        drives_command+=("not_supported")
    fi
}

# Display the main menu of available drives.
display_menu() {
    echo -e "\n--- Available Drives for Sanitization ---"
    if [ ${#drives_name[@]} -eq 0 ]; then
        echo "No suitable drives found."
        exit 0
    fi

    for i in "${!drives_name[@]}"; do
        echo "  $((i+1)): ${drives_name[$i]} (${drives_model[$i]}, ${drives_size_gb[$i]} GB, ${drives_type[$i]})"
        echo "     => Method: ${drives_method[$i]}"
    done
    echo "-------------------------------------------"
}

# Generate and display the certificate of sanitization.
create_certificate() {
    local drive_index=$1
    local success=$2
    local result_text="FAILURE"
    [[ "$success" == "true" ]] && result_text="SUCCESS"

    # Create a filename for the certificate
    local cert_filename="Sanitization-Cert-$(basename ${drives_name[$drive_index]})-$(date +%Y%m%d-%H%M%S).txt"

    # Use a heredoc to create the certificate content
    cat > "$cert_filename" <<- EOF
-------------------------------------------------
      Certificate of Sanitization
-------------------------------------------------
This document certifies that the media described below has been sanitized
in accordance with the specified NIST 800-88 guidelines.

**Media Information**
  - Manufacturer/Model: ${drives_model[$drive_index]}
  - Serial Number:      (Please retrieve from drive label)
  - Media Type:         ${drives_type[$drive_index]}
  - Size:               ${drives_size_gb[$drive_index]} GB

**Sanitization Details**
  - Sanitization Date:  $(date +%Y-%m-%d)
  - Sanitization Time:  $(date +%H:%M:%S)
  - Sanitization Method:${drives_method[$drive_index]}
  - Command Executed:   ${drives_command[$drive_index]}

**Outcome**
  - Result:             $result_text

**Personnel**
  - Performed By:       ____________________ (Your Name)
  - Signature:          ____________________

-------------------------------------------------
EOF

    echo -e "\nSanitization process finished."
    echo "A certificate of sanitization has been saved to:"
    echo "  => $cert_filename"
    echo "Please fill in any missing details and keep it for your records."
}

# --- Main Logic ---

check_requirements

# Declare arrays to hold drive info
declare -a drives_name drives_model drives_size_gb drives_type drives_method drives_command

scan_drives
display_menu

# Prompt user for selection
read -p "Enter the number of the drive to wipe (or 'q' to quit): " choice
if [[ "$choice" == "q" || "$choice" == "Q" ]]; then
    echo "Quitting."
    exit 0
fi

# Validate choice
if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#drives_name[@]} ]; then
    echo "Invalid selection."
    exit 1
fi

drive_index=$((choice-1))
selected_drive_name="${drives_name[$drive_index]}"
wipe_command="${drives_command[$drive_index]}"

if [[ "$wipe_command" == "not_supported" ]]; then
    echo "This drive cannot be wiped with a hardware command by this script."
    echo "Please use a software-based tool like ShredOS/nwipe."
    exit 1
fi

# Final confirmation
echo -e "\n!!! --- WARNING: IRREVERSIBLE ACTION --- !!!"
echo "You are about to permanently erase all data on the drive: $selected_drive_name."
echo "This action cannot be undone."

# Use printf for a more robust prompt, then read the input.
printf "To confirm, please type the full drive name ('%s'): " "$selected_drive_name"
read -r confirmation

if [[ "$confirmation" != "$selected_drive_name" ]]; then
    echo "Confirmation failed. Aborting."
    exit 1
fi

# Execute the wipe using bash -c for safety instead of eval.
echo -e "\nStarting sanitization on $selected_drive_name..."
bash -c "$wipe_command"
exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo -e "\nSanitization command completed successfully."
    create_certificate "$drive_index" "true"
else
    echo -e "\nError: Sanitization command failed with exit code $exit_code."
    create_certificate "$drive_index" "false"
fi

exit 0
