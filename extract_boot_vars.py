#!/usr/bin/env python3
import os
import sys

def extract_boot_variable(var_name, output_file):
    efi_var_path = f"/sys/firmware/efi/efivars/{var_name}-8be4df61-93ca-11d2-aa0d-00e098032b8c"

    if not os.path.exists(efi_var_path):
        print(f"Error: {var_name} variable not found at {efi_var_path}")
        return False

    try:
        with open(efi_var_path, 'rb') as f:
            raw_data = f.read()

        # Skip first 4 bytes (attributes)
        variable_data = raw_data[4:]

        with open(output_file, 'wb') as f:
            f.write(variable_data)

        print(f"Extracted {var_name} variable data: {len(variable_data)} bytes -> {output_file}")

        if len(variable_data) > 0:
            # Show first 16 bytes
            hex_preview = ' '.join(f'{b:02x}' for b in variable_data[:16])
            print(f"First 16 bytes: {hex_preview}")

        return True

    except Exception as e:
        print(f"Error extracting {var_name}: {e}")
        return False

def extract_acpi_data(source_path, output_file, description):
    """Extract ACPI data from QEMU fw_cfg interface"""
    if not os.path.exists(source_path):
        print(f"Error: {description} not found at {source_path}")
        return False

    try:
        with open(source_path, 'rb') as f:
            data = f.read()

        with open(output_file, 'wb') as f:
            f.write(data)

        print(f"Extracted {description}: {len(data)} bytes -> {output_file}")

        if len(data) > 0:
            # Show first 16 bytes
            hex_preview = ' '.join(f'{b:02x}' for b in data[:16])
            print(f"First 16 bytes: {hex_preview}")

        return True

    except Exception as e:
        print(f"Error extracting {description}: {e}")
        return False

def main():
    if os.geteuid() != 0:
        print("This script must be run as root to access EFI variables and ACPI data")
        sys.exit(1)

    print("Extracting Boot000X EFI variable data...")

    variables = ["BootOrder", "Boot0007", "Boot0000", "Boot0001", "Boot0006"]

    for var_name in variables:
        output_file = f"{var_name}.bin"
        extract_boot_variable(var_name, output_file)

    print("\nExtracting ACPI data...")

    # ACPI data extractions
    acpi_extractions = [
        ("/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/tables/raw", "acpi_tables.bin", "ACPI tables"),
        ("/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/rsdp/raw", "rsdp.bin", "RSDP"),
        ("/sys/firmware/qemu_fw_cfg/by_name/etc/table-loader/raw", "table_loader.bin", "Table loader")
    ]

    for source_path, output_file, description in acpi_extractions:
        extract_acpi_data(source_path, output_file, description)

    print("\nDone!")
    print("\nFiles created:")
    
    # Show EFI variable files
    for var_name in variables:
        output_file = f"{var_name}.bin"
        if os.path.exists(output_file):
            size = os.path.getsize(output_file)
            print(f"  {output_file}: {size} bytes")
    
    # Show ACPI files
    for _, output_file, _ in acpi_extractions:
        if os.path.exists(output_file):
            size = os.path.getsize(output_file)
            print(f"  {output_file}: {size} bytes")

if __name__ == "__main__":
    main()
