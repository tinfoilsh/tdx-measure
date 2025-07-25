use std::io::Write;
use std::process::Command;
use anyhow::{Context, Result, anyhow};
use fs_err as fs;
use std::path::Path;
use crate::{PathResolver, PathStorage};

/// Generate a human-readable transcript of metadata files
pub fn generate_transcript(output_file: &Path, path_resolver: &PathResolver, direct_boot: bool, platform_only: bool, runtime_only: bool) -> Result<()> {
    
    let mut output = Vec::new();
    
    writeln!(output, "=== TDX Metadata Transcript ===").unwrap();
    writeln!(output, "Generated by tdx-measure").unwrap();
    writeln!(output).unwrap();

    if !runtime_only {
        // Parse and display ACPI tables using iasl
        write_acpi_tables_with_iasl(&mut output, &path_resolver.paths.acpi_tables)?;

        // Display boot order and boot variables
        write_boot_variables(&mut output, &path_resolver.paths)?;
    }
    
    if !platform_only {
        // Display command line
        writeln!(output, "=== Kernel Command Line ===").unwrap();
        writeln!(output, "{}", path_resolver.paths.cmdline).unwrap();
        writeln!(output).unwrap();
        
        // Display MOK variables and SBAT level for indirect boot
        if !direct_boot {
            write_mok_variables(&mut output, &path_resolver.paths)?;
            write_sbat_level(&mut output, &path_resolver.paths)?;
        }
    }
    
    // Write to file
    fs::write(output_file, output)
        .with_context(|| format!("Failed to write transcript to {}", output_file.display()))?;
    
    println!("Transcript written to: {}", output_file.display());
    
    Ok(())
}

/// ACPI Table info extracted from header
struct AcpiTableInfo {
    signature: String,
    length: u32,
    data: Vec<u8>,
}

/// Check if a signature looks like a valid ACPI signature (printable ASCII)
fn is_valid_acpi_signature(sig: &[u8; 4]) -> bool {
    // Check if all characters are printable ASCII (32-126)
    sig.iter().all(|&b| (32..=126).contains(&b))
}

/// Split concatenated ACPI tables from QEMU fw_cfg dump
fn split_acpi_tables(data: &[u8]) -> Result<Vec<AcpiTableInfo>> {
    let mut tables = Vec::new();
    let mut offset = 0;
    
    eprintln!("Processing {} bytes of ACPI data", data.len());
    
    while offset < data.len() {
        // Ensure there's enough space for a table header (signature + length = 8 bytes)
        if offset + 8 > data.len() {
            break;
        }
        
        // Read signature (4 bytes)
        let signature_bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
        
        // Read length (4 bytes, little-endian)
        let length = u32::from_le_bytes([
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
        ]);
        
        // Validate length
        if length == 0 {
            offset += 1;
            continue;
        }
        
        if offset + length as usize > data.len() {
            eprintln!("Warning: Table length {} exceeds remaining data at offset {}, skipping", length, offset);
            offset += 1;
            continue;
        }
        
        // Try to decode signature as ASCII and validate
        let signature = match std::str::from_utf8(&signature_bytes) {
            Ok(s) if is_valid_acpi_signature(&signature_bytes) => s.to_string(),
            _ => {
                eprintln!("Warning: Invalid signature at offset {}: {:02x?}, searching for next table", offset, signature_bytes);
                offset += 1;
                continue;
            }
        };
        
        // Extract the table data
        let table_data = data[offset..offset + length as usize].to_vec();
        
        tables.push(AcpiTableInfo {
            signature: signature.clone(),
            length,
            data: table_data,
        });
        
        eprintln!("Found ACPI table: {} ({} bytes) at offset {}", signature, length, offset);
        
        // Move to the next table (no alignment padding, just exact length)
        offset += length as usize;
    }
    
    if tables.is_empty() {
        return Err(anyhow!("No valid ACPI tables found in data"));
    }
    
    eprintln!("Successfully extracted {} tables", tables.len());
    Ok(tables)
}

/// Use iasl to disassemble ACPI tables into human-readable format
fn write_acpi_tables_with_iasl(output: &mut Vec<u8>, acpi_tables_path: &str) -> Result<()> {
    writeln!(output, "=== ACPI Tables ===").unwrap();
    writeln!(output, "Source: QEMU fw_cfg concatenated ACPI tables dump").unwrap();
    writeln!(output, "Disassembled using Intel ACPI Source Language Compiler (iasl)").unwrap();
    writeln!(output).unwrap();
    
    // Check if iasl is available
    let iasl_check = Command::new("iasl")
        .arg("-h")
        .output();
    
    if iasl_check.is_err() {
        writeln!(output, "WARNING: iasl tool not found. Install acpica-tools package for detailed ACPI analysis.").unwrap();
        writeln!(output, "Falling back to hex dump:").unwrap();
        writeln!(output).unwrap();
        write_hex_dump(output, acpi_tables_path, "ACPI Tables")?;
        return Ok(());
    }
    
    // Read and split the concatenated ACPI tables
    let acpi_data = fs::read(acpi_tables_path)
        .with_context(|| format!("Failed to read ACPI tables from {}", acpi_tables_path))?;
    
    let tables = match split_acpi_tables(&acpi_data) {
        Ok(tables) => tables,
        Err(e) => {
            writeln!(output, "WARNING: Failed to split ACPI tables: {}", e).unwrap();
            writeln!(output, "Falling back to hex dump:").unwrap();
            writeln!(output).unwrap();
            write_hex_dump(output, acpi_tables_path, "ACPI Tables")?;
            return Ok(());
        }
    };
    
    writeln!(output, "Found {} ACPI tables:", tables.len()).unwrap();
    
    // Group tables by signature for summary
    let mut signature_counts = std::collections::HashMap::new();
    for table in &tables {
        *signature_counts.entry(&table.signature).or_insert(0) += 1;
    }
    
    for (signature, count) in &signature_counts {
        writeln!(output, "  {}: {} table{}", signature, count, if *count > 1 { "s" } else { "" }).unwrap();
    }
    writeln!(output).unwrap();
    
    // Create temporary directory for iasl output
    let temp_dir = std::env::temp_dir().join(format!("tdx-measure-{}", std::process::id()));
    fs::create_dir_all(&temp_dir)
        .with_context(|| format!("Failed to create temp directory: {}", temp_dir.display()))?;
    
    // Process each table with iasl
    for (i, table) in tables.iter().enumerate() {
        writeln!(output, "=== Table {}: {} ({} bytes) ===", i + 1, table.signature, table.length).unwrap();
        
        // Generate unique filename for duplicate signatures
        let table_filename = if signature_counts[&table.signature] > 1 {
            format!("{}_{}.dat", table.signature, i + 1)
        } else {
            format!("{}.dat", table.signature)
        };
        
        let temp_table_file = temp_dir.join(&table_filename);
        fs::write(&temp_table_file, &table.data)
            .with_context(|| format!("Failed to write table {} to temp file", table.signature))?;
        
        // Run iasl on this specific table
        let iasl_output = Command::new("iasl")
            .arg("-d")  // Disassemble
            .arg(&temp_table_file)
            .current_dir(&temp_dir)
            .output()
            .with_context(|| format!("Failed to run iasl on table {}", table.signature))?;
        
        // Include iasl output
        if !iasl_output.stdout.is_empty() {
            writeln!(output, "iasl output for {}:", table.signature).unwrap();
            output.extend_from_slice(&iasl_output.stdout);
            writeln!(output).unwrap();
        }
        
        if !iasl_output.stderr.is_empty() {
            writeln!(output, "iasl warnings/errors for {}:", table.signature).unwrap();
            output.extend_from_slice(&iasl_output.stderr);
            writeln!(output).unwrap();
        }
        
        // Look for generated .dsl file for this table
        let dsl_filename = table_filename.replace(".dat", ".dsl");
        let dsl_file = temp_dir.join(&dsl_filename);
        
        if dsl_file.exists() {
            match fs::read_to_string(&dsl_file) {
                Ok(content) => {
                    writeln!(output, "Disassembled {} table:", table.signature).unwrap();
                    writeln!(output, "---").unwrap();
                    output.extend_from_slice(content.as_bytes());
                    writeln!(output, "---").unwrap();
                }
                Err(e) => {
                    writeln!(output, "Error reading disassembled {} table: {}", table.signature, e).unwrap();
                }
            }
        } else {
            writeln!(output, "No .dsl file generated for {} table. Raw hex dump:", table.signature).unwrap();
            write_raw_table_hex_dump(output, &table.data, &table.signature)?;
        }
        
        writeln!(output).unwrap();
    }
    
    // Clean up temporary directory
    if let Err(e) = fs::remove_dir_all(&temp_dir) {
        eprintln!("Warning: Failed to clean up temp directory {}: {}", temp_dir.display(), e);
    }
    
    Ok(())
}

/// Write raw table data as hex dump
fn write_raw_table_hex_dump(output: &mut Vec<u8>, data: &[u8], table_name: &str) -> Result<()> {
    writeln!(output, "{} table raw data ({} bytes):", table_name, data.len()).unwrap();
    
    let display_bytes = std::cmp::min(data.len(), 256);
    
    for (i, chunk) in data[..display_bytes].chunks(16).enumerate() {
        write!(output, "  {:04x}: ", i * 16).unwrap();
        
        // Hex bytes
        for (j, &byte) in chunk.iter().enumerate() {
            if j == 8 {
                write!(output, " ").unwrap();
            }
            write!(output, "{:02x} ", byte).unwrap();
        }
        
        // Pad remaining space
        for j in chunk.len()..16 {
            if j == 8 {
                write!(output, " ").unwrap();
            }
            write!(output, "   ").unwrap();
        }
        
        write!(output, " |").unwrap();
        
        // ASCII representation
        for &byte in chunk {
            if byte.is_ascii_graphic() || byte == b' ' {
                write!(output, "{}", byte as char).unwrap();
            } else {
                write!(output, ".").unwrap();
            }
        }
        
        writeln!(output, "|").unwrap();
    }
    
    if data.len() > display_bytes {
        writeln!(output, "  ... ({} more bytes)", data.len() - display_bytes).unwrap();
    }
    
    Ok(())
}

// Print UEFI boot variables
// Specification can be found at https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html


/// EFI_LOAD_OPTION structure representing a UEFI boot option
#[derive(Debug)]
struct EfiLoadOption {
    attributes: u32,
    file_path_list_length: u16,
    description: String,
    file_path_list: Vec<u8>,
    optional_data: Vec<u8>,
}

/// UEFI Load Option Attributes constants
const LOAD_OPTION_ACTIVE: u32 = 0x00000001;
const LOAD_OPTION_FORCE_RECONNECT: u32 = 0x00000002;
const LOAD_OPTION_HIDDEN: u32 = 0x00000008;
const LOAD_OPTION_CATEGORY: u32 = 0x00001F00;

/// UEFI Device Path structure
#[derive(Debug, Clone)]
struct DevicePath {
    path_type: u8,
    sub_type: u8,
    data: Vec<u8>,
}

/// Device Path Types
const DEVICE_PATH_TYPE_HARDWARE: u8 = 0x01;
const DEVICE_PATH_TYPE_ACPI: u8 = 0x02;
const DEVICE_PATH_TYPE_MESSAGING: u8 = 0x03;
const DEVICE_PATH_TYPE_MEDIA: u8 = 0x04;
const DEVICE_PATH_TYPE_BIOS_BOOT: u8 = 0x05;
const DEVICE_PATH_TYPE_END: u8 = 0x7F;

/// Device Path SubTypes
const DEVICE_PATH_SUBTYPE_PCI: u8 = 0x01;
const DEVICE_PATH_SUBTYPE_ACPI: u8 = 0x01;
const DEVICE_PATH_SUBTYPE_HARD_DRIVE: u8 = 0x01;
const DEVICE_PATH_SUBTYPE_FILE_PATH: u8 = 0x04;

/// Parse device path list into individual device paths
fn parse_device_paths(data: &[u8]) -> Result<Vec<DevicePath>> {
    let mut paths = Vec::new();
    let mut offset = 0;
    
    while offset < data.len() {
        if offset + 4 > data.len() {
            break; // Not enough data for header
        }
        
        let path_type = data[offset];
        let sub_type = data[offset + 1];
        let length = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        
        if length < 4 {
            break; // Invalid length
        }
        
        if offset + length as usize > data.len() {
            break; // Not enough data for this path
        }
        
        let path_data = if length > 4 {
            data[offset + 4..offset + length as usize].to_vec()
        } else {
            Vec::new()
        };
        
        paths.push(DevicePath {
            path_type,
            sub_type,
            data: path_data,
        });
        
        // Check for end of device path
        if path_type == DEVICE_PATH_TYPE_END {
            break;
        }
        
        offset += length as usize;
    }
    
    Ok(paths)
}

/// Format device path as human-readable string
fn format_device_path(path: &DevicePath) -> String {
    match path.path_type {
        DEVICE_PATH_TYPE_HARDWARE => format_hardware_device_path(path),
        DEVICE_PATH_TYPE_ACPI => format_acpi_device_path(path),
        DEVICE_PATH_TYPE_MESSAGING => format_messaging_device_path(path),
        DEVICE_PATH_TYPE_MEDIA => format_media_device_path(path),
        DEVICE_PATH_TYPE_BIOS_BOOT => format_bios_boot_device_path(path),
        DEVICE_PATH_TYPE_END => "End".to_string(),
        _ => format!("Unknown(Type={}, SubType={}, {} bytes)", 
                    path.path_type, path.sub_type, path.data.len()),
    }
}

/// Format hardware device path
fn format_hardware_device_path(path: &DevicePath) -> String {
    match path.sub_type {
        DEVICE_PATH_SUBTYPE_PCI => {
            if path.data.len() >= 2 {
                let function = path.data[0];
                let device = path.data[1];
                format!("PCI(0x{:02X},0x{:02X})", device, function)
            } else {
                "PCI(Invalid)".to_string()
            }
        }
        _ => format!("Hardware(SubType={}, {} bytes)", path.sub_type, path.data.len()),
    }
}

/// Format ACPI device path
fn format_acpi_device_path(path: &DevicePath) -> String {
    match path.sub_type {
        DEVICE_PATH_SUBTYPE_ACPI => {
            if path.data.len() >= 8 {
                let hid = u32::from_le_bytes([path.data[0], path.data[1], path.data[2], path.data[3]]);
                let uid = u32::from_le_bytes([path.data[4], path.data[5], path.data[6], path.data[7]]);
                format!("ACPI(HID=0x{:08X},UID=0x{:08X})", hid, uid)
            } else {
                "ACPI(Invalid)".to_string()
            }
        }
        _ => format!("ACPI(SubType={}, {} bytes)", path.sub_type, path.data.len()),
    }
}

/// Format messaging device path
fn format_messaging_device_path(path: &DevicePath) -> String {
    format!("Messaging(SubType={}, {} bytes)", path.sub_type, path.data.len())
}

/// Format media device path
fn format_media_device_path(path: &DevicePath) -> String {
    match path.sub_type {
        DEVICE_PATH_SUBTYPE_HARD_DRIVE => {
            if path.data.len() >= 42 {
                let partition_number = u32::from_le_bytes([path.data[0], path.data[1], path.data[2], path.data[3]]);
                let partition_start = u64::from_le_bytes([
                    path.data[4], path.data[5], path.data[6], path.data[7],
                    path.data[8], path.data[9], path.data[10], path.data[11]
                ]);
                let partition_size = u64::from_le_bytes([
                    path.data[12], path.data[13], path.data[14], path.data[15],
                    path.data[16], path.data[17], path.data[18], path.data[19]
                ]);
                let signature_type = path.data[41];
                let signature_type_str = match signature_type {
                    0x00 => "None",
                    0x01 => "MBR",
                    0x02 => "GPT",
                    _ => "Unknown",
                };
                format!("HD(Part={},Sig={},Start=0x{:X},Size=0x{:X})", 
                       partition_number, signature_type_str, partition_start, partition_size)
            } else {
                "HD(Invalid)".to_string()
            }
        }
        DEVICE_PATH_SUBTYPE_FILE_PATH => {
            if !path.data.is_empty() {
                // File path is UTF-16 encoded
                let utf16_chars: Vec<u16> = path.data.chunks(2)
                    .filter_map(|chunk| {
                        if chunk.len() == 2 {
                            Some(u16::from_le_bytes([chunk[0], chunk[1]]))
                        } else {
                            None
                        }
                    })
                    .take_while(|&c| c != 0) // Stop at null terminator
                    .collect();
                
                match String::from_utf16(&utf16_chars) {
                    Ok(file_path) => format!("File({})", file_path),
                    Err(_) => format!("File([Invalid UTF-16, {} bytes])", path.data.len()),
                }
            } else {
                "File(Empty)".to_string()
            }
        }
        _ => format!("Media(SubType={}, {} bytes)", path.sub_type, path.data.len()),
    }
}

/// Format BIOS boot device path
fn format_bios_boot_device_path(path: &DevicePath) -> String {
    format!("BIOS(SubType={}, {} bytes)", path.sub_type, path.data.len())
}

/// Format device path list as human-readable string
fn format_device_path_list(data: &[u8]) -> String {
    match parse_device_paths(data) {
        Ok(paths) => {
            if paths.is_empty() {
                "[Empty]".to_string()
            } else {
                paths.iter()
                    .map(format_device_path)
                    .collect::<Vec<_>>()
                    .join("/")
            }
        }
        Err(_) => "[Parse Error]".to_string(),
    }
}

/// Parse BootOrder variable (array of UINT16 values in little-endian)
fn parse_boot_order(data: &[u8]) -> Result<Vec<u16>> {
    if data.len() % 2 != 0 {
        return Err(anyhow!("BootOrder data length must be even (got {} bytes)", data.len()));
    }
    
    let mut boot_order = Vec::new();
    for chunk in data.chunks(2) {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        boot_order.push(value);
    }
    
    Ok(boot_order)
}

/// Parse Boot#### variable (EFI_LOAD_OPTION structure)
fn parse_boot_option(data: &[u8]) -> Result<EfiLoadOption> {
    if data.len() < 6 {
        return Err(anyhow!("Boot option data too short (need at least 6 bytes, got {})", data.len()));
    }
    
    // Parse fixed header (6 bytes)
    let attributes = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let file_path_list_length = u16::from_le_bytes([data[4], data[5]]);
    
    let mut offset = 6;
    
    // Parse description (UTF-16 null-terminated string)
    let mut description_bytes = Vec::new();
    while offset + 1 < data.len() {
        let char_bytes = [data[offset], data[offset + 1]];
        let char_value = u16::from_le_bytes(char_bytes);
        
        if char_value == 0 {
            offset += 2; // Skip null terminator
            break;
        }
        
        description_bytes.push(char_value);
        offset += 2;
    }
    
    // Convert UTF-16 to UTF-8
    let description = String::from_utf16(&description_bytes)
        .unwrap_or_else(|_| format!("[Invalid UTF-16: {} chars]", description_bytes.len()));
    
    // Parse file path list
    let file_path_end = offset + file_path_list_length as usize;
    let file_path_list = if file_path_end <= data.len() {
        data[offset..file_path_end].to_vec()
    } else {
        return Err(anyhow!("File path list extends beyond data (need {} bytes, have {})", 
                          file_path_end, data.len()));
    };
    
    offset = file_path_end;
    
    // Parse optional data (remaining bytes)
    let optional_data = if offset < data.len() {
        data[offset..].to_vec()
    } else {
        Vec::new()
    };
    
    Ok(EfiLoadOption {
        attributes,
        file_path_list_length,
        description,
        file_path_list,
        optional_data,
    })
}

/// Format load option attributes as human-readable string
fn format_load_option_attributes(attributes: u32) -> String {
    let mut parts = Vec::new();
    
    if attributes & LOAD_OPTION_ACTIVE != 0 {
        parts.push("ACTIVE".to_string());
    }
    if attributes & LOAD_OPTION_FORCE_RECONNECT != 0 {
        parts.push("FORCE_RECONNECT".to_string());
    }
    if attributes & LOAD_OPTION_HIDDEN != 0 {
        parts.push("HIDDEN".to_string());
    }
    
    let category = (attributes & LOAD_OPTION_CATEGORY) >> 8;
    if category != 0 {
        parts.push(format!("CATEGORY_{}", category));
    }
    
    let result = if parts.is_empty() {
        "NONE".to_string()
    } else {
        parts.join(" | ")
    };
    
    format!("{} (0x{:08x})", result, attributes)
}

/// Write boot variables with pretty printing and hex dumps
fn write_boot_variables(output: &mut Vec<u8>, paths: &PathStorage) -> Result<()> {
    writeln!(output, "=== Boot Variables ===").unwrap();
    writeln!(output, "These are UEFI boot variables that control the boot process.").unwrap();
    writeln!(output, "Reference: UEFI Specification 2.10+ Chapter 3: Boot Manager").unwrap();
    writeln!(output).unwrap();
    
    // Parse and display BootOrder
    let boot_entries = write_boot_order_analysis(output, &paths.boot_order)?;
    
    // Parse and display Boot#### variables
    for boot_entry in boot_entries {
        let name = format!("Boot{:04X}", boot_entry);
        let path = format!("{}/{}.bin", paths.path_boot_xxxx, name);
        write_boot_option_analysis(output, &name, &path)?;
    }
    
    writeln!(output).unwrap();
    Ok(())
}

/// Write BootOrder analysis with pretty printing
fn write_boot_order_analysis(output: &mut Vec<u8>, boot_order_path: &str) -> Result<Vec<u16>> {
    writeln!(output, "--- BootOrder Analysis ---").unwrap();
    
    let data = fs::read(boot_order_path)
        .with_context(|| format!("Failed to read BootOrder from {}", boot_order_path))?;
    
    // Parse BootOrder first
    let boot_order = match parse_boot_order(&data) {
        Ok(boot_order) => {
            writeln!(output, "BootOrder contains {} entries:", boot_order.len()).unwrap();
            for (i, boot_num) in boot_order.iter().enumerate() {
                writeln!(output, "  {}: Boot{:04X}", i + 1, boot_num).unwrap();
            }
            writeln!(output, "Boot preference order: {}", 
                    boot_order.iter().map(|n| format!("Boot{:04X}", n)).collect::<Vec<_>>().join(" -> ")).unwrap();
            boot_order
        }
        Err(e) => {
            writeln!(output, "Failed to parse BootOrder: {}", e).unwrap();
            Vec::new() // Return empty vector if parsing fails
        }
    };
    
    writeln!(output).unwrap();
    
    // Also include hex dump
    write_hex_dump(output, boot_order_path, "BootOrder (hex dump)")?;
    
    Ok(boot_order)
}

/// Write Boot#### variable analysis with pretty printing
fn write_boot_option_analysis(output: &mut Vec<u8>, name: &str, boot_path: &str) -> Result<()> {
    writeln!(output, "--- {} Analysis ---", name).unwrap();
    
    let data = fs::read(boot_path)
        .with_context(|| format!("Failed to read {} from {}", name, boot_path))?;
    
    if data.is_empty() {
        writeln!(output, "{} is empty", name).unwrap();
        writeln!(output).unwrap();
        return Ok(());
    }
    
    // Pretty print Boot#### variable
    match parse_boot_option(&data) {
        Ok(boot_option) => {
            writeln!(output, "EFI_LOAD_OPTION structure:").unwrap();
            writeln!(output, "  Attributes: {}", format_load_option_attributes(boot_option.attributes)).unwrap();
            writeln!(output, "  FilePathListLength: {} bytes", boot_option.file_path_list_length).unwrap();
            writeln!(output, "  Description: \"{}\"", boot_option.description).unwrap();
            writeln!(output, "  FilePathList: {} bytes", boot_option.file_path_list.len()).unwrap();
            
            if !boot_option.file_path_list.is_empty() {
                let device_path_str = format_device_path_list(&boot_option.file_path_list);
                writeln!(output, "    Device Path: {}", device_path_str).unwrap();
            }
            
            if !boot_option.optional_data.is_empty() {
                writeln!(output, "  OptionalData: {} bytes", boot_option.optional_data.len()).unwrap();
                writeln!(output, "    OptionalData hex: {}", 
                        boot_option.optional_data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")).unwrap();
            }
            
            // Boot status summary
            let active = boot_option.attributes & LOAD_OPTION_ACTIVE != 0;
            let hidden = boot_option.attributes & LOAD_OPTION_HIDDEN != 0;
            writeln!(output, "  Status: {} {}",
                    if active { "ACTIVE" } else { "INACTIVE" },
                    if hidden { "(HIDDEN)" } else { "(VISIBLE)" }).unwrap();
        }
        Err(e) => {
            writeln!(output, "Failed to parse {} as EFI_LOAD_OPTION: {}", name, e).unwrap();
        }
    }
    
    writeln!(output).unwrap();
    
    // Also include hex dump
    write_hex_dump(output, boot_path, &format!("{} (hex dump)", name))?;
    
    Ok(())
}

/// Write MOK variables for indirect boot
fn write_mok_variables(output: &mut Vec<u8>, paths: &PathStorage) -> Result<()> {
    writeln!(output, "=== MOK Variables ===").unwrap();
    writeln!(output, "Machine Owner Key (MOK) variables for Secure Boot.").unwrap();
    writeln!(output).unwrap();
    
    if let Some(ref mok_list) = paths.mok_list {
        write_hex_dump(output, mok_list, "MOK List")?;
    }
    
    if let Some(ref mok_list_trusted) = paths.mok_list_trusted {
        write_hex_dump(output, mok_list_trusted, "MOK List Trusted")?;
    }
    
    if let Some(ref mok_list_x) = paths.mok_list_x {
        write_hex_dump(output, mok_list_x, "MOK List X")?;
    }
    
    writeln!(output).unwrap();
    Ok(())
}

/// Write SBAT level for indirect boot
fn write_sbat_level(output: &mut Vec<u8>, paths: &PathStorage) -> Result<()> {
    writeln!(output, "=== SBAT Level ===").unwrap();
    writeln!(output, "Secure Boot Advanced Targeting (SBAT) level information.").unwrap();
    writeln!(output).unwrap();
    
    if let Some(ref sbat_level) = paths.sbat_level {
        match fs::read_to_string(sbat_level) {
            Ok(content) => {
                writeln!(output, "SBAT Level (text content):").unwrap();
                writeln!(output, "{}", content).unwrap();
            }
            Err(_) => {
                writeln!(output, "SBAT Level (binary data):").unwrap();
                write_hex_dump(output, sbat_level, "SBAT Level")?;
            }
        }
    }
    
    writeln!(output).unwrap();
    Ok(())
}

/// Write a file as hex dump with ASCII representation
fn write_hex_dump(output: &mut Vec<u8>, file_path: &str, name: &str) -> Result<()> {
    let data = fs::read(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    
    writeln!(output, "{} ({} bytes):", name, data.len()).unwrap();
    
    if data.is_empty() {
        writeln!(output, "  [Empty file]").unwrap();
        return Ok(());
    }
    
    // Show first few bytes as hex dump
    let display_bytes = std::cmp::min(data.len(), 256);
    
    for (i, chunk) in data[..display_bytes].chunks(16).enumerate() {
        write!(output, "  {:04x}: ", i * 16).unwrap();
        
        // Hex bytes
        for (j, &byte) in chunk.iter().enumerate() {
            if j == 8 {
                write!(output, " ").unwrap();
            }
            write!(output, "{:02x} ", byte).unwrap();
        }
        
        // Pad remaining space
        for j in chunk.len()..16 {
            if j == 8 {
                write!(output, " ").unwrap();
            }
            write!(output, "   ").unwrap();
        }
        
        write!(output, " |").unwrap();
        
        // ASCII representation
        for &byte in chunk {
            if byte.is_ascii_graphic() || byte == b' ' {
                write!(output, "{}", byte as char).unwrap();
            } else {
                write!(output, ".").unwrap();
            }
        }
        
        writeln!(output, "|").unwrap();
    }
    
    if data.len() > display_bytes {
        writeln!(output, "  ... ({} more bytes)", data.len() - display_bytes).unwrap();
    }
    
    writeln!(output).unwrap();
    Ok(())
}
