use crate::{measure_log, measure_sha384, num::read_le, util::{debug_print_log, authenticode_sha384_hash, measure_cmdline}};
use anyhow::{bail, Context, Result};
use object::pe;
use std::fs;
use std::path::Path;
use std::process::Command;
use log::debug; 

/// Represents extracted bootloader components from a disk image
#[derive(Debug)]
pub struct BootloaderComponents {
    pub gpt_data: Vec<u8>,
    pub shim_data: Vec<u8>,
    pub grub_data: Vec<u8>,
}

/// Extracts bootloader components from a qcow2 disk image
pub fn extract_bootloader_components(qcow2_path: &str) -> Result<BootloaderComponents> {
    let temp_dir = std::env::temp_dir().join("tdx_bootloader_extract");
    std::fs::create_dir_all(&temp_dir)?;
    
    // Use the direct guestfish approach
    extract_with_guestfish_direct(qcow2_path, &temp_dir)?;
    
    let gpt_path = temp_dir.join("gpt_data.bin");
    let shim_path = temp_dir.join("shim_data.efi");
    let grub_path = temp_dir.join("grub_data.efi");
    
    // Read the extracted files
    let gpt_data = std::fs::read(&gpt_path)
        .context("Failed to read extracted GPT data")?;
    let shim_data = std::fs::read(&shim_path)
        .context("Failed to read extracted shim data")?;
    let grub_data = std::fs::read(&grub_path)
        .context("Failed to read extracted grub data")?;
    
    // Cleanup temp files
    let _ = std::fs::remove_dir_all(&temp_dir);
    
    Ok(BootloaderComponents {
        gpt_data,
        shim_data,
        grub_data,
    })
}

/// Extracts GPT event data in the format used by EV_EFI_GPT_EVENT
fn extract_gpt_event_data(qcow2_path: &str) -> Result<Vec<u8>> {
    // Extract GPT header from LBA 1 (skip MBR at LBA 0)
    let output = Command::new("guestfish")
        .args(&[
            "--ro", "-a", qcow2_path,
            "run", ":",
            "pread-device", "/dev/sda", "512", "512"  // Read LBA 1 (GPT header)
        ])
        .output()
        .context("Failed to extract GPT header")?;
    
    if !output.status.success() {
        bail!("Failed to extract GPT header: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    let gpt_header = output.stdout;
    
    // Parse GPT header
    if gpt_header.len() < 92 {
        bail!("GPT header too short");
    }
    
    // Check GPT signature
    if &gpt_header[0..8] != b"EFI PART" {
        bail!("Invalid GPT signature");
    }
    
    // Read partition entry info from GPT header
    let partition_entry_lba = u64::from_le_bytes(gpt_header[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(gpt_header[80..84].try_into().unwrap()) as usize;
    let entry_size = u32::from_le_bytes(gpt_header[84..88].try_into().unwrap()) as usize;
    
    // Calculate how many sectors we need to read for all partition entries
    let entries_size = num_entries * entry_size;
    let sectors_needed = (entries_size + 511) / 512; // Round up to sector boundary
    
    // Extract partition entries
    let entries_offset = partition_entry_lba * 512;
    let entries_length = sectors_needed * 512;
    
    let output = Command::new("guestfish")
        .args(&[
            "--ro", "-a", qcow2_path,
            "run", ":",
            "pread-device", "/dev/sda", &entries_length.to_string(), &entries_offset.to_string()
        ])
        .output()
        .context("Failed to extract GPT entries")?;
    
    if !output.status.success() {
        bail!("Failed to extract GPT entries: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    let all_entries = output.stdout;
    
    // Filter valid partition entries (non-zero PartitionTypeGUID)
    let mut valid_entries = Vec::new();
    for i in 0..num_entries {
        let entry_offset = i * entry_size;
        if entry_offset + entry_size > all_entries.len() {
            break;
        }
        
        let entry = &all_entries[entry_offset..entry_offset + entry_size];
        
        // Check if PartitionTypeGUID is non-zero (first 16 bytes)
        let is_valid = !entry[0..16].iter().all(|&b| b == 0);
        
        if is_valid {
            valid_entries.push(entry.to_vec());
        }
    }
    
    // Build the EFI_GPT_DATA structure:
    // 1. GPT Header (92 bytes)
    // 2. NumberOfPartitions (8 bytes as UINT64)
    // 3. Valid partition entries (128 bytes each)
    let mut gpt_event_data = Vec::new();
    
    // Add GPT header (92 bytes)
    gpt_event_data.extend_from_slice(&gpt_header[0..92]);
    
    // Add NumberOfPartitions as 64-bit value
    let num_valid_partitions = valid_entries.len() as u64;
    gpt_event_data.extend_from_slice(&num_valid_partitions.to_le_bytes());
    
    // Add valid partition entries
    for entry in valid_entries {
        gpt_event_data.extend_from_slice(&entry);
    }
    
    Ok(gpt_event_data)
}

/// Direct implementation using guestfish commands
fn extract_with_guestfish_direct(qcow2_path: &str, output_dir: &Path) -> Result<()> {
    let gpt_path = output_dir.join("gpt_data.bin");
    let shim_path = output_dir.join("shim_data.efi");
    let grub_path = output_dir.join("grub_data.efi");
    
    // Extract GPT event data (not raw sectors)
    let gpt_data = extract_gpt_event_data(qcow2_path)?;
    std::fs::write(&gpt_path, &gpt_data)?;
    
    // Extract shim
    let output = Command::new("guestfish")
        .args(&[
            "--ro", "-a", qcow2_path, "-i",
            "download", "/boot/efi/EFI/ubuntu/shimx64.efi", shim_path.to_str().unwrap()
        ])
        .output()
        .context("Failed to extract shim")?;
    
    if !output.status.success() {
        bail!("Failed to extract shim: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    // Extract grub
    let output = Command::new("guestfish")
        .args(&[
            "--ro", "-a", qcow2_path, "-i",
            "download", "/boot/efi/EFI/ubuntu/grubx64.efi", grub_path.to_str().unwrap()
        ])
        .output()
        .context("Failed to extract grub")?;
    
    if !output.status.success() {
        bail!("Failed to extract grub: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    Ok(())
}

/// Measures RTMR1 for bootloader-based deployments
pub(crate) fn measure_bootloader_chain(
    gpt_data: &[u8],
    shim_data: &[u8], 
    grub_data: &[u8],
) -> Result<Vec<u8>> {
    let gpt_hash = measure_sha384(gpt_data);
    let shim_hash = authenticode_sha384_hash(shim_data).context("Failed to compute shim hash")?;
    let grub_hash = authenticode_sha384_hash(grub_data).context("Failed to compute grub hash")?;
    
    let rtmr1_log = vec![
        measure_sha384(b"Calling EFI Application from Boot Option"),
        measure_sha384(&[0x00, 0x00, 0x00, 0x00]), // Separator
        gpt_hash,
        shim_hash,
        grub_hash,
        measure_sha384(b"Exit Boot Services Invocation"),
        measure_sha384(b"Exit Boot Services Returned with Success"),
    ];
    debug_print_log("RTMR1", &rtmr1_log);
    Ok(measure_log(&rtmr1_log))
}

/// Main function to measure RTMR1 from a qcow2 disk image
pub fn measure_rtmr1_from_qcow2(qcow2_path: &str) -> Result<Vec<u8>> {
    let components = extract_bootloader_components(qcow2_path)
        .context("Failed to extract bootloader components")?;
    
    measure_bootloader_chain(&components.gpt_data, &components.shim_data, &components.grub_data)
}

/// Represents the cert_table structure from shim
#[derive(Debug)]
struct _CertTable {
    vendor_authorized_size: u32,
    vendor_deauthorized_size: u32,
    vendor_authorized_offset: u32,
    vendor_deauthorized_offset: u32,
}

/// Extracts the cert_table structure from shim PE binary
fn _find_cert_table_offset(shim_data: &[u8]) -> Result<usize> {
    // Parse PE header to find sections
    let lfanew_offset = 0x3c;
    let lfanew: u32 = read_le(shim_data, lfanew_offset, "DOS header")?;

    let pe_sig_offset = lfanew as usize;
    let pe_sig: u32 = read_le(shim_data, pe_sig_offset, "PE signature offset")?;
    if pe_sig != pe::IMAGE_NT_SIGNATURE {
        bail!("Invalid PE signature in shim");
    }

    let coff_header_offset = pe_sig_offset + 4;
    let optional_header_size = read_le::<u16>(shim_data, coff_header_offset + 16, "COFF header size")? as usize;
    let num_sections = read_le::<u16>(shim_data, coff_header_offset + 2, "number of sections")? as usize;

    let optional_header_offset = coff_header_offset + 20;
    let section_table_offset = optional_header_offset + optional_header_size;
    let section_size = 40;

    // Look for .vendor_cert section or similar
    for i in 0..num_sections {
        let section_offset = section_table_offset + (i * section_size);
        
        if section_offset + section_size > shim_data.len() {
            break;
        }

        // Read section name (8 bytes)
        let section_name = &shim_data[section_offset..section_offset + 8];
        
        // Check if this could be a certificate section
        if section_name.starts_with(b".vendor_") || section_name.starts_with(b".cert") {
            let _virtual_address = read_le::<u32>(shim_data, section_offset + 12, "virtual address")? as usize;
            let raw_data_offset = read_le::<u32>(shim_data, section_offset + 20, "raw data offset")? as usize;
            let raw_data_size = read_le::<u32>(shim_data, section_offset + 16, "raw data size")? as usize;
            
            if raw_data_offset + raw_data_size <= shim_data.len() && raw_data_size >= 16 {
                // This could be our cert_table - try to validate it
                if let Ok(cert_table) = _parse_cert_table(shim_data, raw_data_offset) {
                    // Basic validation: check if offsets are reasonable
                    if cert_table.vendor_authorized_offset < raw_data_size as u32 && 
                       cert_table.vendor_deauthorized_offset < raw_data_size as u32 {
                        return Ok(raw_data_offset);
                    }
                }
            }
        }
    }

    // If we can't find a specific section, try to search for the cert_table pattern
    // Look for a pattern that could be cert_table (4 consecutive u32s with reasonable values)
    for i in 0..shim_data.len().saturating_sub(16) {
        if i % 4 == 0 {  // Align to 4-byte boundary
            if let Ok(cert_table) = _parse_cert_table(shim_data, i) {
                // Validate the cert_table structure
                if cert_table.vendor_authorized_size > 0 && 
                   cert_table.vendor_authorized_size < 0x10000 &&
                   cert_table.vendor_authorized_offset > 0 &&
                   cert_table.vendor_authorized_offset < shim_data.len() as u32 {
                    return Ok(i);
                }
            }
        }
    }

    bail!("Could not find cert_table in shim binary");
}

/// Parses the cert_table structure from a given offset
fn _parse_cert_table(shim_data: &[u8], offset: usize) -> Result<_CertTable> {
    if offset + 16 > shim_data.len() {
        bail!("Cert table offset out of bounds");
    }

    let vendor_authorized_size = read_le::<u32>(shim_data, offset, "vendor_authorized_size")?;
    let vendor_deauthorized_size = read_le::<u32>(shim_data, offset + 4, "vendor_deauthorized_size")?;
    let vendor_authorized_offset = read_le::<u32>(shim_data, offset + 8, "vendor_authorized_offset")?;
    let vendor_deauthorized_offset = read_le::<u32>(shim_data, offset + 12, "vendor_deauthorized_offset")?;

    Ok(_CertTable {
        vendor_authorized_size,
        vendor_deauthorized_size,
        vendor_authorized_offset,
        vendor_deauthorized_offset,
    })
}

/// Extracts certificate data from shim binary
fn _extract_cert_data_from_shim(shim_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cert_table_offset = _find_cert_table_offset(shim_data)?;
    let cert_table = _parse_cert_table(shim_data, cert_table_offset)?;

    // Extract vendor_authorized data
    let vendor_auth_start = cert_table_offset + cert_table.vendor_authorized_offset as usize;
    let vendor_auth_end = vendor_auth_start + cert_table.vendor_authorized_size as usize;
    
    let vendor_auth_data = if vendor_auth_end <= shim_data.len() && cert_table.vendor_authorized_size > 0 {
        shim_data[vendor_auth_start..vendor_auth_end].to_vec()
    } else {
        Vec::new()
    };

    // Extract vendor_deauthorized data
    let vendor_deauth_start = cert_table_offset + cert_table.vendor_deauthorized_offset as usize;
    let vendor_deauth_end = vendor_deauth_start + cert_table.vendor_deauthorized_size as usize;
    
    let vendor_deauth_data = if vendor_deauth_end <= shim_data.len() && cert_table.vendor_deauthorized_size > 0 {
        shim_data[vendor_deauth_start..vendor_deauth_end].to_vec()
    } else {
        Vec::new()
    };

    Ok((vendor_auth_data, vendor_deauth_data))
}

/// Reconstructs MOK variables as shim would build them
pub fn _reconstruct_mok_variables(shim_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (vendor_auth_data, vendor_deauth_data) = _extract_cert_data_from_shim(shim_data)?;

    // Reconstruct MokList variable
    // Order: vendor_authorized + build_cert (if any) + user_cert (if any) + existing MokList
    let mut mok_list = Vec::new();
    mok_list.extend_from_slice(&vendor_auth_data);
    // Note: For now, we're only including vendor_authorized data
    // In a full implementation, you'd also need to extract build_cert and user_cert

    // Reconstruct MokListX variable  
    // Order: vendor_deauthorized + existing MokListX
    let mut mok_list_x = Vec::new();
    mok_list_x.extend_from_slice(&vendor_deauth_data);

    // Reconstruct MokListTrusted variable
    // Default to 0x01 (trusted) if variable doesn't exist
    let mok_list_trusted = vec![0x01];

    Ok((mok_list, mok_list_x, mok_list_trusted))
}

fn read_file_data(filename: &str) -> Result<Vec<u8>> {
    let path = Path::new(filename);
    if path.exists() {
        match fs::read(path) {
            Ok(data) => {
                Ok(data)
            }
            Err(e) => {
                debug!("Failed to read {}: {}", filename, e);
                // Return empty data if file doesn't exist or can't be read
                Ok(Vec::new())
            }
        }
    } else {
        debug!("File {} not found, using empty data", filename);
        Ok(Vec::new())
    }
}

/// Measures RTMR2 using actual MOK variable data extracted from shim
pub fn measure_rtmr2_from_qcow2(_qcow2_path: &str, cmdline: &str, ref_mok_list: &str, ref_mok_list_trusted: &str, ref_mok_list_x: &str) -> Result<Vec<u8>> {
    
    // TODO: extract MOK variables from qcow2
    // let components = extract_bootloader_components(qcow2_path)
    //     .context("Failed to extract bootloader components")?;
    
    // let (mok_list, mok_list_x, mok_list_trusted) = reconstruct_mok_variables(&components.shim_data)
    //     .context("Failed to reconstruct MOK variables")?;

    let ref_mok_list_data = read_file_data(ref_mok_list)?;
    let ref_mok_list_trusted_data = read_file_data(ref_mok_list_trusted)?;
    let ref_mok_list_x_data = read_file_data(ref_mok_list_x)?;

    // TODO: extract initrd from qcow2

    let rtmr2_log = vec![
        measure_sha384(&ref_mok_list_data),
        measure_sha384(&ref_mok_list_x_data),
        measure_sha384(&ref_mok_list_trusted_data),
        measure_cmdline(cmdline),
        // measure_sha384(initrd_data),
    ];

    debug_print_log("RTMR2", &rtmr2_log);
    Ok(measure_log(&rtmr2_log))
}
