#![allow(dead_code)] // todo: remove

use crate::{measure_log, measure_sha384, num::read_le, utf16_encode, util::debug_print_log};
use anyhow::{bail, Context, Result};
use object::pe;
use sha2::{Digest, Sha384};
use std::path::Path;
use std::process::Command;

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

/// Calculates the Authenticode hash of a PE/COFF file
fn authenticode_sha384_hash(data: &[u8]) -> Result<Vec<u8>> {
    let lfanew_offset = 0x3c;
    let lfanew: u32 = read_le(data, lfanew_offset, "DOS header")?;

    let pe_sig_offset = lfanew as usize;
    let pe_sig: u32 = read_le(data, pe_sig_offset, "PE signature offset")?;
    if pe_sig != pe::IMAGE_NT_SIGNATURE {
        bail!("Invalid PE signature");
    }

    let coff_header_offset = pe_sig_offset + 4;
    let optional_header_size =
        read_le::<u16>(data, coff_header_offset + 16, "COFF header size")? as usize;

    let optional_header_offset = coff_header_offset + 20;
    let magic: u16 = read_le(data, optional_header_offset, "header magic")?;

    let is_pe32_plus = magic == 0x20b;

    let checksum_offset = optional_header_offset + 64;
    let checksum_end = checksum_offset + 4;

    let data_dir_offset = optional_header_offset + if is_pe32_plus { 112 } else { 96 };
    let cert_dir_offset = data_dir_offset + (pe::IMAGE_DIRECTORY_ENTRY_SECURITY * 8);
    let cert_dir_end = cert_dir_offset + 8;

    let size_of_headers_offset = optional_header_offset + 60;
    let size_of_headers = read_le::<u32>(data, size_of_headers_offset, "size_of_headers")? as usize;

    let mut hasher = Sha384::new();
    hasher.update(&data[0..checksum_offset]);
    hasher.update(&data[checksum_end..cert_dir_offset]);
    hasher.update(&data[cert_dir_end..size_of_headers]);

    let mut sum_of_bytes_hashed = size_of_headers;

    let num_sections_offset = coff_header_offset + 2;
    let num_sections = read_le::<u16>(data, num_sections_offset, "number of sections")? as usize;

    let section_table_offset = optional_header_offset + optional_header_size;
    let section_size = 40;

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let section_offset = section_table_offset + (i * section_size);

        let ptr_raw_data_offset = section_offset + 20;
        let ptr_raw_data =
            read_le::<u32>(data, ptr_raw_data_offset, "pointer_to_raw_data")? as usize;

        let size_raw_data_offset = section_offset + 16;
        let size_raw_data =
            read_le::<u32>(data, size_raw_data_offset, "size_of_raw_data")? as usize;

        if size_raw_data > 0 {
            sections.push((ptr_raw_data, size_raw_data));
        }
    }

    sections.sort_by_key(|&(offset, _)| offset);

    for (offset, size) in sections {
        let start = offset;
        let end = start + size;

        if end <= data.len() {
            hasher.update(&data[start..end]);
        } else {
            let available_size = data.len().saturating_sub(start);
            if available_size > 0 {
                hasher.update(&data[start..start + available_size]);
            }
        }

        sum_of_bytes_hashed += size;
    }

    let file_size = data.len();

    let cert_table_addr_offset = cert_dir_offset;
    let cert_table_size_offset = cert_dir_offset + 4;

    let cert_table_addr =
        read_le::<u32>(data, cert_table_addr_offset, "certificate table address")? as usize;
    let cert_table_size =
        read_le::<u32>(data, cert_table_size_offset, "certificate table size")? as usize;

    if cert_table_addr > 0 && cert_table_size > 0 && file_size > sum_of_bytes_hashed {
        let trailing_data_len = file_size - sum_of_bytes_hashed;

        if trailing_data_len > cert_table_size {
            let hashed_trailing_len = trailing_data_len - cert_table_size;
            let trailing_start = sum_of_bytes_hashed;

            if trailing_start + hashed_trailing_len <= data.len() {
                hasher.update(&data[trailing_start..trailing_start + hashed_trailing_len]);
            }
        }
    }
    let remainder = file_size % 8;
    if remainder != 0 {
        let padding = vec![0u8; 8 - remainder];
        hasher.update(&padding);
    }
    Ok(hasher.finalize().to_vec())
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

/// Patches the kernel image as qemu does.
fn patch_kernel(
    kernel_data: &[u8],
    initrd_size: u32,
    mem_size: u64,
    acpi_data_size: u32,
) -> Result<Vec<u8>> {
    const MIN_KERNEL_LENGTH: usize = 0x1000;
    if kernel_data.len() < MIN_KERNEL_LENGTH {
        bail!("the kernel image is too short");
    }

    let mut kd = kernel_data.to_vec();

    let protocol = u16::from_le_bytes(kd[0x206..0x208].try_into().unwrap());

    let (real_addr, cmdline_addr) = if protocol < 0x200 || (kd[0x211] & 0x01) == 0 {
        (0x90000_u32, 0x9a000_u32)
    } else {
        (0x10000_u32, 0x20000_u32)
    };

    if protocol >= 0x200 {
        kd[0x210] = 0xb0; // type_of_loader = Qemu v0
    }
    if protocol >= 0x201 {
        kd[0x211] |= 0x80; // loadflags |= CAN_USE_HEAP
        let heap_end_ptr = cmdline_addr - real_addr - 0x200;
        kd[0x224..0x228].copy_from_slice(&heap_end_ptr.to_le_bytes());
    }
    if protocol >= 0x202 {
        kd[0x228..0x22C].copy_from_slice(&cmdline_addr.to_le_bytes());
    } else {
        kd[0x20..0x22].copy_from_slice(&0xa33f_u16.to_le_bytes());
        let offset = (cmdline_addr - real_addr) as u16;
        kd[0x22..0x24].copy_from_slice(&offset.to_le_bytes());
    }

    if initrd_size > 0 {
        if protocol < 0x200 {
            bail!("the kernel image is too old for ramdisk");
        }
        let mut initrd_max = if protocol >= 0x20c {
            let xlf = u16::from_le_bytes(kd[0x236..0x238].try_into().unwrap());
            if (xlf & 0x40) != 0 {
                u32::MAX
            } else {
                0x37ffffff
            }
        } else if protocol >= 0x203 {
            let max = u32::from_le_bytes(kd[0x22c..0x230].try_into().unwrap());
            if max == 0 {
                0x37ffffff
            } else {
                max
            }
        } else {
            0x37ffffff
        };

        let lowmem = if mem_size < 0xb0000000 {
            0xb0000000
        } else {
            0x80000000
        };
        let below_4g_mem_size = if mem_size >= lowmem {
            lowmem as u32
        } else {
            mem_size as u32
        };

        if initrd_max >= below_4g_mem_size - acpi_data_size {
            initrd_max = below_4g_mem_size - acpi_data_size - 1;
        }
        if initrd_size >= initrd_max {
            bail!("initrd is too large");
        }

        let initrd_addr = (initrd_max - initrd_size) & !4095;
        kd[0x218..0x21C].copy_from_slice(&initrd_addr.to_le_bytes());
        kd[0x21C..0x220].copy_from_slice(&initrd_size.to_le_bytes());
    }
    Ok(kd)
}

/// Measures a QEMU-patched TDX kernel image (for direct boot).
pub(crate) fn measure_kernel(
    kernel_data: &[u8],
    initrd_size: u32,
    mem_size: u64,
    acpi_data_size: u32,
) -> Result<Vec<u8>> {
    let kd = patch_kernel(kernel_data, initrd_size, mem_size, acpi_data_size)
        .context("Failed to patch kernel")?;
    let kernel_hash = authenticode_sha384_hash(&kd).context("Failed to compute kernel hash")?;
    let rtmr1_log = vec![
        kernel_hash,
        measure_sha384(b"Calling EFI Application from Boot Option"),
        measure_sha384(&[0x00, 0x00, 0x00, 0x00]), // Separator
        measure_sha384(b"Exit Boot Services Invocation"),
        measure_sha384(b"Exit Boot Services Returned with Success"),
    ];
    debug_print_log("RTMR1", &rtmr1_log);
    Ok(measure_log(&rtmr1_log))
}

/// Measures the kernel command line by converting to UTF-16LE and hashing.
pub(crate) fn measure_cmdline(cmdline: &str) -> Vec<u8> {
    let mut utf16_cmdline = utf16_encode(cmdline);
    utf16_cmdline.extend([0, 0]);
    measure_sha384(&utf16_cmdline)
}
