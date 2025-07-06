//! This module provides functionality to generate ACPI tables for QEMU,
//! translated from an original Go implementation.

use anyhow::{bail, Context, Result};
use log::debug;

use crate::Machine;

const LDR_LENGTH: usize = 4096;
const FIXED_STRING_LEN: usize = 56;

pub struct Tables {
    pub tables: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub loader: Vec<u8>,
}

impl Machine<'_> {
    fn create_tables(&self) -> Result<Vec<u8>> {
        match std::fs::read(self.acpi_tables) {
            Ok(data) => {
                debug!("Loaded ACPI tables from file: {} ({} bytes)", self.acpi_tables, data.len());
                Ok(data)
            }
            Err(e) => {
                // Fallback to original behavior if file doesn't exist
                debug!("Failed to load ACPI tables from file: {}, falling back to dstack-acpi-tables", e);
                self.create_tables_with_dstack()
            }
        }
    }

    // Rename the original method as a fallback
    fn create_tables_with_dstack(&self) -> Result<Vec<u8>> {
        if self.cpu_count == 0 {
            bail!("cpuCount must be greater than 0");
        }
        let mem_size_mb = self.memory_size / (1024 * 1024);

        // Dummy disk and shared directory. Use as placeholders for the qemu arguments.
        let dummy_disk = "/bin/sh";
        let shared_dir = "/bin";

        // Prepare the command arguments
        let mut cmd = std::process::Command::new("dstack-acpi-tables");
        cmd.args([
            "-cpu",
            "qemu64",
            "-smp",
            &self.cpu_count.to_string(),
            "-m",
            &format!("{mem_size_mb}M"),
            "-nographic",
            "-nodefaults",
            "-serial",
            "stdio",
            "-bios",
            self.firmware,
            "-kernel",
            self.kernel,
            "-initrd",
            dummy_disk,
            "-drive",
            &format!("file={dummy_disk},if=none,id=hd1,format=raw,readonly=on"),
            "-device",
            "virtio-blk-pci,drive=hd1",
            "-netdev",
            "user,id=net0",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-object",
            "tdx-guest,id=tdx",
            "-device",
            "vhost-vsock-pci,guest-cid=3",
            "-virtfs",
            &format!(
                "local,path={shared_dir},mount_tag=host-shared,readonly=on,security_model=none,id=virtfs0",
            ),
        ]);

        if self.root_verity {
            cmd.args([
                "-drive",
                &format!("file={dummy_disk},if=none,id=hd0,format=raw,readonly=on"),
                "-device",
                "virtio-blk-pci,drive=hd0",
            ]);
        } else {
            cmd.args(["-cdrom", dummy_disk]);
        }

        let mut machine =
            "q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off".to_string();
        if self.smm {
            machine.push_str(",smm=on");
        } else {
            machine.push_str(",smm=off");
        }
        if self.pic {
            machine.push_str(",pic=on");
        } else {
            machine.push_str(",pic=off");
        }
        cmd.args(["-machine", &machine]);
        if self.hugepages {
            let cpu_end = self.cpu_count - 1;
            cmd.args([
                "-numa",
                &format!("node,nodeid=0,cpus=0-{cpu_end},memdev=mem0"),
                "-object",
                &format!("memory-backend-file,id=mem0,size={mem_size_mb}M,mem-path=/dev/hugepages,share=on,prealloc=no,host-nodes=0,policy=bind"),
            ]);
        }
        let mut port_num = 0;
        if self.num_gpus > 0 {
            cmd.args(["-object", "iommufd,id=iommufd0"]);
            let bus = if self.hugepages {
                cmd.args([
                    "-device",
                    "pxb-pcie,id=pcie.node0,bus=pcie.0,addr=10,numa_node=0,bus_nr=5",
                ]);
                "pcie.node0"
            } else {
                "pcie.0"
            };
            for _ in 0..self.num_gpus {
                cmd.args([
                    "-device",
                    &format!("pcie-root-port,id=pci.{port_num},bus={bus},chassis={port_num}"),
                    "-device",
                    &format!("vfio-pci,host=00:00.0,bus=pci.{port_num},iommufd=iommufd0"),
                ]);
                port_num += 1;
            }
        }

        for _ in 0..self.num_nvswitches {
            cmd.args([
                "-device",
                &format!("pcie-root-port,id=pci.{port_num},bus=pcie.0,chassis={port_num}"),
                "-device",
                &format!("vfio-pci,host=00:00.0,bus=pci.{port_num},iommufd=iommufd0"),
            ]);
            port_num += 1;
        }

        if self.hotplug_off {
            cmd.args([
                "-global",
                "ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off",
            ]);
        }
        if let Some(pci_hole64_size) = self.pci_hole64_size {
            cmd.args([
                "-global",
                &format!("q35-pcihost.pci-hole64-size=0x{:x}", pci_hole64_size),
            ]);
        }

        debug!("qemu command: {cmd:?}");

        // Execute the command and capture output
        let output = cmd
            .output()
            .context("failed to execute dstack-acpi-tables")?;

        // Check if the command was successful
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("dstack-acpi-tables failed: {stderr}");
        }
        Ok(output.stdout)
    }

    fn load_rsdp(&self, rsdt_info: Option<(u32, u32, u32)>) -> Result<Vec<u8>> {
        // Always generate the RSDP first for comparison
        let generated_rsdp = self.generate_rsdp(rsdt_info)?;
        
        match std::fs::read(self.rsdp) {
            Ok(file_rsdp) => {
                debug!("Loaded RSDP from file: {} ({} bytes)", self.rsdp, file_rsdp.len());
                debug!("Generated RSDP size: {} bytes", generated_rsdp.len());
                
                // Compare the two RSDPs
                if file_rsdp == generated_rsdp {
                    debug!("File RSDP matches generated RSDP exactly");
                } else {
                    debug!("File RSDP differs from generated RSDP");
                    
                    // Compare sizes
                    if file_rsdp.len() != generated_rsdp.len() {
                        debug!("Size difference: file={} bytes, generated={} bytes", 
                               file_rsdp.len(), generated_rsdp.len());
                    }
                    
                    // Compare byte by byte for first differences
                    let min_len = file_rsdp.len().min(generated_rsdp.len());
                    for i in 0..min_len {
                        if file_rsdp[i] != generated_rsdp[i] {
                            debug!("First difference at byte {}: file=0x{:02x}, generated=0x{:02x}", 
                                   i, file_rsdp[i], generated_rsdp[i]);
                            break;
                        }
                    }
                    
                    // Show hex dumps for comparison
                    debug!("File RSDP hex dump: {:02x?}", file_rsdp);
                    debug!("Generated RSDP hex dump: {:02x?}", generated_rsdp);
                }
                
                Ok(file_rsdp)
            }
            Err(e) => {
                debug!("Failed to load RSDP from file: {}, using generated RSDP", e);
                Ok(generated_rsdp)
            }
        }
    }

    fn generate_rsdp(&self, rsdt_info: Option<(u32, u32, u32)>) -> Result<Vec<u8>> {
        // Generate RSDP
        let mut rsdp = Vec::with_capacity(20);
        rsdp.extend_from_slice(b"RSD PTR "); // Signature
        rsdp.push(0x00); // Checksum placeholder
        rsdp.extend_from_slice(b"BOCHS "); // OEM ID
        rsdp.push(0x00); // Revision
        
        // If we have RSDT, use its offset, otherwise use 0
        let rsdt_offset = rsdt_info.map(|(offset, _, _)| offset).unwrap_or(0);
        rsdp.extend_from_slice(&rsdt_offset.to_le_bytes()); // RSDT Address
        
        Ok(rsdp)
    }

    fn load_table_loader(&self, dsdt_offset: u32, dsdt_csum: u32, dsdt_len: u32,
                        facp_offset: u32, facp_csum: u32, facp_len: u32,
                        apic_offset: u32, apic_csum: u32, apic_len: u32,
                        mcfg_offset: u32, mcfg_csum: u32, mcfg_len: u32,
                        waet_offset: u32, waet_csum: u32, waet_len: u32,
                        rsdt_info: Option<(u32, u32, u32)>) -> Result<Vec<u8>> {
        let generated_loader = self.generate_table_loader(
            dsdt_offset, dsdt_csum, dsdt_len,
            facp_offset, facp_csum, facp_len,
            apic_offset, apic_csum, apic_len,
            mcfg_offset, mcfg_csum, mcfg_len,
            waet_offset, waet_csum, waet_len,
            rsdt_info
        )?;
        
        match std::fs::read(self.table_loader) {
            Ok(file_loader) => {
                debug!("Loaded table loader from file: {} ({} bytes)", self.table_loader, file_loader.len());
                debug!("Generated table loader size: {} bytes", generated_loader.len());
                
                // Compare the two table loaders
                if file_loader == generated_loader {
                    debug!("File table loader matches generated table loader exactly");
                } else {
                    debug!("File table loader differs from generated table loader");
                    
                    // Compare sizes
                    if file_loader.len() != generated_loader.len() {
                        debug!("Size difference: file={} bytes, generated={} bytes", 
                               file_loader.len(), generated_loader.len());
                    }
                    
                    // Compare byte by byte for first differences
                    let min_len = file_loader.len().min(generated_loader.len());
                    for i in 0..min_len {
                        if file_loader[i] != generated_loader[i] {
                            debug!("First difference at byte {}: file=0x{:02x}, generated=0x{:02x}", 
                                   i, file_loader[i], generated_loader[i]);
                            break;
                        }
                    }
                    
                    // Show hex dumps for comparison (first 128 bytes to avoid too much output)
                    let file_sample = &file_loader[..file_loader.len().min(128)];
                    let gen_sample = &generated_loader[..generated_loader.len().min(128)];
                    debug!("File table loader hex dump (first 128 bytes): {:02x?}", file_sample);
                    debug!("Generated table loader hex dump (first 128 bytes): {:02x?}", gen_sample);
                }
                
                Ok(file_loader)
            }
            Err(e) => {
                // Fallback to generated table loader if file doesn't exist
                debug!("Failed to load table loader from file: {}, using generated table loader", e);
                Ok(generated_loader)
            }
        }
    }

    fn generate_table_loader(&self, dsdt_offset: u32, dsdt_csum: u32, dsdt_len: u32,
                            facp_offset: u32, facp_csum: u32, facp_len: u32,
                            apic_offset: u32, apic_csum: u32, apic_len: u32,
                            mcfg_offset: u32, mcfg_csum: u32, mcfg_len: u32,
                            waet_offset: u32, waet_csum: u32, waet_len: u32,
                            rsdt_info: Option<(u32, u32, u32)>) -> Result<Vec<u8>> {
        // Generate table loader commands
        let mut ldr = TableLoader::new();
        ldr.append(LoaderCmd::Allocate {
            file: "etc/acpi/rsdp",
            alignment: 16,
            zone: 2,
        });
        ldr.append(LoaderCmd::Allocate {
            file: "etc/acpi/tables",
            alignment: 64,
            zone: 1,
        });
        
        // Add loader commands for existing tables
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: dsdt_csum,
            start: dsdt_offset,
            length: dsdt_len,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: facp_offset + 36,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: facp_offset + 40,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/tables",
            pointee_file: "etc/acpi/tables",
            pointer_offset: facp_offset + 140,
            pointer_size: 8,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: facp_csum,
            start: facp_offset,
            length: facp_len,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: apic_csum,
            start: apic_offset,
            length: apic_len,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: mcfg_csum,
            start: mcfg_offset,
            length: mcfg_len,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/tables",
            result_offset: waet_csum,
            start: waet_offset,
            length: waet_len,
        });
        
        // Only add RSDT-related commands if RSDT exists
        if let Some((rsdt_offset, rsdt_csum, rsdt_len)) = rsdt_info {
            ldr.append(LoaderCmd::AddPtr {
                pointer_file: "etc/acpi/tables",
                pointee_file: "etc/acpi/tables",
                pointer_offset: rsdt_offset + 36,
                pointer_size: 4,
            });
            ldr.append(LoaderCmd::AddPtr {
                pointer_file: "etc/acpi/tables",
                pointee_file: "etc/acpi/tables",
                pointer_offset: rsdt_offset + 40,
                pointer_size: 4,
            });
            ldr.append(LoaderCmd::AddPtr {
                pointer_file: "etc/acpi/tables",
                pointee_file: "etc/acpi/tables",
                pointer_offset: rsdt_offset + 44,
                pointer_size: 4,
            });
            ldr.append(LoaderCmd::AddPtr {
                pointer_file: "etc/acpi/tables",
                pointee_file: "etc/acpi/tables",
                pointer_offset: rsdt_offset + 48,
                pointer_size: 4,
            });
            ldr.append(LoaderCmd::AddChecksum {
                file: "etc/acpi/tables",
                result_offset: rsdt_csum,
                start: rsdt_offset,
                length: rsdt_len,
            });
        }
        
        ldr.append(LoaderCmd::AddPtr {
            pointer_file: "etc/acpi/rsdp",
            pointee_file: "etc/acpi/tables",
            pointer_offset: 16,
            pointer_size: 4,
        });
        ldr.append(LoaderCmd::AddChecksum {
            file: "etc/acpi/rsdp",
            result_offset: 8,
            start: 0,
            length: 20,
        });
        
        // Pad the loader command blob to the required length
        if ldr.buffer.len() < LDR_LENGTH {
            ldr.buffer.resize(LDR_LENGTH, 0);
        }

        Ok(ldr.buffer)
    }

    pub fn build_tables(&self) -> Result<Tables> {
        let tpl = self.create_tables()?;
        // Find all required ACPI tables
        let (dsdt_offset, dsdt_csum, dsdt_len) = find_acpi_table(&tpl, "DSDT")?;
        let (facp_offset, facp_csum, facp_len) = find_acpi_table(&tpl, "FACP")?;
        let (apic_offset, apic_csum, apic_len) = find_acpi_table(&tpl, "APIC")?;
        let (mcfg_offset, mcfg_csum, mcfg_len) = find_acpi_table(&tpl, "MCFG")?;
        let (waet_offset, waet_csum, waet_len) = find_acpi_table(&tpl, "WAET")?;
        
        // Try to find RSDT, but make it optional
        let rsdt_info = find_acpi_table(&tpl, "RSDT").ok();

        // Load RSDP from file or generate it (with comparison)
        let rsdp = self.load_rsdp(rsdt_info)?;

        // Load table loader from file or generate it (with comparison)
        let loader = self.load_table_loader(
            dsdt_offset, dsdt_csum, dsdt_len,
            facp_offset, facp_csum, facp_len,
            apic_offset, apic_csum, apic_len,
            mcfg_offset, mcfg_csum, mcfg_len,
            waet_offset, waet_csum, waet_len,
            rsdt_info
        )?;

        Ok(Tables {
            tables: tpl,
            rsdp,
            loader,
        })
    }
}

/// An enum to represent the different QEMU loader commands in a type-safe way.
#[derive(Debug)]
enum LoaderCmd<'a> {
    Allocate {
        file: &'a str,
        alignment: u32,
        zone: u8,
    },
    AddPtr {
        pointer_file: &'a str,
        pointee_file: &'a str,
        pointer_offset: u32,
        pointer_size: u8,
    },
    AddChecksum {
        file: &'a str,
        result_offset: u32,
        start: u32,
        length: u32,
    },
}

struct TableLoader {
    buffer: Vec<u8>,
}

impl TableLoader {
    fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(LDR_LENGTH),
        }
    }
    fn append(&mut self, cmd: LoaderCmd) {
        qemu_loader_append(&mut self.buffer, cmd);
    }
}

/// Appends a fixed-length, null-padded string to the data buffer.
fn append_fixed_string(data: &mut Vec<u8>, s: &str) {
    let mut s_bytes = s.as_bytes().to_vec();
    s_bytes.resize(FIXED_STRING_LEN, 0);
    data.extend_from_slice(&s_bytes);
}

/// Appends a serialized QEMU loader command to the data buffer.
fn qemu_loader_append(data: &mut Vec<u8>, cmd: LoaderCmd) {
    match cmd {
        LoaderCmd::Allocate {
            file,
            alignment,
            zone,
        } => {
            data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
            append_fixed_string(data, file);
            data.extend_from_slice(&alignment.to_le_bytes());
            data.push(zone);
            data.resize(data.len() + 63, 0); // Padding
        }
        LoaderCmd::AddPtr {
            pointer_file,
            pointee_file,
            pointer_offset,
            pointer_size,
        } => {
            data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
            append_fixed_string(data, pointer_file);
            append_fixed_string(data, pointee_file);
            data.extend_from_slice(&pointer_offset.to_le_bytes());
            data.push(pointer_size);
            data.resize(data.len() + 7, 0); // Padding
        }
        LoaderCmd::AddChecksum {
            file,
            result_offset,
            start,
            length,
        } => {
            data.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
            append_fixed_string(data, file);
            data.extend_from_slice(&result_offset.to_le_bytes());
            data.extend_from_slice(&start.to_le_bytes());
            data.extend_from_slice(&length.to_le_bytes());
            data.resize(data.len() + 56, 0); // Padding
        }
    }
}

/// Searches for an ACPI table with the given signature and returns its offset,
/// checksum offset, and length.
fn find_acpi_table(tables: &[u8], signature: &str) -> Result<(u32, u32, u32)> {
    let sig_bytes = signature.as_bytes();
    if sig_bytes.len() != 4 {
        bail!("Signature must be 4 bytes long, but got '{signature}'");
    }

    let mut offset = 0;
    while offset < tables.len() {
        // Ensure there's enough space for a table header
        if offset + 8 > tables.len() {
            bail!("Table not found: {signature}");
        }

        let tbl_sig = &tables[offset..offset + 4];
        let tbl_len_bytes: [u8; 4] = tables[offset + 4..offset + 8].try_into().unwrap();
        let tbl_len = u32::from_le_bytes(tbl_len_bytes) as usize;

        if tbl_sig == sig_bytes {
            // Found the table
            return Ok((offset as u32, (offset + 9) as u32, tbl_len as u32));
        }

        if tbl_len == 0 {
            // Invalid table length, stop searching
            bail!("Found table with zero length at offset {offset}");
        }
        // Move to the next table
        offset += tbl_len;
    }

    bail!("Table not found: {signature}");
}
