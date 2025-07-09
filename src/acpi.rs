//! This module provides functionality to load ACPI tables for QEMU from files.

use anyhow::Result;
use crate::util::read_file_data;
use crate::Machine;

pub struct Tables {
    pub tables: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub loader: Vec<u8>,
}

impl Machine<'_> {
    
    pub fn build_tables(&self) -> Result<Tables> {
        let tables = read_file_data(self.acpi_tables)?;
        let rsdp = read_file_data(self.rsdp)?;
        let loader = read_file_data(self.table_loader)?;

        Ok(Tables {
            tables,
            rsdp,
            loader,
        })
    }
}
