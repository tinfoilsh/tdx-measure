use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

pub use machine::Machine;

use util::{measure_log, measure_sha384};

mod acpi;
mod kernel;
mod image;
mod machine;
mod num;
mod tdvf;
mod util;

/// Contains all the measurement values for TDX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxMeasurements {
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mrtd: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr0: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr1: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr2: Vec<u8>,
}

/// Common boot information (platform-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootInfo {
    pub bios: String,
    pub acpi_tables: String,
    pub rsdp: String,
    pub table_loader: String,
    pub boot_order: String,
    pub path_boot_xxxx: String,
}

/// Direct boot specific information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectBoot {
    pub kernel: String,
    pub initrd: String,
    pub cmdline: String,
}

/// Indirect boot specific information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectBoot {
    pub qcow2: String,
    pub cmdline: String,
    pub mok_list: String,
    pub mok_list_trusted: String,
    pub mok_list_x: String,
    pub sbat_level: String,
}

/// Complete image configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageConfig {
    pub boot_info: BootInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct: Option<DirectBoot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indirect: Option<IndirectBoot>,
}

impl ImageConfig {
    /// Validate that exactly one boot mode is specified
    pub fn validate(&self) -> Result<(), String> {
        match (&self.direct, &self.indirect) {
            (Some(_), None) => Ok(()),
            (None, Some(_)) => Ok(()),
            (Some(_), Some(_)) => Err("Cannot specify both direct and indirect boot".to_string()),
            (None, None) => Err("Must specify either direct or indirect boot".to_string()),
        }
    }

    /// Check if this is direct boot mode
    pub fn is_direct_boot(&self) -> bool {
        self.direct.is_some()
    }

    /// Get direct boot info
    pub fn direct_boot(&self) -> Option<&DirectBoot> {
        self.direct.as_ref()
    }

    /// Get indirect boot info
    pub fn indirect_boot(&self) -> Option<&IndirectBoot> {
        self.indirect.as_ref()
    }

    /// Get command line regardless of boot mode
    pub fn cmdline(&self) -> &str {
        match (&self.direct, &self.indirect) {
            (Some(direct), None) => &direct.cmdline,
            (None, Some(indirect)) => &indirect.cmdline,
            _ => "", // Should not happen after validation
        }
    }
}