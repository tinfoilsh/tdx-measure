use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

pub use machine::Machine;

use util::{measure_log, measure_sha384, utf16_encode};

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
    pub rtmr0: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr1: Vec<u8>,
    #[serde(with = "hex_bytes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rtmr2: Vec<u8>,
}

/// Image information for DStack images
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    #[serde(default)]
    pub qcow2: String,
    pub cmdline: String,
    #[serde(default)]
    pub kernel: String,
    #[serde(default)]
    pub initrd: String,
    pub bios: String,
    pub acpi_tables: String,
    pub rsdp: String,
    pub table_loader: String,
    pub boot_order: String,
    pub boot_0000: String,
    pub boot_0001: String,
    pub boot_0006: String,
    pub boot_0007: String,
    pub mok_list: String,
    pub mok_list_trusted: String,
    pub mok_list_x: String,
    pub sbat_level: String,
}