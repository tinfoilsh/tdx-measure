use crate::tdvf::Tdvf;
use crate::util::debug_print_log;
use crate::{kernel, TdxMeasurements};
use crate::image;
use crate::{measure_log, measure_sha384};
use anyhow::{Context, Result};
use fs_err as fs;
use log::debug;

#[derive(Debug, bon::Builder)]
pub struct Machine<'a> {
    pub cpu_count: u8,
    pub memory_size: u64,
    pub qcow2: &'a str,
    pub firmware: &'a str,
    pub kernel: &'a str,
    pub initrd: &'a str,
    pub kernel_cmdline: &'a str,
    pub acpi_tables: &'a str,
    pub rsdp: &'a str,
    pub table_loader: &'a str,
    pub boot_order: &'a str,
    pub boot_0000: &'a str,
    pub boot_0001: &'a str,
    pub boot_0006: &'a str,
    pub boot_0007: &'a str,
    pub mok_list: &'a str,
    pub mok_list_trusted: &'a str,
    pub mok_list_x: &'a str,
    pub sbat_level: &'a str,
    pub two_pass_add_pages: bool,
    pub pic: bool,
    #[builder(default = false)]
    pub smm: bool,
    pub pci_hole64_size: Option<u64>,
    pub hugepages: bool,
    pub num_gpus: u32,
    pub num_nvswitches: u32,
    pub hotplug_off: bool,
    pub root_verity: bool,
    pub direct_boot: bool,
}

impl Machine<'_> {
    pub fn measure(&self) -> Result<TdxMeasurements> {
        debug!("measuring machine: {self:#?}");
        let fw_data = fs::read(self.firmware)?;
        let kernel_data = fs::read(self.kernel)?;
        let initrd_data = fs::read(self.initrd)?;
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;
        let mrtd = tdvf.mrtd(self).context("Failed to compute MR TD")?;
        let rtmr0 = tdvf.rtmr0(self).context("Failed to compute RTMR0")?;

        let rtmr1;
        if self.direct_boot {
            rtmr1 = kernel::measure_kernel(
                &kernel_data,
                initrd_data.len() as u32,
                self.memory_size,
                0x28000,
            )?;
        } else {
            rtmr1 = image::measure_rtmr1_from_qcow2(self.qcow2)?;
        }

        let rtmr2;
        if self.direct_boot {
            let rtmr2_log = vec![
                kernel::measure_cmdline(self.kernel_cmdline),
                measure_sha384(&initrd_data),
            ];
            debug_print_log("RTMR2", &rtmr2_log);
            rtmr2 = measure_log(&rtmr2_log);
        } else {
            rtmr2 = image::measure_rtmr2_from_qcow2(self.qcow2, self.kernel_cmdline, &initrd_data, self.mok_list, self.mok_list_trusted, self.mok_list_x)?;
        }

        Ok(TdxMeasurements {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
        })
    }

    pub fn measure_platform(&self) -> Result<TdxMeasurements> {
        let fw_data = fs::read(self.firmware)?;
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;
        let mrtd = tdvf.mrtd(self).context("Failed to compute MR TD")?;
        let rtmr0 = tdvf.rtmr0(self).context("Failed to compute RTMR0")?;

        Ok(TdxMeasurements {
            mrtd,
            rtmr0,
            rtmr1: vec![],
            rtmr2: vec![],
        })
    }
}
