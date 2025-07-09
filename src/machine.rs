use crate::tdvf::Tdvf;
use crate::{kernel, image, TdxMeasurements};
use anyhow::{Context, Result};
use fs_err as fs;
use log::debug;

#[derive(Debug, bon::Builder)]
pub struct Machine<'a> {
    pub cpu_count: u8,
    pub memory_size: u64,
    pub qcow2: Option<&'a str>,
    pub firmware: &'a str,
    pub kernel: Option<&'a str>,
    pub initrd: Option<&'a str>,
    pub kernel_cmdline: &'a str,
    pub acpi_tables: &'a str,
    pub rsdp: &'a str,
    pub table_loader: &'a str,
    pub boot_order: &'a str,
    pub boot_0000: &'a str,
    pub boot_0001: &'a str,
    pub boot_0006: &'a str,
    pub boot_0007: &'a str,
    pub mok_list: Option<&'a str>,
    pub mok_list_trusted: Option<&'a str>,
    pub mok_list_x: Option<&'a str>,
    pub sbat_level: Option<&'a str>,
    pub direct_boot: bool,
    pub two_pass_add_pages: bool,
}

impl Machine<'_> {
    pub fn measure(&self) -> Result<TdxMeasurements> {
        debug!("measuring machine: {self:#?}");

        // Measure platform
        let fw_data = fs::read(self.firmware)?;
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;
        let mrtd = tdvf.mrtd(self).context("Failed to compute MR TD")?;
        let rtmr0 = tdvf.rtmr0(self).context("Failed to compute RTMR0")?;

        let rtmr1;
        let rtmr2;
        
        // Direct boot
        if self.direct_boot {
            let kernel_path = self.kernel.ok_or_else(|| anyhow::anyhow!("Kernel path required for direct boot"))?;
            let initrd_path = self.initrd.ok_or_else(|| anyhow::anyhow!("Initrd path required for direct boot"))?;

            rtmr1 = kernel::measure_rtm1_direct(kernel_path, initrd_path, self.memory_size, 0x28000)?;
            rtmr2 = kernel::measure_rtmr2_direct(initrd_path, self.kernel_cmdline)?;

        } else { // Indirect boot
            let qcow2_path = self.qcow2.ok_or_else(|| anyhow::anyhow!("Qcow2 path required for indirect boot"))?;
            let mok_list_path = self.mok_list.ok_or_else(|| anyhow::anyhow!("MOK list path required for indirect boot"))?;
            let mok_list_trusted_path = self.mok_list_trusted.ok_or_else(|| anyhow::anyhow!("MOK list trusted path required for indirect boot"))?;
            let mok_list_x_path = self.mok_list_x.ok_or_else(|| anyhow::anyhow!("MOK list X path required for indirect boot"))?;

            rtmr1 = image::measure_rtmr1_from_qcow2(qcow2_path)?;
            rtmr2 = image::measure_rtmr2_from_qcow2(qcow2_path, self.kernel_cmdline, mok_list_path, mok_list_trusted_path, mok_list_x_path)?;
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
