use crate::tdvf::Tdvf;
use crate::util::{debug_print_log, measure_cmdline};
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
        let tdvf = Tdvf::parse(&fw_data).context("Failed to parse TDVF metadata")?;
        let mrtd = tdvf.mrtd(self).context("Failed to compute MR TD")?;
        let rtmr0 = tdvf.rtmr0(self).context("Failed to compute RTMR0")?;

        let rtmr1;
        if self.direct_boot {
            let kernel_path = self.kernel.ok_or_else(|| anyhow::anyhow!("Kernel path required for direct boot"))?;
            let initrd_path = self.initrd.ok_or_else(|| anyhow::anyhow!("Initrd path required for direct boot"))?;
            let kernel_data = fs::read(kernel_path)?;
            let initrd_data = fs::read(initrd_path)?;
            rtmr1 = kernel::measure_kernel(
                &kernel_data,
                initrd_data.len() as u32,
                self.memory_size,
                0x28000,
            )?;
        } else {
            let qcow2_path = self.qcow2.ok_or_else(|| anyhow::anyhow!("Qcow2 path required for indirect boot"))?;
            rtmr1 = image::measure_rtmr1_from_qcow2(qcow2_path)?;
        }

        let rtmr2;
        if self.direct_boot {
            let initrd_path = self.initrd.ok_or_else(|| anyhow::anyhow!("Initrd path required for direct boot"))?;
            let initrd_data = fs::read(initrd_path)?;
            let rtmr2_log = vec![
                measure_cmdline(self.kernel_cmdline),
                measure_sha384(&initrd_data),
            ];
            debug_print_log("RTMR2", &rtmr2_log);
            rtmr2 = measure_log(&rtmr2_log);
        } else {
            let qcow2_path = self.qcow2.ok_or_else(|| anyhow::anyhow!("Qcow2 path required for indirect boot"))?;
            let mok_list_path = self.mok_list.ok_or_else(|| anyhow::anyhow!("MOK list path required for indirect boot"))?;
            let mok_list_trusted_path = self.mok_list_trusted.ok_or_else(|| anyhow::anyhow!("MOK list trusted path required for indirect boot"))?;
            let mok_list_x_path = self.mok_list_x.ok_or_else(|| anyhow::anyhow!("MOK list X path required for indirect boot"))?;
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
