use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use dstack_mr::{Machine, ImageInfo};
use fs_err as fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Measure a machine configuration
    Measure(MachineConfig),
}

type Bool = bool;

#[derive(Parser)]
struct MachineConfig {
    /// Number of CPUs
    #[arg(short, long, default_value = "1")]
    cpu: u8,

    /// Memory size in bytes
    #[arg(short, long, default_value = "2G", value_parser = parse_memory_size)]
    memory: u64,

    /// Path to DStack image metadata.json
    metadata: PathBuf,

    /// Enable two-pass add pages
    #[arg(long, default_value = "true")]
    two_pass_add_pages: Bool,

    /// Enable PIC
    #[arg(long, default_value = "true")]
    pic: Bool,

    /// Enable SMM
    #[arg(long, default_value = "false")]
    smm: Bool,

    /// PCI hole64 size (accepts decimal or hex with 0x prefix)
    #[arg(long, value_parser = parse_memory_size)]
    pci_hole64_size: Option<u64>,

    /// Enable hugepages
    #[arg(long, default_value = "false")]
    hugepages: bool,

    /// Number of GPUs
    #[arg(long, default_value = "0")]
    num_gpus: u32,

    /// Number of NVSwitches
    #[arg(long, default_value = "0")]
    num_nvswitches: u32,

    /// Disable hotplug
    #[arg(long, default_value = "false")]
    hotplug_off: Bool,

    /// Enable root verity
    #[arg(long, default_value = "true")]
    root_verity: Bool,

    /// Output JSON
    #[arg(long)]
    json: bool,

    /// Output JSON to file
    #[arg(long)]
    json_file: Option<PathBuf>,

    /// Compute MRTD and RTMR0 only
    #[arg(long)]
    platform_only: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match &cli.command {
        Commands::Measure(config) => {
            let metadata =
                fs::read_to_string(&config.metadata).context("Failed to read image metadata")?;
            let image_info: ImageInfo =
                serde_json::from_str(&metadata).context("Failed to parse image metadata")?;
            let parent_dir = config.metadata.parent().unwrap_or(".".as_ref());
            
            // Image paths
            let qcow2_path = parent_dir.join(&image_info.qcow2).display().to_string();
            let firmware_path = parent_dir.join(&image_info.bios).display().to_string();
            let kernel_path = parent_dir.join(&image_info.kernel).display().to_string();
            let initrd_path = parent_dir.join(&image_info.initrd).display().to_string();
            let cmdline = image_info.cmdline + " initrd=initrd";
            
            // Machine paths
            let acpi_tables_path = parent_dir.join(&image_info.acpi_tables).display().to_string();
            let rsdp_path = parent_dir.join(&image_info.rsdp).display().to_string();
            let table_loader_path = parent_dir.join(&image_info.table_loader).display().to_string();
            let boot_order_path = parent_dir.join(&image_info.boot_order).display().to_string();
            let boot_0000_path = parent_dir.join(&image_info.boot_0000).display().to_string();
            let boot_0001_path = parent_dir.join(&image_info.boot_0001).display().to_string();
            let boot_0006_path = parent_dir.join(&image_info.boot_0006).display().to_string();
            let boot_0007_path = parent_dir.join(&image_info.boot_0007).display().to_string();

            let machine = Machine::builder()
                .cpu_count(config.cpu)
                .memory_size(config.memory)
                .qcow2(&qcow2_path)
                .firmware(&firmware_path)
                .kernel(&kernel_path)
                .initrd(&initrd_path)
                .kernel_cmdline(&cmdline)
                .acpi_tables(&acpi_tables_path)
                .rsdp(&rsdp_path)
                .table_loader(&table_loader_path)
                .boot_order(&boot_order_path)
                .boot_0000(&boot_0000_path)
                .boot_0001(&boot_0001_path)
                .boot_0006(&boot_0006_path)
                .boot_0007(&boot_0007_path)
                .two_pass_add_pages(config.two_pass_add_pages)
                .pic(config.pic)
                .smm(config.smm)
                .maybe_pci_hole64_size(config.pci_hole64_size)
                .hugepages(config.hugepages)
                .num_gpus(config.num_gpus)
                .num_nvswitches(config.num_nvswitches)
                .hotplug_off(config.hotplug_off)
                .root_verity(config.root_verity)
                .build();

            let measurements = if config.platform_only {
                machine.measure_platform().context("Failed to measure platform")?
            } else {
                machine.measure().context("Failed to measure machine configuration")?
            };

            if config.json {
                println!("{}", serde_json::to_string_pretty(&measurements).unwrap());
            } else {
                println!("Machine measurements:");
                println!("MRTD: {}", hex::encode(&measurements.mrtd));
                println!("RTMR0: {}", hex::encode(&measurements.rtmr0));
                println!("RTMR1: {}", hex::encode(&measurements.rtmr1));
                println!("RTMR2: {}", hex::encode(&measurements.rtmr2));
            }

            if let Some(ref json_file) = config.json_file {
                fs::write(json_file, serde_json::to_string_pretty(&measurements).unwrap())
                    .context("Failed to write measurements to file")?;
            }
        }
    }

    Ok(())
}

/// Parse a memory size value that can be decimal or hexadecimal (with 0x prefix)
fn parse_memory_size(s: &str) -> Result<u64> {
    let s = s.trim();

    if s.is_empty() {
        return Err(anyhow!("Empty memory size"));
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        let hex_str = &s[2..];
        return u64::from_str_radix(hex_str, 16)
            .map_err(|e| anyhow!("Invalid hexadecimal value: {}", e));
    }

    if s.chars().all(|c| c.is_ascii_digit()) {
        return Ok(s.parse::<u64>()?);
    }
    let len = s.len();
    let (num_part, suffix) = match s.chars().last().unwrap() {
        'k' | 'K' => (&s[0..len - 1], 1024u64),
        'm' | 'M' => (&s[0..len - 1], 1024u64 * 1024),
        'g' | 'G' => (&s[0..len - 1], 1024u64 * 1024 * 1024),
        't' | 'T' => (&s[0..len - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => return Err(anyhow!("Unknown memory size suffix")),
    };

    let num = num_part.parse::<u64>()?;
    Ok(num * suffix)
}
