use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use dstack_mr::{Machine, ImageConfig};
use fs_err as fs;
use std::path::{Path, PathBuf};

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

    /// Path to metadata json file
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

    /// Enable direct boot (overrides JSON configuration)
    #[arg(long)]
    direct_boot: Option<Bool>,

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

/// Helper struct to resolve and store file paths
struct PathResolver {
    paths: PathStorage,
}

struct PathStorage {
    firmware: String,
    cmdline: String,
    acpi_tables: String,
    rsdp: String,
    table_loader: String,
    boot_order: String,
    boot_0000: String,
    boot_0001: String,
    boot_0006: String,
    boot_0007: String,
    // Direct boot specific
    kernel: Option<String>,
    initrd: Option<String>,
    // Indirect boot specific
    qcow2: Option<String>,
    mok_list: Option<String>,
    mok_list_trusted: Option<String>,
    mok_list_x: Option<String>,
    sbat_level: Option<String>,
}

impl PathResolver {
    fn new(metadata_path: &Path, image_config: &ImageConfig) -> Result<Self> {
        let parent_dir = metadata_path.parent().unwrap_or(".".as_ref());
        let boot_info = &image_config.boot_info;
        
        let paths = PathStorage {
            firmware: parent_dir.join(&boot_info.bios).display().to_string(),
            cmdline: format!("{} initrd=initrd", image_config.cmdline()),
            acpi_tables: parent_dir.join(&boot_info.acpi_tables).display().to_string(),
            rsdp: parent_dir.join(&boot_info.rsdp).display().to_string(),
            table_loader: parent_dir.join(&boot_info.table_loader).display().to_string(),
            boot_order: parent_dir.join(&boot_info.boot_order).display().to_string(),
            boot_0000: parent_dir.join(&boot_info.boot_0000).display().to_string(),
            boot_0001: parent_dir.join(&boot_info.boot_0001).display().to_string(),
            boot_0006: parent_dir.join(&boot_info.boot_0006).display().to_string(),
            boot_0007: parent_dir.join(&boot_info.boot_0007).display().to_string(),
            kernel: image_config.direct_boot().map(|d| parent_dir.join(&d.kernel).display().to_string()),
            initrd: image_config.direct_boot().map(|d| parent_dir.join(&d.initrd).display().to_string()),
            qcow2: image_config.indirect_boot().map(|i| parent_dir.join(&i.qcow2).display().to_string()),
            mok_list: image_config.indirect_boot().map(|i| parent_dir.join(&i.mok_list).display().to_string()),
            mok_list_trusted: image_config.indirect_boot().map(|i| parent_dir.join(&i.mok_list_trusted).display().to_string()),
            mok_list_x: image_config.indirect_boot().map(|i| parent_dir.join(&i.mok_list_x).display().to_string()),
            sbat_level: image_config.indirect_boot().map(|i| parent_dir.join(&i.sbat_level).display().to_string()),
        };
        
        Ok(Self { paths })
    }
    
    fn build_machine(&self, config: &MachineConfig, direct_boot: bool) -> Machine {
        Machine::builder()
            .cpu_count(config.cpu)
            .memory_size(config.memory)
            .firmware(&self.paths.firmware)
            .kernel_cmdline(&self.paths.cmdline)
            .acpi_tables(&self.paths.acpi_tables)
            .rsdp(&self.paths.rsdp)
            .table_loader(&self.paths.table_loader)
            .boot_order(&self.paths.boot_order)
            .boot_0000(&self.paths.boot_0000)
            .boot_0001(&self.paths.boot_0001)
            .boot_0006(&self.paths.boot_0006)
            .boot_0007(&self.paths.boot_0007)
            .kernel(self.paths.kernel.as_deref().unwrap_or(""))
            .initrd(self.paths.initrd.as_deref().unwrap_or(""))
            .qcow2(self.paths.qcow2.as_deref().unwrap_or(""))
            .mok_list(self.paths.mok_list.as_deref().unwrap_or(""))
            .mok_list_trusted(self.paths.mok_list_trusted.as_deref().unwrap_or(""))
            .mok_list_x(self.paths.mok_list_x.as_deref().unwrap_or(""))
            .sbat_level(self.paths.sbat_level.as_deref().unwrap_or(""))
            .two_pass_add_pages(config.two_pass_add_pages)
            .pic(config.pic)
            .smm(config.smm)
            .maybe_pci_hole64_size(config.pci_hole64_size)
            .hugepages(config.hugepages)
            .num_gpus(config.num_gpus)
            .num_nvswitches(config.num_nvswitches)
            .hotplug_off(config.hotplug_off)
            .root_verity(config.root_verity)
            .direct_boot(direct_boot)
            .build()
    }
}

fn process_measurements(config: &MachineConfig, image_config: &ImageConfig) -> Result<()> {
    // Validate the configuration
    image_config.validate()
        .map_err(|e| anyhow!("Invalid image configuration: {}", e))?;

    // Determine boot mode: CLI flag overrides JSON configuration
    let direct_boot = config.direct_boot.unwrap_or(image_config.is_direct_boot());
    
    // Validate boot mode configuration
    match (direct_boot, image_config.direct_boot(), image_config.indirect_boot()) {
        (true, None, _) => return Err(anyhow!("Direct boot mode specified but no direct boot configuration found in JSON")),
        (false, _, None) => return Err(anyhow!("Indirect boot mode specified but no indirect boot configuration found in JSON")),
        _ => {}
    }
    
    // Build machine
    let path_resolver = PathResolver::new(&config.metadata, image_config)?;
    let machine = path_resolver.build_machine(config, direct_boot);
    
    // Measure
    let measurements = if config.platform_only {
        machine.measure_platform().context("Failed to measure platform")?
    } else {
        machine.measure().context("Failed to measure machine configuration")?
    };
    
    // Output results
    output_measurements(config, &measurements)?;
    
    Ok(())
}

fn output_measurements(config: &MachineConfig, measurements: &dstack_mr::TdxMeasurements) -> Result<()> {
    let json_output = serde_json::to_string_pretty(measurements).unwrap();
    
    if config.json {
        println!("{}", json_output);
    } else {
        println!("Machine measurements:");
        println!("MRTD: {}", hex::encode(&measurements.mrtd));
        println!("RTMR0: {}", hex::encode(&measurements.rtmr0));
        println!("RTMR1: {}", hex::encode(&measurements.rtmr1));
        println!("RTMR2: {}", hex::encode(&measurements.rtmr2));
    }
    
    if let Some(ref json_file) = config.json_file {
        fs::write(json_file, json_output)
            .context("Failed to write measurements to file")?;
    }
    
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match &cli.command {
        Commands::Measure(config) => {
            let metadata = fs::read_to_string(&config.metadata)
                .context("Failed to read image metadata")?;
            let image_config: ImageConfig = serde_json::from_str(&metadata)
                .context("Failed to parse image metadata")?;
            
            process_measurements(config, &image_config)?;
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
