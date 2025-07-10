use anyhow::{Context, Result, anyhow};
use clap::Parser;
use tdx_measure::{Machine, ImageConfig};
use fs_err as fs;
use std::path::{Path, PathBuf};

mod transcript;
use transcript::generate_transcript;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
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
    two_pass_add_pages: bool,

    /// Enable direct boot (overrides JSON configuration)
    #[arg(long)]
    direct_boot: Option<bool>,

    /// Output JSON
    #[arg(long)]
    json: bool,

    /// Output JSON to file
    #[arg(long)]
    json_file: Option<PathBuf>,

    /// Compute MRTD and RTMR0 only
    #[arg(long)]
    platform_only: bool,

    /// Generate a human-readable transcript of all metadata files and write to the specified file
    #[arg(long)]
    transcript: Option<PathBuf>,
}

/// Helper struct to resolve and store file paths
pub struct PathResolver {
    pub paths: PathStorage,
}

pub struct PathStorage {
    pub firmware: String,
    pub cmdline: String,
    pub acpi_tables: String,
    pub rsdp: String,
    pub table_loader: String,
    pub boot_order: String,
    pub boot_0000: String,
    pub boot_0001: String,
    pub boot_0006: String,
    pub boot_0007: String,
    // Direct boot specific
    pub kernel: Option<String>,
    pub initrd: Option<String>,
    // Indirect boot specific
    pub qcow2: Option<String>,
    pub mok_list: Option<String>,
    pub mok_list_trusted: Option<String>,
    pub mok_list_x: Option<String>,
    pub sbat_level: Option<String>,
}

impl PathResolver {
    pub fn new(metadata_path: &Path, image_config: &ImageConfig) -> Result<Self> {
        let parent_dir = metadata_path.parent().unwrap_or(".".as_ref());
        let boot_info = &image_config.boot_info;
        
        let paths = PathStorage {
            firmware: parent_dir.join(&boot_info.bios).display().to_string(),
            cmdline: image_config.cmdline().to_string(),
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
    
    fn build_machine(&self, config: &Cli, direct_boot: bool) -> Machine {
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
            .direct_boot(direct_boot)
            .build()
    }
}

fn process_measurements(config: &Cli, image_config: &ImageConfig) -> Result<()> {
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

fn output_measurements(config: &Cli, measurements: &tdx_measure::TdxMeasurements) -> Result<()> {
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
    let metadata = fs::read_to_string(&cli.metadata)
        .context("Failed to read image metadata")?;
    let image_config: ImageConfig = serde_json::from_str(&metadata)
        .context("Failed to parse image metadata")?;
    
    // Handle transcript mode
    if let Some(ref transcript_file) = cli.transcript {
        return generate_transcript(transcript_file, &image_config, &cli.metadata);
    }
    
    process_measurements(&cli, &image_config)?;

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