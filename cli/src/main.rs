use anyhow::{Context, Result, anyhow};
use clap::Parser;
use tdx_measure::{Machine, ImageConfig};
use fs_err as fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to metadata json file
    metadata: PathBuf,

    /// Enable two-pass add pages
    #[arg(long)]
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

    /// Compute RTMR1 and RTMR2 only
    #[arg(long)]
    runtime_only: bool,
}

/// Helper struct to resolve and store file paths
struct PathResolver {
    paths: PathStorage,
}

struct PathStorage {    
    cpu_count: u8,
    memory_size: u64,
    firmware: String,
    cmdline: String,
    acpi_tables: String,
    rsdp: String,
    table_loader: String,
    boot_order: String,
    path_boot_xxxx: String,
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
    fn new(metadata_path: &Path, image_config: &ImageConfig, require_boot_config: bool) -> Result<Self> {
        let parent_dir = metadata_path.parent().unwrap_or(".".as_ref());
        
        // Handle optional boot_config
        let paths = if let Some(boot_config) = &image_config.boot_config {
            PathStorage {
                cpu_count: boot_config.cpus,
                memory_size: image_config.memory_size()?,
                firmware: parent_dir.join(&boot_config.bios).display().to_string(),
                cmdline: image_config.cmdline().to_string(),
                acpi_tables: parent_dir.join(&boot_config.acpi_tables).display().to_string(),
                rsdp: parent_dir.join(&boot_config.rsdp).display().to_string(),
                table_loader: parent_dir.join(&boot_config.table_loader).display().to_string(),
                boot_order: parent_dir.join(&boot_config.boot_order).display().to_string(),
                path_boot_xxxx: parent_dir.join(&boot_config.path_boot_xxxx).display().to_string(),
                kernel: image_config.direct_boot().map(|d| parent_dir.join(&d.kernel).display().to_string()),
                initrd: image_config.direct_boot().map(|d| parent_dir.join(&d.initrd).display().to_string()),
                qcow2: image_config.indirect_boot().map(|i| parent_dir.join(&i.qcow2).display().to_string()),
                mok_list: image_config.indirect_boot().map(|i| parent_dir.join(&i.mok_list).display().to_string()),
                mok_list_trusted: image_config.indirect_boot().map(|i| parent_dir.join(&i.mok_list_trusted).display().to_string()),
                mok_list_x: image_config.indirect_boot().map(|i| parent_dir.join(&i.mok_list_x).display().to_string()),
                sbat_level: image_config.indirect_boot().map(|i| parent_dir.join(&i.sbat_level).display().to_string()),
            }
        } else {
            // When boot_config is None (runtime-only mode), provide empty strings for platform fields
            if require_boot_config {
                return Err(anyhow!("Boot info is required but not provided in the configuration"));
            }
            PathStorage {
                cpu_count: 0,
                memory_size: 0,
                firmware: String::new(),
                cmdline: image_config.cmdline().to_string(),
                acpi_tables: String::new(),
                rsdp: String::new(),
                table_loader: String::new(),
                boot_order: String::new(),
                path_boot_xxxx: String::new(),
                kernel: image_config.direct_boot().map(|d| parent_dir.join(&d.kernel).display().to_string()),
                initrd: image_config.direct_boot().map(|d| parent_dir.join(&d.initrd).display().to_string()),
                qcow2: image_config.indirect_boot().map(|i| parent_dir.join(&i.qcow2).display().to_string()),
                mok_list: image_config.indirect_boot().map(|i| parent_dir.join(&i.mok_list).display().to_string()),
                mok_list_trusted: image_config.indirect_boot().map(|i| parent_dir.join(&i.mok_list_trusted).display().to_string()),
                mok_list_x: image_config.indirect_boot().map(|i| parent_dir.join(&i.mok_list_x).display().to_string()),
                sbat_level: image_config.indirect_boot().map(|i| parent_dir.join(&i.sbat_level).display().to_string()),
            }
        };
        
        Ok(Self { paths })
    }
    
    fn build_machine(&self, config: &Cli, direct_boot: bool) -> Machine {
        Machine::builder()
            .cpu_count(self.paths.cpu_count)
            .memory_size(self.paths.memory_size)
            .firmware(&self.paths.firmware)
            .kernel_cmdline(&self.paths.cmdline)
            .acpi_tables(&self.paths.acpi_tables)
            .rsdp(&self.paths.rsdp)
            .table_loader(&self.paths.table_loader)
            .boot_order(&self.paths.boot_order)
            .path_boot_xxxx(&self.paths.path_boot_xxxx)
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

    let mut direct_boot = true; // Direct boot by default
    if !config.platform_only { // If platform only, skip boot mode validation
        // Determine boot mode: CLI flag overrides JSON configuration
        direct_boot = config.direct_boot.unwrap_or(image_config.is_direct_boot());
        
        // Validate boot mode configuration
        match (direct_boot, image_config.direct_boot(), image_config.indirect_boot()) {
            (true, None, _) => return Err(anyhow!("Direct boot mode specified but no direct boot configuration found in JSON")),
            (false, _, None) => return Err(anyhow!("Indirect boot mode specified but no indirect boot configuration found in JSON")),
            _ => {}
        }
    }
    
    // Build machine
    let path_resolver = PathResolver::new(&config.metadata, image_config, !config.runtime_only)?;
    let machine = path_resolver.build_machine(config, direct_boot);
    
    // Measure
    let measurements = if config.platform_only {
        machine.measure_platform().context("Failed to measure platform")?
    } else if config.runtime_only {
        machine.measure_runtime().context("Failed to measure runtime")?
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
    
    process_measurements(&cli, &image_config)?;

    Ok(())
}