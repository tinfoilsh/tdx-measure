# tdx-measure

## Scope
Command-line tool and Rust library to calculate expected measurement of an Intel TDX guest VM for confidential computing.

The `tdx-measure` tool takes a set of image binaries and platform config files as an input and outputs the corresponding TDX measurements. This makes it possible to exhaustively publish all images and config files that uniquely identify a TDX workload on a machine, making TD environments transparent and auditable.

The tool specifically targets the boot chains from the Canonical TDX [repo](https://github.com/canonical/tdx).

### Acknowledgment
This project is a fork of dstack-mr from the [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) repository.

## Usage

```tdx-measure [OPTIONS] <METADATA>```

### Arguments:
  `<METADATA>` Path to metadata json file (see format lower down)

### Options
```
      --two-pass-add-pages         Enable two-pass add pages
      --direct-boot <DIRECT_BOOT>  Enable direct boot (overrides JSON configuration) [possible values: true, false]
      --json                       Output JSON
      --json-file <JSON_FILE>      Output JSON to file
      --platform-only              Compute MRTD and RTMR0 only
      --runtime-only               Compute RTMR1 and RTMR2 only
      --transcript <TRANSCRIPT>    Generate a human-readable transcript of all metadata files and write to the specified file
  -h, --help                       Print help
  -V, --version                    Print version
```

WARNING: when running with `--runtime-only`, the tool will assume a VM memory size higher that 2.75GB.

### Required Binaries

To correctly compute measurements, `tdx-measure` requires a set of binaries that correspond the platform/firmware configuration or to the image that is executed.

The required binaries and their locations are provided to the tool using a metadata JSON file (see details under).

#### Extracting Useful Binaries

Platform configuration files can be extracted by running the [`extract_boot_vars.py`](extract_boot_vars.py) script inside a TD guest configured identically on the target platform.

These files follow standard formats that can easily be audited (for instance, ACPI tables can be disassembled). Building tool to programmatically generate these files is future work.

#### Transcript

The transcript flag makes it possible to generate a human-readable transcript from the different binary configuration files. The command line tool `iasl` needs to be installed in order to disassembled the ACPI tables and include its representation in the transcript.

#### Direct Boot Metadata

```
{
  "boot_config": {
    "cpus": 32,
    "memory": "10G",
    "bios": "OVMF.fd",
    "acpi_tables": "acpi_tables.bin",
    "rsdp": "rsdp.bin",
    "table_loader": "table_loader.bin",
    "boot_order": "BootOrder.bin",
    "path_boot_xxxx": [path for Bootxxxx.bin variables],
  },
  "direct": {
    "kernel": "vmlinuz",
    "initrd": "initrd",
    "cmdline": "console=ttyS0 root=/dev/vda1"
  }
}
```

#### Indirect Boot Metadata

```
{
  "boot_config": {
    "cpus": 32,
    "memory": "10G",
    "bios": "OVMF.fd",
    "acpi_tables": "acpi_tables.bin",
    "rsdp": "rsdp.bin",
    "table_loader": "table_loader.bin",
    "boot_order": "BootOrder.bin",
    "path_boot_xxxx": [path for Bootxxxx.bin variables],
  },
  "indirect": {
    "qcow2": "tdx-guest-ubuntu-24.04-generic.qcow2",
    "cmdline": "console=ttyS0 root=/dev/vda1",
    "mok_list": "MokList.bin",
    "mok_list_trusted": "MokListTrusted.bin",
    "mok_list_x": "MokListX.bin",
    "sbat_level": "SbatLevel.bin"
  }
}
```
## Build

```
# Build the project
cargo build --release

# Install the CLI tool
cargo install --path cli
```

### Prerequisite

Install Rust if not already installed

## Info

### Boot Methods
Canonical repo offer two boot options:

1) Direct Boot:
With this method, `OVMF` (the TDVF or virtual firmware) directly boots the kernel image. In this mode, the `kernel`, `initrd` and the kernel `cmdline` are directly supplied to `qemu`.

2) Indirect Boot:
With this method, `tdvirsh` is used to run TDs, the boot chain is more complex and involves `OVMF`, a `SHIM`, `Grub`, and finally the `kernel`+`initrd` image.

### What goes in the measurements

TDX attestation reports expose 4 measurement registers (MR).

The first one, `MRTD`, represent the measurements for the TD virtual firmware binary (TDVF, specifically OVMF.fd in our case).

Three other runtime measurement registers (`RTMR`) correspond to different boot stages and vary depending on the boot chain. 

`RTMR[0]` contains firmware configuration and platform specific measurements. This includes hashes of:
- The TD HOB which mostly contains a description of the memory accessible to the TD.
- TDX configuration values.
- Various Secure Boot variables.
- ACPI tables that describe the device tree.
- Boot variables (BootOrder and others).
- [for indirect boot only] [SbatLevel](https://github.com/rhboot/shim/blob/main/SbatLevel_Variable.txt) variable.

`RTMR[1]` contains measurements of the `kernel` for direct boot. For indirect boot, it contains measurement for the bootchain a.k.a. `gpt` (GUID Partition Table), `shim`, and `grub`.

`RTMR[2]` contains measurements of the kernel `cmdline` and `initrd` for direct boot. For indirect boot, it also contains the measurements of machine owner key [(MOK) vairables](https://github.com/rhboot/shim/blob/main/MokVars.txt).

