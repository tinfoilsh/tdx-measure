# tdx-measure

## Scope
Command-line tool and Rust library to calculate expected measurement of an Intel TDX guest VM for confidential computing.

`tdx-measure` takes a set of binaries and platform config files as an input and outputs the corresponding TDX measurements.

This tool supports the boot chains from the official Canonical TDX [repo](https://github.com/canonical/tdx).

### Acknowledgment
This project is a fork of dstack-mr from the [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) repository.

## Usage

```tdx-measure [OPTIONS] <METADATA>```

### Arguments:
  `<METADATA>` Path to metadata json file (see format lower down)

### Options
```
  -c, --cpu <CPU>                  Number of CPUs [default: 1]
  -m, --memory <MEMORY>            Memory size in bytes [default: 2G]
      --two-pass-add-pages         Enable two-pass add pages
      --direct-boot <BOOL>         Use direct/indirect boot method [true, false]
      --json                       Output JSON
      --json-file <JSON_FILE>      Output JSON to file
      --platform-only              Compute MRTD and RTMR0 only
  -h, --help                       Print help
  -V, --version                    Print version
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

## Extracting Useful Binaries

For now, most of the configuration files required to obtain the TDX measurements need to be extracted from a TD guest running on the same machine and configured identically. However, these files are all in standard formats  that can easily be audited (for instance, ACPI tables can be disassembled). Building tool to programmatically generate these files is future work.

All necessary files can be extracted by running the [`extract_boot_vars.py`](extract_boot_vars.py) script inside a TD guest on the target platform.

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

## Metadata Formats

Metadata file should be in `json` format and indicates to `tdx-measure` where to find the required binaries and configuration files to compute the measurements. There is two different formats depending on the boot method.

#### Direct Boot

```
{
  "boot_info": {
    "bios": "OVMF.fd",
    "acpi_tables": "acpi_tables.bin",
    "rsdp": "rsdp.bin",
    "table_loader": "table_loader.bin",
    "boot_order": "BootOrder.bin",
    "boot_0000": "Boot0000.bin",
    "boot_0001": "Boot0001.bin",
    "boot_0006": "Boot0006.bin",
    "boot_0007": "Boot0007.bin"
  },
  "direct": {
    "kernel": "vmlinuz",
    "initrd": "initrd",
    "cmdline": "console=ttyS0 root=/dev/vda1"
  }
}
```

#### Indirect Boot

```
{
  "boot_info": {
    "bios": "OVMF.fd",
    "acpi_tables": "acpi_tables.bin",
    "rsdp": "rsdp.bin",
    "table_loader": "table_loader.bin",
    "boot_order": "BootOrder.bin",
    "boot_0000": "Boot0000.bin",
    "boot_0001": "Boot0001.bin",
    "boot_0006": "Boot0006.bin",
    "boot_0007": "Boot0007.bin"
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