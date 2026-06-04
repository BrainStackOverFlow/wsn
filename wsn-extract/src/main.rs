use anyhow::{bail, Context, Result};
use clap::Parser;
use goblin::pe::header::COFF_MACHINE_X86_64;
use goblin::pe::PE;
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
};

const VS_FIXEDFILEINFO_SIGNATURE: u32 = 0xFEEF04BD;

#[derive(Debug, Parser)]
#[command()]
struct Args {
    #[arg(long, value_name = "PATH")]
    input: PathBuf,

    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
}

#[derive(Debug)]
struct SyscallEntry {
    name: String,
    number: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let bytes = fs::read(&args.input)
        .with_context(|| format!("failed to read {}", args.input.display()))?;

    let build = extract_build_number_from_version_info(&bytes).with_context(|| {
        format!(
            "failed to extract build number from {}",
            args.input.display()
        )
    })?;

    let pe = PE::parse(&bytes)
        .with_context(|| format!("failed to parse PE file {}", args.input.display()))?;

    if pe.header.coff_header.machine != COFF_MACHINE_X86_64 {
        bail!(
            "expected an x64/AMD64 PE file, got machine type 0x{:04x}",
            pe.header.coff_header.machine
        );
    }

    let mut entries = extract_ntos_syscalls(&pe, &bytes);
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("failed to create {}", args.output_dir.display()))?;

    let output_path = args.output_dir.join(format!("{build}.csv"));

    write_csv(&output_path, &entries)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    Ok(())
}

fn extract_ntos_syscalls(pe: &PE<'_>, bytes: &[u8]) -> Vec<SyscallEntry> {
    let mut entries = Vec::new();

    for export in &pe.exports {
        let Some(export_name) = export.name else {
            continue;
        };

        // NTOS/native syscalls from ntdll are exported as Zw*.
        // Normalize ZwClose -> NtClose.
        if !export_name.starts_with("Zw") {
            continue;
        }

        // Forwarded exports are not syscall stubs.
        if export.reexport.is_some() {
            continue;
        }

        let Some(offset) = export.offset else {
            continue;
        };

        let Some(number) = extract_service_number(bytes, offset) else {
            continue;
        };

        entries.push(SyscallEntry {
            name: format!("Nt{}", &export_name[2..]),
            number,
        });
    }

    entries
}

fn extract_service_number(bytes: &[u8], offset: usize) -> Option<u16> {
    const MAX_STUB_LEN: usize = 32;

    let end = offset.checked_add(MAX_STUB_LEN)?.min(bytes.len());
    let stub = bytes.get(offset..end)?;

    if stub.len() < 5 {
        return None;
    }

    for i in 0..=stub.len() - 5 {
        // x64 ntdll syscall stubs contain:
        //
        //   B8 imm32
        //
        // which is:
        //
        //   mov eax, imm32
        if stub[i] == 0xB8 {
            let imm = u32::from_le_bytes([stub[i + 1], stub[i + 2], stub[i + 3], stub[i + 4]]);

            return u16::try_from(imm).ok();
        }
    }

    None
}

fn write_csv(path: &PathBuf, entries: &[SyscallEntry]) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    writeln!(&mut writer, "SyscallName,Number")?;

    for entry in entries {
        writeln!(writer, "{},{}", entry.name, entry.number)?;
    }

    writer.flush()?;

    Ok(())
}

fn extract_build_number_from_version_info(bytes: &[u8]) -> Result<u32> {
    let signature = VS_FIXEDFILEINFO_SIGNATURE.to_le_bytes();

    for offset in 0..bytes.len().saturating_sub(52) {
        if bytes[offset..offset + 4] != signature {
            continue;
        }

        let struct_version = read_u32(bytes, offset + 4)?;
        let file_version_ms = read_u32(bytes, offset + 8)?;
        let file_version_ls = read_u32(bytes, offset + 12)?;

        if struct_version >> 16 != 1 {
            continue;
        }

        let major = (file_version_ms >> 16) & 0xffff;
        let minor = file_version_ms & 0xffff;
        let build = (file_version_ls >> 16) & 0xffff;

        if major == 0 && minor == 0 {
            continue;
        }

        if build == 0 {
            continue;
        }

        return Ok(build);
    }

    bail!("could not find VS_FIXEDFILEINFO in the input DLL")
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset + 4;

    let slice = bytes
        .get(offset..end)
        .with_context(|| format!("u32 read out of range at offset 0x{offset:x}"))?;

    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}
