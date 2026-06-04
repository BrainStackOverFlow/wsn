use anyhow::{bail, Context, Result};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

const MISSING_SYSCALL: u16 = u16::MAX;

#[derive(Debug, Clone)]
struct CsvEntry {
    service_name: String,
    number: u16,
}

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);

    let csv_dir = manifest_dir
        .join("syscall_csvs");

    println!("cargo:rerun-if-changed={}", csv_dir.display());

    let input = read_csv_dir(&csv_dir)
        .with_context(|| format!("failed to read CSV dir {}", csv_dir.display()))?;

    if input.is_empty() {
        bail!("no CSV files found in {}", csv_dir.display());
    }

    for path in input.keys() {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let generated = generate(input)?;

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let out_path = out_dir.join("generated.rs");

    write_generated(&out_path, generated)
        .with_context(|| format!("failed to write {}", out_path.display()))?;

    Ok(())
}

fn read_csv_dir(dir: &Path) -> Result<BTreeMap<PathBuf, Vec<CsvEntry>>> {
    let mut result = BTreeMap::new();

    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        if path.extension().and_then(|s| s.to_str()) != Some("csv") {
            continue;
        }

        let entries =
            read_one_csv(&path).with_context(|| format!("failed to read {}", path.display()))?;

        result.insert(path, entries);
    }

    Ok(result)
}

fn read_one_csv(path: &Path) -> Result<Vec<CsvEntry>> {
    let mut reader = csv::Reader::from_path(path)?;

    let headers = reader.headers()?.clone();

    let service_name_idx = headers
        .iter()
        .position(|h| h == "SyscallName")
        .context("missing SyscallName column")?;

    let number_idx = headers
        .iter()
        .position(|h| h == "Number")
        .context("missing Number column")?;

    let mut entries = Vec::new();

    for record in reader.records() {
        let record = record?;

        let service_name = record
            .get(service_name_idx)
            .context("missing SyscallName value")?
            .trim()
            .to_owned();

        let number: u16 = record
            .get(number_idx)
            .context("missing Number value")?
            .trim()
            .parse()
            .with_context(|| format!("bad syscall number for {service_name}"))?;

        if number == MISSING_SYSCALL {
            bail!(
                "{} uses reserved missing sentinel value {}",
                service_name,
                MISSING_SYSCALL
            );
        }

        entries.push(CsvEntry {
            service_name,
            number,
        });
    }

    Ok(entries)
}

fn generate(input: BTreeMap<PathBuf, Vec<CsvEntry>>) -> Result<TokenStream> {
    let mut builds: BTreeMap<u32, Vec<CsvEntry>> = BTreeMap::new();
    let mut syscall_names = BTreeSet::<String>::new();

    for (path, entries) in input {
        let build = build_from_filename(&path)?;

        for entry in &entries {
            validate_rust_enum_variant(&entry.service_name)?;
            syscall_names.insert(entry.service_name.clone());
        }

        if builds.insert(build, entries).is_some() {
            bail!("duplicate CSV for build {}", build);
        }
    }

    if syscall_names.len() > u16::MAX as usize {
        bail!(
            "too many syscalls: {} exceeds u16::MAX",
            syscall_names.len()
        );
    }

    if builds.len() > u8::MAX as usize + 1 {
        bail!(
            "too many builds: {} exceeds u8 addressable variants",
            builds.len()
        );
    }

    let syscall_names: Vec<String> = syscall_names.into_iter().collect();
    let syscall_count = syscall_names.len();

    let syscall_id_by_name: BTreeMap<String, usize> = syscall_names
        .iter()
        .enumerate()
        .map(|(idx, name)| (name.clone(), idx))
        .collect();

    let syscall_variants: Vec<_> = syscall_names
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            let ident = format_ident!("{}", name);
            let idx = idx as u16;

            quote! {
                #ident = #idx
            }
        })
        .collect();

    let syscall_name_values: Vec<_> = syscall_names
        .iter()
        .map(|name| {
            quote! {
                #name
            }
        })
        .collect();

    // Sort by generated enum variant name:
    //
    //   V10240, V19041, V22000, ...
    //
    // The WindowsBuild discriminants and BUILD_TO_SYSCALL_TABLES order must match.
    let mut sorted_builds: Vec<(String, u32, Vec<CsvEntry>)> = builds
        .into_iter()
        .map(|(build, entries)| (format!("V{build}"), build, entries))
        .collect();

    sorted_builds.sort_by(|a, b| a.0.cmp(&b.0));

    let builds_count = sorted_builds.len();

    let mut build_variants = Vec::new();
    let mut table_statics = Vec::new();
    let mut build_to_table_values = Vec::new();
    let mut build_name_values = Vec::new();
    let mut windows_build_table_values = Vec::new();

    for (build_index, (build_variant_name, build, entries)) in sorted_builds.iter().enumerate() {
        let build_variant = format_ident!("{}", build_variant_name);
        let table_ident = format_ident!("TABLE_V{}", build);
        let build_index = build_index as u8;
        let build_name = build.to_string();
        let build_u16 = u16::try_from(*build)
            .with_context(|| format!("build number {build} exceeds u16::MAX"))?;

        build_variants.push(quote! {
            #build_variant = #build_index
        });

        build_name_values.push(quote! {
            #build_name
        });

        windows_build_table_values.push(quote! {
            (#build_u16, WindowsBuild::#build_variant)
        });

        let mut table = vec![MISSING_SYSCALL; syscall_count];

        for entry in entries {
            let idx = syscall_id_by_name
                .get(&entry.service_name)
                .copied()
                .with_context(|| {
                    format!("internal error: unknown syscall {}", entry.service_name)
                })?;

            table[idx] = entry.number;
        }

        let table_values = table.iter().map(|value| {
            quote! {
                #value
            }
        });

        table_statics.push(quote! {
            pub const #table_ident: [u16; SYSCALL_COUNT] = [
                #(#table_values),*
            ];
        });

        build_to_table_values.push(quote! {
            &#table_ident
        });
    }

    let expanded = quote! {
        pub const MISSING_SYSCALL: u16 = u16::MAX;

        pub const SYSCALL_COUNT: usize = #syscall_count;

        pub const BUILDS_COUNT: usize = #builds_count;

        pub const BUILD_NAMES: [&str; BUILDS_COUNT] = [
            #(#build_name_values),*
        ];

        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[repr(u8)]
        pub enum WindowsBuild {
            #(#build_variants),*
        }

        pub const BUILD_NUMBERS: [(u16, WindowsBuild); BUILDS_COUNT] = [
            #(#windows_build_table_values),*
        ];

        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[repr(u16)]
        pub enum Syscall {
            #(#syscall_variants),*
        }

        pub const SYSCALL_NAMES: [&str; SYSCALL_COUNT] = [
            #(#syscall_name_values),*
        ];

        #(#table_statics)*

        pub const BUILD_TO_SYSCALL_TABLES: [&[u16; SYSCALL_COUNT]; BUILDS_COUNT] = [
            #(#build_to_table_values),*
        ];
    };

    Ok(expanded)
}

fn build_from_filename(path: &Path) -> Result<u32> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .with_context(|| format!("bad CSV filename {}", path.display()))?;

    let build: u32 = stem
        .parse()
        .with_context(|| format!("CSV filename must be <build>.csv, got {}", path.display()))?;

    Ok(build)
}

fn validate_rust_enum_variant(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("empty syscall name");
    }

    let mut chars = name.chars();

    let first = chars.next().unwrap();

    if !(first == '_' || first.is_ascii_alphabetic()) {
        bail!("syscall name is not a valid Rust enum variant: {name}");
    }

    for ch in chars {
        if !(ch == '_' || ch.is_ascii_alphanumeric()) {
            bail!("syscall name is not a valid Rust enum variant: {name}");
        }
    }

    Ok(())
}

fn write_generated(path: &Path, tokens: TokenStream) -> Result<()> {
    let syntax_tree = syn::parse2::<syn::File>(tokens)?;
    let formatted = prettyplease::unparse(&syntax_tree);

    fs::write(path, formatted)?;

    Ok(())
}