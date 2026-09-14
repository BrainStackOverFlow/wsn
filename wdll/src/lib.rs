#![cfg_attr(not(feature = "std"), no_std)]

use core::arch::asm;
use core::mem::offset_of;
use core::ptr::{addr_of, read_unaligned};
use thiserror::Error;
use widestring::{utf16str, Utf16Str};

const DLL__FULL_NAME__NTDLL_: &Utf16Str = utf16str!(r"C:\WINDOWS\SYSTEM32\ntdll.dll");

#[repr(C)]
struct RawUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct RawListEntry {
    flink: *const RawListEntry,
    blink: *const RawListEntry,
}

unsafe trait ContainsRawListEntry {
    const RAW_LIST_ENTRY_OFFSET: usize;
}

#[repr(C)]
struct RawTypedListEntry<T: ContainsRawListEntry> {
    untyped: RawListEntry,
    _marker: core::marker::PhantomData<T>,
}

impl<T: ContainsRawListEntry> RawTypedListEntry<T> {
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn get_typed_ptr(&self) -> *const T {
        (self as *const Self as usize).wrapping_sub(T::RAW_LIST_ENTRY_OFFSET) as *const T
    }

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn flink(&self) -> *const Self {
        self.untyped.flink as *const Self
    }

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn blink(&self) -> *const Self {
        self.untyped.blink as *const Self
    }
}

struct RawListIterator<T: ContainsRawListEntry> {
    head: *const RawTypedListEntry<T>,
    current: *const RawTypedListEntry<T>,
}

impl<T: ContainsRawListEntry> RawListIterator<T> {
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn new(head: *const RawTypedListEntry<T>) -> Self {
        Self {
            head,
            current: head,
        }
    }
}
impl<T: ContainsRawListEntry> Iterator for RawListIterator<T> {
    type Item = *const RawTypedListEntry<T>;

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn next(&mut self) -> Option<Self::Item> {
        let current = unsafe { (*self.current).flink() };

        if current == self.head {
            return None;
        }

        self.current = current;

        Some(current)
    }
}
#[repr(C)]
struct RawPeb {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: u8,
    reserved3: [usize; 2],
    ldr: *const RawLdr,
}

impl RawPeb {
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    unsafe fn get_ptr() -> *const Self {
        unsafe { Self::get_peb_usize() as *const Self }
    }

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    #[cfg(all(windows, target_arch = "x86_64"))]
    unsafe fn get_peb_usize() -> usize {
        const PEB_OFFSET: usize = 0x60;

        let peb: usize;

        unsafe {
            asm!(
            "mov {}, gs:[{PEB_OFFSET}]",
            out(reg) peb,
            options(nostack, preserves_flags, readonly),
            PEB_OFFSET = const PEB_OFFSET,
            );
        }

        peb
    }
}

#[repr(C)]
struct RawLdr {
    reserved1: [u8; 8],
    reserved2: [usize; 3],
    in_memory_order_module_list: RawListEntry,
}

#[repr(C)]
struct RawLdrDataTableEntry {
    reserved1: [usize; 2],
    in_memory_order_links: RawListEntry,
    reserved2: [usize; 2],
    dll_base: usize,
    reserved3: [usize; 2],
    full_dll_name: RawUnicodeString,
    reserved4: [u8; 8],
    reserved5: [usize; 3],
}

unsafe impl ContainsRawListEntry for RawLdrDataTableEntry {
    const RAW_LIST_ENTRY_OFFSET: usize = offset_of!(RawLdrDataTableEntry, in_memory_order_links);
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn ntdll() -> usize {
    unsafe {
        let list = addr_of!((*Peb::get().ldr().raw).in_memory_order_module_list) as usize;

        let ldr_data_table_entry =
            read_unaligned(read_unaligned(list as *const usize) as *const usize)
                .wrapping_sub(0x10usize);

        let dll_base_p = read_unaligned(ldr_data_table_entry.wrapping_add(0x030) as *const usize);

        dll_base_p
    }
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn ntdll_fixed_vs_version_info() -> usize {
    unsafe {
        let ntdll_base = ntdll();

        let e_lfanew = read_unaligned(ntdll_base.wrapping_add(0x03c) as *const u32) as usize;

        let nt_headers_p = ntdll_base.wrapping_add(e_lfanew);

        let optional_headers_p = nt_headers_p.wrapping_add(0x018);

        let data_directory = optional_headers_p.wrapping_add(0x70);

        let resource_data_directory = data_directory.wrapping_add(0x10);

        let resource_data_virtual_address =
            read_unaligned(resource_data_directory as *const u32) as usize;

        let image_resource_directory_p = ntdll_base.wrapping_add(resource_data_virtual_address);

        let mut image_resource_directory_entry =
            image_resource_directory_p.wrapping_add(0x10 + 0x10);

        let number_of_named_entries =
            read_unaligned(image_resource_directory_p.wrapping_add(0x0c) as *const u16) as usize;

        let number_of_id_entries =
            read_unaligned(image_resource_directory_p.wrapping_add(0x0e) as *const u16) as usize;

        let number_of_entries = number_of_named_entries + number_of_id_entries;

        let mut image_resource_directory_entry_offset = 0usize;

        let mut i = 0usize;

        while i < number_of_entries {
            let name = read_unaligned(image_resource_directory_entry as *const u32);

            if name & (1u32 << 31) == 0 && (name & 0xffff) == 16 {
                image_resource_directory_entry_offset =
                    (read_unaligned(image_resource_directory_entry.wrapping_add(0x4) as *const u32)
                        & !(1u32 << 31)) as usize;

                break;
            }

            image_resource_directory_entry = image_resource_directory_entry.wrapping_add(0x8);

            i += 1;
        }

        let name_dir =
            image_resource_directory_p.wrapping_add(image_resource_directory_entry_offset);

        let name_entry = name_dir.wrapping_add(0x10);

        let name_entry_offset =
            (read_unaligned(name_entry.wrapping_add(0x4) as *const u32) & !(1u32 << 31)) as usize;

        let lang_dir = image_resource_directory_p.wrapping_add(name_entry_offset);

        let lang_entry = lang_dir.wrapping_add(0x10);

        let data_entry_offset =
            (read_unaligned(lang_entry.wrapping_add(0x4) as *const u32) & !(1u32 << 31)) as usize;

        let data_entry = image_resource_directory_p.wrapping_add(data_entry_offset);

        let version_rva = read_unaligned(data_entry as *const u32) as usize;

        let vs_version_info = ntdll_base.wrapping_add(version_rva);

        vs_version_info
    }
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn ntdll_fixed_file_info() -> usize {
    let vs_version_info = unsafe { ntdll_fixed_vs_version_info() };

    vs_version_info.wrapping_add(0x28)
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn ntdll_build() -> u16 {
    unsafe {
        let fixed_file_info = ntdll_fixed_file_info();

        let file_version_ls = read_unaligned(fixed_file_info.wrapping_add(12) as *const u32);
        let build = (file_version_ls >> 16) & 0xffff;

        build as u16
    }
}

#[derive(Error, Debug)]
#[error("WDLLError")]
pub struct WDLLError {
    kind: WDLLErrorKind,
    #[cfg(feature = "std")]
    backtrace: std::backtrace::Backtrace,
}

impl WDLLError {
    #[inline]
    #[track_caller]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn new(kind: WDLLErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "std")]
            backtrace: std::backtrace::Backtrace::capture(),
        }
    }
}

#[derive(Debug)]
enum WDLLErrorKind {
    NoNtdllInLdr,
}

pub struct Peb {
    raw: *const RawPeb,
}

impl Peb {
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub fn get() -> Self {
        Peb {
            raw: unsafe { RawPeb::get_ptr() },
        }
    }

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub fn ldr(self) -> Ldr {
        Ldr {
            raw: unsafe { (*self.raw).ldr },
        }
    }
}

pub struct Ldr {
    raw: *const RawLdr,
}

impl Ldr {
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub fn iter_entries(&self) -> impl Iterator<Item = LdrEntry> {
        LdrEntryIter {
            raw: RawListIterator::new(unsafe {
                &(*self.raw).in_memory_order_module_list as *const RawListEntry
                    as *const RawTypedListEntry<RawLdrDataTableEntry>
            }),
        }
    }
}

struct LdrEntryIter {
    raw: RawListIterator<RawLdrDataTableEntry>,
}

impl Iterator for LdrEntryIter {
    type Item = LdrEntry;

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn next(&mut self) -> Option<Self::Item> {
        self.raw.next().map(|raw_list_entry| LdrEntry {
            raw: unsafe { (*raw_list_entry).get_typed_ptr() },
        })
    }
}

pub struct LdrEntry {
    raw: *const RawLdrDataTableEntry,
}

impl LdrEntry {
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub fn dll(&self) -> InMemoryDll {
        InMemoryDll {
            base: unsafe { (*self.raw).dll_base },
        }
    }

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub fn name(&self) -> &Utf16Str {
        unsafe {
            let full_dll_name = &(*self.raw).full_dll_name;
            let slice = core::slice::from_raw_parts(
                full_dll_name.buffer,
                (full_dll_name.length / 2) as usize,
            );
            Utf16Str::from_slice_unchecked(slice)
        }
    }
}

pub struct InMemoryDll {
    base: usize,
}

impl InMemoryDll {
    pub fn get_loaded_dll_by_full_name(name: &Utf16Str) -> Result<InMemoryDll, WDLLError> {
        for ldr_entry in Peb::get().ldr().iter_entries() {
            if ldr_entry.name() == name {
                return Ok(ldr_entry.dll())
            }
        }

        Err(WDLLError::new(WDLLErrorKind::NoNtdllInLdr))
    }

    pub fn get_loaded_ntdll() -> Result<InMemoryDll, WDLLError> {
        Self::get_loaded_dll_by_full_name(DLL__FULL_NAME__NTDLL_)
    }
}
