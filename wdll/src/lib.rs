#![no_std]

use core::arch::asm;
use core::ptr::read_unaligned;

#[cfg(all(windows, target_arch = "x86_64"))]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn peb() -> usize {
    let peb: usize;

    unsafe {
        asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags, readonly),
        );
    }

    peb
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn ldr() -> usize {
    #[cfg(all(windows, target_arch = "x86_64"))]
    const PEB_LDR_OFFSET: usize = 0x18;

    unsafe { read_unaligned(peb().wrapping_add(PEB_LDR_OFFSET) as *const usize) }
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn in_memory_order_module_list() -> usize {
    #[cfg(all(windows, target_arch = "x86_64"))]
    const LDR_IN_MEMORY_ORDER_MODULE_LIST_OFFSET: usize = 0x20;

    unsafe { ldr().wrapping_add(LDR_IN_MEMORY_ORDER_MODULE_LIST_OFFSET) }
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
unsafe fn ntdll() -> usize {
    unsafe {
        let list = in_memory_order_module_list();

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
