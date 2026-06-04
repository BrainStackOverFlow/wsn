#![no_std]

#[cfg(feature = "ntdll")]
mod ntdll;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

use generated::{
    BUILD_NAMES, BUILD_NUMBERS, BUILD_TO_SYSCALL_TABLES, MISSING_SYSCALL, SYSCALL_COUNT,
    SYSCALL_NAMES,
};
pub use generated::{Syscall, WindowsBuild};

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn build_table(build: WindowsBuild) -> &'static [u16; SYSCALL_COUNT] {
    BUILD_TO_SYSCALL_TABLES[build as usize]
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn build_name(build: WindowsBuild) -> &'static str {
    BUILD_NAMES[build as usize]
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn syscall_no(table: &'static [u16; SYSCALL_COUNT], syscall: Syscall) -> Option<u16> {
    let value = table[syscall as usize];

    if value == MISSING_SYSCALL {
        None
    } else {
        Some(value)
    }
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn syscall_name(syscall: Syscall) -> &'static str {
    SYSCALL_NAMES[syscall as usize]
}

#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn build_u16(build: u16) -> Option<WindowsBuild> {
    for (version, windows_build) in BUILD_NUMBERS {
        if build == version {
            return Some(windows_build);
        }
    }

    None
}

#[cfg(feature = "ntdll")]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn build_from_ntdll() -> Option<WindowsBuild> {
    build_u16(ntdll::ntdll_build())
}
