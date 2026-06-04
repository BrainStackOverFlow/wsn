#![no_main]
#![no_std]

use core::arch::asm;
use core::hint::black_box;
use panic_never as _;

use wsn::{build_from_ntdll, build_table, syscall_no, Syscall};

#[unsafe(no_mangle)]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn start() {
    let optional_build = build_from_ntdll();

    let build = match optional_build {
        Some(build) => build,
        None => loop {},
    };

    black_box(build);

    let table = build_table(build);
    let optional_exit_syscall_no = syscall_no(table, Syscall::NtTerminateProcess);

    let exit_syscall_no = match optional_exit_syscall_no {
        Some(exit_syscall_no) => exit_syscall_no,
        None => loop {},
    };

    syscall4(exit_syscall_no as u32, 0, 0,0,0);
}


#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn syscall4(
    ssn: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> usize {
    let mut rax = ssn as usize;

    unsafe {
        asm!(
        "syscall",

        inout("rax") rax,

        in("r10") a1,
        in("rdx") a2,
        in("r8")  a3,
        in("r9")  a4,

        lateout("rcx") _,
        lateout("r11") _,

        options(nostack),
        );
    }

    rax
}
