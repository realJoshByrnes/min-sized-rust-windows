#![no_std]
#![no_main]
#![windows_subsystem = "console"]

use core::arch::naked_asm;
use core::panic::PanicInfo;

// Blow up if we try to compile without msvc, x64 arch, or windows.
#[cfg(not(all(target_env = "msvc", target_arch = "x86_64", target_os = "windows")))]
compile_error!("Platform not supported!");

macro_rules! buf {
  () => {
    "Hello World!"
  };
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn mainCRTStartup() -> u32 {
  naked_asm!(
    // Locate PEB once (r10) and use it for both resolution and syscall args
    "mov r10, gs:[0x60]",       // PEB -> r10

    // --- Resolution Logic ---
    // Start with PEB from r10
    "mov rax, [r10 + 0x18]",    // PEB->Ldr
    "mov rax, [rax + 0x10]",    // Ldr->InLoadOrderModuleList.Flink (Exe)
    "mov rax, [rax]",           // Link->Flink (Ntdll)
    "mov rax, [rax + 0x30]",    // DllBase (= ntdll_base) -> r15
    "mov r15, rax",

    // Parse PE Header to find Export Directory
    "mov ecx, [rax + 0x3C]",    // e_lfanew
    "add rcx, rax",             // PE Header
    "mov ecx, [rcx + 0x88]",    // Export Directory RVA
    "add rcx, rax",             // Export Directory VA (= export_dir) -> rcx

    // rcx = export_dir
    "mov r14d, [rcx + 0x18]",   // NumberOfNames -> r14d
    "mov r13d, [rcx + 0x20]",   // AddressOfNames RVA -> r13d
    "add r13, r15",             // AddressOfNames VA -> r13

    // r12 = AddressOfNameOrdinals RVA
    "mov r12d, [rcx + 0x24]",
    "add r12, r15",             // AddressOfNameOrdinals VA

    // r11 = AddressOfFunctions RVA
    "mov r11d, [rcx + 0x1C]",
    "add r11, r15",             // AddressOfFunctions VA

    "xor ecx, ecx",             // index i = 0

    "2:", // Loop start
    // "cmp r9, r14",
    // "jae 4f", // Not found

    // Get name pointer
    "mov edi, [r13 + rcx * 4]", // Name RVA (u32)
    "add rdi, r15",             // Name VA

    // NtWriteFile is alphabetically the first export in ntdll.dll starting with "NtWr".
    "cmp dword ptr [rdi], 0x7257744E", // 0x7257744E = "NtWr". Works on WinXP - Win11-25H2 (current)
    "jne 3f",

    // Found!
    // Get ordinal table entry (u16)
    "movzx rdx, word ptr [r12 + rcx * 2]", // ordinal

    // Get function RVA (u32) from AddressOfFunctions
    "mov edx, [r11 + rdx * 4]", // function RVA
    "add rdx, r15",             // function VA

    // Extract syscall ID (offset 4)
    "mov eax, [rdx + 4]",

    "jmp 5f",

    "3:", // Next iteration
    "inc ecx",
    "jmp 2b",

    // "4:", // Not found
    // "mov eax, 8",   // Fallback to 0x8 if not found

    "5:", // Done
    // syscall ID is now in eax.
    // Save it because we need to setup stack args
    // We can use r11 or r12 or push it.
    // r15 is also free now.
    // "mov r15, rax",  // OPTIMIZATION: rax is preserved

    // --- NtWriteFile Call ---
    // NtWriteFile (see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile)
    //
    //  num | type             | name          | register | desc
    // -----|------------------|---------------|----------|---------------------
    //    1 | HANDLE           | FileHandle    | r10      |
    //    2 | HANDLE           | Event         | rdx      | unused
    //    3 | PIO_APC_ROUTINE  | ApcRoutine    | r8       | unused
    //    4 | PVOID            | ApcContext    | r9       | unused
    //    5 | PIO_STATUS_BLOCK | IoStatusBlock | rsp+0x28 | unused (required)
    //    6 | PVOID            | Buffer        | rsp+0x30 |
    //    7 | ULONG            | Length        | rsp+0x38 |
    //    8 | PLARGE_INTEGER   | ByteOffset    | rsp+0x40 | should be 0 at time of syscall
    //    9 | PULONG           | Key           | rsp+0x48 | should be 0 at time of syscall
    //

    // arg 1, r10 = NtCurrentTeb()->ProcessParameters->hStdOutput
    // r10 already has PEB address from start!

    // 0x20 is RTL_USER_PROCESS_PARAMETERS offset
    "mov r10, [r10 + 0x20]",
    // 0x28 is hStdOutput offset
    "mov r10, [r10 + 0x28]",

    // arg 2, rdx = 0
    "xor edx, edx",

    // arg 3, r8 = 0
    // "xor r8, r8"

    // arg 4, r9 = 0
    // r9 was used as loop index, so we MUST zero it.
    "xor r9, r9",

    // arg 9, [rsp + 0x48] = 0
    "push rdx",

    // arg 8, [rsp + 0x40] = 0
    // This and Arg 9 will serve as IoStatusBlock
    "push rdx",

    // arg 7, [rsp + 0x38] = Length
    "push {0}",

    // arg 6, [rsp + 0x30] = Buffer
    "call 2f",
    concat!(".ascii \"", buf!(), "\""),
    // new line
    ".byte 0x0a",
    "2:",

    // arg 5, [rsp + 0x28] = IoStatusBlock
    // Overlap Arg 5 (IoStatusBlock pointer) to point to Arg 6 (Buffer Ptr)
    // This overwrites the Buffer Ptr and Length arguments on completion, but saves bytes.
    "push rsp",

    // Allocate shadow space (32 bytes) + alignment padding (8 bytes)
    "sub rsp, 40",

    // Restore Syscall ID to rax
    // "mov rax, r15", // OPTIMIZATION: rax is preserved

    // make syscall
    "syscall",

    // deallocate memory (5 args * 8 + 40 shadow = 80 bytes)
    "add rsp, 80",
    "ret",
    const buf!().len() + 1,
  );
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
  loop {}
}
