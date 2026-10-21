// SPDX-License-Identifier: GPL-2.0-only
//! `xstate` group: the user-visible extended CPU state of Linux 6.18.57 on x86-64: `XCR0` and
//! `CR4.OSXSAVE`/`OSPKE`, the initial state of a task, the registers a system call, a context
//! switch, `fork` and `execve` keep or reset, the `XSAVE` standard-format signal frame
//! (`uc_flags`, `_fpx_sw_bytes`, header, component placement, `PKRU`), `rt_sigreturn`'s restore
//! and every refusal of it, `arch_prctl(ARCH_*_XCOMP_*)` and the `SEGV_PKUERR` fault.
//! Linux 6.18.57: `arch/x86/kernel/fpu/{core,signal,xstate}.c`, `arch/x86/kernel/fpu/xstate.h`,
//! `arch/x86/kernel/{signal,signal_64,process,process_64}.c`, `arch/x86/mm/{fault,pkeys}.c`,
//! `arch/x86/include/asm/{fpu,pkru}.h`, `arch/x86/include/uapi/asm/{sigcontext,ucontext,prctl}.h`.
//!
//! Host requirement, stated honestly: the checks drive AVX-512 F/BW state and `PKRU` from ring 3,
//! so the group runs only on a machine whose CPU has them (here: the AMD Zen 5 workstation, KVM
//! `-cpu host`); on a CPU without them the first instruction raises `SIGILL`. Expected values
//! derived from the machine (`XCR0`, sizes, offsets) come from `CPUID` leaf `0xd` inside the
//! test, so the recorded lines name no number of this host; the numbers themselves are `info`
//! rows. AMX is not part of this group (the CPU has none).
//!
//! Assembly proof (AGENTS.md rule 3) common to every `asm!` below: user mode (CPL 3), no
//! privileged instruction; the program is soft-float, so the compiler never allocates an x87,
//! SSE, AVX or opmask register and no register operand names one; each block states its memory
//! effect. They exist because the instruction under test (`vmovdqu64 zmm`, `kmovq`, `ldmxcsr`,
//! `fld*`, `rdpkru`/`wrpkru`, `xgetbv`) has no safe construct and no intrinsic without enabling
//! the target feature on a soft-float target, which would let the compiler use the very
//! registers whose contents are being checked.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use syscalls::{Errno, Sysno};

use super::proc::{nap, reap_all, sigaction, spawn, wait4};
use super::signal::{KSigaction, SA_RESTORER, restorer};
use super::{T, addr, addr_mut, fn_addr, getpid, mmap, sys};

const SIGUSR1: usize = 10;
const SIGUSR2: usize = 12;
const SIGSEGV: usize = 11;
const SA_SIGINFO: u64 = 4;
const SA_ONSTACK: u64 = 0x0800_0000;

/// `XFEATURE_MASK_USER_SUPPORTED`: x87, SSE, AVX, MPX x2, opmask, ZMM_Hi256, Hi16_ZMM, PKRU,
/// AMX tile config and data, APX.
const USER_SUPPORTED: u64 = 0xe_02ff;
const XFEATURE_FPSSE: u64 = 3;
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// `UC_FP_XSTATE | UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS`.
const UC_FLAGS: u64 = 7;
/// `init_pkru_value` (arch/x86/mm/pkeys.c:121): every key but 0 access-disabled.
const PKRU_INIT: u32 = 0x5555_5554;
/// A `PKRU` the tests set: keys 1 and 2 enabled for writing, the rest as the default.
const PKRU_USER: u32 = 0x5555_5544;
const MXCSR_INIT: u32 = 0x1f80;
const MXCSR_USER: u32 = 0xbfc3;

/// Largest signal-frame snapshot: standard-format size plus magic, with room to spare.
const SNAP_MAX: usize = 4096 + 128;
const ALT_SIZE: usize = 16384;
const REGION_SIZE: usize = 8192;

// ---------------------------------------------------------------------------------------------
// Single-threaded shared cells. The test program has one thread; a signal handler runs on that
// thread synchronously at the `kill` system call, never while main code holds a borrow.

struct Single<T>(UnsafeCell<T>);

// SAFETY: see above: one thread, and handler and main code never overlap a borrow.
unsafe impl<T> Sync for Single<T> {}

impl<T> Single<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: the cell is only reached through this method on the one thread, and `f` never
        // calls back into the same cell (checked by the call sites: each closure is a plain copy
        // or a plain read).
        f(unsafe { &mut *self.0.get() })
    }
}

/// A 64-byte aligned byte array (the alternate signal stack, the snapshot of a frame).
#[repr(C, align(64))]
struct Aligned<const N: usize>([u8; N]);

static SNAP: Single<Aligned<SNAP_MAX>> = Single::new(Aligned([0; SNAP_MAX]));
/// Mapped bytes below the alternate stack.
const ALT_BELOW: usize = 4096;

/// The alternate signal stack with mapped memory below it. The size checks give the stack exactly
/// the frame, and the handler running on it then needs a few bytes more *below* the start of
/// the array: when the array is the first thing of the data segment, those bytes are an unmapped
/// page and the child dies of `SIGSEGV` on Linux and on the candidate alike, which depends on
/// what the rest of the program links before it.
#[repr(C, align(64))]
struct AltArea {
    _below: [u8; ALT_BELOW],
    stack: [u8; ALT_SIZE],
}

static ALT: Single<AltArea> = Single::new(AltArea {
    _below: [0xa5; ALT_BELOW],
    stack: [0xa5; ALT_SIZE],
});
/// Start and end of a mapped 8 KiB region with unmapped memory right behind it (the buffers of the
/// refused and short frames live at its tail).
static REGION: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static MINSIGSTKSZ: AtomicUsize = AtomicUsize::new(0);

/// What the handler saw and recorded (all plain data).
#[derive(Clone, Copy)]
struct Record {
    hits: usize,
    uc_flags: u64,
    fpstate: u64,
    uc: u64,
    sp_at_signal: u64,
    handler_pkru: u32,
    handler_fcw: u16,
    handler_fsw: u16,
    snap_len: usize,
}

static REC: Single<Record> = Single::new(Record {
    hits: 0,
    uc_flags: 0,
    fpstate: 0,
    uc: 0,
    sp_at_signal: 0,
    handler_pkru: 0,
    handler_fcw: 0,
    handler_fsw: 0,
    snap_len: 0,
});
const NESTED_PKRU: u32 = 0x5555_5504;

#[derive(Clone, Copy)]
struct NestedRecord {
    pkru_live: u32,
    pkru_after: u32,
    fpstate: u64,
}

static NESTED_REC: Single<NestedRecord> = Single::new(NestedRecord {
    pkru_live: 0,
    pkru_after: 0,
    fpstate: 0,
});
static NESTED_LIVE: Single<Image> = Single::new(Image::ZERO);
static NESTED_AFTER: Single<Image> = Single::new(Image::ZERO);
static NESTED_SNAP: Single<Aligned<SNAP_MAX>> = Single::new(Aligned([0; SNAP_MAX]));
/// The registers the handler found live (the init state `fpu__clear_user_states` left).
static LIVE: Single<Image> = Single::new(Image::ZERO);

/// Stores the `AT_MINSIGSTKSZ` the kernel gave this process (called from `main`).
pub fn set_minsigstksz(value: usize) {
    MINSIGSTKSZ.store(value, Relaxed);
}

// ---------------------------------------------------------------------------------------------
// Register images.

/// zmm0-31 (2048 bytes), k0-k7 and MXCSR: the AVX-512 state the tests move in and out.
#[repr(C, align(64))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Image {
    zmm: [u8; 2048],
    k: [u64; 8],
    mxcsr: u32,
    pad: [u32; 15],
}

const IMG_K: usize = 2048;
const IMG_MXCSR: usize = 2112;

impl Image {
    const ZERO: Self = Self {
        zmm: [0; 2048],
        k: [0; 8],
        mxcsr: 0,
        pad: [0; 15],
    };

    /// All registers zero, MXCSR at its reset value: the state of a new task.
    const INIT: Self = Self {
        mxcsr: MXCSR_INIT,
        ..Self::ZERO
    };

    /// A deterministic image with no register in its initial state (`splitmix64`).
    fn pattern(seed: u64) -> Self {
        let mut state = seed;
        let mut next = || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31) | 1
        };
        let mut image = Self::ZERO;
        for chunk in image.zmm.as_chunks_mut::<8>().0 {
            *chunk = next().to_le_bytes();
        }
        for k in &mut image.k {
            *k = next();
        }
        image.mxcsr = MXCSR_USER;
        image
    }

    /// The part a `FXRSTOR` alone restores: XMM0-15 and MXCSR; everything else initial.
    fn legacy_only(&self) -> Self {
        let mut out = Self::INIT;
        for i in 0..16 {
            out.zmm[64 * i..64 * i + 16].copy_from_slice(&self.zmm[64 * i..64 * i + 16]);
        }
        out.mxcsr = self.mxcsr;
        out
    }
}

/// `vmovdqu64 zmm0-31`, `kmovq k0-7`, `ldmxcsr`: make `image` the live user state.
///
/// Memory: reads the 2176-byte `image` through the pointer (`readonly`); AVX-512F/BW and MXCSR
/// reserved bits clear (the images used never set one). Flags and stack untouched.
fn load(image: &Image) {
    // SAFETY: as the module proof; `image` is a live, 64-aligned 2176-byte object, every access
    // is inside it.
    unsafe {
        asm!(
            "vmovdqu64 zmm0, zmmword ptr [{p}]",
            "vmovdqu64 zmm1, zmmword ptr [{p} + 64]",
            "vmovdqu64 zmm2, zmmword ptr [{p} + 128]",
            "vmovdqu64 zmm3, zmmword ptr [{p} + 192]",
            "vmovdqu64 zmm4, zmmword ptr [{p} + 256]",
            "vmovdqu64 zmm5, zmmword ptr [{p} + 320]",
            "vmovdqu64 zmm6, zmmword ptr [{p} + 384]",
            "vmovdqu64 zmm7, zmmword ptr [{p} + 448]",
            "vmovdqu64 zmm8, zmmword ptr [{p} + 512]",
            "vmovdqu64 zmm9, zmmword ptr [{p} + 576]",
            "vmovdqu64 zmm10, zmmword ptr [{p} + 640]",
            "vmovdqu64 zmm11, zmmword ptr [{p} + 704]",
            "vmovdqu64 zmm12, zmmword ptr [{p} + 768]",
            "vmovdqu64 zmm13, zmmword ptr [{p} + 832]",
            "vmovdqu64 zmm14, zmmword ptr [{p} + 896]",
            "vmovdqu64 zmm15, zmmword ptr [{p} + 960]",
            "vmovdqu64 zmm16, zmmword ptr [{p} + 1024]",
            "vmovdqu64 zmm17, zmmword ptr [{p} + 1088]",
            "vmovdqu64 zmm18, zmmword ptr [{p} + 1152]",
            "vmovdqu64 zmm19, zmmword ptr [{p} + 1216]",
            "vmovdqu64 zmm20, zmmword ptr [{p} + 1280]",
            "vmovdqu64 zmm21, zmmword ptr [{p} + 1344]",
            "vmovdqu64 zmm22, zmmword ptr [{p} + 1408]",
            "vmovdqu64 zmm23, zmmword ptr [{p} + 1472]",
            "vmovdqu64 zmm24, zmmword ptr [{p} + 1536]",
            "vmovdqu64 zmm25, zmmword ptr [{p} + 1600]",
            "vmovdqu64 zmm26, zmmword ptr [{p} + 1664]",
            "vmovdqu64 zmm27, zmmword ptr [{p} + 1728]",
            "vmovdqu64 zmm28, zmmword ptr [{p} + 1792]",
            "vmovdqu64 zmm29, zmmword ptr [{p} + 1856]",
            "vmovdqu64 zmm30, zmmword ptr [{p} + 1920]",
            "vmovdqu64 zmm31, zmmword ptr [{p} + 1984]",
            "kmovq k0, qword ptr [{p} + 2048]",
            "kmovq k1, qword ptr [{p} + 2056]",
            "kmovq k2, qword ptr [{p} + 2064]",
            "kmovq k3, qword ptr [{p} + 2072]",
            "kmovq k4, qword ptr [{p} + 2080]",
            "kmovq k5, qword ptr [{p} + 2088]",
            "kmovq k6, qword ptr [{p} + 2096]",
            "kmovq k7, qword ptr [{p} + 2104]",
            "ldmxcsr dword ptr [{p} + 2112]",
            p = in(reg) core::ptr::from_ref(image),
            options(nostack, preserves_flags, readonly),
        );
    }
}

/// The inverse of [`load`]: copy the live registers into `image`.
///
/// Memory: writes the 2176-byte `image` (and nothing else).
fn store(image: &mut Image) {
    // SAFETY: as the module proof; `image` is a live, exclusively borrowed, 64-aligned object.
    unsafe {
        asm!(
            "vmovdqu64 zmmword ptr [{p}], zmm0",
            "vmovdqu64 zmmword ptr [{p} + 64], zmm1",
            "vmovdqu64 zmmword ptr [{p} + 128], zmm2",
            "vmovdqu64 zmmword ptr [{p} + 192], zmm3",
            "vmovdqu64 zmmword ptr [{p} + 256], zmm4",
            "vmovdqu64 zmmword ptr [{p} + 320], zmm5",
            "vmovdqu64 zmmword ptr [{p} + 384], zmm6",
            "vmovdqu64 zmmword ptr [{p} + 448], zmm7",
            "vmovdqu64 zmmword ptr [{p} + 512], zmm8",
            "vmovdqu64 zmmword ptr [{p} + 576], zmm9",
            "vmovdqu64 zmmword ptr [{p} + 640], zmm10",
            "vmovdqu64 zmmword ptr [{p} + 704], zmm11",
            "vmovdqu64 zmmword ptr [{p} + 768], zmm12",
            "vmovdqu64 zmmword ptr [{p} + 832], zmm13",
            "vmovdqu64 zmmword ptr [{p} + 896], zmm14",
            "vmovdqu64 zmmword ptr [{p} + 960], zmm15",
            "vmovdqu64 zmmword ptr [{p} + 1024], zmm16",
            "vmovdqu64 zmmword ptr [{p} + 1088], zmm17",
            "vmovdqu64 zmmword ptr [{p} + 1152], zmm18",
            "vmovdqu64 zmmword ptr [{p} + 1216], zmm19",
            "vmovdqu64 zmmword ptr [{p} + 1280], zmm20",
            "vmovdqu64 zmmword ptr [{p} + 1344], zmm21",
            "vmovdqu64 zmmword ptr [{p} + 1408], zmm22",
            "vmovdqu64 zmmword ptr [{p} + 1472], zmm23",
            "vmovdqu64 zmmword ptr [{p} + 1536], zmm24",
            "vmovdqu64 zmmword ptr [{p} + 1600], zmm25",
            "vmovdqu64 zmmword ptr [{p} + 1664], zmm26",
            "vmovdqu64 zmmword ptr [{p} + 1728], zmm27",
            "vmovdqu64 zmmword ptr [{p} + 1792], zmm28",
            "vmovdqu64 zmmword ptr [{p} + 1856], zmm29",
            "vmovdqu64 zmmword ptr [{p} + 1920], zmm30",
            "vmovdqu64 zmmword ptr [{p} + 1984], zmm31",
            "kmovq qword ptr [{p} + 2048], k0",
            "kmovq qword ptr [{p} + 2056], k1",
            "kmovq qword ptr [{p} + 2064], k2",
            "kmovq qword ptr [{p} + 2072], k3",
            "kmovq qword ptr [{p} + 2080], k4",
            "kmovq qword ptr [{p} + 2088], k5",
            "kmovq qword ptr [{p} + 2096], k6",
            "kmovq qword ptr [{p} + 2104], k7",
            "stmxcsr dword ptr [{p} + 2112]",
            p = in(reg) core::ptr::from_mut(image),
            options(nostack, preserves_flags),
        );
    }
}

const _: () = {
    assert!(core::mem::offset_of!(Image, k) == IMG_K);
    assert!(core::mem::offset_of!(Image, mxcsr) == IMG_MXCSR);
    assert!(core::mem::size_of::<Image>() == 2176);
};

/// `fninit; fld1; fldpi`: ST0 = pi, ST1 = 1.0, TOP = 6. No memory.
fn x87_load() {
    // SAFETY: as the module proof; x87 only, no memory, no flags (`fninit` leaves EFLAGS alone).
    unsafe {
        asm!(
            "fninit",
            "fld1",
            "fldpi",
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// `(FCW, FSW)` without changing the stack.
fn x87_control() -> (u16, u16) {
    let (mut fcw, mut fsw) = (0u16, 0u16);
    // SAFETY: as the module proof; two 2-byte stores through valid local pointers.
    unsafe {
        asm!(
            "fnstcw word ptr [{c}]",
            "fnstsw word ptr [{s}]",
            c = in(reg) core::ptr::from_mut(&mut fcw),
            s = in(reg) core::ptr::from_mut(&mut fsw),
            options(nostack, preserves_flags),
        );
    }
    (fcw, fsw)
}

/// Pops ST0 and ST1 as 80-bit values (destroys the x87 stack).
fn x87_pop2() -> ([u8; 10], [u8; 10]) {
    let (mut a, mut b) = ([0u8; 10], [0u8; 10]);
    // SAFETY: as the module proof; two 10-byte stores through valid local pointers.
    unsafe {
        asm!(
            "fstp tbyte ptr [{a}]",
            "fstp tbyte ptr [{b}]",
            a = in(reg) core::ptr::from_mut(&mut a),
            b = in(reg) core::ptr::from_mut(&mut b),
            options(nostack, preserves_flags),
        );
    }
    (a, b)
}

const PI_80: [u8; 10] = [0x35, 0xc2, 0x68, 0x21, 0xa2, 0xda, 0x0f, 0xc9, 0x00, 0x40];
const ONE_80: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f];

fn rdpkru() -> u32 {
    let eax: u32;
    // SAFETY: as the module proof; `RDPKRU` needs `CR4.PKE` (set by the kernel under test) and
    // ECX = 0; it reads the register and writes EAX/EDX only.
    unsafe {
        asm!("rdpkru", in("ecx") 0, out("eax") eax, out("edx") _, options(nomem, nostack, preserves_flags));
    }
    eax
}

fn wrpkru(value: u32) {
    // SAFETY: as the module proof; `WRPKRU` needs ECX = EDX = 0. It changes which of this
    // process's own pages the CPU lets it touch; the values used keep key 0 (every page of this
    // program) accessible.
    unsafe {
        asm!("wrpkru", in("eax") value, in("ecx") 0, in("edx") 0, options(nostack, preserves_flags));
    }
}

fn xgetbv0() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: as the module proof; `XGETBV` needs `CR4.OSXSAVE` (checked by the caller through
    // `CPUID.1:ECX[27]`); reads XCR0 into EDX:EAX.
    unsafe {
        asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    u64::from(hi) << 32 | u64::from(lo)
}

fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: as the module proof; `RDTSC` is allowed in ring 3 (CR4.TSD clear).
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    u64::from(hi) << 32 | u64::from(lo)
}

fn cpuid(leaf: u32, sub: u32) -> [u32; 4] {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    [r.eax, r.ebx, r.ecx, r.edx]
}

// ---------------------------------------------------------------------------------------------
// The machine's layout, from CPUID.

#[derive(Clone, Copy)]
struct Layout {
    /// `XCR0` as `CPUID.(0xd,0).EAX` limited to Linux's user features.
    xcr0: u64,
    /// `CPUID.(0xd,0).EBX`: standard-format size for the enabled features.
    size: usize,
    /// Standard-format offset and size of components 2..=9 (0 when absent).
    off: [usize; 10],
    len: [usize; 10],
}

impl Layout {
    fn read() -> Self {
        let leaf0 = cpuid(0xd, 0);
        let xcr0 = u64::from(leaf0[0]) & USER_SUPPORTED;
        let mut off = [0; 10];
        let mut len = [0; 10];
        for c in 2..10 {
            if xcr0 >> c & 1 == 1 {
                let leaf = cpuid(0xd, c as u32);
                len[c] = leaf[0] as usize;
                off[c] = leaf[1] as usize;
            }
        }
        Self {
            xcr0,
            size: leaf0[1] as usize,
            off,
            len,
        }
    }

    /// `fpu__get_fpstate_size() + frame`: `AT_MINSIGSTKSZ` of `init_sigframe_size`.
    fn minsigstksz(&self) -> usize {
        // sizeof(struct sigframe_ia32) + 15 + (user size + magic2 + sizeof(fregs_state)) + 63,
        // rounded up to 16.
        (4 + 4 + 88 + 624 + 4 + 8 + 15 + (self.size + 4 + 112) + 63 + 15) & !15
    }

    /// `[start, end)` byte ranges of the standard-format area that `XSAVE` writes (legacy area
    /// excluding the reserved bytes, header, enabled components) and the reserved gap.
    fn written(&self, at: usize) -> bool {
        if at < 464 || (512..576).contains(&at) {
            return true;
        }
        if (464..512).contains(&at) {
            return true; // the software-reserved bytes Linux fills
        }
        (2..10).any(|c| self.len[c] != 0 && (self.off[c]..self.off[c] + self.len[c]).contains(&at))
    }
}

fn rd32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn rd64(buf: &[u8], at: usize) -> u64 {
    let mut b = [0; 8];
    b.copy_from_slice(&buf[at..at + 8]);
    u64::from_le_bytes(b)
}

pub fn run() -> bool {
    let mut t = T::new("xstate");
    reap_all();
    let lay = Layout::read();
    // The state of a new process must be sampled before anything else runs.
    initial_state(&mut t);
    configuration(&mut t, &lay);
    arch_prctl_xcomp(&mut t, &lay);
    roundtrips(&mut t);
    switching(&mut t);
    exec_reset(&mut t);
    frame_layout(&mut t, &lay);
    sigreturn_restores(&mut t, &lay);
    sigreturn_partial(&mut t, &lay);
    sigreturn_refused(&mut t, &lay);
    altstack_sizes(&mut t, &lay);
    nested_signal(&mut t, &lay);
    pkru_fault(&mut t);
    pkru_kernel_access(&mut t);
    user_instructions(&mut t, &lay);
    reap_all();
    t.finish()
}

/// `fpstate_init_user`/`restore_fpregs_from_init_fpstate`: a new task starts with the hardware's
/// initial configuration for every component and `PKRU` at `init_pkru_value`.
fn initial_state(t: &mut T) {
    let mut now = Image::ZERO;
    store(&mut now);
    let (fcw, fsw) = x87_control();
    t.holds(
        "initial-zmm-zero",
        now.zmm.iter().all(|&b| b == 0),
        "nonzero",
        "zmm0-31 zero",
    );
    t.eq("initial-opmask-zero", now.k, [0; 8]);
    t.eq("initial-mxcsr", now.mxcsr, MXCSR_INIT);
    t.eq("initial-fcw", fcw, 0x37f);
    t.eq("initial-fsw", fsw, 0);
    t.eq("initial-pkru", rdpkru(), PKRU_INIT);
}

fn configuration(t: &mut T, lay: &Layout) {
    let leaf1 = cpuid(1, 0);
    t.holds(
        "cpuid-osxsave",
        leaf1[2] >> 27 & 1 == 1,
        leaf1[2],
        "CPUID.1:ECX[27] (CR4.OSXSAVE)",
    );
    let xcr0 = xgetbv0();
    t.eq("xcr0-is-the-user-features-of-cpuid", xcr0, lay.xcr0);
    t.holds("xcr0-has-x87-sse-avx", xcr0 & 7 == 7, xcr0, "XCR0 & 7 == 7");
    t.holds(
        "xcr0-has-avx512-and-pkru",
        xcr0 & 0xe0 == 0xe0 && xcr0 >> 9 & 1 == 1,
        xcr0,
        "opmask, ZMM_Hi256, Hi16_ZMM, PKRU",
    );
    let leaf7 = cpuid(7, 0);
    t.holds(
        "cpuid-ospke",
        leaf7[2] >> 3 & 1 == 1 && leaf7[2] >> 4 & 1 == 1,
        leaf7[2],
        "PKU and OSPKE",
    );
    t.eq(
        "auxv-minsigstksz-from-the-xsave-size",
        MINSIGSTKSZ.load(Relaxed),
        lay.minsigstksz(),
    );
    t.info("xcr0", format_args!("{xcr0:#x}"));
    t.info("xsave-size", format_args!("{}", lay.size));
    t.info("minsigstksz", format_args!("{:#x}", lay.minsigstksz()));
    t.info("offsets", format_args!("{:?}", lay.off));
}

fn arch_prctl_xcomp(t: &mut T, lay: &Layout) {
    const GET_SUPP: usize = 0x1021;
    const GET_PERM: usize = 0x1022;
    const REQ_PERM: usize = 0x1023;
    const GET_GUEST_PERM: usize = 0x1024;
    const REQ_GUEST_PERM: usize = 0x1025;
    for (name, option) in [
        ("xcomp-supp", GET_SUPP),
        ("xcomp-perm", GET_PERM),
        ("xcomp-guest-perm", GET_GUEST_PERM),
    ] {
        let mut word = 0u64;
        t.eq(
            name,
            (sys(Sysno::arch_prctl, &[option, addr_mut(&mut word)]), word),
            (Ok(0), lay.xcr0),
        );
    }
    for (name, option) in [
        ("xcomp-supp-efault", GET_SUPP),
        ("xcomp-perm-efault", GET_PERM),
        ("xcomp-guest-perm-efault", GET_GUEST_PERM),
    ] {
        t.eq(
            name,
            sys(Sysno::arch_prctl, &[option, 0]),
            Err(syscalls::Errno::EFAULT),
        );
    }
    // `xstate_request_perm`: idx >= XFEATURE_MAX (20) is EINVAL, a facility that does not exist
    // (every component but AMX tile data) or one the CPU lacks is EOPNOTSUPP.
    for (name, option) in [("req-perm", REQ_PERM), ("req-guest-perm", REQ_GUEST_PERM)] {
        for idx in [0usize, 2, 9, 17, 18, 19] {
            t.eq(
                format_args!("{name}-{idx}"),
                sys(Sysno::arch_prctl, &[option, idx]),
                Err(syscalls::Errno::EOPNOTSUPP),
            );
        }
        for idx in [20usize, 63, 64, usize::MAX] {
            t.eq(
                format_args!("{name}-{idx}"),
                sys(Sysno::arch_prctl, &[option, idx]),
                Err(syscalls::Errno::EINVAL),
            );
        }
    }
}

/// The registers survive a system call, a sleep and a long interval with timer interrupts.
fn roundtrips(t: &mut T) {
    let a = Image::pattern(1);
    load(&a);
    x87_load();
    let _ = getpid();
    let mut now = Image::ZERO;
    store(&mut now);
    let (fcw, fsw) = x87_control();
    let (st0, st1) = x87_pop2();
    t.holds(
        "syscall-keeps-avx512-state",
        now == a,
        "differs",
        "all of zmm0-31, k0-7, MXCSR unchanged",
    );
    t.eq("syscall-keeps-x87-control", (fcw, fsw), (0x37f, 0x3000));
    t.eq("syscall-keeps-x87-stack", (st0, st1), (PI_80, ONE_80));

    load(&a);
    nap(2);
    store(&mut now);
    t.holds("sleep-keeps-avx512-state", now == a, "differs", "unchanged");

    // About 20 ms of user-mode spinning: the tick interrupts the task several times.
    let start = rdtsc();
    load(&a);
    let mut spins = 0u64;
    while rdtsc().wrapping_sub(start) < 60_000_000 {
        spins += 1;
    }
    store(&mut now);
    t.holds(
        "interrupts-keep-avx512-state",
        now == a && spins > 0,
        "differs",
        "unchanged after timer interrupts",
    );
    t.eq("syscall-pkru", rdpkru(), PKRU_INIT);
    wrpkru(PKRU_USER);
    let _ = getpid();
    t.eq("syscall-keeps-pkru", rdpkru(), PKRU_USER);
    wrpkru(PKRU_INIT);
}

fn flag(n: u32, cond: bool) -> usize {
    usize::from(cond) << n
}

/// `fork` copies the registers and `PKRU`; each task then keeps its own through forced switches
/// (`switch_fpu_prepare`/`switch_fpu_finish`, `x86_pkru_load`).
fn switching(t: &mut T) {
    reap_all();
    let a = Image::pattern(2);
    let (b, c) = (Image::pattern(3), Image::pattern(4));
    const PKRU_CHILD: u32 = 0x5555_5514;
    wrpkru(PKRU_USER);
    load(&a);
    let child = spawn(|| {
        let mut got = Image::ZERO;
        store(&mut got);
        let inherited = got == a;
        let inherited_pkru = rdpkru() == PKRU_USER;
        wrpkru(PKRU_CHILD);
        load(&b);
        let mut keeps = true;
        let mut keeps_pkru = true;
        for _ in 0..30 {
            nap(1);
            store(&mut got);
            keeps &= got == b;
            keeps_pkru &= rdpkru() == PKRU_CHILD;
        }
        flag(0, inherited) | flag(1, inherited_pkru) | flag(2, keeps) | flag(3, keeps_pkru)
    });
    load(&c);
    let mut keeps = true;
    let mut keeps_pkru = true;
    let mut got = Image::ZERO;
    for _ in 0..30 {
        nap(1);
        store(&mut got);
        keeps &= got == c;
        keeps_pkru &= rdpkru() == PKRU_USER;
    }
    t.holds(
        "switch-parent-keeps-avx512-state",
        keeps,
        "changed",
        "unchanged",
    );
    t.holds(
        "switch-parent-keeps-pkru",
        keeps_pkru,
        "changed",
        "unchanged",
    );
    t.eq(
        "fork-child-copies-state-and-keeps-its-own",
        wait4(child as isize, 0),
        (Ok(child), 0xf << 8),
    );
    wrpkru(PKRU_INIT);
}

/// `execve` returns every component to its initial state and `PKRU` to the default
/// (`fpu_flush_thread`, `pkru_flush_thread`); the new image reports through its exit status.
fn exec_reset(t: &mut T) {
    reap_all();
    // The new image prints its hello line first; stdout goes to a pipe so that the log shows
    // one (as the `fork` group's exec checks do).
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (read_end, write_end) = (fds[0] as usize, fds[1] as usize);
    let child = spawn(|| {
        let _ = sys(Sysno::dup3, &[write_end, 1, 0]);
        load(&Image::pattern(5));
        x87_load();
        wrpkru(PKRU_USER);
        let argv = [addr(b"/init\0"), addr(b"xstateexec\0"), 0];
        let envp = [0usize];
        let _ = sys(Sysno::execve, &[addr(b"/init\0"), addr(&argv), addr(&envp)]);
        99
    });
    t.eq(
        "exec-resets-state-and-pkru",
        wait4(child as isize, 0),
        (Ok(child), 0),
    );
    // The read end stays open until the child is gone: a closed one would make its hello line a
    // SIGPIPE.
    let _ = sys(Sysno::close, &[read_end]);
    let _ = sys(Sysno::close, &[write_end]);
}

/// The image `exec_reset` executes: exits with a bit per register group that is not initial.
pub fn execd() -> ! {
    let mut now = Image::ZERO;
    store(&mut now);
    let (fcw, fsw) = x87_control();
    let code = flag(0, !now.zmm.iter().all(|&b| b == 0))
        | flag(1, now.k != [0; 8])
        | flag(2, now.mxcsr != MXCSR_INIT)
        | flag(3, fcw != 0x37f || fsw != 0)
        | flag(4, rdpkru() != PKRU_INIT);
    super::die(code)
}

// ---------------------------------------------------------------------------------------------
// Signals.

#[repr(C)]
struct StackT {
    sp: u64,
    flags: u32,
    pad: u32,
    size: u64,
}

/// Variants of what the handler does to the frame before returning.
mod mode {
    pub const PLAIN: usize = 0;
    pub const MODIFY: usize = 1;
    pub const BAD_MAGIC2: usize = 2;
    pub const BAD_MAGIC1: usize = 3;
    pub const XFEATURES_SUBSET: usize = 4;
    pub const XSTATE_BV_CLEARED: usize = 5;
    pub const FPSTATE_NULL: usize = 6;
    pub const HDR_RESERVED_LOW: usize = 7;
    pub const HDR_RESERVED_HIGH: usize = 8;
    pub const XSTATE_BV_BIT3: usize = 9;
    pub const XSTATE_BV_BIT63: usize = 10;
    pub const MXCSR_BAD: usize = 11;
    pub const MXCSR_BAD_FX_ONLY: usize = 12;
    pub const UNALIGNED: usize = 13;
    pub const KERNEL_ADDRESS: usize = 14;
    pub const UNMAPPED: usize = 15;
    pub const SHORT_OK: usize = 16;
    pub const SHORT_NEEDED: usize = 17;
    pub const COMPACTED: usize = 18;
    pub const NO_SW_READABLE: usize = 19;
    /// The handler loads other registers and a `PKRU`, raises `SIGUSR2` (handled by `nested`)
    /// and records what it finds when that returns.
    pub const NESTED: usize = 20;
}

/// The `MODIFY` edit: (byte offset in the standard-format area, length, byte value), each on a
/// different component: xmm3, the upper half of ymm5, bytes 0..16 of zmm7's upper 256, bytes 8..24
/// of zmm20, k3 and k4. MXCSR and PKRU are edited separately.
fn modifications(lay: &Layout) -> [(usize, usize, u8); 5] {
    [
        (160 + 16 * 3, 16, 0xee),
        (lay.off[2] + 16 * 5, 16, 0xdd),
        (lay.off[6] + 32 * 7, 16, 0xcc),
        (lay.off[7] + 64 * 4 + 8, 16, 0xbb),
        (lay.off[5] + 8 * 3, 16, 0xaa),
    ]
}

const MODIFIED_MXCSR: u32 = 0x7f80;
const MODIFIED_PKRU: u32 = 0x5555_5514;

/// The image `MODIFY` leaves, from the image the signal interrupted.
fn modified(base: &Image, lay: &Layout) -> Image {
    let mut area = [0u8; 4096];
    area_from_image(base, lay, &mut area);
    for (offset, len, byte) in modifications(lay) {
        area[offset..offset + len].fill(byte);
    }
    let mut out = *base;
    image_from_area(&area, lay, &mut out);
    out.mxcsr = MODIFIED_MXCSR;
    out
}

/// Standard-format area bytes of the components `image` holds (x87 and everything else zero).
fn area_from_image(image: &Image, lay: &Layout, area: &mut [u8; 4096]) {
    for i in 0..16 {
        let z = &image.zmm[64 * i..64 * i + 64];
        area[160 + 16 * i..160 + 16 * i + 16].copy_from_slice(&z[..16]);
        area[lay.off[2] + 16 * i..lay.off[2] + 16 * i + 16].copy_from_slice(&z[16..32]);
        area[lay.off[6] + 32 * i..lay.off[6] + 32 * i + 32].copy_from_slice(&z[32..64]);
    }
    for i in 16..32 {
        let at = lay.off[7] + 64 * (i - 16);
        area[at..at + 64].copy_from_slice(&image.zmm[64 * i..64 * i + 64]);
    }
    for (i, k) in image.k.iter().enumerate() {
        area[lay.off[5] + 8 * i..lay.off[5] + 8 * i + 8].copy_from_slice(&k.to_le_bytes());
    }
    area[24..28].copy_from_slice(&image.mxcsr.to_le_bytes());
}

fn image_from_area(area: &[u8], lay: &Layout, image: &mut Image) {
    for i in 0..16 {
        let z = &mut image.zmm[64 * i..64 * i + 64];
        z[..16].copy_from_slice(&area[160 + 16 * i..160 + 16 * i + 16]);
        z[16..32].copy_from_slice(&area[lay.off[2] + 16 * i..lay.off[2] + 16 * i + 16]);
        z[32..64].copy_from_slice(&area[lay.off[6] + 32 * i..lay.off[6] + 32 * i + 32]);
    }
    for i in 16..32 {
        let at = lay.off[7] + 64 * (i - 16);
        image.zmm[64 * i..64 * i + 64].copy_from_slice(&area[at..at + 64]);
    }
    for (i, k) in image.k.iter_mut().enumerate() {
        *k = rd64(area, lay.off[5] + 8 * i);
    }
    image.mxcsr = rd32(area, 24);
}

fn wr(addr: u64, offset: usize, bytes: &[u8]) {
    // SAFETY: only the signal handler calls this, with `addr` the sigcontext `fpstate` pointer of
    // the running handler or a buffer this test mapped; the bytes written are inside the frame
    // (`offset + len <= user_size + 4`) or the mapped buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            core::ptr::with_exposed_provenance_mut::<u8>(addr as usize + offset),
            bytes.len(),
        );
    }
}

fn rd(addr: u64, offset: usize, bytes: &mut [u8]) {
    // SAFETY: as `wr`, for reading.
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::with_exposed_provenance::<u8>(addr as usize + offset),
            bytes.as_mut_ptr(),
            bytes.len(),
        );
    }
}

extern "C" fn handler(_sig: i32, _info: *const u64, uc: *mut u64) {
    // The live registers first: `fpu__clear_user_states` left the initial state.
    LIVE.with(store);
    let (fcw, fsw) = x87_control();
    let pkru = rdpkru();
    let lay = Layout::read();
    // SAFETY: `uc` is the ucontext the kernel built for this handler (SA_SIGINFO): words 0
    // (`uc_flags`), 20 (sigcontext `sp`, byte 160) and 28 (sigcontext `fpstate`, byte 224).
    let (uc_flags, sp, fpstate) = unsafe { (uc.read(), uc.add(20).read(), uc.add(28).read()) };
    let snap_len = (lay.size + 4 + 64).min(SNAP_MAX);
    SNAP.with(|snap| {
        if fpstate != 0 {
            rd(fpstate, 0, &mut snap.0[..snap_len]);
        }
    });
    REC.with(|rec| {
        rec.hits += 1;
        rec.uc_flags = uc_flags;
        rec.fpstate = fpstate;
        rec.uc = uc as u64;
        rec.sp_at_signal = sp;
        rec.handler_pkru = pkru;
        rec.handler_fcw = fcw;
        rec.handler_fsw = fsw;
        rec.snap_len = snap_len;
    });
    let sw_xfeatures = |value: u64| wr(fpstate, 464 + 8, &value.to_le_bytes());
    let set_fpstate = |value: u64| {
        // SAFETY: `uc` words 28 is the sigcontext `fpstate` field `rt_sigreturn` reads.
        unsafe { uc.add(28).write(value) }
    };
    match MODE.load(Relaxed) {
        mode::MODIFY => {
            for (offset, len, byte) in modifications(&lay) {
                wr(fpstate, offset, &[byte; 16][..len]);
            }
            // MXCSR only: MXCSR_MASK (bytes 28..32) stays as the hardware wrote it.
            wr(fpstate, 24, &MODIFIED_MXCSR.to_le_bytes());
            wr(fpstate, lay.off[9], &MODIFIED_PKRU.to_le_bytes());
        }
        mode::BAD_MAGIC2 => wr(fpstate, lay.size, &0u32.to_le_bytes()),
        mode::BAD_MAGIC1 => wr(fpstate, 464, &0u32.to_le_bytes()),
        mode::XFEATURES_SUBSET => sw_xfeatures(0x7),
        mode::XSTATE_BV_CLEARED => wr(fpstate, 512, &XFEATURE_FPSSE.to_le_bytes()),
        mode::FPSTATE_NULL => set_fpstate(0),
        mode::HDR_RESERVED_LOW => wr(fpstate, 512 + 16, &[1]),
        mode::HDR_RESERVED_HIGH => wr(fpstate, 512 + 40, &[1]),
        mode::XSTATE_BV_BIT3 => {
            let bv = rd64_user(fpstate, 512) | 8;
            wr(fpstate, 512, &bv.to_le_bytes());
        }
        mode::XSTATE_BV_BIT63 => {
            let bv = rd64_user(fpstate, 512) | 1 << 63;
            wr(fpstate, 512, &bv.to_le_bytes());
        }
        mode::MXCSR_BAD => wr(fpstate, 24, &0x8000_0000u32.to_le_bytes()),
        mode::MXCSR_BAD_FX_ONLY => {
            wr(fpstate, 24, &0x8000_0000u32.to_le_bytes());
            wr(fpstate, 464, &0u32.to_le_bytes());
        }
        mode::UNALIGNED => {
            // A valid copy of the whole frame, 8 bytes past a 64-byte boundary.
            let copy = REGION.load(Relaxed) as u64 + 8;
            let mut area = [0u8; 4096 + 64];
            let n = lay.size + 4;
            rd(fpstate, 0, &mut area[..n]);
            wr(copy, 0, &area[..n]);
            set_fpstate(copy);
        }
        mode::KERNEL_ADDRESS => set_fpstate(0xffff_8000_0000_0000),
        mode::UNMAPPED => set_fpstate(0xdead_0000_0000),
        mode::SHORT_OK | mode::SHORT_NEEDED => {
            // The first 832 bytes of the frame (legacy area, header, AVX) in a buffer that ends
            // 64 bytes after the magic word, with unmapped memory right behind it.
            let buf = (REGION.load(Relaxed) + REGION_SIZE - 896) as u64;
            let mut area = [0u8; 896];
            rd(fpstate, 0, &mut area[..832]);
            area[832..836].copy_from_slice(&FP_XSTATE_MAGIC2.to_le_bytes());
            let features: u64 = if MODE.load(Relaxed) == mode::SHORT_OK {
                0x7
            } else {
                lay.xcr0
            };
            area[464..468].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
            area[468..472].copy_from_slice(&836u32.to_le_bytes());
            area[472..480].copy_from_slice(&features.to_le_bytes());
            area[480..484].copy_from_slice(&832u32.to_le_bytes());
            if MODE.load(Relaxed) == mode::SHORT_OK {
                let bv = rd64(&area, 512) & 0x7;
                area[512..520].copy_from_slice(&bv.to_le_bytes());
            }
            wr(buf, 0, &area);
            set_fpstate(buf);
        }
        mode::COMPACTED => {
            let word = 1u64 << 63 | lay.xcr0;
            wr(fpstate, 520, &word.to_le_bytes());
        }
        mode::NO_SW_READABLE => {
            // The first 100 bytes of a frame copy at the very end of the mapped page: the
            // software-reserved bytes at 464 are not readable.
            let buf = (REGION.load(Relaxed) + REGION_SIZE - 128) as u64;
            let mut area = [0u8; 128];
            rd(fpstate, 0, &mut area);
            wr(buf, 0, &area);
            set_fpstate(buf);
        }
        mode::NESTED => {
            wrpkru(NESTED_PKRU);
            load(&Image::pattern(99));
            let _ = sys(Sysno::kill, &[getpid(), SIGUSR2]);
            NESTED_AFTER.with(store);
            NESTED_REC.with(|rec| rec.pkru_after = rdpkru());
        }
        _ => {}
    }
}

/// The `SIGUSR2` handler of the nested-signal check: records its frame and its registers.
extern "C" fn nested(_sig: i32, _info: *const u64, uc: *mut u64) {
    NESTED_LIVE.with(store);
    // SAFETY: the ucontext of this handler (SA_SIGINFO), words 28 (`fpstate`).
    let fpstate = unsafe { uc.add(28).read() };
    let lay = Layout::read();
    NESTED_SNAP.with(|snap| rd(fpstate, 0, &mut snap.0[..lay.size + 4]));
    NESTED_REC.with(|rec| {
        rec.pkru_live = rdpkru();
        rec.fpstate = fpstate;
    });
}

fn rd64_user(addr: u64, offset: usize) -> u64 {
    let mut b = [0u8; 8];
    rd(addr, offset, &mut b);
    u64::from_le_bytes(b)
}

fn install(on_stack: bool) {
    let flags = SA_SIGINFO | if on_stack { SA_ONSTACK } else { 0 };
    let _ = sigaction(SIGUSR1, fn_addr(handler as *const ()), flags);
    let _ = sigaction(SIGUSR2, fn_addr(nested as *const ()), flags);
    if on_stack {
        let ss = StackT {
            sp: ALT.with(|alt| alt.stack.as_ptr().expose_provenance() as u64),
            flags: 0,
            pad: 0,
            size: ALT_SIZE as u64,
        };
        let _ = sys(Sysno::sigaltstack, &[addr(&ss), 0]);
    }
}

fn uninstall() {
    let ss = StackT {
        sp: 0,
        flags: 2, // SS_DISABLE
        pad: 0,
        size: 0,
    };
    let _ = sys(Sysno::sigaltstack, &[addr(&ss), 0]);
    let sa = KSigaction {
        handler: 0,
        flags: SA_RESTORER,
        restorer: fn_addr(restorer as *const ()),
        mask: 0,
    };
    let _ = sys(Sysno::rt_sigaction, &[SIGUSR1, addr(&sa), 0, 8]);
    let _ = sys(Sysno::rt_sigaction, &[SIGUSR2, addr(&sa), 0, 8]);
}

/// What was observed around one delivered signal.
struct Delivery {
    after: Image,
    after_pkru: u32,
    x87: (u16, u16, [u8; 10], [u8; 10]),
}

/// Loads `base` (and x87 state, and `PKRU_USER`), signals ourselves with the handler in `mode`,
/// and captures the registers after `rt_sigreturn`.
fn deliver(mode: usize, base: &Image) -> Delivery {
    MODE.store(mode, Relaxed);
    REC.with(|rec| rec.hits = 0);
    wrpkru(PKRU_USER);
    load(base);
    x87_load();
    let _ = sys(Sysno::kill, &[getpid(), SIGUSR1]);
    let mut after = Image::ZERO;
    store(&mut after);
    let (fcw, fsw) = x87_control();
    let (st0, st1) = x87_pop2();
    let after_pkru = rdpkru();
    wrpkru(PKRU_INIT);
    Delivery {
        after,
        after_pkru,
        x87: (fcw, fsw, st0, st1),
    }
}

fn frame_layout(t: &mut T, lay: &Layout) {
    let a = Image::pattern(10);
    // A mapped page whose successor is not mapped: the tail of the "short frame" buffers.
    let page = mmap(0, REGION_SIZE + 4096, 3, 0x22, usize::MAX, 0).unwrap_or(0);
    let _ = sys(Sysno::munmap, &[page + REGION_SIZE, 4096]);
    REGION.store(page, Relaxed);
    for on_stack in [false, true] {
        let tag = if on_stack { "altstack" } else { "stack" };
        install(on_stack);
        if on_stack {
            ALT.with(|alt| alt.stack.fill(0xa5));
        }
        let got = deliver(mode::PLAIN, &a);
        let rec = REC.with(|rec| *rec);
        let snap = SNAP.with(|snap| snap.0);
        t.eq(format_args!("{tag}-handler-ran-once"), rec.hits, 1);
        t.eq(format_args!("{tag}-frame-uc-flags"), rec.uc_flags, UC_FLAGS);
        t.eq(
            format_args!("{tag}-fpstate-aligned-64"),
            rec.fpstate % 64,
            0,
        );
        let top = if on_stack {
            ALT.with(|alt| alt.stack.as_ptr().expose_provenance() as u64) + ALT_SIZE as u64
        } else {
            rec.sp_at_signal - 128
        };
        t.eq(
            format_args!("{tag}-fpstate-position"),
            rec.fpstate,
            (top - (lay.size as u64 + 4)) & !63,
        );
        t.eq(
            format_args!("{tag}-handler-frame-below-fpstate"),
            rec.fpstate - rec.uc,
            448,
        );
        analyse_snapshot(t, tag, lay, &snap, &a);
        t.eq(
            format_args!("{tag}-handler-sees-initial-registers"),
            LIVE.with(|live| *live),
            Image::INIT,
        );
        t.eq(
            format_args!("{tag}-handler-sees-initial-x87"),
            (rec.handler_fcw, rec.handler_fsw),
            (0x37f, 0),
        );
        t.eq(
            format_args!("{tag}-handler-runs-with-default-pkru"),
            rec.handler_pkru,
            PKRU_INIT,
        );
        t.holds(
            format_args!("{tag}-sigreturn-restores-registers"),
            got.after == a,
            "differs",
            "all registers as before the signal",
        );
        t.eq(
            format_args!("{tag}-sigreturn-restores-x87"),
            got.x87,
            (0x37f, 0x3000, PI_80, ONE_80),
        );
        t.eq(
            format_args!("{tag}-sigreturn-restores-pkru"),
            got.after_pkru,
            PKRU_USER,
        );
        if on_stack {
            // Bytes `XSAVE` does not write stay as the stack held them.
            let first_bad = snap[..lay.size]
                .iter()
                .enumerate()
                .find(|&(at, &byte)| !lay.written(at) && byte != 0xa5)
                .map(|(at, _)| at);
            let untouched = first_bad.is_none();
            // The bytes past the magic word are not part of the frame (as far as the array goes).
            let alt_end = ALT.with(|alt| alt.stack.as_ptr().expose_provenance()) + ALT_SIZE;
            let frame_end = rec.fpstate as usize + lay.size + 4;
            let tail = (alt_end - frame_end).min(64);
            let tail_untouched = tail > 0
                && snap[lay.size + 4..lay.size + 4 + tail]
                    .iter()
                    .all(|&b| b == 0xa5);
            t.holds(
                "altstack-unwritten-gaps-keep-the-stack-contents",
                untouched,
                first_bad,
                "every byte outside the components is 0xa5",
            );
            t.holds(
                "altstack-bytes-after-the-frame-untouched",
                tail_untouched,
                tail,
                "the bytes after the trailing magic are 0xa5",
            );
            let reserved = snap[416..464].iter().all(|&b| b == 0xa5);
            t.info("reserved-416-464-untouched", format_args!("{reserved}"));
        }
    }
    uninstall();
}

/// The checks on the copy of the frame the handler saw.
fn analyse_snapshot(t: &mut T, tag: &str, lay: &Layout, snap: &[u8; SNAP_MAX], a: &Image) {
    t.eq(
        format_args!("{tag}-sw-magic1"),
        rd32(snap, 464),
        FP_XSTATE_MAGIC1,
    );
    t.eq(
        format_args!("{tag}-sw-extended-size"),
        rd32(snap, 468) as usize,
        lay.size + 4,
    );
    t.eq(
        format_args!("{tag}-sw-xfeatures"),
        rd64(snap, 472),
        lay.xcr0,
    );
    t.eq(
        format_args!("{tag}-sw-xstate-size"),
        rd32(snap, 480) as usize,
        lay.size,
    );
    t.eq(
        format_args!("{tag}-trailing-magic"),
        rd32(snap, lay.size),
        FP_XSTATE_MAGIC2,
    );
    t.eq(
        format_args!("{tag}-header-xstate-bv"),
        rd64(snap, 512),
        lay.xcr0,
    );
    t.eq(format_args!("{tag}-header-xcomp-bv"), rd64(snap, 520), 0);
    t.holds(
        format_args!("{tag}-header-reserved-zero"),
        snap[528..576].iter().all(|&b| b == 0),
        "nonzero",
        "bytes 16..64 of the header are zero",
    );
    t.holds(
        format_args!("{tag}-x87-top-of-stack"),
        snap[32..42] == PI_80 && snap[48..58] == ONE_80,
        (&snap[32..42], &snap[48..58]),
        "ST0 = pi and ST1 = 1.0 in the FXSAVE register slots",
    );
    t.eq(
        format_args!("{tag}-x87-control-word"),
        (snap[0], snap[1], snap[2], snap[3]),
        (0x7f, 0x03, 0, 0x30),
    );
    t.eq(format_args!("{tag}-mxcsr"), rd32(snap, 24), a.mxcsr);
    let mut frame = Image::ZERO;
    image_from_area(snap, lay, &mut frame);
    let part = |name: &str, same: bool, t: &mut T| {
        t.holds(
            format_args!("{tag}-{name}"),
            same,
            "differs",
            "equals the register",
        );
    };
    let xmm = |i: &Image| (0..16).all(|r| i.zmm[64 * r..64 * r + 16] == a.zmm[64 * r..64 * r + 16]);
    part("xmm-in-the-legacy-area", xmm(&frame), t);
    part(
        "ymm-upper-halves",
        (0..16).all(|r| frame.zmm[64 * r + 16..64 * r + 32] == a.zmm[64 * r + 16..64 * r + 32]),
        t,
    );
    part("opmask", frame.k == a.k, t);
    part(
        "zmm-upper-256",
        (0..16).all(|r| frame.zmm[64 * r + 32..64 * r + 64] == a.zmm[64 * r + 32..64 * r + 64]),
        t,
    );
    part(
        "zmm16-31",
        (16..32).all(|r| frame.zmm[64 * r..64 * r + 64] == a.zmm[64 * r..64 * r + 64]),
        t,
    );
    t.eq(
        format_args!("{tag}-pkru-slot-holds-the-interrupted-pkru"),
        rd32(snap, lay.off[9]),
        PKRU_USER,
    );
}

fn expect_zero_upper_image(a: &Image) -> Image {
    a.legacy_only()
}

/// `rt_sigreturn` of an unmodified, a modified and a re-described frame.
fn sigreturn_restores(t: &mut T, lay: &Layout) {
    let a = Image::pattern(11);
    install(false);
    let got = deliver(mode::MODIFY, &a);
    t.holds(
        "sigreturn-restores-registers-the-handler-changed",
        got.after == modified(&a, lay),
        "differs",
        "the edited xmm3, ymm5, zmm7, zmm20, k3 and MXCSR, the rest unchanged",
    );
    t.eq(
        "sigreturn-restores-the-pkru-the-handler-changed",
        got.after_pkru,
        MODIFIED_PKRU,
    );
    install(true);
    let got = deliver(mode::MODIFY, &a);
    t.holds(
        "sigreturn-from-altstack-restores-the-changed-registers",
        got.after == modified(&a, lay),
        "differs",
        "as on the normal stack",
    );
    t.eq(
        "sigreturn-from-altstack-restores-the-changed-pkru",
        got.after_pkru,
        MODIFIED_PKRU,
    );
    uninstall();
}

/// A frame whose description selects part of the state: what is not restored goes to its initial
/// configuration (`__restore_fpregs_from_user`'s `init_bv`), `PKRU` included (to 0, the hardware's
/// initial value, not `init_pkru_value`).
fn sigreturn_partial(t: &mut T, lay: &Layout) {
    let a = Image::pattern(12);
    install(false);
    let fx_only = expect_zero_upper_image(&a);
    // The initial state of the rest comes from `XRSTOR(init_fpstate, ...)`. In the standard format
    // (a CPU without XSAVEC) that instruction also loads MXCSR from the initial image whenever AVX
    // is among the components, undoing the frame's MXCSR after the legacy restore; in the
    // compacted format MXCSR is only loaded for a component whose `XSTATE_BV` bit is set.
    let compacted = cpuid(0xd, 1)[0] & 2 != 0;
    let mut fx_only_then_init = fx_only;
    if !compacted {
        fx_only_then_init.mxcsr = MXCSR_INIT;
    }
    for (name, m, want) in [
        (
            "sigreturn-bad-trailing-magic-restores-only-x87-and-sse",
            mode::BAD_MAGIC2,
            &fx_only_then_init,
        ),
        (
            "sigreturn-bad-leading-magic-restores-only-x87-and-sse",
            mode::BAD_MAGIC1,
            &fx_only_then_init,
        ),
        (
            "sigreturn-cleared-xstate-bv-restores-only-x87-and-sse",
            mode::XSTATE_BV_CLEARED,
            &fx_only,
        ),
    ] {
        let got = deliver(m, &a);
        t.holds(
            name,
            got.after == *want,
            "differs",
            "xmm restored, the rest initial",
        );
        t.eq(format_args!("{name}-pkru"), got.after_pkru, 0);
        t.eq(
            format_args!("{name}-x87"),
            got.x87,
            (0x37f, 0x3000, PI_80, ONE_80),
        );
    }
    // Only x87, SSE and AVX described: the AVX-512 state and PKRU go initial.
    let got = deliver(mode::XFEATURES_SUBSET, &a);
    let mut want = fx_only;
    for r in 0..16 {
        want.zmm[64 * r + 16..64 * r + 32].copy_from_slice(&a.zmm[64 * r + 16..64 * r + 32]);
    }
    t.holds(
        "sigreturn-described-xfeatures-limit-the-restore",
        got.after == want,
        "differs",
        "x87, xmm and ymm upper halves restored, opmask, zmm and zmm16-31 initial",
    );
    t.eq(
        "sigreturn-described-xfeatures-limit-the-pkru",
        got.after_pkru,
        0,
    );
    // A null fpstate pointer: everything initial, PKRU at the default.
    let got = deliver(mode::FPSTATE_NULL, &a);
    t.holds(
        "sigreturn-null-fpstate-resets-the-registers",
        got.after == Image::INIT,
        "differs",
        "all registers initial",
    );
    t.eq(
        "sigreturn-null-fpstate-resets-x87",
        (got.x87.0, got.x87.1),
        (0x37f, 0),
    );
    t.eq(
        "sigreturn-null-fpstate-resets-pkru-to-the-default",
        got.after_pkru,
        PKRU_INIT,
    );
    // Header bytes 24..64 are not checked by the CPU in the standard format.
    let got = deliver(mode::HDR_RESERVED_HIGH, &a);
    t.holds(
        "sigreturn-ignores-header-bytes-above-24",
        got.after == a,
        "differs",
        "restored as normal",
    );
    // A buffer that ends where the first restored component ends: the CPU reads nothing more.
    let got = deliver(mode::SHORT_OK, &a);
    let mut want = fx_only;
    for r in 0..16 {
        want.zmm[64 * r + 16..64 * r + 32].copy_from_slice(&a.zmm[64 * r + 16..64 * r + 32]);
    }
    t.holds(
        "sigreturn-reads-only-the-described-components",
        got.after == want,
        "differs",
        "x87, xmm and ymm upper halves restored",
    );
    t.eq("sigreturn-short-buffer-pkru", got.after_pkru, 0);
    let _ = lay;
    uninstall();
}

/// A frame the CPU or the kernel refuses: `rt_sigreturn` fails and the task gets `SIGSEGV`
/// (`signal_fault` -> `force_sig(SIGSEGV)`), observed in a child.
fn sigreturn_refused(t: &mut T, lay: &Layout) {
    install(false);
    let a = Image::pattern(13);
    for (name, m) in [
        ("header-reserved-byte-16", mode::HDR_RESERVED_LOW),
        ("xstate-bv-names-a-disabled-component", mode::XSTATE_BV_BIT3),
        ("xstate-bv-bit-63", mode::XSTATE_BV_BIT63),
        ("reserved-mxcsr-bit", mode::MXCSR_BAD),
        (
            "reserved-mxcsr-bit-in-the-legacy-only-restore",
            mode::MXCSR_BAD_FX_ONLY,
        ),
        ("fpstate-not-64-byte-aligned", mode::UNALIGNED),
        ("fpstate-in-kernel-space", mode::KERNEL_ADDRESS),
        ("fpstate-unmapped", mode::UNMAPPED),
        (
            "short-buffer-missing-a-described-component",
            mode::SHORT_NEEDED,
        ),
        ("software-reserved-bytes-unreadable", mode::NO_SW_READABLE),
    ] {
        reap_all();
        let child = spawn(|| {
            let _ = deliver(m, &a);
            0
        });
        let (r, status) = wait4(child as isize, 0);
        t.eq(
            format_args!("sigreturn-refused-{name}"),
            (r == Ok(child), status),
            (true, SIGSEGV as i32),
        );
    }
    // The compacted-format header is evaluated by the CPU: record what it did.
    reap_all();
    let child = spawn(|| {
        let got = deliver(mode::COMPACTED, &a);
        let mut upper_ok = true;
        for r in 0..16 {
            upper_ok &= got.after.zmm[64 * r..64 * r + 16] == a.zmm[64 * r..64 * r + 16];
        }
        1 | flag(1, upper_ok)
    });
    let outcome = outcome_of(child, 1);
    // The reference: `rt_sigreturn` first `XRSTOR`s the frame from user memory (the fast path),
    // so the CPU decides whether a header claiming the compacted format is valid; only when it
    // faults does the slow path refuse `xcomp_bv != 0` (`validate_user_xstate_header`). The same
    // header (empty `XSTATE_BV`: no component is read) executed in ring 3 gives that decision
    // without the kernel's help.
    reap_all();
    static HEADER: Single<Aligned<4224>> = Single::new(Aligned([0; 4224]));
    let reference = spawn(|| {
        HEADER.with(|area| {
            area.0.fill(0);
            area.0[520..528].copy_from_slice(&(1u64 << 63 | lay.xcr0).to_le_bytes());
            // SAFETY: as `user_instructions`: user mode, a 64-aligned area larger than the
            // standard format, a header whose only oddity is the compacted bit (the point: the
            // CPU may raise `#GP`, which is `SIGSEGV` and the answer).
            unsafe {
                asm!("xrstor64 [{p}]", p = in(reg) area.0.as_ptr(), in("eax") lay.xcr0 as u32, in("edx") (lay.xcr0 >> 32) as u32, options(nostack, readonly));
            }
        });
        1
    });
    let cpu = outcome_of(reference, 1);
    t.info("compacted-header", format_args!("{outcome}"));
    t.eq(
        "sigreturn-compacted-header-is-the-cpus-decision",
        outcome,
        cpu,
    );
    let _ = lay;
    uninstall();
}

/// How a child that exits with `want` in its status byte ended: `"killed"` by `SIGSEGV`,
/// `"survived"`, or `"unexpected"`.
fn outcome_of(child: usize, want: i32) -> &'static str {
    let (r, status) = wait4(child as isize, 0);
    if status & 0x7f == SIGSEGV as i32 {
        "killed"
    } else if r == Ok(child) && status >> 8 & want == want {
        "survived"
    } else {
        "unexpected"
    }
}

/// The frame must fit the alternate stack: `get_sigframe` refuses (`SIGSEGV`) when it does not,
/// and `AT_MINSIGSTKSZ` is enough. The smallest size that fits is computed from the frame
/// arithmetic of `get_sigframe`; a task whose stack is one byte smaller dies, as does none at the
/// computed size and at `AT_MINSIGSTKSZ`.
fn altstack_sizes(t: &mut T, lay: &Layout) {
    let base = ALT.with(|alt| alt.stack.as_ptr().expose_provenance());
    let fits = |size: usize| {
        let top = base + size;
        let fpstate = (top - (lay.size + 4)) & !63;
        let sp = ((fpstate - 440) & !15) - 8;
        sp >= base
    };
    let smallest = (2048..ALT_SIZE).find(|&size| fits(size)).unwrap_or(0);
    let survives = |size: usize| {
        reap_all();
        let child = spawn(|| {
            let ss = StackT {
                sp: base as u64,
                flags: 0,
                pad: 0,
                size: size as u64,
            };
            let _ = sys(Sysno::sigaltstack, &[addr(&ss), 0]);
            let _ = sigaction(
                SIGUSR1,
                fn_addr(handler as *const ()),
                SA_SIGINFO | SA_ONSTACK,
            );
            MODE.store(mode::PLAIN, Relaxed);
            load(&Image::pattern(17));
            let _ = sys(Sysno::kill, &[getpid(), SIGUSR1]);
            0
        });
        wait4(child as isize, 0) == (Ok(child), 0)
    };
    t.holds(
        "altstack-too-small-by-one-byte-kills-the-task",
        smallest > 2048 && !survives(smallest - 1),
        smallest,
        "SIGSEGV when the XSAVE frame does not fit",
    );
    t.holds(
        "altstack-just-big-enough-takes-the-signal",
        survives(smallest),
        smallest,
        "the signal is delivered",
    );
    t.holds(
        "altstack-of-at-minsigstksz-takes-the-signal",
        survives(MINSIGSTKSZ.load(Relaxed)),
        MINSIGSTKSZ.load(Relaxed),
        "AT_MINSIGSTKSZ is enough",
    );
}

/// A signal raised inside a handler: the nested frame holds the first handler's registers and
/// `PKRU`, its handler starts from the initial state, and both returns restore what they saved.
fn nested_signal(t: &mut T, lay: &Layout) {
    let a = Image::pattern(14);
    let b = Image::pattern(99);
    install(false);
    let got = deliver(mode::NESTED, &a);
    let live = NESTED_LIVE.with(|live| *live);
    let after = NESTED_AFTER.with(|after| *after);
    let rec = NESTED_REC.with(|rec| *rec);
    let snap = NESTED_SNAP.with(|snap| snap.0);
    let mut frame = Image::ZERO;
    image_from_area(&snap, lay, &mut frame);
    t.holds(
        "nested-signal-handler-starts-from-the-initial-state",
        live == Image::INIT && rec.pkru_live == PKRU_INIT,
        rec.pkru_live,
        "initial registers and the default PKRU",
    );
    t.holds(
        "nested-signal-frame-holds-the-first-handlers-registers",
        frame == b && rd32(&snap, lay.off[9]) == NESTED_PKRU,
        "differs",
        "the registers and PKRU the first handler had set",
    );
    t.holds(
        "nested-signal-return-restores-the-first-handlers-registers",
        after == b && rec.pkru_after == NESTED_PKRU,
        rec.pkru_after,
        "the first handler's registers and PKRU",
    );
    t.holds(
        "nested-signal-both-returns-restore-the-interrupted-registers",
        got.after == a && got.after_pkru == PKRU_USER,
        "differs",
        "the registers and PKRU before the first signal",
    );
    uninstall();
}

/// The instructions of the state, executed from ring 3: `XSAVE`/`XRSTOR` of the user's own
/// state work, the privileged and the malformed ones raise `#GP`, which is `SIGSEGV`.
fn user_instructions(t: &mut T, lay: &Layout) {
    static AREA: Single<Aligned<4224>> = Single::new(Aligned([0; 4224]));
    let a = Image::pattern(15);
    load(&a);
    x87_load();
    let (lo, hi) = (lay.xcr0 as u32, (lay.xcr0 >> 32) as u32);
    AREA.with(|area| {
        area.0.fill(0);
        // SAFETY: as the module proof; `XSAVE64` needs CR4.OSXSAVE; the 64-aligned area is
        // 4224 bytes, more than the standard-format size; the mask is XCR0.
        unsafe {
            asm!("xsave64 [{p}]", p = in(reg) area.0.as_mut_ptr(), in("eax") lo, in("edx") hi, options(nostack));
        }
    });
    let saved = AREA.with(|area| area.0);
    let mut image = Image::ZERO;
    image_from_area(&saved, lay, &mut image);
    t.eq("user-xsave-xstate-bv", rd64(&saved, 512), lay.xcr0);
    t.holds(
        "user-xsave-saves-the-registers",
        image == a,
        "differs",
        "the live registers",
    );
    let _ = x87_pop2();
    // XRSTOR of a modified area changes the registers.
    let b = Image::pattern(16);
    AREA.with(|area| {
        let mut std = [0u8; 4096];
        area_from_image(&b, lay, &mut std);
        area.0[..4096].copy_from_slice(&std);
        // x87 and the PKRU stay as they were: only the described components are restored.
        area.0[512..520].copy_from_slice(&(lay.xcr0 & !(1 | (1 << 9))).to_le_bytes());
        // SAFETY: as above, `XRSTOR64` of a header the CPU accepts (bytes 8..64 zero, bits within
        // XCR0); the request mask leaves x87 and PKRU alone.
        let request = (lay.xcr0 & !(1 | (1 << 9))) as u32;
        unsafe {
            asm!("xrstor64 [{p}]", p = in(reg) area.0.as_ptr(), in("eax") request, in("edx") hi, options(nostack, readonly));
        }
    });
    let mut now = Image::ZERO;
    store(&mut now);
    t.holds(
        "user-xrstor-restores-the-registers",
        now == b,
        "differs",
        "the area's registers",
    );
    // Malformed or privileged: SIGSEGV.
    for (name, child) in [
        ("xsetbv-in-ring-3", 0usize),
        ("xsaves-in-ring-3", 1),
        ("wrpkru-with-ecx-not-zero", 2),
        ("xrstor-misaligned", 3),
        ("xrstor-reserved-header-bytes", 4),
    ] {
        reap_all();
        let pid = spawn(|| {
            // SAFETY: each block faults on purpose (the point of the check): the instruction is
            // privileged, or its operand is malformed; user mode, no memory except the area.
            unsafe {
                match child {
                    0 => asm!("xsetbv", in("ecx") 0, in("eax") 7, in("edx") 0, options(nostack)),
                    1 => AREA.with(|area| asm!("xsaves64 [{p}]", p = in(reg) area.0.as_mut_ptr(), in("eax") 3, in("edx") 0, options(nostack))),
                    2 => asm!("wrpkru", in("eax") 0, in("ecx") 1, in("edx") 0, options(nostack)),
                    3 => AREA.with(|area| asm!("xrstor64 [{p}]", p = in(reg) area.0.as_ptr().add(8), in("eax") 3, in("edx") 0, options(nostack, readonly))),
                    _ => AREA.with(|area| {
                        area.0[512 + 16] = 1;
                        asm!("xrstor64 [{p}]", p = in(reg) area.0.as_ptr(), in("eax") 3, in("edx") 0, options(nostack, readonly));
                    }),
                }
            }
            0
        });
        t.eq(
            format_args!("{name}-is-sigsegv"),
            wait4(pid as isize, 0),
            (Ok(pid), SIGSEGV as i32),
        );
    }
    wrpkru(PKRU_INIT);
}

/// A `SIGSEGV` from a `PKRU` fault: `SEGV_PKUERR` with the key of the VMA (0), the interrupted
/// `PKRU` in the frame, the default `PKRU` in the handler.
fn pkru_fault(t: &mut T) {
    reap_all();
    static WORD: AtomicUsize = AtomicUsize::new(7);
    extern "C" fn segv(_sig: i32, info: *const u64, uc: *mut u64) {
        // SAFETY: the kernel's siginfo (16 words) and ucontext (word 28 is `fpstate`).
        let (words, fpstate) = unsafe {
            (
                [info.add(1).read(), info.add(2).read(), info.add(4).read()],
                uc.add(28).read(),
            )
        };
        let pkru_in_frame = {
            let lay = Layout::read();
            rd64_user(fpstate, lay.off[9]) as u32
        };
        let code = words[0] as u32 as i32; // si_code is the low half of word 1
        let address = words[1];
        let pkey = words[2] as u32;
        let ok = code == 4
            && address == core::ptr::addr_of!(WORD).expose_provenance() as u64
            && pkey == 0
            && pkru_in_frame == 1
            && rdpkru() == PKRU_INIT;
        super::die(usize::from(ok));
    }
    let child = spawn(|| {
        let ss = StackT {
            sp: ALT.with(|alt| alt.stack.as_ptr().expose_provenance() as u64),
            flags: 0,
            pad: 0,
            size: ALT_SIZE as u64,
        };
        let _ = sys(Sysno::sigaltstack, &[addr(&ss), 0]);
        let _ = sigaction(SIGSEGV, fn_addr(segv as *const ()), SA_SIGINFO | SA_ONSTACK);
        // SAFETY: as the module proof: PKRU = 1 disables all access through key 0, so the load
        // faults (the point of the test); no stack access follows before the fault.
        unsafe {
            asm!(
                "wrpkru",
                "mov {t}, qword ptr [{a}]",
                a = in(reg) core::ptr::addr_of!(WORD),
                t = out(reg) _,
                in("eax") 1,
                in("ecx") 0,
                in("edx") 0,
                options(nostack),
            );
        }
        2
    });
    t.eq(
        "pkru-access-disable-gives-segv-pkuerr",
        wait4(child as isize, 0),
        (Ok(child), 1 << 8),
    );
}

/// A system call made with `PKRU = pkru`, and `PKRU` back at `PKRU_INIT` afterwards. Nothing in
/// ring 3 touches memory between the two `WRPKRU`s (key 0, which every page of this program
/// has, is disabled meanwhile), so the block is one `asm!`. Returns the raw result.
fn syscall_with_pkru(pkru: u32, nr: Sysno, a0: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    // SAFETY: as the module proof; user mode. `WRPKRU` needs ECX = EDX = 0 and sets PKRU from
    // EAX; the first changes it to `pkru`, the second back to `PKRU_INIT`, which keeps key 0
    // accessible, so the compiler's own accesses (stack, statics) are never affected: the
    // block itself reads and writes no memory, and no spill can be placed between the two
    // instructions that change PKRU because they are in one block. The system call (`SYSCALL`
    // convention: number in RAX, arguments in RDI/RSI/RDX, RCX and R11 clobbered, the other
    // registers kept) may write memory through the pointer argument, so the block is not
    // `nomem`. Flags are changed by `XOR`.
    unsafe {
        asm!(
            "xor ecx, ecx",
            "xor edx, edx",
            "mov eax, r8d",
            "wrpkru",
            "mov eax, r9d",
            "mov rdx, r10",
            "syscall",
            "mov r12, rax",
            "xor ecx, ecx",
            "xor edx, edx",
            "mov eax, {init}",
            "wrpkru",
            init = const PKRU_INIT,
            in("r8") u64::from(pkru),
            in("r9") nr.id() as u64,
            in("r10") a2,
            in("rdi") a0,
            in("rsi") a1,
            out("r12") ret,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// The protection keys apply to the kernel's own accesses on the task's behalf: with key 0
/// access-disabled `read(2)`/`write(2)`/`clock_gettime`/`arch_prctl` fail with `EFAULT` (the
/// hardware checks `copy_from_user`/`copy_to_user` like any user access; Documentation/core-api/
/// protection-keys.rst), with write-disabled only the calls that store to user memory do, and
/// nothing is consumed or stored by a refused call.
fn pkru_kernel_access(t: &mut T) {
    const AD: u32 = PKRU_INIT | 1;
    const WD: u32 = PKRU_INIT | 2;
    const O_NONBLOCK: usize = 0o4000;
    reap_all();
    let efault = -(Errno::EFAULT.into_raw() as isize);
    let eagain = -(Errno::EAGAIN.into_raw() as isize);
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), O_NONBLOCK]);
    let (r, w) = (fds[0] as usize, fds[1] as usize);
    let mut buf = [0xa5u8; 16];
    let p = addr_mut(&mut buf);
    let io = |pkru, nr, fd| syscall_with_pkru(pkru, nr, fd, p, 4);
    t.eq(
        "pkru-ad-makes-write-fail-with-efault",
        io(AD, Sysno::write, w),
        efault,
    );
    t.eq(
        "pkru-refused-write-queued-nothing",
        io(PKRU_INIT, Sysno::read, r),
        eagain,
    );
    t.eq(
        "pkru-wd-allows-write-to-read-user-memory",
        io(WD, Sysno::write, w),
        4,
    );
    t.eq(
        "pkru-ad-makes-read-fail-with-efault",
        io(AD, Sysno::read, r),
        efault,
    );
    t.eq(
        "pkru-wd-makes-read-fail-with-efault",
        io(WD, Sysno::read, r),
        efault,
    );
    t.eq(
        "pkru-refused-read-consumed-nothing",
        io(PKRU_INIT, Sysno::read, r),
        4,
    );
    for (name, pkru) in [("ad", AD), ("wd", WD)] {
        t.eq(
            format_args!("pkru-{name}-makes-clock_gettime-fail-with-efault"),
            syscall_with_pkru(pkru, Sysno::clock_gettime, 1, p, 0),
            efault,
        );
    }
    t.eq(
        "pkru-clock_gettime-with-the-default-pkru",
        syscall_with_pkru(PKRU_INIT, Sysno::clock_gettime, 1, p, 0),
        0,
    );
    t.eq(
        "pkru-wd-makes-arch_prctl-store-fail-with-efault",
        syscall_with_pkru(WD, Sysno::arch_prctl, 0x1021, p, 0),
        efault,
    );
    // A page nobody touched yet: the denied access is refused whether or not it is resident.
    if let Ok(page) = mmap(0, 4096, 3, 0x22, usize::MAX, 0) {
        t.eq(
            "pkru-ad-on-an-untouched-page-is-efault",
            syscall_with_pkru(AD, Sysno::write, w, page, 1),
            efault,
        );
        t.eq(
            "pkru-the-untouched-page-is-usable-afterwards",
            syscall_with_pkru(PKRU_INIT, Sysno::write, w, page, 1),
            1,
        );
    } else {
        t.holds(
            "pkru-mmap-for-the-untouched-page",
            false,
            "mmap failed",
            "a page",
        );
    }
    t.eq("pkru-back-at-the-default", rdpkru(), PKRU_INIT);
    let _ = sys(Sysno::close, &[r]);
    let _ = sys(Sysno::close, &[w]);
}
