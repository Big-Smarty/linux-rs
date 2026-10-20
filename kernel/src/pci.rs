// SPDX-License-Identifier: GPL-2.0-only
//! Read-only PCI inventory for the bare-metal suite (decision A21), through
//! configuration mechanism #1 (I/O ports 0xCF8 address / 0xCFC data), the same
//! mechanism as Linux's `arch/x86/pci/direct.c` (`pci_conf1_read`).
//!
//! # Why every access is side-effect free
//! * The only register ever written is the address register 0xCF8, and only
//!   with the enable bit, bus/device/function and a dword-aligned register
//!   offset of 0x00, 0x08 or 0x0C. Writing 0xCF8 selects a register and starts
//!   no transaction by itself.
//! * The only data accesses are 32-bit reads of 0xCFC at those offsets: the
//!   vendor/device ID, the revision/class code and the header type. The PCI
//!   Local Bus Specification (rev 3.0, 6.2.1/6.2.2) defines them as read-only
//!   registers with no read side effects; a read of a non-existent function
//!   completes with all ones (master abort), which is how absence is detected.
//! * No BAR is sized (that needs writes to the BAR), no command or status
//!   register is touched, no capability list is walked, no memory or I/O
//!   window is decoded or enabled.
//! * 0xCF8 holds its previous value again when the scan ends.
//!
//! # Contract
//! CPL0 on the BSP with interrupts off and no other user of 0xCF8/0xCFC: this
//! kernel has no PCI driver, no AP runs and nothing else touches the ports.
//! The scan is bounded: 256 buses x 32 devices x (1 or 8 functions) reads.
//! shortcut: mechanism #1 only; a platform without it (very old) reports
//! "mechanism 1 absent". `PCIe` ECAM (MCFG) is not used. Upgrade with a PCI core.

use x86_64::instructions::port::Port;

const ADDRESS: u16 = 0xcf8;
const DATA: u16 = 0xcfc;
/// Most functions listed (the scan itself is bounded by the bus/device/function counts).
pub const MAX_FUNCTIONS: usize = 512;

/// The three ID registers of one function.
#[derive(Clone, Copy, Debug)]
pub struct Function {
    pub bus: u8,
    pub device: u8,
    pub func: u8,
    pub vendor: u16,
    pub device_id: u16,
    pub revision: u8,
    pub prog_if: u8,
    pub sub_class: u8,
    pub base_class: u8,
    pub header_type: u8,
}

/// Outcome of a scan: how many functions exist, how many were listed.
#[derive(Clone, Copy, Debug)]
pub struct Scan {
    pub found: usize,
    pub listed: usize,
    pub buses: usize,
}

struct Ports {
    address: Port<u32>,
    data: Port<u32>,
}

impl Ports {
    const fn new() -> Self {
        Self {
            address: Port::new(ADDRESS),
            data: Port::new(DATA),
        }
    }

    /// 32-bit configuration read of `offset` (dword aligned) of a function.
    ///
    /// # Safety
    /// The contract of this module.
    unsafe fn read(&mut self, bus: u8, device: u8, function: u8, offset: u8) -> u32 {
        let address = 0x8000_0000
            | u32::from(bus) << 16
            | u32::from(device & 0x1f) << 11
            | u32::from(function & 7) << 8
            | u32::from(offset & 0xfc);
        // SAFETY: the module contract; the address selects a standard header
        // register and the data read has no side effect.
        unsafe {
            self.address.write(address);
            self.data.read()
        }
    }
}

/// Whether configuration mechanism #1 answers: the address register keeps the
/// enable bit and host bridge 00:00.0 has a vendor ID (Linux's `pci_check_type1`
/// and `pci_sanity_check`, without the mechanism-2 probe that writes 0xCFB).
///
/// # Safety
/// The contract of this module.
unsafe fn mechanism_one(ports: &mut Ports) -> bool {
    // SAFETY: module contract; the saved value is restored below.
    unsafe {
        let saved = ports.address.read();
        ports.address.write(0x8000_0000);
        let present = ports.address.read() == 0x8000_0000;
        let vendor = ports.read(0, 0, 0, 0) & 0xffff;
        ports.address.write(saved);
        present && vendor != 0xffff
    }
}

/// Scan every bus and call `visit` for each function present (at most
/// [`MAX_FUNCTIONS`]); returns `None` when mechanism #1 is absent.
///
/// # Safety
/// The contract of this module.
pub unsafe fn scan(mut visit: impl FnMut(&Function)) -> Option<Scan> {
    let mut ports = Ports::new();
    // SAFETY: forwarded contract.
    if !unsafe { mechanism_one(&mut ports) } {
        return None;
    }
    // SAFETY: as above; restored at the end.
    let saved = unsafe { ports.address.read() };
    let mut scan = Scan {
        found: 0,
        listed: 0,
        buses: 0,
    };
    for bus in 0..=255u8 {
        let mut bus_has_device = false;
        for device in 0..32u8 {
            // SAFETY: forwarded contract.
            let id = unsafe { ports.read(bus, device, 0, 0) };
            if id & 0xffff == 0xffff {
                continue;
            }
            // SAFETY: as above.
            let header = unsafe { ports.read(bus, device, 0, 0x0c) };
            let functions = if (header >> 16) & 0x80 != 0 { 8 } else { 1 };
            for function in 0..functions {
                // SAFETY: as above.
                let (id, class, header) = unsafe {
                    (
                        ports.read(bus, device, function, 0),
                        ports.read(bus, device, function, 0x08),
                        ports.read(bus, device, function, 0x0c),
                    )
                };
                if id & 0xffff == 0xffff {
                    continue;
                }
                bus_has_device = true;
                scan.found += 1;
                if scan.listed < MAX_FUNCTIONS {
                    scan.listed += 1;
                    visit(&Function {
                        bus,
                        device,
                        func: function,
                        vendor: (id & 0xffff) as u16,
                        device_id: (id >> 16) as u16,
                        revision: (class & 0xff) as u8,
                        prog_if: ((class >> 8) & 0xff) as u8,
                        sub_class: ((class >> 16) & 0xff) as u8,
                        base_class: (class >> 24) as u8,
                        header_type: ((header >> 16) & 0x7f) as u8,
                    });
                }
            }
        }
        scan.buses += usize::from(bus_has_device);
    }
    // SAFETY: as above.
    unsafe { ports.address.write(saved) };
    Some(scan)
}
