// SPDX-License-Identifier: GPL-2.0-only
//! Host fakes for the syscall tests: a task whose user memory is the sparse
//! `usercopy::fake::Space`, whose console collects bytes, and whose files are a
//! real tmpfs rootfs (`/dev/console`, `/root`, optional extra entries) with
//! descriptors 0-2 on the console, as `console_on_rootfs` leaves init.

use super::{
    AddressSpace, Console, Context, ExecAux, Files, Machine, Tasks, TtyParts,
    time::{ClockState, Clocks, RestartBlock},
};
use crate::{
    cputime::CpuSample,
    mm::{Env, Mm, VmFlags, tests::Fake},
    signal::{
        self, SIGALRM, SIGUSR1, SIGUSR2, State, frame::Sigreturn, info::SigInfo, state::Target,
    },
    task::{Attributes, TaskId, Tasklist, exit::NoWake, fork::ForkRequest, tasklist::ForkParams},
    usercopy::{UserPages, fake::Space},
    vfs::{FdTable, FileId, Timespec, Vfs},
};
extern crate std;
use crate::sched::WaitKey;
use std::{boxed::Box, collections::BTreeMap, vec::Vec};

#[derive(Default)]
pub struct Sink(pub Vec<u8>);
impl Console for Sink {
    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

/// Scriptable timekeeper and CPU accounting for the time group.
pub struct FakeClocks {
    pub state: ClockState,
    pub sample: CpuSample,
    pub adjusted: (u64, u64),
    pub rtc: bool,
    pub capable: bool,
    /// The next sleep is interrupted with this many ns remaining.
    pub interrupt: Option<u64>,
    /// Sleep through the real `signal::wait::sleep_until` (the fake `wait`
    /// clock, `Task::now`) instead of the scripted `interrupt`.
    pub real_sleep: bool,
    /// Deadlines passed to `sleep_until`.
    pub slept: Vec<u64>,
    /// Offsets passed to `set_realtime`.
    pub set: Vec<i64>,
    /// Every `restart_block` store, in order.
    pub restarts: Vec<RestartBlock>,
}

impl Default for FakeClocks {
    fn default() -> Self {
        Self {
            state: ClockState {
                mono_ns: 5_123_456_789,
                boot_offset_ns: 0,
                real_offset_ns: 1_800_000_000_000_000_000,
                settod_real_ns: 0,
            },
            sample: CpuSample {
                runtime_ns: 3_000_000,
                user_ns: 2_000_000,
                system_ns: 1_000_000,
            },
            adjusted: (2_000_000, 1_000_000),
            rtc: true,
            capable: true,
            interrupt: None,
            real_sleep: false,
            slept: Vec::new(),
            set: Vec::new(),
            restarts: Vec::new(),
        }
    }
}

/// What another task does to the shared state while this one sleeps.
pub type WaitHook = Box<dyn FnOnce(&mut Vfs, &mut FdTable)>;

/// The unwind payload of a fake wait that would sleep forever ([`would_hang`]).
pub struct Hang;

/// Run `call`; whether it ended in a wait that nothing could end (the state
/// the call left is whatever it had done before sleeping).
pub fn would_hang<R>(call: impl FnOnce() -> R) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(call)) {
        Ok(_) => false,
        Err(payload) if payload.is::<Hang>() => true,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

pub struct Task<P = Space, C = Sink> {
    pub pages: P,
    pub sink: C,
    pub tgid: u32,
    pub attrs: Attributes,
    pub fs_base: u64,
    pub gs_base: u64,
    pub machine: Machine,
    pub cpuid_fault_absent: bool,
    /// The user extended state `arch_prctl(ARCH_*_XCOMP_*)` reports.
    pub xstate: crate::xstate::Config,
    pub clocks: FakeClocks,
    /// The address space the memory syscalls edit, over the model's fake tables.
    pub mm: Mm,
    pub env: Env,
    pub tables: Fake,
    pub vfs: Vfs,
    pub fdt: FdTable,
    /// The console tty (`tty::Tty`), as the binary keeps it beside the VFS.
    pub tty: crate::tty::Tty,
    /// Private copies of file pages a kernel access faulted in (the binary's
    /// `user_fault` for `NeedsFile`: `Vfs::fault_page`, then a private frame).
    pub file_pages: BTreeMap<u64, Box<[u8; 4096]>>,
    /// The task list; `current` is its init (pid 1).
    pub tasks: Tasklist,
    pub current: TaskId,
    pub wake: NoWake,
    /// `mm->exe_file` as `replace_exe_file` last set it.
    pub exe: Option<FileId>,
    /// `(ip, sp)` of the last `start_thread`.
    pub started: Option<(u64, u64)>,
    /// The state of the fake hardware generator ([`Context::hw_random`]).
    pub random_state: u64,
    /// A CPU without a hardware generator.
    pub no_hw_random: bool,
    /// shortcut: this is a second signal object for the task `current`, whose
    /// own is in `tasks` (the binary has only the latter, via
    /// `Tasklist::signal_state`). Exec, wait and exit tests that touch both
    /// exercise a different arrangement than the boot. The signal tests need
    /// a non-init process (`global_init` and `SIGNAL_UNKILLABLE` are derived
    /// from the task list's init), so unify them when the fake gets a forked
    /// non-init current task (the fork lane).
    ///
    /// The signal state: a non-init process whose `SIGUSR1`, `SIGUSR2` and
    /// `SIGALRM` have handlers, so sending them queues rather than kills.
    pub state: State<'static>,
    /// `CLOCK_MONOTONIC` of the fake wait.
    pub now: u64,
    /// Number of `Task::wait` calls.
    pub waits: usize,
    /// Waits that no timer, signal or scripted event could end ([`Hang`]).
    pub hangs: usize,
    /// What other tasks do while this one sleeps: the next `wait` runs (and
    /// consumes) the first hook against the shared state and returns, as the
    /// wake-up it stands for would.
    pub on_wait: Vec<WaitHook>,
    /// Signals the fake delivers to the process when the clock reaches `at`.
    pub script: Vec<(u64, u8)>,
    /// The value the fake `rt_sigreturn` reports.
    pub sigreturn_ret: u64,
    /// The plain-copy requests `copy_process` served (the fake adds the child
    /// to the task list only; address space, descriptors and registers are
    /// the binary's and are exercised by the kernel-test cases).
    pub forked: Vec<ForkRequest>,
}

fn clock() -> Timespec {
    Timespec { sec: 0, nsec: 0 }
}

impl<P, C> Task<P, C> {
    pub fn new(pages: P, sink: C) -> Self {
        let env = Env::init(1 << 17, 0);
        let mut vfs = Vfs::new(1 << 20, 1 << 20, clock).expect("rootfs");
        vfs.default_rootfs().expect("default rootfs");
        let mut fdt = FdTable::default();
        vfs.console_on_rootfs(&mut fdt).expect("console");
        let mut attrs = Attributes::init(1000);
        attrs.fs = vfs.new_fs_struct(0o022);
        let (tasks, current) = Tasklist::new(1000, &attrs.cred, 1000).expect("task list");
        let state = State::standalone(1, 0, 1000);
        for sig in [SIGUSR1, SIGUSR2, SIGALRM] {
            state.hand.actions[usize::from(sig) - 1].handler = 0x4000;
        }
        Self {
            pages,
            sink,
            tgid: 1,
            attrs,
            fs_base: 0,
            gs_base: 0,
            machine: Machine {
                uptime_ns: 0,
                total_pages: 100,
                free_pages: 40,
                loads: [0; 3],
            },
            cpuid_fault_absent: false,
            xstate: crate::xstate::Config::fxsave(0xffbf),
            clocks: FakeClocks::default(),
            mm: Mm::new(&env),
            env,
            tables: Fake::default(),
            vfs,
            fdt,
            tty: crate::tty::Tty::new().expect("console tty"),
            file_pages: BTreeMap::new(),
            tasks,
            current,
            wake: NoWake,
            exe: None,
            started: None,
            random_state: 0,
            no_hw_random: false,
            state,
            now: 0,
            waits: 0,
            hangs: 0,
            on_wait: Vec::new(),
            script: Vec::new(),
            sigreturn_ret: 0,
            forked: Vec::new(),
        }
    }

    pub fn script_signal(&mut self, at: u64, sig: u8) {
        self.script.push((at, sig));
    }
}

pub fn task() -> Task {
    Task::new(Space::default(), Sink::default())
}

impl<P: UserPages, C> UserPages for Task<P, C> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; 4096]> {
        if self.pages.page(page, write).is_some() {
            return self.pages.page(page, write);
        }
        // A page of a private file mapping is supplied on first access.
        let vma = *self.mm.find_vma_intersection(page, page + 4096)?;
        let file = vma.file?;
        if !vma
            .flags
            .contains(if write { VmFlags::WRITE } else { VmFlags::READ })
        {
            return None;
        }
        if !self.file_pages.contains_key(&page) {
            let mut bytes = Box::new([0u8; 4096]);
            let pgoff = vma.pgoff + ((page - vma.start) >> 12);
            self.vfs.fault_page(0, file, pgoff, &mut bytes).ok()?;
            self.file_pages.insert(page, bytes);
        }
        self.file_pages.get_mut(&page).map(|bytes| &mut **bytes)
    }
}

impl<P: UserPages, C: Console> Context for Task<P, C> {
    fn tty_parts(&mut self) -> TtyParts<'_> {
        TtyParts {
            tty: &mut self.tty,
            tasks: Tasks {
                list: &mut self.tasks,
                current: self.current,
                wake: &mut self.wake,
            },
            console: &mut self.sink,
        }
    }
    fn tgid(&self) -> u32 {
        self.tgid
    }
    fn tid(&self) -> u32 {
        self.tgid
    }
    fn attrs(&mut self) -> &mut Attributes {
        &mut self.attrs
    }
    fn fs_base(&self) -> u64 {
        self.fs_base
    }
    fn set_fs_base(&mut self, base: u64) {
        self.fs_base = base;
    }
    fn gs_base(&self) -> u64 {
        self.gs_base
    }
    fn set_gs_base(&mut self, base: u64) {
        self.gs_base = base;
    }
    fn machine(&self) -> Machine {
        self.machine
    }
    fn cpuid_fault_absent(&self) -> bool {
        self.cpuid_fault_absent
    }
    fn xstate(&self) -> crate::xstate::Config {
        self.xstate
    }
    fn tasks(&mut self) -> Tasks<'_> {
        Tasks {
            list: &mut self.tasks,
            current: self.current,
            wake: &mut self.wake,
        }
    }
    fn replace_exe_file(&mut self, file: FileId) -> Option<FileId> {
        self.exe.replace(file)
    }
    fn exec_aux(&mut self) -> ExecAux {
        ExecAux {
            hwcap: 0x0183_fbff,
            random: *b"0123456789abcdef",
        }
    }
    fn hw_random(&mut self) -> Option<u64> {
        self.random_state = self.random_state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        (!self.no_hw_random).then_some(self.random_state)
    }
    fn start_thread(&mut self, ip: u64, sp: u64) {
        self.started = Some((ip, sp));
        self.fs_base = 0;
        self.gs_base = 0;
    }
    fn address_space(&mut self) -> AddressSpace<'_> {
        AddressSpace {
            mm: &mut self.mm,
            env: &self.env,
            pages: &mut self.tables,
        }
    }
    fn files(&mut self) -> Files<'_> {
        Files {
            vfs: &mut self.vfs,
            fdt: &mut self.fdt,
            fs: &mut self.attrs.fs,
            owner: 0,
        }
    }
    fn copy_process(&mut self, request: &ForkRequest) -> Result<i32, syscalls::Errno> {
        let params = ForkParams::of(&self.attrs, request);
        let child = self.tasks.fork(self.current, params)?;
        self.forked.push(*request);
        Ok(self.tasks.task_pid_vnr(child))
    }
}

impl<P: UserPages, C> Clocks for Task<P, C> {
    fn clock_state(&self) -> ClockState {
        self.clocks.state
    }
    fn set_realtime(&mut self, offset: i64, real_ns: i64) {
        self.clocks.set.push(offset);
        self.clocks.state.real_offset_ns = offset;
        self.clocks.state.settod_real_ns = real_ns;
    }
    fn set_restart_block(&mut self, block: RestartBlock) {
        self.clocks.restarts.push(block);
    }
    fn restart_block(&self) -> RestartBlock {
        self.clocks
            .restarts
            .last()
            .copied()
            .unwrap_or(RestartBlock::NONE)
    }
    fn cpu_sample(&self) -> CpuSample {
        self.clocks.sample
    }
    fn cpu_adjusted(&mut self) -> (u64, u64) {
        self.clocks.adjusted
    }
    fn sleep_until(&mut self, deadline_ns: u64) -> Option<u64> {
        self.clocks.slept.push(deadline_ns);
        if self.clocks.real_sleep {
            return signal::wait::sleep_until(self, deadline_ns);
        }
        self.clocks.interrupt.take()
    }
    fn capable_sys_time(&self) -> bool {
        self.clocks.capable
    }
    fn capable_wake_alarm(&self) -> bool {
        self.clocks.capable
    }
    fn alarm_rtc(&self) -> bool {
        self.clocks.rtc
    }
}

impl<P: UserPages, C> signal::Task for Task<P, C> {
    type Pages<'a>
        = &'a mut P
    where
        Self: 'a;
    fn state(&mut self) -> State<'_> {
        self.state.reborrow()
    }
    fn parts(&mut self) -> (State<'_>, &mut P) {
        (self.state.reborrow(), &mut self.pages)
    }
    fn now_ns(&self) -> u64 {
        self.now
    }
    /// Advance the clock to the earliest of the deadline, the interval timer
    /// and the scripted signals, then deliver the scripted ones that are due.
    fn wait(&mut self, _key: WaitKey, deadline_ns: Option<u64>) {
        self.waits += 1;
        if !self.on_wait.is_empty() {
            let hook = self.on_wait.remove(0);
            hook(&mut self.vfs, &mut self.fdt);
            return;
        }
        let Some(next) = deadline_ns
            .into_iter()
            .chain(self.state.sig.itimer.next_event())
            .chain(self.script.iter().map(|&(at, _)| at))
            .min()
        else {
            // Nothing could ever wake the task (the real kernel sleeps forever,
            // as Linux would): unwind to the test without the panic hook.
            self.hangs += 1;
            std::panic::resume_unwind(Box::new(Hang));
        };
        self.now = self.now.max(next);
        let now = self.now;
        let (due, later): (Vec<_>, Vec<_>) = self.script.drain(..).partition(|&(at, _)| at <= now);
        self.script = later;
        for (_, sig) in due {
            let _ = self
                .state
                .send_signal(sig, SigInfo::kernel(sig), Target::Process);
        }
    }
    fn user_sp(&self) -> u64 {
        0x7fff_0000
    }
    fn rt_sigreturn(&mut self) -> Sigreturn {
        Sigreturn {
            ret: self.sigreturn_ret,
            bad_frame: false,
            reached_sigcontext: true,
        }
    }
}
