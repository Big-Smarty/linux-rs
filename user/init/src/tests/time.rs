// SPDX-License-Identifier: GPL-2.0-only
//! `time` group: clocks, resolution, `gettimeofday`/`time`/`times`, `nanosleep` and
//! `clock_nanosleep`. Linux 6.18.57: `kernel/time/posix-timers.c`, `posix-stubs.c`,
//! `posix-cpu-timers.c`, `time.c`, `hrtimer.c` (`hrtimer_nanosleep`), `alarmtimer.c`,
//! `include/uapi/linux/time.h`. Only durations and orderings are checked, never absolute
//! monotonic values; resolution values hold for the reference configuration (`HZ=1000`,
//! high-resolution timers active), recorded in `init-reference-005`.

use syscalls::{Errno, Sysno};

use super::{R, T, addr, addr_mut, suite_start, sys};

const BAD: usize = 0xdead_0000_0000;
const ABSTIME: usize = 1;

const REALTIME: usize = 0;
const MONOTONIC: usize = 1;
const PROCESS_CPUTIME: usize = 2;
const THREAD_CPUTIME: usize = 3;
const MONOTONIC_RAW: usize = 4;
const REALTIME_COARSE: usize = 5;
const MONOTONIC_COARSE: usize = 6;
const BOOTTIME: usize = 7;
const REALTIME_ALARM: usize = 8;
const BOOTTIME_ALARM: usize = 9;
const SGI_CYCLE: usize = 10;
const TAI: usize = 11;

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

impl Timespec {
    fn ns(self) -> i64 {
        self.sec * 1_000_000_000 + self.nsec
    }
}

fn gettime(clock: usize) -> (R, Timespec) {
    let mut ts = Timespec { sec: -1, nsec: -1 };
    (sys(Sysno::clock_gettime, &[clock, addr_mut(&mut ts)]), ts)
}

fn getres(clock: usize) -> (R, Timespec) {
    let mut ts = Timespec { sec: -1, nsec: -1 };
    (sys(Sysno::clock_getres, &[clock, addr_mut(&mut ts)]), ts)
}

fn now(clock: usize) -> i64 {
    gettime(clock).1.ns()
}

fn nanosleep(req: &Timespec) -> R {
    sys(Sysno::nanosleep, &[addr(req), 0])
}

fn clock_nanosleep(clock: usize, flags: usize, req: &Timespec) -> R {
    sys(Sysno::clock_nanosleep, &[clock, flags, addr(req), 0])
}

pub fn run() -> bool {
    let mut t = T::new("time");
    clocks(&mut t);
    resolution(&mut t);
    wall_time(&mut t);
    sleeping(&mut t);
    settime_and_cpu_sleep(&mut t);
    t.finish()
}

fn clocks(t: &mut T) {
    let supported = [
        ("realtime", REALTIME),
        ("monotonic", MONOTONIC),
        ("process-cputime", PROCESS_CPUTIME),
        ("thread-cputime", THREAD_CPUTIME),
        ("monotonic-raw", MONOTONIC_RAW),
        ("realtime-coarse", REALTIME_COARSE),
        ("monotonic-coarse", MONOTONIC_COARSE),
        ("boottime", BOOTTIME),
        ("tai", TAI),
    ];
    for (name, clock) in supported {
        let (r, ts) = gettime(clock);
        t.holds(
            format_args!("gettime-{name}"),
            r == Ok(0) && ts.sec >= 0 && (0..1_000_000_000).contains(&ts.nsec),
            (r, ts),
            "Ok(0) with a normalised timespec",
        );
    }
    // The alarm clocks need an RTC wakeup device (`alarmtimer_get_rtcdev`); QEMU provides one.
    for (name, clock) in [
        ("realtime-alarm", REALTIME_ALARM),
        ("boottime-alarm", BOOTTIME_ALARM),
    ] {
        t.eq(format_args!("gettime-{name}"), gettime(clock).0, Ok(0));
    }
    for (name, clock) in [
        ("sgi-cycle", SGI_CYCLE),
        ("12", 12),
        ("255", 255),
        ("int-max", 0x7fff_ffff),
    ] {
        t.eq(
            format_args!("gettime-invalid-{name}"),
            gettime(clock).0,
            Err(Errno::EINVAL),
        );
    }
    t.eq(
        "gettime-fault",
        sys(Sysno::clock_gettime, &[MONOTONIC, BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "gettime-null",
        sys(Sysno::clock_gettime, &[REALTIME, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "gettime-invalid-clock-before-fault",
        sys(Sysno::clock_gettime, &[12, BAD]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "gettime-invalid-clock-untouched",
        gettime(12).1,
        Timespec { sec: -1, nsec: -1 },
    );

    // Orderings.
    let mut last = 0;
    let mut monotonic_ok = true;
    for _ in 0..100 {
        let n = now(MONOTONIC);
        monotonic_ok &= n >= last;
        last = n;
    }
    t.eq("monotonic-never-goes-back", monotonic_ok, true);
    // The coarse clock is read first: read after `mono`, a tick between the two
    // reads (likely on a slow emulated CPU) puts it ahead of `mono` on Linux too.
    let coarse = now(MONOTONIC_COARSE);
    let (mono, raw, boot) = (now(MONOTONIC), now(MONOTONIC_RAW), now(BOOTTIME));
    let (rt, rt_coarse, tai) = (now(REALTIME), now(REALTIME_COARSE), now(TAI));
    t.holds(
        "boottime-ge-monotonic",
        boot >= mono - 1_000_000,
        (boot, mono),
        "boottime >= monotonic",
    );
    t.holds(
        "boottime-equals-monotonic-without-suspend",
        boot - mono < 1_000_000_000,
        boot - mono,
        "< 1 s apart",
    );
    t.holds(
        "monotonic-raw-near-monotonic",
        (raw - mono).abs() < 1_000_000_000,
        raw - mono,
        "< 1 s apart",
    );
    t.holds(
        "monotonic-coarse-near-monotonic",
        (0..=50_000_000).contains(&(mono - coarse)),
        mono - coarse,
        "within one tick of monotonic, never ahead",
    );
    // The suite starts each group long after boot: the bound counts from there.
    let from = suite_start().unwrap_or(0) as i64 * 1_000_000_000;
    t.holds(
        "monotonic-since-boot",
        mono > from.max(0) && mono < from + 120_000_000_000,
        mono,
        "0 < up < 120 s (counted from the group's start in the suite)",
    );
    t.holds(
        "realtime-plausible",
        rt >= 1_704_067_200 * 1_000_000_000,
        rt / 1_000_000_000,
        "after 2024-01-01",
    );
    t.holds(
        "realtime-coarse-near-realtime",
        (rt - rt_coarse).abs() < 50_000_000,
        rt - rt_coarse,
        "within 50 ms",
    );
    t.holds(
        "tai-offset-zero",
        (tai - rt).abs() < 50_000_000,
        tai - rt,
        "TAI == realtime (tai_offset 0)",
    );
    let (p0, th0) = (now(PROCESS_CPUTIME), now(THREAD_CPUTIME));
    let mut spin = 0u64;
    for i in 0..2_000_000u64 {
        spin = core::hint::black_box(spin.wrapping_add(i));
    }
    let (p1, th1) = (now(PROCESS_CPUTIME), now(THREAD_CPUTIME));
    t.holds(
        "cputime-advances-with-work",
        p1 > p0 && th1 > th0 && p1 < 30_000_000_000 && th1 < 30_000_000_000,
        (p0, p1, th0, th1, spin),
        "both CPU clocks advance and stay small",
    );
    // clock_settime on clocks that cannot be set (none of the settable ones is touched).
    let zero = Timespec::default();
    for (name, clock) in [
        ("monotonic", MONOTONIC),
        ("boottime", BOOTTIME),
        ("monotonic-raw", MONOTONIC_RAW),
        ("coarse", REALTIME_COARSE),
        ("invalid", 12),
    ] {
        t.eq(
            format_args!("settime-{name}"),
            sys(Sysno::clock_settime, &[clock, addr(&zero)]),
            Err(Errno::EINVAL),
        );
    }
    t.eq(
        "settime-cputime-denied",
        sys(Sysno::clock_settime, &[PROCESS_CPUTIME, addr(&zero)]),
        Err(Errno::EINVAL),
    );
}

/// Waits (bounded) until the monotonic clock reports 1 ns: Linux switches `hrtimer`s to
/// high-resolution mode some time after boot, once a suitable clocksource and one-shot clock
/// event device exist, and reports the tick (1 ms) before that.
fn wait_for_high_resolution() {
    for _ in 0..200 {
        if getres(MONOTONIC).1.nsec == 1 {
            return;
        }
        let _ = nanosleep(&Timespec {
            sec: 0,
            nsec: 50_000_000,
        });
    }
}

fn resolution(t: &mut T) {
    wait_for_high_resolution();
    // High-resolution timers: every hrtimer-backed clock reports 1 ns; the coarse clocks report
    // one tick (HZ=1000 -> 1 ms); the CPU-time clocks report 1 ns.
    let tick = Timespec {
        sec: 0,
        nsec: 1_000_000,
    };
    let ns = Timespec { sec: 0, nsec: 1 };
    for (name, clock, want) in [
        ("realtime", REALTIME, ns),
        ("monotonic", MONOTONIC, ns),
        ("process-cputime", PROCESS_CPUTIME, ns),
        ("thread-cputime", THREAD_CPUTIME, ns),
        ("monotonic-raw", MONOTONIC_RAW, ns),
        ("realtime-coarse", REALTIME_COARSE, tick),
        ("monotonic-coarse", MONOTONIC_COARSE, tick),
        ("boottime", BOOTTIME, ns),
        ("realtime-alarm", REALTIME_ALARM, ns),
        ("boottime-alarm", BOOTTIME_ALARM, ns),
        ("tai", TAI, ns),
    ] {
        t.eq(format_args!("getres-{name}"), getres(clock), (Ok(0), want));
    }
    t.eq(
        "getres-null",
        sys(Sysno::clock_getres, &[MONOTONIC, 0]),
        Ok(0),
    );
    t.eq("getres-invalid", getres(12).0, Err(Errno::EINVAL));
    t.eq(
        "getres-invalid-null",
        sys(Sysno::clock_getres, &[12, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "getres-fault",
        sys(Sysno::clock_getres, &[MONOTONIC, BAD]),
        Err(Errno::EFAULT),
    );
}

fn wall_time(t: &mut T) {
    #[repr(C)]
    #[derive(Default, Debug)]
    struct Timeval {
        sec: i64,
        usec: i64,
    }
    #[repr(C)]
    #[derive(Debug)]
    struct Timezone {
        minuteswest: i32,
        dsttime: i32,
    }
    let mut tv = Timeval::default();
    let mut tz = Timezone {
        minuteswest: 77,
        dsttime: 77,
    };
    let r = sys(Sysno::gettimeofday, &[addr_mut(&mut tv), addr_mut(&mut tz)]);
    let rt = gettime(REALTIME).1;
    t.eq("gettimeofday", r, Ok(0));
    t.holds(
        "gettimeofday-usec-range",
        (0..1_000_000).contains(&tv.usec),
        tv.usec,
        "0 <= usec < 1e6",
    );
    t.holds(
        "gettimeofday-matches-clock_gettime",
        (rt.sec - tv.sec).abs() <= 1,
        (tv.sec, rt.sec),
        "within a second of CLOCK_REALTIME",
    );
    t.eq(
        "gettimeofday-timezone-zero",
        (tz.minuteswest, tz.dsttime),
        (0, 0),
    );
    t.eq(
        "gettimeofday-tv-only",
        sys(Sysno::gettimeofday, &[addr_mut(&mut tv), 0]),
        Ok(0),
    );
    t.eq(
        "gettimeofday-tz-only",
        sys(Sysno::gettimeofday, &[0, addr_mut(&mut tz)]),
        Ok(0),
    );
    t.eq(
        "gettimeofday-neither",
        sys(Sysno::gettimeofday, &[0, 0]),
        Ok(0),
    );
    t.eq(
        "gettimeofday-fault-tv",
        sys(Sysno::gettimeofday, &[BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "gettimeofday-fault-tz",
        sys(Sysno::gettimeofday, &[0, BAD]),
        Err(Errno::EFAULT),
    );

    let mut stored = 0i64;
    let secs = sys(Sysno::time, &[0]).unwrap_or(0);
    let via_ptr = sys(Sysno::time, &[addr_mut(&mut stored)]).unwrap_or(1);
    t.holds(
        "time",
        secs as i64 >= 1_704_067_200 && (secs as i64 - rt.sec).abs() <= 2,
        (secs, rt.sec),
        "seconds of CLOCK_REALTIME",
    );
    t.holds(
        "time-stores-result",
        stored as usize == via_ptr && (via_ptr as i64 - secs as i64).abs() <= 1,
        (stored, via_ptr),
        "stored == returned",
    );
    t.eq("time-fault", sys(Sysno::time, &[BAD]), Err(Errno::EFAULT));

    #[repr(C)]
    #[derive(Default)]
    struct Tms {
        utime: i64,
        stime: i64,
        cutime: i64,
        cstime: i64,
    }
    let mut tms = Tms::default();
    let a = sys(Sysno::times, &[addr_mut(&mut tms)]);
    let b = sys(Sysno::times, &[0]);
    t.holds(
        "times",
        matches!((a, b), (Ok(x), Ok(y)) if x > 0 && y >= x),
        (a, b),
        "ticks since boot, non-decreasing",
    );
    t.eq("times-children-zero", (tms.cutime, tms.cstime), (0, 0));
    t.holds(
        "times-small-cpu",
        tms.utime + tms.stime < 3000,
        (tms.utime, tms.stime),
        "< 30 s of CPU",
    );
    t.eq("times-fault", sys(Sysno::times, &[BAD]), Err(Errno::EFAULT));
}

fn sleeping(t: &mut T) {
    let ms = |n: i64| Timespec {
        sec: 0,
        nsec: n * 1_000_000,
    };
    let start = now(MONOTONIC);
    t.eq("nanosleep-20ms", nanosleep(&ms(20)), Ok(0));
    let slept = now(MONOTONIC) - start;
    t.holds(
        "nanosleep-elapsed",
        (20_000_000..1_000_000_000).contains(&slept),
        slept,
        "20 ms <= elapsed < 1 s",
    );
    t.eq("nanosleep-zero", nanosleep(&Timespec::default()), Ok(0));
    let rem_before = Timespec { sec: 5, nsec: 5 };
    let mut rem = rem_before;
    let r = sys(Sysno::nanosleep, &[addr(&ms(1)), addr_mut(&mut rem)]);
    t.eq(
        "nanosleep-rem-untouched-on-success",
        (r, rem),
        (Ok(0), rem_before),
    );
    t.eq(
        "nanosleep-nsec-too-big",
        nanosleep(&Timespec {
            sec: 0,
            nsec: 1_000_000_000,
        }),
        Err(Errno::EINVAL),
    );
    t.eq(
        "nanosleep-nsec-negative",
        nanosleep(&Timespec { sec: 0, nsec: -1 }),
        Err(Errno::EINVAL),
    );
    t.eq(
        "nanosleep-sec-negative",
        nanosleep(&Timespec { sec: -1, nsec: 0 }),
        Err(Errno::EINVAL),
    );
    t.eq(
        "nanosleep-fault",
        sys(Sysno::nanosleep, &[BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "nanosleep-null",
        sys(Sysno::nanosleep, &[0, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "nanosleep-bad-rem-ignored-on-success",
        sys(Sysno::nanosleep, &[addr(&ms(1)), BAD]),
        Ok(0),
    );

    for (name, clock) in [
        ("realtime", REALTIME),
        ("monotonic", MONOTONIC),
        ("boottime", BOOTTIME),
        ("tai", TAI),
    ] {
        let start = now(MONOTONIC);
        t.eq(
            format_args!("clock_nanosleep-rel-{name}"),
            clock_nanosleep(clock, 0, &ms(10)),
            Ok(0),
        );
        let slept = now(MONOTONIC) - start;
        t.holds(
            format_args!("clock_nanosleep-rel-{name}-elapsed"),
            (10_000_000..1_000_000_000).contains(&slept),
            slept,
            "10 ms <= elapsed < 1 s",
        );
    }
    for (name, clock) in [
        ("monotonic", MONOTONIC),
        ("realtime", REALTIME),
        ("boottime", BOOTTIME),
    ] {
        let start = now(MONOTONIC);
        let deadline = gettime(clock).1;
        let abs = Timespec {
            sec: deadline.sec,
            nsec: deadline.nsec + 20_000_000,
        };
        let abs = Timespec {
            sec: abs.sec + abs.nsec / 1_000_000_000,
            nsec: abs.nsec % 1_000_000_000,
        };
        t.eq(
            format_args!("clock_nanosleep-abs-{name}"),
            clock_nanosleep(clock, ABSTIME, &abs),
            Ok(0),
        );
        let slept = now(MONOTONIC) - start;
        t.holds(
            format_args!("clock_nanosleep-abs-{name}-elapsed"),
            (20_000_000..1_000_000_000).contains(&slept) && gettime(clock).1.ns() >= abs.ns(),
            slept,
            "returns at or after the absolute deadline",
        );
        let past = Timespec { sec: 0, nsec: 1 };
        let start = now(MONOTONIC);
        t.eq(
            format_args!("clock_nanosleep-abs-{name}-past"),
            clock_nanosleep(clock, ABSTIME, &past),
            Ok(0),
        );
        let slept = now(MONOTONIC) - start;
        t.holds(
            format_args!("clock_nanosleep-abs-{name}-past-immediate"),
            slept < 10_000_000,
            slept,
            "returns at once",
        );
    }
    t.eq(
        "clock_nanosleep-abs-zero",
        clock_nanosleep(MONOTONIC, ABSTIME, &Timespec::default()),
        Ok(0),
    );
    t.eq(
        "clock_nanosleep-nsec-too-big",
        clock_nanosleep(
            MONOTONIC,
            0,
            &Timespec {
                sec: 0,
                nsec: 1_000_000_000,
            },
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clock_nanosleep-nsec-negative",
        clock_nanosleep(MONOTONIC, 0, &Timespec { sec: 0, nsec: -1 }),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clock_nanosleep-sec-negative",
        clock_nanosleep(MONOTONIC, 0, &Timespec { sec: -1, nsec: 0 }),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clock_nanosleep-abs-nsec-too-big",
        clock_nanosleep(
            MONOTONIC,
            ABSTIME,
            &Timespec {
                sec: 0,
                nsec: 2_000_000_000,
            },
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clock_nanosleep-invalid-clock",
        clock_nanosleep(12, 0, &ms(1)),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clock_nanosleep-sgi-cycle",
        clock_nanosleep(SGI_CYCLE, 0, &ms(1)),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clock_nanosleep-raw",
        clock_nanosleep(MONOTONIC_RAW, 0, &ms(1)),
        Err(Errno::EOPNOTSUPP),
    );
    t.eq(
        "clock_nanosleep-coarse",
        clock_nanosleep(MONOTONIC_COARSE, 0, &ms(1)),
        Err(Errno::EOPNOTSUPP),
    );
    t.eq(
        "clock_nanosleep-thread-cputime",
        clock_nanosleep(THREAD_CPUTIME, 0, &ms(1)),
        Err(Errno::EOPNOTSUPP),
    );
    t.eq(
        "clock_nanosleep-fault",
        sys(Sysno::clock_nanosleep, &[MONOTONIC, 0, BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "clock_nanosleep-invalid-flag-bits",
        clock_nanosleep(MONOTONIC, 2, &ms(1)),
        Ok(0),
    );
}

/// Paths that answer at once without a successful `clock_settime` or CPU-clock wait ever having
/// been observed above: `do_settimeofday64` stores `xtime` exactly (`time` is the new second
/// immediately), and `do_cpu_nanosleep` returns 0 for a zero expiry or an absolute one that has
/// passed (`posix_cpu_timer_set` arms nothing, resp. fires at once).
fn settime_and_cpu_sleep(t: &mut T) {
    const SET: i64 = 2_000_000_000;
    let (real0, mono0) = (now(REALTIME), now(MONOTONIC));
    let set = Timespec { sec: SET, nsec: 0 };
    t.eq(
        "settime-realtime",
        sys(Sysno::clock_settime, &[REALTIME, addr(&set)]),
        Ok(0),
    );
    t.eq(
        "settime-time-at-once",
        sys(Sysno::time, &[0]),
        Ok(SET as usize),
    );
    t.eq(
        "settime-coarse-at-once",
        gettime(REALTIME_COARSE).1.sec,
        SET,
    );
    let read_back = now(REALTIME) - SET * 1_000_000_000;
    t.holds(
        "settime-realtime-reads-back",
        (0..50_000_000).contains(&read_back),
        read_back,
        "0 <= elapsed < 50 ms after the set time",
    );
    // Put the clock back so later groups see the real time.
    let back = real0 + (now(MONOTONIC) - mono0);
    let restore = Timespec {
        sec: back / 1_000_000_000,
        nsec: back % 1_000_000_000,
    };
    t.eq(
        "settime-restore",
        sys(Sysno::clock_settime, &[REALTIME, addr(&restore)]),
        Ok(0),
    );

    let zero = Timespec::default();
    let one_ns = Timespec { sec: 0, nsec: 1 };
    // `make_process_cpuclock(1, CPUCLOCK_SCHED)`: this process by pid.
    let by_pid = (-14i32) as usize;
    t.eq(
        "cpu-nanosleep-zero",
        clock_nanosleep(PROCESS_CPUTIME, 0, &zero),
        Ok(0),
    );
    t.eq(
        "cpu-nanosleep-abs-zero",
        clock_nanosleep(PROCESS_CPUTIME, ABSTIME, &zero),
        Ok(0),
    );
    t.eq(
        "cpu-nanosleep-abs-past",
        clock_nanosleep(PROCESS_CPUTIME, ABSTIME, &one_ns),
        Ok(0),
    );
    t.eq(
        "cpu-nanosleep-by-pid-zero",
        clock_nanosleep(by_pid, 0, &zero),
        Ok(0),
    );
    t.eq(
        "cpu-nanosleep-by-pid-abs-past",
        clock_nanosleep(by_pid, ABSTIME, &one_ns),
        Ok(0),
    );
}
