// SPDX-License-Identifier: GPL-2.0-only
use super::*;

fn rq(capacity: usize) -> Rq {
    Rq::new(capacity).unwrap()
}

/// A runnable task.
fn spawn(rq: &mut Rq) -> SchedId {
    let id = rq.add_task().unwrap();
    assert!(rq.wake_up_new_task(id));
    id
}

fn key(id: u32) -> WaitKey {
    WaitKey::new(CLASS_TEST, id)
}

#[test]
fn fifo_order_is_deterministic_and_idle_takes_over() {
    let mut rq = rq(8);
    let idle = rq.idle();
    let tasks = [spawn(&mut rq), spawn(&mut rq), spawn(&mut rq)];
    assert_eq!(rq.nr_active(), 3);
    // idle -> a (first in), then each yields to the next in arrival order.
    let mut order = Vec::new();
    for _ in 0..7 {
        let switch = rq.schedule().unwrap();
        order.push(switch.next);
    }
    assert_eq!(
        order,
        [
            tasks[0], tasks[1], tasks[2], tasks[0], tasks[1], tasks[2], tasks[0]
        ]
    );
    assert_ne!(rq.curr(), idle);
}

#[test]
fn the_only_runnable_task_keeps_the_cpu() {
    let mut rq = rq(4);
    let a = spawn(&mut rq);
    assert_eq!(rq.schedule().unwrap().next, a);
    assert_eq!(rq.schedule(), None);
    assert_eq!(rq.curr(), a);
}

#[test]
fn a_sleeper_leaves_the_queue_and_idle_runs_when_all_sleep() {
    let mut rq = rq(4);
    let a = spawn(&mut rq);
    let idle = rq.idle();
    assert_eq!(rq.schedule().unwrap().next, a);
    rq.prepare_to_wait(key(1), TaskState::Interruptible);
    let switch = rq.schedule().unwrap();
    assert_eq!((switch.prev, switch.next), (a, idle));
    assert_eq!(rq.state(a), Some(TaskState::Interruptible));
    assert!(!rq.has_runnable());
    // Idle with nothing to run stays idle.
    assert_eq!(rq.schedule(), None);
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Normal, 0), 1);
    assert!(rq.has_runnable());
    assert_eq!(rq.schedule().unwrap().next, a);
    rq.finish_wait();
    assert_eq!(rq.state(a), Some(TaskState::Running));
}

/// Put the tasks to sleep one after the other, in the order given.
fn sleep_in_order(rq: &mut Rq, sleepers: &[(SchedId, WaitKey, bool, TaskState)]) {
    for &(task, wait_key, exclusive, state) in sleepers {
        while rq.curr() != task {
            rq.schedule();
        }
        if exclusive {
            rq.prepare_to_wait_exclusive(wait_key, state);
        } else {
            rq.prepare_to_wait(wait_key, state);
        }
        rq.schedule();
    }
}

/// The order tasks leave the queue in after the wake-ups so far.
fn run_order(rq: &mut Rq, count: usize) -> Vec<SchedId> {
    (0..count).map(|_| rq.schedule().unwrap().next).collect()
}

#[test]
fn wake_up_key_wakes_only_that_key_newest_non_exclusive_first() {
    use TaskState::Uninterruptible as U;
    let mut rq = rq(8);
    let [a, b, c] = [spawn(&mut rq), spawn(&mut rq), spawn(&mut rq)];
    // Sleep order a (key 1), b (key 2), c (key 1).
    sleep_in_order(
        &mut rq,
        &[
            (a, key(1), false, U),
            (b, key(2), false, U),
            (c, key(1), false, U),
        ],
    );
    assert_eq!(rq.wake_up_key(WaitKey::NONE, WakeMode::Normal, 0), 0);
    assert_eq!(rq.wake_up_key(key(3), WakeMode::Normal, 0), 0);
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Normal, 0), 2);
    assert_eq!(rq.state(b), Some(TaskState::Uninterruptible));
    // `prepare_to_wait_event` queues a non-exclusive waiter at the head and
    // `__wake_up_common` walks from there: c slept after a, so c wakes first
    // (kernel/sched/wait.c:93-117, :290-320; include/linux/wait.h:171-182).
    assert_eq!(run_order(&mut rq, 2), [c, a]);
}

#[test]
fn exclusive_waiters_queue_behind_and_wake_oldest_first_up_to_the_count() {
    use TaskState::Interruptible as I;
    let mut rq = rq(8);
    let [x1, n1, x2, n2, x3] = [(); 5].map(|()| spawn(&mut rq));
    sleep_in_order(
        &mut rq,
        &[
            (x1, key(1), true, I),
            (n1, key(1), false, I),
            (x2, key(1), true, I),
            (n2, key(1), false, I),
            (x3, key(1), true, I),
        ],
    );
    // Queue, head first: n2 n1 x1 x2 x3. `wake_up` (nr_exclusive 1) wakes all
    // non-exclusive waiters and the first exclusive one, then stops.
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Normal, 1), 3);
    assert_eq!(run_order(&mut rq, 3), [n2, n1, x1]);
    assert_eq!(rq.state(x2), Some(I));
    assert_eq!(rq.state(x3), Some(I));
    // Each further `wake_up` takes the oldest remaining exclusive waiter.
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Normal, 1), 1);
    assert_eq!(rq.state(x2), Some(TaskState::Running));
    assert_eq!(rq.state(x3), Some(I));
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Normal, 1), 1);
    assert_eq!(rq.state(x3), Some(TaskState::Running));
}

#[test]
fn wake_up_all_wakes_every_exclusive_waiter_too() {
    use TaskState::Interruptible as I;
    let mut rq = rq(8);
    let [x1, x2] = [spawn(&mut rq), spawn(&mut rq)];
    sleep_in_order(&mut rq, &[(x1, key(1), true, I), (x2, key(1), true, I)]);
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Normal, 0), 2);
}

#[test]
fn interruptible_mode_skips_uninterruptible_sleepers_without_using_the_count() {
    let mut rq = rq(8);
    let [u, i] = [spawn(&mut rq), spawn(&mut rq)];
    // The uninterruptible exclusive waiter is first in the queue but not
    // selected by the mode: `try_to_wake_up` returns 0 and the scan goes on, so
    // the count is spent on the interruptible one.
    sleep_in_order(
        &mut rq,
        &[
            (u, key(1), true, TaskState::Uninterruptible),
            (i, key(1), true, TaskState::Interruptible),
        ],
    );
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Interruptible, 1), 1);
    assert_eq!(rq.state(u), Some(TaskState::Uninterruptible));
    assert_eq!(rq.state(i), Some(TaskState::Running));
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Normal, 1), 1);
}

#[test]
fn reset_drops_every_task_and_returns_to_idle() {
    let mut rq = rq(4);
    let [a, b] = [spawn(&mut rq), spawn(&mut rq)];
    // Both sleep, so idle is current; c is queued and the tick asked for a switch.
    sleep_in_order(
        &mut rq,
        &[
            (a, key(1), false, TaskState::Interruptible),
            (b, key(2), false, TaskState::Uninterruptible),
        ],
    );
    assert_eq!(rq.curr(), rq.idle());
    let c = spawn(&mut rq);
    rq.tick();
    assert!(rq.need_resched());
    rq.reset();
    assert_eq!(rq.state(c), None);
    assert_eq!(rq.state(a), None);
    assert_eq!(rq.state(b), None);
    assert!(!rq.has_runnable() && !rq.need_resched());
    assert_eq!(rq.nr_active(), 0);
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Normal, 0), 0);
    // All slots are available again, with new generations.
    let d = rq.add_task().unwrap();
    assert_ne!(d, a);
}

#[test]
fn signal_wakes_interruptible_only() {
    let mut rq = rq(4);
    let [a, b] = [spawn(&mut rq), spawn(&mut rq)];
    assert_eq!(rq.schedule().unwrap().next, a);
    rq.prepare_to_wait(WaitKey::NONE, TaskState::Interruptible);
    rq.schedule();
    rq.prepare_to_wait(WaitKey::NONE, TaskState::Uninterruptible);
    rq.schedule();
    assert!(!rq.wake_interruptible(b));
    assert!(rq.wake_interruptible(a));
    assert!(!rq.wake_interruptible(a), "already running");
    assert!(rq.try_to_wake_up(b));
    assert!(!rq.try_to_wake_up(b));
}

#[test]
fn waking_the_current_task_does_not_queue_it() {
    let mut rq = rq(4);
    let a = spawn(&mut rq);
    rq.schedule();
    rq.prepare_to_wait(key(1), TaskState::Interruptible);
    // A wake between prepare_to_wait and schedule(): no switch, still current.
    assert_eq!(rq.wake_up_key(key(1), WakeMode::Normal, 0), 1);
    assert!(!rq.has_runnable());
    assert_eq!(rq.schedule(), None);
    assert_eq!(rq.curr(), a);
}

#[test]
fn tick_rotates_only_when_someone_waits() {
    let mut rq = rq(4);
    let a = spawn(&mut rq);
    rq.schedule();
    rq.tick();
    assert!(!rq.need_resched(), "nobody else runnable");
    let b = spawn(&mut rq);
    rq.tick();
    assert!(rq.need_resched());
    assert_eq!(rq.schedule().unwrap().next, b);
    assert!(!rq.need_resched());
    assert_eq!(rq.state(a), Some(TaskState::Running));
}

#[test]
fn idle_is_asked_to_reschedule_when_work_arrives() {
    let mut rq = rq(4);
    rq.tick();
    assert!(!rq.need_resched());
    spawn(&mut rq);
    rq.tick();
    assert!(rq.need_resched());
}

#[test]
fn dead_task_is_freed_by_the_next_and_its_handle_goes_stale() {
    let mut rq = rq(3);
    let a = spawn(&mut rq);
    let b = spawn(&mut rq);
    assert_eq!(rq.schedule().unwrap().next, a);
    rq.exit_current();
    assert_eq!(rq.state(a), Some(TaskState::Dead));
    let switch = rq.schedule().unwrap();
    assert_eq!((switch.prev, switch.next), (a, b));
    assert_eq!(rq.nr_active(), 1);
    assert!(!rq.free(b), "the current task is never freed");
    assert!(rq.free(a));
    assert!(!rq.free(a), "stale");
    assert_eq!(rq.state(a), None);
    assert!(!rq.try_to_wake_up(a));
    // The slot is reused with a new generation.
    let c = rq.add_task().unwrap();
    assert_eq!(c.index(), a.index());
    assert_ne!(c, a);
    assert_eq!(rq.state(a), None);
    assert_eq!(rq.state(c), Some(TaskState::Running));
}

#[test]
fn slots_are_bounded() {
    let mut rq = rq(3);
    assert!(rq.add_task().is_ok());
    assert!(rq.add_task().is_ok());
    assert_eq!(rq.add_task(), Err(NoSlot));
}

#[test]
fn a_new_task_cannot_be_queued_twice() {
    let mut rq = rq(4);
    let a = spawn(&mut rq);
    assert!(!rq.wake_up_new_task(a));
    assert!(!rq.wake_up_new_task(rq.idle()));
}
