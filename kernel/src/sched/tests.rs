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
    assert_eq!(rq.wake_up_key(key(1)), 1);
    assert!(rq.has_runnable());
    assert_eq!(rq.schedule().unwrap().next, a);
    rq.finish_wait();
    assert_eq!(rq.state(a), Some(TaskState::Running));
}

#[test]
fn wake_up_key_wakes_only_that_key_longest_sleeper_first() {
    let mut rq = rq(8);
    let [a, b, c] = [spawn(&mut rq), spawn(&mut rq), spawn(&mut rq)];
    // Sleep order a (key 1), b (key 2), c (key 1).
    for (task, wait_key) in [(a, key(1)), (b, key(2)), (c, key(1))] {
        while rq.curr() != task {
            rq.schedule();
        }
        rq.prepare_to_wait(wait_key, TaskState::Uninterruptible);
        rq.schedule();
    }
    assert_eq!(rq.wake_up_key(WaitKey::NONE), 0);
    assert_eq!(rq.wake_up_key(key(3)), 0);
    assert_eq!(rq.wake_up_key(key(1)), 2);
    assert_eq!(rq.state(b), Some(TaskState::Uninterruptible));
    // a slept before c, so a is queued first.
    assert_eq!(rq.schedule().unwrap().next, a);
    assert_eq!(rq.schedule().unwrap().next, c);
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
    assert_eq!(rq.wake_up_key(key(1)), 1);
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
