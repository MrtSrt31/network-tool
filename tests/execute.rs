//! Integration tests for the streaming command executor.
//!
//! These tests pin down three operational guarantees of `execute_streaming`:
//!
//! 1. **No deadlock on busy children.** A `yes`-style producer that would
//!    otherwise fill the stdout pipe is drained by a dedicated reader thread,
//!    and a short watchdog timeout kills it cleanly.
//! 2. **Both streams are captured independently.** A child that writes to
//!    stdout and stderr simultaneously yields lines on both tags.
//! 3. **External cancel works within one tick.** Setting the shared stop flag
//!    kills a sleeping child in well under one second.
//!
//! The tests only use POSIX `sh` fixtures, which are present on both macOS and
//! Linux (this project does not target Windows).

use network_tool::modules::{execute_streaming, LineTag};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn sh(script: &str) -> (String, Vec<String>) {
    ("sh".to_string(), vec!["-c".into(), script.into()])
}

#[test]
fn fills_pipe_buffer_without_deadlock() {
    // Deadlock scenario that would hang a sequential `read_to_string(stdout)
    // then read_to_string(stderr)` reader: write ~256 KB to stderr (well past
    // the 64 KB default pipe buffer) BEFORE anything appears on stdout. With
    // sequential reads the child would block on write(stderr) and the reader
    // would wait forever on stdout. The per-pipe reader threads drain both in
    // parallel, so this must finish cleanly.
    let script = r#"
for i in $(seq 1 2000); do
    printf 'err-pad-%04d-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' $i 1>&2
done
echo stdout-done
"#;
    let (prog, args) = sh(script);
    let start = Instant::now();
    let r = execute_streaming(&prog, &args, 10, None, |_| {}).expect("spawn");
    let elapsed = start.elapsed();
    assert!(!r.timed_out, "should finish without hitting the watchdog");
    assert!(!r.cancelled);
    assert_eq!(r.exit_code, Some(0));
    assert!(r.stdout.contains("stdout-done"));
    assert_eq!(r.stderr.lines().count(), 2000);
    assert!(
        elapsed < Duration::from_secs(5),
        "should drain quickly; took {elapsed:?}"
    );
}

#[test]
fn watchdog_kills_sleeping_child() {
    let (prog, args) = sh("sleep 30");
    let start = Instant::now();
    let r = execute_streaming(&prog, &args, 1, None, |_| {}).expect("spawn");
    let elapsed = start.elapsed();
    assert!(
        r.timed_out,
        "watchdog should have fired within the deadline"
    );
    assert!(!r.cancelled);
    assert!(
        elapsed < Duration::from_millis(1800),
        "kill latency should be under 1.8 s; took {elapsed:?}"
    );
}

#[test]
fn both_streams_are_captured_without_starvation() {
    // Write 100 lines to stdout and 100 to stderr, interleaved via two shell
    // loops that race. With single-threaded `read_to_string(stdout)` first,
    // the stderr pipe can fill and deadlock — the per-pipe reader threads
    // prevent that.
    let (prog, args) = sh(r#"
for i in $(seq 1 100); do echo "out-$i"; done &
for i in $(seq 1 100); do echo "err-$i" 1>&2; done &
wait
"#);
    let seen = Arc::new(Mutex::new((0usize, 0usize))); // (out, err)
    let seen_cb = Arc::clone(&seen);
    let r = execute_streaming(&prog, &args, 10, None, move |line| {
        let mut g = seen_cb.lock().unwrap();
        match line.tag {
            LineTag::Stdout => g.0 += 1,
            LineTag::Stderr => g.1 += 1,
        }
    })
    .expect("spawn");
    assert!(!r.timed_out, "should finish within 10 s");
    assert!(!r.cancelled);
    let (o, e) = *seen.lock().unwrap();
    assert_eq!(o, 100, "all 100 stdout lines reached the callback");
    assert_eq!(e, 100, "all 100 stderr lines reached the callback");
    // Aggregated buffers also contain everything.
    assert_eq!(r.stdout.lines().count(), 100);
    assert_eq!(r.stderr.lines().count(), 100);
}

#[test]
fn external_stop_flag_cancels_quickly() {
    let (prog, args) = sh("sleep 30");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_cb = Arc::clone(&stop);
    // Trigger the stop after a short delay from a side thread.
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        stop_cb.store(true, Ordering::SeqCst);
    });
    let start = Instant::now();
    let r = execute_streaming(&prog, &args, 60, Some(stop), |_| {}).expect("spawn");
    let elapsed = start.elapsed();
    assert!(r.cancelled, "stop flag must mark the run as cancelled");
    assert!(!r.timed_out);
    assert!(
        elapsed < Duration::from_millis(1500),
        "cancel latency should be well under 1.5 s; took {elapsed:?}"
    );
}

#[test]
fn callback_sees_lines_in_order_per_stream() {
    let (prog, args) = sh(r#"
echo A
echo B
echo C
"#);
    let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let r_cb = Arc::clone(&received);
    execute_streaming(&prog, &args, 5, None, move |line| {
        if line.tag == LineTag::Stdout {
            r_cb.lock().unwrap().push(line.text);
        }
    })
    .expect("spawn");
    let got = received.lock().unwrap().clone();
    assert_eq!(got, vec!["A".to_string(), "B".into(), "C".into()]);
}

#[test]
fn clean_exit_is_reported() {
    let (prog, args) = sh("echo done; exit 0");
    let r = execute_streaming(&prog, &args, 5, None, |_| {}).expect("spawn");
    assert_eq!(r.exit_code, Some(0));
    assert!(!r.timed_out);
    assert!(!r.cancelled);
    assert!(r.stdout.contains("done"));
}

#[test]
fn non_zero_exit_is_preserved() {
    let (prog, args) = sh("exit 7");
    let r = execute_streaming(&prog, &args, 5, None, |_| {}).expect("spawn");
    assert_eq!(r.exit_code, Some(7));
    assert!(!r.timed_out);
    assert!(!r.cancelled);
}
