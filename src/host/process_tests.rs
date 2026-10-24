use super::*;
#[test]
fn transport_retains_exit_code_and_never_formats_raw_output() {
    let out = run(
        "/bin/sh",
        &["-c", "printf secret; printf hidden >&2; exit 7"],
        Duration::from_secs(2),
        64,
        &Cancellation::new(),
    )
    .unwrap();
    assert_eq!(out.code(), 7);
    assert_eq!(out.bytes(), b"secret");
    assert!(!format!("{out:?}").contains("secret"));
}
#[test]
fn stdout_stderr_and_descendant_pipe_are_bounded() {
    for script in [
        "while :; do printf 0123456789; done",
        "while :; do printf 0123456789 >&2; done",
    ] {
        assert!(matches!(
            run(
                "/bin/sh",
                &["-c", script],
                Duration::from_secs(2),
                4096,
                &Cancellation::new()
            ),
            Err(HostError::OutputLimit)
        ));
    }
    let began = Instant::now();
    assert!(matches!(
        run(
            "/bin/sh",
            &["-c", "sleep 20 & exit 0"],
            Duration::from_millis(150),
            4096,
            &Cancellation::new()
        ),
        Err(HostError::Timeout)
    ));
    assert!(began.elapsed() < Duration::from_secs(2));
}
#[test]
fn cancellation_before_and_during_run_reaps_owned_process_group() {
    let stop = Cancellation::new();
    stop.cancel();
    assert!(matches!(
        run("/does-not-exist", &[], Duration::from_secs(1), 16, &stop),
        Err(HostError::Cancelled)
    ));
    let stop = Cancellation::new();
    let handle = stop.clone();
    let worker = thread::spawn(move || {
        run(
            "/bin/sh",
            &["-c", "sleep 20"],
            Duration::from_secs(5),
            4096,
            &handle,
        )
    });
    thread::sleep(Duration::from_millis(100));
    stop.cancel();
    assert!(matches!(worker.join().unwrap(), Err(HostError::Cancelled)));
}
#[test]
fn native_probes_do_not_run_on_unsupported_platforms() {
    if !cfg!(target_os = "linux") {
        assert!(matches!(
            NativeReadOnly.query(Query::Package, &Cancellation::new()),
            Err(HostError::UnsupportedHost)
        ));
    }
}

#[test]
fn repeated_interrupted_reads_still_observe_cancellation() {
    struct Interrupting {
        reads: u8,
        stop: Cancellation,
    }
    impl Read for Interrupting {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            if self.reads == 2 {
                self.stop.cancel()
            }
            if self.reads >= 3 {
                return Ok(0);
            }
            Err(std::io::Error::from(ErrorKind::Interrupted))
        }
    }
    let stop = Cancellation::new();
    let mut input = Interrupting {
        reads: 0,
        stop: stop.clone(),
    };
    assert!(matches!(
        drain(
            &mut input,
            &mut Vec::new(),
            16,
            &stop,
            Instant::now() + Duration::from_secs(1)
        ),
        Err(HostError::Cancelled)
    ));
    assert_eq!(input.reads, 2);
}
