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

#[test]
fn owner_session_stop_cancels_a_real_owned_child_without_cancelling_a_fresh_session() {
    let session = crate::subscription_serving::Cancellation::new();
    let stop = Cancellation::from(session.clone());
    let start = Instant::now();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(35));
            session.cancel();
        });
        assert!(matches!(
            run(
                "/bin/sh",
                &["-c", "exec sleep 10"],
                Duration::from_secs(2),
                4096,
                &stop
            ),
            Err(HostError::Cancelled)
        ));
    });
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(stop.cancelled());
    assert!(!Cancellation::new().cancelled());
}

#[test]
fn timing_distinguishes_actual_spawn_and_completion_without_argv_or_output() {
    let (result, bytes) = super::super::timing::capture(|| {
        run(
            "/bin/sh",
            &["-c", "printf 'SECRET-SENTINEL /private/path'"],
            Duration::from_secs(2),
            1024,
            &Cancellation::new(),
        )
    });
    assert_eq!(result.unwrap().bytes(), b"SECRET-SENTINEL /private/path");
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        !text.contains("SECRET-SENTINEL")
            && !text.contains("/private/path")
            && !text.contains("/bin/sh")
    );
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line.strip_prefix("SBXR_NATIVE_PHASE ").unwrap()).unwrap())
        .collect();
    let phases: Vec<_> = rows
        .iter()
        .map(|r| (r["phase"].as_str().unwrap(), r["event"].as_str().unwrap()))
        .collect();
    assert_eq!(
        phases,
        vec![
            ("subprocess", "begin"),
            ("subprocess-spawn", "begin"),
            ("subprocess-spawn", "end"),
            ("subprocess", "end")
        ]
    );
    assert_eq!(rows[0]["id"], rows[3]["id"]);
    assert_eq!(rows[1]["id"], rows[2]["id"]);
}
