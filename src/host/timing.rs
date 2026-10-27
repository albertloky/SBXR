//! Fixed, non-secret native timings. End means scope exit, including refusal.
use super::process::Query;
use std::{cell::RefCell, io::Write, marker::PhantomData, rc::Rc, time::Instant};

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Entry,
    Select,
    Authenticate,
    ReviewStatus,
    ReviewDetails,
    ReviewAction,
    Details,
    Journeys,
    Standard,
    Tunnel,
    Removal,
    Http,
    Identity,
    Disclosure,
    Package,
    Probe,
    Snapshot,
    Lifecycle,
    Installed,
    Material,
    Network,
    Roots,
    Dns,
    IpHttp,
    Tls,
    Connect,
    Handshake,
    Bind,
    Process,
    Spawn,
    Query(Query),
}
impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Select => "entry-select",
            Self::Authenticate => "authenticate",
            Self::ReviewStatus => "review-status",
            Self::ReviewDetails => "review-details",
            Self::ReviewAction => "review-action",
            Self::Details => "write-details",
            Self::Journeys => "journeys",
            Self::Standard => "open-standard",
            Self::Tunnel => "open-tunnel",
            Self::Removal => "open-removal",
            Self::Http => "open-http",
            Self::Identity => "open-identity",
            Self::Disclosure => "open-disclosure",
            Self::Package => "package",
            Self::Probe => "probe-image",
            Self::Material => "material",
            Self::Dns => "network-dns",
            Self::Connect => "network-connect",
            Self::Handshake => "network-handshake",
            Self::Snapshot => "snapshot",
            Self::Lifecycle => "lifecycle",
            Self::Installed => "installed-pair",
            Self::Network => "network",
            Self::Roots => "network-roots",
            Self::IpHttp => "network-ip-http",
            Self::Tls => "network-tls",
            Self::Bind => "network-bind",
            Self::Process => "subprocess",
            Self::Spawn => "subprocess-spawn",
            Self::Query(q) => match q {
                Query::Package => "query-package",
                Query::Hold => "query-hold",
                Query::User => "query-user",
                Query::Group => "query-group",
                Query::Process => "query-process",
                Query::Enabled => "query-enabled",
                Query::Active => "query-active",
                Query::LoadState => "query-load-state",
                Query::Listener => "query-listener",
                Query::UnitOwner => "query-unit-owner",
                Query::ConfigurationOwner => "query-configuration-owner",
                Query::Clock => "query-clock",
                Query::ValidateConfiguration => "query-validate",
                Query::DestinationDns => "query-destination-dns",
                Query::PublicIpDns => "query-public-ip-dns",
                Query::ProxyStartCondition => "query-start-condition",
            },
        }
    }
}
struct Trace {
    start: Instant,
    next: u64,
    sink: Rc<RefCell<Box<dyn Write>>>,
}
thread_local! { static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) }; }
pub(crate) struct Enabled(Option<Trace>);
impl Drop for Enabled {
    fn drop(&mut self) {
        TRACE.with(|t| *t.borrow_mut() = self.0.take());
    }
}
fn enable_with(sink: Box<dyn Write>) -> Enabled {
    Enabled(TRACE.with(|t| {
        t.replace(Some(Trace {
            start: Instant::now(),
            next: 0,
            sink: Rc::new(RefCell::new(sink)),
        }))
    }))
}
#[path = "timing_sink.rs"]
mod native_sink;
pub(crate) fn enable() -> Enabled {
    match native_sink::NativeSink::new(&std::io::stderr()) {
        Ok(sink) => enable_with(Box::new(sink)),
        Err(_) => Enabled(TRACE.with(|t| t.take())),
    }
}

fn emit(phase: Phase, event: &str, id: u64) {
    let value = TRACE.with(|t| {
        t.borrow().as_ref().map(|trace| {
            (
                trace.sink.clone(),
                trace.start.elapsed().as_micros().min(u64::MAX as u128) as u64,
            )
        })
    });
    let Some((sink, elapsed)) = value else { return };
    let Ok(mut sink) = sink.try_borrow_mut() else {
        return;
    };
    // No state borrow is retained across I/O; diagnostics never decide authority.
    let line = format!(
        "SBXR_NATIVE_PHASE {{\"phase\":\"{}\",\"event\":\"{}\",\"id\":{},\"elapsed_us\":{}}}\n",
        phase.label(),
        event,
        id,
        elapsed
    );
    let _ = sink.write(line.as_bytes());
}
pub(crate) struct Span(Option<(Phase, u64)>, PhantomData<Rc<()>>);
pub(crate) fn span(phase: Phase) -> Span {
    let id = TRACE.with(|t| {
        let mut state = t.borrow_mut();
        let trace = state.as_mut()?;
        trace.next = trace.next.saturating_add(1);
        Some(trace.next)
    });
    if let Some(id) = id {
        emit(phase, "begin", id);
    }
    Span(id.map(|id| (phase, id)), PhantomData)
}
impl Span {
    pub(super) fn query_result(
        &self,
        observation: &super::process::ProcessObservation,
        result: &Result<super::process::CommandOutput, super::HostError>,
    ) {
        let Some((Phase::Query(query), id)) = self.0 else {
            return;
        };
        use super::HostError;
        let outcome = match result {
            Ok(output) if output.code() == 0 => "completed-zero",
            Ok(_) => "completed-nonzero",
            Err(HostError::Timeout) => "timeout",
            Err(HostError::Cancelled) => "cancelled",
            Err(HostError::OutputLimit) => "output-limit",
            Err(HostError::Io) => "io",
            Err(HostError::Unsafe) => "unsafe",
            Err(HostError::Foreign) => "foreign",
            Err(HostError::Injected) => "injected",
            Err(HostError::LiveUnavailable) => "live-unavailable",
            Err(HostError::UnsupportedHost) => "unsupported-host",
            Err(HostError::Busy) => "busy",
        };
        TRACE.with(|t| {
            let value = t.borrow().as_ref().map(|trace| {
                (
                    trace.sink.clone(),
                    trace.start.elapsed().as_micros().min(u64::MAX as u128) as u64,
                )
            });
            let Some((sink, elapsed)) = value else { return };
            let Ok(mut sink) = sink.try_borrow_mut() else {
                return;
            };
            let row = serde_json::json!({
                "query": Phase::Query(query).label(), "id": id,
                "elapsed_us": elapsed, "outcome": outcome, "process": observation,
            });
            let line = format!("SBXR_NATIVE_QUERY {row}\n");
            // One best-effort write through the private nonblocking pipe sink.
            // No flush/retry: a failed or partial diagnostic cannot delay cleanup,
            // alter the result, or confer authority. The relay drops partial rows.
            let _ = sink.write(line.as_bytes());
        });
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if let Some((phase, id)) = self.0 {
            emit(phase, "end", id);
        }
    }
}
#[cfg(test)]
pub(crate) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<u8>) {
    struct Sink(Rc<RefCell<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let bytes = Rc::new(RefCell::new(Vec::new()));
    let enabled = enable_with(Box::new(Sink(bytes.clone())));
    let result = f();
    drop(enabled);
    let output = bytes.borrow().clone();
    (result, output)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scopes_pair_on_refusal_without_payload_or_path_and_restore_disabled_state() {
        assert!(span(Phase::Entry).0.is_none());
        let (result, bytes) = capture(|| {
            let _outer = span(Phase::Network);
            let _inner = span(Phase::Query(Query::PublicIpDns));
            Err::<(), _>("SECRET-SENTINEL /private/path")
        });
        assert!(result.is_err());
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("SECRET-SENTINEL") && !text.contains("/private/path"));
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|line| {
                serde_json::from_str(line.strip_prefix("SBXR_NATIVE_PHASE ").unwrap()).unwrap()
            })
            .collect();
        assert_eq!(rows.len(), 4);
        for (row, (phase, event, id)) in rows.iter().zip([
            ("network", "begin", 1),
            ("query-public-ip-dns", "begin", 2),
            ("query-public-ip-dns", "end", 2),
            ("network", "end", 1),
        ]) {
            assert_eq!(row["phase"], phase);
            assert_eq!(row["event"], event);
            assert_eq!(row["id"], id);
            assert_eq!(row.as_object().unwrap().len(), 4);
            assert!(row["elapsed_us"].is_u64());
        }
        assert!(
            rows.windows(2)
                .all(|r| r[0]["elapsed_us"].as_u64() <= r[1]["elapsed_us"].as_u64())
        );
        assert!(span(Phase::Entry).0.is_none());
    }
    #[test]
    fn every_typed_native_phase_is_accepted_by_the_driver_schema() {
        use std::process::{Command, Stdio};
        let phases = [
            Phase::Entry,
            Phase::Select,
            Phase::Authenticate,
            Phase::ReviewStatus,
            Phase::ReviewDetails,
            Phase::ReviewAction,
            Phase::Details,
            Phase::Journeys,
            Phase::Standard,
            Phase::Tunnel,
            Phase::Removal,
            Phase::Http,
            Phase::Identity,
            Phase::Disclosure,
            Phase::Package,
            Phase::Probe,
            Phase::Snapshot,
            Phase::Lifecycle,
            Phase::Installed,
            Phase::Material,
            Phase::Network,
            Phase::Roots,
            Phase::Dns,
            Phase::IpHttp,
            Phase::Tls,
            Phase::Connect,
            Phase::Handshake,
            Phase::Bind,
            Phase::Process,
            Phase::Spawn,
            Phase::Query(Query::Package),
            Phase::Query(Query::Hold),
            Phase::Query(Query::User),
            Phase::Query(Query::Group),
            Phase::Query(Query::Process),
            Phase::Query(Query::Enabled),
            Phase::Query(Query::Active),
            Phase::Query(Query::LoadState),
            Phase::Query(Query::Listener),
            Phase::Query(Query::UnitOwner),
            Phase::Query(Query::ConfigurationOwner),
            Phase::Query(Query::Clock),
            Phase::Query(Query::ValidateConfiguration),
            Phase::Query(Query::DestinationDns),
            Phase::Query(Query::PublicIpDns),
            Phase::Query(Query::ProxyStartCondition),
        ];
        let (_, bytes) = capture(|| {
            for phase in phases {
                drop(span(phase));
            }
        });
        let program = r#"import importlib.util,io,json,sys
spec=importlib.util.spec_from_file_location('driver',sys.argv[1]);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
sink=io.StringIO();timing=driver.PhaseTiming(sink,1e20)
for raw in sys.stdin.buffer.read().splitlines():timing.native(raw)
timing.close()
rows=[json.loads(line.removeprefix('SBXR_NATIVE_PHASE ')) for line in sink.getvalue().splitlines()]
assert len(rows)==int(sys.argv[2]),len(rows)
assert {row['phase'] for row in rows}==driver.NATIVE_PHASES
"#;
        let mut child = Command::new("python3")
            .args([
                "-B",
                "-c",
                program,
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/.github/scripts/v3-menu-session.py"
                ),
                &(phases.len() * 2).to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn query_diagnostic_terminal_outcomes_are_closed_and_payload_free() {
        use super::super::{
            HostError,
            process::{CommandOutput, ProcessObservation},
        };
        let cases = [
            (
                Ok(CommandOutput::completed(0, b"SECRET-SENTINEL".to_vec()).unwrap()),
                "completed-zero",
            ),
            (
                Ok(CommandOutput::completed(7, b"SECRET-SENTINEL".to_vec()).unwrap()),
                "completed-nonzero",
            ),
            (Err(HostError::Timeout), "timeout"),
            (Err(HostError::Cancelled), "cancelled"),
            (Err(HostError::OutputLimit), "output-limit"),
            (Err(HostError::Io), "io"),
            (Err(HostError::Unsafe), "unsafe"),
            (Err(HostError::Foreign), "foreign"),
            (Err(HostError::Injected), "injected"),
            (Err(HostError::LiveUnavailable), "live-unavailable"),
            (Err(HostError::UnsupportedHost), "unsupported-host"),
            (Err(HostError::Busy), "busy"),
        ];
        for (result, expected) in cases {
            let (_, bytes) = capture(|| {
                let query = span(Phase::Query(Query::PublicIpDns));
                query.query_result(&ProcessObservation::default(), &result);
            });
            let text = String::from_utf8(bytes).unwrap();
            assert!(!text.contains("SECRET-SENTINEL"));
            let rows: Vec<_> = text
                .lines()
                .filter_map(|l| l.strip_prefix("SBXR_NATIVE_QUERY "))
                .collect();
            assert_eq!(rows.len(), 1);
            let row: serde_json::Value = serde_json::from_str(rows[0]).unwrap();
            assert_eq!(row["outcome"], expected);
            assert_eq!(row["process"]["location"], "before-run");
            assert_eq!(row["process"]["leader"], "unobserved");
            if let Ok(output) = result {
                assert_eq!(output.bytes(), b"SECRET-SENTINEL");
            }
        }
    }

    #[test]
    fn query_diagnostic_sink_failures_never_retry_or_change_result() {
        struct Sink {
            calls: Rc<RefCell<usize>>,
            kind: u8,
        }
        impl Write for Sink {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                *self.calls.borrow_mut() += 1;
                match self.kind {
                    0 => Err(std::io::ErrorKind::WouldBlock.into()),
                    1 => Err(std::io::ErrorKind::Interrupted.into()),
                    2 => Err(std::io::ErrorKind::BrokenPipe.into()),
                    3 => Ok(0),
                    _ => Ok(1),
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                panic!("must not flush")
            }
        }
        for kind in 0..5 {
            let calls = Rc::new(RefCell::new(0));
            let enabled = enable_with(Box::new(Sink {
                calls: calls.clone(),
                kind,
            }));
            // Construct a query span without emitting unrelated begin/end rows.
            let mut phase = Span(Some((Phase::Query(Query::PublicIpDns), 1)), PhantomData);
            let result = Err(super::super::HostError::Timeout);
            phase.query_result(
                &super::super::process::ProcessObservation::default(),
                &result,
            );
            assert_eq!(*calls.borrow(), 1);
            assert!(matches!(result, Err(super::super::HostError::Timeout)));
            phase.0 = None;
            drop(enabled);
        }
    }

    #[test]
    fn failed_diagnostic_sink_does_not_change_the_operation() {
        struct Failed;
        impl Write for Failed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("SECRET-SENTINEL /private/path"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("failed"))
            }
        }
        let _enabled = enable_with(Box::new(Failed));
        let _span = span(Phase::Query(Query::Active));
    }
}
