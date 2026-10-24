# Native Owner runtime fixtures

`sing-box.service` is the byte-preserved unit from `data.tar.gz` in the pinned,
inert `tests/testdata/package_acquisition/sing-box_1.14.3_amd64.deb`. Its SHA256 is
`259fa4ee0a29fb863bd1597eba9392bd9767c679c1e28b8b1ee91ce1ea01c84d`.
It was read in memory with Python's standard-library ar/tar/gzip handling; the
package, executable and unit were never executed or installed.

Native command/process observations in tests are explicitly injected. Tests use
real protected temporary files, locks, descriptor lending, cutover consumption,
the bounded serving module and loopback TCP. The fixture-only serving-state
constructor maps only its bind address to loopback while retaining the actual
production artifact bytes. It is absent from production builds. Source/target,
process and loaded-unit assertions remain active; no signature proof is replaced.
These tests do not qualify native systemd, cgroups, firewall or deployed traffic.
