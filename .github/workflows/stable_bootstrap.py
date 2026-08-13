import fcntl
import os
import pty
import select
import signal
import struct
import termios
import time


command = "bash <(curl -fsSL https://github.com/albertloky/SBXR/releases/latest/download/install.sh)"
pid, terminal = pty.fork()
if pid == 0:
    fcntl.ioctl(1, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
    environment = {
        "HOME": os.environ["HOME"],
        "LANG": "C.UTF-8",
        "LOGNAME": os.environ["USER"],
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM": "xterm-256color",
        "USER": os.environ["USER"],
    }
    os.execve("/bin/bash", ["bash", "-lc", command], environment)

output = bytearray()
terminal_reported = False
deadline = time.monotonic() + 120
while time.monotonic() < deadline and b"Not installed" not in output:
    ready, _, _ = select.select([terminal], [], [], 1)
    if ready:
        try:
            output.extend(os.read(terminal, 65536))
            if not terminal_reported and b"\x1b[?1049$p" in output:
                os.write(terminal, b"\x1b[?1;2$y\x1b[?6;2$y\x1b[?25;1$y\x1b[?1000;2$y\x1b[?1002;2$y\x1b[?1003;2$y\x1b[?1006;2$y\x1b[?1049;2$y\x1b[?2004;2$y\x1b[1;1R")
                terminal_reported = True
        except OSError:
            break

if b"SBXR bootstrap: launching Owner Console" not in output or b"Not installed" not in output:
    os.write(2, output)
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    raise SystemExit("public bootstrap did not reach the Owner Console")

os.write(terminal, b"\x03")
time.sleep(1)
os.write(terminal, b"\r")
for _ in range(20):
    child, status = os.waitpid(pid, os.WNOHANG)
    if child == pid:
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise SystemExit("public bootstrap did not exit cleanly")
        break
    time.sleep(0.5)
else:
    os.killpg(pid, signal.SIGTERM)
    raise SystemExit("public bootstrap did not clean up")

with open("bootstrap-transcript.txt", "wb") as transcript:
    transcript.write(output)
