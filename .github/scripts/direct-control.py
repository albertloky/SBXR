"""Physical TCP control on the candidate's already authenticated SSH endpoint."""
import ipaddress
import socket
import sys
import time


def physical(host):
    if sys.platform != 'darwin' or str(ipaddress.IPv4Address(host)) != host:
        raise ValueError('requires the reviewed macOS IPv4 outside route')
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        interface = socket.if_nametoindex('en0')
        stream.setsockopt(socket.IPPROTO_IP, 25, interface)  # Darwin IP_BOUND_IF
        if stream.getsockopt(socket.IPPROTO_IP, 25) != interface:
            raise ValueError('outside interface binding differs')
        return stream
    except BaseException:
        stream.close()
        raise


def observe(host, deadline, *, socket_for=physical, now=time.time):
    remaining = deadline-now()
    if remaining <= 4:
        raise ValueError('outside control deadline')
    with socket_for(host) as stream:
        stream.settimeout(min(3, remaining-1))
        stream.connect((host, 22))
        banner = stream.recv(255)
        if stream.getpeername() != (host, 22) or not banner.startswith(b'SSH-2.0-'):
            raise ValueError('outside SSH control absent')
    return {'passed': True}
