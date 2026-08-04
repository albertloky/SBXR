# SBXR

SBXR is a single-owner system for managing a fixed set of proxy connection choices on one VPS.

## Language

**Owner**:
The one person who exclusively controls an SBXR installation and its credentials.
_Avoid_: User, account, administrator

**Connection Profile**:
One named connection choice that the Owner can configure, test, export, and use from a client device.
_Avoid_: Protocol, mode, node

**Client Access Value**:
A credential-bearing value used by a client device, including a Connection Profile credential, share URI, QR code content, or subscription URL.
_Avoid_: Infrastructure credential

**Infrastructure Secret**:
A credential or private key used by SBXR or a managed service to administer infrastructure or prove server identity, rather than by a client device.
_Avoid_: Client credential, Client Access Value
