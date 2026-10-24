All inputs are inert, synthetic offline fixtures. The token claims contain no
account credential, and no test executes cloudflared, sing-box or an endpoint.

The WebSocket accept vectors contain the RFC6455 example plus deterministic
inputs independently generated with Python hashlib.sha1 and base64.b64encode.
They check the protocol challenge helper; SHA-1 is not used for authentication.

Orchestration tests use the real protected OwnershipStore in newly created
0700 temporary directories, with explicitly injected host/process observations.
Store reopen tests prove journal direction and replay, not native deployment.
