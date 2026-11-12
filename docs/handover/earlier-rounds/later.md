### Scale

| ID | Test | Pass when |
| --- | --- | --- |
| SCL-01 | SSH fleet 100 to 200 hosts | Time, node CPU and memory recorded; failure rate under 1% |
| SCL-02 | Sparse /16 network sweep | Completes inside window; rate respected |
| SCL-03 | 500-repo organisation | Completes within Git host rate limits |
| SCL-04 | Cloud account with 5,000 parameters | Completes; API throttling handled |

### Chaos

| ID | Test | Pass when |
| --- | --- | --- |
| CHS-01 | Packet loss 10% and 500 ms latency | Completes; results equal the clean run |
| CHS-02 | Path-MTU black hole with large chains | Handshakes complete or fail with a clear reason |
| CHS-03 | Credential rotated mid-job | Fresh credential fetched; no lockout |
| CHS-04 | Node disk full | Clear error; no silent data loss |
| CHS-05 | Control-plane outage 30 min | Node buffers and catches up |

### Soak

| ID | Test | Pass when |
| --- | --- | --- |
| SOK-01 | 72-hour soak | No memory or handle growth; zero result drift |
