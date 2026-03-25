# InfinityAuthWebApiTest

NTLM authentication soak test for comparing `AppFxWebServiceProvider` behavior through App Gateway v1 vs v2.

## Problem

Customers using `AppFxWebServiceProvider` with `NetworkCredential` (NTLM) get HTTP 401 Unauthorized after their environment is migrated to App Gateway v2.

NTLM requires a 3-leg handshake (Type 1 → Type 2 → Type 3) that must complete on the **same TCP connection**. App Gateway v2 sends `Connection: close` after the 401 challenge response, breaking the handshake. `SoapHttpClientProtocol` (the base class of `AppFxWebService`) does not retry on a new connection, so the call fails.

## What This App Does

- Calls `GetAvailableREDatabases` via the WebAPI library using NTLM auth
- Runs 10 iterations with 5-second delays
- Uses a `DiagnosticWebService` subclass that overrides `GetWebRequest`/`GetWebResponse` to capture full request and response headers on both success and failure paths
- Logs source port (ephemeral port) for each iteration to verify connection reuse behavior
- Supports two connection modes: **reuse** (same TCP connection/source port) and **no-reuse** (new connection each iteration)
- Supports Fiddler proxy for additional traffic inspection
- Logs everything to both console and a timestamped log file

## Four-Scenario Test Plan

Run each scenario by changing `appsettings.json` and executing the app. Each produces a separate log file with the host and mode in the filename.

| # | Gateway | ReuseConnection | Expected Result | Log Pattern |
|---|---------|-----------------|-----------------|-------------|
| 1 | V1 | `true` | 10/10 pass | `auth-test-crm5740s26-reuse-*.log` |
| 2 | V1 | `false` | 10/10 pass | `auth-test-crm5740s26-no-reuse-*.log` |
| 3 | V2 | `true` | 0-1/10 pass | `auth-test-crm5740s29-reuse-*.log` |
| 4 | V2 | `false` | 0/10 pass | `auth-test-crm5740s29-no-reuse-*.log` |

### What to look for in the logs

**Success indicators (V1):**
- `Persistent-Auth: true` — server preserves the authenticated connection
- `Authorization: NTLM TlRMTVNTUAAD...` — NTLM Type 3 token (final handshake leg completed)
- Source port remains the same across iterations (reuse mode)

**Failure indicators (V2):**
- `Connection: close` — gateway kills the TCP connection between NTLM handshake legs
- `WWW-Authenticate: Negotiate,NTLM` — server requests NTLM but handshake can never complete
- `ApplicationGatewayAffinityCORS` cookie — confirms App Gateway v2 is in the path
- Response times ~3300ms (NTLM retry timeout) vs ~600ms for successful V1 calls

### Connection Mode Details

**`ReuseConnection: true`** — Same ephemeral source port across requests:
- Reuses the same `AppFxWebService` proxy instance across all iterations
- `KeepAlive` defaults to `true`
- TCP connection is maintained between iterations

**`ReuseConnection: false`** — Different source port each iteration:
- Creates a new `AppFxWebService` proxy instance per iteration
- Sets `KeepAlive = false` (sends `Connection: Close` header)
- Closes the `ServicePoint` connection group between iterations

## Configuration

Edit `appsettings.json`:

```json
{
  "ServiceUrl": "https://crm5740s29.sky.blackbaud.com/5740S29/appfxwebservice.asmx",
  "Database": "5740S29",
  "Username": "YOUR_USERNAME_HERE",
  "Password": "YOUR_PASSWORD_HERE",
  "Domain": "s29",
  "ReuseConnection": false,
  "ProxyUrl": "http://127.0.0.1:8888"
}
```

| Field | Description |
|-------|-------------|
| `ServiceUrl` | AppFxWebService endpoint URL |
| `Database` | Infinity database name |
| `Username` | Domain account username |
| `Password` | Domain account password |
| `Domain` | Windows domain |
| `ReuseConnection` | `true` = reuse TCP connection (same source port); `false` = new connection each iteration |
| `ProxyUrl` | HTTP proxy URL for Fiddler (e.g., `http://127.0.0.1:8888`), leave empty to disable |

## Logging Details

Each iteration logs:

- **Header block** (once): URL, Database, User, Auth mode, Connection mode, Public IP, Local IPs, Hostname, Server Host, Server IPs (DNS), TLS version, Connection Limit
- **Request**: Method, URL, all HTTP headers (User-Agent, Content-Type, SOAPAction, Authorization, Host, Content-Length, Expect, Connection), KeepAlive setting
- **Response**: Status code, all HTTP headers (Persistent-Auth, Connection, WWW-Authenticate, Set-Cookie, etc.)
- **Source Port**: Local ephemeral port and TCP connection state, or "(connection already closed)"
- **On failure**: Response body (first 500 chars), inner exception details

## Using with Fiddler

1. Open Fiddler and ensure it's capturing traffic on `http://127.0.0.1:8888`
2. Set `"ProxyUrl": "http://127.0.0.1:8888"` in appsettings
3. If Fiddler is configured for HTTPS decryption, it will show full request/response bodies
4. Run the test — Fiddler will capture all NTLM handshake roundtrips

## Build & Run

```
MSBuild InfinityAuthWebApiTest.csproj -t:Build -p:Configuration=Debug
bin\Debug\InfinityAuthWebApiTest.exe
```

Log files are written to `bin\Debug\auth-test-{host}-{mode}-YYYYMMDD-HHmmss.log`.

