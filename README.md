# InfinityAuthWebApiTest

Reproduces the NTLM authentication failure that occurs when using the `Blackbaud.AppFx.WebAPI` library through Azure App Gateway v2.

## Problem

Customers using `AppFxWebServiceProvider` with `NetworkCredential` (NTLM) get HTTP 401 Unauthorized on every call after their environment is migrated to App Gateway v2.

NTLM requires a 3-leg handshake (Type 1 -> Type 2 -> Type 3) that must complete on the **same TCP connection**. App Gateway v2 sends `Connection: close` after each response, breaking the handshake. `SoapHttpClientProtocol` (the base class of `AppFxWebService`) does not retry, so every call fails.

## What This App Does

- Calls `GetAvailableREDatabases` via the WebAPI library using NTLM auth (`CredentialCache` with `"NTLM"`)
- Runs 10 iterations with 5-second delays between each
- Logs timestamps, public IP, local IPs, response status, and response headers to both console and a timestamped log file

## Expected Result

All 10 iterations return **HTTP 401 Unauthorized** when pointed at an App Gateway v2 endpoint.

Key response headers confirming the issue:
- `Connection: close` — gateway kills the TCP connection between NTLM handshake roundtrips
- `WWW-Authenticate: Negotiate, NTLM` — server wants NTLM, but the handshake can never complete
- `ApplicationGatewayAffinityCORS` cookie — confirms App Gateway v2 is in the path

## Configuration

Edit `appsettings.json`:

```json
{
  "ServiceUrl": "https://crm5740s29.sky.blackbaud.com/5740S29/appfxwebservice.asmx",
  "Database": "5740S29",
  "Username": "APIUser5740S29",
  "Password": "...",
  "Domain": "s29"
}
```

## Build & Run

```
MSBuild InfinityAuthWebApiTest.csproj -t:Build -p:Configuration=Debug
bin\Debug\InfinityAuthWebApiTest.exe
```

Log files are written to `bin\Debug\auth-test-YYYYMMDD-HHmmss.log`.

## See Also

- **InfinityAuthWebApiUpgradeTest** — demonstrates the fix using Basic auth header injection
- **InfinityAuthTest** — same WebAPI library with Basic auth via `CredentialCache` (works against localhost where IIS advertises Basic, but not through App Gateway v2 where the server only advertises Negotiate/NTLM)
