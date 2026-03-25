using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Web.Services.Protocols;
using Blackbaud.AppFx.WebAPI;
using Blackbaud.AppFx.WebAPI.ServiceProxy;

namespace InfinityAuthWebApiTest
{
    class Program
    {
        static StreamWriter _log;

        static int Main(string[] args)
        {
            var settings = LoadSettings();

            // When using a proxy (Fiddler), trust its HTTPS interception certificate
            if (!string.IsNullOrEmpty(settings.ProxyUrl))
            {
                ServicePointManager.ServerCertificateValidationCallback =
                    (object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) => true;
            }

            // Build descriptive log filename: auth-test-{host}-{mode}-YYYYMMDD-HHmmss.log
            var hostShort = new Uri(settings.ServiceUrl).Host.Split('.')[0];
            var modeLabel = settings.ReuseConnection ? "reuse" : "no-reuse";
            var logName = $"auth-test-{hostShort}-{modeLabel}-{DateTime.Now:yyyyMMdd-HHmmss}.log";
            var logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, logName);
            _log = new StreamWriter(logPath, append: true) { AutoFlush = true };

            try
            {
                Log("════════════════════════════════════════════════════════════════");
                Log("InfinityAuthWebApiTest — NTLM Auth Soak Test");
                Log("════════════════════════════════════════════════════════════════");
                Log($"URL:        {settings.ServiceUrl}");
                Log($"Database:   {settings.Database}");
                Log($"User:       {FormatUser(settings)}");
                Log($"Auth:       NTLM");
                Log($"Mode:       {(settings.ReuseConnection ? "REUSE connection (same ephemeral source port)" : "NEW connection each iteration (different source port)")}");
                if (!string.IsNullOrEmpty(settings.ProxyUrl))
                    Log($"Proxy:      {settings.ProxyUrl}");
                Log($"Log:        {logPath}");
                Log("");

                // Network info
                Log($"Public IP:   {GetPublicIp()}");
                Log($"Local IPs:   {GetLocalIps()}");
                Log($"Hostname:    {Dns.GetHostName()}");

                // Resolve server IP
                var serverHost = new Uri(settings.ServiceUrl).Host;
                var serverIps = ResolveHost(serverHost);
                Log($"Server Host: {serverHost}");
                Log($"Server IPs:  {serverIps}");

                // ServicePoint info
                var sp = ServicePointManager.FindServicePoint(new Uri(settings.ServiceUrl));
                Log($"TLS:         {ServicePointManager.SecurityProtocol}");
                Log($"Conn Limit:  {sp.ConnectionLimit}");
                Log("");

                const int iterations = 10;
                const int delaySeconds = 5;
                int passes = 0;
                int failures = 0;

                Log($"Running {iterations} iterations with {delaySeconds}s delay between each");
                Log("────────────────────────────────────────────────────────────────");
                Log("");

                // For reuse mode: create one service/provider and reuse across iterations
                DiagnosticWebService sharedDiagService = null;
                AppFxWebServiceProvider sharedProvider = null;

                if (settings.ReuseConnection)
                {
                    sharedDiagService = new DiagnosticWebService();
                    sharedProvider = CreateProvider(settings, sharedDiagService);

                    // Pre-authenticate to establish the connection
                    sharedDiagService.PreAuthenticate = true;
                }

                // Capture server endpoint for source port lookups
                var serverEndpoint = ResolveServerEndpoint(serverHost);

                for (int i = 1; i <= iterations; i++)
                {
                    Log($"── Iteration {i}/{iterations} ──");

                    DiagnosticWebService diagService;
                    AppFxWebServiceProvider provider;

                    if (settings.ReuseConnection)
                    {
                        diagService = sharedDiagService;
                        provider = sharedProvider;
                    }
                    else
                    {
                        // New connection each time
                        diagService = new DiagnosticWebService();
                        diagService.KeepAlive = false;
                        provider = CreateProvider(settings, diagService);
                    }

                    var sw = Stopwatch.StartNew();

                    try
                    {
                        Log($"  >> GetAvailableREDatabases");

                        var req = provider.CreateRequest<GetAvailableREDatabasesRequest>();
                        var reply = provider.Service.GetAvailableREDatabases(req);
                        sw.Stop();

                        if (reply.Databases == null || reply.Databases.Length == 0)
                        {
                            Log($"  << 200 OK — no databases returned ({sw.ElapsedMilliseconds}ms)", ConsoleColor.Yellow);
                        }
                        else
                        {
                            Log($"  << 200 OK — {reply.Databases.Length} database(s) ({sw.ElapsedMilliseconds}ms)", ConsoleColor.Green);
                            foreach (var db in reply.Databases)
                                Log($"     {db}");
                        }

                        LogRequest(diagService);
                        LogResponse(diagService);
                        LogSourcePort(serverEndpoint);
                        passes++;
                    }
                    catch (SoapException soapEx)
                    {
                        sw.Stop();
                        Log($"  << SOAP ERROR ({sw.ElapsedMilliseconds}ms): {soapEx.Message}", ConsoleColor.Red);
                        LogRequest(diagService);
                        LogResponse(diagService);
                        LogSourcePort(serverEndpoint);
                        failures++;
                    }
                    catch (WebException webEx)
                    {
                        sw.Stop();

                        if (webEx.Response is HttpWebResponse resp)
                        {
                            Log($"  << HTTP {(int)resp.StatusCode} {resp.StatusDescription} ({sw.ElapsedMilliseconds}ms)", ConsoleColor.Red);
                        }
                        else
                        {
                            Log($"  << WebException ({sw.ElapsedMilliseconds}ms): {webEx.Status} — {webEx.Message}", ConsoleColor.Red);
                            if (webEx.InnerException != null)
                                Log($"     Inner: {webEx.InnerException.GetType().Name}: {webEx.InnerException.Message}");
                        }

                        LogRequest(diagService);

                        if (diagService.LastResponseHeaders != null)
                        {
                            LogResponse(diagService);
                        }
                        else if (webEx.Response is HttpWebResponse errorResp)
                        {
                            LogResponseFromException(errorResp);
                        }

                        LogSourcePort(serverEndpoint);
                        failures++;
                    }
                    catch (Exception ex)
                    {
                        sw.Stop();
                        Log($"  << EXCEPTION ({sw.ElapsedMilliseconds}ms): {ex.GetType().Name}: {ex.Message}", ConsoleColor.Red);
                        if (ex.InnerException != null)
                            Log($"     Inner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
                        LogRequest(diagService);
                        LogResponse(diagService);
                        LogSourcePort(serverEndpoint);
                        failures++;
                    }

                    Log("");

                    if (i < iterations)
                    {
                        // In no-reuse mode, close the ServicePoint to force a new connection
                        if (!settings.ReuseConnection)
                        {
                            sp.CloseConnectionGroup("");
                        }

                        Log($"  Waiting {delaySeconds}s...");
                        Thread.Sleep(delaySeconds * 1000);
                    }
                }

                // Summary
                Log("════════════════════════════════════════════════════════════════");
                Log("SUMMARY");
                Log("════════════════════════════════════════════════════════════════");
                Log($"  Mode:     {(settings.ReuseConnection ? "REUSE connection" : "NEW connection each iteration")}");
                Log($"  Passes:   {passes}/{iterations}");
                Log($"  Failures: {failures}/{iterations}");
                Log($"  Result:   {(failures == 0 ? "ALL PASSED" : $"{failures} FAILED")}");
                Log("");

                return failures > 0 ? 1 : 0;
            }
            finally
            {
                _log?.Dispose();
            }
        }

        // ─────────────────────────────────────────────────────────────
        // Diagnostic subclass — captures request/response headers
        // on both success and failure paths
        // ─────────────────────────────────────────────────────────────

        class DiagnosticWebService : AppFxWebService
        {
            public WebHeaderCollection LastRequestHeaders { get; private set; }
            public WebHeaderCollection LastResponseHeaders { get; private set; }
            public string LastRequestMethod { get; private set; }
            public Uri LastRequestUri { get; private set; }
            public HttpStatusCode? LastResponseStatus { get; private set; }
            public string LastResponseServer { get; private set; }

            public bool KeepAlive { get; set; } = true;

            protected override WebRequest GetWebRequest(Uri uri)
            {
                var request = base.GetWebRequest(uri);
                LastRequestUri = uri;
                LastResponseHeaders = null;
                LastResponseStatus = null;
                LastResponseServer = null;

                if (request is HttpWebRequest httpReq)
                {
                    LastRequestMethod = httpReq.Method;
                    LastRequestHeaders = httpReq.Headers;
                    httpReq.KeepAlive = KeepAlive;
                }

                return request;
            }

            protected override WebResponse GetWebResponse(WebRequest request)
            {
                var response = base.GetWebResponse(request);
                CaptureResponse(response);
                return response;
            }

            protected override WebResponse GetWebResponse(WebRequest request, IAsyncResult result)
            {
                var response = base.GetWebResponse(request, result);
                CaptureResponse(response);
                return response;
            }

            void CaptureResponse(WebResponse response)
            {
                if (response is HttpWebResponse httpResp)
                {
                    LastResponseHeaders = httpResp.Headers;
                    LastResponseStatus = httpResp.StatusCode;
                    LastResponseServer = httpResp.Server;
                }
            }
        }

        // ─────────────────────────────────────────────────────────────
        // Unified logging — same format for success and failure
        // ─────────────────────────────────────────────────────────────

        static void LogRequest(DiagnosticWebService svc)
        {
            Log("  Request:");
            if (svc.LastRequestUri != null)
                Log($"     {svc.LastRequestMethod ?? "POST"} {svc.LastRequestUri}");

            if (svc.LastRequestHeaders != null)
            {
                foreach (string header in svc.LastRequestHeaders)
                {
                    var val = svc.LastRequestHeaders[header];
                    if (val != null && val.Length > 200)
                        val = val.Substring(0, 200) + "...";
                    Log($"     {header}: {val}");
                }
                Log($"     KeepAlive: {svc.KeepAlive}");
            }
            else
            {
                Log("     (request headers not captured)");
            }
        }

        static void LogResponse(DiagnosticWebService svc)
        {
            Log("  Response:");
            if (svc.LastResponseHeaders != null)
            {
                if (svc.LastResponseStatus.HasValue)
                    Log($"     Status: {(int)svc.LastResponseStatus.Value} {svc.LastResponseStatus.Value}");
                if (!string.IsNullOrEmpty(svc.LastResponseServer))
                    Log($"     Server: {svc.LastResponseServer}");
                foreach (string header in svc.LastResponseHeaders)
                {
                    var val = svc.LastResponseHeaders[header];
                    if (val != null && val.Length > 200)
                        val = val.Substring(0, 200) + "...";
                    Log($"     {header}: {val}");
                }
            }
            else
            {
                Log("     (response headers not captured via diagnostic proxy — see above for WebException details)");
            }
        }

        static void LogResponseFromException(HttpWebResponse resp)
        {
            Log("  Response:");
            Log($"     Status: {(int)resp.StatusCode} {resp.StatusDescription}");
            if (!string.IsNullOrEmpty(resp.Server))
                Log($"     Server: {resp.Server}");
            foreach (string header in resp.Headers)
            {
                var val = resp.Headers[header];
                if (val != null && val.Length > 200)
                    val = val.Substring(0, 200) + "...";
                Log($"     {header}: {val}");
            }

            try
            {
                using (var reader = new StreamReader(resp.GetResponseStream()))
                {
                    var body = reader.ReadToEnd();
                    if (!string.IsNullOrWhiteSpace(body))
                        Log($"  Response Body: {body.Substring(0, Math.Min(500, body.Length))}");
                }
            }
            catch { }
        }

        // ─────────────────────────────────────────────────────────────
        // Source port logging — find active TCP connection to server
        // ─────────────────────────────────────────────────────────────

        static IPEndPoint ResolveServerEndpoint(string hostname)
        {
            try
            {
                var entry = Dns.GetHostEntry(hostname);
                var ip = entry.AddressList.FirstOrDefault();
                if (ip != null)
                    return new IPEndPoint(ip, 443);
            }
            catch { }
            return null;
        }

        static void LogSourcePort(IPEndPoint serverEndpoint)
        {
            if (serverEndpoint == null)
            {
                Log("  Source Port: (server endpoint unknown)");
                return;
            }

            try
            {
                var connections = IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpConnections()
                    .Where(c => c.RemoteEndPoint.Address.Equals(serverEndpoint.Address)
                             && c.RemoteEndPoint.Port == serverEndpoint.Port)
                    .ToArray();

                if (connections.Length > 0)
                {
                    foreach (var conn in connections)
                    {
                        Log($"  Source Port: {conn.LocalEndPoint.Port} → {conn.RemoteEndPoint} (State: {conn.State})");
                    }
                }
                else
                {
                    Log("  Source Port: (no active TCP connection to server — connection already closed)");
                }
            }
            catch (Exception ex)
            {
                Log($"  Source Port: (unable to determine: {ex.Message})");
            }
        }

        // ─────────────────────────────────────────────────────────────
        // Provider factory — uses diagnostic subclass
        // ─────────────────────────────────────────────────────────────

        class DiagnosticProvider : AppFxWebServiceProvider
        {
            readonly DiagnosticWebService _svc;

            public DiagnosticProvider(DiagnosticWebService svc)
            {
                _svc = svc;
            }

            public string ProxyUrl { get; set; }

            public override AppFxWebService CreateAppFxWebService()
            {
                _svc.Url = this.Url;
                _svc.Credentials = this.Credentials;

                if (!string.IsNullOrEmpty(ProxyUrl))
                    _svc.Proxy = new WebProxy(ProxyUrl);

                return _svc;
            }
        }

        static AppFxWebServiceProvider CreateProvider(Settings settings, DiagnosticWebService diagService)
        {
            var provider = new DiagnosticProvider(diagService);
            provider.Url = settings.ServiceUrl;
            provider.Database = settings.Database;
            provider.ApplicationName = "InfinityAuthWebApiTest";
            provider.ProxyUrl = settings.ProxyUrl;

            var cache = new CredentialCache();
            cache.Add(new Uri(settings.ServiceUrl), "NTLM",
                string.IsNullOrEmpty(settings.Domain)
                    ? new NetworkCredential(settings.Username, settings.Password)
                    : new NetworkCredential(settings.Username, settings.Password, settings.Domain));
            provider.Credentials = cache;

            return provider;
        }

        // ─────────────────────────────────────────────────────────────
        // Helpers
        // ─────────────────────────────────────────────────────────────

        static void Log(string message, ConsoleColor? color = null)
        {
            var timestamped = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";

            _log.WriteLine(timestamped);

            if (color.HasValue)
                Console.ForegroundColor = color.Value;
            Console.WriteLine(timestamped);
            if (color.HasValue)
                Console.ResetColor();
        }

        static string GetPublicIp()
        {
            try
            {
                using (var client = new WebClient())
                    return client.DownloadString("https://api.ipify.org").Trim();
            }
            catch (Exception ex)
            {
                return $"(unable to determine: {ex.Message})";
            }
        }

        static string GetLocalIps()
        {
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                var ips = host.AddressList
                    .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(a => a.ToString())
                    .ToArray();
                return ips.Length > 0 ? string.Join(", ", ips) : "(none)";
            }
            catch
            {
                return "(unable to determine)";
            }
        }

        static string ResolveHost(string hostname)
        {
            try
            {
                var entry = Dns.GetHostEntry(hostname);
                var ips = entry.AddressList
                    .Select(a => a.ToString())
                    .ToArray();
                return ips.Length > 0 ? string.Join(", ", ips) : "(no addresses)";
            }
            catch (Exception ex)
            {
                return $"(unable to resolve: {ex.Message})";
            }
        }

        static string FormatUser(Settings settings)
        {
            return string.IsNullOrEmpty(settings.Domain)
                ? settings.Username
                : $"{settings.Domain}\\{settings.Username}";
        }

        static Settings LoadSettings()
        {
            var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appsettings.json");
            if (!File.Exists(configPath))
            {
                Console.WriteLine($"Missing: {configPath}");
                Environment.Exit(1);
            }

            var json = File.ReadAllText(configPath);
            return new Settings(json);
        }
    }

    class Settings
    {
        public string ServiceUrl { get; }
        public string Database { get; }
        public string Username { get; }
        public string Password { get; }
        public string Domain { get; }
        public bool ReuseConnection { get; }
        public string ProxyUrl { get; }

        public Settings(string json)
        {
            ServiceUrl = Extract(json, "ServiceUrl");
            Database = Extract(json, "Database");
            Username = Extract(json, "Username");
            Password = Extract(json, "Password");
            Domain = Extract(json, "Domain");
            ProxyUrl = Extract(json, "ProxyUrl");

            var reuseStr = Extract(json, "ReuseConnection");
            ReuseConnection = string.Equals(reuseStr, "true", StringComparison.OrdinalIgnoreCase);
        }

        static string Extract(string json, string key)
        {
            var search = $"\"{key}\"";
            var idx = json.IndexOf(search, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return "";

            var colonIdx = json.IndexOf(':', idx + search.Length);
            if (colonIdx < 0) return "";

            // Handle both string values ("value") and bare values (true/false)
            var rest = json.Substring(colonIdx + 1).TrimStart();
            if (rest.Length == 0) return "";

            if (rest[0] == '"')
            {
                var quoteEnd = rest.IndexOf('"', 1);
                return quoteEnd > 0 ? rest.Substring(1, quoteEnd - 1) : "";
            }

            // Bare value (true, false, numbers)
            var end = rest.IndexOfAny(new[] { ',', '}', '\r', '\n' });
            return end > 0 ? rest.Substring(0, end).Trim() : rest.Trim();
        }
    }
}
