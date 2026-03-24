using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
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
            var logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"auth-test-{DateTime.Now:yyyyMMdd-HHmmss}.log");
            _log = new StreamWriter(logPath, append: true) { AutoFlush = true };

            try
            {
                var settings = LoadSettings();

                Log("════════════════════════════════════════════════════════════════");
                Log("InfinityAuthWebApiTest — NTLM Auth Soak Test");
                Log("════════════════════════════════════════════════════════════════");
                Log($"URL:      {settings.ServiceUrl}");
                Log($"Database: {settings.Database}");
                Log($"User:     {FormatUser(settings)}");
                Log($"Auth:     NTLM");
                Log($"Log:      {logPath}");
                Log("");

                // Network info
                var publicIp = GetPublicIp();
                Log($"Public IP:   {publicIp}");
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
                Log($"Connection Limit: {sp.ConnectionLimit}");
                Log("");

                const int iterations = 10;
                const int delaySeconds = 5;
                int passes = 0;
                int failures = 0;

                Log($"Running {iterations} iterations with {delaySeconds}s delay between each");
                Log("────────────────────────────────────────────────────────────────");
                Log("");

                for (int i = 1; i <= iterations; i++)
                {
                    Log($"── Iteration {i}/{iterations} ──");

                    var diagService = new DiagnosticWebService();
                    var provider = CreateProvider(settings, diagService);
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

                        // Log request/response details on success
                        LogDiagnostics(diagService);
                        passes++;
                    }
                    catch (SoapException soapEx)
                    {
                        sw.Stop();
                        Log($"  << SOAP ERROR ({sw.ElapsedMilliseconds}ms): {soapEx.Message}", ConsoleColor.Red);
                        LogDiagnostics(diagService);
                        failures++;
                    }
                    catch (WebException webEx)
                    {
                        sw.Stop();
                        if (webEx.Response is HttpWebResponse resp)
                        {
                            Log($"  << HTTP {(int)resp.StatusCode} {resp.StatusDescription} ({sw.ElapsedMilliseconds}ms)", ConsoleColor.Red);
                            Log("  Response Headers:");
                            foreach (string header in resp.Headers)
                                Log($"     {header}: {resp.Headers[header]}");

                            // Try to read response body
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
                        else
                        {
                            Log($"  << WebException ({sw.ElapsedMilliseconds}ms): {webEx.Message}", ConsoleColor.Red);
                            if (webEx.InnerException != null)
                                Log($"     Inner: {webEx.InnerException.GetType().Name}: {webEx.InnerException.Message}");
                        }

                        LogDiagnostics(diagService);
                        failures++;
                    }
                    catch (Exception ex)
                    {
                        sw.Stop();
                        Log($"  << EXCEPTION ({sw.ElapsedMilliseconds}ms): {ex.GetType().Name}: {ex.Message}", ConsoleColor.Red);
                        if (ex.InnerException != null)
                            Log($"     Inner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
                        LogDiagnostics(diagService);
                        failures++;
                    }

                    Log("");

                    if (i < iterations)
                    {
                        Log($"  Waiting {delaySeconds}s...");
                        Thread.Sleep(delaySeconds * 1000);
                    }
                }

                // Summary
                Log("════════════════════════════════════════════════════════════════");
                Log("SUMMARY");
                Log("════════════════════════════════════════════════════════════════");
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
        // ─────────────────────────────────────────────────────────────

        class DiagnosticWebService : AppFxWebService
        {
            public WebHeaderCollection LastRequestHeaders { get; private set; }
            public WebHeaderCollection LastResponseHeaders { get; private set; }
            public string LastRequestMethod { get; private set; }
            public Uri LastRequestUri { get; private set; }
            public HttpStatusCode? LastResponseStatus { get; private set; }
            public string LastResponseServer { get; private set; }

            protected override WebRequest GetWebRequest(Uri uri)
            {
                var request = base.GetWebRequest(uri);
                LastRequestUri = uri;

                if (request is HttpWebRequest httpReq)
                {
                    LastRequestMethod = httpReq.Method;
                    // Headers aren't fully populated until send, capture what we can
                    LastRequestHeaders = httpReq.Headers;
                }

                return request;
            }

            protected override WebResponse GetWebResponse(WebRequest request)
            {
                var response = base.GetWebResponse(request);

                if (response is HttpWebResponse httpResp)
                {
                    LastResponseHeaders = httpResp.Headers;
                    LastResponseStatus = httpResp.StatusCode;
                    LastResponseServer = httpResp.Server;
                }

                return response;
            }
        }

        static void LogDiagnostics(DiagnosticWebService svc)
        {
            if (svc.LastRequestUri != null)
            {
                Log($"  Request:");
                Log($"     {svc.LastRequestMethod ?? "POST"} {svc.LastRequestUri}");
                if (svc.LastRequestHeaders != null)
                {
                    foreach (string header in svc.LastRequestHeaders)
                    {
                        // Skip large/noisy headers
                        var val = svc.LastRequestHeaders[header];
                        if (val != null && val.Length > 200)
                            val = val.Substring(0, 200) + "...";
                        Log($"     {header}: {val}");
                    }
                }
            }

            if (svc.LastResponseHeaders != null)
            {
                Log($"  Response:");
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

            public override AppFxWebService CreateAppFxWebService()
            {
                _svc.Url = this.Url;
                _svc.Credentials = this.Credentials;
                return _svc;
            }
        }

        static AppFxWebServiceProvider CreateProvider(Settings settings, DiagnosticWebService diagService)
        {
            var provider = new DiagnosticProvider(diagService);
            provider.Url = settings.ServiceUrl;
            provider.Database = settings.Database;
            provider.ApplicationName = "InfinityAuthWebApiTest";

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

        public Settings(string json)
        {
            ServiceUrl = Extract(json, "ServiceUrl");
            Database = Extract(json, "Database");
            Username = Extract(json, "Username");
            Password = Extract(json, "Password");
            Domain = Extract(json, "Domain");
        }

        static string Extract(string json, string key)
        {
            var search = $"\"{key}\"";
            var idx = json.IndexOf(search, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return "";

            var colonIdx = json.IndexOf(':', idx + search.Length);
            if (colonIdx < 0) return "";

            var quoteStart = json.IndexOf('"', colonIdx + 1);
            if (quoteStart < 0) return "";

            var quoteEnd = json.IndexOf('"', quoteStart + 1);
            if (quoteEnd < 0) return "";

            return json.Substring(quoteStart + 1, quoteEnd - quoteStart - 1);
        }
    }
}
