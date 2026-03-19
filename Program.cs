using System;
using System.Diagnostics;
using System.IO;
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

                // Get public IP (like ipchicken)
                var publicIp = GetPublicIp();
                Log($"Public IP:  {publicIp}");
                Log($"Local IPs:  {GetLocalIps()}");
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

                    var provider = CreateProvider(settings);
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
                        passes++;
                    }
                    catch (SoapException soapEx)
                    {
                        sw.Stop();
                        Log($"  << SOAP ERROR ({sw.ElapsedMilliseconds}ms): {soapEx.Message}", ConsoleColor.Red);
                        failures++;
                    }
                    catch (WebException webEx)
                    {
                        sw.Stop();
                        if (webEx.Response is HttpWebResponse resp)
                        {
                            Log($"  << HTTP {(int)resp.StatusCode} {resp.StatusDescription} ({sw.ElapsedMilliseconds}ms)", ConsoleColor.Red);

                            // Log response headers
                            foreach (string header in resp.Headers)
                                Log($"     {header}: {resp.Headers[header]}");
                        }
                        else
                        {
                            Log($"  << WebException ({sw.ElapsedMilliseconds}ms): {webEx.Message}", ConsoleColor.Red);
                        }
                        failures++;
                    }
                    catch (Exception ex)
                    {
                        sw.Stop();
                        Log($"  << EXCEPTION ({sw.ElapsedMilliseconds}ms): {ex.GetType().Name}: {ex.Message}", ConsoleColor.Red);
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

        static void Log(string message, ConsoleColor? color = null)
        {
            var timestamped = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";

            // Write to log file
            _log.WriteLine(timestamped);

            // Write to console (with optional color)
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
                {
                    var ip = client.DownloadString("https://api.ipify.org").Trim();
                    return ip;
                }
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
                var ips = new System.Collections.Generic.List<string>();
                foreach (var addr in host.AddressList)
                {
                    if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        ips.Add(addr.ToString());
                }
                return ips.Count > 0 ? string.Join(", ", ips) : "(none)";
            }
            catch
            {
                return "(unable to determine)";
            }
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

        static AppFxWebServiceProvider CreateProvider(Settings settings)
        {
            var provider = new AppFxWebServiceProvider();
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

        static string FormatUser(Settings settings)
        {
            return string.IsNullOrEmpty(settings.Domain)
                ? settings.Username
                : $"{settings.Domain}\\{settings.Username}";
        }
    }

    /// <summary>
    /// Minimal JSON settings reader — avoids Newtonsoft dependency.
    /// </summary>
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
