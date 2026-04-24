using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.RateLimiting;

// ─── Load .env ────────────────────────────────────────────────────────────────
var envFile = Path.Combine(AppContext.BaseDirectory, ".env");
if (File.Exists(envFile))
{
    foreach (var line in File.ReadAllLines(envFile))
    {
        if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#')) continue;
        var idx = line.IndexOf('=');
        if (idx < 1) continue;
        Environment.SetEnvironmentVariable(line[..idx].Trim(), line[(idx + 1)..].Trim());
    }
}

static string Cfg(string key, string fallback = "") =>
    Environment.GetEnvironmentVariable(key) ?? fallback;

// ─── OTP store (in-memory) ────────────────────────────────────────────────────
var _otpStore = new ConcurrentDictionary<string, (string Code, DateTime Expiry)>();

string OtpGenerate(string username)
{
    var code   = RandomNumberGenerator.GetInt32(100000, 1000000).ToString("D6");
    var expiry = DateTime.UtcNow.AddSeconds(int.TryParse(Cfg("OTP_TTL_SECONDS", "300"), out var t) ? t : 300);
    _otpStore[username.ToLowerInvariant()] = (code, expiry);
    return code;
}

(bool Valid, string Reason) OtpValidate(string username, string code)
{
    var key = username.ToLowerInvariant();
    if (!_otpStore.TryGetValue(key, out var entry))
        return (false, "No OTP was requested for this user.");
    if (DateTime.UtcNow > entry.Expiry)
    {
        _otpStore.TryRemove(key, out _);
        return (false, "OTP has expired. Request a new one.");
    }
    if (entry.Code != code)
        return (false, "Invalid OTP.");
    _otpStore.TryRemove(key, out _);
    return (true, "OK");
}

// ─── LDAP helpers ─────────────────────────────────────────────────────────────
static string LdapEscape(string s) =>
    s.Replace("\\", "\\5c").Replace("*",  "\\2a")
     .Replace("(",  "\\28").Replace(")",  "\\29")
     .Replace("\0", "\\00");

LdapConnection CreateLdap()
{
    var url  = new Uri(Cfg("AD_URL", "ldaps://172.16.10.4:636"));
    var id   = new LdapDirectoryIdentifier(url.Host, url.Port, false, false);
    var conn = new LdapConnection(id)
    {
        AuthType = AuthType.Basic,
        Timeout  = TimeSpan.FromSeconds(10),
    };
    conn.SessionOptions.ProtocolVersion         = 3;
    conn.SessionOptions.SecureSocketLayer       = true;
    conn.SessionOptions.VerifyServerCertificate = (_, _) => true;
    return conn;
}

(string? Dn, string? Mail, string? DisplayName) AdFindUser(string username)
{
    using var conn = CreateLdap();
    conn.Bind(new NetworkCredential(Cfg("AD_BIND_DN"), Cfg("AD_BIND_PASSWORD")));

    var filter = $"(&(objectClass=user)(sAMAccountName={LdapEscape(username)})" +
                  "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    var req  = new SearchRequest(Cfg("AD_BASE_DN", "DC=viz,DC=in"), filter,
                                 SearchScope.Subtree, "mail", "displayName");
    req.SizeLimit = 1;

    var resp = (SearchResponse)conn.SendRequest(req);
    if (resp.Entries.Count == 0) return (null, null, null);

    var e    = resp.Entries[0];
    var mail = e.Attributes["mail"]?[0]?.ToString();
    var name = e.Attributes["displayName"]?[0]?.ToString() ?? username;
    return mail is null ? (null, null, null) : (e.DistinguishedName, mail, name);
}

void AdResetPassword(string dn, string newPassword)
{
    using var conn = CreateLdap();
    conn.Bind(new NetworkCredential(Cfg("AD_BIND_DN"), Cfg("AD_BIND_PASSWORD")));

    var encoded = Encoding.Unicode.GetBytes($"\"{newPassword}\"");
    var mod     = new DirectoryAttributeModification
    {
        Name      = "unicodePwd",
        Operation = DirectoryAttributeOperation.Replace,
    };
    mod.Add(encoded);
    conn.SendRequest(new ModifyRequest(dn, mod));
}

// ─── Email helper ─────────────────────────────────────────────────────────────
static async Task SendOtpEmail(string to, string displayName, string otp, int ttlSeconds)
{
    var minutes = ttlSeconds / 60;
    var text = string.Join("\r\n",
        $"Hello {displayName},",
        "",
        "You requested a password reset for your Active Directory account.",
        "",
        $"Your one-time code is:  {otp}",
        "",
        $"This code expires in {minutes} minute(s).",
        "If you did not request this, ignore this email.",
        "",
        "— IT Support");

    using var smtp = new SmtpClient(Cfg("SMTP_HOST"))
    {
        Port        = int.TryParse(Cfg("SMTP_PORT", "587"), out var p) ? p : 587,
        EnableSsl   = true,
        Credentials = new NetworkCredential(Cfg("SMTP_USER"), Cfg("SMTP_PASSWORD")),
    };

    using var msg = new MailMessage
    {
        From       = new MailAddress(Cfg("SMTP_USER"), "IT Support"),
        Subject    = $"Password reset code: {otp}",
        Body       = text,
        IsBodyHtml = false,
    };
    msg.To.Add(to);
    await smtp.SendMailAsync(msg);
}

// ─── Build app ────────────────────────────────────────────────────────────────
var builder = WebApplication.CreateBuilder(args);

builder.Host.UseWindowsService();

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddEventLog(s => s.SourceName = "ResetPasswordAPI");

builder.WebHost.ConfigureKestrel(k =>
{
    var port = int.TryParse(Cfg("PORT", "8443"), out var p) ? p : 8443;
    var pfx  = Cfg("TLS_PFX_PATH");
    var pass = Cfg("TLS_PFX_PASSWORD", "");

    if (string.IsNullOrEmpty(pfx) || !File.Exists(pfx))
    {
        Console.Error.WriteLine($"[FATAL] TLS_PFX_PATH not found: {pfx}");
        Environment.Exit(1);
    }
    k.Listen(IPAddress.Any, port, o => o.UseHttps(pfx, pass));
    Console.WriteLine($"Listening on HTTPS port {port}");
});

builder.Services.AddRateLimiter(rl =>
{
    var max = int.TryParse(Cfg("RATE_LIMIT_MAX", "10"), out var m) ? m : 10;
    rl.AddFixedWindowLimiter("auth", o =>
    {
        o.Window      = TimeSpan.FromMinutes(15);
        o.PermitLimit = max;
        o.QueueLimit  = 0;
    });
    rl.OnRejected = async (ctx, _) =>
    {
        ctx.HttpContext.Response.StatusCode  = 429;
        ctx.HttpContext.Response.ContentType = "application/json";
        await ctx.HttpContext.Response.WriteAsync(
            "{\"message\":\"Too many requests. Try again in 15 minutes.\"}");
    };
});

var app = builder.Build();
app.UseRateLimiter();

// ─── Routes ───────────────────────────────────────────────────────────────────

app.MapGet("/health", () =>
    Results.Ok(new { status = "ok", time = DateTime.UtcNow.ToString("o") }));

// POST /api/auth/request-otp
app.MapPost("/api/auth/request-otp", async (HttpContext ctx) =>
{
    JsonElement root;
    try   { using var doc = await JsonDocument.ParseAsync(ctx.Request.Body); root = doc.RootElement.Clone(); }
    catch { return Results.Json(new { message = "Invalid JSON." }, statusCode: 400); }

    var username = root.TryGetProperty("username", out var u) ? u.GetString()?.Trim() : null;
    if (string.IsNullOrEmpty(username))
        return Results.Json(new { message = "Username is required." }, statusCode: 400);

    string? dn, mail, displayName;
    try   { (dn, mail, displayName) = AdFindUser(username); }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[request-otp] AD error: {ex.Message}");
        return Results.Json(new { message = "Failed to contact directory server." }, statusCode: 500);
    }

    if (dn is null || mail is null)
        return Results.Json(new { message = "User not found or account disabled." }, statusCode: 404);

    var otp = OtpGenerate(username);
    var ttl = int.TryParse(Cfg("OTP_TTL_SECONDS", "300"), out var t) ? t : 300;

    try   { await SendOtpEmail(mail, displayName!, otp, ttl); }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[request-otp] Email error: {ex.Message}");
        return Results.Json(new { message = "Could not send OTP email. Contact IT support." }, statusCode: 500);
    }

    Console.WriteLine($"[request-otp] OTP sent: {username} → {mail}");
    return Results.Ok(new { message = "OTP sent to your registered email address." });

}).RequireRateLimiting("auth");

// POST /api/auth/reset-password
app.MapPost("/api/auth/reset-password", async (HttpContext ctx) =>
{
    JsonElement root;
    try   { using var doc = await JsonDocument.ParseAsync(ctx.Request.Body); root = doc.RootElement.Clone(); }
    catch { return Results.Json(new { message = "Invalid JSON." }, statusCode: 400); }

    var username    = root.TryGetProperty("username",    out var u)  ? u.GetString()?.Trim() : null;
    var otp         = root.TryGetProperty("otp",         out var o)  ? o.GetString()?.Trim() : null;
    var newPassword = root.TryGetProperty("newPassword", out var np) ? np.GetString()         : null;

    if (string.IsNullOrEmpty(username))
        return Results.Json(new { message = "Username is required." }, statusCode: 400);
    if (string.IsNullOrEmpty(otp))
        return Results.Json(new { message = "OTP is required." }, statusCode: 400);
    if (string.IsNullOrEmpty(newPassword) || newPassword.Length < 12)
        return Results.Json(new { message = "New password must be at least 8 characters." }, statusCode: 400);

    var (valid, reason) = OtpValidate(username, otp);
    if (!valid)
        return Results.Json(new { message = reason }, statusCode: 401);

    string? dn;
    try   { (dn, _, _) = AdFindUser(username); }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[reset-password] AD error: {ex.Message}");
        return Results.Json(new { message = "Failed to contact directory server." }, statusCode: 500);
    }

    if (dn is null)
        return Results.Json(new { message = "User not found or account disabled." }, statusCode: 404);

    try   { AdResetPassword(dn, newPassword); }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[reset-password] Reset failed: {ex.Message}");
        var msg = (ex.Message.Contains("constraint") || ex.Message.Contains("52D"))
            ? "Password does not meet domain complexity requirements."
            : ex.Message;
        return Results.Json(new { message = msg }, statusCode: 400);
    }

    Console.WriteLine($"[reset-password] Success: {username}");
    return Results.Ok(new { message = "Password reset successfully." });

}).RequireRateLimiting("auth");

app.Run();
