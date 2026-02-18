using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => {
    options.ListenLocalhost(8765);
});
builder.Services.AddCors(o => o.AddDefaultPolicy(b => b.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));
var app = builder.Build();
app.UseCors();

var LOG_DIR = Path.Combine(AppContext.BaseDirectory, "logs");
Directory.CreateDirectory(LOG_DIR);
string LogFile() => Path.Combine(LOG_DIR, DateTime.UtcNow.ToString("yyyyMMdd") + ".log");
void LogLine(string category, string text)
{
    var line = $"{DateTime.UtcNow:o} [{category}] {text}";
    File.AppendAllText(LogFile(), line + Environment.NewLine);
}
string Trunc(string? s, int max = 4000) => string.IsNullOrEmpty(s) ? "" : (s!.Length <= max ? s : s!.Substring(0, max));
string AttemptsFile() => Path.Combine(LOG_DIR, "attempts.jsonl");
void AppendAttempt(object obj)
{
    var line = System.Text.Json.JsonSerializer.Serialize(obj);
    File.AppendAllText(AttemptsFile(), line + Environment.NewLine);
}
var EXPORT_DIR = Path.Combine(AppContext.BaseDirectory, "exports");
Directory.CreateDirectory(EXPORT_DIR);
string ExportPath(string name) => Path.Combine(EXPORT_DIR, name);

// CONFIGURAZIONE FILE -> PASSWORD
var COMPANIES = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
    { "certificato.p12", Environment.GetEnvironmentVariable("RENTRI_CERT_PASS_GLOBAL") ?? "2$i5)*-H" },      
    { "08934760961.p12", Environment.GetEnvironmentVariable("RENTRI_CERT_PASS_GLOBAL") ?? "2$i5)*-H" },      
    { "niyol.p12",       Environment.GetEnvironmentVariable("RENTRI_CERT_PASS_NIYOL") ?? "86v@1|mG" },      
    { "multyproget.p12", Environment.GetEnvironmentVariable("RENTRI_CERT_PASS_MULTY") ?? "1k+F_9nN" }       
};

// HELPER PER SCRIVERE CERTIFICATI DA BASE64 SU DISCO ALL'AVVIO
void RestoreCertificates() {
    var globalBase64 = Environment.GetEnvironmentVariable("RENTRI_CERT_BASE64_GLOBAL");
    if (!string.IsNullOrEmpty(globalBase64)) File.WriteAllBytes("certificato.p12", Convert.FromBase64String(globalBase64));

    var multyBase64 = Environment.GetEnvironmentVariable("RENTRI_CERT_BASE64_MULTY");
    if (!string.IsNullOrEmpty(multyBase64)) File.WriteAllBytes("multyproget.p12", Convert.FromBase64String(multyBase64));

    var niyolBase64 = Environment.GetEnvironmentVariable("RENTRI_CERT_BASE64_NIYOL");
    if (!string.IsNullOrEmpty(niyolBase64)) File.WriteAllBytes("niyol.p12", Convert.FromBase64String(niyolBase64));
}
RestoreCertificates();

// CONFIGURAZIONE ISSUER SEPARATA
// POST: usare CF dell'operatore come issuer
var POST_ISSUERS = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
    { "certificato.p12", "08934760961" },
    { "08934760961.p12", "08934760961" },
    { "niyol.p12",       "09879800010" },
    { "multyproget.p12", "12347770013" }
};
// GET: usare CF dell'operatore come issuer
var GET_ISSUERS = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
    { "certificato.p12", "08934760961" },
    { "08934760961.p12", "08934760961" },
    { "niyol.p12",       "09879800010" },
    { "multyproget.p12", "12347770013" }
};

const string AUDIENCE = "rentrigov.api";

X509Certificate2? LoadCert(string filename) { 
    if (!COMPANIES.ContainsKey(filename)) return null; 
    var candidates = new [] {
        Path.Combine(Directory.GetCurrentDirectory(), filename),
        Path.Combine(AppContext.BaseDirectory, filename),
        Path.Combine(Directory.GetCurrentDirectory(), "bridge-service", filename)
    };
    string? path = candidates.FirstOrDefault(File.Exists);
    if (string.IsNullOrEmpty(path)) return null; 
    return new X509Certificate2(path, COMPANIES[filename], X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet); 
} 

Console.ForegroundColor = ConsoleColor.Yellow; 
Console.WriteLine("--- BRIDGE RENTRI UFFICIALE (SELF-SIGNED TOKENS) ---"); 
app.MapGet("/health", () => Results.Ok(new { status = "ok" })); 

app.MapPost("/send-rentri", async ([FromBody] RentriRequest req) => { 
    try { 
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename; 
        var cert = LoadCert(fname); 
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato."); 

        string? issuer = null;
        bool isGet = req.url.Contains("/status") || req.url.Contains("/transazioni/") || req.url.Contains("?limit");
        if (!string.IsNullOrWhiteSpace(req.issuer)) issuer = req.issuer;
        if (isGet) {
            if (GET_ISSUERS.TryGetValue(fname, out var knownGet)) issuer = knownGet;
        } else {
            if (POST_ISSUERS.TryGetValue(fname, out var knownPost)) issuer = knownPost;
        }
        if (string.IsNullOrWhiteSpace(issuer)) {
            try {
                var subj = cert.Subject;
                var marker = "dnQualifier=";
                var idx = subj.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (idx >= 0) {
                    var start = idx + marker.Length;
                    var end = subj.IndexOf(',', start);
                    issuer = end >= 0 ? subj.Substring(start, end - start).Trim() : subj.Substring(start).Trim();
                }
            } catch { }
        }
        if (string.IsNullOrWhiteSpace(issuer)) issuer = POST_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        Console.WriteLine($"[AGID] Firma con Issuer: {issuer}"); 

        // 1. Metodo e Digest (POST vs GET)
        ByteArrayContent? content = null;
        string contentTypeString;
        string digestHeader;
        if (!isGet) {
            var contentBytes = Encoding.UTF8.GetBytes(req.payload);
            content = new ByteArrayContent(contentBytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            contentTypeString = content.Headers.ContentType?.ToString() ?? "application/json";
            using var sha256 = SHA256.Create();
            var hash = Convert.ToBase64String(sha256.ComputeHash(contentBytes));
            digestHeader = $"SHA-256={hash}";
        } else {
            // SHA256("") in Base64
            digestHeader = "SHA-256=47DEQpj8HBSa+/TImW+JCeuQeRkm5NMpJWZG3hSuFU=";
            contentTypeString = "application/json";
        }
        // 2. Generazione Token (Authorization + Integrity) 
        string tokenAuth, tokenInteg; 
        var now = DateTime.UtcNow; 
        var jti = Guid.NewGuid().ToString();
        var aud = req.url.Contains("demoapi.rentri.gov.it") ? "rentrigov.demo.api" : AUDIENCE;
        LogLine("send.init", $"method={(isGet?"GET":"POST")} url={req.url} iss={issuer} aud={aud}");

        // Chiavi prive: non usare using per evitare dispose anticipato
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }

        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = false;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.Build(cert);
        var x5cList = chain.ChainElements
            .Cast<X509ChainElement>()
            .Select(e => Convert.ToBase64String(e.Certificate.Export(X509ContentType.Cert)))
            .ToArray();
        Console.WriteLine($"[CERT] Subject: {cert.Subject}");
        Console.WriteLine($"[CERT] Thumbprint: {cert.Thumbprint}");
        Console.WriteLine($"[CERT] x5c elements: {x5cList.Length}");
        Console.WriteLine($"[CERT] SerialNumber: {cert.SerialNumber}");
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };

        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", jti } },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        tokenAuth = tokenHandler.CreateToken(idDesc);
        Console.WriteLine($"[POST/GET] {(isGet?"GET":"POST")} {req.url}");

        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", jti },
                { "signed_headers", (!isGet
                    ? new object[] {
                        new Dictionary<string, string> { { "digest", digestHeader } },
                        new Dictionary<string, string> { { "content-type", contentTypeString } }
                      }
                    : new object[] {
                        new Dictionary<string, string> { { "digest", digestHeader } }
                      }
                  ) }
            },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        tokenInteg = tokenHandler.CreateToken(intDesc);
        Console.WriteLine($"[HDR] Digest set, Integrity signed");

        // 3. Invio 
        var httpHandler = new HttpClientHandler(); 
        httpHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
        httpHandler.ClientCertificates.Add(cert); 
        
        using var client = new HttpClient(httpHandler); 
        var requestMsg = new HttpRequestMessage(isGet ? HttpMethod.Get : HttpMethod.Post, req.url); 
        if (!isGet && content != null) requestMsg.Content = content; 
        
        requestMsg.Headers.Add("Authorization", $"Bearer {tokenAuth}"); 
        requestMsg.Headers.Add("Digest", digestHeader); 
        requestMsg.Headers.Add("Agid-JWT-Signature", tokenInteg); 
        if (!string.IsNullOrWhiteSpace(req.replyTo)) requestMsg.Headers.Add("X-ReplyTo", req.replyTo);
        requestMsg.Headers.Add("Accept", "application/json, application/problem+json");
        
        var response = await client.SendAsync(requestMsg); 
        var responseString = await response.Content.ReadAsStringAsync(); 
        Console.WriteLine($"[RES] {(int)response.StatusCode}"); 
        LogLine("send.resp", $"method={(isGet?"GET":"POST")} url={req.url} status={(int)response.StatusCode}");
        try {
            AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = isGet ? "GET" : "POST", url = req.url, filename = fname, issuer, status = (int)response.StatusCode, data = responseString });
        } catch {}
        return Results.Ok(new { success = response.IsSuccessStatusCode, status = (int)response.StatusCode, data = responseString, jti }); 
        
    } catch (Exception ex) { 
        Console.WriteLine($"[ERROR] {ex.ToString()}"); 
        LogLine("send.error", Trunc(ex.ToString(), 4000));
        return Results.Problem(ex.Message); 
    } 
}); 

app.MapPost("/send-registrazioni", async ([FromBody] RentriRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");

        string? issuer = null;
        if (!string.IsNullOrWhiteSpace(req.issuer)) issuer = req.issuer;
        if (POST_ISSUERS.TryGetValue(fname, out var knownIssuer2)) issuer = knownIssuer2;
        if (string.IsNullOrWhiteSpace(issuer)) {
            try {
                var subj = cert.Subject;
                var marker = "dnQualifier=";
                var idx = subj.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (idx >= 0) {
                    var start = idx + marker.Length;
                    var end = subj.IndexOf(',', start);
                    issuer = end >= 0 ? subj.Substring(start, end - start).Trim() : subj.Substring(start).Trim();
                }
            } catch { }
        }
        if (string.IsNullOrWhiteSpace(issuer)) issuer = POST_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        Console.WriteLine($"[AGID] Firma con Issuer: {issuer}");

        var contentBytes = Encoding.UTF8.GetBytes(req.payload);
        var content = new ByteArrayContent(contentBytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        var contentTypeString = content.Headers.ContentType?.ToString() ?? "application/json";
        using var sha256 = SHA256.Create();
        var hash = Convert.ToBase64String(sha256.ComputeHash(contentBytes));
        var digestHeader = $"SHA-256={hash}";
        Console.WriteLine($"[DEBUG] Digest: {digestHeader}");
        Console.WriteLine($"[DEBUG] Content-Type firmato: {contentTypeString}");

        var now = DateTime.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var aud = req.url.Contains("demoapi.rentri.gov.it") ? "rentrigov.demo.api" : AUDIENCE;
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };
        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", jti } },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenAuth = tokenHandler.CreateToken(idDesc);
        digestHeader = "SHA-256=47DEQpj8HBSa+/TImW+JCeuQeRkm5NMpJWZG3hSuFU=";
        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", jti },
                { "signed_headers", new object[] { new Dictionary<string, string> { { "digest", digestHeader } } } }
            },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenInteg = tokenHandler.CreateToken(intDesc);
        var intDesc2 = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", jti },
                { "signed_headers", new[] {
                    new Dictionary<string, string> { { "digest", digestHeader } },
                    new Dictionary<string, string> { { "content-type", contentTypeString } }
                }}
            },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenInteg2 = tokenHandler.CreateToken(intDesc2);

        var httpHandler = new HttpClientHandler();
        httpHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
        httpHandler.ClientCertificates.Add(cert);
        using var client = new HttpClient(httpHandler);
        var requestMsg = new HttpRequestMessage(HttpMethod.Post, req.url);
        requestMsg.Content = content;
        requestMsg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
        requestMsg.Headers.Add("Digest", digestHeader);
        requestMsg.Headers.Add("Agid-JWT-Signature", tokenInteg2);
        if (!string.IsNullOrWhiteSpace(req.replyTo)) requestMsg.Headers.Add("X-ReplyTo", req.replyTo);
        requestMsg.Headers.Add("Accept", "application/json, application/problem+json");
        Console.WriteLine($"[POST] {req.url}");
        var response = await client.SendAsync(requestMsg);
        var responseString = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"[RENTRI] {(int)response.StatusCode}");
        if (!string.IsNullOrWhiteSpace(responseString)) Console.WriteLine($"[BODY] {responseString}");
        LogLine("registrazioni.resp", $"url={req.url} status={(int)response.StatusCode} body={Trunc(responseString)}");
        try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "POST", url = req.url, filename = fname, issuer, status = (int)response.StatusCode, data = responseString }); } catch {}
        return Results.Ok(new { success = response.IsSuccessStatusCode, status = (int)response.StatusCode, data = responseString, jti = jti });
    } catch (Exception ex) { Console.WriteLine($"[ERROR] {ex}"); LogLine("registrazioni.error", Trunc(ex.ToString(), 4000)); return Results.Problem(ex.Message); }
});
app.MapPost("/list-rentri", async ([FromBody] RentriListRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");

        string? issuer = null;
        try {
            var subj = cert.Subject;
            var marker = "dnQualifier=";
            var idx = subj.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0) {
                var start = idx + marker.Length;
                var end = subj.IndexOf(',', start);
                issuer = end >= 0 ? subj.Substring(start, end - start).Trim() : subj.Substring(start).Trim();
            }
        } catch { }
        if (!string.IsNullOrWhiteSpace(req.issuer)) issuer = req.issuer;
        if (string.IsNullOrWhiteSpace(issuer) && GET_ISSUERS.TryGetValue(fname, out var knownIssuer2)) issuer = knownIssuer2;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = GET_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        Console.WriteLine($"[AGID LIST] Issuer: {issuer}");

        var now = DateTime.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var aud = req.url.Contains("demoapi.rentri.gov.it") ? "rentrigov.demo.api" : AUDIENCE;

        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };

        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", jti } },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenAuth = tokenHandler.CreateToken(idDesc);
        var digestHeader = "SHA-256=47DEQpj8HBSa+/TImW+JCeuQeRkm5NMpJWZG3hSuFU=";
        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", jti },
                { "signed_headers", new object[] { new Dictionary<string, string> { { "digest", digestHeader } } } }
            },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenInteg = tokenHandler.CreateToken(intDesc);

        var handler = new HttpClientHandler();
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        handler.ClientCertificates.Add(cert);
        using var client = new HttpClient(handler);
        var msg = new HttpRequestMessage(HttpMethod.Get, req.url);
        msg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
        msg.Headers.Add("Digest", digestHeader);
        msg.Headers.Add("Agid-JWT-Signature", tokenInteg);
        msg.Headers.Add("Accept", "application/json");
        var resp = await client.SendAsync(msg);
        var body = await resp.Content.ReadAsStringAsync();
        LogLine("list.registrazioni", $"url={req.url} status={(int)resp.StatusCode}");
        try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "GET", url = req.url, filename = fname, issuer, status = (int)resp.StatusCode, data = body }); } catch {}
        return Results.Ok(new { success = resp.IsSuccessStatusCode, status = (int)resp.StatusCode, data = body });
    } catch (Exception ex) {
        LogLine("list.registrazioni.error", Trunc(ex.ToString(), 4000));
        return Results.Problem(ex.Message);
    }
});

app.MapPost("/create-registro", async ([FromBody] CreateRegistroRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");

        string? issuer = null;
        try {
            var subj = cert.Subject;
            var marker = "dnQualifier=";
            var idx = subj.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0) {
                var start = idx + marker.Length;
                var end = subj.IndexOf(',', start);
                issuer = end >= 0 ? subj.Substring(start, end - start).Trim() : subj.Substring(start).Trim();
            }
        } catch { }
        if (!string.IsNullOrWhiteSpace(req.issuer)) issuer = req.issuer;
        if (string.IsNullOrWhiteSpace(issuer) && POST_ISSUERS.TryGetValue(fname, out var knownIssuer3)) issuer = knownIssuer3;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = POST_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        Console.WriteLine($"[AGID] Firma con Issuer: {issuer}");

        var payloadObj = new {
            numIscrSito = req.numIscrSito,
            attivita = req.attivita ?? new [] { "Recupero" },
            attivita_rec_smalt = req.attivitaRecSmalt ?? new [] { "R4", "R12", "R13" },
            descrizione = req.descrizione ?? "Registro creato via interoperabilita"
        };
        var payloadJson = System.Text.Json.JsonSerializer.Serialize(payloadObj);
        var contentBytes = Encoding.UTF8.GetBytes(payloadJson);
        var content = new ByteArrayContent(contentBytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        var contentTypeString = content.Headers.ContentType?.ToString() ?? "application/json";
        using var sha256 = SHA256.Create();
        var hash = Convert.ToBase64String(sha256.ComputeHash(contentBytes));
        var digestHeader = $"SHA-256={hash}";

        var now = DateTime.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var aud = AUDIENCE;
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };
        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", jti } },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenAuth = tokenHandler.CreateToken(idDesc);
        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", jti },
                { "signed_headers", new[] {
                    new Dictionary<string, string> { { "digest", digestHeader } },
                    new Dictionary<string, string> { { "content-type", contentTypeString } }
                }}
            },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            SigningCredentials = creds
        };
        var tokenInteg = tokenHandler.CreateToken(intDesc);

        var httpHandler = new HttpClientHandler();
        httpHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
        httpHandler.ClientCertificates.Add(cert);
        using var client = new HttpClient(httpHandler);
        var basePath = req.basePath?.TrimEnd('/') ?? "https://api.rentri.gov.it/anagrafiche/v1.0";
        var requestMsg = new HttpRequestMessage(HttpMethod.Post, $"{basePath}/registri");
        requestMsg.Content = content;
        requestMsg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
        requestMsg.Headers.Add("Digest", digestHeader);
        requestMsg.Headers.Add("Agid-JWT-Signature", tokenInteg);
        requestMsg.Headers.Add("Accept", "application/json, application/problem+json");
        Console.WriteLine($"[POST] {basePath}/registri");
        var response = await client.SendAsync(requestMsg);
        var responseString = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"[ANAGRAFICHE] {(int)response.StatusCode}");
        if (!string.IsNullOrWhiteSpace(responseString)) Console.WriteLine($"[BODY] {responseString}");
        return Results.Ok(new { success = response.IsSuccessStatusCode, status = (int)response.StatusCode, data = responseString });
    } catch (Exception ex) { Console.WriteLine($"[ERROR] {ex}"); return Results.Problem(ex.Message); }
});
app.MapPost("/list-registrazioni", async ([FromBody] RentriRegistrazioniRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");
        string issuer = req.issuer;
        if (string.IsNullOrWhiteSpace(issuer) && GET_ISSUERS.TryGetValue(fname, out var known)) issuer = known;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = GET_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        var now = DateTime.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var aud = AUDIENCE;
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };
        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", jti } },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenAuth = tokenHandler.CreateToken(idDesc);
        var digestHeader = "SHA-256=47DEQpj8HBSa+/TImW+JCeuQeRkm5NMpJWZG3hSuFU=";
        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", jti },
                { "signed_headers", new object[] { new Dictionary<string, string> { { "digest", digestHeader } } } }
            },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenInteg = tokenHandler.CreateToken(intDesc);
        var handler = new HttpClientHandler();
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        handler.ClientCertificates.Add(cert);
        using var client = new HttpClient(handler);
        var limit = req.limit > 0 ? req.limit : 1;
        var order = string.IsNullOrWhiteSpace(req.order) ? "desc" : req.order;
        var qs = new List<string> { $"limit={limit}", $"order={order}" };
        if (!string.IsNullOrWhiteSpace(req.from)) qs.Add($"from={req.from}");
        if (!string.IsNullOrWhiteSpace(req.to)) qs.Add($"to={req.to}");
        var url = $"https://api.rentri.gov.it/dati-registri/v1.0/operatore/{req.registryId}/registrazioni?{string.Join("&", qs)}";
        var msg = new HttpRequestMessage(HttpMethod.Get, url);
        msg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
        msg.Headers.Add("Digest", digestHeader);
        msg.Headers.Add("Agid-JWT-Signature", tokenInteg);
        msg.Headers.Add("Accept", "application/json");
        var resp = await client.SendAsync(msg);
        var body = await resp.Content.ReadAsStringAsync();
        LogLine("list.movimenti", $"url={url} status={(int)resp.StatusCode} body={Trunc(body)}");
        try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "GET", url, filename = fname, issuer, status = (int)resp.StatusCode, data = body }); } catch {}
        return Results.Ok(new { success = resp.IsSuccessStatusCode, status = (int)resp.StatusCode, data = body });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.MapPost("/list-movimenti", async ([FromBody] RentriRegistrazioniRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");
        string issuer = req.issuer;
        if (string.IsNullOrWhiteSpace(issuer) && GET_ISSUERS.TryGetValue(fname, out var known)) issuer = known;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = GET_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        var now = DateTime.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var aud = AUDIENCE;
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };
        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", jti } },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            SigningCredentials = creds
        };
        var tokenAuth = tokenHandler.CreateToken(idDesc);
        var digestHeader = "SHA-256=47DEQpj8HBSa+/TImW+JCeuQeRkm5NMpJWZG3hSuFU=";
        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", jti },
                { "signed_headers", new object[] { new Dictionary<string, string> { { "digest", digestHeader } } } }
            },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenInteg = tokenHandler.CreateToken(intDesc);

        var handler = new HttpClientHandler();
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        handler.ClientCertificates.Add(cert);
        using var client = new HttpClient(handler);
        var limit = req.limit > 0 ? req.limit : 1;
        var order = string.IsNullOrWhiteSpace(req.order) ? "desc" : req.order;
        var qs = new List<string> { $"limit={limit}", $"order={order}" };
        if (!string.IsNullOrWhiteSpace(req.from)) qs.Add($"from={req.from}");
        if (!string.IsNullOrWhiteSpace(req.to)) qs.Add($"to={req.to}");
        var url = $"https://api.rentri.gov.it/dati-registri/v1.0/operatore/{req.registryId}/movimenti?{string.Join("&", qs)}";
        var msg = new HttpRequestMessage(HttpMethod.Get, url);
        msg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
        msg.Headers.Add("Digest", digestHeader);
        msg.Headers.Add("Agid-JWT-Signature", tokenInteg);
        msg.Headers.Add("Accept", "application/json");
        var resp = await client.SendAsync(msg);
        var body = await resp.Content.ReadAsStringAsync();
        try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "GET", url, filename = fname, issuer, status = (int)resp.StatusCode, data = body }); } catch {}
        return Results.Ok(new { success = resp.IsSuccessStatusCode, status = (int)resp.StatusCode, data = body });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.MapPost("/export-list", async ([FromBody] ExportListRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");
        string issuer = req.issuer;
        if (string.IsNullOrWhiteSpace(issuer) && GET_ISSUERS.TryGetValue(fname, out var known)) issuer = known;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = GET_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        var now = DateTime.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var aud = AUDIENCE;
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };
        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", jti } },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenAuth = tokenHandler.CreateToken(idDesc);
        var digestHeader = "SHA-256=47DEQpj8HBSa+/TImW+JCeuQeRkm5NMpJWZG3hSuFU=";
        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", jti },
                { "signed_headers", new object[] { new Dictionary<string, string> { { "digest", digestHeader } } } }
            },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenInteg = tokenHandler.CreateToken(intDesc);
        var handler = new HttpClientHandler();
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        handler.ClientCertificates.Add(cert);
        using var client = new HttpClient(handler);
        var limit = req.limit > 0 ? req.limit : 50;
        var order = string.IsNullOrWhiteSpace(req.order) ? "desc" : req.order!;
        var kind = string.IsNullOrWhiteSpace(req.type) ? "movimenti" : req.type!;
        var url = $"https://api.rentri.gov.it/dati-registri/v1.0/operatore/{req.registryId}/{kind}?limit={limit}&order={order}";
        var msg = new HttpRequestMessage(HttpMethod.Get, url);
        msg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
        msg.Headers.Add("Digest", digestHeader);
        msg.Headers.Add("Agid-JWT-Signature", tokenInteg);
        msg.Headers.Add("Accept", "application/json");
        var resp = await client.SendAsync(msg);
        var body = await resp.Content.ReadAsStringAsync();
        var nameJson = $"list_{req.registryId}_{kind}_{DateTime.UtcNow:yyyyMMddHHmmss}.json";
        var pathJson = Path.Combine(AppContext.BaseDirectory, "exports", nameJson);
        Directory.CreateDirectory(Path.GetDirectoryName(pathJson)!);
        File.WriteAllText(pathJson, body ?? "");
        try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "GET", url, filename = fname, issuer, status = (int)resp.StatusCode, data = body }); } catch {}
        return Results.Ok(new { success = resp.IsSuccessStatusCode, status = (int)resp.StatusCode, path = pathJson, count_hint = (body ?? "[]").Length });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});
app.MapPost("/check-transazione", async ([FromBody] CheckTransazioneRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");
        string issuer = req.issuer;
        if (string.IsNullOrWhiteSpace(issuer) && GET_ISSUERS.TryGetValue(fname, out var known)) issuer = known;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = GET_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        var now = DateTime.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var aud = AUDIENCE;
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };
        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", jti } },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            SigningCredentials = creds
        };
        var digestHeader = "SHA-256=47DEQpj8HBSa+/TImW+JCeuQeRkm5NMpJWZG3hSuFU=";
        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", jti },
                { "signed_headers", new[] {
                    new Dictionary<string, string> { { "digest", digestHeader } }
                }}
            },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            IssuedAt = now,
            SigningCredentials = creds
        };
        var tokenInteg = tokenHandler.CreateToken(intDesc);

        var handler = new HttpClientHandler();
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        handler.ClientCertificates.Add(cert);
        using var client = new HttpClient(handler);
        var basePath = "https://api.rentri.gov.it/dati-registri/v1.0";
        var statusUrl = $"{basePath}/{req.transazioneId}/status";
        var tokenAuth = tokenHandler.CreateToken(new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", Guid.NewGuid().ToString() } },
            Expires = DateTime.UtcNow.AddMinutes(5),
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            SigningCredentials = creds
        });
        var msg = new HttpRequestMessage(HttpMethod.Get, statusUrl);
        msg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
        msg.Headers.Add("Digest", digestHeader);
        msg.Headers.Add("Agid-JWT-Signature", tokenInteg);
        msg.Headers.Add("Accept", "application/json");
        var resp = await client.SendAsync(msg);
        if ((int)resp.StatusCode == 303) {
            var loc = resp.Headers.Location?.ToString() ?? string.Empty;
            var tokenAuth2 = tokenHandler.CreateToken(new SecurityTokenDescriptor {
                AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
                Audience = aud,
                Issuer = issuer,
                Claims = new Dictionary<string, object> { { "jti", Guid.NewGuid().ToString() } },
                Expires = DateTime.UtcNow.AddMinutes(5),
                NotBefore = DateTime.UtcNow.AddMinutes(-1),
                SigningCredentials = creds
            });
            var tokenInteg2 = tokenHandler.CreateToken(new SecurityTokenDescriptor {
                AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
                Audience = aud,
                Issuer = issuer,
                Claims = new Dictionary<string, object> {
                    { "jti", Guid.NewGuid().ToString() },
                    { "signed_headers", new object[] { new Dictionary<string, string> { { "digest", digestHeader } } } }
                },
                Expires = DateTime.UtcNow.AddMinutes(5),
                NotBefore = DateTime.UtcNow.AddMinutes(-1),
                IssuedAt = DateTime.UtcNow,
                SigningCredentials = creds
            });
            var msg2 = new HttpRequestMessage(HttpMethod.Get, string.IsNullOrWhiteSpace(loc) ? $"{basePath}/{req.transazioneId}/result" : loc);
            msg2.Headers.Add("Authorization", $"Bearer {tokenAuth2}");
            msg2.Headers.Add("Digest", digestHeader);
            msg2.Headers.Add("Agid-JWT-Signature", tokenInteg2);
            msg2.Headers.Add("Accept", "application/json");
            var resp2 = await client.SendAsync(msg2);
            var body2 = await resp2.Content.ReadAsStringAsync();
            try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "GET", url = msg2.RequestUri!.ToString(), filename = fname, issuer, status = (int)resp2.StatusCode, data = body2 }); } catch {}
            return Results.Ok(new { success = resp2.IsSuccessStatusCode, status = (int)resp2.StatusCode, url = msg2.RequestUri!.ToString(), data = body2 });
        } else {
            var body = await resp.Content.ReadAsStringAsync();
            try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "GET", url = statusUrl, filename = fname, issuer, status = (int)resp.StatusCode, data = body }); } catch {}
            return Results.Ok(new { success = resp.IsSuccessStatusCode, status = (int)resp.StatusCode, url = statusUrl, data = body });
        }
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.MapPost("/status-poller", async ([FromBody] StatusPollRequest req) => {
    try {
        var results = new List<object>();
        foreach (var item in req.items ?? new List<StatusPollItem>()) {
            string fname = string.IsNullOrEmpty(item.filename) ? "certificato.p12" : item.filename;
            var cert = LoadCert(fname);
            if (cert == null) {
                results.Add(new { transazioneId = item.transazioneId, ok = false, error = $"Certificato {fname} non trovato." });
                continue;
            }
            string issuer = item.issuer;
            if (string.IsNullOrWhiteSpace(issuer) && GET_ISSUERS.TryGetValue(fname, out var known)) issuer = known;
            if (string.IsNullOrWhiteSpace(issuer)) issuer = GET_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
            var aud = AUDIENCE;
            var ecdsaKey = cert.GetECDsaPrivateKey();
            var rsaKey = cert.GetRSAPrivateKey();
            SecurityKey securityKey;
            string algorithm;
            if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
            else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
            else {
                results.Add(new { transazioneId = item.transazioneId, ok = false, error = "Chiave privata non trovata nel certificato." });
                continue;
            }
            var creds = new SigningCredentials(securityKey, algorithm);
            var tokenHandler = new JsonWebTokenHandler();
            var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };
            using var sha256 = SHA256.Create();
            var digestHeader = $"SHA-256={Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(string.Empty)))}";
            var handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(cert);
            using var client = new HttpClient(handler);
            var urls = new List<string>();
            urls.Add($"https://api.rentri.gov.it/dati-registri/v1.0/transazioni/{item.transazioneId}");
            if (!string.IsNullOrWhiteSpace(item.registryId)) {
                urls.Add($"https://api.rentri.gov.it/dati-registri/v1.0/operatore/{item.registryId}/transazioni/{item.transazioneId}");
                urls.Add($"https://api.rentri.gov.it/dati-registri/v1.0/operatore/{item.registryId}/movimenti/transazioni/{item.transazioneId}");
            }
            if (!string.IsNullOrWhiteSpace(item.operatorId)) {
                urls.Add($"https://api.rentri.gov.it/dati-registri/v1.0/operatore/{item.operatorId}/transazioni/{item.transazioneId}");
            }
            int attempts = req.attempts > 0 ? req.attempts : 6;
            int delay = req.delayMs > 0 ? req.delayMs : 3000;
            bool ok = false;
            int lastStatus = 0;
            string lastUrl = "";
            string lastBody = "";
            for (int a = 0; a < attempts && !ok; a++) {
                foreach (var u in urls) {
                    var tokenAuth = tokenHandler.CreateToken(new SecurityTokenDescriptor {
                        AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
                        Audience = aud,
                        Issuer = issuer,
                        Claims = new Dictionary<string, object> { { "jti", Guid.NewGuid().ToString() } },
                        Expires = DateTime.UtcNow.AddMinutes(5),
                        NotBefore = DateTime.UtcNow.AddMinutes(-1),
                        IssuedAt = DateTime.UtcNow,
                        SigningCredentials = creds
                    });
                    var intDesc = new SecurityTokenDescriptor {
                        AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
                        Audience = aud,
                        Issuer = issuer,
                        Claims = new Dictionary<string, object> {
                            { "jti", Guid.NewGuid().ToString() },
                            { "signed_headers", new object[] { new Dictionary<string, string> { { "digest", digestHeader } } } }
                        },
                        Expires = DateTime.UtcNow.AddMinutes(5),
                        NotBefore = DateTime.UtcNow.AddMinutes(-1),
                        IssuedAt = DateTime.UtcNow,
                        SigningCredentials = creds
                    };
                    var tokenInteg = tokenHandler.CreateToken(intDesc);
                    var msg = new HttpRequestMessage(HttpMethod.Get, u);
                    msg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
                    msg.Headers.Add("Digest", digestHeader);
                    msg.Headers.Add("Agid-JWT-Signature", tokenInteg);
                    msg.Headers.Add("Accept", "application/json");
                    var resp = await client.SendAsync(msg);
                    lastStatus = (int)resp.StatusCode;
                    lastUrl = u;
                    lastBody = await resp.Content.ReadAsStringAsync();
                    try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "GET", url = u, filename = fname, issuer, status = lastStatus, data = lastBody }); } catch {}
                    if (resp.IsSuccessStatusCode) { ok = true; break; }
                    if ((int)resp.StatusCode == 303) {
                        var loc = resp.Headers.Location?.ToString() ?? "";
                        if (!string.IsNullOrWhiteSpace(loc)) {
                            var msg2 = new HttpRequestMessage(HttpMethod.Get, loc);
                            var tokenAuth2 = tokenHandler.CreateToken(new SecurityTokenDescriptor {
                                AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
                                Audience = aud,
                                Issuer = issuer,
                                Claims = new Dictionary<string, object> { { "jti", Guid.NewGuid().ToString() } },
                                Expires = DateTime.UtcNow.AddMinutes(5),
                                NotBefore = DateTime.UtcNow.AddMinutes(-1),
                                IssuedAt = DateTime.UtcNow,
                                SigningCredentials = creds
                            });
                            var tokenInteg2 = tokenHandler.CreateToken(new SecurityTokenDescriptor {
                                AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
                                Audience = aud,
                                Issuer = issuer,
                                Claims = new Dictionary<string, object> {
                                    { "jti", Guid.NewGuid().ToString() },
                                    { "signed_headers", new object[] { new Dictionary<string, string> { { "digest", digestHeader } } } }
                                },
                                Expires = DateTime.UtcNow.AddMinutes(5),
                                NotBefore = DateTime.UtcNow.AddMinutes(-1),
                                IssuedAt = DateTime.UtcNow,
                                SigningCredentials = creds
                            });
                            msg2.Headers.Add("Authorization", $"Bearer {tokenAuth2}");
                            msg2.Headers.Add("Digest", digestHeader);
                            msg2.Headers.Add("Agid-JWT-Signature", tokenInteg2);
                            msg2.Headers.Add("Accept", "application/json");
                            var resp2 = await client.SendAsync(msg2);
                            lastStatus = (int)resp2.StatusCode;
                            lastUrl = loc;
                            lastBody = await resp2.Content.ReadAsStringAsync();
                            try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "GET", url = loc, filename = fname, issuer, status = lastStatus, data = lastBody }); } catch {}
                            if (resp2.IsSuccessStatusCode) { ok = true; break; }
                        }
                    }
                }
                if (!ok) await Task.Delay(delay);
            }
            results.Add(new { transazioneId = item.transazioneId, ok, status = lastStatus, url = lastUrl, data = lastBody });
        }
        return Results.Ok(new { items = results });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.MapPost("/check-status", async ([FromBody] CheckStatusRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");
        string issuer = req.issuer;
        if (string.IsNullOrWhiteSpace(issuer) && GET_ISSUERS.TryGetValue(fname, out var known)) issuer = known;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = GET_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        var aud = AUDIENCE;
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };

        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        handler.ClientCertificates.Add(cert);
        using var client = new HttpClient(handler);

        var basePath = $"https://api.rentri.gov.it/{req.api}/v1.0";
        var statusUrl = $"{basePath}/{req.transazioneId}/status";

        var useJti = string.IsNullOrWhiteSpace(req.jti) ? Guid.NewGuid().ToString() : req.jti!;
        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", useJti } },
            Expires = DateTime.UtcNow.AddMinutes(5),
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            IssuedAt = DateTime.UtcNow,
            SigningCredentials = creds
        };
        var tokenAuth = tokenHandler.CreateToken(idDesc);
        using var sha256 = SHA256.Create();
        var digestHeader = $"SHA-256={Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(string.Empty)))}";
        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", useJti },
                { "signed_headers", new[] {
                    new Dictionary<string, string> { { "digest", digestHeader } }
                }}
            },
            Expires = DateTime.UtcNow.AddMinutes(5),
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            IssuedAt = DateTime.UtcNow,
            SigningCredentials = creds
        };
        var tokenInteg = tokenHandler.CreateToken(intDesc);
        var msg = new HttpRequestMessage(HttpMethod.Get, statusUrl);
        msg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
        msg.Headers.Add("Digest", digestHeader);
        msg.Headers.Add("Agid-JWT-Signature", tokenInteg);
        msg.Headers.Add("Accept", "application/json");
        var resp = await client.SendAsync(msg);
        if ((int)resp.StatusCode == 303) {
            var loc = resp.Headers.Location?.ToString() ?? string.Empty;
            LogLine("check-status.redirect", $"status=303 location={loc}");
            var idDesc2 = new SecurityTokenDescriptor {
                AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
                Audience = aud,
                Issuer = issuer,
                Claims = new Dictionary<string, object> { { "jti", Guid.NewGuid().ToString() } },
                Expires = DateTime.UtcNow.AddMinutes(5),
                NotBefore = DateTime.UtcNow.AddMinutes(-1),
                IssuedAt = DateTime.UtcNow,
                SigningCredentials = creds
            };
            var tokenAuth2 = tokenHandler.CreateToken(idDesc2);
            var intDesc2 = new SecurityTokenDescriptor {
                AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
                Audience = aud,
                Issuer = issuer,
                Claims = new Dictionary<string, object> {
                    { "jti", Guid.NewGuid().ToString() },
                    { "signed_headers", new[] {
                        new Dictionary<string, string> { { "digest", digestHeader } }
                    }}
                },
                Expires = DateTime.UtcNow.AddMinutes(5),
                NotBefore = DateTime.UtcNow.AddMinutes(-1),
                IssuedAt = DateTime.UtcNow,
                SigningCredentials = creds
            };
            var tokenInteg2 = tokenHandler.CreateToken(intDesc2);
            var msg2 = new HttpRequestMessage(HttpMethod.Get, string.IsNullOrWhiteSpace(loc) ? $"{basePath}/{req.transazioneId}/result" : loc);
            msg2.Headers.Add("Authorization", $"Bearer {tokenAuth2}");
            msg2.Headers.Add("Digest", digestHeader);
            msg2.Headers.Add("Agid-JWT-Signature", tokenInteg2);
            msg2.Headers.Add("Accept", "application/json");
            var resp2 = await client.SendAsync(msg2);
            var body2 = await resp2.Content.ReadAsStringAsync();
            LogLine("check-status.result", $"url={msg2.RequestUri!.ToString()} status={(int)resp2.StatusCode} body={Trunc(body2)}");
            return Results.Ok(new { success = resp2.IsSuccessStatusCode, status = (int)resp2.StatusCode, url = msg2.RequestUri!.ToString(), data = body2 });
        } else {
            var body = await resp.Content.ReadAsStringAsync();
            LogLine("check-status.direct", $"url={statusUrl} status={(int)resp.StatusCode} body={Trunc(body)}");
            return Results.Ok(new { success = resp.IsSuccessStatusCode, status = (int)resp.StatusCode, url = statusUrl, data = body });
        }
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

string Base64UrlPad(string s) {
    s = s.Replace('-', '+').Replace('_', '/');
    switch (s.Length % 4) {
        case 2: s += "=="; break;
        case 3: s += "="; break;
    }
    return s;
}

app.MapPost("/debug-status-sign", ([FromBody] CheckStatusRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");
        string issuer = req.issuer;
        if (string.IsNullOrWhiteSpace(issuer) && GET_ISSUERS.TryGetValue(fname, out var known)) issuer = known;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = GET_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        var aud = AUDIENCE;
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else return Results.Problem("Chiave privata non trovata nel certificato.");
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };
        var useJti = string.IsNullOrWhiteSpace(req.jti) ? Guid.NewGuid().ToString() : req.jti!;
        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", useJti } },
            Expires = DateTime.UtcNow.AddMinutes(5),
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            IssuedAt = DateTime.UtcNow,
            SigningCredentials = creds
        };
        var tokenAuth = tokenHandler.CreateToken(idDesc);
        var digestHeader = "SHA-256=47DEQpj8HBSa+/TImW+JCeuQeRkm5NMpJWZG3hSuFU=";
        var intDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> {
                { "jti", useJti },
                { "signed_headers", new[] {
                    new Dictionary<string, string> { { "digest", digestHeader } }
                }}
            },
            Expires = DateTime.UtcNow.AddMinutes(5),
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            IssuedAt = DateTime.UtcNow,
            SigningCredentials = creds
        };
        var tokenInteg = tokenHandler.CreateToken(intDesc);
        object Decode(string jwt) {
            try {
                var parts = jwt.Split('.');
                var hdr = Encoding.UTF8.GetString(Convert.FromBase64String(Base64UrlPad(parts[0])));
                var pl = Encoding.UTF8.GetString(Convert.FromBase64String(Base64UrlPad(parts[1])));
                return new { header = System.Text.Json.JsonDocument.Parse(hdr).RootElement, payload = System.Text.Json.JsonDocument.Parse(pl).RootElement };
            } catch {
                return new { error = "decode_failed" };
            }
        }
        var da = Decode(tokenAuth);
        var di = Decode(tokenInteg);
        return Results.Ok(new {
            method = "GET",
            url = $"https://api.rentri.gov.it/{req.api}/v1.0/{req.transazioneId}/status",
            headers = new {
                Authorization = "Bearer <idAuth>",
                Digest = digestHeader,
                Agid_JWT_Signature = "<jwtIntegrity>",
                Accept = "application/json"
            },
            auth = da,
            integrity = di,
            jti = useJti,
            iss = issuer,
            aud = aud,
            x5c_present = true
        });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.MapPost("/rentri-callback", async (HttpRequest http) => {
    try {
        var correlation = http.Headers.ContainsKey("X-Correlation-ID") ? http.Headers["X-Correlation-ID"].ToString() : "";
        var digest = http.Headers.ContainsKey("Digest") ? http.Headers["Digest"].ToString() : "";
        var sig = http.Headers.ContainsKey("Agid-JWT-Signature") ? http.Headers["Agid-JWT-Signature"].ToString() : "";
        using var reader = new StreamReader(http.Body);
        var body = await reader.ReadToEndAsync();
        var dir = Path.Combine(AppContext.BaseDirectory, "callbacks");
        Directory.CreateDirectory(dir);
        var fname = string.IsNullOrWhiteSpace(correlation) ? ($"cb_{DateTime.UtcNow:yyyyMMdd_HHmmssfff}.json") : ($"cb_{correlation}.json");
        var path = Path.Combine(dir, fname);
        var payload = System.Text.Json.JsonSerializer.Serialize(new { correlation_id = correlation, digest, signature = sig, body }, new System.Text.Json.JsonSerializerOptions{ WriteIndented = true });
        await File.WriteAllTextAsync(path, payload);
        Console.WriteLine($"[CALLBACK] {correlation} saved to {path}");
        try { AppendAttempt(new { ts = DateTime.UtcNow.ToString("o"), kind = "CALLBACK", correlation_id = correlation, status = 200, data = body }); } catch {}
        return Results.Ok(new { saved = true, correlation_id = correlation });
    } catch (Exception ex) { Console.WriteLine($"[CALLBACK ERROR] {ex.Message}"); return Results.Problem(ex.Message); }
});

app.MapGet("/callbacks", () => {
    try {
        var dir = Path.Combine(AppContext.BaseDirectory, "callbacks");
        if (!Directory.Exists(dir)) return Results.Ok(new { files = Array.Empty<object>() });
        var files = Directory.GetFiles(dir, "cb_*.json").OrderByDescending(f => new FileInfo(f).LastWriteTimeUtc).Take(50).Select(f => {
            var name = Path.GetFileName(f);
            var text = File.ReadAllText(f);
            string correlation = "";
            try {
                var doc = System.Text.Json.JsonDocument.Parse(text);
                correlation = doc.RootElement.TryGetProperty("correlation_id", out var cid) ? cid.GetString() ?? "" : "";
            } catch { }
            return new { file = name, correlation_id = correlation, last_write_utc = File.GetLastWriteTimeUtc(f).ToString("o") };
        }).ToArray();
        return Results.Ok(new { files });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.MapGet("/callbacks/{file}", (string file) => {
    try {
        var dir = Path.Combine(AppContext.BaseDirectory, "callbacks");
        var path = Path.Combine(dir, file);
        if (!File.Exists(path)) return Results.NotFound(new { error = "Not found" });
        var text = File.ReadAllText(path);
        return Results.Content(text, "application/json");
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});
app.MapGet("/attempts", () => {
    try {
        var f = AttemptsFile();
        if (!File.Exists(f)) return Results.Ok(new { success = Array.Empty<object>(), errors = Array.Empty<object>() });
        var lines = File.ReadAllLines(f).Reverse().Take(200).ToArray();
        var success = new List<object>();
        var errors = new List<object>();
        foreach (var l in lines) {
            try {
                var doc = System.Text.Json.JsonDocument.Parse(l);
                var root = doc.RootElement;
                int status = root.TryGetProperty("status", out var st) && st.TryGetInt32(out var si) ? si : 0;
                var item = new {
                    ts = root.TryGetProperty("ts", out var ts) ? ts.GetString() : "",
                    kind = root.TryGetProperty("kind", out var kd) ? kd.GetString() : "",
                    url = root.TryGetProperty("url", out var ur) ? ur.GetString() : "",
                    issuer = root.TryGetProperty("issuer", out var iss) ? (iss.ValueKind == System.Text.Json.JsonValueKind.String ? iss.GetString() : null) : null,
                    filename = root.TryGetProperty("filename", out var fn) ? (fn.ValueKind == System.Text.Json.JsonValueKind.String ? fn.GetString() : null) : null,
                    data = root.TryGetProperty("data", out var dt) ? (dt.ValueKind == System.Text.Json.JsonValueKind.String ? dt.GetString() : null) : null,
                    status
                };
                if (status >= 200 && status < 300) success.Add(item); else errors.Add(item);
            } catch {}
        }
        return Results.Ok(new { success, errors });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});
app.MapGet("/monitor", () => {
    try {
        var f = AttemptsFile();
        var sb = new StringBuilder();
        sb.Append("<html><head><title>RENTRI Monitor</title><style>body{font-family:sans-serif} .ok{color:#0a0} .err{color:#c00} table{border-collapse:collapse} td,th{border:1px solid #ccc;padding:4px} .toolbar{margin-bottom:10px} button{padding:6px 10px;margin-right:8px}</style></head><body>");
        sb.Append("<h3>RENTRI Monitor</h3>");
        sb.Append("<div class='toolbar'><a href='/demo'><button>Apri Demo</button></a><a href='/attempts'><button>Vedi JSON</button></a><a href='/attempts/clear'><button>Pulisci Log</button></a></div>");
        if (!File.Exists(f)) { sb.Append("<p>Nessun dato</p>"); sb.Append("</body></html>"); return Results.Content(sb.ToString(), "text/html"); }
        var lines = File.ReadAllLines(f).Reverse().Take(100).ToArray();
        sb.Append("<table><tr><th>TS</th><th>Kind</th><th>Status</th><th>URL</th></tr>");
        foreach (var l in lines) {
            try {
                var doc = System.Text.Json.JsonDocument.Parse(l);
                var root = doc.RootElement;
                var ts = root.TryGetProperty("ts", out var tsn) ? tsn.GetString() : "";
                var kind = root.TryGetProperty("kind", out var kn) ? kn.GetString() : "";
                int status = root.TryGetProperty("status", out var st) && st.TryGetInt32(out var si) ? si : 0;
                var url = root.TryGetProperty("url", out var ur) ? ur.GetString() : "";
                var cls = (status >= 200 && status < 300) ? "ok" : "err";
                sb.Append("<tr><td>").Append(ts).Append("</td><td>").Append(kind).Append("</td><td class='").Append(cls).Append("'>").Append(status).Append("</td><td>").Append(System.Net.WebUtility.HtmlEncode(url ?? "")).Append("</td></tr>");
            } catch {}
        }
        sb.Append("</table></body></html>");
        return Results.Content(sb.ToString(), "text/html");
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});
app.MapGet("/attempts/clear", () => {
    try {
        var f = AttemptsFile();
        if (File.Exists(f)) File.Delete(f);
        return Results.Content("<html><body><p>Log pulito.</p><a href='/monitor'>Torna al Monitor</a></body></html>", "text/html");
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});
app.MapGet("/demo", () => {
    var html = @"<html><head><title>RENTRI Demo</title><style>body{font-family:sans-serif} input,button,select{padding:8px 12px;margin:6px}</style></head><body>
    <h3>Demo Invio</h3>
    <p>Usa questi pulsanti per generare invii di test e popolare il monitor. Puoi sovrascrivere issuer e registryId.</p>
    <div>
      <form method='post' action='/demo-send'>
        <input type='hidden' name='key' value='global' />
        <label>Issuer</label>
        <select name='iss'>
          <option value='auto' selected>Auto (dal certificato)</option>
          <option value='08934760961'>08934760961 (GLOBAL RECO)</option>
          <option value='12347770013'>12347770013 (MULTY PROGET)</option>
        </select>
        <label>Registry</label>
        <select name='reg'>
          <option value='auto' selected>Auto (predefinito)</option>
          <option value='R6QSWHZ6HJV'>R6QSWHZ6HJV (Global)</option>
          <option value='RQEL39R7NS0'>RQEL39R7NS0 (Multy)</option>
        </select>
        <label>Usa DEMO</label><input type='checkbox' name='demo' value='1' />
        <button>Invia Test Global</button>
      </form>
      <form method='post' action='/demo-send'>
        <input type='hidden' name='key' value='multy' />
        <label>Issuer</label>
        <select name='iss'>
          <option value='auto' selected>Auto (dal certificato)</option>
          <option value='12347770013'>12347770013 (MULTY PROGET)</option>
          <option value='08934760961'>08934760961 (GLOBAL RECO)</option>
        </select>
        <label>Registry</label>
        <select name='reg'>
          <option value='auto' selected>Auto (predefinito)</option>
          <option value='RQEL39R7NS0'>RQEL39R7NS0 (Multy)</option>
          <option value='R6QSWHZ6HJV'>R6QSWHZ6HJV (Global)</option>
        </select>
        <label>Usa DEMO</label><input type='checkbox' name='demo' value='1' />
        <button>Invia Test Multy</button>
      </form>
      <a href='/monitor'><button>Apri Monitor</button></a>
    </div>
    </body></html>";
    return Results.Content(html, "text/html");
});
app.MapPost("/demo-send", async (HttpRequest http) => {
    try {
        string key = http.Query.ContainsKey("key") ? http.Query["key"].ToString() : (http.Form.ContainsKey("key") ? http.Form["key"].ToString() : "global");
        string filename = key=="multy" ? "multyproget.p12" : "certificato.p12";
        string issuer = key=="multy" ? "OP2501XMQ021914" : "OP2501RMK022692";
        if (http.Query.ContainsKey("iss")) issuer = http.Query["iss"].ToString();
        else if (http.HasFormContentType && http.Form.ContainsKey("iss")) issuer = http.Form["iss"].ToString();
        if (string.Equals(issuer, "auto", StringComparison.OrdinalIgnoreCase)) issuer = ""; // lascia auto-mapping al bridge
        string registryId = key=="multy" ? "RQEL39R7NS0" : "R6QSWHZ6HJV";
        if (http.Query.ContainsKey("reg")) registryId = http.Query["reg"].ToString();
        else if (http.HasFormContentType && http.Form.ContainsKey("reg")) registryId = http.Form["reg"].ToString();
        if (string.Equals(registryId, "auto", StringComparison.OrdinalIgnoreCase)) registryId = key=="multy" ? "RQEL39R7NS0" : "R6QSWHZ6HJV";
        bool useDemo = false;
        if (http.Query.ContainsKey("demo")) useDemo = http.Query["demo"].ToString() == "1";
        else if (http.HasFormContentType && http.Form.ContainsKey("demo")) useDemo = http.Form["demo"].ToString() == "1";
        var payloadObj = new [] {
            new {
                riferimenti = new {
                    numero_registrazione = new { anno = DateTime.UtcNow.Year, progressivo = 1 },
                    data_ora_registrazione = DateTime.UtcNow.ToString("yyyy-MM-dd")+"T12:00:00Z",
                    causale_operazione = "RE"
                },
                rifiuto = new {
                    codice_eer = "170407",
                    stato_fisico = "S",
                    quantita = new { valore = 1, unita_misura = "kg" },
                    provenienza = "U"
                }
            }
        };
        var baseUrl = useDemo ? "https://demoapi.rentri.gov.it" : "https://api.rentri.gov.it";
        var url = $"{baseUrl}/dati-registri/v1.0/operatore/{registryId}/movimenti";
        var body = new {
            payload = System.Text.Json.JsonSerializer.Serialize(payloadObj),
            filename,
            url,
            issuer,
            replyTo = "http://localhost:8765/rentri-callback"
        };
        using var client = new HttpClient();
        var msg = new HttpRequestMessage(HttpMethod.Post, "http://localhost:8765/send-rentri"){
            Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
        var resp = await client.SendAsync(msg);
        var text = await resp.Content.ReadAsStringAsync();
        var html = $"<html><body><h3>Demo Send ({key})</h3><p>Ambiente: {(useDemo ? "DEMO" : "PROD")}</p><p>Status: {(int)resp.StatusCode}</p><p>Issuer usato: {System.Net.WebUtility.HtmlEncode(string.IsNullOrEmpty(issuer) ? "AUTO" : issuer)}</p><p>Registry: {System.Net.WebUtility.HtmlEncode(registryId)}</p><pre>{System.Net.WebUtility.HtmlEncode(text)}</pre><a href='/monitor'>Apri Monitor</a></body></html>";
        return Results.Content(html, "text/html");
    } catch (Exception ex) {
        var html = $"<html><body><h3>Demo Send Error</h3><pre>{System.Net.WebUtility.HtmlEncode(ex.ToString())}</pre><a href='/monitor'>Apri Monitor</a></body></html>";
        return Results.Content(html, "text/html");
    }
});

app.MapGet("/whoami", ([FromQuery] string? filename) => {
    try {
        string fname = string.IsNullOrWhiteSpace(filename) ? "certificato.p12" : filename!;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");
        string? dnQualifier = null;
        string? orgIdentifier = null;
        try {
            var subj = cert.Subject;
            var marker = "dnQualifier=";
            var idx = subj.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0) {
                var start = idx + marker.Length;
                var end = subj.IndexOf(',', start);
                dnQualifier = end >= 0 ? subj.Substring(start, end - start).Trim() : subj.Substring(start).Trim();
            }
            var marker97 = "OID.2.5.4.97=";
            var idx97 = subj.IndexOf(marker97, StringComparison.OrdinalIgnoreCase);
            if (idx97 >= 0) {
                var start97 = idx97 + marker97.Length;
                var end97 = subj.IndexOf(',', start97);
                orgIdentifier = end97 >= 0 ? subj.Substring(start97, end97 - start97).Trim() : subj.Substring(start97).Trim();
            }
        } catch { }
        var mapped = POST_ISSUERS.TryGetValue(fname, out var m) ? m : null;
        var audienceProd = AUDIENCE;
        var audienceDemo = "rentrigov.demo.api";
        return Results.Ok(new {
            filename = fname,
            subject = cert.Subject,
            thumbprint = cert.Thumbprint,
            dnQualifier,
            organizationIdentifier = orgIdentifier,
            mappedIssuer = mapped,
            audiences = new { prod = audienceProd, demo = audienceDemo }
        });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.MapPost("/suggest-next", async ([FromBody] RentriRegistrazioniRequest req) => {
    try {
        string fname = string.IsNullOrEmpty(req.filename) ? "certificato.p12" : req.filename;
        var cert = LoadCert(fname);
        if (cert == null) return Results.Problem($"Certificato {fname} non trovato.");
        string issuer = req.issuer;
        if (string.IsNullOrWhiteSpace(issuer) && GET_ISSUERS.TryGetValue(fname, out var known)) issuer = known;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = GET_ISSUERS.TryGetValue(fname, out var mi) ? mi : "";
        var now = DateTime.UtcNow;
        var jti = Guid.NewGuid().ToString();
        var aud = AUDIENCE;
        var ecdsaKey = cert.GetECDsaPrivateKey();
        var rsaKey = cert.GetRSAPrivateKey();
        SecurityKey securityKey;
        string algorithm;
        if (ecdsaKey != null) { securityKey = new ECDsaSecurityKey(ecdsaKey); algorithm = SecurityAlgorithms.EcdsaSha256; }
        else if (rsaKey != null) { securityKey = new RsaSecurityKey(rsaKey); algorithm = SecurityAlgorithms.RsaSha256; }
        else { return Results.Problem("Chiave privata non trovata nel certificato."); }
        var creds = new SigningCredentials(securityKey, algorithm);
        var tokenHandler = new JsonWebTokenHandler();
        var x5cLeaf = new[] { Convert.ToBase64String(cert.Export(X509ContentType.Cert)) };
        var idDesc = new SecurityTokenDescriptor {
            AdditionalHeaderClaims = new Dictionary<string, object> { { "x5c", x5cLeaf } },
            Audience = aud,
            Issuer = issuer,
            Claims = new Dictionary<string, object> { { "jti", jti } },
            Expires = now.AddMinutes(5),
            NotBefore = now.AddMinutes(-1),
            SigningCredentials = creds
        };
        var tokenAuth = tokenHandler.CreateToken(idDesc);
        var handler = new HttpClientHandler();
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        handler.ClientCertificates.Add(cert);
        using var client = new HttpClient(handler);
        var url = $"https://api.rentri.gov.it/dati-registri/v1.0/operatore/{req.registryId}/registrazioni?limit=50&order=desc";
        var msg = new HttpRequestMessage(HttpMethod.Get, url);
        msg.Headers.Add("Authorization", $"Bearer {tokenAuth}");
        msg.Headers.Add("Accept", "application/json");
        var resp = await client.SendAsync(msg);
        var body = await resp.Content.ReadAsStringAsync();
        try {
            var doc = System.Text.Json.JsonDocument.Parse(body);
            var root = doc.RootElement;
            string? lastDate = null; string? lastProg = null; int? lastAnno = null;
            int maxProg = 0; int maxAnno = DateTime.UtcNow.Year;
            if (root.ValueKind == System.Text.Json.JsonValueKind.Array && root.GetArrayLength() > 0) {
                for (int i = 0; i < root.GetArrayLength(); i++) {
                    var el = root[i];
                    if (i == 0 && el.TryGetProperty("data_registrazione", out var dr)) lastDate = dr.GetString();
                    if (el.TryGetProperty("numero_registrazione", out var nr)) {
                        if (nr.TryGetProperty("progressivo", out var pr)) {
                            if (pr.ValueKind == System.Text.Json.JsonValueKind.String) {
                                var s = pr.GetString() ?? ""; var d = new string(s.Where(char.IsDigit).ToArray()); if (int.TryParse(d, out var pv)) maxProg = Math.Max(maxProg, pv);
                                lastProg = s;
                            } else if (pr.TryGetInt32(out var pi)) { maxProg = Math.Max(maxProg, pi); lastProg = pi.ToString(); }
                        }
                        if (nr.TryGetProperty("anno", out var an)) { if (an.TryGetInt32(out var ai)) { maxAnno = Math.Max(maxAnno, ai); if (lastAnno == null) lastAnno = ai; } }
                    } else if (el.TryGetProperty("riferimenti", out var rif) && rif.TryGetProperty("numero_registrazione", out var nrR)) {
                        if (nrR.TryGetProperty("progressivo", out var prR)) {
                            if (prR.ValueKind == System.Text.Json.JsonValueKind.String) {
                                var s = prR.GetString() ?? ""; var d = new string(s.Where(char.IsDigit).ToArray()); if (int.TryParse(d, out var pv)) maxProg = Math.Max(maxProg, pv);
                                lastProg = s;
                            } else if (prR.TryGetInt32(out var piR)) { maxProg = Math.Max(maxProg, piR); lastProg = piR.ToString(); }
                        }
                        if (nrR.TryGetProperty("anno", out var anR)) { if (anR.TryGetInt32(out var aiR)) { maxAnno = Math.Max(maxAnno, aiR); if (lastAnno == null) lastAnno = aiR; } }
                    }
                }
            }
            if (string.IsNullOrEmpty(lastProg)) {
                var url2 = $"https://api.rentri.gov.it/dati-registri/v1.0/operatore/{req.registryId}/movimenti?limit=50&order=desc";
                var msg2 = new HttpRequestMessage(HttpMethod.Get, url2);
                msg2.Headers.Add("Authorization", $"Bearer {tokenAuth}");
                msg2.Headers.Add("Accept", "application/json");
                var resp2 = await client.SendAsync(msg2);
                var body2 = await resp2.Content.ReadAsStringAsync();
                try {
                    var doc2 = System.Text.Json.JsonDocument.Parse(body2);
                    var r2 = doc2.RootElement;
                    if (r2.ValueKind == System.Text.Json.JsonValueKind.Array && r2.GetArrayLength() > 0) {
                        for (int i = 0; i < r2.GetArrayLength(); i++) {
                            var el2 = r2[i];
                            if (i == 0 && el2.TryGetProperty("data_registrazione", out var dr2)) lastDate = dr2.GetString();
                            if (el2.TryGetProperty("numero_registrazione", out var nr2)) {
                                if (nr2.TryGetProperty("progressivo", out var pr2)) {
                                    if (pr2.ValueKind == System.Text.Json.JsonValueKind.String) {
                                        var s = pr2.GetString() ?? ""; var d = new string(s.Where(char.IsDigit).ToArray()); if (int.TryParse(d, out var pv2)) maxProg = Math.Max(maxProg, pv2);
                                        lastProg = s;
                                    } else if (pr2.TryGetInt32(out var pi2)) { maxProg = Math.Max(maxProg, pi2); lastProg = pi2.ToString(); }
                                }
                                if (nr2.TryGetProperty("anno", out var an2)) { if (an2.TryGetInt32(out var ai2)) { maxAnno = Math.Max(maxAnno, ai2); if (lastAnno == null) lastAnno = ai2; } }
                            } else if (el2.TryGetProperty("riferimenti", out var rif2) && rif2.TryGetProperty("numero_registrazione", out var nr2b)) {
                                if (nr2b.TryGetProperty("progressivo", out var pr2b)) {
                                    if (pr2b.ValueKind == System.Text.Json.JsonValueKind.String) {
                                        var s = pr2b.GetString() ?? ""; var d = new string(s.Where(char.IsDigit).ToArray()); if (int.TryParse(d, out var pv2b)) maxProg = Math.Max(maxProg, pv2b);
                                        lastProg = s;
                                    } else if (pr2b.TryGetInt32(out var pi2b)) { maxProg = Math.Max(maxProg, pi2b); lastProg = pi2b.ToString(); }
                                }
                                if (nr2b.TryGetProperty("anno", out var an2b)) { if (an2b.TryGetInt32(out var ai2b)) { maxAnno = Math.Max(maxAnno, ai2b); if (lastAnno == null) lastAnno = ai2b; } }
                            }
                        }
                    }
                } catch { }
            }
            string suggestDate = lastDate != null && lastDate.Length>=10 ? lastDate.Substring(0,10) : DateTime.UtcNow.ToString("yyyy-MM-dd");
            int pad = (lastProg ?? "0000001").Where(char.IsDigit).Count(); pad = pad == 0 ? 7 : pad;
            int next = (maxProg > 0 ? maxProg + 1 : 1);
            string suggestProg = next.ToString($"D{pad}");
            int suggestAnno = lastAnno ?? maxAnno;
            return Results.Ok(new { success = true, data = new { date = suggestDate, anno = suggestAnno, progressivo = suggestProg } });
        } catch {
            return Results.Ok(new { success = false, status = (int)resp.StatusCode, data = body });
        }
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

var BULK = new Dictionary<string, List<BulkItemState>>();
app.MapPost("/bulk-send", async ([FromBody] BulkSendRequest req) => {
    try {
        var jobId = Guid.NewGuid().ToString();
        var list = new List<BulkItemState>();
        foreach (var j in req.jobs ?? Array.Empty<BulkItem>()){
            var body = System.Text.Json.JsonSerializer.Serialize(new RentriRequest(j.payload, j.filename, j.url, j.issuer, j.replyTo));
            using var client = new HttpClient();
            var msg = new HttpRequestMessage(HttpMethod.Post, "http://localhost:8765/send-registrazioni");
            msg.Content = new StringContent(body, Encoding.UTF8, "application/json");
            var resp = await client.SendAsync(msg);
            var text = await resp.Content.ReadAsStringAsync();
            string transId = ""; int status = (int)resp.StatusCode; int accepted = 0; int duplicates = 0;
            try {
                var doc = System.Text.Json.JsonDocument.Parse(text);
                if (doc.RootElement.TryGetProperty("data", out var d)){
                    try { var model = System.Text.Json.JsonDocument.Parse(d.GetString() ?? "{}"); if (model.RootElement.TryGetProperty("transazione_id", out var tid)) transId = tid.GetString() ?? ""; } catch {}
                }
            } catch {}
            list.Add(new BulkItemState{ registryId = j.registryId, filename = j.filename, issuer = j.issuer, transazioneId = transId, status = status, accepted = accepted, duplicates = duplicates });
        }
        BULK[jobId] = list;
        return Results.Ok(new { jobId, items = list.Select(x=> new { x.registryId, x.transazioneId, x.status }) });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});
app.MapGet("/bulk-status/{jobId}", async (string jobId) => {
    try {
        if (!BULK.ContainsKey(jobId)) return Results.NotFound(new { error = "job not found" });
        var items = BULK[jobId];
        for (int i=0;i<items.Count;i++){
            var it = items[i];
            if (!string.IsNullOrWhiteSpace(it.transazioneId)){
                var body = System.Text.Json.JsonSerializer.Serialize(new CheckTransazioneRequest(it.registryId, it.transazioneId, it.filename, it.issuer));
                using var client = new HttpClient();
                var msg = new HttpRequestMessage(HttpMethod.Post, "http://localhost:8765/check-transazione");
                msg.Content = new StringContent(body, Encoding.UTF8, "application/json");
                var resp = await client.SendAsync(msg);
                var text = await resp.Content.ReadAsStringAsync();
                try {
                    var doc = System.Text.Json.JsonDocument.Parse(text);
                    if (doc.RootElement.TryGetProperty("data", out var d)){
                        var payload = d.GetString() ?? "";
                        try {
                            var model = System.Text.Json.JsonDocument.Parse(payload);
                            var esito = model.RootElement.TryGetProperty("esito", out var es) ? es : default;
                            int acc = 0; int dup = 0;
                            if (esito.ValueKind != System.Text.Json.JsonValueKind.Undefined){
                                if (esito.TryGetProperty("numero_registrazioni", out var nrl) && nrl.ValueKind==System.Text.Json.JsonValueKind.Array) acc = nrl.GetArrayLength();
                            }
                            var valid = model.RootElement.TryGetProperty("validazione", out var val) ? val : default;
                            if (valid.ValueKind==System.Text.Json.JsonValueKind.Array){
                                for (int k=0;k<valid.GetArrayLength();k++){
                                    var el = valid[k];
                                    string code = el.TryGetProperty("codice_messaggio", out var cm) ? (cm.GetString() ?? "") : "";
                                    if (code.Contains("movimentoDuplicatoDatabase")) dup++;
                                }
                            }
                            it.accepted = acc; it.duplicates = dup;
                        } catch {}
                    }
                } catch {}
            }
        }
        var totalAccepted = items.Sum(x=>x.accepted);
        var totalDuplicates = items.Sum(x=>x.duplicates);
        return Results.Ok(new { jobId, items = items.Select(x=> new { x.registryId, x.transazioneId, x.accepted, x.duplicates }), totals = new { accepted = totalAccepted, duplicates = totalDuplicates } });
    } catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.Run();
public record RentriRequest(string payload, string filename, string url, string? issuer, string? replyTo);
public record RentriListRequest(string url, string filename, string? issuer);
public record RentriRegistrazioniRequest(string registryId, string filename, string? issuer, int limit, string? order, string? from, string? to);
public record CreateRegistroRequest(string? basePath, string numIscrSito, string[]? attivita, string[]? attivitaRecSmalt, string? descrizione, string filename, string? issuer);
public record CheckTransazioneRequest(string registryId, string transazioneId, string filename, string? issuer);
public record StatusPollItem(string transazioneId, string filename, string issuer, string? registryId, string? operatorId);
public record StatusPollRequest(List<StatusPollItem> items, int attempts, int delayMs);
public record ExportListRequest(string registryId, string filename, string issuer, int limit, string? order, string? type);
public record CheckStatusRequest(string api, string transazioneId, string filename, string? issuer, string? jti);
public record BulkSendRequest(BulkItem[] jobs);
public record BulkItem(string registryId, string filename, string url, string payload, string? issuer, string? replyTo);
public class BulkItemState { public string registryId {get;set;}=""; public string filename {get;set;}=""; public string? issuer {get;set;}=""; public string transazioneId {get;set;}=""; public int status {get;set;}=0; public int accepted {get;set;}=0; public int duplicates {get;set;}=0; }
