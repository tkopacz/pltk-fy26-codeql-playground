using System.Data.SqlClient; // Demonstrates potential SQL injection usage
using System.Diagnostics; // Demonstrates command injection usage
using System.Runtime.Serialization.Formatters.Binary; // Insecure deserialization
using System.Text; // For unsafe string building
using System.Xml; // For XXE demo

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// BASIC REFLECTED XSS: echoes the 'q' parameter directly
app.MapGet("/xss", (HttpContext ctx) => {
    var q = ctx.Request.Query["q"].ToString();
    // Intentionally vulnerable: output not encoded
    return $"<html><body>Search: {q}</body></html>";
});

// SQL INJECTION: concatenates user input into query
app.MapGet("/sql", (HttpContext ctx) => {
    var user = ctx.Request.Query["user"].ToString();
    var connString = "Server=localhost;Database=demo;User Id=sa;Password=SuperSecret123!"; // Hardcoded secret
    using var conn = new SqlConnection(connString); // (May fail at runtime; demo only)
    var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM Users WHERE Name = '" + user + "'"; // Vulnerable concatenation
    return cmd.CommandText; // Show the constructed query
});

// PATH TRAVERSAL: reads arbitrary file from disk
app.MapGet("/file", (HttpContext ctx) => {
    var name = ctx.Request.Query["name"].ToString();
    // Vulnerable: no validation, allows ..\..
    try {
        var text = System.IO.File.ReadAllText(name);
        return text.Length > 200 ? text.Substring(0,200) : text;
    } catch (Exception ex) {
        return ex.Message;
    }
});

// COMMAND INJECTION: passes user input directly to shell
app.MapGet("/run", (HttpContext ctx) => {
    var cmd = ctx.Request.Query["cmd"].ToString();
    // Vulnerable: user-controlled command execution
    try {
        var p = Process.Start(new ProcessStartInfo {
            FileName = "cmd.exe",
            Arguments = "/c " + cmd,
            RedirectStandardOutput = true,
            UseShellExecute = false
        });
        return p?.StandardOutput.ReadToEnd();
    } catch (Exception ex) {
        return ex.ToString();
    }
});

// INSECURE DESERIALIZATION: BinaryFormatter on user input
app.MapPost("/deserialize", async (HttpContext ctx) => {
    using var ms = new MemoryStream();
    await ctx.Request.Body.CopyToAsync(ms);
#pragma warning disable SYSLIB0011 // BinaryFormatter obsolete
    var bf = new BinaryFormatter();
    ms.Position = 0;
    var obj = bf.Deserialize(ms); // Vulnerable
#pragma warning restore SYSLIB0011
    return obj?.ToString() ?? "null";
});

// XXE DEMO: parses user-supplied XML with DTD resolution enabled
app.MapPost("/xxe", async (HttpContext ctx) => {
    using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
    var xmlInput = await reader.ReadToEndAsync();
    var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() }; // Vulnerable: external entities allowed
    doc.LoadXml(xmlInput);
    return doc.OuterXml;
});

// DEFAULT
app.MapGet("/", () => "Insecure ASP.NET Demo Loaded");

app.Run();
