using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Linq;

public class UserRecord 
{
    public string username { get; set; } 
    public string salt { get; set; } 
    public string hash { get; set; } 
}

public class ObjectRecord
{
    public string id { get; set; }
    public string name { get; set; }
    public string owner { get; set; }
    public Dictionary<string, string> acl { get; set; } 
    public string contentFile { get; set; }
}

class ServerExtended
{
    const int PORT = 5000;
    const int Pbkdf2Iterations = 100_000;
    const int KeyBytes = 32;
    static string DbPath = @"C:\Lessons\Course4\Безпека програм та даних\Lab7ACL\users_db.json";
    static string ObjectsDbPath = @"C:\Lessons\Course4\Безпека програм та даних\Lab7ACL\objects_db.json";
    static string ObjectsFolder = @"C:\Lessons\Course4\Безпека програм та даних\Lab7ACL\objects";
    static string CertPath => Path.Combine(AppContext.BaseDirectory, "server.pfx");
    static string CertPassword = "changeit";

    static async Task Main()
    {
        Console.WriteLine("=== Auth + Access Control Server (TLS, DAC) ===");
        Directory.CreateDirectory(ObjectsFolder);
        EnsureCertificate();
        LoadOrCreateDb();
        LoadOrCreateObjectsDb();

        var listener = new TcpListener(IPAddress.Any, PORT);
        listener.Start();
        Console.WriteLine($"Listening on 0.0.0.0:{PORT} (TLS).");

        while (true)
        {
            var tcp = await listener.AcceptTcpClientAsync();
            _ = HandleClient(tcp);
        }
    }

    static void EnsureCertificate()
    {
        if (File.Exists(CertPath)) { Console.WriteLine($"Using certificate: {CertPath}"); return; }

        Console.WriteLine("Server certificate not found — creating self-signed certificate (server.pfx)...");
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=AuthServerLocal", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(5));
        var export = cert.Export(X509ContentType.Pfx, CertPassword);
        File.WriteAllBytes(CertPath, export);
        Console.WriteLine($"Self-signed certificate saved to {CertPath}");
    }

    static void LoadOrCreateDb()
    {
        if (!File.Exists(DbPath))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(DbPath) ?? ".");
            var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var hash = Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2("secret", Convert.FromBase64String(salt), Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyBytes));
            var rec = new UserRecord { username = "Galya", salt = salt, hash = hash };
            File.WriteAllText(DbPath, JsonSerializer.Serialize(new[] { rec }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine("Demo user 'Galya' created (password: secret).");
        }
        else Console.WriteLine("User DB found at: " + DbPath);
    }

    static void LoadOrCreateObjectsDb()
    {
        if (!File.Exists(ObjectsDbPath))
        {
            var list = new List<ObjectRecord>();
            File.WriteAllText(ObjectsDbPath, JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine("Created empty objects DB.");
        }
        else Console.WriteLine("Objects DB found at: " + ObjectsDbPath);
    }

    static async Task HandleClient(TcpClient tcp)
    {
        Console.WriteLine("Incoming connection...");
        using var network = tcp.GetStream();
        var cert = new X509Certificate2(CertPath, CertPassword, X509KeyStorageFlags.Exportable);
        using var ssl = new System.Net.Security.SslStream(network, leaveInnerStreamOpen: false);
        try
        {
            ssl.AuthenticateAsServer(cert, clientCertificateRequired: false, enabledSslProtocols: System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, checkCertificateRevocation: false);
        }
        catch (Exception ex)
        {
            Console.WriteLine("TLS auth failed: " + ex.Message);
            tcp.Close();
            return;
        }

        using var reader = new StreamReader(ssl, Encoding.UTF8);
        using var writer = new StreamWriter(ssl, Encoding.UTF8) { AutoFlush = true };

        var authLine = await reader.ReadLineAsync();
        if (string.IsNullOrWhiteSpace(authLine)) { tcp.Close(); return; }

        UserRecord incoming;
        try { incoming = JsonSerializer.Deserialize<UserRecord>(authLine); }
        catch { await writer.WriteLineAsync("ERROR: invalid auth format"); tcp.Close(); return; }

        if (!ValidateUser(incoming))
        {
            await writer.WriteLineAsync("FAIL: bad credentials or user not found");
            Console.WriteLine($"Authentication failed for {incoming?.username}");
            tcp.Close();
            return;
        }

        await writer.WriteLineAsync("OK_AUTH");
        Console.WriteLine($"User {incoming.username} authenticated. Entering command loop.");

        string username = incoming.username;
        while (true)
        {
            var cmd = await reader.ReadLineAsync();
            if (cmd == null) break;
            var resp = ProcessCommand(username, cmd.Trim());
            await writer.WriteLineAsync(resp);
            await writer.FlushAsync();
            if (resp == "GOODBYE") break;
        }

        tcp.Close();
    }

    static bool ValidateUser(UserRecord u)
    {
        if (u == null || string.IsNullOrEmpty(u.username) || string.IsNullOrEmpty(u.hash)) return false;
        if (!File.Exists(DbPath)) return false;
        var users = JsonSerializer.Deserialize<UserRecord[]>(File.ReadAllText(DbPath));
        var found = Array.Find(users, x => x.username == u.username);
        if (found == null) return false;
        return found.hash == u.hash; 
    }

    // Command processing
    // Commands:
    // LIST
    // WHOAMI
    // CREATE <name> <content>
    // READ <id>
    // WRITE <id> <content>
    // DELETE <id>
    // SETACL <id> <username> <rights>
    // LOGOUT
    static string ProcessCommand(string username, string cmdLine)
    {
        if (string.IsNullOrWhiteSpace(cmdLine)) return "ERR: empty command";
        var parts = SplitCommand(cmdLine);
        var cmd = parts[0].ToUpperInvariant();

        try
        {
            switch (cmd)
            {
                case "WHOAMI":
                    return $"USER: {username}";
                case "LIST":
                    return CmdList(username);
                case "CREATE":
                    if (parts.Length < 3) return "ERR: CREATE usage: CREATE <name> <content>";
                    return CmdCreate(username, parts[1], parts[2]);
                case "READ":
                    if (parts.Length < 2) return "ERR: READ usage: READ <id>";
                    return CmdRead(username, parts[1]);
                case "WRITE":
                    if (parts.Length < 3) return "ERR: WRITE usage: WRITE <id> <content>";
                    return CmdWrite(username, parts[1], parts[2]);
                case "DELETE":
                    if (parts.Length < 2) return "ERR: DELETE usage: DELETE <id>";
                    return CmdDelete(username, parts[1]);
                case "SETACL":
                    if (parts.Length < 4) return "ERR: SETACL usage: SETACL <id> <username> <rights>";
                    return CmdSetAcl(username, parts[1], parts[2], parts[3]);
                case "LOGOUT":
                case "EXIT":
                    return "GOODBYE";
                default:
                    return "ERR: unknown command";
            }
        }
        catch (Exception ex)
        {
            return "ERR: " + ex.Message;
        }
    }

    static string[] SplitCommand(string line)
    {
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 3 && parts[0].ToUpper() != "SETACL")
        {
            // для команд CREATE, WRITE — об’єднуємо все після другого аргументу як контент
            var merged = parts.Take(2).ToList();
            merged.Add(string.Join(' ', parts.Skip(2)));
            return merged.ToArray();
        }
        return parts;
    }


    static List<ObjectRecord> LoadObjects()
    {
        var json = File.ReadAllText(ObjectsDbPath);
        return JsonSerializer.Deserialize<List<ObjectRecord>>(json) ?? new List<ObjectRecord>();
    }

    static void SaveObjects(List<ObjectRecord> objs)
    {
        File.WriteAllText(ObjectsDbPath, JsonSerializer.Serialize(objs, new JsonSerializerOptions { WriteIndented = true }));
    }

    static string CmdList(string username)
    {
        var objs = LoadObjects();
        if (objs.Count == 0) return "NO_OBJECTS";
        var list = objs.Select(o =>
            $"ID:{o.id} NAME:{o.name} OWNER:{o.owner} RIGHTS:{(o.acl != null && o.acl.ContainsKey(username) ? o.acl[username] : (o.owner == username ? "o" : ""))}"
        );
        return string.Join(" | ", list);
    }

    static string CmdCreate(string username, string name, string content)
    {
        var objs = LoadObjects();
        var id = Guid.NewGuid().ToString("N").Substring(0, 8);
        var fname = Path.Combine(ObjectsFolder, id + ".txt");
        File.WriteAllText(fname, content);
        var o = new ObjectRecord
        {
            id = id,
            name = name,
            owner = username,
            contentFile = fname,
            acl = new Dictionary<string, string> { { username, "owrd" } } 
        };
        objs.Add(o);
        SaveObjects(objs);
        return $"CREATED {id}";
    }

    static string CmdRead(string username, string id)
    {
        var objs = LoadObjects();
        var o = objs.FirstOrDefault(x => x.id == id);
        if (o == null) return "ERR: object not found";
        if (!HasRight(o, username, 'r')) return "ERR: no read right";
        var content = File.Exists(o.contentFile) ? File.ReadAllText(o.contentFile) : "";
        content = content.Replace('\n', ' ').Replace('\r', ' ');
        return $"Answer: {content}";
    }

    static string CmdWrite(string username, string id, string content)
    {
        var objs = LoadObjects();
        var o = objs.FirstOrDefault(x => x.id == id);
        if (o == null) return "ERR: object not found";
        if (!HasRight(o, username, 'w')) return "ERR: no write right";
        File.WriteAllText(o.contentFile, content);
        return "OK: written";
    }

    static string CmdDelete(string username, string id)
    {
        var objs = LoadObjects();
        var o = objs.FirstOrDefault(x => x.id == id);
        if (o == null) return "ERR: object not found";
        if (!HasRight(o, username, 'd')) return "ERR: no delete right";
        if (File.Exists(o.contentFile)) File.Delete(o.contentFile);
        objs.RemoveAll(x => x.id == id);
        SaveObjects(objs);
        return "OK: deleted";
    }

    static string CmdSetAcl(string username, string id, string targetUser, string rights)
    {
        var objs = LoadObjects();
        var o = objs.FirstOrDefault(x => x.id == id);
        if (o == null) return "ERR: object not found";
        if (o.owner != username) return "ERR: only owner can set ACL";
        if (o.acl == null) o.acl = new Dictionary<string, string>();
        if (targetUser == o.owner)
        {
            o.acl[targetUser] = "owrd";
        }
        else
        {
            // рядок з правами очищення: дозволяю лише o, r, w, d (але 'o' лише коли target==власник)
            var allowed = new string(rights.Where(ch => ch == 'r' || ch == 'w' || ch == 'd').ToArray());
            o.acl[targetUser] = allowed;
        }
        SaveObjects(objs);
        return "OK: ACL updated";
    }

    static bool HasRight(ObjectRecord o, string username, char right)
    {
        if (o.owner == username) return true; // owner has all rights
        if (o.acl != null && o.acl.TryGetValue(username, out var s))
        {
            return s.IndexOf(right) >= 0;
        }
        return false;
    }
}
