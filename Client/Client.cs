using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

public class EncryptedToken 
{
    public string kdfSalt { get; set; } 
    public string nonce { get; set; } 
    public string ciphertext { get; set; } 
    public string tag { get; set; } 
}

public class TokenFile 
{ 
    public string username { get; set; } 
    public string salt { get; set; } 
}

public class UserRecord 
{ 
    public string username { get; set; } 
    public string salt { get; set; } 
    public string hash { get; set; } 
}

class ClientExtended
{
    const int Pbkdf2Iterations = 100_000;
    const int KeyBytes = 32;
    const int PORT = 5000;

    static async Task Main()
    {
        Console.WriteLine("=== Auth Client (TLS + Encrypted token) ===");

        Console.Write("Path to encrypted token file (e.g. E:\\token.enc): ");
        var tokenPath = Console.ReadLine();
        if (!File.Exists(tokenPath)) { Console.WriteLine("Token file not found."); return; }

        Console.Write("Enter password (used to decrypt token and authenticate): ");
        var password = ReadPassword();

        EncryptedToken enc;
        try
        {
            var encJson = File.ReadAllText(tokenPath);
            enc = JsonSerializer.Deserialize<EncryptedToken>(encJson);
            if (enc == null) throw new Exception("Invalid token format");
        }
        catch (Exception ex) { Console.WriteLine("Cannot read token: " + ex.Message); return; }

        TokenFile token;
        try { token = DecryptToken(enc, password); }
        catch (Exception ex) { Console.WriteLine("Decrypt failed: " + ex.Message); return; }

        var saltBytes = Convert.FromBase64String(token.salt);
        var hashBytes = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyBytes);
        var hashB64 = Convert.ToBase64String(hashBytes);

        Console.Write("Enter server IP (default 127.0.0.1): ");
        var ip = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(ip)) ip = "127.0.0.1";

        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(ip, PORT);
            using var net = tcp.GetStream();
            using var ssl = new System.Net.Security.SslStream(net, leaveInnerStreamOpen: false, new System.Net.Security.RemoteCertificateValidationCallback((s, cert, chain, err) => true));
            try { await ssl.AuthenticateAsClientAsync("AuthServerLocal"); }
            catch (Exception ex) { Console.WriteLine("TLS handshake failed: " + ex.Message); return; }

            using var writer = new StreamWriter(ssl, Encoding.UTF8) { AutoFlush = true };
            using var reader = new StreamReader(ssl, Encoding.UTF8);

            var authJson = JsonSerializer.Serialize(new UserRecord { username = token.username, hash = hashB64 });
            await writer.WriteLineAsync(authJson);
            var authResp = await reader.ReadLineAsync();
            if (authResp != "OK_AUTH") { Console.WriteLine("Auth failed: " + authResp); return; }
            Console.WriteLine("Authenticated. Enter commands (LIST, WHOAMI, CREATE <name> <content>, READ <id>, WRITE <id> <content>, DELETE <id>, SETACL <id> <username> <rights>, LOGOUT)");

            while (true)
            {
                Console.Write("> ");
                var line = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(line)) continue;
                await writer.WriteLineAsync(line);
                var resp = await reader.ReadLineAsync();
                if (resp == null) break;
                if (resp == "GOODBYE") { Console.WriteLine("Logged out."); break; }
                if (resp.StartsWith("OK\n"))
                {
                    Console.WriteLine(resp.Substring(3));
                }
                else
                {
                    Console.WriteLine(resp);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Connection error: " + ex.Message);
        }
    }

    static TokenFile DecryptToken(EncryptedToken enc, string password)
    {
        var kdfSalt = Convert.FromBase64String(enc.kdfSalt);
        var nonce = Convert.FromBase64String(enc.nonce);
        var ciphertext = Convert.FromBase64String(enc.ciphertext);
        var tag = Convert.FromBase64String(enc.tag);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, kdfSalt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyBytes);
        var plaintext = new byte[ciphertext.Length];
        using (var aesg = new AesGcm(key))
        {
            aesg.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        var json = Encoding.UTF8.GetString(plaintext);
        var token = JsonSerializer.Deserialize<TokenFile>(json);
        if (token == null) throw new Exception("Invalid token content");
        return token;
    }

    static string ReadPassword()
    {
        var sb = new StringBuilder();
        ConsoleKeyInfo k;
        while (true)
        {
            k = Console.ReadKey(intercept: true);
            if (k.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
            if (k.Key == ConsoleKey.Backspace && sb.Length > 0) { sb.Length--; Console.Write("\b \b"); }
            else if (!char.IsControl(k.KeyChar)) { sb.Append(k.KeyChar); Console.Write("*"); }
        }
        return sb.ToString();
    }
}
