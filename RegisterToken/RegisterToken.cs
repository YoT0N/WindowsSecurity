using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Collections.Generic;

class RegisterToken
{
    class User 
    { 
        public string username { get; set; } 
        public string salt { get; set; } 
        public string hash { get; set; } 
    }

    
    const int Pbkdf2Iterations = 100000;
    const int KeyBytes = 32; // 256 біт

    static void Main()
    {
        Console.WriteLine("=== Token Registration (encrypted token + server DB) ===");

        Console.Write("Enter username: ");
        var username = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(username)) 
        { 
            Console.WriteLine("Username required");
            return; 
        }

        Console.Write("Enter password: ");
        var password = ReadPassword();
        if (string.IsNullOrEmpty(password)) 
        {
            Console.WriteLine("Password required");
            return;
        }

        // Генерую сіль для хешування пароля
        var saltBytes = RandomNumberGenerator.GetBytes(16);
        var saltB64 = Convert.ToBase64String(saltBytes);

        // Обчислюю PBKDF2 хеш для сервера (Це верифікатор)
        var hashBytes = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyBytes);
        var hashB64 = Convert.ToBase64String(hashBytes);

        var dbPath = @"C:\Lessons\Course4\Безпека програм та даних\Lab7ACL\users_db.json";

        List<User> users;
        if (File.Exists(dbPath))
        {
            var j = File.ReadAllText(dbPath);
            users = JsonSerializer.Deserialize<List<User>>(j) ?? new List<User>();
        }
        else users = new List<User>();

        users.RemoveAll(u => u.username == username);
        users.Add(new User { username = username, salt = saltB64, hash = hashB64 });
        File.WriteAllText(dbPath, JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"User '{username}' added/updated in DB at: {dbPath}");

        // Створюю JSON токен
        var tokenObj = new { username = username, salt = saltB64 };
        var tokenJson = JsonSerializer.Serialize(tokenObj);

        // Зашифрую иокен Json ключем, отриманим з пароля через PBKDF2 (окрема сіль для виведення ключа)
        // Отримую ключ AES, використовуючи PBKDF2 з іншою випадковою сіллю (kdfSalt), і зберігаю цю сіль у заголовку файлу.
        var kdfSalt = RandomNumberGenerator.GetBytes(16);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, kdfSalt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyBytes);

        // Використовую AesGcm (автентифіковане шифрування)
        byte[] plaintext = Encoding.UTF8.GetBytes(tokenJson);
        var nonce = RandomNumberGenerator.GetBytes(12); // 96-bit nonce
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        using (var aesg = new AesGcm(key))
        {
            aesg.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        // Зберегаю зашифрований токен як JSON
        var encryptedToken = new
        {
            kdfSalt = Convert.ToBase64String(kdfSalt),
            nonce = Convert.ToBase64String(nonce),
            ciphertext = Convert.ToBase64String(ciphertext),
            tag = Convert.ToBase64String(tag)
        };

        Console.Write("Enter path where to save encrypted token (e.g. E:\\token.enc): ");
        var tokenPath = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(tokenPath)) 
        {
            Console.WriteLine("No path given");
            return;
        }

        File.WriteAllText(tokenPath, JsonSerializer.Serialize(encryptedToken, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Encrypted token written to: {tokenPath}\n\nDone.");
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
