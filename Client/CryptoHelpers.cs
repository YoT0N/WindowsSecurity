using System;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

public static class CryptoHelpers
{
    private const uint PROV_RSA_AES = 24; 
    private const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
    private const uint CALG_SHA_256 = 0x0000800c;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptAcquireContext(
        out IntPtr phProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptCreateHash(IntPtr hProv, uint Algid, IntPtr hKey, uint dwFlags, out IntPtr phHash);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptHashData(IntPtr hHash, byte[] data, uint dataLen, uint flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptGetHashParam(IntPtr hHash, uint dwParam, [Out] byte[] pbData, ref uint pdwDataLen, uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptDestroyHash(IntPtr hHash);

    private const uint HP_HASHSIZE = 0x0004;
    private const uint HP_HASHVAL = 0x0002;

    public static byte[] HashWithCryptoAPI_SHA256(byte[] data)
    {
        // Try to use CryptoAPI
        if (CryptAcquireContext(out IntPtr hProv, null, null, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            try
            {
                if (!CryptCreateHash(hProv, CALG_SHA_256, IntPtr.Zero, 0, out IntPtr hHash))
                {
                    // fallback
                    return HashManagedSha256(data);
                }

                try
                {
                    if (!CryptHashData(hHash, data, (uint)data.Length, 0))
                        return HashManagedSha256(data);

                    uint size = 0;
                    CryptGetHashParam(hHash, HP_HASHSIZE, null, ref size, 0);
                    if (size == 0) return HashManagedSha256(data);

                    byte[] hash = new byte[size];
                    CryptGetHashParam(hHash, HP_HASHVAL, hash, ref size, 0);
                    return hash;
                }
                finally
                {
                    CryptDestroyHash(hHash);
                }
            }
            finally
            {
                CryptReleaseContext(hProv, 0);
            }
        }
        else
        {
            return HashManagedSha256(data);
        }
    }

    public static byte[] HashManagedSha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    public static string ToBase64(byte[] b) => Convert.ToBase64String(b);
    public static byte[] FromBase64(string s) => Convert.FromBase64String(s);

    public static byte[] RandomSalt(int size = 16)
    {
        byte[] s = new byte[size];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(s);
        return s;
    }

    public static byte[] SaltedHash(string password, byte[] salt)
    {
        byte[] pw = Encoding.UTF8.GetBytes(password);
        byte[] all = new byte[salt.Length + pw.Length];
        Buffer.BlockCopy(salt, 0, all, 0, salt.Length);
        Buffer.BlockCopy(pw, 0, all, salt.Length, pw.Length);
        return HashWithCryptoAPI_SHA256(all);
    }
}
