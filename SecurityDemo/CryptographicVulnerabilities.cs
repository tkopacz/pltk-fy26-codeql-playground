using System.Security.Cryptography;
using System.Text;

namespace SecurityDemo;

/// <summary>
/// This class demonstrates various cryptographic vulnerabilities including
/// hardcoded credentials, weak encryption, and insecure random number generation.
/// </summary>
public class CryptographicVulnerabilities
{
    // VULNERABILITY: Hardcoded credentials and secrets
    // Credentials in source code can be discovered by anyone with access to the code.
    
    /// <summary>
    /// VULNERABILITY: Hardcoded database password
    /// Never store passwords in source code.
    /// </summary>
    private const string DatabasePassword = "MySecretP@ssw0rd123!";
    private const string ApiKey = "sk_test_EXAMPLE1234567890abcdefghijklmno";  // Example fake key
    private const string AdminPassword = "admin123";
    
    /// <summary>
    /// VULNERABILITY: Hardcoded connection string with credentials
    /// Connection strings should be in configuration files with restricted access.
    /// </summary>
    private readonly string _connectionString = 
        "Server=myserver;Database=mydb;User Id=sa;Password=SqlP@ssw0rd!;";

    /// <summary>
    /// VULNERABILITY: Hardcoded encryption key
    /// Encryption keys must be generated securely and stored in secure key vaults.
    /// </summary>
    private static readonly byte[] HardcodedKey = 
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    /// <summary>
    /// VULNERABILITY: Weak encryption - DES algorithm
    /// DES is cryptographically broken and should never be used.
    /// </summary>
#pragma warning disable SYSLIB0021 // DES is obsolete
    public byte[] EncryptWithDES_Vulnerable(string plaintext, byte[] key, byte[] iv)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var des = DES.Create();
        des.Key = key;
        des.IV = iv;
        
        using var encryptor = des.CreateEncryptor();
        byte[] data = Encoding.UTF8.GetBytes(plaintext);
        return encryptor.TransformFinalBlock(data, 0, data.Length);
    }
#pragma warning restore SYSLIB0021

    /// <summary>
    /// VULNERABILITY: Weak encryption - Triple DES
    /// 3DES has known vulnerabilities and is deprecated.
    /// </summary>
#pragma warning disable SYSLIB0021
    public byte[] EncryptWithTripleDES_Vulnerable(string plaintext)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var tripleDES = TripleDES.Create();
        tripleDES.Key = HardcodedKey;  // Also using hardcoded key
        tripleDES.Mode = CipherMode.ECB;  // ECB mode is insecure
        
        using var encryptor = tripleDES.CreateEncryptor();
        byte[] data = Encoding.UTF8.GetBytes(plaintext);
        return encryptor.TransformFinalBlock(data, 0, data.Length);
    }
#pragma warning restore SYSLIB0021

    /// <summary>
    /// VULNERABILITY: ECB mode encryption
    /// ECB mode doesn't use an IV and reveals patterns in the plaintext.
    /// Identical plaintext blocks produce identical ciphertext blocks.
    /// </summary>
    public byte[] EncryptWithECB_Vulnerable(string plaintext, byte[] key)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;  // ECB mode is insecure
        
        using var encryptor = aes.CreateEncryptor();
        byte[] data = Encoding.UTF8.GetBytes(plaintext);
        return encryptor.TransformFinalBlock(data, 0, data.Length);
    }

    /// <summary>
    /// VULNERABILITY: Weak hashing - MD5
    /// MD5 is cryptographically broken and should not be used for security.
    /// </summary>
#pragma warning disable CA5351 // MD5 is weak
    public string HashWithMD5_Vulnerable(string input)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var md5 = MD5.Create();
        byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }
#pragma warning restore CA5351

    /// <summary>
    /// VULNERABILITY: Weak hashing - SHA1
    /// SHA1 is deprecated and vulnerable to collision attacks.
    /// </summary>
#pragma warning disable CA5350 // SHA1 is weak
    public string HashWithSHA1_Vulnerable(string input)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var sha1 = SHA1.Create();
        byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hash);
    }
#pragma warning restore CA5350

    /// <summary>
    /// VULNERABILITY: Insecure random number generation
    /// Random class is not cryptographically secure and predictable.
    /// </summary>
    public string GenerateToken_Vulnerable()
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var random = new Random();  // Not cryptographically secure
        var token = new byte[32];
        random.NextBytes(token);
        return Convert.ToBase64String(token);
    }

    /// <summary>
    /// VULNERABILITY: Predictable random with seed
    /// Using a predictable seed makes the random sequence reproducible.
    /// </summary>
    public int GenerateRandomNumber_Vulnerable(int seed)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var random = new Random(seed);  // Predictable with known seed
        return random.Next();
    }

    /// <summary>
    /// VULNERABILITY: Weak password hashing
    /// Hashing passwords without salt or using weak algorithms.
    /// </summary>
    public string HashPassword_Vulnerable(string password)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(hash);  // No salt, no iterations
    }

    /// <summary>
    /// VULNERABILITY: Hardcoded salt for password hashing
    /// Using the same salt for all passwords defeats its purpose.
    /// </summary>
    private const string HardcodedSalt = "MySaltValue123";
    
    public string HashPasswordWithSalt_Vulnerable(string password)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var sha256 = SHA256.Create();
        string saltedPassword = password + HardcodedSalt;  // Same salt for all
        byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(saltedPassword));
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// VULNERABILITY: Insufficient iteration count for PBKDF2
    /// Low iteration count makes brute-force attacks easier.
    /// </summary>
    public byte[] DeriveKey_Vulnerable(string password, byte[] salt)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100);  // Too few iterations
        return pbkdf2.GetBytes(32);
    }

    /// <summary>
    /// VULNERABILITY: Using user credentials in code
    /// Building authentication with hardcoded credentials.
    /// </summary>
    public bool Authenticate_Vulnerable(string username, string password)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        return username == "admin" && password == AdminPassword;
    }

    /// <summary>
    /// SAFE: Using AES with GCM mode
    /// AES-GCM provides authenticated encryption.
    /// </summary>
    public byte[] EncryptWithAESGCM_Safe(string plaintext, byte[] key, byte[] nonce, out byte[] tag)
    {
        // SAFE CODE - Use AES-GCM
        byte[] data = Encoding.UTF8.GetBytes(plaintext);
        byte[] ciphertext = new byte[data.Length];
        tag = new byte[16];  // 128-bit tag
        
        using var aesGcm = new AesGcm(key, 16);
        aesGcm.Encrypt(nonce, data, ciphertext, tag);
        
        return ciphertext;
    }

    /// <summary>
    /// SAFE: Secure random number generation
    /// Use RandomNumberGenerator for cryptographic purposes.
    /// </summary>
    public string GenerateToken_Safe()
    {
        // SAFE CODE - Use cryptographically secure random
        byte[] token = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(token);
        }
        return Convert.ToBase64String(token);
    }

    /// <summary>
    /// SAFE: Secure password hashing with PBKDF2
    /// Use proper iteration count and unique salt per password.
    /// </summary>
    public string HashPassword_Safe(string password, out byte[] salt)
    {
        // SAFE CODE - Use PBKDF2 with proper parameters
        salt = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        
        // NIST recommends at least 10,000 iterations, preferably 100,000+
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password, 
            salt, 
            100000,  // High iteration count
            HashAlgorithmName.SHA256
        );
        
        byte[] hash = pbkdf2.GetBytes(32);
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// SAFE: Using SHA256 or SHA512 for hashing
    /// Modern secure hash algorithms.
    /// </summary>
    public string HashData_Safe(string input)
    {
        // SAFE CODE - Use SHA256 or better
        using var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// SAFE: Load credentials from secure configuration
    /// Never hardcode credentials in source code.
    /// </summary>
    public string GetDatabasePassword_Safe()
    {
        // SAFE CODE - Load from environment variables or secure vault
        // In production, use Azure Key Vault, AWS Secrets Manager, etc.
        string? password = Environment.GetEnvironmentVariable("DB_PASSWORD");
        
        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException("Database password not configured");
        }
        
        return password;
    }
}
