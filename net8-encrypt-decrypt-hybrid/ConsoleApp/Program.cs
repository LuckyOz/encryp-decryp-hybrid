
//********************Main Program********************

using System.Text;
using System.Text.Json;

var (publicKey, privateKey) = LoadEnvironmentVariables();
if (publicKey == null || privateKey == null)
{
    return;
}

ShowBanner();
RunMenu(publicKey, privateKey);

return;

//********************End Program********************

static void ShowBanner()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("╔═══════════════════════════════════════════════════════════╗");
    Console.WriteLine("║                                                           ║");
    Console.WriteLine("║        HYBRID ENCRYPTION - AES 256 + RSA 2048             ║");
    Console.WriteLine("║              .NET 8 Console Application                   ║");
    Console.WriteLine("║                                                           ║");
    Console.WriteLine("╚═══════════════════════════════════════════════════════════╝");
    Console.ResetColor();
    Console.WriteLine();
}

static void RunMenu(string publicKey, string privateKey)
{
    var isRunning = true;
    
    while (isRunning)
    {
        ShowMenuOptions();
        var input = Console.ReadLine()?.Trim();
        
        switch (input)
        {
            case "1":
                EncryptText(publicKey);
                break;
            case "2":
                DecryptText(privateKey);
                break;
            case "0":
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n👋 Terima kasih telah menggunakan aplikasi ini!");
                Console.ResetColor();
                isRunning = false;
                break;
            default:
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n❌ Pilihan tidak valid. Silakan coba lagi.");
                Console.ResetColor();
                break;
        }
    }
}

static void ShowMenuOptions()
{
    Console.WriteLine("\n════════════════ MENU UTAMA ════════════════");
    Console.WriteLine();
    Console.WriteLine("  [1] Encrypt Text");
    Console.WriteLine("  [2] Decrypt Text");
    Console.WriteLine("  [0] Exit");
    Console.WriteLine();
    Console.WriteLine("════════════════════════════════════════════");
    Console.Write("\nPilih menu: ");
}

static void EncryptText(string publicKey)
{
    Console.WriteLine("\n────────────── ENCRYPT TEXT ──────────────");
    Console.Write("\nMasukkan teks yang akan di-encrypt: ");
    var plainText = Console.ReadLine();
    
    if (string.IsNullOrWhiteSpace(plainText))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("❌ Teks tidak boleh kosong!");
        Console.ResetColor();
        return;
    }
    
    try
    {
        var result = EncryptDecryptHelper.Encrypt(plainText, publicKey);
        
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n✅ Enkripsi berhasil!");
        Console.ResetColor();
        
        Console.WriteLine("\n📦 Hasil Enkripsi:");
        Console.WriteLine("─────────────────────────────────────────────");
        
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"Data (Encrypted): {result.Data}");
        Console.WriteLine($"AES Key (RSA Encrypted): {result.Aes}");
        Console.WriteLine($"IV: {result.Iv}");
        Console.ResetColor();
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"\n❌ Error saat enkripsi: {ex.Message}");
        Console.ResetColor();
    }
}

static void DecryptText(string privateKey)
{
    Console.WriteLine("\n────────────── DECRYPT TEXT ──────────────");
    
    Console.Write("\nMasukkan Data (encrypted text): ");
    var encryptedData = Console.ReadLine();
    
    Console.Write("Masukkan AES Key (RSA encrypted): ");
    var encryptedAesKey = Console.ReadLine();
    
    Console.Write("Masukkan IV: ");
    var iv = Console.ReadLine();
    
    if (string.IsNullOrWhiteSpace(encryptedData) || 
        string.IsNullOrWhiteSpace(encryptedAesKey) || 
        string.IsNullOrWhiteSpace(iv))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("❌ Semua field harus diisi!");
        Console.ResetColor();
        return;
    }
    
    try
    {
        var request = new EncryptRequest
        {
            Data = encryptedData,
            Aes = encryptedAesKey,
            Iv = iv
        };
        
        var helper = new EncryptDecryptHelper();
        var decryptedText = EncryptDecryptHelper.Decrypt(request, privateKey);
        
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n✅ Dekripsi berhasil!");
        Console.ResetColor();
        
        Console.WriteLine("\n📄 Hasil Dekripsi:");
        Console.WriteLine("─────────────────────────────────────────────");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(decryptedText);
        Console.ResetColor();
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"\n❌ Error saat dekripsi: {ex.Message}");
        Console.ResetColor();
    }
}

static (string?, string?) LoadEnvironmentVariables()
{
    try
    {
        // Load environment variables from .env file
        DotNetEnv.Env.Load();

        // Retrieve RSA keys from environment variables
        var publicKey = Environment.GetEnvironmentVariable("RSA_PUBLIC_KEY");
        var privateKey = Environment.GetEnvironmentVariable("RSA_PRIVATE_KEY");

        // Validate that keys are loaded before decoding
        if (string.IsNullOrEmpty(publicKey) || string.IsNullOrEmpty(privateKey))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ERROR: RSA keys not found in .env file!");
            Console.WriteLine("Please ensure RSA_PUBLIC_KEY and RSA_PRIVATE_KEY are defined in .env");
            Console.WriteLine($"Public Key found: {!string.IsNullOrEmpty(publicKey)}");
            Console.WriteLine($"Private Key found: {!string.IsNullOrEmpty(privateKey)}");
            Console.ResetColor();
            return (null, null);
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("✓ Environment variables loaded successfully");
        Console.ResetColor();
        Console.WriteLine();

        return (publicKey, privateKey);
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"ERROR: Failed to load .env file - {ex.Message}");
        Console.ResetColor();
        return (null, null);
    }
}

