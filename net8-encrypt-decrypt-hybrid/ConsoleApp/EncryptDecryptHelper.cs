using System.Security.Cryptography;
using System.Text;

public class EncryptDecryptHelper
{
    public static EncryptRequest Encrypt(string data, string publicKey)
    {
        //Generate Aes & Iv Key
        var aesKey = GenerateAesKey();
        var ivKey = GenerateIV();
        
        //Encrypt 
        var encryptedData = EncryptData(data, aesKey, ivKey);
        
        //Encrypt Aes Key
        var encryptedAesKey = EncryptAesKey(aesKey, publicKey);

        //Setup Response
        var dataResponse = new EncryptRequest()
        {
            Data = encryptedData,
            Aes = encryptedAesKey,
            Iv = Convert.ToBase64String(ivKey)
        };
        
        return dataResponse;
    }

    public static string Decrypt(EncryptRequest request, string privateKey)
    {
        //Decrypt Aes Key
        var aesKey = DecryptAesKey(request.Aes!, privateKey);
        
        //Decrypt Data
        return DecryptData(
            ciphertext: request.Data,
            key: aesKey,
            iv: Convert.FromBase64String(request.Iv));
    }
    
    private static byte[] GenerateAesKey()
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        return aes.Key;
    }
    
    private static byte[] GenerateIV()
    {
        using var aes = Aes.Create();
        aes.GenerateIV();
        return aes.IV;
    }

    private static string EncryptData(string plaintext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        
        using var encryptor = aes.CreateEncryptor();
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plaintext);
        }
        
        return Convert.ToBase64String(msEncrypt.ToArray());
    }

    private static string DecryptData(string ciphertext, byte[] key, byte[] iv)
    {
        var ciphertextByte = 
            Convert.FromBase64String(ciphertext);
        
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        
        using var decryptor = aes.CreateDecryptor();
        using var msDecrypt = new MemoryStream(ciphertextByte);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        
        return srDecrypt.ReadToEnd();
    }

    private static string EncryptAesKey(byte[] aesKey, string publicKey)
    {
        var publicKeyDecode =
            Encoding.UTF8.GetString(Convert.FromBase64String(publicKey));
        
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyDecode);
        var encryptedAesKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(encryptedAesKey);
    }

    private static byte[] DecryptAesKey(string encryptedAesKey, string privateKey)
    {
        var encryptedAesKeyByte = Convert.FromBase64String(encryptedAesKey);
        var privateKeyDecode =
            Encoding.UTF8.GetString(Convert.FromBase64String(privateKey));
        
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyDecode);
        return rsa.Decrypt(encryptedAesKeyByte, RSAEncryptionPadding.OaepSHA256);
    }
}