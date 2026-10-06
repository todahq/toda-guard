using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Toda.Guard.Services;

/// <summary>
/// Token signing and encryption keys, created on first start and kept on disk, so tokens survive
/// restarts. In production the folder sits on a persistent volume (or is replaced by keys from a
/// secret store); it must never be committed or shared between unrelated installations.
/// </summary>
public static class OidcKeys
{
    public static (SecurityKey Signing, SecurityKey Encryption) LoadOrCreate(string folder)
    {
        Directory.CreateDirectory(folder);

        string signingPath = Path.Combine(folder, "signing.pem");
        RSA rsa = RSA.Create(2048);
        if (File.Exists(signingPath))
        {
            rsa.ImportFromPem(File.ReadAllText(signingPath));
        }
        else
        {
            File.WriteAllText(signingPath, rsa.ExportRSAPrivateKeyPem());
        }

        string encryptionPath = Path.Combine(folder, "encryption.key");
        byte[] encryptionKey;
        if (File.Exists(encryptionPath))
        {
            encryptionKey = Convert.FromBase64String(File.ReadAllText(encryptionPath).Trim());
        }
        else
        {
            encryptionKey = RandomNumberGenerator.GetBytes(32);
            File.WriteAllText(encryptionPath, Convert.ToBase64String(encryptionKey));
        }

        RsaSecurityKey signing = new(rsa) { KeyId = Convert.ToHexString(SHA256.HashData(rsa.ExportRSAPublicKey()))[..16] };
        SymmetricSecurityKey encryption = new(encryptionKey) { KeyId = Convert.ToHexString(SHA256.HashData(encryptionKey))[..16] };
        return (signing, encryption);
    }
}
