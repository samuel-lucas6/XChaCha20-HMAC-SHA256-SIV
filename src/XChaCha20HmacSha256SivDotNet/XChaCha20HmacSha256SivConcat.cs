using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;

namespace XChaCha20HmacSha256SivDotNet;

// Not from the Internet-Draft
// This is for benchmarking concatenation vs S2V
// The concatenation is done based on the Internet-Draft associatedData processing
public static class XChaCha20HmacSha256SivConcat
{
    public const int KeySize = 64;
    public const int NonceSize = 24;
    public const int TagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, params byte[][] associatedData)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        ValidateAssociatedData(associatedData);

        ReadOnlySpan<byte> macKey = key[..(KeySize / 2)], encKey = key[(KeySize / 2)..];
        Span<byte> tag = ciphertext[..TagSize];
        ComputeTag(tag, plaintext, macKey, associatedData);
        XChaCha20.Encrypt(ciphertext[TagSize..], plaintext, tag[..XChaCha20.NonceSize], encKey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, params byte[][] associatedData)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        ValidateAssociatedData(associatedData);

        ReadOnlySpan<byte> macKey = key[..(KeySize / 2)], encKey = key[(KeySize / 2)..];
        ReadOnlySpan<byte> tag = ciphertext[..TagSize];
        XChaCha20.Decrypt(plaintext, ciphertext[TagSize..], tag[..XChaCha20.NonceSize], encKey);

        Span<byte> computedTag = stackalloc byte[TagSize];
        ComputeTag(computedTag, plaintext, macKey, associatedData);

        if (!ConstantTime.Equals(tag, computedTag)) {
            CryptographicOperations.ZeroMemory(computedTag);
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException();
        }
    }

    private static void ValidateAssociatedData(params byte[][] associatedData)
    {
        if (associatedData == null) { throw new ArgumentNullException(nameof(associatedData), $"{nameof(associatedData)} cannot be null."); }
        if (associatedData.Any(ad => ad == null)) {
            throw new ArgumentNullException(nameof(associatedData), $"None of the {nameof(associatedData)} inputs can be null.");
        }
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> macKey, params byte[][] associatedData)
    {
        Span<byte> lengths = stackalloc byte[16];
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, macKey);
        int associatedDataLength = associatedData.Length > 0 ? associatedData.Sum(ad => ad.Length) : associatedData.Length;
        // Treat the associated data as one string
        if (associatedDataLength > 0) {
            foreach (var ad in associatedData) {
                hmac.AppendData(ad);
            }
        }
        hmac.AppendData(plaintext);
        // The plaintext length isn't required but doing it for consistency
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[..8], (ulong)associatedDataLength);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)plaintext.Length);
        hmac.AppendData(lengths);
        hmac.GetCurrentHash(tag);
    }
}
