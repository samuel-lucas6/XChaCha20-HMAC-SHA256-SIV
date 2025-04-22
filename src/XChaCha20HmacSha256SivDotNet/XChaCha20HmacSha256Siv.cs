using System.Security.Cryptography;
using Geralt;

namespace XChaCha20HmacSha256SivDotNet;

public static class XChaCha20HmacSha256Siv
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
        Span<byte> d = stackalloc byte[TagSize]; d.Clear();
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, macKey);
        // Unclear from the Internet-Draft whether empty associated data gets processed
        // If associatedData = Array.Empty<byte>(), associatedData.Length == 1
        // If no associatedData is specified, associatedData.Length == 0
        int associatedDataLength = associatedData.Length > 0 ? associatedData.Sum(ad => ad.Length) : associatedData.Length;
        if (associatedDataLength == 0 && plaintext.Length == 0) {
            d[^1] = 1;
            hmac.AppendData(d);
            hmac.GetCurrentHash(tag);
            return;
        }

        hmac.AppendData(d);
        hmac.GetHashAndReset(d);

        foreach (var ad in associatedData) {
            if (ad.Length == 0) {
                continue;
            }
            Dbl256(d);
            hmac.AppendData(ad);
            hmac.GetHashAndReset(tag);
            Xor(d, tag, TagSize);
        }

        if (plaintext.Length >= TagSize) {
            hmac.AppendData(plaintext[..^TagSize]);
            Xor(d, plaintext[^TagSize..], TagSize);
        }
        else {
            Dbl256(d);
            Xor(d, plaintext, plaintext.Length);
            d[plaintext.Length] ^= 0x80;
        }
        hmac.AppendData(d);
        hmac.GetCurrentHash(tag);
        CryptographicOperations.ZeroMemory(d);
    }

    private static void Dbl256(Span<byte> d)
    {
        var carry = 0;
        for (int i = TagSize; i-- > 0;) {
            var tmp = (d[i] << 1) | carry;
            carry = (d[i] >> 7) & 0x01;
            d[i] = (byte)tmp;
        }
        var mask = -carry;
        d[TagSize - 2] ^= (byte)(0x04 & mask);
        d[TagSize - 1] ^= (byte)(0x25 & mask);
    }

    private static void Xor(Span<byte> buffer, ReadOnlySpan<byte> message, int length)
    {
        for (int i = 0; i < length; i++) {
            buffer[i] ^= message[i];
        }
    }
}
