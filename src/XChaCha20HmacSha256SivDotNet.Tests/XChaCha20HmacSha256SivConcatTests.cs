using System.Security.Cryptography;

namespace XChaCha20HmacSha256SivDotNet.Tests;

[TestClass]
public class XChaCha20HmacSha256SivConcatConcatTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "35e240cc94bf8e5ac218fb8483567a5131fda5478e7a6826a58e39d2d64b5af21e367ffff92ef671fe82a8bbcde3ed98000e33930dab848ae9c8aced7665511d091fe1440cf63f3cb7335fc0df37c5f668e772ad1f7f9a90d778078f4857c145e313af6ef5e3c5d0e65fba3c8b12a0805b2b31f8b9a1200d304570904347a9f366643db68f1ee09f7e017f22f4404be61195",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "50515253c0c1c2c3c4c5c6c7",
            "4041424344454647"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [XChaCha20HmacSha256SivConcat.TagSize - 1, 0, XChaCha20HmacSha256SivConcat.KeySize, XChaCha20HmacSha256SivConcat.TagSize];
        yield return [XChaCha20HmacSha256SivConcat.TagSize, 1, XChaCha20HmacSha256SivConcat.KeySize, XChaCha20HmacSha256SivConcat.TagSize];
        yield return [XChaCha20HmacSha256SivConcat.TagSize, 0, XChaCha20HmacSha256SivConcat.KeySize + 1, XChaCha20HmacSha256SivConcat.TagSize];
        yield return [XChaCha20HmacSha256SivConcat.TagSize, 0, XChaCha20HmacSha256SivConcat.KeySize - 1, XChaCha20HmacSha256SivConcat.TagSize];
        yield return [XChaCha20HmacSha256SivConcat.TagSize, 0, XChaCha20HmacSha256SivConcat.KeySize, null!];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(64, XChaCha20HmacSha256SivConcat.KeySize);
        Assert.AreEqual(24, XChaCha20HmacSha256SivConcat.NonceSize);
        Assert.AreEqual(32, XChaCha20HmacSha256SivConcat.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string key, string associatedData1, string associatedData2)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> k = Convert.FromHexString(key);
        byte[] ad1 = Convert.FromHexString(associatedData1);
        byte[] ad2 = Convert.FromHexString(associatedData2);

        XChaCha20HmacSha256SivConcat.Encrypt(c, p, k, ad1, ad2);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int? associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var k = new byte[keySize];
        var ad = associatedDataSize == null ? null : new byte[(int)associatedDataSize];

        if (associatedDataSize != null) {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => XChaCha20HmacSha256SivConcat.Encrypt(c, p, k, ad!));
        }
        else {
            Assert.ThrowsExactly<ArgumentNullException>(() => XChaCha20HmacSha256SivConcat.Encrypt(c, p, k, ad!));
            Assert.ThrowsExactly<ArgumentNullException>(() => XChaCha20HmacSha256SivConcat.Encrypt(c, p, k, ad!, ad!));
        }
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string key, string associatedData1, string associatedData2)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        byte[] ad1 = Convert.FromHexString(associatedData1);
        byte[] ad2 = Convert.FromHexString(associatedData2);

        XChaCha20HmacSha256SivConcat.Decrypt(p, c, k, ad1, ad2);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string key, string associatedData1, string associatedData2)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "c", Convert.FromHexString(ciphertext) },
            { "k", Convert.FromHexString(key) },
            { "ad1", Convert.FromHexString(associatedData1) },
            { "ad2", Convert.FromHexString(associatedData2) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsExactly<CryptographicException>(() => XChaCha20HmacSha256SivConcat.Decrypt(p, parameters["c"], parameters["k"], parameters["ad1"], parameters["ad2"]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int? associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var k = new byte[keySize];
        var ad = associatedDataSize == null ? null : new byte[(int)associatedDataSize];

        if (associatedDataSize != null) {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => XChaCha20HmacSha256SivConcat.Decrypt(p, c, k, ad!));
        }
        else {
            Assert.ThrowsExactly<ArgumentNullException>(() => XChaCha20HmacSha256SivConcat.Decrypt(p, c, k, ad!));
            Assert.ThrowsExactly<ArgumentNullException>(() => XChaCha20HmacSha256SivConcat.Decrypt(p, c, k, ad!, ad!));
        }
    }
}
