using System.Security.Cryptography;

namespace XChaCha20HmacSha256SivDotNet.Tests;

[TestClass]
public class XChaCha20HmacSha256SivConcatConcatTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "347bf35fafc59dde9ace95fdbc23c6770db27d330474fce94cfc4794d38fae843465f8002f3adc6974e4955b08e1236bea49c5811e93a4f94b4da61bf3057eec8ed028ad956e3f7f99ee013b3cbf1a15a88de49f247aab4c6bedf2c58b9b577711dc70965b23b4db15f2fd8a6237c7acd496408dfea880c8774b24b251492642dd686bc78e8cf77096c02ebb42f54913fd6a",
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
