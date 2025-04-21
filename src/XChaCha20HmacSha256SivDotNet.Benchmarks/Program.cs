using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.

namespace XChaCha20HmacSha256SivDotNet.Benchmarks;

[CategoriesColumn]
[Config(typeof(Configuration))]
// ByCategory required for Baseline = true
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class Program
{
    private byte[] _ciphertext, _plaintext, _key, _associatedData, _nonce;

    [Params(0, 16, 32, 64, 128, 256, 512, 1024, 1536, 2048, 16384, 32768, 65536, 131072, 1048576, 10485760, 52428800, 104857600)]
    public int PlaintextSize;

    [Params(0, 64, 1536)]
    public int AssociatedDataSize;

    //
    // S2V (Serial)
    //

    // Not benchmarking S2V in parallel because it's almost always slower (I know from other benchmarks)
    [GlobalSetup(Targets = [nameof(XChaCha20HmacSha256Siv_Encrypt), nameof(XChaCha20HmacSha256Siv_Decrypt)])]
    public void S2vSetup()
    {
        _ciphertext = new byte[PlaintextSize + XChaCha20HmacSha256Siv.TagSize];
        _plaintext = new byte[PlaintextSize];
        _key = new byte[XChaCha20HmacSha256Siv.KeySize];
        _associatedData = new byte[AssociatedDataSize];
        _nonce = new byte[XChaCha20HmacSha256Siv.NonceSize];

        RandomNumberGenerator.Fill(_plaintext);
        RandomNumberGenerator.Fill(_key);
        RandomNumberGenerator.Fill(_associatedData);
        RandomNumberGenerator.Fill(_nonce);

        // Unique random component included as the last element of the header following the Internet-Draft
        XChaCha20HmacSha256Siv.Encrypt(_ciphertext, _plaintext, _key, _associatedData, _nonce);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark(Baseline = true)]
    public void XChaCha20HmacSha256Siv_Encrypt()
    {
        XChaCha20HmacSha256Siv.Encrypt(_ciphertext, _plaintext, _key, _associatedData, _nonce);
    }

    [BenchmarkCategory(Constants.Decryption), Benchmark(Baseline = true)]
    public void XChaCha20HmacSha256Siv_Decrypt()
    {
        XChaCha20HmacSha256Siv.Decrypt(_plaintext, _ciphertext, _key, _associatedData, _nonce);
    }

    //
    // Concat
    //

    [GlobalSetup(Targets = [nameof(XChaCha20HmacSha256SivConcat_Encrypt), nameof(XChaCha20HmacSha256SivConcat_Decrypt)])]
    public void ConcatSetup()
    {
        _ciphertext = new byte[PlaintextSize + XChaCha20HmacSha256SivConcat.TagSize];
        _plaintext = new byte[PlaintextSize];
        _key = new byte[XChaCha20HmacSha256SivConcat.KeySize];
        _associatedData = new byte[AssociatedDataSize];
        _nonce = new byte[XChaCha20HmacSha256SivConcat.NonceSize];

        RandomNumberGenerator.Fill(_plaintext);
        RandomNumberGenerator.Fill(_key);
        RandomNumberGenerator.Fill(_associatedData);
        RandomNumberGenerator.Fill(_nonce);

        XChaCha20HmacSha256SivConcat.Encrypt(_ciphertext, _plaintext, _key, _associatedData, _nonce);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void XChaCha20HmacSha256SivConcat_Encrypt()
    {
        XChaCha20HmacSha256SivConcat.Encrypt(_ciphertext, _plaintext, _key, _associatedData, _nonce);
    }

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void XChaCha20HmacSha256SivConcat_Decrypt()
    {
        XChaCha20HmacSha256SivConcat.Decrypt(_plaintext, _ciphertext, _key, _associatedData, _nonce);
    }

    static void Main(string[] args)
    {
        BenchmarkRunner.Run<Program>();
    }
}
