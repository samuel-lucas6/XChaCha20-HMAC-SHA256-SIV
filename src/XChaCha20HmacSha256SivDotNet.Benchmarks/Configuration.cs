using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Reports;

namespace XChaCha20HmacSha256SivDotNet.Benchmarks;

public class Configuration : ManualConfig
{
    public Configuration()
    {
        SummaryStyle = SummaryStyle.Default.WithRatioStyle(RatioStyle.Trend);
    }
}
