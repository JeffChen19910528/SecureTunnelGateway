using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecureTunnel.GatewayAgent.Cli;

public static class OutputFormat
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public static void PrintJson(object value) => Console.WriteLine(JsonSerializer.Serialize(value, JsonOptions));
}

/// <summary>CLI exit codes - see docs/operations-guide.md 一、CLI 總覽.</summary>
public static class ExitCodes
{
    public const int Success = 0;
    public const int GeneralFailure = 1;
    public const int ValidationFailure = 2;
    public const int PermissionDenied = 3;
}
