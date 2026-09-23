namespace SecureTunnel.GatewayAgent.Models;

public enum ValidationSeverity
{
    Warning,
    Error
}

/// <summary>A single validation finding. Never includes secret values (see docs/security-model.md).</summary>
public sealed record ValidationIssue(string Field, ValidationSeverity Severity, string Message, string? FixHint = null)
{
    public override string ToString()
    {
        var prefix = Severity == ValidationSeverity.Error ? "[ERROR]" : "[WARN]";
        var fix = FixHint is null ? "" : $" Fix: {FixHint}";
        return $"{prefix} {Field}: {Message}{fix}";
    }
}

public sealed class ValidationResult
{
    public List<ValidationIssue> Issues { get; } = new();

    public bool IsValid => !Issues.Exists(i => i.Severity == ValidationSeverity.Error);

    public IEnumerable<ValidationIssue> Errors => Issues.Where(i => i.Severity == ValidationSeverity.Error);
    public IEnumerable<ValidationIssue> Warnings => Issues.Where(i => i.Severity == ValidationSeverity.Warning);

    public void AddError(string field, string message, string? fixHint = null) =>
        Issues.Add(new ValidationIssue(field, ValidationSeverity.Error, message, fixHint));

    public void AddWarning(string field, string message, string? fixHint = null) =>
        Issues.Add(new ValidationIssue(field, ValidationSeverity.Warning, message, fixHint));
}
