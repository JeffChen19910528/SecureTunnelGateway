using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

public sealed class FirewallApplyOrchestrator : IFirewallApplyOrchestrator
{
    private readonly IFirewallRuleGenerator _generator;
    private readonly IFirewallService _firewallService;
    private readonly ILogger<FirewallApplyOrchestrator> _logger;

    public FirewallApplyOrchestrator(IFirewallRuleGenerator generator, IFirewallService firewallService, ILogger<FirewallApplyOrchestrator> logger)
    {
        _generator = generator;
        _firewallService = firewallService;
        _logger = logger;
    }

    public async Task<FirewallApplyResult> ApplyAsync(
        GatewayConfiguration configuration,
        IReadOnlyList<Peer> peers,
        IReadOnlyList<ProtectedResource> resources,
        IReadOnlyList<AccessPolicy> policies,
        bool dryRun,
        CancellationToken cancellationToken = default)
    {
        // Step 1: generate + validate (dry-run mode so nothing touches disk yet).
        var generation = await _generator.GenerateAsync(configuration, peers, resources, policies,
            new FirewallGenerationOptions { DryRun = true }, cancellationToken);

        if (!generation.Success)
        {
            return Failed(FirewallApplyState.NotStarted, dryRun,
                $"Validation failed before any candidate was generated: {string.Join("; ", generation.ValidationIssues.Select(i => i.Message))}",
                generation.ValidationIssues);
        }

        if (dryRun)
        {
            return new FirewallApplyResult
            {
                Success = true,
                DryRun = true,
                State = FirewallApplyState.Generated,
                Message = $"[DRY-RUN] Candidate ruleset generated with {generation.EffectiveRules.Count} effective rule(s). Nothing was applied.",
                ValidationIssues = generation.ValidationIssues
            };
        }

        var activePath = configuration.FirewallRulesetPath;
        var candidatePath = activePath + ".candidate";
        var backupPath = activePath + ".lastknowngood";

        // Step 2: write the candidate to a scratch path (never the active path yet).
        try
        {
            var directory = Path.GetDirectoryName(candidatePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }
            await File.WriteAllTextAsync(candidatePath, generation.RenderedForReview, cancellationToken);
        }
        catch (Exception ex)
        {
            return Failed(FirewallApplyState.NotStarted, false, $"Failed to write candidate ruleset: {ex.Message}", generation.ValidationIssues);
        }

        // Step 3: syntax-check the candidate before touching the active file or kernel state.
        var syntaxCheck = await _firewallService.ValidateSyntaxAsync(candidatePath, cancellationToken);
        if (syntaxCheck.ExitCode == -1)
        {
            return Failed(FirewallApplyState.Generated, false, "BLOCKED: 'nft' command not available on this host - cannot validate or apply.", generation.ValidationIssues);
        }
        if (!syntaxCheck.Success)
        {
            _logger.LogError("nftables syntax check failed: {Stderr}", syntaxCheck.StandardError);
            return Failed(FirewallApplyState.Generated, false, $"nftables syntax validation failed: {syntaxCheck.StandardError.Trim()}", generation.ValidationIssues);
        }

        // Step 4: back up the current active ruleset (if any) before replacing it, so a
        // failure below leaves us able to identify/restore the last known good file.
        var hadPreviousActive = File.Exists(activePath);
        if (hadPreviousActive)
        {
            File.Copy(activePath, backupPath, overwrite: true);
        }

        try
        {
            File.Copy(candidatePath, activePath, overwrite: true);
        }
        catch (Exception ex)
        {
            return Failed(FirewallApplyState.SyntaxValidated, false, $"Failed to promote candidate to active ruleset: {ex.Message}", generation.ValidationIssues);
        }

        // Step 5: apply.
        var apply = await _firewallService.ApplyAsync(activePath, cancellationToken);
        if (apply.ExitCode == -1)
        {
            RestoreOrRemove(activePath, backupPath, hadPreviousActive);
            return Failed(FirewallApplyState.SyntaxValidated, false, "BLOCKED: 'nft' command not available on this host - candidate was validated but not applied.", generation.ValidationIssues);
        }
        if (!apply.Success)
        {
            _logger.LogError("nftables apply failed: {Stderr}", apply.StandardError);
            RestoreOrRemove(activePath, backupPath, hadPreviousActive);
            return Failed(FirewallApplyState.SyntaxValidated, false, $"nftables apply failed: {apply.StandardError.Trim()}. The previous ruleset (if any) was left in place.", generation.ValidationIssues);
        }

        // Step 6: verify - only report success if the table is actually confirmed present.
        var status = await _firewallService.GetStatusAsync(cancellationToken);
        if (status.State != FirewallTableState.Present)
        {
            _logger.LogError("nftables apply reported success but verification did not confirm the table is present: {Message}", status.Message);
            return Failed(FirewallApplyState.Applied, false,
                $"Applied, but verification failed: {status.Message}. Effective firewall state is UNKNOWN - do not assume the previous ruleset is still in effect.",
                generation.ValidationIssues);
        }

        _logger.LogInformation("Firewall ruleset applied and verified: {RuleCount} effective rule(s).", generation.EffectiveRules.Count);

        return new FirewallApplyResult
        {
            Success = true,
            DryRun = false,
            State = FirewallApplyState.Verified,
            Message = $"Applied and verified. {generation.EffectiveRules.Count} effective rule(s) active in table 'inet securetunnel'.",
            ValidationIssues = generation.ValidationIssues
        };
    }

    private static void RestoreOrRemove(string activePath, string backupPath, bool hadPreviousActive)
    {
        try
        {
            if (hadPreviousActive && File.Exists(backupPath))
            {
                File.Copy(backupPath, activePath, overwrite: true);
            }
            else if (!hadPreviousActive && File.Exists(activePath))
            {
                File.Delete(activePath);
            }
        }
        catch
        {
            // Best-effort: the failure is already reported to the caller; a secondary
            // filesystem error here must not mask the original apply failure.
        }
    }

    private static FirewallApplyResult Failed(FirewallApplyState state, bool dryRun, string message, IReadOnlyList<ValidationIssue> issues) => new()
    {
        Success = false,
        DryRun = dryRun,
        State = FirewallApplyState.Failed,
        Message = $"[last successful step: {state}] {message}",
        ValidationIssues = issues
    };
}
