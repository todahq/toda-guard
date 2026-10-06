using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Casl;
using Toda.Guard.Domain;
using Toda.Guard.Services;
using Toda.Platform.Controllers;
using Volo.Abp;
using Volo.Abp.Domain.Entities;

namespace Toda.Guard.Controllers;

/// <summary>Roles hold rules in CASL's format; grants give a role to an account or a group, with a scope.</summary>
[Route("api/guard/roles")]
[Authorize(Policy = TodaPolicies.Admin)]
public class RolesController(GuardDb guardDb) : GuardControllerBase
{
    public sealed record GrantDto(Guid Id, string PrincipalType, Guid PrincipalId, string PrincipalName, JsonNode? Scope, DateTime? ValidUntil, DateTime CreatedAt);

    public sealed record RoleDto(Guid Id, string Key, string Name, string? Description, bool IsSystem, List<JsonNode?> Rules, List<GrantDto> Grants);

    public sealed record CreateRoleInput(string Key, string Name, string? Description, List<JsonObject> Rules);

    public sealed record GrantInput(string PrincipalType, Guid PrincipalId, JsonObject? Scope, DateTime? ValidUntil);

    public sealed record ValidateInput(JsonObject Rule);

    [HttpGet]
    public Task<List<RoleDto>> List(CancellationToken cancellationToken) => guardDb.RunAsync(async db =>
    {
        List<Role> roles = await db.Roles.AsNoTracking().OrderBy(r => r.Name).ToListAsync(cancellationToken);
        ILookup<Guid, RoleRule> rules = (await db.RoleRules.AsNoTracking().OrderBy(r => r.Order).ToListAsync(cancellationToken)).ToLookup(r => r.RoleId);
        List<RoleGrant> grants = await db.RoleGrants.AsNoTracking().OrderBy(g => g.CreatedAt).ToListAsync(cancellationToken);
        List<Guid> principalIds = grants.Select(g => g.PrincipalId).Distinct().ToList();
        Dictionary<Guid, string> names = (await db.Accounts.AsNoTracking().Where(a => principalIds.Contains(a.Id)).Select(a => new { a.Id, a.Username }).ToListAsync(cancellationToken))
            .ToDictionary(a => a.Id, a => a.Username);
        foreach (var g in await db.Groups.AsNoTracking().Where(g => principalIds.Contains(g.Id)).Select(g => new { g.Id, g.Name }).ToListAsync(cancellationToken))
        {
            names[g.Id] = g.Name;
        }

        return roles.Select(r => new RoleDto(
                r.Id, r.Key, r.Name, r.Description, r.IsSystem,
                rules[r.Id].Select(x => JsonNode.Parse(x.Json)).ToList(),
                grants.Where(g => g.RoleId == r.Id)
                    .Select(g => new GrantDto(g.Id, g.PrincipalType.ToString(), g.PrincipalId, names.GetValueOrDefault(g.PrincipalId, "(removed)"), JsonNode.Parse(g.ScopeJson), g.ValidUntil, g.CreatedAt))
                    .ToList()))
            .ToList();
    }, cancellationToken: cancellationToken);

    /// <summary>Checks a rule before saving: subjects, fields, condition paths and operators. Placeholders are allowed.</summary>
    [HttpPost("validate-rule")]
    public object Validate([FromBody] ValidateInput input)
    {
        try
        {
            return new { errors = AbilityBuilder.Validate(RawRule.Parse(input.Rule.ToJsonString()), GuardSubjects.Registry) };
        }
        catch (JsonException ex)
        {
            return new { errors = new[] { ex.Message } };
        }
    }

    [HttpPost]
    public async Task<RoleDto> Create([FromBody] CreateRoleInput input, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(input.Key) || !System.Text.RegularExpressions.Regex.IsMatch(input.Key, "^[a-z][a-z0-9-]{1,63}$"))
        {
            throw new UserFriendlyException("Role keys are lowercase letters, digits and dashes.");
        }

        List<string> errors = input.Rules.SelectMany((rule, i) => Problems(rule).Select(e => $"Rule {i + 1}: {e}")).ToList();
        if (errors.Count > 0)
        {
            throw new UserFriendlyException(string.Join(" ", errors));
        }

        Guid id = await guardDb.RunAsync(async db =>
        {
            if (await db.Roles.AnyAsync(r => r.Key == input.Key, cancellationToken))
            {
                throw new UserFriendlyException($"A role with key '{input.Key}' already exists.");
            }

            Role role = new(Guid.NewGuid(), input.Key, input.Name.Trim(), isSystem: false) { Description = input.Description };
            db.Roles.Add(role);
            for (int i = 0; i < input.Rules.Count; i++)
            {
                db.RoleRules.Add(new RoleRule(Guid.NewGuid(), role.Id, i, input.Rules[i].ToJsonString()));
            }

            await db.SaveChangesAsync(cancellationToken);
            return role.Id;
        }, requiresNew: true, cancellationToken);

        return (await List(cancellationToken)).Single(r => r.Id == id);
    }

    [HttpPost("{roleId:guid}/grants")]
    public async Task<RoleDto> Grant(Guid roleId, [FromBody] GrantInput input, CancellationToken cancellationToken)
    {
        if (!Enum.TryParse(input.PrincipalType, ignoreCase: true, out PrincipalType principalType))
        {
            throw new UserFriendlyException("principalType is Account or Group.");
        }

        await guardDb.RunAsync(async db =>
        {
            if (!await db.Roles.AnyAsync(r => r.Id == roleId, cancellationToken))
            {
                throw new EntityNotFoundException(typeof(Role), roleId);
            }

            bool principalExists = principalType == PrincipalType.Account
                ? await db.Accounts.AnyAsync(a => a.Id == input.PrincipalId, cancellationToken)
                : await db.Groups.AnyAsync(g => g.Id == input.PrincipalId, cancellationToken);
            if (!principalExists)
            {
                throw new UserFriendlyException($"No {principalType} with id {input.PrincipalId}.");
            }

            // The grant's scope must fill every ${grant.*} placeholder its role's rules use.
            JsonObject scope = input.Scope ?? [];
            List<RawRule> rules = (await db.RoleRules.Where(r => r.RoleId == roleId).ToListAsync(cancellationToken)).Select(r => RawRule.Parse(r.Json)).ToList();
            try
            {
                _ = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options)
                    .WithVariables(new { user = new { id = Guid.Empty, username = "", directoryId = Guid.Empty, groupIds = Array.Empty<Guid>() } })
                    .AddRange(rules, new { grant = scope })
                    .Build();
            }
            catch (CaslConfigurationException ex)
            {
                throw new UserFriendlyException($"This scope doesn't fit the role's rules: {ex.Message}");
            }

            db.RoleGrants.Add(new RoleGrant(Guid.NewGuid(), roleId, principalType, input.PrincipalId, scope.ToJsonString())
            {
                ValidUntil = input.ValidUntil,
                CreatedBy = CurrentAccountId,
            });
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

        return (await List(cancellationToken)).Single(r => r.Id == roleId);
    }

    [HttpDelete("{roleId:guid}/grants/{grantId:guid}")]
    public async Task<NoContentResult> Revoke(Guid roleId, Guid grantId, CancellationToken cancellationToken)
    {
        await guardDb.RunAsync(async db =>
        {
            RoleGrant grant = await db.RoleGrants.FirstOrDefaultAsync(g => g.Id == grantId && g.RoleId == roleId, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(RoleGrant), grantId);
            if (grant.RoleId == GuardRoles.AdministratorId && grant.PrincipalId == GuardConstants.AdminsGroupId)
            {
                throw new UserFriendlyException("The Administrator grant to toda-admins can't be revoked; manage admins through that group.");
            }

            db.RoleGrants.Remove(grant);
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

        return NoContent();
    }

    private static IReadOnlyList<string> Problems(JsonObject rule)
    {
        try
        {
            return AbilityBuilder.Validate(RawRule.Parse(rule.ToJsonString()), GuardSubjects.Registry);
        }
        catch (JsonException ex)
        {
            return [ex.Message];
        }
    }
}
