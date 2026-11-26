/*
 * File: AdminRequestValidator.cs
 * Implements: Guide §4.4 the manager approval reference and the single role are checked before any admin change.
 * Controls:   R6
 */
using System.Text.RegularExpressions;
using SBD.API.Common;

namespace SBD.API.Services.Admin.Functions;

public static partial class AdminRequestValidator
{
    private const int MaxApprovalRefLength = 50;

    private static readonly string[] Roles = [RoleNames.Normal, RoleNames.Accounting, RoleNames.Privileged, RoleNames.UserAdmin];

    [GeneratedRegex(@"^[A-Za-z0-9\-_/.]{1,50}$")]
    private static partial Regex ApprovalRefPattern();

    // [Guide §4.4] The approval reference is required (1-50 letters, digits, - _ / .) for create and role change.
    // Why: no role is assigned without a recorded manager approval. The database CHECK is the second barrier.
    // Standard: ISO/IEC 27001:2022; OWASP ASVS 5.0 V2.
    // Evidence: test RoleChange_NeedsApprovalRef (R6).
    public static string? ApprovalRef(string? raw, bool required, Dictionary<string, string[]> errors)
    {
        var value = raw?.Trim();
        if (string.IsNullOrEmpty(value))
        {
            if (required) errors["approvalRef"] = ["Enter the manager's approval reference."];
            return null;
        }

        if (value.Length > MaxApprovalRefLength || !ApprovalRefPattern().IsMatch(value))
        {
            errors["approvalRef"] = ["Use 1 to 50 letters, digits, '-', '_', '/' or '.'."];
            return null;
        }
        return value;
    }

    // [Guide §4.1, §4.2] The role must be one of the four known roles, one per user.
    // Why: unknown roles are rejected, never given a default.
    // Standard: OWASP ASVS 5.0 V8.2.1.
    // Evidence: test CreateUser_UnknownRole_Rejected (R6).
    public static string? Role(string? raw, Dictionary<string, string[]> errors)
    {
        var role = Roles.FirstOrDefault(r => r == raw?.Trim());
        if (role is null) errors["role"] = ["Choose Normal, Accounting, Privileged or UserAdmin."];
        return role;
    }
}
