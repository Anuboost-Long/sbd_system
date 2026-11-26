/*
 * File: EnvLoader.cs
 * Implements: Guide §3.2 secrets are read from .env, never from code, appsettings or the submission ZIP.
 * Controls:   E9
 */
namespace SBD.API.SetUp;

public static class EnvLoader
{
    // [Guide §3.2] Read KEY=VALUE lines from the nearest .env file; a variable that is already set is never overridden.
    // Why: secrets stay outside the code and the ZIP (risk R7); real environment values win over the file.
    // An in-house reader avoids an extra dependency.
    // Standard: Guide §3.2 (risk R7).
    // Evidence: E9 (release_check.sh secrets check).
    public static void Load()
    {
        var path = FindEnvFile();
        if (path is null) return;

        foreach (var line in File.ReadLines(path))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;

            var separator = trimmed.IndexOf('=');
            if (separator <= 0) continue;

            var key = trimmed[..separator].Trim();
            if (Environment.GetEnvironmentVariable(key) is not null) continue;

            Environment.SetEnvironmentVariable(key, trimmed[(separator + 1)..].Trim());
        }
    }

    private static string? FindEnvFile()
    {
        for (var directory = new DirectoryInfo(Directory.GetCurrentDirectory()); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, ".env");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}
