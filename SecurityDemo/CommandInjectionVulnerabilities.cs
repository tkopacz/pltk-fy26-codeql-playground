using System.Diagnostics;

namespace SecurityDemo;

/// <summary>
/// This class demonstrates Command Injection vulnerabilities.
/// Command Injection occurs when user input is passed to system shell commands
/// without proper validation or sanitization, allowing attackers to execute arbitrary commands.
/// </summary>
public class CommandInjectionVulnerabilities
{
    /// <summary>
    /// VULNERABILITY: Direct command execution with user input
    /// An attacker could input: "file.txt & del important.txt" to execute additional commands.
    /// On Unix: "file.txt; rm -rf /" could be devastating.
    /// </summary>
    public string ExecuteCommand_Vulnerable(string filename)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var processInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c type {filename}",  // Direct concatenation of user input
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        using var process = Process.Start(processInfo);
        if (process == null) return string.Empty;
        
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output;
    }

    /// <summary>
    /// VULNERABILITY: Unix command with shell metacharacters
    /// User input containing shell metacharacters (;, |, &, $, etc.) can chain commands.
    /// </summary>
    public string PingHost_Vulnerable(string hostname)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var processInfo = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-c \"ping -c 4 {hostname}\"",  // Shell interprets metacharacters
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        using var process = Process.Start(processInfo);
        if (process == null) return string.Empty;
        
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output;
    }

    /// <summary>
    /// VULNERABILITY: PowerShell command injection
    /// PowerShell is powerful and dangerous when user input is not sanitized.
    /// Attacker input: "Get-Process; Remove-Item C:\Important -Recurse"
    /// </summary>
    public string ExecutePowerShell_Vulnerable(string scriptContent)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var processInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-Command \"{scriptContent}\"",
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        using var process = Process.Start(processInfo);
        if (process == null) return string.Empty;
        
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output;
    }

    /// <summary>
    /// VULNERABILITY: File operation with shell execution
    /// Using shell to execute file operations with user input.
    /// </summary>
    public void CompressFile_Vulnerable(string sourceFile, string destFile)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        string command = $"tar -czf {destFile} {sourceFile}";
        
        var processInfo = new ProcessStartInfo
        {
            FileName = "/bin/sh",
            Arguments = $"-c \"{command}\"",
            UseShellExecute = false
        };

        using var process = Process.Start(processInfo);
        process?.WaitForExit();
    }

    /// <summary>
    /// VULNERABILITY: String interpolation in shell commands
    /// Using C# interpolation doesn't protect against command injection.
    /// </summary>
    public List<string> ListDirectory_Vulnerable(string directory)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var results = new List<string>();
        var processInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c dir {directory}",
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        using var process = Process.Start(processInfo);
        if (process != null)
        {
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            results.AddRange(output.Split('\n'));
        }
        return results;
    }

    /// <summary>
    /// VULNERABILITY: Command with environment variable expansion
    /// Shell will expand environment variables, which can be exploited.
    /// </summary>
    public string ExecuteWithEnvVar_Vulnerable(string envVarName)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var processInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c echo %{envVarName}%",
            RedirectStandardOutput = true,
            UseShellExecute = false
        };

        using var process = Process.Start(processInfo);
        if (process == null) return string.Empty;
        
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output;
    }

    /// <summary>
    /// SAFE: Using Process without shell execution
    /// Avoid UseShellExecute=true and pass arguments as array/list.
    /// </summary>
    public string PingHost_Safe(string hostname)
    {
        // SAFE CODE - Validate input and avoid shell
        // Whitelist validation
        if (!System.Text.RegularExpressions.Regex.IsMatch(hostname, @"^[a-zA-Z0-9\-\.]+$"))
        {
            throw new ArgumentException("Invalid hostname format");
        }

        var processInfo = new ProcessStartInfo
        {
            FileName = "ping",
            Arguments = $"-c 4 {hostname}",  // No shell interpretation
            RedirectStandardOutput = true,
            UseShellExecute = false,  // Critical: Don't use shell
            CreateNoWindow = true
        };

        using var process = Process.Start(processInfo);
        if (process == null) return string.Empty;
        
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output;
    }

    /// <summary>
    /// SAFE: Input validation with whitelist
    /// Validate and sanitize all user inputs before using them.
    /// </summary>
    public string ExecuteCommand_Safe(string filename)
    {
        // SAFE CODE - Validate input against whitelist
        string safeFilename = System.IO.Path.GetFileName(filename);
        string basePath = "/safe/directory/";
        string fullPath = System.IO.Path.Combine(basePath, safeFilename);

        // Ensure path doesn't escape base directory
        if (!fullPath.StartsWith(basePath))
        {
            throw new ArgumentException("Invalid file path");
        }

        // Use .NET file APIs instead of shell commands
        if (System.IO.File.Exists(fullPath))
        {
            return System.IO.File.ReadAllText(fullPath);
        }
        return string.Empty;
    }
}
