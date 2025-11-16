namespace SecurityDemo;

/// <summary>
/// This class demonstrates Path Traversal (Directory Traversal) vulnerabilities.
/// Path Traversal occurs when user input is used to construct file paths without
/// proper validation, allowing attackers to access files outside intended directories.
/// </summary>
public class PathTraversalVulnerabilities
{
    private readonly string _baseDirectory;

    public PathTraversalVulnerabilities(string baseDirectory)
    {
        _baseDirectory = baseDirectory;
    }

    /// <summary>
    /// VULNERABILITY: Direct path concatenation
    /// An attacker could input: "../../etc/passwd" to access system files.
    /// On Windows: "..\..\..\Windows\System32\config\SAM" could expose sensitive data.
    /// </summary>
    public string ReadFile_Vulnerable(string filename)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        string filePath = _baseDirectory + "/" + filename;  // No validation
        
        if (File.Exists(filePath))
        {
            return File.ReadAllText(filePath);
        }
        return string.Empty;
    }

    /// <summary>
    /// VULNERABILITY: Path.Combine without validation
    /// Even using Path.Combine doesn't prevent traversal if not validated.
    /// Input like "..\..\..\sensitive.txt" can escape the base directory.
    /// </summary>
    public byte[] DownloadFile_Vulnerable(string relativePath)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        string fullPath = Path.Combine(_baseDirectory, relativePath);
        
        if (File.Exists(fullPath))
        {
            return File.ReadAllBytes(fullPath);
        }
        return Array.Empty<byte>();
        //DODANY KOMENTARZ1
    }

    /// <summary>
    /// VULNERABILITY: File upload without validation
    /// Accepting user-provided paths for saving uploaded files.
    /// Attacker could overwrite system files or plant malicious files.
    /// </summary>
    public void SaveUploadedFile_Vulnerable(string userFilename, byte[] content)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        string uploadPath = Path.Combine(_baseDirectory, userFilename);
        File.WriteAllBytes(uploadPath, content);
    }

    /// <summary>
    /// VULNERABILITY: Directory listing without restriction
    /// Allows listing of any directory on the system if traversal is not blocked.
    /// </summary>
    public string[] ListDirectory_Vulnerable(string subdirectory)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        string dirPath = Path.Combine(_baseDirectory, subdirectory);
        
        if (Directory.Exists(dirPath))
        {
            return Directory.GetFiles(dirPath);
        }
        return Array.Empty<string>();
    }

    /// <summary>
    /// VULNERABILITY: Delete file with user input
    /// Allows deletion of any file if path traversal is not prevented.
    /// </summary>
    public void DeleteFile_Vulnerable(string filename)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        string filePath = _baseDirectory + Path.DirectorySeparatorChar + filename;
        
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
        }
    }

    /// <summary>
    /// VULNERABILITY: Archive extraction without validation
    /// Extracting archives (ZIP, TAR) without validating entry paths.
    /// "Zip Slip" vulnerability can overwrite arbitrary files.
    /// </summary>
    public void ExtractArchive_Vulnerable(string archivePath, string destinationDir)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        // Simulating zip extraction without path validation
        // In real scenario, use System.IO.Compression.ZipFile
        
        string[] entries = { "../../etc/passwd", "../../../Windows/System32/evil.dll" };
        foreach (string entry in entries)
        {
            string targetPath = Path.Combine(destinationDir, entry);
            // No validation - can write anywhere
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            File.WriteAllText(targetPath, "malicious content");
        }
    }

    /// <summary>
    /// VULNERABILITY: Using user input as directory name
    /// Creating or accessing directories based on user input.
    /// </summary>
    public void CreateUserDirectory_Vulnerable(string username)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        string userDir = Path.Combine(_baseDirectory, username);
        Directory.CreateDirectory(userDir);
    }

    /// <summary>
    /// VULNERABILITY: File copy without path validation
    /// Copying files to user-specified destinations.
    /// </summary>
    public void CopyFile_Vulnerable(string sourceFile, string destFile)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        string sourcePath = Path.Combine(_baseDirectory, sourceFile);
        string destPath = Path.Combine(_baseDirectory, destFile);
        
        if (File.Exists(sourcePath))
        {
            File.Copy(sourcePath, destPath, true);
        }
    }

    /// <summary>
    /// SAFE: Proper path validation and canonicalization
    /// Validates that the resolved path is within the base directory.
    /// </summary>
    public string ReadFile_Safe(string filename)
    {
        // SAFE CODE - Validate and canonicalize paths
        // Remove any path traversal sequences
        string safeFilename = Path.GetFileName(filename);
        
        // Combine with base directory
        string fullPath = Path.Combine(_baseDirectory, safeFilename);
        
        // Get the full canonical path
        string canonicalPath = Path.GetFullPath(fullPath);
        string canonicalBase = Path.GetFullPath(_baseDirectory);
        
        // Ensure the resolved path is within base directory
        if (!canonicalPath.StartsWith(canonicalBase, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("Access denied: path traversal detected");
        }
        
        if (File.Exists(canonicalPath))
        {
            return File.ReadAllText(canonicalPath);
        }
        return string.Empty;
    }

    /// <summary>
    /// SAFE: Whitelist approach for file access
    /// Only allow access to explicitly permitted files.
    /// </summary>
    public byte[] DownloadFile_Safe(string relativePath)
    {
        // SAFE CODE - Whitelist validation
        string[] allowedFiles = { "report.pdf", "document.txt", "image.jpg" };
        
        if (!allowedFiles.Contains(relativePath))
        {
            throw new UnauthorizedAccessException("File not permitted");
        }
        
        string fullPath = Path.Combine(_baseDirectory, relativePath);
        string canonicalPath = Path.GetFullPath(fullPath);
        string canonicalBase = Path.GetFullPath(_baseDirectory);
        
        if (!canonicalPath.StartsWith(canonicalBase, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("Access denied");
        }
        
        if (File.Exists(canonicalPath))
        {
            return File.ReadAllBytes(canonicalPath);
        }
        return Array.Empty<byte>();
    }

    /// <summary>
    /// SAFE: Generate safe filenames for uploads
    /// Don't trust user-provided filenames.
    /// </summary>
    public void SaveUploadedFile_Safe(string userFilename, byte[] content)
    {
        // SAFE CODE - Generate safe filename
        string extension = Path.GetExtension(userFilename);
        
        // Validate extension against whitelist
        string[] allowedExtensions = { ".jpg", ".png", ".pdf", ".txt" };
        if (!allowedExtensions.Contains(extension.ToLowerInvariant()))
        {
            throw new ArgumentException("File type not allowed");
        }
        
        // Generate random filename
        string safeFilename = Guid.NewGuid().ToString() + extension;
        string uploadPath = Path.Combine(_baseDirectory, safeFilename);
        
        // Additional validation
        string canonicalPath = Path.GetFullPath(uploadPath);
        string canonicalBase = Path.GetFullPath(_baseDirectory);
        
        if (!canonicalPath.StartsWith(canonicalBase, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("Access denied");
        }
        
        File.WriteAllBytes(canonicalPath, content);
    }
}
