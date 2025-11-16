namespace SecurityDemo;

/// <summary>
/// C# Security Vulnerabilities Demo for CodeQL Analysis
/// 
/// This application demonstrates various security vulnerabilities in C# code
/// that can be detected using CodeQL queries. Each vulnerability class contains
/// both vulnerable and safe implementations for educational purposes.
/// 
/// IMPORTANT: This code contains intentional security vulnerabilities.
/// DO NOT use any of the vulnerable code patterns in production applications.
/// </summary>
class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=======================================================");
        Console.WriteLine("C# Security Vulnerabilities Demo for CodeQL");
        Console.WriteLine("=======================================================");
        Console.WriteLine();
        Console.WriteLine("This application demonstrates common security vulnerabilities:");
        Console.WriteLine("1. SQL Injection");
        Console.WriteLine("2. Command Injection");
        Console.WriteLine("3. Path Traversal");
        Console.WriteLine("4. XML External Entity (XXE)");
        Console.WriteLine("5. Insecure Deserialization");
        Console.WriteLine("6. Hardcoded Credentials");
        Console.WriteLine("7. Weak Cryptography");
        Console.WriteLine("8. LDAP Injection");
        Console.WriteLine("9. Cross-Site Scripting (XSS)");
        Console.WriteLine("10. Insecure Random Number Generation");
        Console.WriteLine();
        Console.WriteLine("WARNING: This code is for educational purposes only!");
        Console.WriteLine("Do NOT use these patterns in production code.");
        Console.WriteLine("=======================================================");
        Console.WriteLine();
        
        // Demonstrate various vulnerability categories
        DemoSqlInjection();
        DemoCommandInjection();
        DemoPathTraversal();
        DemoXxe();
        DemoInsecureDeserialization();
        DemoCryptographic();
        DemoLdapAndXss();
        
        Console.WriteLine();
        Console.WriteLine("Demo completed. Review the source code and CodeQL queries.");
        Console.WriteLine("Use CodeQL to scan this codebase and detect these vulnerabilities.");
    }

    static void DemoSqlInjection()
    {
        Console.WriteLine("[SQL INJECTION DEMO]");
        Console.WriteLine("See SqlInjectionVulnerabilities.cs for examples");
        Console.WriteLine("- Direct string concatenation in queries");
        Console.WriteLine("- String interpolation vulnerabilities");
        Console.WriteLine("- Dynamic ORDER BY clauses");
        Console.WriteLine("Safe alternative: Use parameterized queries");
        Console.WriteLine();
    }

    static void DemoCommandInjection()
    {
        Console.WriteLine("[COMMAND INJECTION DEMO]");
        Console.WriteLine("See CommandInjectionVulnerabilities.cs for examples");
        Console.WriteLine("- Shell command execution with user input");
        Console.WriteLine("- PowerShell command injection");
        Console.WriteLine("- File operations via shell");
        Console.WriteLine("Safe alternative: Avoid shell, validate input, use .NET APIs");
        Console.WriteLine();
    }

    static void DemoPathTraversal()
    {
        Console.WriteLine("[PATH TRAVERSAL DEMO]");
        Console.WriteLine("See PathTraversalVulnerabilities.cs for examples");
        Console.WriteLine("- Direct path concatenation");
        Console.WriteLine("- File upload without validation");
        Console.WriteLine("- Archive extraction (Zip Slip)");
        Console.WriteLine("Safe alternative: Validate and canonicalize paths");
        Console.WriteLine();
    }

    static void DemoXxe()
    {
        Console.WriteLine("[XXE VULNERABILITY DEMO]");
        Console.WriteLine("See XxeVulnerabilities.cs for examples");
        Console.WriteLine("- XmlDocument with DTD processing");
        Console.WriteLine("- XmlTextReader without secure settings");
        Console.WriteLine("- External entity resolution");
        Console.WriteLine("Safe alternative: Disable DTD processing and external entities");
        Console.WriteLine();
    }

    static void DemoInsecureDeserialization()
    {
        Console.WriteLine("[INSECURE DESERIALIZATION DEMO]");
        Console.WriteLine("See InsecureDeserializationVulnerabilities.cs for examples");
        Console.WriteLine("- BinaryFormatter deserialization");
        Console.WriteLine("- JSON.NET with TypeNameHandling");
        Console.WriteLine("- NetDataContractSerializer");
        Console.WriteLine("Safe alternative: Use System.Text.Json, disable type handling");
        Console.WriteLine();
    }

    static void DemoCryptographic()
    {
        Console.WriteLine("[CRYPTOGRAPHIC VULNERABILITIES DEMO]");
        Console.WriteLine("See CryptographicVulnerabilities.cs for examples");
        Console.WriteLine("- Hardcoded passwords and API keys");
        Console.WriteLine("- Weak encryption (DES, 3DES, ECB mode)");
        Console.WriteLine("- Weak hashing (MD5, SHA1)");
        Console.WriteLine("- Insecure random number generation");
        Console.WriteLine("Safe alternative: Use secure algorithms, store secrets properly");
        Console.WriteLine();
    }

    static void DemoLdapAndXss()
    {
        Console.WriteLine("[LDAP INJECTION & XSS DEMO]");
        Console.WriteLine("See LdapAndXssVulnerabilities.cs for examples");
        Console.WriteLine("- LDAP query with string concatenation");
        Console.WriteLine("- Reflected and stored XSS");
        Console.WriteLine("- XSS in various contexts (HTML, JS, attributes)");
        Console.WriteLine("Safe alternative: Escape LDAP chars, HTML encode output");
        Console.WriteLine();
    }
}
