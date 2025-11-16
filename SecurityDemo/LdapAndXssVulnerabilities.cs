using System.DirectoryServices;
using System.Text;

namespace SecurityDemo;

/// <summary>
/// This class demonstrates LDAP Injection and XSS vulnerabilities.
/// LDAP Injection allows attackers to manipulate LDAP queries.
/// XSS allows attackers to inject malicious scripts into web pages.
/// </summary>
public class LdapAndXssVulnerabilities
{
    private readonly string _ldapServer;

    public LdapAndXssVulnerabilities(string ldapServer)
    {
        _ldapServer = ldapServer;
    }

    // ==================== LDAP INJECTION VULNERABILITIES ====================

    /// <summary>
    /// VULNERABILITY: LDAP query with string concatenation
    /// User input is directly concatenated into LDAP filter.
    /// Attacker input: "*)(uid=*))(|(uid=*" bypasses authentication.
    /// </summary>
    public List<string> SearchUsers_Vulnerable(string username)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var results = new List<string>();
        
        // Constructing LDAP filter with user input - VULNERABLE
        string filter = $"(&(objectClass=user)(uid={username}))";
        
        using var entry = new DirectoryEntry(_ldapServer);
        using var searcher = new DirectorySearcher(entry, filter);
        
        var searchResults = searcher.FindAll();
        foreach (SearchResult result in searchResults)
        {
            if (result.Properties["cn"].Count > 0)
            {
                results.Add(result.Properties["cn"][0]?.ToString() ?? "");
            }
        }
        
        return results;
    }

    /// <summary>
    /// VULNERABILITY: LDAP authentication bypass
    /// Allowing user input in LDAP DN construction.
    /// Attacker: username="admin*" can match multiple users.
    /// </summary>
    public bool AuthenticateLDAP_Vulnerable(string username, string password)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        string filter = $"(&(objectClass=person)(uid={username})(userPassword={password}))";
        
        using var entry = new DirectoryEntry(_ldapServer);
        using var searcher = new DirectorySearcher(entry, filter);
        
        var result = searcher.FindOne();
        return result != null;
    }

    /// <summary>
    /// VULNERABILITY: Complex LDAP filter with multiple user inputs
    /// Multiple injection points increase attack surface.
    /// </summary>
    public List<string> SearchUsersAdvanced_Vulnerable(string firstName, string lastName, string department)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var results = new List<string>();
        
        string filter = $"(&(objectClass=user)(givenName={firstName})(sn={lastName})(department={department}))";
        
        using var entry = new DirectoryEntry(_ldapServer);
        using var searcher = new DirectorySearcher(entry, filter);
        
        var searchResults = searcher.FindAll();
        foreach (SearchResult result in searchResults)
        {
            if (result.Properties["cn"].Count > 0)
            {
                results.Add(result.Properties["cn"][0]?.ToString() ?? "");
            }
        }
        
        return results;
    }

    /// <summary>
    /// VULNERABILITY: LDAP query with OR condition
    /// Easier to exploit with OR conditions.
    /// Input: "*)(|(objectClass=*" can list all objects.
    /// </summary>
    public List<string> FindUserByEmailOrPhone_Vulnerable(string emailOrPhone)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var results = new List<string>();
        
        string filter = $"(|(mail={emailOrPhone})(telephoneNumber={emailOrPhone}))";
        
        using var entry = new DirectoryEntry(_ldapServer);
        using var searcher = new DirectorySearcher(entry, filter);
        
        var searchResults = searcher.FindAll();
        foreach (SearchResult result in searchResults)
        {
            if (result.Properties["cn"].Count > 0)
            {
                results.Add(result.Properties["cn"][0]?.ToString() ?? "");
            }
        }
        
        return results;
    }

    /// <summary>
    /// SAFE: LDAP query with input sanitization
    /// Escape special LDAP characters in user input.
    /// </summary>
    public List<string> SearchUsers_Safe(string username)
    {
        // SAFE CODE - Escape LDAP special characters
        string sanitizedUsername = EscapeLdapString(username);
        string filter = $"(&(objectClass=user)(uid={sanitizedUsername}))";
        
        var results = new List<string>();
        using var entry = new DirectoryEntry(_ldapServer);
        using var searcher = new DirectorySearcher(entry, filter);
        
        var searchResults = searcher.FindAll();
        foreach (SearchResult result in searchResults)
        {
            if (result.Properties["cn"].Count > 0)
            {
                results.Add(result.Properties["cn"][0]?.ToString() ?? "");
            }
        }
        
        return results;
    }

    /// <summary>
    /// Helper method to escape LDAP special characters
    /// </summary>
    private static string EscapeLdapString(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        var sb = new StringBuilder();
        foreach (char c in input)
        {
            switch (c)
            {
                case '\\':
                    sb.Append("\\5c");
                    break;
                case '*':
                    sb.Append("\\2a");
                    break;
                case '(':
                    sb.Append("\\28");
                    break;
                case ')':
                    sb.Append("\\29");
                    break;
                case '\0':
                    sb.Append("\\00");
                    break;
                case '/':
                    sb.Append("\\2f");
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    // ==================== CROSS-SITE SCRIPTING (XSS) VULNERABILITIES ====================

    /// <summary>
    /// VULNERABILITY: Reflected XSS - Direct output of user input
    /// User input is directly embedded in HTML without encoding.
    /// Attack: <script>alert('XSS')</script>
    /// </summary>
    public string GenerateWelcomePage_Vulnerable(string username)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        return $"<html><body><h1>Welcome {username}!</h1></body></html>";
    }

    /// <summary>
    /// VULNERABILITY: Stored XSS - Displaying stored user content
    /// User comments stored in database are displayed without encoding.
    /// </summary>
    public string DisplayUserComment_Vulnerable(string comment, string author)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        return $@"
            <div class='comment'>
                <div class='author'>Posted by: {author}</div>
                <div class='content'>{comment}</div>
            </div>";
    }

    /// <summary>
    /// VULNERABILITY: XSS in HTML attributes
    /// User input in HTML attributes without proper encoding.
    /// Attack: " onload="alert('XSS')
    /// </summary>
    public string GenerateImageTag_Vulnerable(string imageUrl, string altText)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        return $"<img src='{imageUrl}' alt='{altText}' />";
    }

    /// <summary>
    /// VULNERABILITY: XSS in JavaScript context
    /// User input embedded directly in JavaScript code.
    /// Attack: ';alert('XSS');//
    /// </summary>
    public string GenerateJavaScript_Vulnerable(string userName)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        return $@"
            <script>
                var userName = '{userName}';
                console.log('User: ' + userName);
            </script>";
    }

    /// <summary>
    /// VULNERABILITY: XSS via innerHTML or similar DOM methods
    /// Setting innerHTML with unescaped user content.
    /// </summary>
    public string GenerateDynamicContent_Vulnerable(string userContent)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        return $@"
            <script>
                document.getElementById('content').innerHTML = '{userContent}';
            </script>";
    }

    /// <summary>
    /// VULNERABILITY: XSS in URL parameters
    /// User input in href attributes or redirects.
    /// Attack: javascript:alert('XSS')
    /// </summary>
    public string GenerateLink_Vulnerable(string url, string linkText)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        return $"<a href='{url}'>{linkText}</a>";
    }

    /// <summary>
    /// VULNERABILITY: XSS in CSS context
    /// User input in style attributes or tags.
    /// Attack: expression(alert('XSS')) [IE] or url('javascript:alert()')
    /// </summary>
    public string GenerateStyledDiv_Vulnerable(string backgroundColor)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        return $"<div style='background-color: {backgroundColor};'>Content</div>";
    }

    /// <summary>
    /// SAFE: HTML encoding to prevent XSS
    /// Encode all user input before displaying in HTML.
    /// </summary>
    public string GenerateWelcomePage_Safe(string username)
    {
        // SAFE CODE - HTML encode user input
        string encodedUsername = System.Net.WebUtility.HtmlEncode(username);
        return $"<html><body><h1>Welcome {encodedUsername}!</h1></body></html>";
    }

    /// <summary>
    /// SAFE: Displaying user content with proper encoding
    /// Use HTML encoding for content and attributes.
    /// </summary>
    public string DisplayUserComment_Safe(string comment, string author)
    {
        // SAFE CODE - Encode all user inputs
        string encodedComment = System.Net.WebUtility.HtmlEncode(comment);
        string encodedAuthor = System.Net.WebUtility.HtmlEncode(author);
        
        return $@"
            <div class='comment'>
                <div class='author'>Posted by: {encodedAuthor}</div>
                <div class='content'>{encodedComment}</div>
            </div>";
    }

    /// <summary>
    /// SAFE: JavaScript context with JSON encoding
    /// Use proper JSON encoding for JavaScript contexts.
    /// </summary>
    public string GenerateJavaScript_Safe(string userName)
    {
        // SAFE CODE - Use JSON encoding
        string jsonEncoded = System.Text.Json.JsonSerializer.Serialize(userName);
        
        return $@"
            <script>
                var userName = {jsonEncoded};
                console.log('User: ' + userName);
            </script>";
    }

    /// <summary>
    /// SAFE: URL validation and encoding
    /// Validate URLs against whitelist and encode properly.
    /// </summary>
    public string GenerateLink_Safe(string url, string linkText)
    {
        // SAFE CODE - Validate and encode
        // Whitelist allowed URL schemes
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Invalid URL scheme");
        }
        
        string encodedUrl = System.Net.WebUtility.HtmlEncode(url);
        string encodedText = System.Net.WebUtility.HtmlEncode(linkText);
        
        return $"<a href='{encodedUrl}'>{encodedText}</a>";
    }
}
