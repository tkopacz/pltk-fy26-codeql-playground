using System.Runtime.Serialization.Formatters.Binary;
using Newtonsoft.Json;
using System.Runtime.Serialization;

namespace SecurityDemo;

/// <summary>
/// This class demonstrates Insecure Deserialization vulnerabilities.
/// Insecure deserialization occurs when untrusted data is deserialized,
/// potentially allowing attackers to execute arbitrary code or manipulate application logic.
/// </summary>
public class InsecureDeserializationVulnerabilities
{
    /// <summary>
    /// VULNERABILITY: BinaryFormatter deserialization
    /// BinaryFormatter is inherently unsafe and should never be used with untrusted data.
    /// Attackers can craft malicious payloads that execute code during deserialization.
    /// </summary>
#pragma warning disable SYSLIB0011 // BinaryFormatter is obsolete
    public object DeserializeBinary_Vulnerable(byte[] data)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var formatter = new BinaryFormatter();
        using var memoryStream = new MemoryStream(data);
        return formatter.Deserialize(memoryStream);  // Extremely dangerous!
    }
#pragma warning restore SYSLIB0011

    /// <summary>
    /// VULNERABILITY: BinaryFormatter with custom data
    /// Even with seemingly safe objects, BinaryFormatter is exploitable.
    /// </summary>
#pragma warning disable SYSLIB0011
    public T DeserializeGeneric_Vulnerable<T>(byte[] serializedData)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var formatter = new BinaryFormatter();
        using var stream = new MemoryStream(serializedData);
        return (T)formatter.Deserialize(stream);
    }
#pragma warning restore SYSLIB0011

    /// <summary>
    /// VULNERABILITY: JSON.NET with TypeNameHandling
    /// Using TypeNameHandling.All or TypeNameHandling.Auto allows type information in JSON,
    /// which can be exploited to instantiate arbitrary types.
    /// </summary>
    public object DeserializeJson_Vulnerable(string json)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All  // Allows arbitrary type instantiation
        };
        
        return JsonConvert.DeserializeObject(json, settings)!;
    }

    /// <summary>
    /// VULNERABILITY: JSON with TypeNameHandling.Auto
    /// TypeNameHandling.Auto is also vulnerable as it processes $type properties.
    /// Malicious JSON: {"$type":"System.Windows.Data.ObjectDataProvider, ..."}
    /// </summary>
    public T DeserializeJsonTyped_Vulnerable<T>(string json)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.Auto  // Still vulnerable
        };
        
        return JsonConvert.DeserializeObject<T>(json, settings)!;
    }

    /// <summary>
    /// VULNERABILITY: DataContractSerializer without known types
    /// Using DataContractSerializer with untrusted data and without restricting types.
    /// </summary>
    public object DeserializeDataContract_Vulnerable(string xml, Type type)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var serializer = new DataContractSerializer(type);
        using var stringReader = new StringReader(xml);
        using var xmlReader = System.Xml.XmlReader.Create(stringReader);
        
        return serializer.ReadObject(xmlReader)!;
    }

    /// <summary>
    /// VULNERABILITY: XmlSerializer with unsafe settings
    /// XmlSerializer can be exploited if additional type resolution is allowed.
    /// Note: NetDataContractSerializer was also vulnerable but is deprecated in .NET 8.
    /// </summary>
    public object DeserializeXmlUnsafe_Vulnerable(string xml, Type type)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var serializer = new System.Xml.Serialization.XmlSerializer(type);
        using var stringReader = new StringReader(xml);
        // Without proper type validation, this can be exploited
        return serializer.Deserialize(stringReader)!;
    }

    /// <summary>
    /// VULNERABILITY: Loading assemblies from untrusted sources
    /// Loading and executing code from user-controlled paths.
    /// </summary>
    public object LoadAndDeserialize_Vulnerable(string assemblyPath, byte[] data)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var assembly = System.Reflection.Assembly.LoadFrom(assemblyPath);
        var type = assembly.GetType("MaliciousType");
        
        if (type == null) return null!;
        
        var serializer = new DataContractSerializer(type);
        using var stream = new MemoryStream(data);
        return serializer.ReadObject(stream)!;
    }

    /// <summary>
    /// VULNERABILITY: ViewState deserialization (ASP.NET)
    /// In ASP.NET, vulnerable ViewState deserialization can lead to RCE.
    /// This simulates the pattern.
    /// </summary>
    public object DeserializeViewState_Vulnerable(string base64ViewState)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        byte[] data = Convert.FromBase64String(base64ViewState);
        
#pragma warning disable SYSLIB0011
        var formatter = new BinaryFormatter();
        using var stream = new MemoryStream(data);
        return formatter.Deserialize(stream);
#pragma warning restore SYSLIB0011
    }

    /// <summary>
    /// VULNERABILITY: Deserializing session data
    /// Session data from cookies or storage without validation.
    /// </summary>
    public UserSession DeserializeSession_Vulnerable(string sessionData)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.Objects
        };
        
        return JsonConvert.DeserializeObject<UserSession>(sessionData, settings)!;
    }

    /// <summary>
    /// SAFE: Use specific types without TypeNameHandling
    /// Never use TypeNameHandling with untrusted data.
    /// </summary>
    public T DeserializeJson_Safe<T>(string json) where T : class
    {
        // SAFE CODE - No type handling, explicit type
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None,  // Disable type handling
            MaxDepth = 32  // Limit depth to prevent DoS
        };
        
        return JsonConvert.DeserializeObject<T>(json, settings)!;
    }

    /// <summary>
    /// SAFE: Use DataContractSerializer with known types
    /// Explicitly specify allowed types.
    /// </summary>
    public T DeserializeDataContract_Safe<T>(string xml) where T : class
    {
        // SAFE CODE - Use known types only
        var knownTypes = new Type[] { typeof(T) };
        var serializer = new DataContractSerializer(typeof(T), knownTypes);
        
        var settings = new System.Xml.XmlReaderSettings
        {
            DtdProcessing = System.Xml.DtdProcessing.Prohibit,
            XmlResolver = null
        };
        
        using var stringReader = new StringReader(xml);
        using var xmlReader = System.Xml.XmlReader.Create(stringReader, settings);
        
        return (T)serializer.ReadObject(xmlReader)!;
    }

    /// <summary>
    /// SAFE: Use System.Text.Json (modern, secure by default)
    /// System.Text.Json doesn't support TypeNameHandling and is secure by default.
    /// </summary>
    public T DeserializeSystemTextJson_Safe<T>(string json) where T : class
    {
        // SAFE CODE - Use System.Text.Json
        var options = new System.Text.Json.JsonSerializerOptions
        {
            MaxDepth = 32,
            PropertyNameCaseInsensitive = true
        };
        
        return System.Text.Json.JsonSerializer.Deserialize<T>(json, options)!;
    }

    /// <summary>
    /// SAFE: Validate data before deserialization
    /// Add integrity checks like HMAC signatures.
    /// </summary>
    public T DeserializeWithValidation_Safe<T>(string json, string signature, byte[] key) where T : class
    {
        // SAFE CODE - Verify signature before deserializing
        using var hmac = new System.Security.Cryptography.HMACSHA256(key);
        byte[] computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(json));
        byte[] providedHash = Convert.FromBase64String(signature);
        
        if (!computedHash.SequenceEqual(providedHash))
        {
            throw new System.Security.SecurityException("Invalid signature");
        }
        
        return System.Text.Json.JsonSerializer.Deserialize<T>(json)!;
    }
}

/// <summary>
/// Sample class for deserialization examples
/// </summary>
[Serializable]
public class UserSession
{
    public string? Username { get; set; }
    public DateTime LoginTime { get; set; }
    public string? Token { get; set; }
}
