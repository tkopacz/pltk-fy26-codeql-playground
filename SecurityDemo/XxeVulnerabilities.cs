using System.Xml;

namespace SecurityDemo;

/// <summary>
/// This class demonstrates XML External Entity (XXE) vulnerabilities.
/// XXE attacks exploit XML parsers that process external entity references,
/// potentially leading to file disclosure, SSRF, or DoS attacks.
/// </summary>
public class XxeVulnerabilities
{
    /// <summary>
    /// VULNERABILITY: XmlDocument with default settings
    /// Default XmlDocument settings allow DTD processing and external entities.
    /// Attacker XML: &lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;&lt;root&gt;&amp;xxe;&lt;/root&gt;
    /// </summary>
    public string ParseXml_Vulnerable(string xmlContent)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(xmlContent);  // Vulnerable to XXE
        
        return xmlDoc.InnerText;
    }

    /// <summary>
    /// VULNERABILITY: XmlTextReader with DTD processing enabled
    /// Explicitly enabling DTD processing makes it vulnerable to XXE.
    /// </summary>
    public List<string> ParseXmlFile_Vulnerable(string filePath)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var results = new List<string>();
        
        using var reader = new XmlTextReader(filePath);
        reader.DtdProcessing = DtdProcessing.Parse;  // Enables DTD processing - VULNERABLE
        
        while (reader.Read())
        {
            if (reader.NodeType == XmlNodeType.Text)
            {
                results.Add(reader.Value);
            }
        }
        
        return results;
    }

    /// <summary>
    /// VULNERABILITY: XmlReader with unsafe settings
    /// Creating XmlReader with settings that allow external entities.
    /// </summary>
    public string ReadXmlWithSettings_Vulnerable(string xmlContent)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,  // Allows DTD processing
            XmlResolver = new XmlUrlResolver()    // Allows external resources
        };
        
        using var stringReader = new StringReader(xmlContent);
        using var xmlReader = XmlReader.Create(stringReader, settings);
        
        var doc = new XmlDocument();
        doc.Load(xmlReader);
        
        return doc.InnerText;
    }

    /// <summary>
    /// VULNERABILITY: XPathDocument with external entities
    /// XPathDocument can also be vulnerable if not configured properly.
    /// </summary>
    public string ParseXPath_Vulnerable(string xmlContent)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var stringReader = new StringReader(xmlContent);
        using var xmlReader = new XmlTextReader(stringReader);
        // Not disabling DTD processing - vulnerable
        
        var xpathDoc = new System.Xml.XPath.XPathDocument(xmlReader);
        var navigator = xpathDoc.CreateNavigator();
        
        return navigator.InnerXml;
    }

    /// <summary>
    /// VULNERABILITY: Loading XML from untrusted source
    /// Loading XML from user-provided URLs without validation.
    /// </summary>
    public string LoadXmlFromUrl_Vulnerable(string url)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var xmlDoc = new XmlDocument();
        xmlDoc.Load(url);  // Loads from external URL - can trigger SSRF
        
        return xmlDoc.OuterXml;
    }

    /// <summary>
    /// VULNERABILITY: DataSet ReadXml with unsafe settings
    /// DataSet.ReadXml can also be exploited for XXE attacks.
    /// </summary>
    public System.Data.DataSet LoadDataSet_Vulnerable(string xmlContent)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var dataSet = new System.Data.DataSet();
        using var stringReader = new StringReader(xmlContent);
        dataSet.ReadXml(stringReader);  // Default settings may be vulnerable
        
        return dataSet;
    }

    /// <summary>
    /// VULNERABILITY: XmlSerializer with unsafe reader
    /// Using XmlSerializer with an unsafe XmlReader.
    /// </summary>
    public T DeserializeXml_Vulnerable<T>(string xmlContent) where T : class
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var serializer = new System.Xml.Serialization.XmlSerializer(typeof(T));
        
        using var stringReader = new StringReader(xmlContent);
        using var xmlReader = new XmlTextReader(stringReader);
        // DTD processing not disabled - vulnerable
        
        return (T)serializer.Deserialize(xmlReader)!;
    }

    /// <summary>
    /// VULNERABILITY: SOAP XML processing
    /// Processing SOAP messages without XXE protection.
    /// </summary>
    public string ProcessSoapMessage_Vulnerable(string soapXml)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var doc = new XmlDocument();
        doc.LoadXml(soapXml);
        
        var soapBody = doc.GetElementsByTagName("soap:Body")[0];
        return soapBody?.InnerText ?? string.Empty;
    }

    /// <summary>
    /// SAFE: XmlDocument with secure settings
    /// Disable DTD processing and external entity resolution.
    /// </summary>
    public string ParseXml_Safe(string xmlContent)
    {
        // SAFE CODE - Disable dangerous features
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,  // Prohibit DTD processing
            XmlResolver = null  // Disable external entity resolution
        };
        
        using var stringReader = new StringReader(xmlContent);
        using var xmlReader = XmlReader.Create(stringReader, settings);
        
        var xmlDoc = new XmlDocument();
        xmlDoc.Load(xmlReader);
        
        return xmlDoc.InnerText;
    }

    /// <summary>
    /// SAFE: XmlTextReader with secure configuration
    /// Explicitly disable DTD processing.
    /// </summary>
    public List<string> ParseXmlFile_Safe(string filePath)
    {
        // SAFE CODE - Secure XML parsing
        var results = new List<string>();
        
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 1024  // Limit entity expansion
        };
        
        using var xmlReader = XmlReader.Create(filePath, settings);
        
        while (xmlReader.Read())
        {
            if (xmlReader.NodeType == XmlNodeType.Text)
            {
                results.Add(xmlReader.Value);
            }
        }
        
        return results;
    }

    /// <summary>
    /// SAFE: Modern XML parsing with security best practices
    /// Use secure defaults and validate input.
    /// </summary>
    public string ReadXmlWithSettings_Safe(string xmlContent)
    {
        // SAFE CODE - Comprehensive security settings
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 10000000,  // Limit document size
            MaxCharactersFromEntities = 1024,    // Limit entity expansion
            IgnoreComments = true,
            IgnoreProcessingInstructions = true
        };
        
        using var stringReader = new StringReader(xmlContent);
        using var xmlReader = XmlReader.Create(stringReader, settings);
        
        var doc = new XmlDocument();
        doc.Load(xmlReader);
        
        return doc.InnerText;
    }

    /// <summary>
    /// SAFE: DataSet with secure XML reader
    /// Configure DataSet to use secure XML parsing.
    /// </summary>
    public System.Data.DataSet LoadDataSet_Safe(string xmlContent)
    {
        // SAFE CODE - Use secure XmlReader
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };
        
        var dataSet = new System.Data.DataSet();
        using var stringReader = new StringReader(xmlContent);
        using var xmlReader = XmlReader.Create(stringReader, settings);
        
        dataSet.ReadXml(xmlReader);
        
        return dataSet;
    }
}
