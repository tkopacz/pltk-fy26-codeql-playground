using System.Data.SqlClient;

namespace SecurityDemo;

/// <summary>
/// This class demonstrates various SQL Injection vulnerabilities.
/// SQL Injection occurs when user input is directly concatenated into SQL queries
/// without proper sanitization or parameterization.
/// </summary>
public class SqlInjectionVulnerabilities
{
    private readonly string _connectionString;

    public SqlInjectionVulnerabilities(string connectionString)
    {
        _connectionString = connectionString;
    }

    /// <summary>
    /// VULNERABILITY: Direct string concatenation in SQL query
    /// User input is directly concatenated into the SQL query string.
    /// An attacker could input: "admin' OR '1'='1" to bypass authentication.
    /// </summary>
    public bool AuthenticateUser_Vulnerable(string username, string password)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var connection = new SqlConnection(_connectionString);
        string query = "SELECT * FROM Users WHERE Username = '" + username + 
                      "' AND Password = '" + password + "'";
        
        using var command = new SqlCommand(query, connection);
        connection.Open();
        using var reader = command.ExecuteReader();
        return reader.HasRows;
    }

    /// <summary>
    /// VULNERABILITY: String interpolation in SQL query
    /// Using C# string interpolation is just as vulnerable as concatenation.
    /// Input like "'; DROP TABLE Users; --" could delete entire tables.
    /// </summary>
    public List<string> SearchUsers_Vulnerable(string searchTerm)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var results = new List<string>();
        using var connection = new SqlConnection(_connectionString);
        string query = $"SELECT Username FROM Users WHERE Username LIKE '%{searchTerm}%'";
        
        using var command = new SqlCommand(query, connection);
        connection.Open();
        using var reader = command.ExecuteReader();
        
        while (reader.Read())
        {
            results.Add(reader.GetString(0));
        }
        return results;
    }

    /// <summary>
    /// VULNERABILITY: String.Format in SQL query
    /// Using String.Format is also vulnerable to SQL injection.
    /// </summary>
    public int DeleteUser_Vulnerable(string userId)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var connection = new SqlConnection(_connectionString);
        string query = string.Format("DELETE FROM Users WHERE UserId = {0}", userId);
        
        using var command = new SqlCommand(query, connection);
        connection.Open();
        return command.ExecuteNonQuery();
    }

    /// <summary>
    /// VULNERABILITY: Dynamic ORDER BY clause
    /// Allowing user input in ORDER BY without validation.
    /// </summary>
    public List<string> GetUsersSorted_Vulnerable(string sortColumn)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        var results = new List<string>();
        using var connection = new SqlConnection(_connectionString);
        string query = "SELECT Username FROM Users ORDER BY " + sortColumn;
        
        using var command = new SqlCommand(query, connection);
        connection.Open();
        using var reader = command.ExecuteReader();
        
        while (reader.Read())
        {
            results.Add(reader.GetString(0));
        }
        return results;
    }

    /// <summary>
    /// VULNERABILITY: Stored procedure with dynamic SQL inside
    /// Even using stored procedures can be vulnerable if they build dynamic SQL.
    /// </summary>
    public void ExecuteDynamicStoredProc_Vulnerable(string tableName, string condition)
    {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        using var connection = new SqlConnection(_connectionString);
        // This stored procedure internally builds dynamic SQL - still vulnerable
        string query = "EXEC sp_executesql N'SELECT * FROM " + tableName + 
                      " WHERE " + condition + "'";
        
        using var command = new SqlCommand(query, connection);
        connection.Open();
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// SAFE: Using parameterized queries
    /// This is the correct way to prevent SQL injection.
    /// </summary>
    public bool AuthenticateUser_Safe(string username, string password)
    {
        // SAFE CODE - Use parameterized queries
        using var connection = new SqlConnection(_connectionString);
        string query = "SELECT * FROM Users WHERE Username = @Username AND Password = @Password";
        
        using var command = new SqlCommand(query, connection);
        command.Parameters.AddWithValue("@Username", username);
        command.Parameters.AddWithValue("@Password", password);
        
        connection.Open();
        using var reader = command.ExecuteReader();
        return reader.HasRows;
    }

    /// <summary>
    /// SAFE: Using stored procedures with parameters
    /// Properly parameterized stored procedures are safe.
    /// </summary>
    public List<string> SearchUsers_Safe(string searchTerm)
    {
        // SAFE CODE - Use parameterized stored procedure
        var results = new List<string>();
        using var connection = new SqlConnection(_connectionString);
        
        using var command = new SqlCommand("sp_SearchUsers", connection);
        command.CommandType = System.Data.CommandType.StoredProcedure;
        command.Parameters.AddWithValue("@SearchTerm", searchTerm);
        
        connection.Open();
        using var reader = command.ExecuteReader();
        
        while (reader.Read())
        {
            results.Add(reader.GetString(0));
        }
        return results;
    }
}
