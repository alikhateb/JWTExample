using System.Text.Json.Serialization;

namespace Core.DTO.Register;

public class RegisterResult
{
    public string Message { get; set; }
    public string Token { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public bool IsAuthenticated { get; set; } = false;
    //public DateTime TokenExpiration { get; set; }
    public List<string> Roles { get; set; }

    [JsonIgnore]
    public string RefreshToken { get; set; }
    public DateTime RefershTokenExpiration { get; set; }
}
