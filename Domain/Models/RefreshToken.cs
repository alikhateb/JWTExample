namespace Domain.Models;

public class RefreshToken
{
    public string Token { get; set; }
    public DateTime ExpiresOn { get; set; }
    public bool IsExpired => DateTime.UtcNow >= ExpiresOn;
    public DateTime CreatedOn { get; set; }
    public DateTime? RevokeOn { get; set; }
    public bool IsActive => RevokeOn is null && !IsExpired;
}
