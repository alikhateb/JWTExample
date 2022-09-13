using Microsoft.AspNetCore.Identity;

namespace Domain.Models;

public class ApplicationUser : IdentityUser
{
    public ApplicationUser()
    {
        RefreshTokens = new HashSet<RefreshToken>();
    }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public virtual ICollection<RefreshToken> RefreshTokens { get; set; }
}
