namespace Infrastructure.Configurations;

public class JwtConfiguration
{
    public string Key { get; }
    public string Issuer { get; }
    public string Audience { get; }
    public int DurationInDays { get; }
}
