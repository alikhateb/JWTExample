using Microsoft.Extensions.DependencyInjection;

namespace Domain;

public static class DependencyInjection
{
    public static IServiceCollection RegisterDomain(this IServiceCollection services)
    {
        return services;
    }
}
