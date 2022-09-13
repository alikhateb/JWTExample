using Microsoft.Extensions.DependencyInjection;

namespace Core;

public static class DependencyInjection
{
    public static IServiceCollection RegisterCore(this IServiceCollection services)
    {
        return services;
    }
}
