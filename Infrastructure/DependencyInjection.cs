using Core.Services;
using Domain.Models;
using FluentValidation;
using Infrastructure.Configurations;
using Infrastructure.Data;
using Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection RegisterInfrastracture(this IServiceCollection services)
    {
        services.RegisterDbContext();

        services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>();

        services.AddScoped<IAuthenticationService, AuthenticationService>();

        services.AddAutoMapper(typeof(InfrastructureAssemblyReference).Assembly);

        services.AddValidatorsFromAssemblyContaining<InfrastructureAssemblyReference>();

        services.RegisterJwt();

        return services;
    }

    public static void RegisterDbContext(this IServiceCollection services)
    {
        var serviceProvider = services.BuildServiceProvider();

        var configurations = serviceProvider.GetRequiredService<IConfiguration>();

        var connectionStrings = configurations.GetConnectionString("DefaultConnections");

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseSqlServer(
                connectionStrings,
                b => b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName)
                );
        });
    }

    public static void RegisterJwt(this IServiceCollection services)
    {
        var serviceProvider = services.BuildServiceProvider();

        var configurations = serviceProvider.GetRequiredService<IConfiguration>();

        services.Configure<JwtConfiguration>(configurations.GetRequiredSection("JWTConfiguration"));

        //var jwtConfiguration = new JwtConfiguration();

        //configurations.Bind("JWTConfiguration", jwtConfiguration);

        //services.AddSingleton(jwtConfiguration);

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            options.RequireHttpsMetadata = false;
            options.SaveToken = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                //ValidIssuer = jwtConfiguration.Issuer,
                ValidIssuer = configurations["JWTConfiguration:Issuer"],
                //ValidAudience = jwtConfiguration.Audience,
                ValidAudience = configurations["JWTConfiguration:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configurations["JWTConfiguration:Key"])),
                //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfiguration.Key)),
                ClockSkew = TimeSpan.Zero,
            };
        });
    }

}
