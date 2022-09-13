using AutoMapper;
using Core.DTO.Register;
using Domain.Models;

namespace Infrastructure.Mappers;

public class ApplicationUserMapper : Profile
{
    public ApplicationUserMapper()
    {
        CreateMap<RegisterCommand, ApplicationUser>()
            .ForMember(c => c.FirstName, opt => opt.MapFrom(c => c.FirstName))
            .ForMember(c => c.LastName, opt => opt.MapFrom(c => c.LastName))
            .ForMember(c => c.UserName, opt => opt.MapFrom(c => c.Username))
            .ForMember(c => c.Email, opt => opt.MapFrom(c => c.Email));
    }
}
