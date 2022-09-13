using Core.DTO.Register;
using FluentValidation;

namespace Infrastructure.Validator;

public class RegisterValidator : AbstractValidator<RegisterCommand>
{
    public RegisterValidator()
    {
        RuleFor(x => x.FirstName)
            .MaximumLength(50)
            .NotEmpty();

        RuleFor(x => x.LastName)
            .MaximumLength(50)
            .NotEmpty();

        RuleFor(x => x.Username)
            .MaximumLength(100)
            .NotEmpty();

        RuleFor(x => x.Email)
            .MaximumLength(50)
            .EmailAddress();

        RuleFor(x => x.Password)
            .MaximumLength(50)
            .NotEmpty();
    }
}
