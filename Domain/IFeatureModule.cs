namespace Domain;

using Microsoft.Extensions.DependencyInjection;

public interface IFeatureModule
{
    void RegisterServices(IServiceCollection services);
}
