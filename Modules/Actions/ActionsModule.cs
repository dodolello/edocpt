using Domain;
using Microsoft.Extensions.DependencyInjection;

namespace Actions;

public class ActionsModule : IFeatureModule
{
    public void RegisterServices(IServiceCollection services)
    {
        // Register action-related services (disabled by default)
    }
}
