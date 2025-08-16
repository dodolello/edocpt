using System.Windows;
using Microsoft.Extensions.DependencyInjection;

namespace Edocpt.App;

public partial class App : Application
{
    private readonly ServiceProvider _serviceProvider;

    public App()
    {
        var services = new ServiceCollection();
        services.AddSingleton<MainWindow>();
        _serviceProvider = services.BuildServiceProvider();
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var main = _serviceProvider.GetRequiredService<MainWindow>();
        main.Show();
    }
}
