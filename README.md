# Edocpt Monitoring Tool

Prototype of an extensible PowerToys-style WPF application focused on monitoring vSphere environments.

## Structure

- `App` – WPF shell with dependency injection, theming and navigation.
- `Domain` – shared contracts and DTOs for modules.
- `Infrastructure` – persistence, logging and safety services.
- `Modules/Monitoring` – dashboards, charts and collectors.
- `Modules/Actions` – command framework (disabled by default).
- `Adapters` – PowerCLI and vSphere integration points.
- `Tests` – xUnit tests.
