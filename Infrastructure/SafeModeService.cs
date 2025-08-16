namespace Infrastructure;

public class SafeModeService
{
    public bool ActionsEnabled { get; private set; }

    public void EnableActions() => ActionsEnabled = true;
    public void DisableActions() => ActionsEnabled = false;
}
