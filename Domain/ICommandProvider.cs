namespace Domain;

public interface ICommandProvider
{
    string Name { get; }
    void Execute();
}
