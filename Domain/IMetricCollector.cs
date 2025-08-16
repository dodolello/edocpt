using System;
namespace Domain;

public interface IMetricCollector
{
    IObservable<object> Metrics { get; }
}
