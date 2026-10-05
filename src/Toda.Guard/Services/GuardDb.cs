using Toda.Guard.Data;
using Volo.Abp.DependencyInjection;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.Uow;

namespace Toda.Guard.Services;

/// <summary>Runs work against GuardDbContext inside an ABP unit of work, joining the caller's if there is one.</summary>
public class GuardDb(IUnitOfWorkManager unitOfWorkManager, IDbContextProvider<GuardDbContext> provider) : ITransientDependency
{
    public async Task<T> RunAsync<T>(Func<GuardDbContext, Task<T>> work, bool requiresNew = false, CancellationToken cancellationToken = default, bool isTransactional = false)
    {
        using IUnitOfWork uow = unitOfWorkManager.Begin(requiresNew: requiresNew, isTransactional: isTransactional);
        GuardDbContext db = await provider.GetDbContextAsync();
        T result = await work(db);
        await uow.CompleteAsync(cancellationToken);
        return result;
    }

    public Task RunAsync(Func<GuardDbContext, Task> work, bool requiresNew = false, CancellationToken cancellationToken = default, bool isTransactional = false) =>
        RunAsync<bool>(async db => { await work(db); return true; }, requiresNew, cancellationToken, isTransactional);
}
