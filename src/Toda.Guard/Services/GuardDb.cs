using Toda.Guard.Data;
using Toda.Platform.Data;
using Volo.Abp.DependencyInjection;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.Uow;

namespace Toda.Guard.Services;

/// <summary>Runs work against GuardDbContext in a unit of work (see <see cref="ModuleDb{TDbContext}"/>).</summary>
public class GuardDb(IUnitOfWorkManager unitOfWorkManager, IDbContextProvider<GuardDbContext> provider)
    : ModuleDb<GuardDbContext>(unitOfWorkManager, provider), ITransientDependency;
