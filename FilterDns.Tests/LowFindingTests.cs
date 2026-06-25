using System.Security;
using FilterDns.Cache;
using FilterDns.Config;

namespace FilterDns.Tests;

public class LowFindingTests
{
    [Fact]
    public void ZoneHistoryStorage_RejectsSiblingPathWithSamePrefix()
    {
        var baseDirectory = Path.Combine(Path.GetTempPath(), $"filterdns-low-{Guid.NewGuid():N}", "data");
        var siblingDirectory = baseDirectory + "-backup";
        Directory.CreateDirectory(baseDirectory);
        Directory.CreateDirectory(siblingDirectory);
        var storage = new ZoneHistoryStorage(baseDirectory, exportBindZoneFiles: false);

        Assert.Throws<SecurityException>(() =>
            InvokeValidatePath(storage, Path.Combine(siblingDirectory, "example.json"), baseDirectory));
    }

    [Fact]
    public void ZoneHistoryStorage_TreatsBrokenSymlinkAsUnsafeWhenHardeningEnabled()
    {
        var baseDirectory = Path.Combine(Path.GetTempPath(), $"filterdns-low-{Guid.NewGuid():N}");
        Directory.CreateDirectory(baseDirectory);
        var symlinkPath = Path.Combine(baseDirectory, "broken-link.json");
        File.CreateSymbolicLink(symlinkPath, Path.Combine(baseDirectory, "missing-target.json"));
        var storage = new ZoneHistoryStorage(baseDirectory, exportBindZoneFiles: false);

        Assert.Throws<SecurityException>(() => InvokeValidatePath(storage, symlinkPath, baseDirectory));
    }

    [Fact]
    public void ZoneHistoryStorage_RejectsSymlinkedAncestorDirectory()
    {
        var root = Path.Combine(Path.GetTempPath(), $"filterdns-low-{Guid.NewGuid():N}");
        var dataDirectory = Path.Combine(root, "data");
        var outsideDirectory = Path.Combine(root, "outside");
        Directory.CreateDirectory(dataDirectory);
        Directory.CreateDirectory(outsideDirectory);
        var historyLink = Path.Combine(dataDirectory, "history");
        Directory.CreateSymbolicLink(historyLink, outsideDirectory);
        var storage = new ZoneHistoryStorage(dataDirectory, exportBindZoneFiles: false);

        Assert.Throws<SecurityException>(() =>
            InvokeValidatePath(storage, Path.Combine(historyLink, "example_com.json"), dataDirectory));
    }

    private static void InvokeValidatePath(ZoneHistoryStorage storage, string filePath, string baseDirectory)
    {
        var method = typeof(ZoneHistoryStorage).GetMethod(
            "ValidatePathWithinDirectory",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);

        try
        {
            method.Invoke(storage, [filePath, baseDirectory]);
        }
        catch (System.Reflection.TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }
}
