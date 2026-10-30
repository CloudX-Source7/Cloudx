
using System.Text.Json;
using CloudX.Remediation.Models;

namespace CloudX.Remediation.Services;

public sealed class RemediationCatalogLoader
{
    private readonly IWebHostEnvironment _environment;

    public RemediationCatalogLoader(
        IWebHostEnvironment environment)
    {
        _environment = environment;
    }

    public List<RemediationCatalogEntry> Load()
    {
        var catalogDirectory = Path.Combine(
            _environment.ContentRootPath,
            "Remediation",
            "Catalog");

        if (!Directory.Exists(catalogDirectory))
        {
            throw new DirectoryNotFoundException(
                $"Remediation catalog directory not found: {catalogDirectory}");
        }

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        var entries = new List<RemediationCatalogEntry>();

        foreach (var file in Directory.GetFiles(
                     catalogDirectory, "*.json"))
        {
            var json = File.ReadAllText(file);

            var catalogEntries =
                JsonSerializer.Deserialize<List<RemediationCatalogEntry>>(
                    json, options);

            if (catalogEntries is null)
            {
                throw new InvalidOperationException(
                    $"Unable to load remediation catalog: {file}");
            }

            entries.AddRange(catalogEntries);
        }

        return entries;
    }
}
