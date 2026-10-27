using System.Reflection;
using Toda.Guard.Services.Privacy;
using Xunit;

namespace Toda.Guard.Tests;

/// <summary>
/// The record of processing's and a person's export's words are a host's to change (Guard:Texts, ADR 0087; ADR 0082):
/// Toda keeps Guard's own word for word, a language is found by its first part and falls back to English, and Guard's
/// own words name the host's product in place of Toda.
/// </summary>
public class GuardTextsTests
{
    /// <summary>Every text of a record, its strings and its lists of names, as it reads.</summary>
    private static void SameWords(ProcessingRecordTexts expected, ProcessingRecordTexts actual)
    {
        foreach (PropertyInfo property in typeof(ProcessingRecordTexts).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            Assert.Equal(property.GetValue(expected), property.GetValue(actual) is IReadOnlyDictionary<string, string> names
                ? names.ToDictionary() as object
                : property.GetValue(actual));
        }
    }

    [Fact]
    public void Toda_keeps_the_records_and_the_exports_words()
    {
        GuardTextOptions toda = new();

        SameWords(ProcessingRecordTexts.English, toda.RecordIn("en"));
        SameWords(ProcessingRecordTexts.Arabic, toda.RecordIn("ar-SA"));
        SameWords(ProcessingRecordTexts.English, toda.RecordIn("fr"));
        Assert.Same(PersonalDataExportTexts.English, toda.ExportIn("en"));
        Assert.Same(PersonalDataExportTexts.Arabic, toda.ExportIn("AR"));
        Assert.Same(PersonalDataExportTexts.English, toda.ExportIn("fr-FR"));
    }

    [Fact]
    public void Guards_own_words_name_the_hosts_product()
    {
        GuardTextOptions market = new();
        market.ProductName["en"] = "Market";
        market.ProductName["ar"] = "ماركت";

        Assert.Equal("people outside Market, known by an address", market.RecordIn("en").Subjects[PersonalDataSubjects.Outside]);
        Assert.Equal("أشخاص من خارج ماركت يُعرفون بعنوان", market.RecordIn("ar").Subjects[PersonalDataSubjects.Outside]);
        Assert.Equal("people outside Toda, known by an address", ProcessingRecordTexts.English.Subjects[PersonalDataSubjects.Outside]);
    }

    [Fact]
    public void A_host_adds_a_language_or_rewords_one()
    {
        GuardTextOptions texts = new();
        texts.Record["fr"] = ProcessingRecordTexts.English with { Title = "Registre des activités de traitement" };
        texts.Export["en"] = PersonalDataExportTexts.English with { Title = "Your data" };

        Assert.Equal("Registre des activités de traitement", texts.RecordIn("fr-CA").Title);
        Assert.Equal("Your data", texts.ExportIn("en").Title);
        Assert.Equal("Record of processing activities", texts.RecordIn("en").Title);
    }
}
