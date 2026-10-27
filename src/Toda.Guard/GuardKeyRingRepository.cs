using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Toda.Guard.Data;
using Npgsql;

namespace Toda.Guard;

/// <summary>
/// A host's Data Protection key ring in Guard's database (ADR 0087), for a host without one of its own (Toda keeps its
/// own, in platform.data_protection_keys): every server and every restart reads the same keys, so what Guard protects
/// with them (authenticator secrets, mailed links, directory passwords) stays readable. The table,
/// <c>guard.data_protection_keys</c>, is made on first use, not by a migration: keys are read before migrations run.
/// </summary>
public sealed class GuardKeyRingRepository(string connectionString) : IXmlRepository
{
    // Making the table once at a time, across servers: "GUAR" and a 1.
    private const long MakeLock = 0x47554152_00000001;

    private const string Table = """
        CREATE SCHEMA IF NOT EXISTS guard;
        CREATE TABLE IF NOT EXISTS guard.data_protection_keys (
            id bigserial PRIMARY KEY,
            friendly_name text NOT NULL,
            xml text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now());
        """;

    private readonly Lock _ready = new();
    private bool _made;

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        using NpgsqlConnection connection = Open();
        List<XElement> elements = [];
        using NpgsqlCommand read = new("SELECT xml FROM guard.data_protection_keys ORDER BY id", connection);
        using NpgsqlDataReader rows = read.ExecuteReader();
        while (rows.Read())
        {
            elements.Add(XElement.Parse(rows.GetString(0)));
        }

        return elements;
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        using NpgsqlConnection connection = Open();
        using NpgsqlCommand insert = new("INSERT INTO guard.data_protection_keys (friendly_name, xml) VALUES (@name, @xml)", connection);
        insert.Parameters.AddWithValue("name", friendlyName);
        insert.Parameters.AddWithValue("xml", element.ToString(SaveOptions.DisableFormatting));
        insert.ExecuteNonQuery();
    }

    private NpgsqlConnection Open()
    {
        NpgsqlConnection connection = KeyDatabase.Open(connectionString);
        lock (_ready)
        {
            if (!_made)
            {
                using NpgsqlTransaction transaction = connection.BeginTransaction();
                using (NpgsqlCommand take = new($"SELECT pg_advisory_xact_lock({MakeLock})", connection, transaction))
                {
                    take.ExecuteNonQuery();
                }

                using (NpgsqlCommand make = new(Table, connection, transaction))
                {
                    make.ExecuteNonQuery();
                }

                transaction.Commit();
                _made = true;
            }
        }

        return connection;
    }
}

/// <summary>Keeping a host's key ring in Guard's database (ADR 0087).</summary>
public static class GuardKeyRingExtensions
{
    /// <summary>
    /// Keeps the Data Protection key ring in Guard's database (ConnectionStrings:Guard, else Default), table
    /// guard.data_protection_keys. For a host that has nowhere of its own; Guard's start-up check then passes.
    /// </summary>
    public static IDataProtectionBuilder AddGuardKeyRing(this IDataProtectionBuilder builder)
    {
        builder.Services.AddOptions<KeyManagementOptions>().Configure<IConfiguration>((options, configuration) =>
            options.XmlRepository = new GuardKeyRingRepository(GuardConnection.Of(configuration)
                ?? throw new InvalidOperationException("AddGuardKeyRing needs ConnectionStrings:Guard or ConnectionStrings:Default.")));
        return builder;
    }
}
