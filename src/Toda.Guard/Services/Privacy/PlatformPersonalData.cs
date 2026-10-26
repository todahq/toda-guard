using Volo.Abp.DependencyInjection;
using To = Toda.Guard.PersonalDataDestinations;
using static Toda.Guard.PersonalDataKinds;

namespace Toda.Guard.Services.Privacy;

/// <summary>
/// What the platform keeps about people (ADR 0082, the data map): messages, notices and the addresses they go to,
/// accounts at other systems, what people ran, and backups. The platform can't see Guard's contracts (it knows neither
/// module), so its declaration sits here beside its merge participant, and moves with it into Toda.Guard.Integration
/// (ADR 0087, S2). tests/Toda.Projects.Tests/DataMapTests.cs holds that every platform table, and every file store and
/// folder, is here or among those holding nothing about people.
/// </summary>
[ExposeServices(typeof(IPersonalDataDeclarations))]
public sealed class PlatformPersonalData : IPersonalDataDeclarations, ITransientDependency
{
    private const string Owner = "platform";

    public IReadOnlyList<PersonalDataStore> Stores { get; } =
    [
        new("platform.mail-log", Owner,
            new("Mail sent and received", "البريد المرسل والمستلم"),
            new("Every message Toda sent or took in by mail: the address and name, the subject and the whole text.",
                "كل رسالة أرسلها تودا أو استلمها بالبريد: العنوان والاسم والموضوع والنص كاملًا."),
            ["platform.mail_log"], [],
            PersonalDataSubjects.Both, [Contact, Content], PersonalDataKept.Setting("Toda:Mail:KeepDays", 180), [To.Mail], []),
        new("platform.mail-folders", Owner,
            new("Mail folders", "مجلدات البريد"),
            new("Where a server set up for it drops each message it sends (the pickup folder) and reads mail coming in (the inbox folder); read mail is moved aside, and nothing cleans either.",
                "حيث يضع الخادم المهيّأ لذلك كل رسالة يرسلها (مجلد الالتقاط) ويقرأ البريد الوارد (مجلد الوارد)؛ يُنقل البريد المقروء جانبًا ولا يُنظَّف أي منهما."),
            [], ["folder:mail-pickup", "folder:mail-inbox"],
            PersonalDataSubjects.Both, [Contact, Content], PersonalDataKept.Forever, [], []),
        new("platform.notices", Owner,
            new("Notices and how people hear", "الإشعارات وطريقة وصولها"),
            new("What Toda tells people (with excerpts of records and comments) and how each person wants to hear: by mail, on the phone, in a chat, quiet hours and digests.",
                "ما يبلّغه تودا للأشخاص (مع مقتطفات من السجلات والتعليقات) وكيف يريد كل منهم أن يصله: بالبريد أو على الهاتف أو في محادثة، وساعات الهدوء والملخصات."),
            ["platform.notices", "platform.notification_settings"], [],
            PersonalDataSubjects.Accounts, [Activity, Content, Preferences], PersonalDataKept.Forever, [To.Mail, To.Push, To.Chat, To.Sms, To.WhatsApp], []),
        new("platform.addresses", Owner,
            new("Phone numbers, chat handles and phones", "أرقام الهواتف ومعرّفات المحادثة والأجهزة"),
            new("Where a person can be reached besides mail: phone numbers and chat handles they confirmed, and the phones the app sends to, with their names.",
                "أين يمكن الوصول إلى الشخص غير البريد: أرقام الهواتف ومعرّفات المحادثة التي أكّدها، والهواتف التي يرسل إليها التطبيق بأسمائها."),
            ["platform.channel_addresses", "platform.devices"], [],
            PersonalDataSubjects.Accounts, [Contact, Security], PersonalDataKept.WithAccount, [To.Sms, To.WhatsApp, To.Chat, To.Push], []),
        new("platform.other-systems", Owner,
            new("Accounts at other systems", "الحسابات في الأنظمة الأخرى"),
            new("The accounts Toda signs in to other systems as, people's usernames at git hosts, and what the repositories say: commit and pull request authors with their names and emails.",
                "الحسابات التي يدخل بها تودا إلى الأنظمة الأخرى، وأسماء مستخدمي الأشخاص لدى مستضيفي git، وما تقوله المستودعات: كتّاب الإيداعات وطلبات الدمج بأسمائهم وبريدهم."),
            ["platform.connections", "platform.git_accounts", "platform.development_items", "platform.smart_commit_runs"], ["folder:git"],
            PersonalDataSubjects.Both, [Identity, Contact, Credentials, Activity], PersonalDataKept.Forever, [To.GitHosts, To.OutsideMcp], []),
        new("platform.runs", Owner,
            new("What people ran", "ما شغّله الأشخاص"),
            new("Jobs and scripts with their input and output, what AI and skills were used for and by whom, calls to outside tools, and backups people started or downloaded.",
                "المهام والنصوص البرمجية بمدخلاتها ومخرجاتها، وفيمَ استُخدم الذكاء الاصطناعي والمهارات ومن استخدمها، واستدعاءات الأدوات الخارجية، والنسخ الاحتياطية التي بدأها الأشخاص أو نزّلوها."),
            ["platform.jobs", "platform.script_runs", "platform.ai_usage", "platform.skill_runs", "platform.outside_tool_calls", "platform.backup_runs", "platform.backup_downloads"], [],
            PersonalDataSubjects.Accounts, [Activity, Content], PersonalDataKept.Forever, [To.Ai, To.OutsideMcp], []),
        new("platform.settings-authors", Owner,
            new("Who changed site settings", "من غيّر إعدادات الموقع"),
            new("Who last changed message templates, texts, backup settings, chat targets, plugin publishers and repositories.",
                "من غيّر آخر مرة قوالب الرسائل والنصوص وإعدادات النسخ الاحتياطي ووجهات المحادثة وناشري الإضافات والمستودعات."),
            ["platform.message_templates", "platform.text_overrides", "platform.backup_settings", "platform.channel_targets", "platform.plugin_publishers", "platform.repositories", "platform.repository_links"], [],
            PersonalDataSubjects.Accounts, [Activity], PersonalDataKept.Forever, [], []),
        new("platform.limits", Owner,
            new("Counts against abuse", "عدّادات منع الإساءة"),
            new("Failed sign-ins and other tries counted by address, email or account, kept only as hashes for a day.",
                "محاولات الدخول الفاشلة وغيرها معدودة حسب العنوان أو البريد أو الحساب، محفوظة مجزّأة ليوم واحد فقط."),
            ["platform.limit_hits"], [],
            PersonalDataSubjects.Both, [Security], PersonalDataKept.Days(1), [], []),
        new("platform.backups", Owner,
            new("Backups", "النسخ الاحتياطية"),
            new("Copies of the whole database and of every file, on the site's storage or the places its servers name. Older ones go after a backup runs; "
                + "the files copied to another place are never removed.",
                "نسخ من قاعدة البيانات كاملة ومن كل ملف، على تخزين الموقع أو في الأماكن التي تسمّيها خوادمه. تُحذف الأقدم بعد كل نسخ احتياطي، "
                + "ولا تُحذف أبدًا الملفات المنسوخة إلى مكان آخر."),
            [], ["backups:"],
            PersonalDataSubjects.Both, [Identity, Contact, Credentials, Security, Activity, Content, Preferences],
            PersonalDataKept.Setting("platform.backup_settings.KeepDays", 7), [To.Backups, To.Storage], []),
        new("platform.events", Owner,
            new("Events waiting to go", "أحداث تنتظر الإرسال"),
            new("Platform events waiting to reach modules, plugins and webhooks: a commit's author and email among them.",
                "أحداث المنصة التي تنتظر الوصول إلى الوحدات والإضافات وخطافات الويب، ومنها كاتب الإيداع وبريده."),
            ["platform.AbpEventOutbox"], [],
            PersonalDataSubjects.Both, [Identity, Contact, Activity], PersonalDataKept.UntilDone, [To.Webhooks], []),
    ];

    public IReadOnlyList<NonPersonalTable> NotPersonal { get; } =
    [
        new("platform.ai_access", "which AI models a site's groups may use"),
        new("platform.ai_aliases", "names for AI models"),
        new("platform.ai_limits", "how much AI a site allows"),
        new("platform.ai_models", "the AI models a site has"),
        new("platform.channel_posts", "which events went to which chat target"),
        new("platform.claimed_slots", "work a server took on, so another doesn't"),
        new("platform.data_protection_keys", "the keys secrets are encrypted with"),
        new("platform.development_keys", "which record keys a repository's items name"),
        new("platform.languages", "the languages a site offers"),
        new("platform.localization_state", "when texts were last changed"),
        new("platform.mail_settings", "how a site sends mail"),
        new("platform.notice_site_settings", "a site's defaults for notices"),
        new("platform.outside_tools", "the tools outside MCP servers offer"),
        new("platform.pending_work", "work waiting for a server"),
        new("platform.plugin_files", "the names and hashes of plugins' files"),
        new("platform.plugin_trust", "which plugins and signers a site trusts"),
        new("platform.plugins", "the plugins installed"),
        new("platform.repository_backfills", "how far a repository's history was read"),
        new("platform.repository_deliveries", "which git host deliveries came in"),
        new("platform.servers", "the servers running"),
        new("platform.site_changes", "when a site took over from another"),
        new("platform.site_keys", "a site's keys"),
        new("platform.site_lag_spells", "when a site fell behind"),
        new("platform.site_state", "a site's state"),
        new("platform.sites", "the sites"),
        new("platform.skill_sources", "where skills come from"),
        new("platform.skills", "the skills a site has"),
        new("platform.spent_challenges", "CAPTCHA answers already used"),
        new("platform.storage_copy", "how far a storage copy got"),
        new("platform.tool_settings", "which tools a site offers"),
    ];
}
