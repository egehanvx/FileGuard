package egehanvx.fileguard

enum class ScanStage(
    val title: String,
    val description: String,
    val progress: Int
) {
    STARTING(
        title = "Analiz başlatılıyor",
        description = "Seçilen dosya hazırlanıyor...",
        progress = 5
    ),

    METADATA(
        title = "Dosya analiz ediliyor",
        description = "Dosya bilgileri ve SHA-256 hesaplanıyor...",
        progress = 25
    ),

    FILE_TYPE(
        title = "Dosya türü kontrol ediliyor",
        description = "Dosyanın gerçek yapısı ve MIME bilgisi karşılaştırılıyor...",
        progress = 45
    ),

    APK_ANALYSIS(
        title = "APK statik analizi",
        description = "APK yapısı, Manifest ve DEX bilgileri inceleniyor...",
        progress = 70
    ),

    RISK_ANALYSIS(
        title = "Risk değerlendiriliyor",
        description = "Analiz bulguları birleştirilerek risk seviyesi hesaplanıyor...",
        progress = 90
    ),

    COMPLETE(
        title = "Analiz tamamlandı",
        description = "Sonuçlar hazır.",
        progress = 100
    )
}