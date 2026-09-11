package egehanvx.fileguard

object RiskAnalyzer {

    fun analyze(
        metadata: FileMetadata?,
        fileType: FileTypeResult?,
        apk: ApkAnalysisResult?
    ): RiskAnalysisResult {

        val findings = mutableListOf<RiskFinding>()

        var score = 0

        /*
         * ---------------------------------------------------------
         * DOSYA TÜRÜ KONTROLLERİ
         * ---------------------------------------------------------
         */

        if (fileType != null) {

            if (!fileType.isKnownFormat) {

                score += 5

                findings.add(
                    RiskFinding(
                        title = "Bilinmeyen dosya formatı",
                        description =
                            "Dosyanın gerçek dosya yapısı tanınamadı.",
                        points = 5
                    )
                )
            }

            if (!fileType.isExtensionConsistent) {

                score += 15

                findings.add(
                    RiskFinding(
                        title = "Uzantı ve içerik uyuşmazlığı",
                        description =
                            "Dosya uzantısı ile tespit edilen gerçek dosya yapısı uyuşmuyor.",
                        points = 15
                    )
                )
            }

            if (!fileType.isMimeConsistent) {

                score += 10

                findings.add(
                    RiskFinding(
                        title = "MIME uyumsuzluğu",
                        description =
                            "Dosyanın bildirilen MIME type bilgisi ile gerçek formatı arasında uyumsuzluk var.",
                        points = 10
                    )
                )
            }
        }

        /*
         * ---------------------------------------------------------
         * APK KONTROLLERİ
         * ---------------------------------------------------------
         */

        if (apk != null) {

            if (!apk.isApkStructureValid) {

                score += 25

                findings.add(
                    RiskFinding(
                        title = "APK yapısı okunamadı",
                        description =
                            "APK paketi beklenen yapıda okunamadı.",
                        points = 25
                    )
                )
            }

            if (!apk.hasManifest) {

                score += 20

                findings.add(
                    RiskFinding(
                        title = "Manifest bulunamadı",
                        description =
                            "APK içerisinde AndroidManifest.xml bulunamadı.",
                        points = 20
                    )
                )
            }

            if (!apk.hasDex) {

                score += 10

                findings.add(
                    RiskFinding(
                        title = "DEX bulunamadı",
                        description =
                            "APK içerisinde beklenen DEX bytecode yapısı bulunamadı.",
                        points = 10
                    )
                )
            }

            /*
             * Native library tek başına kötü değildir.
             * Bu nedenle düşük ağırlık veriyoruz.
             */

            if (apk.nativeLibraryCount > 0) {

                score += 2

                findings.add(
                    RiskFinding(
                        title = "Native code bulundu",
                        description =
                            "APK içerisinde native library bulundu. Bu durum tek başına zararlı yazılım göstergesi değildir.",
                        points = 2
                    )
                )
            }

            if (apk.dexFileCount > 3) {

                score += 5

                findings.add(
                    RiskFinding(
                        title = "Çoklu DEX yapısı",
                        description =
                            "APK içerisinde üçten fazla DEX dosyası bulunuyor.",
                        points = 5
                    )
                )
            }

            /*
             * -----------------------------------------------------
             * MANIFEST
             * -----------------------------------------------------
             */

            val manifest =
                apk.manifestInfo

            if (manifest != null) {

                /*
                 * Dikkat gerektiren izinler
                 */

                for (
                permission in manifest.suspiciousPermissions
                ) {

                    val points =
                        permissionPoints(permission)

                    if (points > 0) {

                        score += points

                        findings.add(
                            RiskFinding(
                                title = "Dikkat gerektiren izin",
                                description = permission,
                                points = points
                            )
                        )
                    }
                }

                /*
                 * Exported component
                 *
                 * Tek başına malware değildir.
                 */

                if (
                    manifest.exportedComponents.isNotEmpty()
                ) {

                    val count =
                        manifest.exportedComponents.size

                    val points =
                        minOf(
                            count * 2,
                            10
                        )

                    score += points

                    findings.add(
                        RiskFinding(
                            title = "Exported component",
                            description =
                                "$count adet exported component bulundu.",
                            points = points
                        )
                    )
                }

                /*
                 * Şüpheli componentler
                 */

                if (
                    manifest.suspiciousComponents.isNotEmpty()
                ) {

                    val count =
                        manifest.suspiciousComponents.size

                    val points =
                        minOf(
                            count * 8,
                            20
                        )

                    score += points

                    findings.add(
                        RiskFinding(
                            title = "Şüpheli component",
                            description =
                                "$count adet dikkat gerektiren component bulundu.",
                            points = points
                        )
                    )
                }
            }

            /*
             * -----------------------------------------------------
             * DEX ANALİZİ
             * -----------------------------------------------------
             */

            val dex =
                apk.dexAnalysis

            if (dex != null) {

                /*
                 * Her pattern eşleşmesini
                 * ayrı ayrı yüksek puanlamıyoruz.
                 */

                val patternCount =
                    dex.matchedPatterns.size

                if (patternCount >= 1) {

                    val points =
                        minOf(
                            patternCount * 2,
                            12
                        )

                    score += points

                    findings.add(
                        RiskFinding(
                            title = "Şüpheli API/string izleri",
                            description =
                                "$patternCount farklı pattern eşleşmesi bulundu.",
                            points = points
                        )
                    )
                }

                if (
                    dex.suspiciousFindings.isNotEmpty()
                ) {

                    val points =
                        minOf(
                            dex.suspiciousFindings.size * 3,
                            15
                        )

                    score += points

                    findings.add(
                        RiskFinding(
                            title = "DEX davranış bulguları",
                            description =
                                "${dex.suspiciousFindings.size} adet DEX bulgusu bulundu.",
                            points = points
                        )
                    )
                }
            }

            /*
             * -----------------------------------------------------
             * YAPISAL BULGULAR
             * -----------------------------------------------------
             */

            if (
                apk.suspiciousStructureFindings.isNotEmpty()
            ) {

                val count =
                    apk.suspiciousStructureFindings.size

                val points =
                    minOf(
                        count * 2,
                        10
                    )

                score += points

                findings.add(
                    RiskFinding(
                        title = "Yapısal bulgular",
                        description =
                            "$count adet yapısal bulgu bulundu.",
                        points = points
                    )
                )
            }
        }

        /*
         * ---------------------------------------------------------
         * SKORU 0-100 ARASINDA SINIRLA
         * ---------------------------------------------------------
         */

        score =
            score.coerceIn(
                0,
                100
            )

        /*
         * ---------------------------------------------------------
         * SEVİYE
         * ---------------------------------------------------------
         */

        val level =
            when {

                score < 15 ->
                    RiskLevel.SAFE

                score < 35 ->
                    RiskLevel.LOW

                score < 65 ->
                    RiskLevel.SUSPICIOUS

                else ->
                    RiskLevel.HIGH
            }

        /*
         * ---------------------------------------------------------
         * ÖZET
         * ---------------------------------------------------------
         */

        val summary =
            when (level) {

                RiskLevel.SAFE ->
                    "Analiz edilen özelliklerde belirgin bir risk göstergesi bulunmadı."

                RiskLevel.LOW ->
                    "Bazı dikkat edilmesi gereken özellikler bulundu, ancak belirgin yüksek risk göstergesi yok."

                RiskLevel.SUSPICIOUS ->
                    "Birden fazla dikkat gerektiren özellik tespit edildi. Dosyanın güvenilirliği ayrıca değerlendirilmelidir."

                RiskLevel.HIGH ->
                    "Birden fazla yüksek risk göstergesi tespit edildi. Dosyanın çalıştırılmaması ve kaynağının doğrulanması önerilir."
            }

        return RiskAnalysisResult(
            score = score,
            level = level,
            findings = findings,
            summary = summary
        )
    }

    private fun permissionPoints(
        permission: String
    ): Int {

        return when (permission) {

            "android.permission.BIND_ACCESSIBILITY_SERVICE" ->
                8

            "android.permission.REQUEST_INSTALL_PACKAGES" ->
                7

            "android.permission.SYSTEM_ALERT_WINDOW" ->
                6

            "android.permission.READ_SMS" ->
                5

            "android.permission.RECEIVE_SMS" ->
                5

            "android.permission.SEND_SMS" ->
                5

            "android.permission.READ_CALL_LOG" ->
                4

            "android.permission.WRITE_CALL_LOG" ->
                4

            "android.permission.RECORD_AUDIO" ->
                3

            "android.permission.READ_CONTACTS" ->
                3

            "android.permission.WRITE_CONTACTS" ->
                3

            "android.permission.READ_PHONE_STATE" ->
                3

            "android.permission.CALL_PHONE" ->
                3

            "android.permission.ACCESS_FINE_LOCATION" ->
                2

            "android.permission.ACCESS_COARSE_LOCATION" ->
                1

            "android.permission.RECEIVE_BOOT_COMPLETED" ->
                2

            "android.permission.READ_EXTERNAL_STORAGE" ->
                1

            "android.permission.WRITE_EXTERNAL_STORAGE" ->
                1

            else ->
                0
        }
    }
}