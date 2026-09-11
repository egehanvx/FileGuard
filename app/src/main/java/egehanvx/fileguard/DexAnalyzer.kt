package egehanvx.fileguard

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

object DexAnalyzer {

    private val suspiciousPatterns = listOf(
        "Ljava/lang/Runtime;",
        "Ljava/lang/ProcessBuilder;",
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/PathClassLoader;",
        "Ljava/lang/System;",
        "loadLibrary",
        "exec",
        "Runtime.getRuntime",
        "SmsManager",
        "sendTextMessage",
        "RECEIVE_SMS",
        "READ_SMS",
        "AccessibilityService",
        "DeviceAdmin",
        "Cipher",
        "SecretKeySpec",
        "Base64",
        "WebView",
        "addJavascriptInterface",
        "su",
        "shell",
        "chmod",
        "busybox"
    )

    fun analyze(
        zipFile: ZipFile
    ): DexAnalysisResult {

        return try {

            val dexEntries =
                mutableListOf<java.util.zip.ZipEntry>()

            val entries =
                zipFile.entries()

            while (entries.hasMoreElements()) {

                val entry =
                    entries.nextElement()

                if (
                    !entry.isDirectory &&
                    entry.name.matches(
                        Regex("classes\\d*\\.dex")
                    )
                ) {

                    dexEntries.add(entry)
                }
            }

            if (dexEntries.isEmpty()) {

                return DexAnalysisResult(
                    dexFileCount = 0,
                    suspiciousFindings = listOf(
                        "DEX dosyası bulunamadı."
                    ),
                    matchedPatterns = emptyList(),
                    stringCount = 0
                )
            }

            val matchedPatterns =
                linkedSetOf<String>()

            var totalStringCount = 0

            for (entry in dexEntries) {

                val bytes =
                    zipFile.getInputStream(entry).use {
                        it.readBytes()
                    }

                val strings =
                    extractDexStrings(bytes)

                totalStringCount += strings.size

                for (string in strings) {

                    for (pattern in suspiciousPatterns) {

                        if (
                            string.contains(
                                pattern,
                                ignoreCase = true
                            )
                        ) {

                            matchedPatterns.add(
                                pattern
                            )
                        }
                    }
                }
            }

            val findings =
                buildFindings(
                    matchedPatterns
                )

            DexAnalysisResult(
                dexFileCount = dexEntries.size,
                suspiciousFindings = findings,
                matchedPatterns = matchedPatterns.toList(),
                stringCount = totalStringCount
            )

        } catch (exception: Exception) {

            DexAnalysisResult(
                dexFileCount = 0,
                suspiciousFindings = emptyList(),
                matchedPatterns = emptyList(),
                stringCount = 0,
                errorMessage =
                    exception.message
                        ?: "DEX analizi başarısız oldu."
            )
        }
    }

    private fun extractDexStrings(
        bytes: ByteArray
    ): List<String> {

        if (bytes.size < 112) {
            return emptyList()
        }

        val strings =
            mutableListOf<String>()

        val buffer =
            ByteBuffer
                .wrap(bytes)
                .order(ByteOrder.LITTLE_ENDIAN)

        val stringIdsSize =
            buffer.getInt(0x38)

        val stringIdsOff =
            buffer.getInt(0x3C)

        if (
            stringIdsSize <= 0 ||
            stringIdsOff <= 0
        ) {
            return emptyList()
        }

        val maxCount =
            minOf(
                stringIdsSize,
                200000
            )

        for (index in 0 until maxCount) {

            val offsetPosition =
                stringIdsOff + (index * 4)

            if (
                offsetPosition < 0 ||
                offsetPosition + 4 > bytes.size
            ) {
                break
            }

            val stringOffset =
                buffer.getInt(offsetPosition)

            if (
                stringOffset < 0 ||
                stringOffset >= bytes.size
            ) {
                continue
            }

            val value =
                readDexString(
                    bytes,
                    stringOffset
                )

            if (value.isNotBlank()) {
                strings.add(value)
            }
        }

        return strings
    }

    private fun readDexString(
        bytes: ByteArray,
        offset: Int
    ): String {

        if (
            offset < 0 ||
            offset >= bytes.size
        ) {
            return ""
        }

        var position =
            offset

        val utf16Size =
            readUleb128(
                bytes,
                position
            )

        position += utf16Size.second

        if (
            position >= bytes.size
        ) {
            return ""
        }

        val start =
            position

        val output =
            StringBuilder()

        while (
            position < bytes.size
        ) {

            val current =
                bytes[position].toInt() and 0xFF

            position++

            if (current == 0) {
                break
            }

            if (
                current in 32..126 ||
                current >= 128
            ) {

                output.append(
                    current.toChar()
                )
            }
        }

        return output
            .toString()
            .take(500)
    }

    private fun readUleb128(
        bytes: ByteArray,
        offset: Int
    ): Pair<Int, Int> {

        var position =
            offset

        var result =
            0

        var shift =
            0

        var count =
            0

        while (
            position < bytes.size &&
            count < 5
        ) {

            val value =
                bytes[position].toInt() and 0xFF

            position++
            count++

            result =
                result or
                        ((value and 0x7F) shl shift)

            if (
                (value and 0x80) == 0
            ) {
                break
            }

            shift += 7
        }

        return Pair(
            result,
            count
        )
    }

    private fun buildFindings(
        patterns: Set<String>
    ): List<String> {

        val findings =
            mutableListOf<String>()

        if (
            "Ljava/lang/Runtime;" in patterns ||
            "Runtime.getRuntime" in patterns ||
            "exec" in patterns
        ) {

            findings.add(
                "Process çalıştırma ile ilişkili API/string izleri bulundu."
            )
        }

        if (
            "Ldalvik/system/DexClassLoader;" in patterns ||
            "Ldalvik/system/PathClassLoader;" in patterns
        ) {

            findings.add(
                "Dinamik class/dex yükleme ile ilişkili izler bulundu."
            )
        }

        if (
            "SmsManager" in patterns ||
            "sendTextMessage" in patterns
        ) {

            findings.add(
                "SMS işlemleriyle ilişkili API izleri bulundu."
            )
        }

        if (
            "AccessibilityService" in patterns
        ) {

            findings.add(
                "Accessibility Service ile ilişkili iz bulundu."
            )
        }

        if (
            "DeviceAdmin" in patterns
        ) {

            findings.add(
                "Device Admin ile ilişkili iz bulundu."
            )
        }

        if (
            "addJavascriptInterface" in patterns
        ) {

            findings.add(
                "WebView JavaScript bridge kullanımı tespit edildi."
            )
        }

        if (
            "su" in patterns ||
            "shell" in patterns ||
            "busybox" in patterns
        ) {

            findings.add(
                "Shell/root araçlarıyla ilişkili string izleri bulundu."
            )
        }

        if (
            "Cipher" in patterns ||
            "SecretKeySpec" in patterns ||
            "Base64" in patterns
        ) {

            findings.add(
                "Kriptografi veya kodlama ile ilişkili API/string izleri bulundu."
            )
        }

        return findings
    }
}