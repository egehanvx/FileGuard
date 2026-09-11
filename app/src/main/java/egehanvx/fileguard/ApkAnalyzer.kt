package egehanvx.fileguard

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.zip.ZipFile

object ApkAnalyzer {

    suspend fun analyze(
        context: Context,
        uri: Uri
    ): ApkAnalysisResult = withContext(Dispatchers.IO) {

        var zipFile: ZipFile? = null
        var temporaryFile: File? = null

        try {

            temporaryFile =
                createTemporaryFile(
                    context = context,
                    uri = uri
                )

            zipFile =
                ZipFile(temporaryFile)

            val entries =
                zipFile.entries()

            var hasManifest = false
            var hasDex = false

            var dexFileCount = 0
            var nativeLibraryCount = 0
            var assetCount = 0
            var resourceFileCount = 0

            val nativeLibraries =
                mutableListOf<String>()

            val suspiciousFindings =
                mutableListOf<String>()

            while (entries.hasMoreElements()) {

                val entry =
                    entries.nextElement()

                if (entry.isDirectory) {
                    continue
                }

                val name =
                    entry.name

                when {

                    name == "AndroidManifest.xml" -> {
                        hasManifest = true
                    }

                    name == "classes.dex" -> {

                        hasDex = true
                        dexFileCount++
                    }

                    name.matches(
                        Regex("classes\\d+\\.dex")
                    ) -> {

                        hasDex = true
                        dexFileCount++
                    }

                    name.startsWith("lib/") -> {

                        nativeLibraryCount++

                        nativeLibraries.add(
                            name
                        )
                    }

                    name.startsWith("assets/") -> {
                        assetCount++
                    }

                    name.startsWith("res/") -> {
                        resourceFileCount++
                    }
                }
            }

            val manifestInfo =
                ApkManifestAnalyzer.analyzeManifest(
                    zipFile
                )

            val dexAnalysis =
                DexAnalyzer.analyze(
                    zipFile
                )

            if (!hasManifest) {

                suspiciousFindings.add(
                    "AndroidManifest.xml bulunamadı."
                )
            }

            if (!hasDex) {

                suspiciousFindings.add(
                    "APK içinde DEX bytecode bulunamadı."
                )
            }

            if (nativeLibraryCount > 0) {

                suspiciousFindings.add(
                    "$nativeLibraryCount native library bulundu."
                )
            }

            if (dexFileCount > 1) {

                suspiciousFindings.add(
                    "Birden fazla DEX dosyası bulundu: $dexFileCount"
                )
            }

            if (assetCount > 1000) {

                suspiciousFindings.add(
                    "APK içinde çok sayıda asset bulundu: $assetCount"
                )
            }

            if (resourceFileCount > 10000) {

                suspiciousFindings.add(
                    "APK içinde çok sayıda resource bulundu: $resourceFileCount"
                )
            }

            if (
                manifestInfo.suspiciousPermissions.isNotEmpty()
            ) {

                suspiciousFindings.add(
                    "${manifestInfo.suspiciousPermissions.size} dikkat gerektiren izin bulundu."
                )
            }

            if (
                manifestInfo.exportedComponents.isNotEmpty()
            ) {

                suspiciousFindings.add(
                    "${manifestInfo.exportedComponents.size} exported component bulundu."
                )
            }

            suspiciousFindings.addAll(
                manifestInfo.suspiciousComponents
            )

            suspiciousFindings.addAll(
                dexAnalysis.suspiciousFindings
            )

            ApkAnalysisResult(
                isApkStructureValid = true,
                hasManifest = hasManifest,
                hasDex = hasDex,
                dexFileCount = dexFileCount,
                nativeLibraryCount = nativeLibraryCount,
                nativeLibraries = nativeLibraries,
                assetCount = assetCount,
                resourceFileCount = resourceFileCount,
                suspiciousStructureFindings =
                    suspiciousFindings.distinct(),
                manifestInfo = manifestInfo,
                dexAnalysis = dexAnalysis
            )

        } catch (exception: Exception) {

            ApkAnalysisResult(
                isApkStructureValid = false,
                hasManifest = false,
                hasDex = false,
                dexFileCount = 0,
                nativeLibraryCount = 0,
                nativeLibraries = emptyList(),
                assetCount = 0,
                resourceFileCount = 0,
                suspiciousStructureFindings = emptyList(),
                manifestInfo = null,
                dexAnalysis = null,
                errorMessage =
                    exception.message
                        ?: "APK analiz edilemedi."
            )

        } finally {

            try {
                zipFile?.close()
            } catch (_: Exception) {
            }

            try {
                temporaryFile?.delete()
            } catch (_: Exception) {
            }
        }
    }

    private fun createTemporaryFile(
        context: Context,
        uri: Uri
    ): File {

        val temporaryFile =
            File.createTempFile(
                "fileguard_apk_",
                ".apk",
                context.cacheDir
            )

        context.contentResolver
            .openInputStream(uri)
            ?.use { input ->

                temporaryFile.outputStream()
                    .use { output ->

                        val buffer =
                            ByteArray(8192)

                        while (true) {

                            val bytesRead =
                                input.read(buffer)

                            if (bytesRead == -1) {
                                break
                            }

                            output.write(
                                buffer,
                                0,
                                bytesRead
                            )
                        }
                    }

            } ?: throw IllegalStateException(
            "APK dosyası okunamadı."
        )

        return temporaryFile
    }
}