package egehanvx.fileguard

import android.content.Context
import android.net.Uri

data class FileTypeResult(
    val detectedType: String,
    val detectedMimeType: String,
    val isExtensionConsistent: Boolean,
    val isMimeConsistent: Boolean,
    val isKnownFormat: Boolean,
    val description: String
)

object FileTypeAnalyzer {

    fun analyze(
        context: Context,
        uri: Uri,
        fileName: String,
        mimeType: String
    ): FileTypeResult {

        val header = readHeader(context, uri)

        val detectedType = detectType(header)

        val detectedMimeType = getMimeType(detectedType)

        val extension = getExtension(fileName)

        val extensionConsistent =
            isExtensionConsistent(
                extension = extension,
                detectedType = detectedType
            )

        val mimeConsistent =
            mimeType == detectedMimeType ||
                    mimeType == "*/*" ||
                    mimeType == "application/octet-stream"

        val knownFormat = detectedType != "UNKNOWN"

        val description = when {

            detectedType == "UNKNOWN" ->
                "Dosya formatı tanınamadı."

            !extensionConsistent ->
                "Dosya uzantısı ile gerçek dosya yapısı uyuşmuyor."

            !mimeConsistent ->
                "Dosyanın MIME type bilgisi gerçek içeriğiyle uyuşmuyor."

            else ->
                "Dosyanın temel dosya yapısı tutarlı görünüyor."
        }

        return FileTypeResult(
            detectedType = detectedType,
            detectedMimeType = detectedMimeType,
            isExtensionConsistent = extensionConsistent,
            isMimeConsistent = mimeConsistent,
            isKnownFormat = knownFormat,
            description = description
        )
    }

    private fun readHeader(
        context: Context,
        uri: Uri
    ): ByteArray {

        val buffer = ByteArray(16)

        context.contentResolver
            .openInputStream(uri)
            ?.use { inputStream ->

                val bytesRead = inputStream.read(buffer)

                if (bytesRead <= 0) {
                    return ByteArray(0)
                }

                return buffer.copyOf(bytesRead)
            }

        return ByteArray(0)
    }

    private fun detectType(
        header: ByteArray
    ): String {

        if (header.size >= 8) {

            if (
                header[0] == 0x89.toByte() &&
                header[1] == 0x50.toByte() &&
                header[2] == 0x4E.toByte() &&
                header[3] == 0x47.toByte() &&
                header[4] == 0x0D.toByte() &&
                header[5] == 0x0A.toByte() &&
                header[6] == 0x1A.toByte() &&
                header[7] == 0x0A.toByte()
            ) {
                return "PNG"
            }
        }

        if (header.size >= 3) {

            if (
                header[0] == 0xFF.toByte() &&
                header[1] == 0xD8.toByte() &&
                header[2] == 0xFF.toByte()
            ) {
                return "JPEG"
            }
        }

        if (header.size >= 6) {

            val text = header.toString(Charsets.US_ASCII)

            if (text.startsWith("%PDF-")) {
                return "PDF"
            }
        }

        if (header.size >= 4) {

            if (
                header[0] == 0x50.toByte() &&
                header[1] == 0x4B.toByte() &&
                header[2] == 0x03.toByte() &&
                header[3] == 0x04.toByte()
            ) {
                return "ZIP"
            }

            if (
                header[0] == 0x50.toByte() &&
                header[1] == 0x4B.toByte() &&
                header[2] == 0x05.toByte() &&
                header[3] == 0x06.toByte()
            ) {
                return "ZIP"
            }
        }

        if (header.size >= 4) {

            if (
                header[0] == 0x7F.toByte() &&
                header[1] == 0x45.toByte() &&
                header[2] == 0x4C.toByte() &&
                header[3] == 0x46.toByte()
            ) {
                return "ELF"
            }
        }

        if (header.size >= 2) {

            if (
                header[0] == 0x4D.toByte() &&
                header[1] == 0x5A.toByte()
            ) {
                return "PE"
            }
        }

        return "UNKNOWN"
    }

    private fun getMimeType(
        detectedType: String
    ): String {

        return when (detectedType) {

            "PNG" ->
                "image/png"

            "JPEG" ->
                "image/jpeg"

            "PDF" ->
                "application/pdf"

            "ZIP" ->
                "application/zip"

            "ELF" ->
                "application/x-executable"

            "PE" ->
                "application/vnd.microsoft.portable-executable"

            else ->
                "application/octet-stream"
        }
    }

    private fun isExtensionConsistent(
        extension: String,
        detectedType: String
    ): Boolean {

        return when (detectedType) {

            "PNG" ->
                extension == "png"

            "JPEG" ->
                extension == "jpg" ||
                        extension == "jpeg"

            "PDF" ->
                extension == "pdf"

            "ZIP" ->
                extension == "zip" ||
                        extension == "apk"

            "ELF" ->
                extension == "so" ||
                        extension == "elf"

            "PE" ->
                extension == "exe" ||
                        extension == "dll"

            else ->
                true
        }
    }

    private fun getExtension(
        fileName: String
    ): String {

        val index = fileName.lastIndexOf('.')

        if (index == -1 || index == fileName.lastIndex) {
            return ""
        }

        return fileName
            .substring(index + 1)
            .lowercase()
    }
}