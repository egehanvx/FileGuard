package egehanvx.fileguard

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest

object FileMetadataAnalyzer {

    suspend fun analyze(
        context: Context,
        uri: Uri
    ): FileMetadata = withContext(Dispatchers.IO) {

        val resolver = context.contentResolver

        val fileName = getFileName(context, uri)
        val fileSize = getFileSize(context, uri)
        val mimeType = resolver.getType(uri) ?: "Bilinmiyor"
        val extension = getExtension(fileName)
        val sha256 = calculateSha256(context, uri)

        FileMetadata(
            fileName = fileName,
            fileSize = fileSize,
            mimeType = mimeType,
            extension = extension,
            sha256 = sha256
        )
    }

    private fun getFileName(
        context: Context,
        uri: Uri
    ): String {

        context.contentResolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null
        )?.use { cursor ->

            val nameIndex =
                cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)

            if (nameIndex >= 0 && cursor.moveToFirst()) {
                val name = cursor.getString(nameIndex)

                if (!name.isNullOrBlank()) {
                    return name
                }
            }
        }

        return "Bilinmeyen dosya"
    }

    private fun getFileSize(
        context: Context,
        uri: Uri
    ): Long {

        context.contentResolver.query(
            uri,
            arrayOf(OpenableColumns.SIZE),
            null,
            null,
            null
        )?.use { cursor ->

            val sizeIndex =
                cursor.getColumnIndex(OpenableColumns.SIZE)

            if (sizeIndex >= 0 && cursor.moveToFirst()) {
                if (!cursor.isNull(sizeIndex)) {
                    return cursor.getLong(sizeIndex)
                }
            }
        }

        return -1L
    }

    private fun getExtension(
        fileName: String
    ): String {

        val dotIndex = fileName.lastIndexOf('.')

        if (dotIndex == -1 || dotIndex == fileName.lastIndex) {
            return ""
        }

        return fileName
            .substring(dotIndex + 1)
            .lowercase()
    }

    private fun calculateSha256(
        context: Context,
        uri: Uri
    ): String {

        val digest = MessageDigest.getInstance("SHA-256")

        context.contentResolver
            .openInputStream(uri)
            ?.use { inputStream ->

                val buffer = ByteArray(8192)

                while (true) {

                    val bytesRead = inputStream.read(buffer)

                    if (bytesRead == -1) {
                        break
                    }

                    digest.update(
                        buffer,
                        0,
                        bytesRead
                    )
                }

            }
            ?: throw IllegalStateException(
                "Dosya okunamadı."
            )

        return digest
            .digest()
            .joinToString("") { byte ->
                "%02x".format(byte)
            }
    }

    fun formatFileSize(
        size: Long
    ): String {

        if (size < 0) {
            return "Bilinmiyor"
        }

        if (size < 1024) {
            return "$size B"
        }

        val kb = size / 1024.0

        if (kb < 1024) {
            return String.format("%.2f KB", kb)
        }

        val mb = kb / 1024.0

        if (mb < 1024) {
            return String.format("%.2f MB", mb)
        }

        val gb = mb / 1024.0

        return String.format("%.2f GB", gb)
    }
}