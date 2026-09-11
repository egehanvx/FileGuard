package egehanvx.fileguard

data class FileMetadata(
    val fileName: String,
    val fileSize: Long,
    val mimeType: String,
    val extension: String,
    val sha256: String
)