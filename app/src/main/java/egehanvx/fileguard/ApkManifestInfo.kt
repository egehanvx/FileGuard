package egehanvx.fileguard

data class ApkManifestInfo(
    val packageName: String?,
    val permissions: List<String>,
    val activities: List<String>,
    val services: List<String>,
    val receivers: List<String>,
    val providers: List<String>,
    val exportedComponents: List<String>,
    val suspiciousPermissions: List<String>,
    val suspiciousComponents: List<String>,
    val errorMessage: String? = null
)