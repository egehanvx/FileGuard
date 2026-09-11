package egehanvx.fileguard

data class ApkAnalysisResult(
    val isApkStructureValid: Boolean,
    val hasManifest: Boolean,
    val hasDex: Boolean,
    val dexFileCount: Int,
    val nativeLibraryCount: Int,
    val nativeLibraries: List<String>,
    val assetCount: Int,
    val resourceFileCount: Int,
    val suspiciousStructureFindings: List<String>,
    val manifestInfo: ApkManifestInfo? = null,
    val dexAnalysis: DexAnalysisResult? = null,
    val errorMessage: String? = null
)