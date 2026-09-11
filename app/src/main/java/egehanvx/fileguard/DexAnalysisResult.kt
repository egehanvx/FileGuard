package egehanvx.fileguard

data class DexAnalysisResult(
    val dexFileCount: Int,
    val suspiciousFindings: List<String>,
    val matchedPatterns: List<String>,
    val stringCount: Int,
    val errorMessage: String? = null
)