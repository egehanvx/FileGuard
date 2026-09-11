package egehanvx.fileguard

data class RiskAnalysisResult(
    val score: Int,
    val level: RiskLevel,
    val findings: List<RiskFinding>,
    val summary: String
)

enum class RiskLevel {
    SAFE,
    LOW,
    SUSPICIOUS,
    HIGH
}

data class RiskFinding(
    val title: String,
    val description: String,
    val points: Int
)