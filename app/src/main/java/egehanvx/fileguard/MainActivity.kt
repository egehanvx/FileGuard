package egehanvx.fileguard

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import egehanvx.fileguard.ui.theme.FileGuardTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    private var selectedFileUri by mutableStateOf<Uri?>(null)

    private val filePicker =
        registerForActivityResult(
            ActivityResultContracts.OpenDocument()
        ) { uri ->
            selectedFileUri = uri
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        enableEdgeToEdge()

        setContent {
            FileGuardTheme {
                FileGuardScreen(
                    selectedFileUri = selectedFileUri,
                    onSelectFile = {
                        filePicker.launch(arrayOf("*/*"))
                    }
                )
            }
        }
    }
}

@Composable
fun FileGuardScreen(
    selectedFileUri: Uri?,
    onSelectFile: () -> Unit
) {

    val context = LocalContext.current

    var metadata by remember {
        mutableStateOf<FileMetadata?>(null)
    }

    var fileTypeResult by remember {
        mutableStateOf<FileTypeResult?>(null)
    }

    var apkResult by remember {
        mutableStateOf<ApkAnalysisResult?>(null)
    }

    var riskResult by remember {
        mutableStateOf<RiskAnalysisResult?>(null)
    }

    var scanStage by remember {
        mutableStateOf<ScanStage?>(null)
    }

    var isAnalyzing by remember {
        mutableStateOf(false)
    }

    var errorMessage by remember {
        mutableStateOf<String?>(null)
    }

    LaunchedEffect(selectedFileUri) {

        metadata = null
        fileTypeResult = null
        apkResult = null
        riskResult = null
        scanStage = null
        errorMessage = null

        val uri = selectedFileUri

        if (uri == null) {
            isAnalyzing = false
            return@LaunchedEffect
        }

        isAnalyzing = true

        try {

            scanStage = ScanStage.STARTING

            scanStage = ScanStage.METADATA

            val metadataResult =
                withContext(Dispatchers.IO) {
                    FileMetadataAnalyzer.analyze(
                        context = context,
                        uri = uri
                    )
                }

            metadata = metadataResult

            scanStage = ScanStage.FILE_TYPE

            val typeResult =
                withContext(Dispatchers.IO) {
                    FileTypeAnalyzer.analyze(
                        context = context,
                        uri = uri,
                        fileName = metadataResult.fileName,
                        mimeType = metadataResult.mimeType
                    )
                }

            fileTypeResult = typeResult

            var apkAnalysis: ApkAnalysisResult? = null

            if (
                metadataResult.extension.equals(
                    "apk",
                    ignoreCase = true
                )
            ) {

                scanStage = ScanStage.APK_ANALYSIS

                apkAnalysis =
                    ApkAnalyzer.analyze(
                        context = context,
                        uri = uri
                    )

                apkResult = apkAnalysis
            }

            scanStage = ScanStage.RISK_ANALYSIS

            val calculatedRisk =
                withContext(Dispatchers.Default) {
                    RiskAnalyzer.analyze(
                        metadata = metadataResult,
                        fileType = typeResult,
                        apk = apkAnalysis
                    )
                }

            riskResult = calculatedRisk

            scanStage = ScanStage.COMPLETE

        } catch (exception: Exception) {

            errorMessage =
                exception.message
                    ?.takeIf {
                        it.isNotBlank()
                    }
                    ?: "Dosya analiz edilirken bir hata oluştu."

            scanStage = null

        } finally {

            isAnalyzing = false
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = Color(0xFF080B12)
    ) { innerPadding ->

        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF080B12),
                            Color(0xFF101925),
                            Color(0xFF080B12)
                        )
                    )
                )
                .padding(innerPadding)
        ) {

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(
                    start = 20.dp,
                    end = 20.dp,
                    top = 24.dp,
                    bottom = 30.dp
                ),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {

                item {

                    HeaderSection()
                }

                item {

                    FileSelectionCard(
                        hasFile = selectedFileUri != null,
                        isAnalyzing = isAnalyzing,
                        onSelectFile = onSelectFile
                    )
                }

                if (isAnalyzing && scanStage != null) {

                    item {

                        ScanProgressCard(
                            stage = scanStage!!
                        )
                    }
                }

                if (errorMessage != null) {

                    item {

                        ErrorCard(
                            message = errorMessage!!
                        )
                    }
                }

                if (metadata != null) {

                    item {

                        MetadataCard(
                            metadata = metadata!!
                        )
                    }
                }

                if (fileTypeResult != null && !isAnalyzing) {

                    item {

                        FileTypeCard(
                            result = fileTypeResult!!
                        )
                    }
                }

                if (
                    apkResult != null &&
                    !isAnalyzing
                ) {

                    item {

                        ApkAnalysisCard(
                            result = apkResult!!
                        )
                    }
                }

                if (
                    riskResult != null &&
                    !isAnalyzing
                ) {

                    item {

                        RiskCard(
                            result = riskResult!!
                        )
                    }
                }

                item {

                    PrivacyCard()
                }
            }
        }
    }
}

@Composable
fun HeaderSection() {

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        Text(
            text = "FILEGUARD",
            color = Color(0xFF65E6A8),
            fontSize = 30.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(
            modifier = Modifier.height(8.dp)
        )

        Text(
            text = "Dosya Güvenlik Analizörü",
            color = Color.White,
            fontSize = 23.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center
        )

        Spacer(
            modifier = Modifier.height(8.dp)
        )

        Text(
            text = "Dosyalarını cihaz üzerinde statik güvenlik analizinden geçir.",
            color = Color(0xFFA5AFBF),
            fontSize = 14.sp,
            lineHeight = 21.sp,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
fun FileSelectionCard(
    hasFile: Boolean,
    isAnalyzing: Boolean,
    onSelectFile: () -> Unit
) {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF141B27)
        )
    ) {

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(22.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Text(
                text = when {

                    isAnalyzing ->
                        "Dosya Analiz Ediliyor"

                    hasFile ->
                        "Dosya Seçildi"

                    else ->
                        "Dosyanı Güvenlik Taramasına Gönder"
                },
                color = Color.White,
                fontSize = 19.sp,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center
            )

            Spacer(
                modifier = Modifier.height(9.dp)
            )

            Text(
                text = when {

                    isAnalyzing ->
                        "Dosyanın güvenlik özellikleri inceleniyor."

                    hasFile ->
                        "Analiz tamamlandı. Sonuçları aşağıda inceleyebilirsin."

                    else ->
                        "Cihazından bir dosya seçerek statik güvenlik analizini başlat."
                },
                color = Color(0xFF9BA5B5),
                fontSize = 13.sp,
                lineHeight = 20.sp,
                textAlign = TextAlign.Center
            )

            Spacer(
                modifier = Modifier.height(18.dp)
            )

            Button(
                onClick = onSelectFile,
                enabled = !isAnalyzing,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF65E6A8),
                    contentColor = Color(0xFF08110C)
                )
            ) {

                Text(
                    text = if (hasFile) {
                        "Başka Dosya Seç"
                    } else {
                        "Dosya Seç"
                    },
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

@Composable
fun ScanProgressCard(
    stage: ScanStage
) {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF111A25)
        )
    ) {

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            CircularProgressIndicator(
                color = Color(0xFF65E6A8),
                trackColor = Color(0xFF26342F)
            )

            Spacer(
                modifier = Modifier.height(18.dp)
            )

            Text(
                text = stage.title,
                color = Color.White,
                fontSize = 19.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Text(
                text = stage.description,
                color = Color(0xFFA5AFBF),
                fontSize = 13.sp,
                lineHeight = 20.sp,
                textAlign = TextAlign.Center
            )

            Spacer(
                modifier = Modifier.height(15.dp)
            )

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Text(
                    text = "${stage.progress}%",
                    color = Color(0xFF65E6A8),
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(
                    modifier = Modifier.width(8.dp)
                )

                Text(
                    text = "analiz aşaması",
                    color = Color(0xFF7F8997),
                    fontSize = 12.sp
                )
            }
        }
    }
}

@Composable
fun ErrorCard(
    message: String
) {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF2A1719)
        )
    ) {

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {

            Text(
                text = "ANALİZ HATASI",
                color = Color(0xFFFF7777),
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Text(
                text = message,
                color = Color(0xFFF0CCCC),
                fontSize = 14.sp,
                lineHeight = 20.sp
            )
        }
    }
}

@Composable
fun MetadataCard(
    metadata: FileMetadata
) {

    AnalysisCard(
        title = "DOSYA BİLGİLERİ"
    ) {

        InfoRow(
            label = "Dosya adı",
            value = metadata.fileName
        )

        InfoRow(
            label = "Boyut",
            value = FileMetadataAnalyzer.formatFileSize(
                metadata.fileSize
            )
        )

        InfoRow(
            label = "MIME type",
            value = metadata.mimeType
        )

        InfoRow(
            label = "Uzantı",
            value = if (
                metadata.extension.isBlank()
            ) {
                "Yok"
            } else {
                metadata.extension
            }
        )

        Spacer(
            modifier = Modifier.height(10.dp)
        )

        Text(
            text = "SHA-256",
            color = Color(0xFF7E8998),
            fontSize = 12.sp
        )

        Spacer(
            modifier = Modifier.height(4.dp)
        )

        Text(
            text = metadata.sha256,
            color = Color(0xFF65E6A8),
            fontSize = 11.sp,
            lineHeight = 17.sp
        )
    }
}

@Composable
fun FileTypeCard(
    result: FileTypeResult
) {

    val statusColor =
        when {

            !result.isKnownFormat ->
                Color(0xFFFFC857)

            !result.isExtensionConsistent ||
                    !result.isMimeConsistent ->
                Color(0xFFFFA45C)

            else ->
                Color(0xFF65E6A8)
        }

    val statusText =
        when {

            !result.isKnownFormat ->
                "FORMAT TANINAMADI"

            !result.isExtensionConsistent ||
                    !result.isMimeConsistent ->
                "UYUMSUZLUK TESPİT EDİLDİ"

            else ->
                "DOSYA YAPISI TUTARLI"
        }

    AnalysisCard(
        title = "DOSYA TÜRÜ ANALİZİ"
    ) {

        Text(
            text = statusText,
            color = statusColor,
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(
            modifier = Modifier.height(10.dp)
        )

        InfoRow(
            label = "Algılanan format",
            value = result.detectedType
        )

        InfoRow(
            label = "Algılanan MIME",
            value = result.detectedMimeType
        )

        Spacer(
            modifier = Modifier.height(6.dp)
        )

        Text(
            text = result.description,
            color = Color(0xFFA5AFBF),
            fontSize = 13.sp,
            lineHeight = 20.sp
        )
    }
}

@Composable
fun ApkAnalysisCard(
    result: ApkAnalysisResult
) {

    AnalysisCard(
        title = "APK STATİK ANALİZİ"
    ) {

        InfoRow(
            label = "APK yapısı",
            value = if (
                result.isApkStructureValid
            ) {
                "Okunabilir"
            } else {
                "Okunamadı"
            }
        )

        InfoRow(
            label = "AndroidManifest",
            value = if (
                result.hasManifest
            ) {
                "Bulundu"
            } else {
                "Bulunamadı"
            }
        )

        InfoRow(
            label = "DEX",
            value = result.dexFileCount.toString()
        )

        InfoRow(
            label = "Native library",
            value = result.nativeLibraryCount.toString()
        )

        InfoRow(
            label = "Asset",
            value = result.assetCount.toString()
        )

        InfoRow(
            label = "Resource",
            value = result.resourceFileCount.toString()
        )

        result.manifestInfo?.let { manifest ->

            Spacer(
                modifier = Modifier.height(16.dp)
            )

            SectionTitle(
                text = "MANIFEST ANALİZİ"
            )

            InfoRow(
                label = "Package",
                value = manifest.packageName
                    ?: "Bilinmiyor"
            )

            InfoRow(
                label = "Permission",
                value = manifest.permissions.size.toString()
            )

            InfoRow(
                label = "Activity",
                value = manifest.activities.size.toString()
            )

            InfoRow(
                label = "Service",
                value = manifest.services.size.toString()
            )

            InfoRow(
                label = "Receiver",
                value = manifest.receivers.size.toString()
            )

            InfoRow(
                label = "Provider",
                value = manifest.providers.size.toString()
            )

            InfoRow(
                label = "Exported",
                value = manifest.exportedComponents.size.toString()
            )

            if (
                manifest.suspiciousPermissions.isNotEmpty()
            ) {

                Spacer(
                    modifier = Modifier.height(12.dp)
                )

                SectionTitle(
                    text = "DİKKAT GEREKTİREN İZİNLER"
                )

                manifest.suspiciousPermissions.forEach { permission ->

                    FindingText(
                        text = permission
                    )
                }
            }

            if (
                manifest.suspiciousComponents.isNotEmpty()
            ) {

                Spacer(
                    modifier = Modifier.height(12.dp)
                )

                SectionTitle(
                    text = "ŞÜPHELİ COMPONENTLER"
                )

                manifest.suspiciousComponents.forEach { component ->

                    FindingText(
                        text = component
                    )
                }
            }

            if (
                manifest.exportedComponents.isNotEmpty()
            ) {

                Spacer(
                    modifier = Modifier.height(12.dp)
                )

                SectionTitle(
                    text = "EXPORTED COMPONENTLER"
                )

                manifest.exportedComponents.forEach { component ->

                    FindingText(
                        text = component,
                        color = Color(0xFFB4BEC9)
                    )
                }
            }
        }

        result.dexAnalysis?.let { dex ->

            Spacer(
                modifier = Modifier.height(16.dp)
            )

            SectionTitle(
                text = "DEX ANALİZİ"
            )

            InfoRow(
                label = "DEX sayısı",
                value = dex.dexFileCount.toString()
            )

            InfoRow(
                label = "String sayısı",
                value = dex.stringCount.toString()
            )

            InfoRow(
                label = "Pattern eşleşmesi",
                value = dex.matchedPatterns.size.toString()
            )

            if (
                dex.matchedPatterns.isNotEmpty()
            ) {

                Spacer(
                    modifier = Modifier.height(10.dp)
                )

                SectionTitle(
                    text = "EŞLEŞEN PATTERNLER"
                )

                dex.matchedPatterns.forEach { pattern ->

                    FindingText(
                        text = pattern
                    )
                }
            }

            if (
                dex.suspiciousFindings.isNotEmpty()
            ) {

                Spacer(
                    modifier = Modifier.height(10.dp)
                )

                SectionTitle(
                    text = "DEX BULGULARI"
                )

                dex.suspiciousFindings.forEach { finding ->

                    FindingText(
                        text = finding
                    )
                }
            }

            dex.errorMessage?.let { error ->

                FindingText(
                    text = error,
                    color = Color(0xFFFF7777)
                )
            }
        }

        if (
            result.nativeLibraries.isNotEmpty()
        ) {

            Spacer(
                modifier = Modifier.height(16.dp)
            )

            SectionTitle(
                text = "NATIVE LIBRARYLER"
            )

            result.nativeLibraries.forEach { library ->

                FindingText(
                    text = library,
                    color = Color(0xFFB4BEC9)
                )
            }
        }

        if (
            result.suspiciousStructureFindings.isNotEmpty()
        ) {

            Spacer(
                modifier = Modifier.height(16.dp)
            )

            SectionTitle(
                text = "YAPISAL BULGULAR"
            )

            result.suspiciousStructureFindings.forEach { finding ->

                FindingText(
                    text = finding
                )
            }
        }

        result.errorMessage?.let { error ->

            Spacer(
                modifier = Modifier.height(10.dp)
            )

            FindingText(
                text = error,
                color = Color(0xFFFF7777)
            )
        }
    }
}

@Composable
fun RiskCard(
    result: RiskAnalysisResult
) {

    val riskColor =
        when (result.level) {

            RiskLevel.SAFE ->
                Color(0xFF65E6A8)

            RiskLevel.LOW ->
                Color(0xFF8FD694)

            RiskLevel.SUSPICIOUS ->
                Color(0xFFFFC857)

            RiskLevel.HIGH ->
                Color(0xFFFF6969)
        }

    val riskTitle =
        when (result.level) {

            RiskLevel.SAFE ->
                "GÜVENLİ GÖRÜNÜYOR"

            RiskLevel.LOW ->
                "DÜŞÜK RİSK"

            RiskLevel.SUSPICIOUS ->
                "ŞÜPHELİ"

            RiskLevel.HIGH ->
                "YÜKSEK RİSK"
        }

    AnalysisCard(
        title = "RİSK DEĞERLENDİRMESİ"
    ) {

        Text(
            text = riskTitle,
            modifier = Modifier.fillMaxWidth(),
            color = riskColor,
            fontSize = 23.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center
        )

        Spacer(
            modifier = Modifier.height(8.dp)
        )

        Text(
            text = "${result.score}/100",
            modifier = Modifier.fillMaxWidth(),
            color = Color.White,
            fontSize = 30.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center
        )

        Spacer(
            modifier = Modifier.height(10.dp)
        )

        Text(
            text = result.summary,
            modifier = Modifier.fillMaxWidth(),
            color = Color(0xFFA5AFBF),
            fontSize = 13.sp,
            lineHeight = 20.sp,
            textAlign = TextAlign.Center
        )

        if (
            result.findings.isNotEmpty()
        ) {

            Spacer(
                modifier = Modifier.height(15.dp)
            )

            SectionTitle(
                text = "${result.findings.size} RİSK BULGUSU"
            )

            result.findings.forEach { finding ->

                Spacer(
                    modifier = Modifier.height(7.dp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.Top
                ) {

                    Text(
                        text = finding.title,
                        color = Color.White,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.weight(1f)
                    )

                    Text(
                        text = "+${finding.points}",
                        color = riskColor,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Text(
                    text = finding.description,
                    color = Color(0xFF8995A5),
                    fontSize = 11.sp,
                    lineHeight = 17.sp
                )
            }
        }
    }
}

@Composable
fun AnalysisCard(
    title: String,
    content: @Composable () -> Unit
) {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF141B27)
        )
    ) {

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {

            Text(
                text = title,
                color = Color(0xFF65E6A8),
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(
                modifier = Modifier.height(10.dp)
            )

            content()
        }
    }
}

@Composable
fun SectionTitle(
    text: String
) {

    Text(
        text = text,
        color = Color(0xFF65E6A8),
        fontSize = 12.sp,
        fontWeight = FontWeight.Bold
    )
}

@Composable
fun FindingText(
    text: String,
    color: Color = Color(0xFFFFC857)
) {

    Text(
        text = "• $text",
        color = color,
        fontSize = 11.sp,
        lineHeight = 17.sp
    )

    Spacer(
        modifier = Modifier.height(4.dp)
    )
}

@Composable
fun InfoRow(
    label: String,
    value: String
) {

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                vertical = 4.dp
            )
    ) {

        Text(
            text = label,
            color = Color(0xFF7E8998),
            fontSize = 11.sp
        )

        Spacer(
            modifier = Modifier.height(2.dp)
        )

        Text(
            text = value,
            color = Color.White,
            fontSize = 13.sp,
            lineHeight = 18.sp
        )
    }
}

@Composable
fun PrivacyCard() {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF10161F)
        )
    ) {

        Text(
            text = "Bu sürümde dosyalar cihaz üzerinde analiz edilir. Otomatik olarak çevrimiçi bir servise gönderilmez.",
            modifier = Modifier.padding(18.dp),
            color = Color(0xFF7D8999),
            fontSize = 12.sp,
            lineHeight = 18.sp,
            textAlign = TextAlign.Center
        )
    }
}