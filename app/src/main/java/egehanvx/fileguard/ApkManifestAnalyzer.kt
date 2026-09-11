package egehanvx.fileguard

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

object ApkManifestAnalyzer {

    private const val RES_XML_TYPE = 0x0003
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102

    private const val TYPE_STRING = 0x03

    private val suspiciousPermissionWeights = mapOf(
        "android.permission.READ_SMS" to 4,
        "android.permission.RECEIVE_SMS" to 4,
        "android.permission.SEND_SMS" to 4,
        "android.permission.READ_CALL_LOG" to 3,
        "android.permission.WRITE_CALL_LOG" to 3,
        "android.permission.READ_CONTACTS" to 2,
        "android.permission.WRITE_CONTACTS" to 2,
        "android.permission.RECORD_AUDIO" to 3,
        "android.permission.CAMERA" to 1,
        "android.permission.ACCESS_FINE_LOCATION" to 2,
        "android.permission.ACCESS_COARSE_LOCATION" to 1,
        "android.permission.READ_PHONE_STATE" to 2,
        "android.permission.CALL_PHONE" to 3,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 4,
        "android.permission.SYSTEM_ALERT_WINDOW" to 4,
        "android.permission.RECEIVE_BOOT_COMPLETED" to 2,
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 5,
        "android.permission.READ_EXTERNAL_STORAGE" to 1,
        "android.permission.WRITE_EXTERNAL_STORAGE" to 1
    )

    suspend fun analyzeManifest(
        zipFile: ZipFile
    ): ApkManifestInfo {

        return try {

            val entry =
                zipFile.getEntry("AndroidManifest.xml")
                    ?: return ApkManifestInfo(
                        packageName = null,
                        permissions = emptyList(),
                        activities = emptyList(),
                        services = emptyList(),
                        receivers = emptyList(),
                        providers = emptyList(),
                        exportedComponents = emptyList(),
                        suspiciousPermissions = emptyList(),
                        suspiciousComponents = emptyList(),
                        errorMessage =
                            "AndroidManifest.xml bulunamadı."
                    )

            val bytes =
                zipFile.getInputStream(entry).use {
                    it.readBytes()
                }

            parse(bytes)

        } catch (exception: Exception) {

            ApkManifestInfo(
                packageName = null,
                permissions = emptyList(),
                activities = emptyList(),
                services = emptyList(),
                receivers = emptyList(),
                providers = emptyList(),
                exportedComponents = emptyList(),
                suspiciousPermissions = emptyList(),
                suspiciousComponents = emptyList(),
                errorMessage =
                    exception.message
                        ?: "Manifest analiz edilemedi."
            )
        }
    }

    private fun parse(
        bytes: ByteArray
    ): ApkManifestInfo {

        if (bytes.size < 8) {
            throw IllegalStateException(
                "Manifest dosyası geçersiz."
            )
        }

        val reader = BinaryReader(bytes)

        val xmlType = reader.readU16()

        reader.readU16()
        reader.readU32()

        if (xmlType != RES_XML_TYPE) {
            throw IllegalStateException(
                "Dosya binary Android XML formatında değil."
            )
        }

        val strings = mutableListOf<String>()

        var packageName: String? = null

        val permissions = mutableListOf<String>()
        val activities = mutableListOf<String>()
        val services = mutableListOf<String>()
        val receivers = mutableListOf<String>()
        val providers = mutableListOf<String>()
        val exportedComponents = mutableListOf<String>()

        val suspiciousComponents = mutableListOf<String>()

        while (reader.remaining >= 8) {

            val chunkStart = reader.position

            val chunkType = reader.readU16()
            val headerSize = reader.readU16()
            val chunkSize = reader.readU32()

            if (chunkSize < headerSize || chunkSize <= 0) {
                break
            }

            when (chunkType) {

                RES_STRING_POOL_TYPE -> {

                    val stringCount = reader.readU32()
                    val styleCount = reader.readU32()
                    val flags = reader.readU32()
                    val stringsStart = reader.readU32()

                    repeat(styleCount) {
                        reader.readU32()
                    }

                    val offsets = IntArray(stringCount)

                    repeat(stringCount) { index ->
                        offsets[index] =
                            reader.readU32()
                    }

                    val stringDataStart =
                        chunkStart + stringsStart

                    strings.clear()

                    repeat(stringCount) { index ->

                        val absolute =
                            stringDataStart + offsets[index]

                        strings.add(
                            readStringAt(
                                bytes = bytes,
                                offset = absolute,
                                utf8 = (flags and 0x00000100) != 0
                            )
                        )
                    }
                }

                RES_XML_START_ELEMENT_TYPE -> {

                    if (headerSize < 16) {
                        skipTo(
                            reader,
                            chunkStart + chunkSize
                        )
                        continue
                    }

                    reader.readU32()
                    reader.readU32()

                    val nameIndex =
                        reader.readU32()

                    reader.readU16()
                    reader.readU16()

                    val attributeCount =
                        reader.readU16()

                    reader.readU16()
                    reader.readU16()
                    reader.readU16()

                    val tagName =
                        strings.getOrNull(nameIndex)

                            ?: run {
                                skipTo(
                                    reader,
                                    chunkStart + chunkSize
                                )
                                continue
                            }

                    val attributes =
                        mutableMapOf<String, String>()

                    repeat(attributeCount) {

                        reader.readU32()

                        val attrNameIndex =
                            reader.readU32()

                        val rawValueIndex =
                            reader.readU32()

                        reader.readU16()
                        reader.readByte()

                        val valueType =
                            reader.readByte()

                        val valueData =
                            reader.readU32()

                        val attrName =
                            strings.getOrNull(
                                attrNameIndex
                            ) ?: ""

                        val rawValue =
                            if (rawValueIndex != -1) {

                                strings.getOrNull(
                                    rawValueIndex
                                )

                            } else {

                                null
                            }

                        val typedValue =
                            if (
                                valueType == TYPE_STRING
                            ) {

                                strings.getOrNull(
                                    valueData
                                )

                            } else {

                                valueData.toString()
                            }

                        attributes[attrName] =
                            rawValue
                                ?: typedValue
                                        ?: ""
                    }

                    when (tagName) {

                        "manifest" -> {

                            packageName =
                                attributes["package"]
                        }

                        "uses-permission",
                        "uses-permission-sdk-23",
                        "uses-permission-sdk-m",
                        "uses-permission-sdk-28" -> {

                            val permission =
                                attributes["name"]

                            if (
                                !permission.isNullOrBlank()
                            ) {
                                permissions.add(permission)
                            }
                        }

                        "activity" -> {

                            val name =
                                attributes["name"]

                            if (!name.isNullOrBlank()) {

                                activities.add(name)

                                checkExported(
                                    tagName = "activity",
                                    name = name,
                                    attributes = attributes,
                                    output = exportedComponents
                                )
                            }
                        }

                        "service" -> {

                            val name =
                                attributes["name"]

                            if (!name.isNullOrBlank()) {

                                services.add(name)

                                checkExported(
                                    tagName = "service",
                                    name = name,
                                    attributes = attributes,
                                    output = exportedComponents
                                )

                                if (
                                    name.contains(
                                        "accessibility",
                                        ignoreCase = true
                                    )
                                ) {

                                    suspiciousComponents.add(
                                        "Accessibility benzeri service: $name"
                                    )
                                }
                            }
                        }

                        "receiver" -> {

                            val name =
                                attributes["name"]

                            if (!name.isNullOrBlank()) {

                                receivers.add(name)

                                checkExported(
                                    tagName = "receiver",
                                    name = name,
                                    attributes = attributes,
                                    output = exportedComponents
                                )
                            }
                        }

                        "provider" -> {

                            val name =
                                attributes["name"]

                            if (!name.isNullOrBlank()) {

                                providers.add(name)

                                checkExported(
                                    tagName = "provider",
                                    name = name,
                                    attributes = attributes,
                                    output = exportedComponents
                                )
                            }
                        }
                    }

                    skipTo(
                        reader,
                        chunkStart + chunkSize
                    )
                }

                else -> {

                    skipTo(
                        reader,
                        chunkStart + chunkSize
                    )
                }
            }
        }

        val suspiciousPermissions =
            permissions
                .filter {
                    suspiciousPermissionWeights.containsKey(it)
                }
                .distinct()

        return ApkManifestInfo(
            packageName = packageName,
            permissions = permissions.distinct(),
            activities = activities.distinct(),
            services = services.distinct(),
            receivers = receivers.distinct(),
            providers = providers.distinct(),
            exportedComponents = exportedComponents.distinct(),
            suspiciousPermissions = suspiciousPermissions,
            suspiciousComponents = suspiciousComponents.distinct()
        )
    }

    private fun checkExported(
        tagName: String,
        name: String,
        attributes: Map<String, String>,
        output: MutableList<String>
    ) {

        val exported =
            attributes["exported"]

        if (exported == "true") {

            output.add(
                "$tagName: $name"
            )
        }
    }

    private fun readStringAt(
        bytes: ByteArray,
        offset: Int,
        utf8: Boolean
    ): String {

        if (offset >= bytes.size) {
            return ""
        }

        val input =
            ByteArrayInputStream(
                bytes,
                offset,
                bytes.size - offset
            )

        return if (utf8) {

            val utf8Length =
                readLength8(input)

            readLength8(input)

            val raw =
                ByteArray(utf8Length)

            val read =
                input.read(raw)

            if (read <= 0) {
                ""
            } else {
                String(
                    raw,
                    0,
                    read,
                    Charsets.UTF_8
                )
            }

        } else {

            val charCount =
                readLength16(input)

            val raw =
                ByteArray(charCount * 2)

            val read =
                input.read(raw)

            if (read <= 0) {
                ""
            } else {

                String(
                    raw,
                    0,
                    read - (read % 2),
                    Charsets.UTF_16LE
                )
            }
        }
    }

    private fun readLength8(
        input: ByteArrayInputStream
    ): Int {

        val first =
            input.read()

        if (first == -1) {
            return 0
        }

        return if ((first and 0x80) != 0) {

            val second =
                input.read()

            ((first and 0x7F) shl 7) or
                    (second and 0x7F)

        } else {

            first
        }
    }

    private fun readLength16(
        input: ByteArrayInputStream
    ): Int {

        val low =
            input.read()

        val high =
            input.read()

        if (low == -1 || high == -1) {
            return 0
        }

        return if ((high and 0x80) != 0) {

            val low2 =
                input.read()

            val high2 =
                input.read()

            ((low and 0x7F) shl 8) or
                    low2 or
                    ((high2 and 0x7F) shl 8)

        } else {

            low or (high shl 8)
        }
    }

    private fun skipTo(
        reader: BinaryReader,
        target: Int
    ) {

        if (target > reader.position) {
            reader.skip(
                target - reader.position
            )
        }
    }

    private class BinaryReader(
        private val bytes: ByteArray
    ) {

        private val buffer =
            ByteBuffer
                .wrap(bytes)
                .order(ByteOrder.LITTLE_ENDIAN)

        val position: Int
            get() = buffer.position()

        val remaining: Int
            get() = buffer.remaining()

        fun readByte(): Int {
            return buffer.get().toInt() and 0xFF
        }

        fun readU16(): Int {
            return buffer.short.toInt() and 0xFFFF
        }

        fun readU32(): Int {
            return buffer.int
        }

        fun skip(count: Int) {

            val newPosition =
                (buffer.position() + count)
                    .coerceAtMost(buffer.limit())

            buffer.position(newPosition)
        }
    }
}