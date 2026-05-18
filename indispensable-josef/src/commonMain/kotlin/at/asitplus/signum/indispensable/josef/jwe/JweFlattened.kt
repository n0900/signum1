package at.asitplus.signum.indispensable.josef.jwe

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlNoPaddingSerializer
import at.asitplus.signum.indispensable.josef.JweHeader
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Flattened JSON JWE serialization.
 *
 * A flattened JWE carries one encrypted content value and one recipient. Unprotected header parameters can be split
 * between the shared [sharedUnprotectedHeader] and per-recipient [recipientUnprotectedHeader] locations.
 */
@ConsistentCopyVisibility
@Serializable
data class JweFlattened internal constructor(
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.PROTECTED)
    val plainProtectedHeader: ByteArray? = null,
    @SerialName(SerialNames.UNPROTECTED)
    val sharedUnprotectedHeader: JweHeader.Part? = null,
    @SerialName(SerialNames.HEADER)
    val recipientUnprotectedHeader: JweHeader.Part? = null,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.ENCRYPTED_KEY)
    val encryptedKey: ByteArray? = null,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.AAD)
    val additionalAuthenticatedData: ByteArray? = null,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.INITIALIZATION_VECTOR)
    val initializationVector: ByteArray? = null,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.CIPHERTEXT)
    val ciphertext: ByteArray,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.AUTHENTICATION_TAG)
    val authenticationTag: ByteArray? = null,
) : JWE() {

    init {
        JweProtectedHeaderSerializer.requireAbsentIfEmpty(plainProtectedHeader)
        requireAbsentIfEmpty(sharedUnprotectedHeader, SerialNames.UNPROTECTED)
        requireAbsentIfEmpty(recipientUnprotectedHeader, SerialNames.HEADER)
        requireAbsentIfEmpty(encryptedKey, SerialNames.ENCRYPTED_KEY)
        requireAbsentIfEmpty(additionalAuthenticatedData, SerialNames.AAD)
        requireAbsentIfEmpty(initializationVector, SerialNames.INITIALIZATION_VECTOR)
        requireAbsentIfEmpty(authenticationTag, SerialNames.AUTHENTICATION_TAG)
    }

    @Transient
    val jweHeader: JweHeader = JweHeader.fromParts(
        plainProtectedHeader,
        sharedUnprotectedHeader,
        recipientUnprotectedHeader,
    )

    @Transient
    val additionalAuthenticatedDataInput: ByteArray =
        getAdditionalAuthenticatedData(plainProtectedHeader, additionalAuthenticatedData)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JweFlattened

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (sharedUnprotectedHeader != other.sharedUnprotectedHeader) return false
        if (recipientUnprotectedHeader != other.recipientUnprotectedHeader) return false
        if (!encryptedKey.contentEquals(other.encryptedKey)) return false
        if (!additionalAuthenticatedData.contentEquals(other.additionalAuthenticatedData)) return false
        if (!initializationVector.contentEquals(other.initializationVector)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!authenticationTag.contentEquals(other.authenticationTag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader?.contentHashCode() ?: 0
        result = 31 * result + (sharedUnprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (recipientUnprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (encryptedKey?.contentHashCode() ?: 0)
        result = 31 * result + (additionalAuthenticatedData?.contentHashCode() ?: 0)
        result = 31 * result + (initializationVector?.contentHashCode() ?: 0)
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + (authenticationTag?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        /**
         * Creates a flattened JWE from protected and unprotected header fragments plus encrypted components.
         */
        operator fun invoke(
            protectedHeader: JweHeader.Part?,
            sharedUnprotectedHeader: JweHeader.Part? = null,
            recipientUnprotectedHeader: JweHeader.Part? = null,
            encryptedKey: ByteArray? = null,
            additionalAuthenticatedData: ByteArray? = null,
            initializationVector: ByteArray? = null,
            ciphertext: ByteArray,
            authenticationTag: ByteArray? = null,
        ): JweFlattened {
            val plainProtectedHeader = JweProtectedHeaderSerializer.encodeToByteArrayOrNull(protectedHeader)
            return JweFlattened(
                plainProtectedHeader = plainProtectedHeader,
                sharedUnprotectedHeader = sharedUnprotectedHeader?.takeUnless { it.toJsonObject().isEmpty() },
                recipientUnprotectedHeader = recipientUnprotectedHeader?.takeUnless { it.toJsonObject().isEmpty() },
                encryptedKey = encryptedKey.takeUnlessEmpty(),
                additionalAuthenticatedData = additionalAuthenticatedData.takeUnlessEmpty(),
                initializationVector = initializationVector.takeUnlessEmpty(),
                ciphertext = ciphertext,
                authenticationTag = authenticationTag.takeUnlessEmpty(),
            )
        }
    }
}

val JweFlattened.protectedHeader: JweHeader.Part?
    get() = plainProtectedHeader?.let(JweProtectedHeaderSerializer::decodeFromByteArray)

/**
 * Converts flattened JSON serialization to compact serialization.
 */
fun JweFlattened.toJweCompact(): JweCompact {
    require(sharedUnprotectedHeader == null) { "Compact Serialization does not support shared unprotected header" }
    require(recipientUnprotectedHeader == null) { "Compact Serialization does not support per-recipient unprotected header" }
    require(additionalAuthenticatedData == null) { "Compact Serialization does not support JWE AAD" }
    requireNotNull(plainProtectedHeader)
    runCatching { JweHeader.fromParts(protectedHeader) }.getOrElse {
        throw IllegalArgumentException("Compact JWE requires protected header to be a valid JweHeader")
    }
    return JweCompact(
        plainProtectedHeader = plainProtectedHeader,
        encryptedKey = encryptedKey,
        initializationVector = initializationVector,
        ciphertext = ciphertext,
        authenticationTag = authenticationTag,
    )
}

/**
 * Converts multiple flattened JWE values with the same shared encrypted content into general JSON JWE representation.
 */
fun List<JweFlattened>.toJweGeneral(): JweGeneral {
    require(isNotEmpty()) { "General JWE requires at least one recipient" }
    val first = this[0]
    val recipients = map {
        require(first.hasSameSharedContentAs(it)) {
            "Additional encrypted JWE content must match existing content"
        }
        RecipientElement(
            unprotectedHeader = it.recipientUnprotectedHeader,
            encryptedKey = it.encryptedKey,
        )
    }
    return JweGeneral(
        plainProtectedHeader = first.plainProtectedHeader,
        sharedUnprotectedHeader = first.sharedUnprotectedHeader,
        recipientElements = recipients,
        additionalAuthenticatedData = first.additionalAuthenticatedData,
        initializationVector = first.initializationVector,
        ciphertext = first.ciphertext,
        authenticationTag = first.authenticationTag,
    )
}

internal fun JweFlattened.hasSameSharedContentAs(other: JweFlattened): Boolean =
    plainProtectedHeader.contentEquals(other.plainProtectedHeader) &&
            sharedUnprotectedHeader == other.sharedUnprotectedHeader &&
            additionalAuthenticatedData.contentEquals(other.additionalAuthenticatedData) &&
            initializationVector.contentEquals(other.initializationVector) &&
            ciphertext.contentEquals(other.ciphertext) &&
            authenticationTag.contentEquals(other.authenticationTag)
