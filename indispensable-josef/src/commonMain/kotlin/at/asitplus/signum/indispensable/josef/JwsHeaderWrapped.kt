package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializer

/**
 * An effective [JwsHeaderBase] together with the names of the members carried in its unprotected fragment.
 *
 * Member placement belongs to a concrete JSON JWS representation rather than to the modeled [header]. The
 * serializer is retained as a capability so that the protected and unprotected fragments can be produced even
 * after [H] has been erased at runtime.
 */
data class JwsHeaderWrapped<out H : JwsHeaderBase>(
    val header: H,
    val unprotectedMembers: Set<String>,
    private val headerSerializer: KSerializer<H>,
) {

    private fun serializedHeader(): JsonObject =
        joseCompliantSerializer.encodeToJsonElement(headerSerializer, header).jsonObject

    /** Names requested as unprotected that are represented by the modeled [header]. */
    val effectiveUnprotectedMembers: Set<String>
        get() = unprotectedMembers intersect serializedHeader().keys

    internal fun toHeaderParts(): Pair<ByteArray, JsonObject> {
        val serializedHeader = serializedHeader()
        val effectiveUnprotectedMembers = unprotectedMembers intersect serializedHeader.keys
        val protectedHeader =
            JsonObject(serializedHeader.filterKeys { it !in effectiveUnprotectedMembers }).toProtectedHeaderBytes()
        val unprotectedHeader = JsonObject(serializedHeader.filterKeys { it in effectiveUnprotectedMembers })
        return protectedHeader to unprotectedHeader
    }

    fun toProtectedHeader(): ByteArray = toHeaderParts().first

    fun toUnprotectedHeader(): JsonObject = toHeaderParts().second

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JwsHeaderWrapped<*>) return false

        if (header != other.header) return false
        if (effectiveUnprotectedMembers != other.effectiveUnprotectedMembers) return false

        return true
    }

    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + effectiveUnprotectedMembers.hashCode()
        return result
    }

    companion object {
        /** Creates a wrapper when [H]'s serializer is available explicitly. */
        operator fun <H : JwsHeaderBase> invoke(
            header: H,
            serializer: KSerializer<H>,
            unprotectedMembers: Set<String> = emptySet(),
        ): JwsHeaderWrapped<H> = JwsHeaderWrapped(header, unprotectedMembers, serializer)

        /** Creates a wrapper while [H] is still reified at the call site. */
        inline operator fun <reified H : JwsHeaderBase> invoke(
            header: H,
            unprotectedMembers: Set<String> = emptySet(),
        ): JwsHeaderWrapped<H> = invoke(
            header = header,
            serializer = joseCompliantSerializer.serializersModule.serializer(),
            unprotectedMembers = unprotectedMembers,
        )

        /** Decodes and combines protected and unprotected fragments using the supplied header serializer. */
        context(serialFormat: Json)
        fun <H : JwsHeaderBase> fromParts(
            serializer: KSerializer<H>,
            protectedHeader: ByteArray? = null,
            unprotectedHeader: JsonObject? = null,
        ): JwsHeaderWrapped<H> = fromJsonObjects(
            serializer = serializer,
            protectedHeader = protectedHeader?.toProtectedHeaderJsonObject(),
            unprotectedHeader = unprotectedHeader,
        )

        /** Decodes fragments while [H] is still reified at the call site. */
        context(serialFormat: Json)
        inline fun <reified H : JwsHeaderBase> fromParts(
            protectedHeader: ByteArray? = null,
            unprotectedHeader: JsonObject? = null,
        ): JwsHeaderWrapped<H> = fromParts(
            serializer = serialFormat.serializersModule.serializer(),
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
        )

        /** Decodes and combines JSON fragments using the supplied header serializer. */
        context(serialFormat: Json)
        fun <H : JwsHeaderBase> fromJsonObjects(
            serializer: KSerializer<H>,
            protectedHeader: JsonObject? = null,
            unprotectedHeader: JsonObject? = null,
        ): JwsHeaderWrapped<H> = protectedHeader.strictUnion(unprotectedHeader).let { combinedHeader ->
            invoke(
                header = serialFormat.decodeFromJsonElement(serializer, combinedHeader),
                serializer = serializer,
                unprotectedMembers = unprotectedHeader?.keys ?: emptySet(),
            )
        }

        /** Decodes JSON fragments while [H] is still reified at the call site. */
        context(serialFormat: Json)
        inline fun <reified H : JwsHeaderBase> fromJsonObjects(
            protectedHeader: JsonObject? = null,
            unprotectedHeader: JsonObject? = null,
        ): JwsHeaderWrapped<H> = fromJsonObjects(
            serializer = serialFormat.serializersModule.serializer(),
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
        )
    }
}

@PublishedApi
internal fun JsonObject.toProtectedHeaderBytes(): ByteArray =
    joseCompliantSerializer.encodeToString(JsonObject.serializer(), this).encodeToByteArray()

internal fun ByteArray.toProtectedHeaderJsonObject(): JsonObject =
    joseCompliantSerializer.decodeFromString(JsonObject.serializer(), decodeToString())

private const val EMPTY_JSON_OBJECT = "{}"
private val EMPTY_JSON_OBJECT_BYTES = EMPTY_JSON_OBJECT.encodeToByteArray()

internal fun ByteArray?.requireAbsentIfEmptyProtectedHeader() {
    require(this == null || !contentEquals(EMPTY_JSON_OBJECT_BYTES)) {
        "JWS protected header must be absent when it would otherwise be empty"
    }
}
