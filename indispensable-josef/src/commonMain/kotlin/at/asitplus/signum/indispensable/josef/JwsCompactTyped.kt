package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

data class JwsCompactTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsCompact,
    override val payload: P,
    val wrappedHeader: JwsHeaderWrapped<H>,
    val signature: CryptoSignature.RawByteEncodable
) : JwsTyped<JwsCompact, P, H>() {

    class SerializerTemplate<P, H : JwsHeaderBase>(
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>
    ) : TransformingSerializerTemplate<JwsCompactTyped<P, H>, JwsCompact>(
        parent = JwsCompactStringSerializer,
        encodeAs = { it.jws },
        decodeAs = { it.typed(payloadSerializer, headerSerializer) }
    )
}

context(serialFormat: Json)
inline fun <reified P, reified H : JwsHeaderBase> JwsCompact.typed(): JwsCompactTyped<P, H> =
    this.typed(serialFormat.serializersModule.serializer<P>(), serialFormat.serializersModule.serializer<H>())

fun <P, H : JwsHeaderBase> JwsCompact.typed(
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
): JwsCompactTyped<P, H> = with(joseCompliantSerializer) {
    JwsHeaderWrapped.fromParts(headerSerializer, plainProtectedHeader, null).let { wrapped ->
        JwsCompactTyped(
            this@typed,
            getPayload(payloadSerializer).getOrThrow(),
            wrapped,
            JWS.getSignature(wrapped.header.algorithm, plainSignature),
        )
    }
}


fun <P, H : JwsHeaderBase> JwsCompactTyped<P, H>.toJwsFlattenedTyped() =
    JwsFlattenedTyped(jws.toJwsFlattened(), payload, wrappedHeader, signature)
