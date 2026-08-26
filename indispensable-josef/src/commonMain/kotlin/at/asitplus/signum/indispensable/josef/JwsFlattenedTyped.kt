package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

data class JwsFlattenedTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsFlattened,
    override val payload: P,
    val wrappedHeader: JwsHeaderWrapped<H>,
    val signature: CryptoSignature.RawByteEncodable
) : JwsTyped<JwsFlattened, P, H>() {

    class SerializerTemplate<P, H : JwsHeaderBase>(
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>
    ) : TransformingSerializerTemplate<JwsFlattenedTyped<P, H>, JwsFlattened>(
        parent = JwsFlattened.serializer(),
        encodeAs = { it.jws },
        decodeAs = { it.typed(payloadSerializer, headerSerializer) }
    )

}

context(serialFormat: Json)
inline fun <reified P, reified H : JwsHeaderBase> JwsFlattened.typed(): JwsFlattenedTyped<P, H> =
    this.typed(serialFormat.serializersModule.serializer<P>(), serialFormat.serializersModule.serializer<H>())


fun <P, H : JwsHeaderBase> JwsFlattened.typed(
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
): JwsFlattenedTyped<P, H> = with(joseCompliantSerializer) {
    JwsHeaderWrapped.fromParts(
        headerSerializer,
        plainProtectedHeader,
        unprotectedHeader,
    ).let { wrapped ->
        JwsFlattenedTyped(
            this@typed,
            getPayload(payloadSerializer).getOrThrow(),
            wrapped,
            JWS.getSignature(wrapped.header.algorithm, plainSignature),
        )
    }
}

fun <P, H : JwsHeaderBase> JwsFlattenedTyped<P, H>.toJwsCompactTyped() =
    JwsCompactTyped(jws.toJwsCompact(), payload, wrappedHeader, signature)
