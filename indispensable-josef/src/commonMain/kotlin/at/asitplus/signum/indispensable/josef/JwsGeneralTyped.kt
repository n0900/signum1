package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

data class JwsGeneralTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsGeneral,
    override val payload: P,
    val wrappedHeaders: List<JwsHeaderWrapped<H>>,
    val signatures: List<CryptoSignature.RawByteEncodable>
) : JwsTyped<JwsGeneral, P, H>() {
    class SerializerTemplate<P, H : JwsHeaderBase>(
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>
    ) : TransformingSerializerTemplate<JwsGeneralTyped<P, H>, JwsGeneral>(
        parent = JwsGeneral.serializer(),
        encodeAs = { it.jws },
        decodeAs = { it.typed(payloadSerializer, headerSerializer) }
    )
}

context(serialFormat: Json)
inline fun <reified P, reified H : JwsHeaderBase> JwsGeneral.typed(): JwsGeneralTyped<P, H> =
    this.typed(serialFormat.serializersModule.serializer<P>(), serialFormat.serializersModule.serializer<H>())

fun <P, H : JwsHeaderBase> JwsGeneral.typed(
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
): JwsGeneralTyped<P, H> = with(joseCompliantSerializer) {
    val wrappedHeaders = signatureElements.map {
        JwsHeaderWrapped.fromParts(
            headerSerializer,
            it.plainProtectedHeader,
            it.unprotectedHeader,
        )
    }
    JwsGeneralTyped(
        this@typed,
        getPayload(payloadSerializer).getOrThrow(),
        wrappedHeaders,
        wrappedHeaders.zip(signatureElements) { wrapped, signatureElement ->
            JWS.getSignature(
                wrapped.header.algorithm,
                signatureElement.plainSignature,
            )
        },
    )
}

fun <P, H : JwsHeaderBase> JwsGeneralTyped<P, H>.toJwsFlattenedTyped() =
    jws.toJwsFlattened().mapIndexed { index, flattened ->
        JwsFlattenedTyped(flattened, payload, wrappedHeaders[index], signatures[index])
    }
