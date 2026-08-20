package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import kotlinx.serialization.json.Json

data class JwsGeneralTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsGeneral,
    override val payload: P,
    val wrappedHeaders: List<JwsHeaderWrapped<H>>,
    val signatures: List<CryptoSignature.RawByteEncodable>
) : JwsTyped<JwsGeneral, P, H>()

context(serialFormat: Json)
inline fun <reified P, reified H : JwsHeaderBase> JwsGeneral.typed(): JwsGeneralTyped<P, H> {
    val wrappedHeaders = signatureElements.map {
        JwsHeaderWrapped.fromParts<H>(it.plainProtectedHeader, it.unprotectedHeader)
    }

    return JwsGeneralTyped(
        this,
        getPayload<P>().getOrThrow(),
        wrappedHeaders,
        wrappedHeaders.zip(signatureInputs) { wrapped, sigInput ->
            JWS.getSignature(
                wrapped.header.algorithm,
                sigInput
            )
        }
    )
}

fun <P, H : JwsHeaderBase> JwsGeneralTyped<P, H>.toJwsFlattenedTyped() =
    jws.toJwsFlattened().mapIndexed { index, flattened -> JwsFlattenedTyped(flattened, payload, wrappedHeaders[index]) }
