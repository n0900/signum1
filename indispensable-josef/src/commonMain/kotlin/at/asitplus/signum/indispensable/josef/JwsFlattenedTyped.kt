package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import kotlinx.serialization.json.Json

data class JwsFlattenedTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsFlattened,
    override val payload: P,
    val wrappedHeader: JwsHeaderWrapped<H>,
    val signature: CryptoSignature.RawByteEncodable
) : JwsTyped<JwsFlattened, P, H>()

context(serialFormat: Json)
inline fun <reified P, reified H : JwsHeaderBase> JwsFlattened.typed(): JwsFlattenedTyped<P, H> =
    JwsHeaderWrapped.fromParts<H>(plainProtectedHeader, unprotectedHeader).let { wrapped ->
        JwsFlattenedTyped(
            this,
            getPayload<P>().getOrThrow(),
            wrapped,
            JWS.getSignature(wrapped.header.algorithm, plainSignature)
        )
    }

fun <P, H : JwsHeaderBase> JwsFlattenedTyped<P, H>.toJwsCompactTyped() =
    JwsCompactTyped(jws.toJwsCompact(), payload, wrappedHeader, signature)
