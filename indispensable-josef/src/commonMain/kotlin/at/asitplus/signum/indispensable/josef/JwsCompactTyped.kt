package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.json.Json

data class JwsCompactTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsCompact,
    override val payload: P,
    val header: JwsHeaderWrapped<H>,
) : JwsTyped<JwsCompact, P, H>()

context(serialFormat: Json)
inline fun <reified P, reified H : JwsHeaderBase> JwsCompact.typed(): JwsCompactTyped<P,H> =
    JwsCompactTyped(this, getPayload<P>().getOrThrow(), JwsHeaderWrapped.fromParts(plainProtectedHeader, null))

fun <P, H : JwsHeaderBase> JwsCompactTyped<P, H>.toJwsFlattenedTyped() =
    JwsFlattenedTyped(jws.toJwsFlattened(), payload, header)
