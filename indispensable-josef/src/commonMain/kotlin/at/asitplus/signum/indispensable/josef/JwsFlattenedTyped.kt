package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.json.Json

data class JwsFlattenedTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsFlattened,
    override val payload: P,
    val header: JwsHeaderWrapped<H>,
) : JwsTyped<JwsFlattened, P, H>()

context(serialFormat: Json)
inline fun <reified P, reified H : JwsHeaderBase> JwsFlattened.typed(): JwsFlattenedTyped<P,H> =
    JwsFlattenedTyped(this, getPayload<P>().getOrThrow(), decodeHeader())