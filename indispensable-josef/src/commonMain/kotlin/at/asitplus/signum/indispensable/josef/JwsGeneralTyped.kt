package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.json.Json

data class JwsGeneralTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsGeneral,
    override val payload: P,
    val header: List<JwsHeaderWrapped<H>>,
) : JwsTyped<JwsGeneral, P, H>()

context(serialFormat: Json)
inline fun <reified P, reified H : JwsHeaderBase> JwsGeneral.typed(): JwsGeneralTyped<P, H> =
    JwsGeneralTyped(
        this,
        getPayload<P>().getOrThrow(),
        signatureElements.map { JwsHeaderWrapped.fromParts(it.plainProtectedHeader, it.unprotectedHeader) })

fun <P, H : JwsHeaderBase> JwsGeneralTyped<P, H>.toJwsFlattenedTyped() =
    jws.toJwsFlattened().mapIndexed { index, flattened -> JwsFlattenedTyped(flattened, payload, header[index]) }
