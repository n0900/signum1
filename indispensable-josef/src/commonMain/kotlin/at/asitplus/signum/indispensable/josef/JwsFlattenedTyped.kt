package at.asitplus.signum.indispensable.josef

data class JwsFlattenedTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsFlattened,
    override val payload: P,
    val header: H,
) : JwsTyped<JwsFlattened, P, H>()