package at.asitplus.signum.indispensable.josef

data class JwsCompactTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsCompact,
    override val payload: P,
    val header: H,
) : JwsTyped<JwsCompact, P, H>()