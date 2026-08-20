package at.asitplus.signum.indispensable.josef

data class JwsGeneralTyped<out P, out H : JwsHeaderBase>(
    override val jws: JwsGeneral,
    override val payload: P,
    val header: List<H>,
) : JwsTyped<JwsGeneral, P, H>()