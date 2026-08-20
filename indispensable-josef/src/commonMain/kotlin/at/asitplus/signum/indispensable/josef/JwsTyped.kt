package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.json.Json

/**
 * Wrapper for [at.asitplus.signum.indispensable.josef.JWS]. Useful when [payload] type is known as part of the contract.
 * All communication over the wire should use [jws] only!
 * Serialization is not recommended but does work. See [JwsTypedSerializerTemplate]
 *
 * While the constructor can be used the different [invoke]s are recommended.
 * For convenience also see the typealiases
 */
sealed class JwsTyped<out J : JWS, out P, out H : JwsHeaderBase> {
    abstract val jws: J
    abstract val payload: P

    override fun toString() = jws.toString()

    companion object {
        context(serialFormat: Json)
        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(base64UrlString: String) =
            JwsCompact(base64UrlString).typed<P, H>()

        context(serialFormat: Json)
        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(jwsFlattened: List<JwsFlattened>): JwsTyped<JwsGeneral, P, H> =
            jwsFlattened.toJwsGeneral().typed<P, H>()

    }
}
