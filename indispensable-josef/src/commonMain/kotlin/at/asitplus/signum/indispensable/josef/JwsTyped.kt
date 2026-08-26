package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

/**
 * Wrapper for [at.asitplus.signum.indispensable.josef.JWS]. Useful when [payload] type is known as part of the contract.
 * All communication over the wire should use [jws] only!
 * Serialization is not recommended but does work. See [SerializerTemplate]
 *
 * While the constructor can be used the different [invoke]s are recommended.
 * For convenience also see the typealiases
 */
sealed class JwsTyped<out J : JWS, out P, out H : JwsHeaderBase> {
    abstract val jws: J
    abstract val payload: P

    final override fun toString() = jws.toString()

    /**
     * Convenience Serializer Template to serialize through wrapper and
     * only serialize [JwsTyped.jws]. Prefer [JwsCompactTyped.SerializerTemplate],
     * [JwsFlattenedTyped.SerializerTemplate], or [JwsGeneralTyped.SerializerTemplate]
     * when the concrete JWS representation is known.
     */
    @Suppress("UNCHECKED_CAST")
    class SerializerTemplate<J : JWS, P, H : JwsHeaderBase>(
        jwsSerializer: KSerializer<J>,
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>,
    ) : TransformingSerializerTemplate<JwsTyped<J, P, H>, J>(
        parent = jwsSerializer,
        encodeAs = { it.jws },
        decodeAs = { jws ->
            when (jws) {
                is JwsCompact -> jws.typed(payloadSerializer, headerSerializer)
                is JwsFlattened -> jws.typed(payloadSerializer, headerSerializer)
                is JwsGeneral -> jws.typed(payloadSerializer, headerSerializer)
            } as JwsTyped<J, P, H>
        }
    )

    companion object {
        context(serialFormat: Json)
        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(base64UrlString: String) =
            JwsCompact(base64UrlString).typed<P, H>()

        context(serialFormat: Json)
        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(jwsFlattened: List<JwsFlattened>): JwsTyped<JwsGeneral, P, H> =
            jwsFlattened.toJwsGeneral().typed<P, H>()

    }
}
