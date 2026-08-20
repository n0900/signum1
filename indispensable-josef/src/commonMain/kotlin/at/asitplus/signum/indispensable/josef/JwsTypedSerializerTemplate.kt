package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer

/**
 * Convenience Serializer Template to serialize through wrapper and
 * only serialize [JwsTyped.jws].
 */
@Suppress("UNCHECKED_CAST")
class JwsTypedSerializerTemplate<J : JWS, P, H : JwsHeaderBase>(
    jwsSerializer: KSerializer<J>,
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
) : TransformingSerializerTemplate<JwsTyped<J, P, H>, J>(
    parent = jwsSerializer,
    encodeAs = { it.jws },
    decodeAs = { jws ->
        with(joseCompliantSerializer) {
            when (jws) {
                is JwsCompact -> JwsCompactTyped(
                    jws,
                    jws.getPayload(payloadSerializer).getOrThrow(),
                    JwsHeaderWrapped.fromParts(headerSerializer, jws.plainProtectedHeader, null)
                )

                is JwsFlattened -> JwsFlattenedTyped(
                    jws, jws.getPayload(payloadSerializer).getOrThrow(),
                    JwsHeaderWrapped.fromParts(headerSerializer, jws.plainProtectedHeader, jws.unprotectedHeader)
                )

                is JwsGeneral -> JwsGeneralTyped(
                    jws, jws.getPayload(payloadSerializer).getOrThrow(),
                    jws.signatureElements.map {
                        JwsHeaderWrapped.fromParts(
                            headerSerializer,
                            it.plainProtectedHeader,
                            it.unprotectedHeader
                        )
                    })
            } as JwsTyped<J, P, H>
        }
    }
)