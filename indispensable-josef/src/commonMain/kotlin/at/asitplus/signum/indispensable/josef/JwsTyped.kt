package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.sign.Signer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

/**
 * Typed payload and header views over a retained [JWS] wire object.
 *
 * Use the concrete compact, flattened, or general view to access decoded headers and signatures.
 * Forward [jws] or serialize through [JwsTypedSerializerTemplate] to preserve the original signed bytes.
 * Typed decoding does not verify signatures or establish key trust.
 */
sealed class JwsTyped<out J : JWS, out P, out H : JwsHeaderBase> {
    abstract val jws: J
    abstract val payload: P

    final override fun toString() = jws.toString()

    companion object {
        /** Creates a compact typed JWS. */
        suspend operator fun <P, H : JwsHeaderBase> invoke(
            protectedHeader: H,
            payload: P,
            signer: Signer,
            payloadSerializer: KSerializer<P>,
            headerSerializer: KSerializer<H>,
        ): JwsCompactTyped<P, H> = JwsCompactTyped(
            protectedHeader, payload, signer, payloadSerializer, headerSerializer,
        )

        suspend inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            protectedHeader: H,
            payload: P,
            signer: Signer,
        ): JwsCompactTyped<P, H> = JwsCompactTyped(protectedHeader, payload, signer)

        /** Creates a general typed JWS with one shared payload. */
        suspend operator fun <P, H : JwsHeaderBase> invoke(
            payload: P,
            signatures: List<JwsSigningParameters<H>>,
            payloadSerializer: KSerializer<P>,
            headerSerializer: KSerializer<H>,
        ): JwsGeneralTyped<P, H> = JwsGeneralTyped(payload, signatures, payloadSerializer, headerSerializer)

        suspend inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            payload: P,
            signatures: List<JwsSigningParameters<H>>,
        ): JwsGeneralTyped<P, H> = JwsGeneralTyped(payload, signatures)

        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            base64UrlString: String,
            serialFormat: Json = joseCompliantSerializer,
        ) = JwsCompactTyped<P, H>(base64UrlString, serialFormat)

        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            jwsFlattened: List<JwsFlattened>,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsGeneralTyped<P, H> = JwsGeneralTyped<P, H>(jwsFlattened, serialFormat)

    }
}
