package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.sign.Signer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

/**
 * Typed payload, effective header, and signature over an unchanged compact [jws].
 * Create views through [typed] or the companion factories; component construction and copying are internal.
 */
@ConsistentCopyVisibility
data class JwsCompactTyped<out P, H : JwsHeaderBase> internal constructor(
    override val jws: JwsCompact,
    override val payload: P,
    internal val wrappedHeader: JwsHeaderWrapped<H>,
    val signature: CryptoSignature
) : JwsTyped<JwsCompact, P, H>() {

    val header = wrappedHeader.header
    val unprotectedHeaderMembers = wrappedHeader.unprotectedHeaderMembers

    companion object {
        /** Signs a serialized payload and derives the typed view from the resulting wire object. */
        suspend operator fun <P, H : JwsHeaderBase> invoke(
            protectedHeader: H,
            payload: P,
            signer: Signer,
            payloadSerializer: KSerializer<P>,
            headerSerializer: KSerializer<H>,
        ): JwsCompactTyped<P, H> =
            signJwsFlattened(
                JwsHeaderWrapped(protectedHeader, headerSerializer, emptySet()),
                joseCompliantSerializer.encodeToString(payloadSerializer, payload).encodeToByteArray(),
                signer,
            ).toJwsCompact().typed(payloadSerializer, headerSerializer)

        suspend inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            protectedHeader: H,
            payload: P,
            signer: Signer,
        ): JwsCompactTyped<P, H> = invoke(
            protectedHeader, payload, signer,
            joseCompliantSerializer.serializersModule.serializer<P>(),
            joseCompliantSerializer.serializersModule.serializer<H>(),
        )

        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            base64UrlString: String,
            serialFormat: Json = joseCompliantSerializer,
        ) = JwsCompact(base64UrlString).typed<P, H>(serialFormat)
    }
}

inline fun <reified P, reified H : JwsHeaderBase> JwsCompact.typed(
    serialFormat: Json = joseCompliantSerializer,
): JwsCompactTyped<P, H> = typed(
    payloadSerializer = serialFormat.serializersModule.serializer<P>(),
    headerSerializer = serialFormat.serializersModule.serializer<H>(),
    serialFormat = serialFormat,
)

/** Decodes a typed view using explicit payload and header serializers, retaining the original wire object. */
fun <P, H : JwsHeaderBase> JwsCompact.typed(
    payloadSerializer: KSerializer<P>,
    headerSerializer: KSerializer<H>,
    serialFormat: Json = joseCompliantSerializer,
): JwsCompactTyped<P, H> =
    JwsHeaderWrapped.fromParts(
        serializer = headerSerializer,
        protectedHeader = plainProtectedHeader,
        serialFormat = serialFormat,
    ).let { wrapped ->
        JwsCompactTyped(
            this,
            getPayload(payloadSerializer, serialFormat).getOrThrow(),
            wrapped,
            JWS.getSignature(wrapped.header.algorithm, plainSignature)
        )
    }

fun <P, H : JwsHeaderBase> JwsCompactTyped<P, H>.toJwsFlattenedTyped() =
    JwsFlattenedTyped(jws.toJwsFlattened(), payload, wrappedHeader, signature)
