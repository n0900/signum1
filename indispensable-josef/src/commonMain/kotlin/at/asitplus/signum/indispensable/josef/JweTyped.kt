package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JweTyped.Companion.getSignedPayload


typealias JweCompactTyped<J, P> = JweTyped<JweCompact, J, P>
typealias JweFlattenedTyped<J, P> = JweTyped<JweFlattened, J, P>
typealias JweGeneralTyped<J, P> = JweTyped<JweGeneral, J, P>


inline fun <J1 : JWE, reified J2 : JWS, reified P> J1.typed(noinline decrypter: (JWE) -> ByteArray): JweTyped<J1, J2, P> =
    JweTyped(this, getSignedPayload<J2>(decrypter, this).getOrThrow().typed<P, J2>())

/**
 * Wrapper for [JWE]. Useful when [signedPayload] type is known as part of the contract.
 * We assume all payloads are signed and the sender uses the convention
 * ENCRYPT(SIGN(PAYLOAD))
 * If the use-case arises this can be changed.
 *
 * A JWE does not carry plaintext, so reopening a typed wrapper from serialized data requires caller-supplied
 * decryption that returns the plaintext bytes.
 *
 * All communication over the wire should use [jwe] only.
 *
 * While the constructor can be used, the different [invoke]s are recommended. For convenience also see the typealiases.
 */
data class JweTyped<out J1 : JWE, out J2 : JWS, out P>(
    val jwe: J1,
    val signedPayload: JwsTyped<J2, P>,
) {
    override fun toString() = jwe.toString()

    companion object {
        inline fun <reified J : JWS> getSignedPayload(
            noinline decrypter: (JWE) -> ByteArray,
            jwe: JWE
        ): KmmResult<J> = runCatching {
            joseCompliantSerializer.decodeFromString<J>(decrypter(jwe).decodeToString())
        }.wrap()
    }
}
