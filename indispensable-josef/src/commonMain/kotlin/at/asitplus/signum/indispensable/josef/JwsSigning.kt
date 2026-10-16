package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signature

internal suspend fun signJwsFlattened(
    header: JwsHeaderWrapped<*>,
    payload: ByteArray,
    signer: Signer,
): JwsFlattened {
    requireMatchingSigner(header, signer)
    val protectedHeader = header.toProtectedHeader().takeUnless { it.toProtectedHeaderJsonObject().isEmpty() }
    val unprotectedHeader = header.toUnprotectedHeader().takeUnless { it.isEmpty() }
    val signature = signer.sign(JWS.getSignatureInput(protectedHeader, payload)).signature
    return JwsFlattened(protectedHeader, unprotectedHeader, payload, signature.joseBytes.copyOf())
}

internal fun requireMatchingSigner(header: JwsHeaderWrapped<*>, signer: Signer) {
    val protectedHeader = header.toProtectedHeader().toProtectedHeaderJsonObject()
    val encodedAlgorithm = requireNotNull(protectedHeader["alg"] ?: header.toUnprotectedHeader()["alg"]) {
        "JWS header must contain an algorithm"
    }
    val algorithm = joseCompliantSerializer.decodeFromJsonElement(JwsAlgorithmSerializer, encodedAlgorithm)
    require(algorithm == signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow()) {
        "JWS header algorithm does not match the signer"
    }
    if (algorithm is JwsAlgorithm.Signature.EC) {
        require((signer.publicKey as? EcdsaPublicKey)?.curve == algorithm.ecCurve) {
            "Signer curve does not match the JWS header algorithm"
        }
    }
}
