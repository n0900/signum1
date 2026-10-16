package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.SignatureResult
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.UserInitiatedCancellation
import at.asitplus.signum.indispensable.sign.makeVerifier
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.supreme.Supreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.jsonObject

@Serializable
internal data class ConstructorHeader(
    @SerialName("alg") override val algorithm: JwsAlgorithm,
    @SerialName("kid") override val keyId: String? = null,
    val extension: String? = null,
) : JwsHeaderBase {
    @Transient override val type: String? = null
    @Transient override val contentType: String? = null
    @Transient override val certificateChain: CertificateChain? = null
    @Transient override val jsonWebKey: JsonWebKey? = null
    @Transient override val jsonWebKeySetUrl: String? = null
    @Transient override val certificateUrl: String? = null
    @Transient override val certificateSha1Thumbprint: ByteArray? = null
    @Transient override val certificateSha256Thumbprint: ByteArray? = null
    @Transient override val crit: List<String>? = null
}

@Serializable
internal data class ConstructorPayload(val sub: String)

private suspend fun newEcSigner(): Signer.WithExportableKey = Signer.Ephemeral { ec {} }

private suspend fun newRsaSigner(): Signer.WithExportableKey = Signer.Ephemeral {
    rsa {
        bits = 2048
        digest = Digest.SHA256
        padding = RsaAlgorithm.Padding.PSS
    }
}

private class CountingSigner(private val delegate: Signer) : Signer by delegate {
    var calls = 0
        private set

    override suspend fun sign(data: SignatureInput): SignatureResult<*> {
        calls++
        return delegate.sign(data)
    }
}

val JwsConstructorsTest by matrixSuite {
    Supreme.init()

    "compact constructors sign typed payloads with EC and RSA keys" {
        for (signer in listOf(newEcSigner(), newRsaSigner())) {
            val header = ConstructorHeader(signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(), "key")
            val typed = JwsCompactTyped(header, ConstructorPayload("alice"), signer)
            typed.payload shouldBe ConstructorPayload("alice")
            typed.header shouldBe header
            typed.unprotectedHeaderMembers shouldBe emptySet()
            typed.jws.typed<ConstructorPayload, ConstructorHeader>() shouldBe typed
            signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
            val base = JwsTyped(header, ConstructorPayload("alice"), signer)
            base.payload shouldBe typed.payload
            base.header shouldBe header
        }
    }

    "flattened constructors preserve protected, split and wholly unprotected headers" {
        val signer = newEcSigner()
        val header = ConstructorHeader(JwsAlgorithm.Signature.ES256, "key", "custom")
        for (placement in listOf(emptySet(), setOf("kid"), setOf("alg", "kid", "extension"))) {
            val typed = JwsFlattenedTyped(header, ConstructorPayload("alice"), signer, placement)
            typed.header shouldBe header
            typed.unprotectedHeaderMembers shouldBe placement
            typed.jws.unprotectedHeader?.keys.orEmpty() shouldBe placement
            val wireJson = joseCompliantSerializer.encodeToJsonElement(JwsFlattened.serializer(), typed.jws).jsonObject
            (JWS.SerialNames.HEADER in wireJson) shouldBe placement.isNotEmpty()
            if ("alg" in placement) typed.jws.plainProtectedHeader shouldBe null
            signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
            joseCompliantSerializer.decodeFromString<JwsFlattened>(
                joseCompliantSerializer.encodeToString(typed.jws)
            ).typed<ConstructorPayload, ConstructorHeader>() shouldBe typed
        }
    }

    "general construction serializes one shared payload and preserves signature order" {
        val signers = listOf(newEcSigner(), newRsaSigner())
        val parameters = signers.mapIndexed { index, signer ->
            JwsSigningParameters(
                ConstructorHeader(signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(), "key-$index"),
                signer,
                if (index == 0) setOf("kid") else emptySet(),
            )
        }
        var encodings = 0
        val serializer = object : KSerializer<ConstructorPayload> by ConstructorPayload.serializer() {
            override fun serialize(encoder: Encoder, value: ConstructorPayload) {
                encodings++
                ConstructorPayload.serializer().serialize(encoder, value)
            }
        }
        val typed = JwsGeneralTyped(ConstructorPayload("alice"), parameters, serializer, ConstructorHeader.serializer())
        encodings shouldBe 1
        typed.headers.map { it.keyId } shouldBe listOf("key-0", "key-1")
        typed.unprotectedHeaderMembers shouldBe listOf(setOf("kid"), emptySet())
        typed.payload shouldBe ConstructorPayload("alice")
        typed.toJwsFlattenedTyped().forEachIndexed { index, flattened ->
            flattened.jws.plainPayload shouldBe typed.jws.plainPayload
            signers[index].makeVerifier().verify(flattened.jws.signatureInput, flattened.signature) shouldBe
                    SignatureVerifier.Success
        }
        val reified = JwsGeneralTyped(ConstructorPayload("alice"), parameters)
        reified.headers shouldBe typed.headers
        reified.payload shouldBe typed.payload
        JwsTyped(ConstructorPayload("alice"), parameters).headers shouldBe typed.headers
    }

    "typed constructors derive normalized views from the bytes they sign" {
        val signer = newEcSigner()
        val payloadSerializer = object : KSerializer<ConstructorPayload> by ConstructorPayload.serializer() {
            override fun deserialize(decoder: Decoder) =
                ConstructorPayload.serializer().deserialize(decoder).let { it.copy(sub = it.sub.lowercase()) }
        }
        val headerSerializer = object : KSerializer<ConstructorHeader> by ConstructorHeader.serializer() {
            override fun serialize(encoder: Encoder, value: ConstructorHeader) =
                ConstructorHeader.serializer().serialize(encoder, value.copy(keyId = value.keyId?.uppercase()))

            override fun deserialize(decoder: Decoder) =
                ConstructorHeader.serializer().deserialize(decoder).let { it.copy(keyId = it.keyId?.lowercase()) }
        }
        val header = ConstructorHeader(JwsAlgorithm.Signature.ES256, "key")
        val payload = ConstructorPayload("ALICE")
        val compact = JwsCompactTyped(header, payload, signer, payloadSerializer, headerSerializer)
        val flattened = JwsFlattenedTyped(header, payload, signer, payloadSerializer, headerSerializer, setOf("kid"))
        val general = JwsGeneralTyped(
            payload, listOf(JwsSigningParameters(header, signer)), payloadSerializer, headerSerializer,
        )
        (listOf(compact.toJwsFlattenedTyped(), flattened) + general.toJwsFlattenedTyped()).forEach { typed ->
            typed.payload.sub shouldBe "alice"
            typed.header.keyId shouldBe "key"
            typed.jws.getPayload(ConstructorPayload.serializer()).getOrThrow().sub shouldBe "ALICE"
            JwsHeaderWrapped.fromParts<ConstructorHeader>(
                typed.jws.plainProtectedHeader, typed.jws.unprotectedHeader,
            ).header.keyId shouldBe "KEY"
            signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
        }
    }

    "invalid serialized algorithms are rejected before signing" {
        val signer = CountingSigner(newEcSigner())
        val valid = ConstructorHeader(JwsAlgorithm.Signature.ES256, "key")
        shouldThrow<IllegalArgumentException> {
            JwsCompactTyped(valid.copy(algorithm = JwsAlgorithm.Signature.ES384), ConstructorPayload("alice"), signer)
        }
        val changedAlgorithm = object : JsonTransformingSerializer<ConstructorHeader>(ConstructorHeader.serializer()) {
            override fun transformSerialize(element: JsonElement): JsonElement =
                JsonObject(element.jsonObject + ("alg" to JsonPrimitive("RS256")))
        }
        shouldThrow<IllegalArgumentException> {
            JwsCompactTyped(valid, ConstructorPayload("alice"), signer, ConstructorPayload.serializer(), changedAlgorithm)
        }
        shouldThrow<IllegalArgumentException> {
            JwsGeneralTyped(ConstructorPayload("alice"), listOf(
                JwsSigningParameters(valid, signer),
                JwsSigningParameters(valid.copy(algorithm = JwsAlgorithm.Signature.RS256), signer),
            ))
        }
        shouldThrow<IllegalArgumentException> {
            JwsGeneralTyped(ConstructorPayload("alice"), emptyList<JwsSigningParameters<ConstructorHeader>>())
        }
        signer.calls shouldBe 0
    }

    "signing snapshots mutable payloads and signature parameters" {
        val delegate = newEcSigner()
        val claims = mutableMapOf("sub" to JsonPrimitive("alice"))
        val payload = JsonObject(claims)
        val parameters = mutableListOf<JwsSigningParameters<ConstructorHeader>>()
        val signer = object : Signer by delegate {
            override suspend fun sign(data: SignatureInput): SignatureResult<*> {
                claims["sub"] = JsonPrimitive("changed")
                parameters.clear()
                return delegate.sign(data)
            }
        }
        parameters += JwsSigningParameters(ConstructorHeader(JwsAlgorithm.Signature.ES256), signer)
        parameters += JwsSigningParameters(ConstructorHeader(JwsAlgorithm.Signature.ES256), delegate)
        val typed = JwsGeneralTyped(payload, parameters)
        typed.payload["sub"] shouldBe JsonPrimitive("alice")
        val wire = typed.jws
        wire.getPayload<JsonObject>().getOrThrow() shouldBe typed.payload
        wire.signatureElements.size shouldBe 2
        wire.signatureElements.forEachIndexed { index, signature ->
            delegate.makeVerifier().verify(
                wire.signatureInputs[index], JWS.getSignature(JwsAlgorithm.Signature.ES256, signature.plainSignature),
            ) shouldBe SignatureVerifier.Success
        }
    }

    "signer failures propagate through constructors" {
        val delegate = newEcSigner()
        val problem = UserInitiatedCancellation("cancelled", null)
        val signer = object : Signer by delegate {
            override suspend fun sign(data: SignatureInput): SignatureResult<*> = SignatureResult.Failure(problem)
        }
        shouldThrow<UserInitiatedCancellation> {
            JwsCompactTyped(ConstructorHeader(JwsAlgorithm.Signature.ES256), ConstructorPayload("alice"), signer)
        } shouldBe problem
    }
}
