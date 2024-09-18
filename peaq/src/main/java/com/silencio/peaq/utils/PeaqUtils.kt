package com.silencio.peaq.utils

import android.util.Log
import com.silencio.peaq.model.DIDDocumentCustomData
import com.silencio.peaq.model.PublicKeyPrivateKeyAddressData
import dev.sublab.ed25519.ed25519
import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.sr25519.sr25519
import dev.sublab.sr25519.sr25519Clone
import dev.sublab.ss58.ss58
import io.novasama.substrate_sdk_android.encrypt.mnemonic.Mnemonic
import io.novasama.substrate_sdk_android.encrypt.mnemonic.MnemonicCreator
import io.novasama.substrate_sdk_android.extensions.toHexString
import io.peaq.did.Document
import io.peaq.did.Service
import io.peaq.did.Signature
import io.peaq.did.VerificationMethod
import io.peaq.did.VerificationType


object PeaqUtils {

    suspend fun generateMnemonicSeed(): String {
        return MnemonicCreator.randomMnemonic(Mnemonic.Length.TWELVE).words
    }

    suspend fun getPublicPrivateKeyAddressFromMachineSeed(mnemonicWord: String): PublicKeyPrivateKeyAddressData {
        val keyPair = KeyPair.Factory.sr25519().generate(phrase = mnemonicWord)
        val privateKey = keyPair.privateKey
        val publicKey = keyPair.publicKey

        val accountIdOwner = publicKey.ss58.accountId()
        val accountAddressOwner = publicKey.ss58.address(type = 42)
        return PublicKeyPrivateKeyAddressData(
            publicKey = publicKey,
            privateKey = privateKey,
            address = accountAddressOwner
        )
    }

    suspend fun getED25519PublicPrivateKeyAddressFromMachineSeed(mnemonicWord: String): PublicKeyPrivateKeyAddressData {
        val keyPair = KeyPair.Factory.ed25519.generate(phrase = mnemonicWord)
        val privateKey = keyPair.privateKey
        val publicKey = keyPair.publicKey

        val accountIdOwner = publicKey.ss58.accountId()
        val accountAddressOwner = publicKey.ss58.address(type = 42)
        return PublicKeyPrivateKeyAddressData(
            publicKey = publicKey,
            privateKey = privateKey,
            address = accountAddressOwner
        )
    }

    suspend fun createDidDocumentWithoutSeed(
        issuerAddress: String,
        ownerAddress: String,
        machineAddress: String,
        machinePublicKey: ByteArray,
        signature: String,
        customData: List<DIDDocumentCustomData> = emptyList()
    ): Document {

        val builder = Document.newBuilder()

        builder.id = "did:peaq:${machineAddress}"
        builder.controller = "did:peaq:${issuerAddress}"

        val docVerificationMethod =
            VerificationMethod.newBuilder().setType(VerificationType.Sr25519VerificationKey2020)
                .setId(machinePublicKey.ss58.toString().toByteArray().toHexString())
                .setController("did:peaq:${issuerAddress}")
                .setPublicKeyMultibase(machinePublicKey.toHexString())

        builder.addVerificationMethods(docVerificationMethod.build())


        val docSignature = Signature.newBuilder().setIssuer(issuerAddress)
            .setType(VerificationType.Sr25519VerificationKey2020).setHash(signature)
            .build()


        builder.signature = docSignature




        builder.addAllAuthentications(
            mutableListOf(
                machinePublicKey.ss58.toString().toByteArray().toHexString()
            )
        )

        val docService = Service.newBuilder()
        docService.id = "owner"
        docService.type = "owner"
        docService.data = ownerAddress
        builder.addServices(docService.build())

        if (!customData.isNullOrEmpty()) {
            for (data in customData) {
                val docServiceCustom = Service.newBuilder()
                docServiceCustom.id = data.id
                docServiceCustom.type = data.type
                docServiceCustom.data = data.data

                builder.addServices(docServiceCustom.build())
            }

        }

        val document = builder.build()

        return document
    }

    suspend fun signData(
        plainData: String,
        machineSeed: String,
        format: EncryptionType
    ): String {
        val originalData = plainData.toByteArray()
        val keyPair: KeyPair
        var sign: ByteArray? = null
        when (format) {
            EncryptionType.SR25519 -> {
                keyPair = KeyPair.Factory.sr25519().generate(phrase = machineSeed)
                sign = keyPair.sign(originalData)

            }

            EncryptionType.ED25519 -> {
                keyPair = KeyPair.Factory.ed25519.generate(phrase = machineSeed)
                sign = keyPair.sign(originalData)

            }

            else -> {
                return "Invalid format"
            }
        }
        if (sign != null) {
            return sign.toHexString()
        }
        return ""
    }

    @OptIn(ExperimentalStdlibApi::class)
    suspend fun verifyData(
        machinePublicKey: String,
        plainData: String,
        signature: String
    ): Boolean {
        val originalData = plainData.toByteArray()
        var verify: Boolean = false

        val sigData = signature.hexToByteArray()


        val publicKey: ByteArray = machinePublicKey.hexToByteArray()
        try {
            verify = publicKey.sr25519Clone().verify(originalData, sigData)
        } catch (_: Exception) {
            try {
                verify = publicKey.ed25519.verify(originalData, sigData)
            } catch (e: Exception) {
                Log.e("Exception", "Exception ${e}")
            }
        }

        return verify

    }



}