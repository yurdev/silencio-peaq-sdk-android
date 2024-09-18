package com.silencio.peaqexample

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.gson.Gson
import com.silencio.peaq.Peaq
import com.silencio.peaq.model.DIDData
import com.silencio.peaq.model.DIDDocumentCustomData
import com.silencio.peaq.utils.EncryptionType
import com.silencio.peaq.utils.PeaqUtils
import io.peaq.did.Document
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.transform
import kotlinx.coroutines.launch
import java.lang.Integer.parseInt
import java.nio.charset.Charset


class MainActivity : AppCompatActivity() {
    @OptIn(ExperimentalStdlibApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val issuerSeed = "ADD_ISSUER_SEED_HERE"
        val peaqInstance = Peaq(
            baseURL = "ADD_SOCKET_BASE_URL_HERE",
            seed =  issuerSeed
        )

        lifecycleScope.launch {
            val (issuerPublicKey, issuerPrivateKey, issuerAddress) = PeaqUtils.getPublicPrivateKeyAddressFromMachineSeed(
                mnemonicWord = issuerSeed
            )

            val ownerSeed = PeaqUtils.generateMnemonicSeed()
            val (ownerPublicKey, ownerPrivateKey, ownerAddress) = PeaqUtils.getPublicPrivateKeyAddressFromMachineSeed(
                mnemonicWord = ownerSeed
            )

            val machineSeed = PeaqUtils.generateMnemonicSeed()
            val (machinePublicKey, machinePrivateKey, machineAddress) = PeaqUtils.getPublicPrivateKeyAddressFromMachineSeed(
                mnemonicWord = machineSeed
            )

            val document = peaqInstance.createDidDocument(
                ownerAddress = ownerAddress,
                machineAddress = machineAddress,
                machinePublicKey = machinePublicKey
            )
            /**
             * use this when you don't have issuer seed to generate didDocument
                val documentWithoutSeed = peaqInstance.createDidDocumentWithoutSeed(
                    issuerAddress = issuerAddress,
                    ownerAddress = ownerAddress,
                    machineAddress = machineAddress,
                    machinePublicKey = machinePublicKey,
                    signature = "ADD_YOUR_SIGNATURE_WHICH_SIGN_BY_YOUR_ISSUER"
                )
            */
            Log.e("Document", "Document : ${document}")
            val map = peaqInstance.createDid(
                secretPhrase = machineSeed,
                name = "did:peaq:$machineAddress",
                value = document.toByteArray().toHexString()
            )
            map.collectLatest {
                if (it.inBlock != null) {
                    Log.e("Hash Key", "Hash Key ${it.inBlock}")
                }
                if (it.error != null) {
                    Log.e("Error", "Error ${it.error}")
                }


                val payloadData = DIDDocumentCustomData(
                    id = "machineAddress",
                    type = "Custom_data",
                    data = "a@gmail.com"
                )
                val payload = Gson().toJson(payloadData)
                val payloadHex =
                    PeaqUtils.signData(payload, issuerSeed, format = EncryptionType.ED25519)


                val store = peaqInstance.storeMachineDataHash(
                    payloadData = payloadHex,
                    itemType = "peaq_123",
                    machineSeed = machineSeed
                )
                if (store?.error != null) {
                    Log.e(
                        "Store Error",
                        "Store Error  ${store.error?.code}  ${store.error?.message}"
                    )
                }
                if (store?.result != null) {
                    Log.e("Store Result", "Store Result ${store.result.toString()}")
                }
                peaqInstance.disconnect()
            }


        }
    }
}
