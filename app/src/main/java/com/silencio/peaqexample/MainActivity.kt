package com.silencio.peaqexample

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.gson.Gson
import com.silencio.peaq.Peaq
import com.silencio.peaq.model.DIDDocumentCustomData
import com.silencio.peaq.utils.EncryptionType
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val issuerSeed = "ADD_ISSUER_SEED_HERE"
        val peaqInstance = Peaq(
            baseURL = "ADD_SOCKET_BASE_URL_HERE",
            seed =  issuerSeed
        )

        lifecycleScope.launch {
            val (issuerPublicKey,issuerPrivateKey,issuerAddress) = peaqInstance.getPublicPrivateKeyAddressFromMachineSeed(mnemonicWord = issuerSeed)

            val ownerSeed = peaqInstance.generateMnemonicSeed()
            val (ownerPublicKey,ownerPrivateKey,ownerAddress) = peaqInstance.getPublicPrivateKeyAddressFromMachineSeed(mnemonicWord = ownerSeed)

            val machineSeed = peaqInstance.generateMnemonicSeed()
            val (machinePublicKey,machinePrivateKey,machineAddress) = peaqInstance.getPublicPrivateKeyAddressFromMachineSeed(mnemonicWord = machineSeed)

            val document = peaqInstance.createDidDocument(
                ownerAddress = ownerAddress,
                machineAddress = machineAddress,
                machinePublicKey = machinePublicKey
            )
           val map =  peaqInstance.createDid(name ="did:peaq:$machineAddress" , value = document)
            map.collectLatest {
                if (it.containsKey("inBlock")){
                    Log.e("Hash Key","Hash Key ${it["inBlock"]}")
                }

            }
            val payloadData = DIDDocumentCustomData(id = machineAddress, type = "Custom_data", data = "a@gmail.com")
            val payload = Gson().toJson(payloadData)
            val payloadHex = peaqInstance.signData(payload,issuerSeed, format = EncryptionType.ED25519)
            Log.e("PayLoadHex","PayLoadHex ${payloadHex}")

            peaqInstance.storeMachineDataHash(payloadData = payloadHex , itemType = "113")
            peaqInstance.disconnect()
        }



    }
}