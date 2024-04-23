package com.silencio.peaqexample

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.gson.Gson
import com.silencio.peaq.Peaq
import com.silencio.peaq.model.CustomServiceData
import com.silencio.peaq.utils.EncryptionType
import com.silencio.peaq.utils.PeaqUtils
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
            val (issuerPublicKey,issuerPrivateKey,issuerAddress) = peaqInstance.generatePublicKeyPrivateKeyAddress(mnemonicWord = issuerSeed)

            val ownerSeed = peaqInstance.generateMnemonicWord()
            val (ownerPublicKey,ownerPrivateKey,ownerAddress) = peaqInstance.generatePublicKeyPrivateKeyAddress(mnemonicWord = ownerSeed)

            val machineSeed = peaqInstance.generateMnemonicWord()
            val (machinePublicKey,machinePrivateKey,machineAddress) = peaqInstance.generatePublicKeyPrivateKeyAddress(mnemonicWord = machineSeed)

            val document = peaqInstance.createDidDocument(
                issuerSeed = issuerSeed,
                ownerAddress = ownerAddress,
                machineAddress = machineAddress,
                machinePublicKey = machinePublicKey
            )
           val map =  peaqInstance.didCreate(name ="did:peaq:$machineAddress" , value = document)
            map.collectLatest {
                if (it.containsKey("inBlock")){
                    Log.e("Hash Key","Hash Key ${it["inBlock"]}")
                }

            }
            val payloadData = CustomServiceData(id = machineAddress, type = "Custom_data", data = "a@gmail.com")
            val payload = Gson().toJson(payloadData)
            val payloadHex = peaqInstance.signData(payload,issuerSeed, format = EncryptionType.ED25519)
            Log.e("PayLoadHex","PayLoadHex ${payloadHex}")

            peaqInstance.store(payloadData = payloadHex , itemType = "113")
            peaqInstance.disconnect()
        }



    }
}