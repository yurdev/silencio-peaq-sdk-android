package com.silencio.peaqexample

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.silencio.peaq.Peaq
import com.silencio.peaq.utils.PeaqUtils
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val issuerSeed = "speed movie excess amateur tent envelope few raise egg large either antique"
        val peaqInstance = Peaq(
            baseURL = "wss://wsspc1-qa.agung.peaq.network/",
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
                if (it.containsKey("finalized")){
                    peaqInstance.disconnect()
                }
            }
        }



    }
}