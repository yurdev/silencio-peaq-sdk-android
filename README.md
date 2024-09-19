# SilencioPeaq.Android



```groovy
implementation('store.silencio:peaqsdk:1.0.11')
```

## Project Configuration

Update your `settings.gradle` to manage dependencies as follows:

```groovy
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
        maven { url = uri("https://repo.repsy.io/mvn/chrynan/public") }
    }
}
```
If needed please add below line in `<application>` tag Manifest 

```manifest

        tools:replace="android:theme"
```

## Setup Instructions

initialize the Peaq instance as follows:

```kotlin
val issuerSeed = "ADD_ISSUER_SEED_HERE"  // Replace with your actual issuer seed
val peaqInstance = Peaq(
    baseURL = "ADD_BASE_URL_ACCORDINGLY", // Replace with the actual base URL
    seed = issuerSeed
)
```
You can use some utils function directly without use of `peaqInstance`

```kotlin
// This function is use for creating Mnemonic(Seed)
val ownerSeed = PeaqUtils.generateMnemonicSeed()

// This function is use for get PublicKey, PrivateKey & Address from seed in SR25519 format
val (ownerPublicKey, ownerPrivateKey, ownerAddress) = PeaqUtils.getPublicPrivateKeyAddressFromMachineSeed(
    mnemonicWord = ownerSeed
)

// This function is use for get PublicKey, PrivateKey & Address from seed in ED25519 format
val (ownerPublicKeyED25519, ownerPrivateKeyED25519, ownerAddressED25519) = PeaqUtils.getED25519PublicPrivateKeyAddressFromMachineSeed(
    mnemonicWord = ownerSeed
)

// This Function is use for create signature or sign data
PeaqUtils.signData(
    plainData = "DATA_YOU_NEED_TO_SIGN_IN_STRING", // Replace this with your plain data
    machineSeed = "SEED_WHICH_ARE_YOU_USING_FOR_SIGN_DATA", // Replace this with your seed
    format = "YOUR_SIGN_FORMAT") // use  EncryptionType.SR25519 or EncryptionType.ED25519

// This function use for verify your signature and return boolean value

PeaqUtils.verifyData(
    machinePublicKey = "YOUR_PUBLIC_KEY_WHICH_SEED_YOU_HAVE_USE_FOR_SIGNATURE_DATA",
    plainData = "YOUR_PLAIN_DATA_WHICH_YOU_HAVE_USE_FOR_CREATE_SIGNATURE",
    signature = "YOUR_SIGNATURE"
)

// This is use for creating did document with out using of issuer seed
val documentWithoutSeed = PeaqUtils.createDidDocumentWithoutSeed(
    issuerAddress = "YOUR_ISSUER_SEED",
    ownerAddress = "YOUR_OWNER_ADDRESS",
    machineAddress = "YOUR_MACHINE_ADDRESS",
    machinePublicKey = "YOUR_MACHINE_PUBLIC_KEY",
    signature = "ADD_YOUR_SIGNATURE_WHICH_SIGN_BY_YOUR_ISSUER",
    customData = "YOUR_CUSTOM_DATA" // This is in List<DIDDocumentCustomData>
    
)

```

## Example

```kotlin

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
                val documentWithoutSeed = PeaqUtils.createDidDocumentWithoutSeed(
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

```

