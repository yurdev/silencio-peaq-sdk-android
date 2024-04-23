package com.silencio.peaq

import android.util.Log
import com.google.gson.Gson
import com.google.gson.stream.JsonReader
import com.neovisionaries.ws.client.WebSocketFactory
import com.silencio.peaq.model.ConstantCodingPath
import com.silencio.peaq.model.CustomServiceData
import com.silencio.peaq.model.PublicKeyPrivateKeyAddressData
import com.silencio.peaq.utils.LoggerImpl
import com.silencio.peaq.utils.getResourceReader
import com.silencio.peaq.utils.notValidResult
import dev.sublab.common.numerics.UInt32
import dev.sublab.common.numerics.UInt64
import dev.sublab.ed25519.ed25519
import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.hex.hex
import dev.sublab.sr25519.sr25519
import dev.sublab.sr25519.sr25519dub
import dev.sublab.ss58.ss58
import io.emeraldpay.polkaj.scale.ScaleCodecReader
import io.peaq.did.Document
import io.peaq.did.Service
import io.peaq.did.Signature
import io.peaq.did.VerificationMethod
import io.peaq.did.VerificationType
import jp.co.soramitsu.fearless_utils.encrypt.EncryptionType
import jp.co.soramitsu.fearless_utils.encrypt.MultiChainEncryption
import jp.co.soramitsu.fearless_utils.encrypt.keypair.substrate.Sr25519Keypair
import jp.co.soramitsu.fearless_utils.encrypt.mnemonic.Mnemonic
import jp.co.soramitsu.fearless_utils.encrypt.mnemonic.MnemonicCreator
import jp.co.soramitsu.fearless_utils.extensions.fromHex
import jp.co.soramitsu.fearless_utils.extensions.requirePrefix
import jp.co.soramitsu.fearless_utils.extensions.toHexString
import jp.co.soramitsu.fearless_utils.runtime.RuntimeSnapshot
import jp.co.soramitsu.fearless_utils.runtime.definitions.TypeDefinitionParser
import jp.co.soramitsu.fearless_utils.runtime.definitions.TypeDefinitionsTree
import jp.co.soramitsu.fearless_utils.runtime.definitions.dynamic.DynamicTypeResolver
import jp.co.soramitsu.fearless_utils.runtime.definitions.dynamic.extentsions.GenericsExtension
import jp.co.soramitsu.fearless_utils.runtime.definitions.registry.TypeRegistry
import jp.co.soramitsu.fearless_utils.runtime.definitions.registry.v14Preset
import jp.co.soramitsu.fearless_utils.runtime.definitions.types.generics.Era
import jp.co.soramitsu.fearless_utils.runtime.definitions.v14.TypesParserV14
import jp.co.soramitsu.fearless_utils.runtime.extrinsic.ExtrinsicBuilder
import jp.co.soramitsu.fearless_utils.runtime.extrinsic.Nonce
import jp.co.soramitsu.fearless_utils.runtime.extrinsic.signer.KeyPairSigner
import jp.co.soramitsu.fearless_utils.runtime.metadata.RuntimeMetadata
import jp.co.soramitsu.fearless_utils.runtime.metadata.RuntimeMetadataReader
import jp.co.soramitsu.fearless_utils.runtime.metadata.builder.VersionedRuntimeBuilder
import jp.co.soramitsu.fearless_utils.runtime.metadata.module.Module
import jp.co.soramitsu.fearless_utils.runtime.metadata.v14.RuntimeMetadataSchemaV14
import jp.co.soramitsu.fearless_utils.wsrpc.SocketService
import jp.co.soramitsu.fearless_utils.wsrpc.executeAsync
import jp.co.soramitsu.fearless_utils.wsrpc.interceptor.WebSocketResponseInterceptor
import jp.co.soramitsu.fearless_utils.wsrpc.recovery.Reconnector
import jp.co.soramitsu.fearless_utils.wsrpc.request.RequestExecutor
import jp.co.soramitsu.fearless_utils.wsrpc.request.base.RpcRequest
import jp.co.soramitsu.fearless_utils.wsrpc.request.runtime.RuntimeRequest
import jp.co.soramitsu.fearless_utils.wsrpc.request.runtime.chain.RuntimeVersion
import jp.co.soramitsu.fearless_utils.wsrpc.response.RpcResponse
import jp.co.soramitsu.fearless_utils.wsrpc.subscription.response.SubscriptionChange
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlin.math.max
import kotlin.math.min

class Peaq(
    private val baseURL: String,
    private val seed: String
) {
    private var socketService: SocketService? = null
    private var runTimeVersion: RuntimeVersion? = null
    private var runtimeMetaData: RuntimeMetadata? = null
    private var catalog: TypeRegistry? = null
    private val maxFinalityLag: UInt32 = 5u
    private val mortalPeriod: UInt64 = 5uL * 60uL * 1000uL
    private var blockNumber: UInt32? = null
    private var eraBlockNumber: ULong? = null
    private var extrinsicEra: Era.Mortal? = null


    init {
        val reconnector = Reconnector()
        val requestExecutor = RequestExecutor()
        socketService = SocketService(
            Gson(),
            LoggerImpl(),
            WebSocketFactory(),
            reconnector,
            requestExecutor
        )
        socketService?.setInterceptor(object : WebSocketResponseInterceptor {
            override fun onRpcResponseReceived(rpcResponse: RpcResponse): WebSocketResponseInterceptor.ResponseDelivery {
                return WebSocketResponseInterceptor.ResponseDelivery.DELIVER_TO_SENDER
            }
        })
        socketService?.start(baseURL)
    }

    suspend fun didCreate(name: String, value: String): Flow<Map<String, String>> {
        return callbackFlow {
            if (socketService?.started() == false){
                socketService?.start(url = baseURL)
            }

            val keyPair = KeyPair.Factory.sr25519().generate(phrase = seed)
            val privateKey = keyPair.privateKey
            val publicKey = keyPair.publicKey
            val accountIdOwner = publicKey.ss58.accountId()
            val accountAddressOwner = publicKey.ss58.address(type = 42)
            fetchRuntimeData()
            val genesisHash = fetchBlockHash(blockNumber = 0u)
            val nonceOwner = fetchAccountNonce(accountAddressOwner)
            executeMortalEraOperation()
            val eraBlockHash = fetchBlockHash(blockNumber = eraBlockNumber?.toUInt() ?: 0u)

            val builder = ExtrinsicBuilder(
                runtime = RuntimeSnapshot(
                    catalog!!,
                    runtimeMetaData!!
                ),
                nonce = Nonce.singleTx(
                    nonceOwner.toInt().toBigInteger()
                ),
                runtimeVersion = runTimeVersion!!,
                genesisHash = genesisHash.fromHex(),
                accountId = accountIdOwner,
                signer = KeyPairSigner(
                    keypair = Sr25519Keypair(
                        keyPair.privateKey.copyOfRange(0, 32),
                        keyPair.publicKey,
                        nonce = keyPair.privateKey.copyOfRange(32, 64)
                    ),
                    encryption = MultiChainEncryption.Substrate(
                        EncryptionType.SR25519
                    )
                ),
                blockHash = eraBlockHash.fromHex(),
                era = extrinsicEra!!
            )

            val theMap = HashMap<String, Any>()
            theMap["did_account"] = accountAddressOwner.ss58.accountId()
            theMap["name"] = name.toByteArray()
            theMap["value"] = value.toByteArray()
            builder.call(
                moduleName = "PeaqDid",
                callName = "add_attribute",
                arguments = theMap
            )
            val extrinsic = builder.build()
            socketService?.subscribe(
                RpcRequest.Rpc2(
                    RuntimeRequest(
                        method = "author_submitAndWatchExtrinsic",
                        params = listOf(extrinsic)
                    )
                ),
                object : SocketService.ResponseListener<SubscriptionChange> {
                    override fun onError(throwable: Throwable) {

                    }

                    override fun onNext(response: SubscriptionChange) {
                        val resultInBlock = response.params.result as? Map<*, *> ?: notValidResult(
                            response.params.result,
                            "bestHeaderResult"
                        )
                        if (resultInBlock["inBlock"] != null) {
                            trySend(mapOf("inBlock" to resultInBlock["inBlock"].toString())).isSuccess
                        } else if (resultInBlock["finalized"] != null) {
                            trySend(mapOf("finalized" to resultInBlock["finalized"].toString())).isSuccess
                            close()
                        }
                    }
                },
                ""
            )
            awaitClose {
                disconnect()
            }
        }


    }

    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun fetchBlockHash(blockNumber: UInt): String {
        var resultString: String? = null
        try {
            val result = socketService?.executeAsync(
                RuntimeRequest(
                    method = "chain_getBlockHash",
                    params = listOf(blockNumber.toHexString().requirePrefix("0x")),
                )
            )
            resultString = result?.result.toString()
        } catch (e: Exception) {
            e.printStackTrace()
        }

        return resultString ?: ""
    }

    private suspend fun fetchAccountNonce(accountAddress: String): UInt32 {
        var resultNonce: UInt32? = null
        val result = socketService?.executeAsync(
            RuntimeRequest(
                method = "system_accountNextIndex",
                params = listOf(accountAddress)
            )
        )
        resultNonce = result?.result.toString().toDoubleOrNull()?.toUInt()
        return resultNonce ?: 0u
    }

    private suspend fun executeMortalEraOperation() {
        val path = ConstantCodingPath(moduleName = "System", constantName = "BlockHashCount")
        val value =
            runtimeMetaData?.modules?.get(path.moduleName)?.constants?.get(path.constantName)?.value
        val type =
            runtimeMetaData?.modules?.get(path.moduleName)?.constants?.get(path.constantName)?.type?.name
        val blockHashCount = catalog?.get(type!!)?.decode(
            scaleCodecReader = ScaleCodecReader(value),
            RuntimeSnapshot(catalog!!, runtimeMetaData!!)
        )
        val path2 = ConstantCodingPath(moduleName = "Timestamp", constantName = "MinimumPeriod")
        val value2 =
            runtimeMetaData?.modules?.get(path2.moduleName)?.constants?.get(path2.constantName)?.value
        val type2 =
            runtimeMetaData?.modules?.get(path2.moduleName)?.constants?.get(path2.constantName)?.type?.name
        val minimumPeriod = catalog?.get(type2!!)?.decode(
            scaleCodecReader = ScaleCodecReader(value2),
            RuntimeSnapshot(catalog!!, runtimeMetaData!!)
        )

        val blockTime = minimumPeriod.toString().toULong()

        val unmappedPeriod = (mortalPeriod / blockTime) + maxFinalityLag.toULong()
        val mortalLength = min(blockHashCount.toString().toULong(), unmappedPeriod)

        fetchBlockNumber()
        val constrainedPeriod = min((1 shl 16).toULong(), max(4u, mortalLength))
        var period: UInt64 = 1u
        while (period < constrainedPeriod) {
            period = period shl 1
        }
        val unquantizedPhase = blockNumber?.toULong()?.rem(period)
        val quantizeFactor = max(period shr 12, 1u)
        val phase = (unquantizedPhase?.div(quantizeFactor))?.times(quantizeFactor)
        eraBlockNumber = (((blockNumber?.toULong()
            ?.minus(phase ?: 0u))?.div(period))?.times(period))?.plus(phase ?: 0u)
        extrinsicEra =
            phase?.toInt()?.let { Era.Mortal(period = period.toInt(), phase = it) }
    }

    private suspend fun fetchRuntimeData() {

        /**
         * RunTime Version
         */
        val resultRuntimeVersion = socketService?.executeAsync(
            RuntimeRequest(
                method = "chain_getRuntimeVersion",
                params = listOf()
            )
        )
        val resultRuntimeVersionMap = resultRuntimeVersion?.result as? Map<*, *> ?: notValidResult(
            resultRuntimeVersion?.result,
            "RuntimeVersion"
        )
        val specVersion =
            resultRuntimeVersionMap["specVersion"] as? Double ?: notValidResult(
                resultRuntimeVersionMap,
                "RuntimeVersion"
            )
        val transactionVersion =
            resultRuntimeVersionMap["transactionVersion"] as? Double ?: notValidResult(
                resultRuntimeVersionMap,
                "RuntimeVersion"
            )


        runTimeVersion = RuntimeVersion(specVersion.toInt(), transactionVersion.toInt())


        /**
         * Runtime Meta data
         */


        val resultRuntimeMetadata = socketService?.executeAsync(
            RuntimeRequest(
                method = "state_getMetadata",
                params = listOf()
            )
        )

        val metadataReader = RuntimeMetadataReader.read(resultRuntimeMetadata?.result.toString())
        when (metadataReader.metadataVersion) {
            14 -> {
                val typePreset = TypesParserV14.parse(
                    lookup = metadataReader.metadata[RuntimeMetadataSchemaV14.lookup],
                    typePreset = v14Preset()
                )

                val typeRegistry = TypeRegistry(
                    typePreset,
                    DynamicTypeResolver.defaultCompoundResolver()
                )
                runtimeMetaData = VersionedRuntimeBuilder.buildMetadata(
                    metadataReader,
                    typeRegistry
                )
            }

            else -> {
                /**
                 * need to find this else runtimeMetadata generator code
                 */
                throw Exception("Version ${metadataReader.metadataVersion} is not supported yet.")
            }
        }

        /**
         * catalog
         */

        val gson = Gson()
        val metadataTypePreset = TypesParserV14.parse(
            lookup = metadataReader.metadata[RuntimeMetadataSchemaV14.lookup],
            typePreset = v14Preset()
        )


        val networkTypesReader = JsonReader(getResourceReader("runtime-peaq.json"))
        val networkTypesTree = gson.fromJson<TypeDefinitionsTree>(
            networkTypesReader,
            TypeDefinitionsTree::class.java
        )
        val completeTypes = TypeDefinitionParser.parseBaseDefinitions(
            networkTypesTree,
            metadataTypePreset
        )

        val typeRegistry = TypeRegistry(
            types = completeTypes,
            dynamicTypeResolver = DynamicTypeResolver(
                DynamicTypeResolver.DEFAULT_COMPOUND_EXTENSIONS + GenericsExtension
            )
        )
        catalog = typeRegistry

    }

    private suspend fun fetchBlockNumber() {
        /**
         * blockHash
         */
        val resultBlockHash = socketService?.executeAsync(
            RuntimeRequest(
                method = "chain_getFinalizedHead",
                params = listOf()
            )
        )

        /**
         * finalizedHeader
         */
        val resultFinalizedHeader = socketService?.executeAsync(
            RuntimeRequest(
                method = "chain_getHeader",
                params = listOf(resultBlockHash?.result ?: Any())
            )
        )

        /**
         * header
         */
        val resultHeader = socketService?.executeAsync(
            RuntimeRequest(
                method = "chain_getHeader",
                params = listOf()
            )
        )

        /**
         * bestHeader
         */
        val resultBlockHashMap = resultHeader?.result as? Map<*, *> ?: notValidResult(
            resultHeader?.result,
            "Header"
        )
        var bestHeader: Any? = null

        if (!resultBlockHashMap["parentHash"].toString().isNullOrEmpty()) {
            val resultBestHeader = socketService?.executeAsync(
                RuntimeRequest(
                    method = "chain_getHeader",
                    params = listOf(resultBlockHashMap["parentHash"]!!)
                )
            )
            bestHeader = resultBestHeader?.result


        } else {
            bestHeader = resultHeader.result
        }
        val bestHeaderResultMap =
            bestHeader as? Map<*, *> ?: notValidResult(bestHeader, "bestHeaderResult")

        val finalizedHeaderResultMAp =
            resultFinalizedHeader?.result as? Map<*, *> ?: notValidResult(
                resultFinalizedHeader?.result,
                "finalizedHeaderResult"
            )
        var bestNumber =
            bestHeaderResultMap["number"].toString().hex.toBigInteger().toInt().toULong()
        var finalizedNumber =
            finalizedHeaderResultMAp["number"].toString().hex.toBigInteger().toInt().toULong()
        if (bestNumber >= finalizedNumber) {
            blockNumber = if (bestNumber - finalizedNumber > maxFinalityLag) {
                bestNumber.toUInt()
            } else {
                finalizedNumber.toUInt()
            }

        } else {
            throw Exception("bestNumber is grater then finalizedNumber")
        }
    }

    /**
     * Disconnect socketService
     */
     fun disconnect(){
        socketService?.stop()
    }


    /**
     * CreateDidDocument
     */


    suspend fun createDidDocument(
        issuerSeed: String,
        ownerAddress: String,
        machineAddress: String,
        machinePublicKey: ByteArray,
        customData: List<CustomServiceData> = emptyList()
    ): String {
        val keyPair = KeyPair.Factory.sr25519().generate(phrase = issuerSeed)
        val issuerPublicKey = keyPair.publicKey
        val issuerAddress = issuerPublicKey.ss58.address(42)
        val originalData = machineAddress.ss58.toString().toByteArray()
        val signature = keyPair.sign(originalData)
        val builder = Document.newBuilder()

        builder.id = "did:peaq:${machineAddress}"
        builder.controller = "did:peaq:${issuerAddress}"

        val docVerificationMethod =
            VerificationMethod.newBuilder().setType(VerificationType.Sr25519VerificationKey2020)
                .setId(machinePublicKey.ss58.toString().toByteArray().toHexString())
                .setController("did:peaq:${issuerAddress}")
                .setPublicKeyMultibase(machineAddress)

        builder.addVerificationMethods(docVerificationMethod.build())

        val docSignature = Signature.newBuilder().setIssuer(issuerAddress)
            .setType(VerificationType.Sr25519VerificationKey2020).setHash(signature.toHexString())
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
            for (data in customData){
                val docServiceCustom = Service.newBuilder()
                docServiceCustom.id = data.id
                docServiceCustom.type = data.type
                docServiceCustom.data = data.data

                builder.addServices(docServiceCustom.build())
            }

        }

        val document = builder.build()


        return document.toByteArray().toHexString()
    }

    suspend fun generateMnemonicWord(): String {
        return MnemonicCreator.randomMnemonic(Mnemonic.Length.TWELVE).words
    }

    suspend fun generatePublicKeyPrivateKeyAddress(mnemonicWord : String) : PublicKeyPrivateKeyAddressData {
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

     suspend fun signData(
        plainData: String,
        machineSeed: String,
        format: com.silencio.peaq.utils.EncryptionType
    ): String {
        val originalData = plainData.toByteArray()
        val keyPair: KeyPair
        var sign: ByteArray? = null
        when (format) {
           com.silencio.peaq.utils.EncryptionType.SR25519 -> {
                keyPair = KeyPair.Factory.sr25519().generate(phrase = machineSeed)
                sign = keyPair.sign(originalData)

            }
            com.silencio.peaq.utils.EncryptionType.ED25519 -> {
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
    suspend fun verifySignatureData(
        machinePublicKey: String,
        plainData: String,
        signature: String
    ): Boolean {
        val originalData = plainData.toByteArray()
        var verify: Boolean = false

        val sigData = signature.hexToByteArray()


        val publicKey : ByteArray = machinePublicKey.hexToByteArray()
        try {
            verify = publicKey.sr25519dub().verify(originalData,sigData)
        }catch (_ : Exception){
            try {
                verify = publicKey.ed25519.verify(originalData,sigData)
            }catch (e : Exception){
                Log.e("Exception","Exception ${e}")
            }
        }

        return verify

    }



    suspend fun store(payloadData : String,itemType : String) {
        if (socketService?.started() == false){
            socketService?.start(url = baseURL)
        }
        val keyPair = KeyPair.Factory.sr25519().generate(phrase = seed)
        val privateKey = keyPair.privateKey
        val publicKey = keyPair.publicKey
        val accountIdOwner = publicKey.ss58.accountId()
        val accountAddressOwner = publicKey.ss58.address(type = 42)
        fetchRuntimeData()
        val genesisHash = fetchBlockHash(blockNumber = 0u)
        val nonceOwner = fetchAccountNonce(accountAddressOwner)
        executeMortalEraOperation()
        val eraBlockHash = fetchBlockHash(blockNumber = eraBlockNumber?.toUInt() ?: 0u)

        val builder = ExtrinsicBuilder(
            runtime = RuntimeSnapshot(
                catalog!!,
                runtimeMetaData!!
            ),
            nonce = Nonce.singleTx(
                nonceOwner.toInt().toBigInteger()
            ),
            runtimeVersion = runTimeVersion!!,
            genesisHash = genesisHash.fromHex(),
            accountId = accountIdOwner,
            signer = KeyPairSigner(
                keypair = Sr25519Keypair(
                    keyPair.privateKey.copyOfRange(0, 32),
                    keyPair.publicKey,
                    nonce = keyPair.privateKey.copyOfRange(32, 64)
                ),
                encryption = MultiChainEncryption.Substrate(
                    EncryptionType.SR25519
                )
            ),
            blockHash = eraBlockHash.fromHex(),
            era = extrinsicEra!!
        )




        val theMap = HashMap<String, Any>()
        theMap["did_account"] = accountAddressOwner.ss58.accountId()

        theMap["item_type"] = itemType.toByteArray()
        theMap["item"] = payloadData.toByteArray()

        builder.call(
            moduleName = "PeaqStorage",
            callName = "add_item",
            arguments = theMap
        )

        val extrinsic = builder.build()

        val store = socketService?.executeAsync(
            RuntimeRequest(
                method = "author_submitExtrinsic",
                params = listOf(extrinsic)
            )
        )
        Log.e("Store Data","Store Data ${store?.result}")
    }

}