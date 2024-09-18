package com.silencio.peaq

import android.util.Log
import com.google.gson.Gson
import com.google.gson.stream.JsonReader
import com.neovisionaries.ws.client.WebSocketFactory
import com.silencio.peaq.model.ConstantCodingPath
import com.silencio.peaq.model.DIDData
import com.silencio.peaq.model.DIDDocumentCustomData
import com.silencio.peaq.model.PublicKeyPrivateKeyAddressData
import com.silencio.peaq.utils.LoggerImpl
import com.silencio.peaq.utils.LoggerMode
import com.silencio.peaq.utils.getResourceReader
import com.silencio.peaq.utils.notValidResult
import dev.sublab.common.numerics.UInt32
import dev.sublab.common.numerics.UInt64
import dev.sublab.ed25519.ed25519
import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.hex.hex
import dev.sublab.sr25519.sr25519
import dev.sublab.sr25519.sr25519Clone

import dev.sublab.ss58.ss58
import io.emeraldpay.polkaj.scale.ScaleCodecReader
import io.peaq.did.Document
import io.peaq.did.Service
import io.peaq.did.Signature
import io.peaq.did.VerificationMethod
import io.peaq.did.VerificationType
import io.novasama.substrate_sdk_android.encrypt.EncryptionType
import io.novasama.substrate_sdk_android.encrypt.MultiChainEncryption
import io.novasama.substrate_sdk_android.encrypt.keypair.substrate.Sr25519Keypair
import io.novasama.substrate_sdk_android.encrypt.mnemonic.Mnemonic
import io.novasama.substrate_sdk_android.encrypt.mnemonic.MnemonicCreator
import io.novasama.substrate_sdk_android.extensions.fromHex
import io.novasama.substrate_sdk_android.extensions.requirePrefix
import io.novasama.substrate_sdk_android.extensions.toHexString
import io.novasama.substrate_sdk_android.runtime.RuntimeSnapshot
import io.novasama.substrate_sdk_android.runtime.definitions.TypeDefinitionParser
import io.novasama.substrate_sdk_android.runtime.definitions.TypeDefinitionsTree
import io.novasama.substrate_sdk_android.runtime.definitions.dynamic.DynamicTypeResolver
import io.novasama.substrate_sdk_android.runtime.definitions.dynamic.extentsions.GenericsExtension
import io.novasama.substrate_sdk_android.runtime.definitions.registry.TypeRegistry
import io.novasama.substrate_sdk_android.runtime.definitions.registry.v14Preset
import io.novasama.substrate_sdk_android.runtime.definitions.types.generics.Era
import io.novasama.substrate_sdk_android.runtime.definitions.v14.TypesParserV14
import io.novasama.substrate_sdk_android.runtime.extrinsic.ExtrinsicBuilder
import io.novasama.substrate_sdk_android.runtime.extrinsic.Nonce
import io.novasama.substrate_sdk_android.runtime.extrinsic.signer.KeyPairSigner
import io.novasama.substrate_sdk_android.runtime.metadata.RuntimeMetadata
import io.novasama.substrate_sdk_android.runtime.metadata.RuntimeMetadataReader
import io.novasama.substrate_sdk_android.runtime.metadata.builder.VersionedRuntimeBuilder
import io.novasama.substrate_sdk_android.runtime.metadata.v14.RuntimeMetadataSchemaV14
import io.novasama.substrate_sdk_android.wsrpc.SocketService
import io.novasama.substrate_sdk_android.wsrpc.executeAsync
import io.novasama.substrate_sdk_android.wsrpc.interceptor.WebSocketResponseInterceptor
import io.novasama.substrate_sdk_android.wsrpc.recovery.Reconnector
import io.novasama.substrate_sdk_android.wsrpc.request.RequestExecutor
import io.novasama.substrate_sdk_android.wsrpc.request.base.RpcRequest
import io.novasama.substrate_sdk_android.wsrpc.request.runtime.RuntimeRequest
import io.novasama.substrate_sdk_android.wsrpc.request.runtime.chain.RuntimeVersion
import io.novasama.substrate_sdk_android.wsrpc.response.RpcResponse
import io.novasama.substrate_sdk_android.wsrpc.subscription.response.SubscriptionChange
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlin.math.max
import kotlin.math.min

class Peaq(
    private val baseURL: String,
    private val seed: String?
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

    private val logger = LoggerImpl()

    init {
        val reconnector = Reconnector()
        val requestExecutor = RequestExecutor()
        socketService = SocketService(
            Gson(),
            logger,
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

    suspend fun createDid(secretPhrase: String, name: String, value: String): Flow<DIDData> {
        return callbackFlow {
            if (socketService?.started() == false) {
                socketService?.start(url = baseURL)
            }

            val keyPair = KeyPair.Factory.sr25519().generate(phrase = secretPhrase)
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
                        trySend(DIDData(error = throwable.message.toString())).isSuccess
                    }

                    override fun onNext(response: SubscriptionChange) {
                        val resultInBlock = response.params.result as? Map<*, *> ?: notValidResult(
                            response.params.result,
                            "bestHeaderResult"
                        )
                        if (resultInBlock["inBlock"] != null) {
                            trySend(DIDData(inBlock = resultInBlock["inBlock"].toString())).isSuccess
                        } else if (resultInBlock["finalized"] != null) {
                            trySend(DIDData(finalized = resultInBlock["finalized"].toString())).isSuccess
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

    fun setLoggerMode(mode: LoggerMode) {
        logger.setMode(mode)
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
    fun disconnect() {
        socketService?.stop()
    }


    /**
     * CreateDidDocument
     */


    suspend fun createDidDocument(
        ownerAddress: String,
        machineAddress: String,
        machinePublicKey: ByteArray,
        customData: List<DIDDocumentCustomData> = emptyList()
    ): Document {
        if (!seed.isNullOrEmpty() && seed.isNotBlank()){
            val keyPair = KeyPair.Factory.sr25519().generate(phrase = seed)
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
                    .setPublicKeyMultibase(machinePublicKey.toHexString())

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
        }else {
            return Document.newBuilder().build()
        }

    }





    suspend fun storeMachineDataHash(
        payloadData: String,
        itemType: String,
        machineSeed: String
    ): RpcResponse? {
        if (socketService?.started() == false) {
            socketService?.start(url = baseURL)
        }
        val keyPair = KeyPair.Factory.sr25519().generate(phrase = machineSeed)
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
        return store
    }









}