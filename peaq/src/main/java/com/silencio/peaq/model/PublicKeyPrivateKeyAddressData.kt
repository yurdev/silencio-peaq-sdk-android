package com.silencio.peaq.model

data class PublicKeyPrivateKeyAddressData(
    val publicKey: ByteArray,
    val privateKey : ByteArray,
    val address: String
)
