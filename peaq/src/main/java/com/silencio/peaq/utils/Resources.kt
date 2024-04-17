package com.silencio.peaq.utils

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.Reader

fun Any.notValidResult(result: Any?, ofWhat: String): Nothing {
    throw IllegalArgumentException("$result is not a valid $ofWhat result")
}

fun Any.getResourceReader(fileName: String): Reader {
    val stream = javaClass.classLoader!!.getResourceAsStream(fileName)

    return BufferedReader(InputStreamReader(stream))
}