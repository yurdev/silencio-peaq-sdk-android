package com.silencio.peaq.utils

import android.util.Log
import jp.co.soramitsu.fearless_utils.wsrpc.logging.Logger

class LoggerImpl : Logger {
    override fun log(message: String?) {
        Log.w("Logger Message","Logger Message : ${message}")
    }

    override fun log(throwable: Throwable?) {
        Log.w("Logger Throwable","Logger Throwable : ${throwable}")
    }
}