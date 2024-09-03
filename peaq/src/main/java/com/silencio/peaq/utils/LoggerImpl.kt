package com.silencio.peaq.utils

import android.util.Log
import io.novasama.substrate_sdk_android.wsrpc.logging.Logger

class LoggerImpl : Logger {

    private var mode = LoggerMode.PRODUCTION

    override fun log(message: String?) {
        if(mode == LoggerMode.DEBUG){
            Log.w("Logger Message","Logger Message : ${message}")
        }
    }

    override fun log(throwable: Throwable?) {
        if(mode == LoggerMode.DEBUG){
            Log.w("Logger Throwable","Logger Throwable : ${throwable}")
        }
    }

    fun setMode(mode: LoggerMode){
        this.mode = mode
    }
}