package org.awep2p

import android.app.Service
import android.content.Intent
import android.os.IBinder

/** Lifecycle boundary: the Rust core owns node state; Android owns lifecycle and power policy. */
class AweNodeService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY
}
