package org.awep2p

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder

/** Lifecycle boundary: the Rust core owns node state; Android owns lifecycle, battery, and power policy. */
class AweNodeService : Service() {

    companion object {
        const val CHANNEL_ID = "awep2p_node_channel"
        const val NOTIFICATION_ID = 1001

        external fun nativeStartNode(dataDir: String, listenAddr: String): Int
        external fun nativeStopNode(): Int
        external fun nativeGetNodeStatus(): String

        init {
            System.loadLibrary("awep2p_core")
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = buildForegroundNotification()
        startForeground(NOTIFICATION_ID, notification)

        val dataDir = filesDir.absolutePath
        nativeStartNode(dataDir, "0.0.0.0:41000")

        return START_STICKY
    }

    override fun onDestroy() {
        nativeStopNode()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "AWEp2P Background Node",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildForegroundNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("AWEp2P Node Active")
            .setContentText("Sovereign P2P network node running")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .build()
    }
}
