package billion.group.wireguard_flutter

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.PluginRegistry

import android.app.Activity
import io.flutter.embedding.android.FlutterActivity
import android.content.Intent
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import com.beust.klaxon.Klaxon
import com.wireguard.android.backend.*
import com.wireguard.config.Config
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair
import io.flutter.plugin.common.EventChannel
import kotlinx.coroutines.*
import java.util.*


import kotlinx.coroutines.launch
import java.io.ByteArrayInputStream

/** WireguardFlutterPlugin */

const val PERMISSIONS_REQUEST_CODE = 10014
const val METHOD_CHANNEL_NAME = "billion.group.wireguard_flutter/wgcontrol"
const val METHOD_EVENT_NAME = "billion.group.wireguard_flutter/wgstage"

class WireguardFlutterPlugin : FlutterPlugin, MethodCallHandler, ActivityAware,
    PluginRegistry.ActivityResultListener {
    private lateinit var channel: MethodChannel
    private lateinit var events: EventChannel
    private lateinit var tunnelName: String
    private val futureBackend = CompletableDeferred<Backend>()
    private var vpnStageSink: EventChannel.EventSink? = null
    private val scope = CoroutineScope(Job() + Dispatchers.Main.immediate)
    private var backend: Backend? = null
    private var havePermission = false
    private lateinit var context: Context
    private var activity: Activity? = null
    private var config: com.wireguard.config.Config? = null
    private var tunnel: WireGuardTunnel? = null
    private val TAG = "NVPN"
    var isVpnChecked = false
    companion object {
        private var state: String = "no_connection"

        fun getStatus(): String {
            return state
        }
    }
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        this.havePermission =
            (requestCode == PERMISSIONS_REQUEST_CODE) && (resultCode == Activity.RESULT_OK)
        return havePermission
    }

    override fun onAttachedToActivity(activityPluginBinding: ActivityPluginBinding) {
        this.activity = activityPluginBinding.activity as FlutterActivity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        this.activity = null
    }

    override fun onReattachedToActivityForConfigChanges(activityPluginBinding: ActivityPluginBinding) {
        this.activity = activityPluginBinding.activity as FlutterActivity
    }

    override fun onDetachedFromActivity() {
        this.activity = null
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, METHOD_CHANNEL_NAME)
        events = EventChannel(flutterPluginBinding.binaryMessenger, METHOD_EVENT_NAME)
        context = flutterPluginBinding.applicationContext

        scope.launch(Dispatchers.IO) {
            try {
                backend = createBackend()
                futureBackend.complete(backend!!)
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }

        channel.setMethodCallHandler(this)
        events.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                isVpnChecked = false
                vpnStageSink = events
            }

            override fun onCancel(arguments: Any?) {
                isVpnChecked = false
                vpnStageSink = null
            }
        })

    }

    private fun createBackend(): Backend {
        if (backend == null) {
            backend = GoBackend(context)
        }
        return backend as Backend
    }

    private fun flutterSuccess(result: Result, o: Any) {
        scope.launch(Dispatchers.Main) {
            result.success(o)
        }
    }

    private fun flutterError(result: Result, error: String) {
        scope.launch(Dispatchers.Main) {
            result.error(error, null, null)
        }
    }

    private fun flutterNotImplemented(result: Result) {
        scope.launch(Dispatchers.Main) {
            result.notImplemented()
        }
    }

    override fun onMethodCall(call: MethodCall, result: Result) {

        when (call.method) {
            "initialize" -> setupTunnel(call.argument<String>("localizedDescription").toString(), result)
            "start" -> {
                connect(call.argument<String>("wgQuickConfig").toString(), result)

                if (!isVpnChecked) {
                    if (isVpnActive()) {
                        state = "connected"
                        isVpnChecked = true
                        println("VPN is active")
                    } else {
                        state = "disconnected"
                        isVpnChecked = true
                        println("VPN is not active")
                    }
                }
            }
            "stop" -> {
                disconnect(result)
            }
            "stage" -> {
                result.success(getStatus())
            }
            "checkPermission" -> {
                checkPermission()
                result.success(null)
            }
            "getDownloadData" -> {
                getDownloadData(result)
            }
            "getUploadData" -> {
                getUploadData(result)
            }
            else -> flutterNotImplemented(result)
        }
    }

    private fun isVpnActive(): Boolean {
        try {
            val connectivityManager =
                context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val activeNetwork = connectivityManager.activeNetwork
                val networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                return networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            } else {
                return false
            }
        } catch (e: Exception) {
            Log.e(TAG, "isVpnActive - ERROR - ${e.message}")
            return false
        }
    }

    private fun updateStage(stage: String?) {
        scope.launch(Dispatchers.Main) {
            val updatedStage = stage ?: "no_connection"
            state = updatedStage
            vpnStageSink?.success(updatedStage.lowercase(Locale.ROOT))
        }
    }

    private fun updateStageFromState(state: Tunnel.State) {
        scope.launch(Dispatchers.Main) {
            when (state) {
                Tunnel.State.UP -> updateStage("connected")
                Tunnel.State.DOWN -> updateStage("disconnected")
                else -> updateStage("wait_connection")
            }
        }
    }

    // Создаём минимальный конфиг для отключения
    private fun createDummyConfig(): Config {
        val keyPair = KeyPair()
        
        val interfaceBuilder = Interface.Builder()
        interfaceBuilder.parseAddresses("10.0.0.1/32")
        interfaceBuilder.setKeyPair(keyPair)
        
        val peerBuilder = Peer.Builder()
        peerBuilder.parsePublicKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        peerBuilder.parseAllowedIPs("0.0.0.0/0")
        
        return Config.Builder()
            .setInterface(interfaceBuilder.build())
            .addPeer(peerBuilder.build())
            .build()
    }

    private fun disconnect(result: Result) {
        scope.launch(Dispatchers.IO) {
            try {
                val backend = futureBackend.await()
                val runningTunnels = backend.runningTunnelNames
                val vpnActuallyRunning = isVpnActive()
                
                Log.i(TAG, "Disconnect - runningTunnels: $runningTunnels, vpnActuallyRunning: $vpnActuallyRunning")
                
                // VPN не работает - просто выходим
                if (runningTunnels.isEmpty() && !vpnActuallyRunning) {
                    Log.i(TAG, "Disconnect - VPN already off")
                    updateStage("disconnected")
                    flutterSuccess(result, "")
                    return@launch
                }
                
                updateStage("disconnecting")
                
                // Способ 1: Плагин знает о туннеле - стандартное отключение
                if (runningTunnels.isNotEmpty()) {
                    try {
                        Log.i(TAG, "Disconnect - trying standard method for tunnels: $runningTunnels")
                        
                        // Отключаем ВСЕ известные туннели
                        for (tunnelNameItem in runningTunnels) {
                            Log.i(TAG, "Disconnect - stopping tunnel: $tunnelNameItem")
                            val tempTunnel = object : Tunnel {
                                override fun getName(): String = tunnelNameItem
                                override fun onStateChange(newState: Tunnel.State) {
                                    Log.i(TAG, "Tunnel $tunnelNameItem state: $newState")
                                }
                            }
                            backend.setState(tempTunnel, Tunnel.State.DOWN, null)
                        }
                        
                        delay(300)
                        if (!isVpnActive()) {
                            Log.i(TAG, "Disconnect - standard method success!")
                            tunnel = null
                            updateStage("disconnected")
                            flutterSuccess(result, "")
                            return@launch
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Disconnect standard failed: ${e.message}")
                    }
                }
                
                // Способ 2: VPN работает но плагин не знает - пробуем "подключиться" с dummy config и сразу отключить
                if (isVpnActive()) {
                    Log.i(TAG, "Disconnect - VPN still running, trying reconnect-disconnect trick")
                    
                    try {
                        val dummyConfig = createDummyConfig()
                        val tempTunnel = object : Tunnel {
                            override fun getName(): String = tunnelName
                            override fun onStateChange(newState: Tunnel.State) {
                                Log.i(TAG, "Dummy tunnel state: $newState")
                            }
                        }
                        
                        // Это должно "перехватить" существующий VPN
                        Log.i(TAG, "Disconnect - setting UP with dummy config to take over VPN")
                        backend.setState(tempTunnel, Tunnel.State.UP, dummyConfig)
                        
                        delay(500)
                        
                        // Теперь отключаем
                        Log.i(TAG, "Disconnect - now setting DOWN")
                        backend.setState(tempTunnel, Tunnel.State.DOWN, null)
                        
                        delay(300)
                        if (!isVpnActive()) {
                            Log.i(TAG, "Disconnect - reconnect-disconnect trick worked!")
                            tunnel = null
                            updateStage("disconnected")
                            flutterSuccess(result, "")
                            return@launch
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Reconnect-disconnect trick failed: ${e.message}", e)
                    }
                }
                
                // Способ 3: Пробуем отключить по имени wg0 напрямую
                if (isVpnActive()) {
                    Log.i(TAG, "Disconnect - trying to disconnect wg0 directly")
                    
                    try {
                        val wg0Tunnel = object : Tunnel {
                            override fun getName(): String = "wg0"
                            override fun onStateChange(newState: Tunnel.State) {
                                Log.i(TAG, "wg0 state: $newState")
                            }
                        }
                        backend.setState(wg0Tunnel, Tunnel.State.DOWN, null)
                        
                        delay(300)
                        if (!isVpnActive()) {
                            Log.i(TAG, "Disconnect - wg0 direct disconnect worked!")
                            tunnel = null
                            updateStage("disconnected")
                            flutterSuccess(result, "")
                            return@launch
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "wg0 direct disconnect failed: ${e.message}")
                    }
                }
                
                // Способ 4: stopService как последняя надежда
                if (isVpnActive()) {
                    Log.i(TAG, "Disconnect - trying stopService")
                    try {
                        val intent = Intent(context, GoBackend.VpnService::class.java)
                        context.stopService(intent)
                        delay(500)
                    } catch (e: Exception) {
                        Log.e(TAG, "stopService failed: ${e.message}")
                    }
                }
                
                tunnel = null
                val stillRunning = isVpnActive()
                Log.i(TAG, "Disconnect - finished, VPN still running: $stillRunning")
                
                updateStage("disconnected")
                
                if (stillRunning) {
                    flutterError(result, "VPN_STILL_RUNNING")
                } else {
                    flutterSuccess(result, "")
                }
                
            } catch (e: BackendException) {
                Log.e(TAG, "Disconnect - BackendException - ${e.reason}", e)
                tunnel = null
                updateStage("disconnected")
                flutterError(result, e.reason.toString())
            } catch (e: Throwable) {
                Log.e(TAG, "Disconnect - Error: ${e.message}", e)
                tunnel = null
                updateStage("disconnected")
                flutterError(result, e.message.toString())
            }
        }
    }

    private fun connect(wgQuickConfig: String, result: Result) {
        scope.launch(Dispatchers.IO) {
            try {
                if (!havePermission) {
                    checkPermission()
                    throw Exception("Permissions are not given")
                }
                
                // Сначала убедимся что старый VPN отключен
                if (isVpnActive()) {
                    Log.i(TAG, "Connect - VPN already active, will be replaced")
                }
                
                // Сбрасываем старый tunnel перед новым подключением
                tunnel = null
                
                updateStage("prepare")
                val inputStream = ByteArrayInputStream(wgQuickConfig.toByteArray())
                config = com.wireguard.config.Config.parse(inputStream)
                updateStage("connecting")
                futureBackend.await().setState(
                    tunnel(tunnelName) { state ->
                        scope.launch(Dispatchers.Main) {
                            Log.i(TAG, "onStateChange - $state")
                            updateStageFromState(state)
                        }
                    }, Tunnel.State.UP, config
                )
                Log.i(TAG, "Connect - success!")
                flutterSuccess(result, "")
            } catch (e: BackendException) {
                Log.e(TAG, "Connect - BackendException - ERROR - ${e.reason}", e)
                flutterError(result, e.reason.toString())
            } catch (e: Throwable) {
                Log.e(TAG, "Connect - Can't connect to tunnel: $e", e)
                flutterError(result, e.message.toString())
            }
        }
    }

    private fun setupTunnel(localizedDescription: String, result: Result) {
        scope.launch(Dispatchers.IO) {
            if (Tunnel.isNameInvalid(localizedDescription)) {
                flutterError(result, "Invalid Name")
                return@launch
            }
            tunnelName = localizedDescription
            checkPermission()
            result.success(null)
        }
    }

    private fun checkPermission() {
        val intent = GoBackend.VpnService.prepare(this.activity)
        if (intent != null) {
            havePermission = false
            this.activity?.startActivityForResult(intent, PERMISSIONS_REQUEST_CODE)
        } else {
            havePermission = true
        }
    }

    private fun getDownloadData(result: Result) {
        scope.launch(Dispatchers.IO) {
            try {
                val stats = futureBackend.await().getStatistics(tunnel(tunnelName))
                val rx = stats.totalRx()
                flutterSuccess(result, rx)
            } catch (e: Throwable) {
                Log.e(TAG, "getDownloadData - ERROR - ${e.message}")
                flutterError(result, e.message.toString())
            }
        }
    }

    private fun getUploadData(result: Result) {
        scope.launch(Dispatchers.IO) {
            try {
                val stats = futureBackend.await().getStatistics(tunnel(tunnelName))
                val tx = stats.totalTx()
                flutterSuccess(result, tx)
            } catch (e: Throwable) {
                Log.e(TAG, "getUploadData - ERROR - ${e.message}")
                flutterError(result, e.message.toString())
            }
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        events.setStreamHandler(null)
        isVpnChecked = false
    }

    private fun tunnel(name: String, callback: StateChangeCallback? = null): WireGuardTunnel {
        if (tunnel == null) {
            tunnel = WireGuardTunnel(name, callback)
        }
        return tunnel as WireGuardTunnel
    }
}

typealias StateChangeCallback = (Tunnel.State) -> Unit

class WireGuardTunnel(
    private val name: String, private val onStateChanged: StateChangeCallback? = null
) : Tunnel {

    override fun getName() = name

    override fun onStateChange(newState: Tunnel.State) {
        onStateChanged?.invoke(newState)
    }

}
