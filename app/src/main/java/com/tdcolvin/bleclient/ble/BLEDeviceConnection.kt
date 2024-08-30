package com.tdcolvin.bleclient.ble

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattService
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import androidx.annotation.RequiresPermission
import androidx.core.app.ActivityCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import java.util.UUID

val CTF_SERVICE_UUID: UUID = UUID.fromString("8c380000-10bd-4fdb-ba21-1922d6cf860d")
val PASSWORD_CHARACTERISTIC_UUID: UUID = UUID.fromString("8c380001-10bd-4fdb-ba21-1922d6cf860d")
val NAME_CHARACTERISTIC_UUID: UUID = UUID.fromString("8c380002-10bd-4fdb-ba21-1922d6cf860d")

@Suppress("DEPRECATION")
class BLEDeviceConnection @RequiresPermission("PERMISSION_BLUETOOTH_CONNECT") constructor(
    private val context: Context,
    private val bluetoothDevice: BluetoothDevice
) {
    val isConnected = MutableStateFlow(false)
    val passwordRead = MutableStateFlow<String?>(null)
    val successfulNameWrites = MutableStateFlow(0)
    val services = MutableStateFlow<List<BluetoothGattService>>(emptyList())
    private var gatter: BluetoothGatt? = null

    private val callback = object: BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            super.onConnectionStateChange(gatt, status, newState)
            val connected = newState == BluetoothGatt.STATE_CONNECTED
            if (connected) {
                //read the list of services
                services.value = gatter?.services!!
                Log.v("bluetooth2 :", services.value.toString())
                Log.v("bluetooth3 :", gatter?.services!!.toString())

                Log.v("bluetooth service discover?", gatt.discoverServices().toString())
            }
            isConnected.value = connected
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            super.onServicesDiscovered(gatt, status)
            services.value = gatt.services
        }

        @Deprecated("Deprecated in Java")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            super.onCharacteristicRead(gatt, characteristic, status)
            if (characteristic.uuid == PASSWORD_CHARACTERISTIC_UUID) {
                Log.v("PASSWORD", String(characteristic.value))
                passwordRead.value = String(characteristic.value)
            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            super.onCharacteristicWrite(gatt, characteristic, status)
            if (characteristic.uuid == NAME_CHARACTERISTIC_UUID) {
                successfulNameWrites.update { it + 1 }
            }
        }
    }

    @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
    fun disconnect() {
        gatter?.disconnect()
        gatter?.close()
        gatter = null
    }

    @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
    fun connect() {
        gatter = bluetoothDevice.connectGatt(context, false, callback)
    }

    @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
    fun discoverServices() {
        gatter?.discoverServices()
    }

    fun readPassword() {
        val service = gatter?.getService(CTF_SERVICE_UUID)
        if (service == null) {
            Log.v("bluetooth", "service error")

        }
        val characteristic = service?.getCharacteristic(PASSWORD_CHARACTERISTIC_UUID)
        gatter?.readCharacteristic(characteristic)

    }

    @SuppressLint("MissingPermission")
    fun writeName() {
        val service = gatter?.getService(CTF_SERVICE_UUID)
        val characteristic = service?.getCharacteristic(NAME_CHARACTERISTIC_UUID)
        if (characteristic != null) {
            val data = "Hello whjung"
            characteristic.value = data.toByteArray()
            val success = gatter?.writeCharacteristic(characteristic)
            Log.v("bluetooth", "Write status: $success")
        } else {
            Log.v("bluetooth", "Write func error")

        }
    }
}