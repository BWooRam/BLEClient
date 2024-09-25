package com.tdcolvin.bleclient.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattService
import android.content.Context
import android.util.Log
import androidx.annotation.RequiresPermission
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

val CTF_SERVICE_UUID: UUID = UUID.fromString("8c380000-10bd-4fdb-ba21-1922d6cf860d")
val PUBLICK_KEY_DATA_CHARACTERISTIC_UUID: UUID = UUID.fromString("8c380001-10bd-4fdb-ba21-1922d6cf860d")
val DATA_CHARACTERISTIC_UUID: UUID = UUID.fromString("8c380002-10bd-4fdb-ba21-1922d6cf860d")

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
    var publicKey: PublicKey? = null
    var publicKeyRead = MutableStateFlow<String?>(null)

    private var privateKey: PrivateKey? = null
    private var receivePublicKey: PublicKey? = null

    private val callback = object: BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            super.onConnectionStateChange(gatt, status, newState)
            val connected = newState == BluetoothGatt.STATE_CONNECTED
            if (connected) {
                gatter?.requestMtu(255)
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
            if (characteristic.uuid == PUBLICK_KEY_DATA_CHARACTERISTIC_UUID) {

                Log.v("TTTT Receive : ", String(characteristic.value))
                Log.v("TTTT Receive Public key", String(characteristic.value))
                receivePublicKey = getPublicKeyFromEncoded(characteristic.value)

            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            super.onCharacteristicWrite(gatt, characteristic, status)
            if (characteristic.uuid == PUBLICK_KEY_DATA_CHARACTERISTIC_UUID) {
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

    @SuppressLint("MissingPermission")
    fun readPassword() {
        val service = gatter?.getService(CTF_SERVICE_UUID)
        if (service == null) {
            Log.v("bluetooth", "service error")

        }
        val characteristic = service?.getCharacteristic(DATA_CHARACTERISTIC_UUID)
        gatter?.readCharacteristic(characteristic)

    }

    @SuppressLint("MissingPermission")
    fun writeName() {
        val service = gatter?.getService(CTF_SERVICE_UUID)
        val characteristic = service?.getCharacteristic(DATA_CHARACTERISTIC_UUID)
        if (characteristic != null) {
            val data = "{\n" +
                    "  \"ssid\": \"TEST-WiFi-2.4G\",                   // 무선 공유기의 Device Name\n" +
                    "  \"bssid\": \"1234-1234-1234\",                  // 무선 공유기의 Device Mac 주소\n" +
                    "  \"pw\": \"ABCD1234!\",                          // 무선 공유기의 Password\n" +
                    "  \"access-token\": \"ABCD-EFGH-IJKLMN-OPQRSTU\"  // 도어락에서 사용할 WebSocket Access-Token\n" +
                    "}"

            Log.d("TTTT data :", stringToJson(data).toString())

            characteristic.value = stringToJson(data).toString().toByteArray()

            val success = gatter?.writeCharacteristic(characteristic)
            Log.v("bluetooth", "Write status: $success")
        } else {
            Log.v("bluetooth", "Write func error")

        }
    }

    @SuppressLint("MissingPermission")
    fun injectionData() {
        val sharedSecret = generateSharedSecret(privateKey!!, receivePublicKey!!)

        val service = gatter?.getService(CTF_SERVICE_UUID)
        val characteristic = service?.getCharacteristic(DATA_CHARACTERISTIC_UUID)
        if (characteristic != null) {
            val data = "{\n" +
                    "  \"ssid\": \"TEST-WiFi-2.4G\",                   // 무선 공유기의 Device Name\n" +
                    "  \"bssid\": \"1234-1234-1234\",                  // 무선 공유기의 Device Mac 주소\n" +
                    "  \"pw\": \"ABCD1234!\",                          // 무선 공유기의 Password\n" +
                    "  \"token\": \"ABCD-EFGH-IJKLMN-OPQRSTUAsdfasdfasdf\"  // Token\n" +
                    "}"

            Log.d("TTTT data :", stringToJson(data).toString())

            val byteData = stringToJson(data).toString().toByteArray()
            Log.d("TTTT encrypt data :", String(encrypt(byteData, sharedSecret)))

            characteristic.value = encrypt(byteData, sharedSecret)

            val success = gatter?.writeCharacteristic(characteristic)
            Log.v("bluetooth", "Write status: $success")
        } else {
            Log.v("bluetooth", "Write func error")

        }
    }

    @SuppressLint("MissingPermission")
    fun sendPublicKey() {
        val service = gatter?.getService(CTF_SERVICE_UUID)
        val characteristic = service?.getCharacteristic(PUBLICK_KEY_DATA_CHARACTERISTIC_UUID)
        if (characteristic != null) {
            generateKeyPair().apply {
                publicKey = this.first
                privateKey = this.second
            }

            Log.d("TTTT public key :", publicKeyToString(publicKey!!))
            Log.d("TTTT privateKey key :", priveKeyToString(privateKey!!))

            characteristic.value = publicKey!!.encoded

            val success = gatter?.writeCharacteristic(characteristic)
            Log.v("bluetooth", "Write status: $success")
        } else {
            Log.v("bluetooth", "Write func error")

        }

    }

    @SuppressLint("MissingPermission")
    fun receivePublicKey() {
        val service = gatter?.getService(CTF_SERVICE_UUID)
        if (service == null) {
            Log.v("bluetooth", "service error")

        }
        val characteristic = service?.getCharacteristic(PUBLICK_KEY_DATA_CHARACTERISTIC_UUID)
        gatter?.readCharacteristic(characteristic)

    }


    fun stringToJson(jsonString: String): JSONObject {
        return JSONObject(jsonString)
    }

    fun publicKeyToString(publicKey: PublicKey): String {
        return Base64.getEncoder().encodeToString(publicKey.encoded)
    }

    fun priveKeyToString(privateKey: PrivateKey): String {
        return Base64.getEncoder().encodeToString(privateKey.encoded)
    }

    fun generateKeyPair(): Pair<PublicKey, PrivateKey> {
        val keyGen = KeyPairGenerator.getInstance("EC")
        keyGen.initialize(256)
        val keyPair = keyGen.generateKeyPair()
        return Pair(keyPair.public, keyPair.private)
    }

    fun generateSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }

    // AES-256 암호화
    fun encrypt(data: ByteArray, secret: ByteArray): ByteArray {
        val key: SecretKey = SecretKeySpec(secret.copyOf(32), "AES") // 32 bytes for AES-256
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val iv = ByteArray(16).apply { java.security.SecureRandom().nextBytes(this) } // 랜덤 IV 생성
        val ivParameterSpec = IvParameterSpec(iv)

        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec)
        val encrypted = cipher.doFinal(data)

        // IV와 암호문을 Base64로 인코딩하여 반환
        return iv + encrypted
    }

    // AES-256 복호화
    fun decrypt(encryptedData: String, secret: ByteArray): ByteArray {
        val key: SecretKey = SecretKeySpec(secret.copyOf(32), "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        val decodedData = Base64.getDecoder().decode(encryptedData)
        val iv = decodedData.copyOfRange(0, 16) // IV를 추출
        val encryptedBytes = decodedData.copyOfRange(16, decodedData.size)

        val ivParameterSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec)
        return cipher.doFinal(encryptedBytes)
    }

    fun getPublicKeyFromEncoded(encoded: ByteArray): PublicKey {
        val keySpec = X509EncodedKeySpec(encoded)
        val keyFactory = KeyFactory.getInstance("EC") // ECDH 알고리즘 사용
        return keyFactory.generatePublic(keySpec)
    }

}