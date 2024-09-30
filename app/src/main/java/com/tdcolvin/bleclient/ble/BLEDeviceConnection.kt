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
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
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
    private val TAG = "TTTT"
    private val callback = object: BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            super.onConnectionStateChange(gatt, status, newState)
            val connected = newState == BluetoothGatt.STATE_CONNECTED
            gatter?.requestMtu(255)
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
            if (characteristic.uuid == PUBLICK_KEY_DATA_CHARACTERISTIC_UUID) {

                Log.v("TTTT Receive : ", String(characteristic.value))
                Log.d("TTTT Receive content byte : ", characteristic.value.contentToString())
                Log.d("TTTT Receive base64 :", "String = ${android.util.Base64.encode(characteristic.value, android.util.Base64.NO_WRAP).decodeToString()}")

                val ecParameterSpec: ECParameterSpec = KeyFactory
                    .getInstance("EC")
                    .getKeySpec(
                        publicKey,
                        ECPublicKeySpec::class.java
                    ).params
                receivePublicKey = getEcPublicKey(characteristic.value, ecParameterSpec)

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
        Log.d("TTTT secret byte : ", sharedSecret.decodeToString())
        Log.d("TTTT secret content byte : ", sharedSecret.contentToString())
        Log.d("TTTT secret base64 :", "String = ${android.util.Base64.encode(sharedSecret, android.util.Base64.NO_WRAP).decodeToString()}")

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

            Log.d("TTTT no public key :", publicKey!!.encoded.decodeToString())
            Log.d("TTTT no public key size:", publicKey!!.encoded.decodeToString().length.toString())
            Log.d("TTTT public key size: ", publicKey!!.encoded.size.toString())
            Log.d("TTTT public data: ", "${publicKey}")
            Log.d("TTTT public format: ", "${publicKey!!.format}")
            Log.d("TTTT public key :", publicKeyToString(publicKey!!))
            Log.d("TTTT public Base64 size :", publicKeyToString(publicKey!!).length.toString())
            Log.d("TTTT privateKey key :", priveKeyToString(privateKey!!))
            Log.d("TTTT publicKey key byte size :", base64ToByteArray(publicKeyToString(publicKey!!)).size.toString())
            Log.d("TTTT sendData :", "String = ${android.util.Base64.encode(sendData(publicKey!!), android.util.Base64.NO_PADDING).decodeToString()}")

            characteristic.value = sendData(publicKey!!)

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
        keyGen.initialize(ECGenParameterSpec("secp256r1")) // P-256은 secp256r1로 정의됨
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

    fun base64ToByteArray(base64String: String): ByteArray {
        return Base64.getDecoder().decode(base64String)
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

    private fun filterMostSignificantByte(byteArray: ByteArray): ByteArray {
        val xBytes32 = ByteArray(32)
        val byteArraySize = byteArray.size
        Log.d(TAG, "filterMostSignificantByte byteArray = ${byteArray.decodeToString()}, byteArraySize = $byteArraySize")

        if (byteArraySize <= 32) {
            // 패딩 추가
            System.arraycopy(byteArray, 0, xBytes32, 32 - byteArraySize, byteArraySize)
        } else if (byteArraySize == 33) {
            // 33바이트인 경우, 최상위 바이트 제거
            System.arraycopy(byteArray, 1, xBytes32, 0, 32)
        } else {
            throw Throwable("removeMostSignificantByte Too many Byte")
        }

        return xBytes32
    }

    private fun getEcPublicKey(ecPublicKey: ByteArray, params: ECParameterSpec): PublicKey {
        val ecPointX = ecPublicKey.sliceArray(IntRange(1, 32))
        val ecPointY = ecPublicKey.sliceArray(IntRange(33, 64))
        // x와 y를 BigInteger로 변환
        val x = BigInteger(1, ecPointX) // 1은 부호를 나타냄 (양수)
        val y = BigInteger(1, ecPointY)

        // ECPoint를 사용하여 공개 키의 포인트 정의
        val ecPoint = ECPoint(x, y)
        val keyFactory = KeyFactory.getInstance("EC") // ECDH 알고리즘 사용
        val pubSpec = ECPublicKeySpec(ecPoint, params)
        return keyFactory.generatePublic(pubSpec)

    }

    private fun sendData(publicKey: PublicKey): ByteArray? {
        if (publicKey is ECPublicKey) {
            val ecPublicKey = publicKey as ECPublicKey
            val affineXByteArray = ecPublicKey.w.affineX.toByteArray()
            val filteredAffineXByteArray = filterMostSignificantByte(affineXByteArray)
            val affineYByteArray = ecPublicKey.w.affineY.toByteArray()
            val filteredAffineYByteArray = filterMostSignificantByte(affineYByteArray)
            val keyByteArray = byteArrayOf(0x04).plus(filteredAffineXByteArray).plus(filteredAffineYByteArray)
            Log.d(TAG, "ECPublicKey affineXByteArray = ${affineXByteArray.contentToString()}, size = ${affineXByteArray.size}")
            Log.d(TAG, "ECPublicKey affineYByteArray = ${affineYByteArray.contentToString()}, size = ${affineYByteArray.size}")
            Log.d(TAG, "ECPublicKey filteredAffineXByteArray = ${filteredAffineXByteArray.contentToString()}, size = ${filteredAffineXByteArray.size}")
            Log.d(TAG, "ECPublicKey filteredAffineYByteArray = ${filteredAffineYByteArray.contentToString()}, size = ${filteredAffineYByteArray.size}")
            Log.d(TAG, "ECPublicKey keyByteArray = ${keyByteArray.contentToString()}, size = ${keyByteArray.size}")
            Log.d(TAG, "String = ${android.util.Base64.encode(keyByteArray, android.util.Base64.NO_PADDING).decodeToString()}")

            return keyByteArray
        } else {
            Log.d(TAG, "ECPublicKey This is not an EC public key.")
        }
        return null
    }

}