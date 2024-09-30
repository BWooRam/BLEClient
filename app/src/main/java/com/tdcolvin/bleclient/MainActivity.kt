package com.tdcolvin.bleclient

import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.tdcolvin.bleclient.ui.navigation.MainNavigation
import com.tdcolvin.bleclient.ui.theme.BLEClientTheme
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
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

class MainActivity : ComponentActivity() {
    val TAG = "MainAcitivity"
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BLEClientTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                   MainNavigation()
                }
            }
        }
    }

    //test code
    fun test2() {
        val key = generateKeyPair()



        val base64EncodeKey ="BBMHvIPjTK/b8uzEzGawXJTlIx3SD/rzyKQaIPClA3wQpY2T3h2oRH97jcN61nnIZrkcs/HLDKoKL04YqkNZO6A="
        val base64DecodeKey = Base64.decode(base64EncodeKey, Base64.NO_WRAP)
        Log.d(TAG, "base64DecodeKey PublicKey contentToString = ${base64DecodeKey.contentToString()}, size = ${base64DecodeKey.size}")
        val ecParameterSpec2: ECParameterSpec = KeyFactory
            .getInstance("EC")
            .getKeySpec(
                key.first,
                ECPublicKeySpec::class.java
            ).params
        // X,Y 좌표 뽑은 다음에 다시 Public Key 생성 테스트
        val reDecodeKey = getEcPublicKey(base64DecodeKey, ecParameterSpec2)
        Log.d(TAG, "reDecodeKey PublicKey = $reDecodeKey")
        Log.d(TAG, "reDecodeKey PublicKey encoded = ${reDecodeKey.encoded.contentToString()}")
        Log.d(TAG, "reDecodeKey PublicKey encoded size = ${reDecodeKey.encoded.size}")
        Log.d(TAG, "reDecodeKey PublicKey format = ${reDecodeKey.format}")
        Log.d(TAG, "reDecodeKey PublicKey algorithm = ${reDecodeKey.algorithm}")
    }

    fun test() {
        val base64EncodeKey ="BBMHvIPjTK/b8uzEzGawXJTlIx3SD/rzyKQaIPClA3wQpY2T3h2oRH97jcN61nnIZrkcs/HLDKoKL04YqkNZO6A="
        val base64DecodeKey = Base64.decode(base64EncodeKey, Base64.NO_WRAP)
        Log.d(TAG, "base64DecodeKey PublicKey contentToString = ${base64DecodeKey.contentToString()}, size = ${base64DecodeKey.size}")

        val key = generateKeyPair()

        Log.d(TAG, "generateKeyPair PublicKey = ${key.first}, PrivateKey = ${key.second}")
        Log.d(TAG, "generateKeyPair PublicKey decodeToString = ${key.first.encoded.decodeToString()}, PrivateKey decodeToString = ${key.second.encoded.decodeToString()}")
        Log.d(TAG, "generateKeyPair PublicKey encoded = ${key.first.encoded.contentToString()}, PrivateKey encoded = ${key.second.encoded.contentToString()}")
        Log.d(TAG, "generateKeyPair PublicKey encoded size = ${key.first.encoded.size}, PrivateKey encoded size = ${key.second.encoded.size}")
        Log.d(TAG, "generateKeyPair PublicKey format = ${key.first.format}, PrivateKey format = ${key.second.format}")
        Log.d(TAG, "generateKeyPair PublicKey algorithm = ${key.first.algorithm}, PrivateKey algorithm = ${key.second.algorithm}")

        val ecParameterSpec: ECParameterSpec = KeyFactory
            .getInstance("EC")
            .getKeySpec(
                key.first,
                ECPublicKeySpec::class.java
            ).params

        Log.d(TAG, "getEcPublicKey x,y = ${base64DecodeKey.contentToString()}")
        Log.d(TAG, "getEcPublicKey size = ${base64DecodeKey.size}")
        val decodeKey = getEcPublicKey(base64DecodeKey, ecParameterSpec)
//        val decodeKey = getPublicKeyFromEncoded(base64DecodeKey)
        Log.d(TAG, "getEcPublicKey PublicKey = $decodeKey")
        Log.d(TAG, "getEcPublicKey PublicKey encoded = ${decodeKey.encoded.contentToString()}")
        Log.d(TAG, "getEcPublicKey PublicKey encoded size = ${decodeKey.encoded.size}")
        Log.d(TAG, "getEcPublicKey PublicKey format = ${decodeKey.format}")
        Log.d(TAG, "getEcPublicKey PublicKey algorithm = ${decodeKey.algorithm}")

        val sharedSecretKey = generateSharedSecret(key.second, decodeKey)
        Log.d(TAG, "sharedSecretKey decode = ${sharedSecretKey.decodeToString()}")
        Log.d(TAG, "sharedSecretKey content = ${sharedSecretKey.contentToString()}")
        Log.d(TAG, "sharedSecretKey size = ${sharedSecretKey.size}")
        Log.d(TAG, "sharedSecretKey String = ${Base64.encode(sharedSecretKey, Base64.NO_PADDING).decodeToString()}")

        if (key.first is ECPublicKey) {
            val ecPublicKey = key.first as ECPublicKey
            val affineXByteArray = ecPublicKey.w.affineX.toByteArray()
            val filteredAffineXByteArray = filterMostSignificantByte(affineXByteArray)
            val affineYByteArray = ecPublicKey.w.affineY.toByteArray()
            val filteredAffineYByteArray = filterMostSignificantByte(affineYByteArray)
            val keyByteArray = filteredAffineXByteArray.plus(filteredAffineYByteArray)
            Log.d(TAG, "ECPublicKey affineXByteArray = ${affineXByteArray.contentToString()}, size = ${affineXByteArray.size}")
            Log.d(TAG, "ECPublicKey affineYByteArray = ${affineYByteArray.contentToString()}, size = ${affineYByteArray.size}")
            Log.d(TAG, "ECPublicKey filteredAffineXByteArray = ${filteredAffineXByteArray.contentToString()}, size = ${filteredAffineXByteArray.size}")
            Log.d(TAG, "ECPublicKey filteredAffineYByteArray = ${filteredAffineYByteArray.contentToString()}, size = ${filteredAffineYByteArray.size}")
            Log.d(TAG, "ECPublicKey keyByteArray = ${keyByteArray.contentToString()}, size = ${keyByteArray.size}")
            Log.d(TAG, "String = ${Base64.encode(keyByteArray, android.util.Base64.NO_PADDING).decodeToString()}")

        } else {
            Log.d(TAG, "ECPublicKey This is not an EC public key.")
        }

        val key2 = generateKeyPair()
        val ecParameterSpec2: ECParameterSpec = KeyFactory
            .getInstance("EC")
            .getKeySpec(
                key2.first,
                ECPublicKeySpec::class.java
            ).params
        // X,Y 좌표 뽑은 다음에 다시 Public Key 생성 테스트
        val reDecodeKey = getEcPublicKey(base64DecodeKey, ecParameterSpec2)
        Log.d(TAG, "reDecodeKey PublicKey = $reDecodeKey")
        Log.d(TAG, "reDecodeKey PublicKey encoded = ${reDecodeKey.encoded.contentToString()}")
        Log.d(TAG, "reDecodeKey PublicKey encoded size = ${reDecodeKey.encoded.size}")
        Log.d(TAG, "reDecodeKey PublicKey format = ${reDecodeKey.format}")
        Log.d(TAG, "reDecodeKey PublicKey algorithm = ${reDecodeKey.algorithm}")

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

    private fun generateSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }

    private fun generateKeyPair(): Pair<PublicKey, PrivateKey> {
        val keyGen = KeyPairGenerator.getInstance("EC")
        keyGen.initialize(ECGenParameterSpec("secp256r1")) // P-256은 secp256r1로 정의됨
        val keyPair = keyGen.generateKeyPair()
        return Pair(keyPair.public, keyPair.private)
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

    fun getPublicKeyFromEncoded(encoded: ByteArray): PublicKey {
        val keySpec = X509EncodedKeySpec(encoded)
        val keyFactory = KeyFactory.getInstance("EC") // ECDH 알고리즘 사용
        return keyFactory.generatePublic(keySpec)
    }
    
}