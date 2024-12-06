package com.tdcolvin.bleclient.ble

import android.util.Log
import org.junit.Test
import kotlin.random.Random

class BLEDeviceConnectionTest {

    @Test
    fun `BLEDeviceConnectionTest_sliceByteArrayMtu_기본_동작_테스트`() {
        val data = dummyByteArray(100)
        val slicedBytes = sliceByteArrayMtu(data, 10)
        println("BLEDeviceConnectionTest_sliceByteArrayMtu_기본_동작_테스트 data = ${data.decodeToString()}")
        for(slice in slicedBytes){
            println("BLEDeviceConnectionTest_sliceByteArrayMtu_기본_동작_테스트 slice size = ${slice.size}, string = ${slice.decodeToString()}")
        }
    }

    private fun dummyByteArray(size: Int): ByteArray {
        var dummy = ""
        for (index in 0 until size) {
            val randomData = Random.nextInt(0, 10)
            dummy = dummy.plus(randomData)
        }
        return dummy.toByteArray()
    }

    private fun sliceByteArrayMtu(byteArray: ByteArray, mtu: Int): List<ByteArray> {
        val temp = mutableListOf<ByteArray>()
        val totalSize = byteArray.size
        var startOffset = 0
        var endOffset = 0

        while (endOffset < totalSize) {
            // 요청된 오프셋에 해당하는 데이터 범위 계산
            endOffset = minOf(startOffset + mtu, totalSize)
            val dataChunk = byteArray.copyOfRange(startOffset, endOffset)
            startOffset = endOffset

            temp.add(dataChunk)
        }

        return temp
    }
}