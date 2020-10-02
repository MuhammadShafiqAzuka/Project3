package com.azuka.android.fingerprintactivity.Fragment

import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.azuka.android.fingerprintactivity.R
import com.budiyev.android.codescanner.*
import kotlinx.android.synthetic.main.fragment_barcode.*

private const val CAMERA_CODE = 101

class BarcodeFragment : Fragment(R.layout.fragment_barcode) {

    private lateinit var codeScanner: CodeScanner

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupPermission()
        codeScanner()
    }

    private fun codeScanner(){
        codeScanner = CodeScanner(requireContext(), scanner_view)
        codeScanner.apply {
            camera = CodeScanner.CAMERA_BACK
            formats = CodeScanner.ALL_FORMATS

            autoFocusMode = AutoFocusMode.CONTINUOUS
            scanMode = ScanMode.CONTINUOUS
            isAutoFocusEnabled = true
            isFlashEnabled = false

            decodeCallback = DecodeCallback {
               requireActivity().runOnUiThread {
                   tv_barcode.text = it.text
                   tv_barcode.autoLinkMask
               }
            }
            errorCallback = ErrorCallback {
                requireActivity().runOnUiThread {
                    Log.e("BarCode Fragment", "camera initialization error: ${it.message}")
                }
            }
        }

        scanner_view.setOnClickListener {
            codeScanner.startPreview()
        }
    }

    override fun onResume() {
        super.onResume()
        codeScanner.startPreview()
    }

    override fun onPause() {
        super.onPause()
        codeScanner.releaseResources()
    }

    private fun setupPermission(){
        val permission = ContextCompat.checkSelfPermission(requireContext(),
        android.Manifest.permission.CAMERA)

        if (permission != PackageManager.PERMISSION_GRANTED){
            makeRequest()
        }
    }

    private fun makeRequest() {
        ActivityCompat.requestPermissions(requireActivity(), arrayOf(android.Manifest.permission.CAMERA), CAMERA_CODE)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
      when (requestCode) {
          CAMERA_CODE -> {
              if (grantResults.isEmpty() || grantResults[0] != PackageManager.PERMISSION_GRANTED) {
                  Toast.makeText(
                      requireContext(),
                      "You need camera permission to use this scanner",
                      Toast.LENGTH_SHORT
                  ).show()
              }else{ //Successfull
              }
          }
      }
    }
}