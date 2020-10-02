package com.azuka.android.fingerprintactivity.Fragment

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.Activity.RESULT_OK
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.os.StrictMode
import android.provider.MediaStore
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.azuka.android.fingerprintactivity.R
import com.kotlinpermissions.KotlinPermissions
import com.labters.documentscanner.ImageCropActivity
import com.labters.documentscanner.helpers.ScannerConstants
import kotlinx.android.synthetic.main.fragment_image.*
import org.bytedeco.javacpp.opencv_core.finish
import java.io.File
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*

class ImageFragment : Fragment(R.layout.fragment_image) {

    lateinit var mCurrentPhotoPath: String

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        askPermission()
    }

    fun askPermission() {
        if (
            ContextCompat.checkSelfPermission(
                requireContext(),
                android.Manifest.permission.WRITE_EXTERNAL_STORAGE
            ) != PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(
                requireContext(),
                android.Manifest.permission.READ_EXTERNAL_STORAGE
            ) != PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(
                requireContext(),
                android.Manifest.permission.CAMERA
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            KotlinPermissions.with(requireActivity())
                .permissions(
                    Manifest.permission.WRITE_EXTERNAL_STORAGE,
                    Manifest.permission.READ_EXTERNAL_STORAGE,
                    Manifest.permission.CAMERA
                )
                .onAccepted { permissions ->
                    setView()
                }
                .onDenied { permissions ->
                    askPermission()
                }
                .onForeverDenied { permissions ->
                    Toast.makeText(
                        requireContext(),
                        "You have to grant permissions! Grant them from app settings please.",
                        Toast.LENGTH_LONG
                    ).show()
                    finish()
                }
                .ask()
        } else {
            setView()
        }
    }

    fun setView() {

        btnPick.setOnClickListener(View.OnClickListener {
            val builder = AlertDialog.Builder(requireContext())
            builder.setTitle("Option")
            builder.setMessage("Choose file:")
            builder.setPositiveButton("Gallery") { dialog, which ->
                dialog.dismiss()
                val intent = Intent(Intent.ACTION_PICK)
                intent.type = "image/*"
                startActivityForResult(intent, 1111)
            }
            builder.setNegativeButton("Camera") { dialog, which ->
                dialog.dismiss()
                val cameraIntent = Intent(MediaStore.ACTION_IMAGE_CAPTURE)
                if (cameraIntent.resolveActivity(requireActivity().packageManager) != null) {
                    var photoFile: File? = null
                    try {
                        photoFile = createImageFile()
                    } catch (ex: IOException) {
                        Log.i("Main", "IOException")
                    }
                    if (photoFile != null) {
                        val builder = StrictMode.VmPolicy.Builder()
                        StrictMode.setVmPolicy(builder.build())
                        cameraIntent.putExtra(MediaStore.EXTRA_OUTPUT, Uri.fromFile(photoFile))
                        startActivityForResult(cameraIntent, 1231)
                    }
                }
            }
            builder.setNeutralButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            val dialog: AlertDialog = builder.create()
            dialog.show()
        })
    }

    @SuppressLint("SimpleDateFormat")
    @Throws(IOException::class)
    private fun createImageFile(): File {
        // Create an image file name
        val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
        val imageFileName = "JPEG_" + timeStamp + "_"
        val storageDir = Environment.getExternalStoragePublicDirectory(
            Environment.DIRECTORY_PICTURES
        )
        val image = File.createTempFile(
            imageFileName, // prefix
            ".jpg", // suffix
            storageDir      // directory
        )

        // Save a file: path for use with ACTION_VIEW intents
        mCurrentPhotoPath = "file:" + image.absolutePath
        return image
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1111 && resultCode == RESULT_OK && data != null) {
            var selectedImage = data.data
            var btimap: Bitmap? = null
            try {
                val inputStream =
                    selectedImage?.let { context?.contentResolver?.openInputStream(it) }
                btimap = BitmapFactory.decodeStream(inputStream)
                ScannerConstants.selectedImageBitmap = btimap
                startActivityForResult(
                    Intent(requireContext(), ImageCropActivity::class.java),
                    1234
                )
            } catch (e: Exception) {
                e.printStackTrace()
            }
        } else if (requestCode == 1231 && resultCode == Activity.RESULT_OK) {
            ScannerConstants.selectedImageBitmap = MediaStore.Images.Media.getBitmap(
                this.context?.contentResolver,
                Uri.parse(mCurrentPhotoPath)
            )
            startActivityForResult(Intent(requireContext(), ImageCropActivity::class.java), 1234)
        } else if (requestCode == 1234 && resultCode == Activity.RESULT_OK) {
            if (ScannerConstants.selectedImageBitmap != null) {
                imgBitmap.setImageBitmap(ScannerConstants.selectedImageBitmap)
                imgBitmap.visibility = View.VISIBLE
                btnPick.visibility = View.GONE
            } else
                Toast.makeText(requireContext(), "Not OK", Toast.LENGTH_LONG).show()
        }

    }
}