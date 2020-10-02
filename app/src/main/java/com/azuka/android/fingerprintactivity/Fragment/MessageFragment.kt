package com.azuka.android.fingerprintactivity.Fragment

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.azuka.android.fingerprintactivity.AESCrypto.AesCbcWithIntegrity
import com.azuka.android.fingerprintactivity.AESCrypto.AesCbcWithIntegrity.CipherTextIvMac
import com.azuka.android.fingerprintactivity.AESCrypto.AesCbcWithIntegrity.decryptString
import com.azuka.android.fingerprintactivity.R
import kotlinx.android.synthetic.main.fragment_message.*
import java.security.GeneralSecurityException


class MessageFragment : Fragment(R.layout.fragment_message) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {

        super.onViewCreated(view, savedInstanceState)

        val keys = AesCbcWithIntegrity.generateKey()

        encryptPassword.setOnClickListener {
            try {
                val password = etPassword.text.toString()
                val salt: String =
                    AesCbcWithIntegrity.saltString(AesCbcWithIntegrity.generateSalt())
                val key:String = AesCbcWithIntegrity.generateKeyFromPassword(password, salt).toString()

                encryptPassword.visibility = View.GONE
                encrypt.visibility = View.VISIBLE
                etPlainText.isEnabled = true

                encrypt.setOnClickListener {

                    decrypt.visibility = View.VISIBLE
                    encrypt.visibility = View.GONE

                    try {
                        val cipherTextIvMac = AesCbcWithIntegrity.encrypt(etPlainText.text.toString(), keys)
                        val ciphertextString: String = cipherTextIvMac.toString()
                        outputCrypt.text = ciphertextString

                        decrypt.setOnClickListener {
                            try {
                                val cipherTextIvMac = CipherTextIvMac(ciphertextString)
                                val plainText = decryptString(cipherTextIvMac, keys)
                                outputCryptToDecrypt.text = plainText

                            } catch (e: GeneralSecurityException) {
                                outputCryptToDecrypt.text = e.message.toString()
                            }
                        }

                    } catch (e: GeneralSecurityException) {
                        outputCrypt.text = e.message.toString()
                    }
                }

            } catch (e: GeneralSecurityException) {
                Toast.makeText(requireContext(),"Error: ${e.message.toString()}",Toast.LENGTH_SHORT).show()
            }
        }
    }
}