package com.azuka.android.fingerprintactivity.AESCrypto

import android.os.Build
import android.os.Process
import android.util.Base64
import android.util.Log
import java.io.*
import java.security.*
import java.security.spec.KeySpec
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor


/**
 * Simple library for the "right" defaults for AES key generation, encryption,
 * and decryption using 128-bit AES, CBC, PKCS5 padding, and a random 16-byte IV
 * with SHA1PRNG. Integrity with HmacSHA256.
 */
object AesCbcWithIntegrity {
    // If the PRNG fix would not succeed for some reason, we normally will throw an exception.
    // If ALLOW_BROKEN_PRNG is true, however, we will simply log instead.
    private const val ALLOW_BROKEN_PRNG = false
    private const val CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding"
    private const val CIPHER = "AES"
    private const val AES_KEY_LENGTH_BITS = 128
    private const val IV_LENGTH_BYTES = 16
    private const val PBE_ITERATION_COUNT = 10000
    private const val PBE_SALT_LENGTH_BITS =
        AES_KEY_LENGTH_BITS // same size as key output
    private const val PBE_ALGORITHM = "PBKDF2WithHmacSHA1"

    //Made BASE_64_FLAGS public as it's useful to know for compatibility.
    const val BASE64_FLAGS = Base64.NO_WRAP

    //default for testing
    val prngFixed =
        AtomicBoolean(false)
    private const val HMAC_ALGORITHM = "HmacSHA256"
    private const val HMAC_KEY_LENGTH_BITS = 256

    /**
     * Converts the given AES/HMAC keys into a base64 encoded string suitable for
     * storage. Sister function of keys.
     *
     * @param keys The combined aes and hmac keys
     * @return a base 64 encoded AES string and hmac key as base64(aesKey) : base64(hmacKey)
     */
    fun keyString(keys: SecretKeys): String {
        return keys.toString()
    }

    /**
     * An aes key derived from a base64 encoded key. This does not generate the
     * key. It's not random or a PBE key.
     *
     * @param keysStr a base64 encoded AES key / hmac key as base64(aesKey) : base64(hmacKey).
     * @return an AES and HMAC key set suitable for other functions.
     */
    @Throws(InvalidKeyException::class)
    fun keys(keysStr: String): SecretKeys {
        val keysArr = keysStr.split(":".toRegex()).toTypedArray()
        return if (keysArr.size != 2) {
            throw IllegalArgumentException("Cannot parse aesKey:hmacKey")
        } else {
            val confidentialityKey =
                Base64.decode(keysArr[0], BASE64_FLAGS)
            if (confidentialityKey.size != AES_KEY_LENGTH_BITS / 8) {
                throw InvalidKeyException("Base64 decoded key is not $AES_KEY_LENGTH_BITS bytes")
            }
            val integrityKey =
                Base64.decode(keysArr[1], BASE64_FLAGS)
            if (integrityKey.size != HMAC_KEY_LENGTH_BITS / 8) {
                throw InvalidKeyException("Base64 decoded key is not $HMAC_KEY_LENGTH_BITS bytes")
            }
            SecretKeys(
                SecretKeySpec(
                    confidentialityKey,
                    0,
                    confidentialityKey.size,
                    CIPHER
                ),
                SecretKeySpec(integrityKey, HMAC_ALGORITHM)
            )
        }
    }

    /**
     * A function that generates random AES and HMAC keys and prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @return The AES and HMAC keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     * or a suitable RNG is not available
     */
    @Throws(GeneralSecurityException::class)
    fun generateKey(): SecretKeys {
        fixPrng()
        val keyGen =
            KeyGenerator.getInstance(CIPHER)
        // No need to provide a SecureRandom or set a seed since that will
        // happen automatically.
        keyGen.init(AES_KEY_LENGTH_BITS)
        val confidentialityKey = keyGen.generateKey()

        //Now make the HMAC key
        val integrityKeyBytes =
            randomBytes(HMAC_KEY_LENGTH_BITS / 8) //to get bytes
        val integrityKey: SecretKey =
            SecretKeySpec(integrityKeyBytes, HMAC_ALGORITHM)
        return SecretKeys(confidentialityKey, integrityKey)
    }

    /**
     * A function that generates password-based AES and HMAC keys. It prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @param password The password to derive the keys from.
     * @return The AES and HMAC keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     * or a suitable RNG is not available
     */
    @Throws(GeneralSecurityException::class)
    fun generateKeyFromPassword(password: String, salt: ByteArray?): SecretKeys {
        fixPrng()
        //Get enough random bytes for both the AES key and the HMAC key:
        val keySpec: KeySpec = PBEKeySpec(
            password.toCharArray(),
            salt,
            PBE_ITERATION_COUNT,
            AES_KEY_LENGTH_BITS + HMAC_KEY_LENGTH_BITS
        )
        val keyFactory = SecretKeyFactory
            .getInstance(PBE_ALGORITHM)
        val keyBytes = keyFactory.generateSecret(keySpec).encoded

        // Split the random bytes into two parts:
        val confidentialityKeyBytes = copyOfRange(
            keyBytes,
            0,
            AES_KEY_LENGTH_BITS / 8
        )
        val integrityKeyBytes = copyOfRange(
            keyBytes,
            AES_KEY_LENGTH_BITS / 8,
            AES_KEY_LENGTH_BITS / 8 + HMAC_KEY_LENGTH_BITS / 8
        )

        //Generate the AES key
        val confidentialityKey: SecretKey =
            SecretKeySpec(confidentialityKeyBytes, CIPHER)

        //Generate the HMAC key
        val integrityKey: SecretKey =
            SecretKeySpec(integrityKeyBytes, HMAC_ALGORITHM)
        return SecretKeys(confidentialityKey, integrityKey)
    }

    /**
     * A function that generates password-based AES and HMAC keys. See generateKeyFromPassword.
     * @param password The password to derive the AES/HMAC keys from
     * @param salt A string version of the salt; base64 encoded.
     * @return The AES and HMAC keys.
     * @throws GeneralSecurityException
     */
    @Throws(GeneralSecurityException::class)
    fun generateKeyFromPassword(password: String, salt: String?): SecretKeys {
        return generateKeyFromPassword(
            password,
            Base64.decode(salt, BASE64_FLAGS)
        )
    }

    /**
     * Generates a random salt.
     * @return The random salt suitable for generateKeyFromPassword.
     */
    @Throws(GeneralSecurityException::class)
    fun generateSalt(): ByteArray {
        return randomBytes(PBE_SALT_LENGTH_BITS)
    }

    /**
     * Converts the given salt into a base64 encoded string suitable for
     * storage.
     *
     * @param salt
     * @return a base 64 encoded salt string suitable to pass into generateKeyFromPassword.
     */
    fun saltString(salt: ByteArray?): String {
        return Base64.encodeToString(salt, BASE64_FLAGS)
    }

    /**
     * Creates a random Initialization Vector (IV) of IV_LENGTH_BYTES.
     *
     * @return The byte array of this IV
     * @throws GeneralSecurityException if a suitable RNG is not available
     */
    @Throws(GeneralSecurityException::class)
    fun generateIv(): ByteArray {
        return randomBytes(IV_LENGTH_BYTES)
    }

    @Throws(GeneralSecurityException::class)
    private fun randomBytes(length: Int): ByteArray {
        fixPrng()
        val random = SecureRandom()
        val b = ByteArray(length)
        random.nextBytes(b)
        return b
    }
    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the CipherTextIvMac class.
     *
     * @param plaintext The bytes that will be encrypted
     * @param secretKeys The AES and HMAC keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the specified encoding is invalid
     */
    /*
     * -----------------------------------------------------------------
     * Encryption
     * -----------------------------------------------------------------
     */
    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the CipherTextIvMac class.
     *
     * @param plaintext The text that will be encrypted, which
     * will be serialized with UTF-8
     * @param secretKeys The AES and HMAC keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported in this system
     */
    @JvmOverloads
    @Throws(
        UnsupportedEncodingException::class,
        GeneralSecurityException::class
    )
    fun encrypt(
        plaintext: String,
        secretKeys: SecretKeys,
        encoding: String? = "UTF-8"
    ): CipherTextIvMac {
        return encrypt(plaintext.toByteArray(charset(encoding!!)), secretKeys)
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key. Then attaches
     * a hashed MAC, which is contained in the CipherTextIvMac class.
     *
     * @param plaintext The text that will be encrypted
     * @param secretKeys The combined AES and HMAC keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     */
    @Throws(GeneralSecurityException::class)
    fun encrypt(plaintext: ByteArray?, secretKeys: SecretKeys): CipherTextIvMac {
        var iv = generateIv()
        val aesCipherForEncryption =
            Cipher.getInstance(CIPHER_TRANSFORMATION)
        aesCipherForEncryption.init(
            Cipher.ENCRYPT_MODE,
            secretKeys.confidentialityKey,
            IvParameterSpec(iv)
        )

        /*
         * Now we get back the IV that will actually be used. Some Android
         * versions do funny stuff w/ the IV, so this is to work around bugs:
         */iv = aesCipherForEncryption.iv
        val byteCipherText = aesCipherForEncryption.doFinal(plaintext)
        val ivCipherConcat =
            CipherTextIvMac.ivCipherConcat(iv, byteCipherText)
        val integrityMac =
            generateMac(ivCipherConcat, secretKeys.integrityKey)
        return CipherTextIvMac(byteCipherText, iv, integrityMac)
    }

    /**
     * Ensures that the PRNG is fixed. Should be used before generating any keys.
     * Will only run once, and every subsequent call should return immediately.
     */
    private fun fixPrng() {
        if (!prngFixed.get()) {
            synchronized(PrngFixes::class.java) {
                if (!prngFixed.get()) {
                    PrngFixes.apply()
                    prngFixed.set(true)
                }
            }
        }
    }
    /*
     * -----------------------------------------------------------------
     * Decryption
     * -----------------------------------------------------------------
     */
    /**
     * AES CBC decrypt.
     *
     * @param civ The cipher text, IV, and mac
     * @param secretKeys The AES and HMAC keys
     * @param encoding The string encoding to use to decode the bytes after decryption
     * @return A string derived from the decrypted bytes (not base64 encoded)
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the encoding is unsupported
     */
    /**
     * AES CBC decrypt.
     *
     * @param civ The cipher text, IV, and mac
     * @param secretKeys The AES and HMAC keys
     * @return A string derived from the decrypted bytes, which are interpreted
     * as a UTF-8 String
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported
     */
    @JvmOverloads
    @Throws(
        UnsupportedEncodingException::class,
        GeneralSecurityException::class
    )
    fun decryptString(
        civ: CipherTextIvMac,
        secretKeys: SecretKeys,
        encoding: String? = "UTF-8"
    ): String {
        return String(decrypt(civ, secretKeys), charset(encoding.toString()))
    }

    /**
     * AES CBC decrypt.
     *
     * @param civ the cipher text, iv, and mac
     * @param secretKeys the AES and HMAC keys
     * @return The raw decrypted bytes
     * @throws GeneralSecurityException if MACs don't match or AES is not implemented
     */
    @Throws(GeneralSecurityException::class)
    fun decrypt(civ: CipherTextIvMac, secretKeys: SecretKeys): ByteArray {
        val ivCipherConcat =
            CipherTextIvMac.ivCipherConcat(civ.iv, civ.cipherText)
        val computedMac =
            generateMac(ivCipherConcat, secretKeys.integrityKey)
        return if (constantTimeEq(computedMac, civ.mac)) {
            val aesCipherForDecryption =
                Cipher.getInstance(CIPHER_TRANSFORMATION)
            aesCipherForDecryption.init(
                Cipher.DECRYPT_MODE, secretKeys.confidentialityKey,
                IvParameterSpec(civ.iv)
            )
            aesCipherForDecryption.doFinal(civ.cipherText)
        } else {
            throw GeneralSecurityException("MAC stored in civ does not match computed MAC.")
        }
    }
    /*
     * -----------------------------------------------------------------
     * Helper Code
     * -----------------------------------------------------------------
     */
    /**
     * Generate the mac based on HMAC_ALGORITHM
     * @param integrityKey The key used for hmac
     * @param byteCipherText the cipher text
     * @return A byte array of the HMAC for the given key and ciphertext
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
    fun generateMac(
        byteCipherText: ByteArray?,
        integrityKey: SecretKey?
    ): ByteArray {
        //Now compute the mac for later integrity checking
        val sha256_HMAC =
            Mac.getInstance(HMAC_ALGORITHM)
        sha256_HMAC.init(integrityKey)
        return sha256_HMAC.doFinal(byteCipherText)
    }

    /**
     * Simple constant-time equality of two byte arrays. Used for security to avoid timing attacks.
     * @param a
     * @param b
     * @return true iff the arrays are exactly equal.
     */
    fun constantTimeEq(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) {
            return false
        }
        var result = 0
        for (i in a.indices) {
            result = result or ((a[i] xor b[i]).toInt())
        }
        return result == 0
    }

    /**
     * Copy the elements from the start to the end
     *
     * @param from  the source
     * @param start the start index to copy
     * @param end   the end index to finish
     * @return the new buffer
     */
    private fun copyOfRange(from: ByteArray, start: Int, end: Int): ByteArray {
        val length = end - start
        val result = ByteArray(length)
        System.arraycopy(from, start, result, 0, length)
        return result
    }

    /**
     * Holder class that has both the secret AES key for encryption (confidentiality)
     * and the secret HMAC key for integrity.
     */
    class SecretKeys(
        confidentialityKeyIn: SecretKey?,
        integrityKeyIn: SecretKey?
    ) {
        var confidentialityKey: SecretKey? = null
        var integrityKey: SecretKey? = null

        /**
         * Encodes the two keys as a string
         * @return base64(confidentialityKey):base64(integrityKey)
         */
        override fun toString(): String {
            return (Base64.encodeToString(
                confidentialityKey!!.encoded,
                BASE64_FLAGS
            )
                    + ":" + Base64.encodeToString(
                integrityKey!!.encoded,
                BASE64_FLAGS
            ))
        }

        override fun hashCode(): Int {
            val prime = 31
            var result = 1
            result = prime * result + confidentialityKey.hashCode()
            result = prime * result + integrityKey.hashCode()
            return result
        }

        override fun equals(obj: Any?): Boolean {
            if (this === obj) return true
            if (obj == null) return false
            if (javaClass != obj.javaClass) return false
            val other = obj as SecretKeys
            if (integrityKey != other.integrityKey) return false
            return if (confidentialityKey != other.confidentialityKey) false else true
        }

        /**
         * Construct the secret keys container.
         * @param confidentialityKeyIn The AES key
         * @param integrityKeyIn the HMAC key
         */
        init {
            confidentialityKey = confidentialityKeyIn
            integrityKey = integrityKeyIn
        }
    }

    /**
     * Holder class that allows us to bundle ciphertext and IV together.
     */
    class CipherTextIvMac {
        val cipherText: ByteArray
        val iv: ByteArray
        val mac: ByteArray

        /**
         * Construct a new bundle of ciphertext and IV.
         * @param c The ciphertext
         * @param i The IV
         * @param h The mac
         */
        constructor(c: ByteArray, i: ByteArray, h: ByteArray) {
            cipherText = ByteArray(c.size)
            System.arraycopy(c, 0, cipherText, 0, c.size)
            iv = ByteArray(i.size)
            System.arraycopy(i, 0, iv, 0, i.size)
            mac = ByteArray(h.size)
            System.arraycopy(h, 0, mac, 0, h.size)
        }

        /**
         * Constructs a new bundle of ciphertext and IV from a string of the
         * format `base64(iv):base64(ciphertext)`.
         *
         * @param base64IvAndCiphertext A string of the format
         * `iv:ciphertext` The IV and ciphertext must each
         * be base64-encoded.
         */
        constructor(base64IvAndCiphertext: String) {
            val civArray =
                base64IvAndCiphertext.split(":".toRegex()).toTypedArray()
            require(civArray.size == 3) { "Cannot parse iv:mac:ciphertext" }
            iv = Base64.decode(civArray[0], BASE64_FLAGS)
            mac = Base64.decode(civArray[1], BASE64_FLAGS)
            cipherText =
                Base64.decode(civArray[2], BASE64_FLAGS)
        }

        /**
         * Encodes this ciphertext, IV, mac as a string.
         *
         * @return base64(iv) : base64(mac) : base64(ciphertext).
         * The iv and mac go first because they're fixed length.
         */
        override fun toString(): String {
            val ivString =
                Base64.encodeToString(iv, BASE64_FLAGS)
            val cipherTextString =
                Base64.encodeToString(cipherText, BASE64_FLAGS)
            val macString =
                Base64.encodeToString(mac, BASE64_FLAGS)
            return String.format("$ivString:$macString:$cipherTextString")
        }

        override fun hashCode(): Int {
            val prime = 31
            var result = 1
            result = prime * result + Arrays.hashCode(cipherText)
            result = prime * result + Arrays.hashCode(iv)
            result = prime * result + Arrays.hashCode(mac)
            return result
        }

        override fun equals(obj: Any?): Boolean {
            if (this === obj) return true
            if (obj == null) return false
            if (javaClass != obj.javaClass) return false
            val other = obj as CipherTextIvMac
            if (!Arrays.equals(cipherText, other.cipherText)) return false
            if (!Arrays.equals(iv, other.iv)) return false
            return if (!Arrays.equals(mac, other.mac)) false else true
        }

        companion object {
            /**
             * Concatinate the IV to the cipherText using array copy.
             * This is used e.g. before computing mac.
             * @param iv The IV to prepend
             * @param cipherText the cipherText to append
             * @return iv:cipherText, a new byte array.
             */
            fun ivCipherConcat(
                iv: ByteArray,
                cipherText: ByteArray
            ): ByteArray {
                val combined = ByteArray(iv.size + cipherText.size)
                System.arraycopy(iv, 0, combined, 0, iv.size)
                System.arraycopy(cipherText, 0, combined, iv.size, cipherText.size)
                return combined
            }
        }
    }

    /**
     * Fixes for the RNG as per
     * http://android-developers.blogspot.com/2013/08/some-securerandom-thoughts.html
     *
     * This software is provided 'as-is', without any express or implied
     * warranty. In no event will Google be held liable for any damages arising
     * from the use of this software.
     *
     * Permission is granted to anyone to use this software for any purpose,
     * including commercial applications, and to alter it and redistribute it
     * freely, as long as the origin is not misrepresented.
     *
     * Fixes for the output of the default PRNG having low entropy.
     *
     * The fixes need to be applied via [.apply] before any use of Java
     * Cryptography Architecture primitives. A good place to invoke them is in
     * the application's `onCreate`.
     */
    object PrngFixes {
        private const val VERSION_CODE_JELLY_BEAN = 16
        private const val VERSION_CODE_JELLY_BEAN_MR2 = 18
        private val BUILD_FINGERPRINT_AND_DEVICE_SERIAL =
            buildFingerprintAndDeviceSerial

        /**
         * Applies all fixes.
         *
         * @throws SecurityException if a fix is needed but could not be
         * applied.
         */
        fun apply() {
            applyOpenSSLFix()
            installLinuxPRNGSecureRandom()
        }

        /**
         * Applies the fix for OpenSSL PRNG having low entropy. Does nothing if
         * the fix is not needed.
         *
         * @throws SecurityException if the fix is needed but could not be
         * applied.
         */
        @Throws(SecurityException::class)
        private fun applyOpenSSLFix() {
            if (Build.VERSION.SDK_INT < VERSION_CODE_JELLY_BEAN
                || Build.VERSION.SDK_INT > VERSION_CODE_JELLY_BEAN_MR2
            ) {
                // No need to apply the fix
                return
            }
            try {
                // Mix in the device- and invocation-specific seed.
                Class.forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
                    .getMethod("RAND_seed", ByteArray::class.java)
                    .invoke(null, generateSeed())

                // Mix output of Linux PRNG into OpenSSL's PRNG
                val bytesRead = Class
                    .forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
                    .getMethod(
                        "RAND_load_file",
                        String::class.java,
                        Long::class.javaPrimitiveType
                    )
                    .invoke(null, "/dev/urandom", 1024) as Int
                if (bytesRead != 1024) {
                    throw IOException(
                        "Unexpected number of bytes read from Linux PRNG: "
                                + bytesRead
                    )
                }
            } catch (e: Exception) {
                if (ALLOW_BROKEN_PRNG) {
                    Log.w(
                        PrngFixes::class.java.simpleName,
                        "Failed to seed OpenSSL PRNG",
                        e
                    )
                } else {
                    throw SecurityException("Failed to seed OpenSSL PRNG", e)
                }
            }
        }

        /**
         * Installs a Linux PRNG-backed `SecureRandom` implementation as
         * the default. Does nothing if the implementation is already the
         * default or if there is not need to install the implementation.
         *
         * @throws SecurityException if the fix is needed but could not be
         * applied.
         */
        @Throws(SecurityException::class)
        private fun installLinuxPRNGSecureRandom() {
            if (Build.VERSION.SDK_INT > VERSION_CODE_JELLY_BEAN_MR2) {
                // No need to apply the fix
                return
            }

            // Install a Linux PRNG-based SecureRandom implementation as the
            // default, if not yet installed.
            val secureRandomProviders =
                Security.getProviders("SecureRandom.SHA1PRNG")

            // Insert and check the provider atomically.
            // The official Android Java libraries use synchronized methods for
            // insertProviderAt, etc., so synchronizing on the class should
            // make things more stable, and prevent race conditions with other
            // versions of this code.
            synchronized(Security::class.java) {
                if (secureRandomProviders == null
                    || secureRandomProviders.size < 1
                    || secureRandomProviders[0].javaClass.simpleName != "LinuxPRNGSecureRandomProvider"
                ) {
                    Security.insertProviderAt(LinuxPRNGSecureRandomProvider(), 1)
                }

                // Assert that new SecureRandom() and
                // SecureRandom.getInstance("SHA1PRNG") return a SecureRandom backed
                // by the Linux PRNG-based SecureRandom implementation.
                val rng1 = SecureRandom()
                if (rng1.provider.javaClass.simpleName != "LinuxPRNGSecureRandomProvider") {
                    if (ALLOW_BROKEN_PRNG) {
                        Log.w(
                            PrngFixes::class.java.simpleName,
                            "new SecureRandom() backed by wrong Provider: " + rng1.provider.javaClass
                        )
                        return
                    } else {
                        throw SecurityException(
                            "new SecureRandom() backed by wrong Provider: "
                                    + rng1.provider.javaClass
                        )
                    }
                }
                var rng2: SecureRandom? = null
                try {
                    rng2 = SecureRandom.getInstance("SHA1PRNG")
                } catch (e: NoSuchAlgorithmException) {
                    if (ALLOW_BROKEN_PRNG) {
                        Log.w(
                            PrngFixes::class.java.simpleName,
                            "SHA1PRNG not available",
                            e
                        )
                        return
                    } else {
                        SecurityException("SHA1PRNG not available", e)
                    }
                }
                if (rng2!!.provider.javaClass.simpleName != "LinuxPRNGSecureRandomProvider") {
                    if (ALLOW_BROKEN_PRNG) {
                        Log.w(
                            PrngFixes::class.java.simpleName,
                            "SecureRandom.getInstance(\"SHA1PRNG\") backed by wrong" + " Provider: "
                                    + rng2.provider.javaClass
                        )
                        return
                    } else {
                        throw SecurityException(
                            "SecureRandom.getInstance(\"SHA1PRNG\") backed by wrong" + " Provider: "
                                    + rng2.provider.javaClass
                        )
                    }
                }
            }
        }

        /**
         * Generates a device- and invocation-specific seed to be mixed into the
         * Linux PRNG.
         */
        private fun generateSeed(): ByteArray {
            return try {
                val seedBuffer = ByteArrayOutputStream()
                val seedBufferOut = DataOutputStream(seedBuffer)
                seedBufferOut.writeLong(System.currentTimeMillis())
                seedBufferOut.writeLong(System.nanoTime())
                seedBufferOut.writeInt(Process.myPid())
                seedBufferOut.writeInt(Process.myUid())
                seedBufferOut.write(BUILD_FINGERPRINT_AND_DEVICE_SERIAL)
                seedBufferOut.close()
                seedBuffer.toByteArray()
            } catch (e: IOException) {
                throw SecurityException("Failed to generate seed", e)
            }
        }// We're using the Reflection API because Build.SERIAL is only
        // available since API Level 9 (Gingerbread, Android 2.3).

        /**
         * Gets the hardware serial number of this device.
         *
         * @return serial number or `null` if not available.
         */
        private val deviceSerialNumber: String?
            private get() =// We're using the Reflection API because Build.SERIAL is only
                // available since API Level 9 (Gingerbread, Android 2.3).
                try {
                    Build::class.java.getField("SERIAL")[null] as String
                } catch (ignored: Exception) {
                    null
                }

        private val buildFingerprintAndDeviceSerial: ByteArray
            private get() {
                val result = StringBuilder()
                val fingerprint = Build.FINGERPRINT
                if (fingerprint != null) {
                    result.append(fingerprint)
                }
                val serial = deviceSerialNumber
                if (serial != null) {
                    result.append(serial)
                }
                return try {
                    result.toString().toByteArray(charset("UTF-8"))
                } catch (e: UnsupportedEncodingException) {
                    throw RuntimeException("UTF-8 encoding not supported")
                }
            }

        /**
         * `Provider` of `SecureRandom` engines which pass through
         * all requests to the Linux PRNG.
         */
        private class LinuxPRNGSecureRandomProvider :
            Provider(
                "LinuxPRNG", 1.0, "A Linux-specific random number provider that uses"
                        + " /dev/urandom"
            ) {
            init {
                // Although /dev/urandom is not a SHA-1 PRNG, some apps
                // explicitly request a SHA1PRNG SecureRandom and we thus need
                // to prevent them from getting the default implementation whose
                // output may have low entropy.
                put("SecureRandom.SHA1PRNG", LinuxPRNGSecureRandom::class.java.name)
                put("SecureRandom.SHA1PRNG ImplementedIn", "Software")
            }
        }

        /**
         * [SecureRandomSpi] which passes all requests to the Linux PRNG (
         * `/dev/urandom`).
         */
        class LinuxPRNGSecureRandom : SecureRandomSpi() {
            /**
             * Whether this engine instance has been seeded. This is needed
             * because each instance needs to seed itself if the client does not
             * explicitly seed it.
             */
            private var mSeeded = false
            override fun engineSetSeed(bytes: ByteArray) {
                try {
                    var out: OutputStream?
                    synchronized(
                        sLock
                    ) { out = urandomOutputStream }
                    out!!.write(bytes)
                    out!!.flush()
                } catch (e: IOException) {
                    // On a small fraction of devices /dev/urandom is not
                    // writable Log and ignore.
                    Log.w(
                        PrngFixes::class.java.simpleName, "Failed to mix seed into "
                                + URANDOM_FILE
                    )
                } finally {
                    mSeeded = true
                }
            }

            override fun engineNextBytes(bytes: ByteArray) {
                if (!mSeeded) {
                    // Mix in the device- and invocation-specific seed.
                    engineSetSeed(generateSeed())
                }
                try {
                    var `in`: DataInputStream?
                    synchronized(
                        sLock
                    ) { `in` = urandomInputStream }
                    synchronized(`in`!!) { `in`!!.readFully(bytes) }
                } catch (e: IOException) {
                    throw SecurityException(
                        "Failed to read from $URANDOM_FILE",
                        e
                    )
                }
            }

            override fun engineGenerateSeed(size: Int): ByteArray {
                val seed = ByteArray(size)
                engineNextBytes(seed)
                return seed
            }

            // NOTE: Consider inserting a BufferedInputStream
            // between DataInputStream and FileInputStream if you need
            // higher PRNG output performance and can live with future PRNG
            // output being pulled into this process prematurely.
            private val urandomInputStream: DataInputStream?
                private get() {
                    synchronized(sLock) {
                        if (sUrandomIn == null) {
                            // NOTE: Consider inserting a BufferedInputStream
                            // between DataInputStream and FileInputStream if you need
                            // higher PRNG output performance and can live with future PRNG
                            // output being pulled into this process prematurely.
                            sUrandomIn = try {
                                DataInputStream(
                                    FileInputStream(URANDOM_FILE)
                                )
                            } catch (e: IOException) {
                                throw SecurityException(
                                    "Failed to open " + URANDOM_FILE
                                            + " for reading", e
                                )
                            }
                        }
                        return sUrandomIn
                    }
                }

            @get:Throws(IOException::class)
            private val urandomOutputStream: OutputStream?
                private get() {
                    synchronized(sLock) {
                        if (sUrandomOut == null) {
                            sUrandomOut =
                                FileOutputStream(URANDOM_FILE)
                        }
                        return sUrandomOut
                    }
                }

            companion object {
                /*
             * IMPLEMENTATION NOTE: Requests to generate bytes and to mix in a
             * seed are passed through to the Linux PRNG (/dev/urandom).
             * Instances of this class seed themselves by mixing in the current
             * time, PID, UID, build fingerprint, and hardware serial number
             * (where available) into Linux PRNG.
             *
             * Concurrency: Read requests to the underlying Linux PRNG are
             * serialized (on sLock) to ensure that multiple threads do not get
             * duplicated PRNG output.
             */
                private val URANDOM_FILE = File("/dev/urandom")
                private val sLock = Any()

                /**
                 * Input stream for reading from Linux PRNG or `null` if not
                 * yet opened.
                 *
                 * @GuardedBy("sLock")
                 */
                private var sUrandomIn: DataInputStream? = null

                /**
                 * Output stream for writing to Linux PRNG or `null` if not
                 * yet opened.
                 *
                 * @GuardedBy("sLock")
                 */
                private var sUrandomOut: OutputStream? = null
            }
        }
    }
}