package com.pwdsv.mobile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import java.util.concurrent.CopyOnWriteArrayList
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class MobileAutofillEntry(
    val id: String,
    val name: String,
    val username: String,
    val password: String,
    val uris: List<String>,
    val scope: String,
)

data class PendingSavedCredential(
    val packageName: String,
    val webDomain: String,
    val username: String,
    val password: String,
)

/**
 * 内存态自动填充缓存：仅在手机密码库解锁期间驻留内存，锁库或杀进程即刻归零。
 */
object AutofillVaultMemory {
    @Volatile
    var unlocked: Boolean = false

    private val entries = CopyOnWriteArrayList<MobileAutofillEntry>()
    private val pendingSaves = CopyOnWriteArrayList<PendingSavedCredential>()

    fun updateEntries(isUnlocked: Boolean, jsonList: String) {
        unlocked = isUnlocked
        entries.clear()
        if (!isUnlocked || jsonList.isBlank()) return
        val arr = JSONArray(jsonList)
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val uriArr = obj.optJSONArray("uris") ?: JSONArray()
            val uris = mutableListOf<String>()
            for (j in 0 until uriArr.length()) {
                uris.add(uriArr.optString(j, ""))
            }
            entries.add(
                MobileAutofillEntry(
                    id = obj.optString("id"),
                    name = obj.optString("name"),
                    username = obj.optString("username"),
                    password = obj.optString("password"),
                    uris = uris,
                    scope = obj.optString("pwdsvScope", "universal"),
                ),
            )
        }
    }

    fun matchForTarget(packageName: String, webDomain: String?): List<MobileAutofillEntry> {
        if (!unlocked) return emptyList()
        val pkgLower = packageName.trim().lowercase()
        val domLower = (webDomain ?: "").trim().lowercase().removePrefix("www.")

        return entries.filter { item ->
            if (item.scope != "universal" && item.scope != "mobile") return@filter false
            item.uris.any { raw ->
                val u = raw.trim().lowercase()
                if (pkgLower.isNotEmpty() && (u == "androidapp://$pkgLower" || u == "mobileapp://$pkgLower")) {
                    return@any true
                }
                if (domLower.isNotEmpty() && (u.startsWith("http://") || u.startsWith("https://"))) {
                    val host = runCatching { java.net.URI(u).host?.lowercase()?.removePrefix("www.") ?: "" }.getOrDefault("")
                    if (host.isNotEmpty() && (host == domLower || host.endsWith(".$domLower") || domLower.endsWith(".$host"))) {
                        return@any true
                    }
                }
                false
            }
        }
    }

    fun enqueuePendingSave(cred: PendingSavedCredential) {
        pendingSaves.add(cred)
    }

    fun drainPendingSavesJson(): String {
        val arr = JSONArray()
        while (pendingSaves.isNotEmpty()) {
            val item = pendingSaves.removeAt(0)
            arr.put(
                JSONObject()
                    .put("packageName", item.packageName)
                    .put("webDomain", item.webDomain)
                    .put("username", item.username)
                    .put("password", item.password),
            )
        }
        return arr.toString()
    }
}

/**
 * 基于 Android 硬件级 Keystore (AES-256-GCM) 的本机安全键值存储，
 * 用于保护本地快捷解锁凭据与用户自定义 AI 模型提供商的 API Key。
 */
object KeystoreSecureStore {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "pwdsv_mobile_master_keystore_v2"
    private const val PREFS_NAME = "pwdsv_secure_prefs"

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }

    fun put(context: Context, key: String, plaintext: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = Base64.encodeToString(cipher.iv, Base64.NO_WRAP)
        val ct = Base64.encodeToString(cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(key, "$iv:$ct")
            .apply()
    }

    fun get(context: Context, key: String): String? {
        val packed = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(key, null) ?: return null
        val parts = packed.split(":", limit = 2)
        if (parts.size != 2) return null
        return runCatching {
            val iv = Base64.decode(parts[0], Base64.NO_WRAP)
            val ct = Base64.decode(parts[1], Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
            String(cipher.doFinal(ct), Charsets.UTF_8)
        }.getOrNull()
    }

    fun remove(context: Context, key: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(key)
            .apply()
    }
}
