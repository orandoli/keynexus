package com.pwdsv.mobile

import android.annotation.SuppressLint
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.provider.MediaStore
import android.provider.Settings
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.webkit.WebViewAssetLoader
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private var fileUploadCallback: ValueCallback<Array<Uri>>? = null
    private val ioPool = Executors.newCachedThreadPool()
    private val mainHandler = Handler(Looper.getMainLooper())

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val cb = fileUploadCallback
        fileUploadCallback = null
        if (cb == null) return@registerForActivityResult
        val uris = WebChromeClient.FileChooserParams.parseResult(result.resultCode, result.data)
        cb.onReceiveValue(uris)
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if ((applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            WebView.setWebContentsDebuggingEnabled(true)
        }

        @Suppress("DEPRECATION")
        window.statusBarColor = Color.parseColor("#090F16")
        @Suppress("DEPRECATION")
        window.navigationBarColor = Color.parseColor("#111C29")
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }

        val assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        webView = WebView(this).apply {
            setBackgroundColor(Color.parseColor("#090F16"))
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = true
            settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            addJavascriptInterface(NativeBridge(), "PwdsvAndroid")

            webViewClient = object : WebViewClient() {
                override fun shouldInterceptRequest(
                    view: WebView,
                    request: WebResourceRequest,
                ): WebResourceResponse? {
                    return assetLoader.shouldInterceptRequest(request.url)
                }
            }

            webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(consoleMessage: android.webkit.ConsoleMessage?): Boolean {
                    consoleMessage?.let {
                        android.util.Log.i(
                            "PWDSV_JS",
                            "[${it.messageLevel()}] ${it.message()} (${it.sourceId()}:${it.lineNumber()})",
                        )
                    }
                    return super.onConsoleMessage(consoleMessage)
                }

                override fun onShowFileChooser(
                    webView: WebView?,
                    filePathCallback: ValueCallback<Array<Uri>>?,
                    fileChooserParams: FileChooserParams?,
                ): Boolean {
                    fileUploadCallback?.onReceiveValue(null)
                    fileUploadCallback = filePathCallback

                    val intent = if (fileChooserParams?.isCaptureEnabled == true) {
                        Intent(MediaStore.ACTION_IMAGE_CAPTURE)
                    } else {
                        fileChooserParams?.createIntent() ?: Intent(Intent.ACTION_GET_CONTENT).apply {
                            addCategory(Intent.CATEGORY_OPENABLE)
                            type = "*/*"
                        }
                    }
                    return runCatching {
                        filePickerLauncher.launch(intent)
                        true
                    }.getOrElse {
                        fileUploadCallback = null
                        false
                    }
                }
            }
        }

        // 使用外层 FrameLayout 承载系统栏/挖孔屏/软键盘内边距（WebView 自身内部渲染层会忽略直接设在 WebView 上的 padding）
        val rootContainer = FrameLayout(this).apply {
            setBackgroundColor(Color.parseColor("#090F16"))
            addView(webView, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        }
        setContentView(rootContainer)

        ViewCompat.setOnApplyWindowInsetsListener(rootContainer) { v, windowInsets ->
            val insets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                    WindowInsetsCompat.Type.displayCutout() or
                    WindowInsetsCompat.Type.ime(),
            )
            v.setPadding(insets.left, insets.top, insets.right, insets.bottom)
            WindowInsetsCompat.CONSUMED
        }

        // 使用安全 HTTPS 虚拟域名加载本地资产，确保 ES Module 与 WebCrypto crypto.subtle 100% 可用
        webView.loadUrl("https://appassets.androidplatform.net/assets/www/index.html")
    }

    override fun onResume() {
        super.onResume()
        webView.evaluateJavascript("window.__onPwdsvResume && window.__onPwdsvResume();", null)
    }

    private fun evalCallback(callbackId: String, resultJson: String) {
        mainHandler.post {
            val idQuoted = JSONObject.quote(callbackId)
            val escaped = JSONObject.quote(resultJson)
            webView.evaluateJavascript("window.__pwdsvNativeCallback($idQuoted, JSON.parse($escaped));", null)
        }
    }

    inner class NativeBridge {

        @JavascriptInterface
        fun httpRequestAsync(callbackId: String, reqJson: String) {
            ioPool.execute {
                val reply = runCatching {
                    val req = JSONObject(reqJson)
                    val targetUrl = URL(req.getString("url"))
                    val method = req.optString("method", "GET").uppercase()
                    val insecureTls = req.optBoolean("insecureTls", false)
                    val conn = (targetUrl.openConnection() as HttpURLConnection).apply {
                        requestMethod = method
                        connectTimeout = 20_000
                        readTimeout = 60_000
                        if (this is HttpsURLConnection && insecureTls) {
                            applySelfSignedTls(this)
                        }
                    }

                    val headers = req.optJSONObject("headers")
                    var hasUa = false
                    if (headers != null) {
                        val keys = headers.keys()
                        while (keys.hasNext()) {
                            val k = keys.next()
                            if (k.equals("User-Agent", ignoreCase = true)) hasUa = true
                            conn.setRequestProperty(k, headers.optString(k))
                        }
                    }
                    if (!hasUa) {
                        conn.setRequestProperty("User-Agent", "KeyNexus/2.0")
                    }

                    if (!req.isNull("body")) {
                        val bodyBytes = req.getString("body").toByteArray(Charsets.UTF_8)
                        conn.doOutput = true
                        conn.outputStream.use { it.write(bodyBytes) }
                    }

                    val status = conn.responseCode
                    val stream = if (status in 200..299) conn.inputStream else conn.errorStream
                    val bodyText = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
                    JSONObject().put("ok", true).put("status", status).put("body", bodyText)
                }.getOrElse { err ->
                    JSONObject().put("ok", false).put("error", err.message ?: err.toString())
                }
                evalCallback(callbackId, reply.toString())
            }
        }

        @JavascriptInterface
        fun saveSecureItem(key: String, value: String) {
            KeystoreSecureStore.put(this@MainActivity, key, value)
        }

        @JavascriptInterface
        fun loadSecureItem(key: String): String? {
            return KeystoreSecureStore.get(this@MainActivity, key)
        }

        @JavascriptInterface
        fun removeSecureItem(key: String) {
            KeystoreSecureStore.remove(this@MainActivity, key)
        }

        @JavascriptInterface
        fun syncAutofillCache(unlocked: Boolean, itemsJson: String) {
            AutofillVaultMemory.updateEntries(unlocked, itemsJson)
        }

        @JavascriptInterface
        fun drainPendingAutofillSaves(): String {
            return AutofillVaultMemory.drainPendingSavesJson()
        }

        @JavascriptInterface
        fun listInstalledApps(): String {
            val pm = packageManager
            val apps = pm.getInstalledApplications(0)
                .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 && it.packageName != packageName }
                .map { info ->
                    val label = pm.getApplicationLabel(info)?.toString()?.trim().orEmpty()
                    Pair(label.ifEmpty { info.packageName }, info.packageName)
                }
                .sortedBy { it.first.lowercase() }

            val arr = JSONArray()
            for ((label, pkg) in apps) {
                arr.put(JSONObject().put("name", label).put("packageName", pkg))
            }
            return arr.toString()
        }

        @JavascriptInterface
        fun copySecret(text: String, clearSeconds: Int) {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("pwdsv-secret", text)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                clip.description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
            cm.setPrimaryClip(clip)
            if (clearSeconds > 0) {
                mainHandler.postDelayed({
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        cm.clearPrimaryClip()
                    } else {
                        cm.setPrimaryClip(ClipData.newPlainText("", ""))
                    }
                }, clearSeconds * 1000L)
            }
        }

        @JavascriptInterface
        fun openAutofillSettings() {
            val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
                data = Uri.parse("package:$packageName")
            }
            runCatching { startActivity(intent) }
        }

        @JavascriptInterface
        fun canUseBiometric(): Boolean {
            val bm = BiometricManager.from(this@MainActivity)
            return bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) == BiometricManager.BIOMETRIC_SUCCESS
        }

        @JavascriptInterface
        fun promptBiometric(callbackId: String) {
            mainHandler.post {
                val executor = ContextCompat.getMainExecutor(this@MainActivity)
                val prompt = BiometricPrompt(
                    this@MainActivity,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            evalCallback(callbackId, JSONObject().put("ok", true).toString())
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            evalCallback(callbackId, JSONObject().put("ok", false).put("error", errString.toString()).toString())
                        }
                    },
                )
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("解锁 KeyNexus")
                    .setSubtitle("验证指纹或面容以快速开启密码中枢")
                    .setNegativeButtonText("改用 PIN 或主密码")
                    .build()
                prompt.authenticate(info)
            }
        }

        @JavascriptInterface
        fun getAppVersionJson(): String {
            return runCatching {
                val pInfo = packageManager.getPackageInfo(packageName, 0)
                val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    pInfo.longVersionCode
                } else {
                    @Suppress("DEPRECATION")
                    pInfo.versionCode.toLong()
                }
                JSONObject()
                    .put("versionName", pInfo.versionName ?: "2.0.7")
                    .put("versionCode", code)
                    .toString()
            }.getOrElse {
                """{"versionName":"2.0.7","versionCode":207}"""
            }
        }

        @JavascriptInterface
        fun downloadAndInstallUpdateAsync(callbackId: String, reqJson: String) {
            ioPool.execute {
                runCatching {
                    val req = JSONObject(reqJson)
                    val targetUrl = URL(req.getString("url"))
                    val expectedSha = req.optString("sha256", "").trim().lowercase()
                    val insecureTls = req.optBoolean("insecureTls", false)

                    val conn = (targetUrl.openConnection() as HttpURLConnection).apply {
                        requestMethod = "GET"
                        instanceFollowRedirects = true
                        connectTimeout = 20_000
                        readTimeout = 180_000
                        if (this is HttpsURLConnection && insecureTls) {
                            applySelfSignedTls(this)
                        }
                    }

                    val status = conn.responseCode
                    if (status !in 200..299) {
                        throw IllegalStateException("下载安装包失败 (HTTP $status)")
                    }

                    val updateDir = File(cacheDir, "updates").apply { mkdirs() }
                    val apkFile = File(updateDir, "keynexus-update.apk")
                    val total = conn.contentLengthLong
                    val digest = MessageDigest.getInstance("SHA-256")
                    val buf = ByteArray(16 * 1024)
                    var downloaded = 0L
                    var lastPct = -1

                    conn.inputStream.use { input ->
                        FileOutputStream(apkFile).use { output ->
                            while (true) {
                                val read = input.read(buf)
                                if (read <= 0) break
                                output.write(buf, 0, read)
                                digest.update(buf, 0, read)
                                downloaded += read
                                if (total > 0) {
                                    val pct = ((downloaded * 100) / total).toInt().coerceIn(0, 100)
                                    if (pct != lastPct && (pct % 4 == 0 || pct == 100)) {
                                        lastPct = pct
                                        mainHandler.post {
                                            webView.evaluateJavascript(
                                                "window.__pwdsvUpdateProgress && window.__pwdsvUpdateProgress($pct);",
                                                null,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }

                    val actualSha = digest.digest().joinToString("") { "%02x".format(it) }
                    if (expectedSha.isNotEmpty() && actualSha != expectedSha) {
                        apkFile.delete()
                        throw IllegalStateException("安装包 SHA-256 校验失败，已中止安装")
                    }

                    mainHandler.post {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                            !packageManager.canRequestPackageInstalls()
                        ) {
                            val permIntent = Intent(
                                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                Uri.parse("package:$packageName"),
                            )
                            runCatching { startActivity(permIntent) }
                            evalCallback(
                                callbackId,
                                JSONObject()
                                    .put("ok", true)
                                    .put("needsPermission", true)
                                    .put("message", "请在系统设置允许「KeyNexus」安装应用，返回后再次点击即可安装")
                                    .toString(),
                            )
                            return@post
                        }

                        val apkUri = FileProvider.getUriForFile(
                            this@MainActivity,
                            "$packageName.fileprovider",
                            apkFile,
                        )
                        val installIntent = Intent(Intent.ACTION_VIEW).apply {
                            setDataAndType(apkUri, "application/vnd.android.package-archive")
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        startActivity(installIntent)
                        evalCallback(
                            callbackId,
                            JSONObject().put("ok", true).put("launchedInstaller", true).toString(),
                        )
                    }
                }.onFailure { err ->
                    evalCallback(
                        callbackId,
                        JSONObject()
                            .put("ok", false)
                            .put("error", err.message ?: err.toString())
                            .toString(),
                    )
                }
            }
        }
    }

    @SuppressLint("TrustAllX509TrustManager", "BadHostnameVerifier")
    private fun applySelfSignedTls(conn: HttpsURLConnection) {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, SecureRandom())
        conn.sslSocketFactory = ctx.socketFactory
        conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
    }
}
