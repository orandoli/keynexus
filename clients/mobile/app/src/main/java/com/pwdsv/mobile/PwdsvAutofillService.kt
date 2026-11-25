package com.pwdsv.mobile

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

/**
 * Android 系统级密码自动填充与自动捕获保存服务：
 * - 打开已绑定的手机 App（或手机浏览器）登录框时，直接在键盘/输入框弹出 PWDSV 候选账号（匹配 mobile + universal）
 * - 在其他手机 App 内输入新账号密码提交后，系统弹出「保存到 PWDSV？」并在下次回到 PWDSV 时加密上传
 */
class PwdsvAutofillService : AutofillService() {

    private class ParsedFields(
        var usernameId: AutofillId? = null,
        var passwordId: AutofillId? = null,
        var usernameValue: String = "",
        var passwordValue: String = "",
        var webDomain: String? = null,
    )

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }

        val targetPkg = structure.activityComponent?.packageName ?: ""
        if (targetPkg == packageName) {
            callback.onSuccess(null)
            return
        }

        val fields = parseStructure(structure)
        if (fields.usernameId == null && fields.passwordId == null) {
            callback.onSuccess(null)
            return
        }

        val responseBuilder = FillResponse.Builder()

        // 注册 SaveInfo：用户在第三方 App 填完新账号密码提交后，Android 会提示保存到 PWDSV
        val saveIds = listOfNotNull(fields.usernameId, fields.passwordId).toTypedArray()
        if (fields.passwordId != null && saveIds.isNotEmpty()) {
            val saveType = if (fields.usernameId != null) {
                SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD
            } else {
                SaveInfo.SAVE_DATA_TYPE_PASSWORD
            }
            responseBuilder.setSaveInfo(SaveInfo.Builder(saveType, saveIds).build())
        }

        val matches = AutofillVaultMemory.matchForTarget(targetPkg, fields.webDomain)
        for (entry in matches) {
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                val label = if (entry.username.isNotBlank()) {
                    "🔑 ${entry.name} (${entry.username})"
                } else {
                    "🔑 ${entry.name}"
                }
                setTextViewText(android.R.id.text1, label)
            }

            val dsBuilder = Dataset.Builder()
            fields.usernameId?.let { id ->
                dsBuilder.setValue(id, AutofillValue.forText(entry.username), presentation)
            }
            fields.passwordId?.let { id ->
                dsBuilder.setValue(id, AutofillValue.forText(entry.password), presentation)
            }
            responseBuilder.addDataset(dsBuilder.build())
        }

        if (matches.isEmpty() && fields.passwordId == null) {
            callback.onSuccess(null)
        } else {
            callback.onSuccess(responseBuilder.build())
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess()
            return
        }
        val targetPkg = structure.activityComponent?.packageName ?: ""
        val fields = parseStructure(structure)
        if (fields.passwordValue.isNotBlank()) {
            AutofillVaultMemory.enqueuePendingSave(
                PendingSavedCredential(
                    packageName = targetPkg,
                    webDomain = fields.webDomain ?: "",
                    username = fields.usernameValue,
                    password = fields.passwordValue,
                ),
            )
        }
        callback.onSuccess()
    }

    private fun parseStructure(structure: AssistStructure): ParsedFields {
        val out = ParsedFields()
        for (i in 0 until structure.windowNodeCount) {
            val root = structure.getWindowNodeAt(i).rootViewNode
            traverseNode(root, out)
        }
        return out
    }

    private fun traverseNode(node: AssistStructure.ViewNode, out: ParsedFields) {
        node.webDomain?.takeIf { it.isNotBlank() }?.let {
            if (out.webDomain == null) out.webDomain = it
        }

        val id = node.autofillId
        if (id != null && node.visibility == View.VISIBLE) {
            val hints = (node.autofillHints ?: emptyArray()).map { it.lowercase() }
            val meta = listOfNotNull(node.idEntry, node.hint, node.htmlInfo?.attributes?.toString())
                .joinToString(" ")
                .lowercase()
            val inputType = node.inputType
            val isPasswordType =
                (inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD) != 0 ||
                    (inputType and InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) != 0 ||
                    (inputType and InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD) != 0

            val textVal = node.autofillValue?.let { if (it.isText) it.textValue?.toString() ?: "" else "" } ?: ""

            if (hints.any { it.contains("password") } || isPasswordType || meta.contains("password") || meta.contains("密码")) {
                if (out.passwordId == null) out.passwordId = id
                if (textVal.isNotBlank()) out.passwordValue = textVal
            } else if (
                hints.any { it.contains("username") || it.contains("email") || it.contains("phone") } ||
                Regex("user|email|login|account|phone|账号|邮箱|手机|用户名").containsMatchIn(meta)
            ) {
                if (out.usernameId == null) out.usernameId = id
                if (textVal.isNotBlank()) out.usernameValue = textVal
            }
        }

        for (i in 0 until node.childCount) {
            traverseNode(node.getChildAt(i), out)
        }
    }
}
