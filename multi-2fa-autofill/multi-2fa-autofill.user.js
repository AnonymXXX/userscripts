// ==UserScript==
// @name         多平台 2FA 自动填充（Multi 2FA Autofill）
// @namespace    local.multi-2fa-autofill
// @version      1.5.0
// @description  多账号 TOTP 管理器：otpauth URI 批量导入、站点匹配自动填充、悬浮面板一键复制。悬浮按钮仅在页面存在验证码输入框时显示（登录后自动隐藏）。
// @match        http://*/*
// @match        https://*/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_registerMenuCommand
// @run-at       document-idle
// ==/UserScript==

(function () {
    'use strict';

    var STORE_KEY = 'm2fa_accounts';
    var SETTING_KEY = 'm2fa_settings';
    var RULES_KEY = 'm2fa_rules';

    /* ===== PURE CORE BEGIN ===== */

    var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    function sha1Hex(bytes) {
        var rotl = function (n, b) { return (n << b) | (n >>> (32 - b)); };
        var origLenBits = bytes.length * 8;
        var buf = bytes.slice();
        buf.push(0x80);
        while (buf.length % 64 !== 56) { buf.push(0); }
        buf.push(0, 0, 0, 0, (origLenBits >>> 24) & 0xff, (origLenBits >>> 16) & 0xff, (origLenBits >>> 8) & 0xff, origLenBits & 0xff);
        var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
        var K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];
        var w = new Array(80);
        for (var i = 0; i < buf.length; i += 64) {
            for (var t = 0; t < 16; t++) {
                w[t] = (buf[i + t * 4] << 24) | (buf[i + t * 4 + 1] << 16) | (buf[i + t * 4 + 2] << 8) | buf[i + t * 4 + 3];
            }
            for (t = 16; t < 80; t++) { w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1); }
            var a = h0, b = h1, c = h2, d = h3, e = h4;
            for (t = 0; t < 80; t++) {
                var f, k;
                if (t < 20) { f = (b & c) | (~b & d); k = K[0]; }
                else if (t < 40) { f = b ^ c ^ d; k = K[1]; }
                else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = K[2]; }
                else { f = b ^ c ^ d; k = K[3]; }
                var temp = (rotl(a, 5) + f + e + k + w[t]) >>> 0;
                e = d; d = c; c = rotl(b, 30); b = a; a = temp;
            }
            h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
        }
        var hex = function (n) { return ('00000000' + (n >>> 0).toString(16)).slice(-8); };
        return hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4);
    }

    function hmacSha1(keyBytes, msgBytes) {
        var blockSize = 64;
        var k = keyBytes.slice();
        if (k.length > blockSize) {
            var h = sha1Hex(k);
            k = [];
            for (var i = 0; i < 20; i++) { k.push(parseInt(h.substr(i * 2, 2), 16)); }
        }
        while (k.length < blockSize) { k.push(0); }
        var ipad = k.map(function (b) { return b ^ 0x36; });
        var opad = k.map(function (b) { return b ^ 0x5c; });
        var inner = sha1Hex(ipad.concat(msgBytes));
        var innerBytes = [];
        for (var j = 0; j < 20; j++) { innerBytes.push(parseInt(inner.substr(j * 2, 2), 16)); }
        return sha1Hex(opad.concat(innerBytes));
    }

    function base32ToBytes(s) {
        s = String(s).toUpperCase().replace(/[\s\-=]/g, '');
        var out = [], bits = 0, value = 0;
        for (var i = 0; i < s.length; i++) {
            var idx = B32.indexOf(s.charAt(i));
            if (idx < 0) { continue; }
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                out.push((value >>> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out;
    }

    function isValidBase32(s) {
        s = String(s || '').toUpperCase().replace(/[\s\-=]/g, '');
        if (!s || s.length < 8) { return false; }
        for (var i = 0; i < s.length; i++) {
            if (B32.indexOf(s.charAt(i)) < 0) { return false; }
        }
        return true;
    }

    function totp(seedB32, counter, digits, period) {
        digits = digits || 6;
        var key = base32ToBytes(seedB32);
        var msg = [
            0, 0, 0, 0,
            (counter >>> 24) & 0xff,
            (counter >>> 16) & 0xff,
            (counter >>> 8) & 0xff,
            counter & 0xff
        ];
        var hmacHex = hmacSha1(key, msg);
        var hmac = [];
        for (var i = 0; i < 20; i++) { hmac.push(parseInt(hmacHex.substr(i * 2, 2), 16)); }
        var off = hmac[19] & 0x0f;
        var bin = ((hmac[off] & 0x7f) << 24) | (hmac[off + 1] << 16) | (hmac[off + 2] << 8) | hmac[off + 3];
        var mod = 1;
        for (var d = 0; d < digits; d++) { mod *= 10; }
        return String(bin % mod).padStart(digits, '0');
    }

    function currentCode(account) {
        var step = account.period || 30;
        return totp(account.seed, Math.floor(Date.now() / 1000 / step), account.digits || 6, step);
    }

    function secondsRemain(period) {
        period = period || 30;
        return period - (Math.floor(Date.now() / 1000) % period);
    }

    function parseOtpauthUri(uri) {
        uri = String(uri || '').trim();
        var m = uri.match(/^otpauth:\/\/(totp|hotp)\/([^?]+)\?(.*)$/i);
        if (!m) { return null; }
        var type = m[1].toLowerCase();
        var label = decodeURIComponent(m[2]);
        var params = {};
        m[3].split('&').forEach(function (kv) {
            var i = kv.indexOf('=');
            if (i < 0) { return; }
            params[decodeURIComponent(kv.slice(0, i)).toLowerCase()] = decodeURIComponent(kv.slice(i + 1));
        });
        if (!params.secret || !isValidBase32(params.secret)) { return null; }
        var name = label;
        if (params.issuer && label.indexOf(params.issuer + ':') === 0) {
            name = label.slice(params.issuer.length + 1);
        }
        var issuer = params.issuer || (label.indexOf(':') >= 0 ? label.split(':')[0] : '');
        return {
            type: type,
            name: name || issuer || '未命名',
            issuer: issuer || '',
            seed: params.secret.toUpperCase(),
            digits: params.digits ? parseInt(params.digits, 10) : 6,
            period: params.period ? parseInt(params.period, 10) : 30
        };
    }

    function parseImportText(text) {
        var accounts = [];
        var seen = {};
        text.split(/\r?\n/).forEach(function (line) {
            line = (line || '').trim();
            if (!line) { return; }
            var acc = null;
            if (/^otpauth:\/\//i.test(line)) {
                acc = parseOtpauthUri(line);
            } else if (line.length >= 16 && line.length % 8 === 0 && isValidBase32(line)) {
                acc = { type: 'totp', name: '未命名', issuer: '', seed: line.toUpperCase(), digits: 6, period: 30 };
            } else {
                var cm = line.match(/^([^:]+):\s*([A-Za-z2-7]{8,})$/i);
                if (cm && isValidBase32(cm[2])) {
                    acc = { type: 'totp', name: cm[1].trim(), issuer: '', seed: cm[2].toUpperCase(), digits: 6, period: 30 };
                }
            }
            if (acc && !seen[acc.seed]) {
                seen[acc.seed] = true;
                accounts.push(acc);
            }
        });
        return accounts;
    }

    function normalizeHost(input) {
        var s = String(input || '').trim().toLowerCase().replace(/\/+$/, '');
        if (!s) { return ''; }
        try {
            return new URL(s.includes('://') ? s : 'http://' + s).hostname.toLowerCase();
        } catch (e) {
            return s;
        }
    }

    function hostMatches(accountUrl, pageHref) {
        if (!accountUrl) { return false; }
        var host;
        try { host = new URL(pageHref).hostname.toLowerCase(); } catch (e) { return false; }
        return String(accountUrl).split(/[,，]/).some(function (u) {
            u = (u || '').trim().replace(/\/+$/, '');
            if (!u) { return false; }
            var target;
            try { target = new URL(u.includes('://') ? u : 'http://' + u).hostname.toLowerCase(); }
            catch (e) { return false; }
            return host === target || host.endsWith('.' + target);
        });
    }

    /* ===== PURE CORE END ===== */

    var JUMP_SERVER_RULE = {
        fieldSelector: '#mfa-otp input.input-style, input.input-style[name="code"]',
        submitSelector: '#submit_button'
    };

    // 内置站点规则请按需在此添加；个人站点建议通过油猴菜单「添加站点规则」配置（存本地，不进代码）
    var SITE_RULES = {
        // 'example.com': JUMP_SERVER_RULE
    };

    function getUserRules() {
        try { return JSON.parse(GM_getValue(RULES_KEY, '{}')) || {}; }
        catch (e) { return {}; }
    }

    function getSiteRule() {
        var host;
        try { host = location.hostname.toLowerCase(); } catch (e) { return null; }
        var rules = Object.assign({}, getUserRules(), SITE_RULES);
        for (var k in rules) {
            var target = normalizeHost(k);
            if (!target) { continue; }
            if (host === target || host.endsWith('.' + target)) { return rules[k]; }
        }
        return null;
    }

    var FALLBACK_SELECTORS = [
        'input[autocomplete="one-time-code"]',
        'input[name="code"]',
        'input[name="otp"]',
        'input[name="otp_code"]',
        'input[name="otp_token"]',
        'input[name="totp"]',
        'input[name="2fa"]'
    ];

    var PLACEHOLDER_RE = /(验证码|验证|动态口令|动态密码|六位|otp|2fa|mfa|verification|one[ -]?time|authenticator|figures|digits)/i;

    function getAccounts() {
        try { return JSON.parse(GM_getValue(STORE_KEY, '[]')) || []; }
        catch (e) { return []; }
    }

    function saveAccounts(list) {
        GM_setValue(STORE_KEY, JSON.stringify(list));
    }

    function getSettings() {
        try { return JSON.parse(GM_getValue(SETTING_KEY, '{}')) || {}; }
        catch (e) { return {}; }
    }

    function saveSettings(s) {
        GM_setValue(SETTING_KEY, JSON.stringify(s));
    }

    function isVisible(el) {
        if (!el) { return false; }
        var r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
    }

    function findOtpField() {
        var rule = getSiteRule();
        if (rule) {
            var el = document.querySelector(rule.fieldSelector);
            if (el && isVisible(el)) { return el; }
        }
        for (var i = 0; i < FALLBACK_SELECTORS.length; i++) {
            var cand = document.querySelector(FALLBACK_SELECTORS[i]);
            if (cand && isVisible(cand)) { return cand; }
        }
        var inputs = document.querySelectorAll('input[type="text"], input:not([type]), input[inputmode="numeric"]');
        for (var j = 0; j < inputs.length; j++) {
            var inp = inputs[j];
            var maxLen = parseInt(inp.maxLength || '0', 10);
            if (!isVisible(inp) || inp.disabled || inp.readOnly || inp.type === 'password') { continue; }
            var ph = inp.placeholder || '';
            var autocomplete = inp.getAttribute('autocomplete') || '';
            var pattern = inp.getAttribute('pattern') || '';
            var isOtpField = false;
            if (/one-time-code/i.test(autocomplete)) { isOtpField = true; }
            else if (PLACEHOLDER_RE.test(ph) && (maxLen === 0 || maxLen <= 8)) { isOtpField = true; }
            else if (maxLen > 0 && maxLen <= 8 && /^[0-9\s-]*$/.test(pattern)) { isOtpField = true; }
            else if (inp.getAttribute('inputmode') === 'numeric' && (maxLen === 0 || (maxLen >= 4 && maxLen <= 8))) { isOtpField = true; }
            if (isOtpField) { return inp; }
        }
        return null;
    }

    function matchAccountsForPage() {
        var list = getAccounts();
        var matched = list.filter(function (a) { return hostMatches(a.url, location.href); });
        if (matched.length > 0) { return matched; }
        if (list.length === 1) { return list; }
        return [];
    }

    function fillCode(field, code) {
        field.value = code;
        field.dispatchEvent(new Event('input', { bubbles: true }));
        field.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text);
            return true;
        }
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;opacity:0;';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        ta.remove();
        return ok;
    }

    var panel = null;
    var panelOpen = false;
    var autoFill = getSettings().autofill !== false;
    var autoSubmit = getSettings().autosubmit === true;
    var floatHidden = getSettings().floatHidden === true;

    function showToast(msg, color) {
        var t = document.createElement('div');
        t.textContent = msg;
        t.style.cssText = 'position:fixed;bottom:100px;right:24px;background:' + (color || '#1f2937') + ';color:#fff;padding:8px 14px;border-radius:8px;font-size:13px;z-index:2147483647;box-shadow:0 2px 8px rgba(0,0,0,.3);font-family:system-ui,sans-serif;';
        document.body.appendChild(t);
        setTimeout(function () { t.remove(); }, 1800);
    }

    function buildPanel() {
        if (panel) { panel.remove(); }
        panel = document.createElement('div');
        panel.id = 'm2fa-panel';
        panel.style.cssText = 'position:fixed;right:24px;bottom:100px;z-index:2147483646;width:280px;max-height:60vh;overflow:auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.18);font-family:system-ui,sans-serif;font-size:13px;color:#111827;display:none;';
        renderPanel();
        document.body.appendChild(panel);
    }

    function renderPanel() {
        var list = getAccounts();
        var html = '<div style="padding:10px 12px;border-bottom:1px solid #f3f4f6;display:flex;justify-content:space-between;align-items:center;">';
        html += '<strong>2FA 账号 (' + list.length + ')</strong>';
        html += '<div><button data-act="add" style="margin-right:4px;border:1px solid #d1d5db;background:#fff;border-radius:6px;padding:2px 8px;cursor:pointer;">添加</button>';
        html += '<button data-act="import" style="border:1px solid #d1d5db;background:#fff;border-radius:6px;padding:2px 8px;cursor:pointer;">导入</button></div></div>';
        if (list.length === 0) {
            html += '<div style="padding:16px;color:#6b7280;text-align:center;">暂无账号<br><span style="font-size:12px;">点右上角「导入」粘贴 otpauth:// URI</span></div>';
        } else {
            list.forEach(function (a, idx) {
                var code = currentCode(a);
                var remain = secondsRemain(a.period);
                var matched = hostMatches(a.url, location.href);
                html += '<div data-idx="' + idx + '" style="display:flex;align-items:center;padding:8px 12px;border-bottom:1px solid #f9fafb;cursor:pointer;" title="点击复制验证码">';
                html += '<div style="flex:1;min-width:0;"><div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500;">' + esc(a.name) + (a.issuer ? ' <span style="color:#9ca3af;font-weight:400;">' + esc(a.issuer) + '</span>' : '') + '</div>';
                html += '<div style="color:#6b7280;font-size:11px;font-family:Menlo,monospace;">' + code + '（' + remain + 's）' + (a.url ? (matched ? ' · 当前站点 ✓' : ' · ' + esc(a.url)) : '') + '</div></div>';
                html += '<button data-act="fill" data-idx="' + idx + '" style="border:1px solid #d1d5db;background:#fff;border-radius:6px;padding:2px 8px;margin-right:4px;cursor:pointer;" title="填入当前页面">填</button>';
                html += '<button data-act="del" data-idx="' + idx + '" style="border:none;background:none;color:#ef4444;cursor:pointer;font-size:14px;" title="删除">×</button></div>';
            });
        }
        html += '<div style="padding:8px 12px;border-top:1px solid #f3f4f6;font-size:12px;color:#6b7280;display:flex;justify-content:space-between;flex-wrap:wrap;gap:4px;">';
        html += '<span>自动填充: <b>' + (autoFill ? '开' : '关') + '</b></span><span>自动提交: <b>' + (autoSubmit ? '开' : '关') + '</b></span>';
        html += '<button data-act="float" style="border:1px solid #d1d5db;background:#fff;border-radius:6px;padding:2px 8px;cursor:pointer;font-size:12px;">悬浮按钮: ' + (floatHidden ? '圆点' : '完整') + '</button></div>';
        panel.innerHTML = html;
    }

    function esc(s) {
        return String(s || '').replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function buildFloatButton() {
        var btn = document.createElement('button');
        btn.id = 'm2fa-float';
        btn.textContent = '2FA';
        btn.style.cssText = 'position:fixed;right:24px;bottom:48px;z-index:2147483646;min-width:112px;height:44px;padding:0 14px;border:none;border-radius:22px;background:#2563eb;color:#fff;font-size:15px;font-family:Menlo,monospace;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,.25);';
        btn.addEventListener('click', function (e) {
            e.stopPropagation();
            if (floatHidden) {
                floatHidden = false;
                var s = getSettings(); s.floatHidden = floatHidden; saveSettings(s);
                renderPanel();
                return;
            }
            panelOpen = !panelOpen;
            if (!panel) { buildPanel(); }
            panel.style.display = panelOpen ? 'block' : 'none';
            if (panelOpen) { renderPanel(); }
        });
        document.body.appendChild(btn);

        setInterval(function () {
            if (floatHidden) {
                btn.style.width = '28px';
                btn.style.minWidth = '28px';
                btn.style.height = '28px';
                btn.style.padding = '0';
                btn.style.borderRadius = '50%';
                btn.style.fontSize = '12px';
                btn.textContent = '2';
                return;
            }
            if (!findOtpField()) {
                btn.style.display = 'none';
                return;
            }
            btn.style.display = 'block';
            btn.style.width = 'auto';
            btn.style.minWidth = '112px';
            btn.style.height = '44px';
            btn.style.padding = '0 14px';
            btn.style.borderRadius = '22px';
            btn.style.fontSize = '15px';
            var list = getAccounts();
            if (list.length === 0) { btn.textContent = '2FA'; return; }
            var matched = matchAccountsForPage();
            var acc = matched[0] || list[0];
            btn.textContent = acc.name.slice(0, 8) + ' ' + currentCode(acc) + ' (' + secondsRemain(acc.period) + 's)';
        }, 1000);
    }

    function handlePanelClick(e) {
        var el = e.target;
        var act = el.getAttribute('data-act');
        var idx = el.getAttribute('data-idx');
        var list = getAccounts();
        if (act === 'add') {
            addAccountFlow();
        } else if (act === 'import') {
            importFlow();
        } else if (act === 'fill' && idx !== null) {
            var field = findOtpField();
            var acc = list[parseInt(idx, 10)];
            if (!field) { showToast('当前页面未找到验证码输入框', '#dc2626'); return; }
            fillCode(field, currentCode(acc));
            showToast('已填入: ' + currentCode(acc), '#059669');
        } else if (act === 'del' && idx !== null) {
            if (confirm('删除账号「' + list[parseInt(idx, 10)].name + '」？')) {
                list.splice(parseInt(idx, 10), 1);
                saveAccounts(list);
                renderPanel();
            }
        } else if (act === 'float') {
            floatHidden = !floatHidden;
            var s = getSettings(); s.floatHidden = floatHidden; saveSettings(s);
            renderPanel();
            showToast('悬浮按钮已' + (floatHidden ? '缩为圆点' : '恢复完整'), '#059669');
        } else if (act === null && el.closest('[data-idx]')) {
            var row = el.closest('[data-idx]');
            var i = parseInt(row.getAttribute('data-idx'), 10);
            var code = currentCode(list[i]);
            copyText(code);
            showToast('已复制: ' + code, '#059669');
        }
    }

    function guessAccountName() {
        var t = (document.title || '').trim();
        if (!t) { return ''; }
        var parts = t.split(/[-|_·\s]+/).filter(Boolean);
        var name = parts.length > 1 ? parts[parts.length - 1] : t;
        if (name.length < 2) { name = t; }
        return name.slice(0, 20);
    }

    function addAccountFlow() {
        var guessed = guessAccountName();
        var name = guessed || prompt('账号名称（如 JumpServer）');
        if (!name) { return; }
        var seed = prompt('TOTP Secret（base32）').trim();
        if (!seed || !isValidBase32(seed)) { showToast('Secret 格式无效', '#dc2626'); return; }
        var list = getAccounts();
        list.push({ id: Date.now(), name: name, issuer: '', seed: seed.toUpperCase(), digits: 6, period: 30, url: location.hostname || '' });
        saveAccounts(list);
        renderPanel();
        showToast('已添加「' + name + '」', '#059669');
    }

    function importFlow() {
        var text = prompt('粘贴导入内容（每行一个）：\n1) otpauth://totp/...  URI\n2) 纯 base32 secret\n3) 名称: secret\n\n示例：\notpauth://totp/JumpServer:user?secret=JBSWY3DPEHPK3PXP&issuer=JumpServer\nGITHUB  :  GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        if (!text) { return; }
        var parsed = parseImportText(text);
        if (parsed.length === 0) { showToast('未解析出有效账号', '#dc2626'); return; }
        var list = getAccounts();
        var dup = 0;
        parsed.forEach(function (p) {
            var exists = list.some(function (a) { return a.seed === p.seed; });
            if (exists) { dup++; return; }
            if (p.name === '未命名') { p.name = guessAccountName() || '未命名'; }
            p.id = Date.now() + Math.random();
            p.url = location.hostname || '';
            list.push(p);
        });
        saveAccounts(list);
        renderPanel();
        showToast('导入 ' + parsed.length + ' 个，跳过重复 ' + dup + ' 个', '#059669');
    }

    function setupMenus() {
        GM_registerMenuCommand('导入 otpauth / secret', importFlow);
        GM_registerMenuCommand('导出备份（复制到剪贴板）', function () {
            var lines = getAccounts().map(function (a) {
                return 'otpauth://totp/' + encodeURIComponent((a.issuer ? a.issuer + ':' : '') + a.name) + '?secret=' + a.seed + '&issuer=' + encodeURIComponent(a.issuer || a.name) + '&digits=' + (a.digits || 6) + '&period=' + (a.period || 30);
            });
            copyText(lines.join('\n'));
            showToast('已复制 ' + lines.length + ' 条 otpauth URI（请安全保管）', '#059669');
        });
        GM_registerMenuCommand('自动填充: ' + (autoFill ? '开' : '关'), function () {
            autoFill = !autoFill;
            var s = getSettings(); s.autofill = autoFill; saveSettings(s);
            showToast('自动填充已' + (autoFill ? '开启' : '关闭'));
        });
        GM_registerMenuCommand('悬浮按钮: ' + (floatHidden ? '圆点' : '完整'), function () {
            floatHidden = !floatHidden;
            var s = getSettings(); s.floatHidden = floatHidden; saveSettings(s);
            showToast('悬浮按钮已' + (floatHidden ? '缩为圆点' : '恢复完整'));
        });
        GM_registerMenuCommand('自动提交: ' + (autoSubmit ? '开' : '关'), function () {
            autoSubmit = !autoSubmit;
            var s = getSettings(); s.autosubmit = autoSubmit; saveSettings(s);
            showToast('自动提交已' + (autoSubmit ? '开启' : '关闭'));
        });
        GM_registerMenuCommand('添加站点规则（自定义字段选择器）', function () {
            var host = prompt('站点域名（如 vpn.example.com）');
            if (!host) { return; }
            host = host.trim().toLowerCase();
            var field = prompt('验证码输入框 CSS 选择器（如 #mfa-otp input 或 input[name="code"]）');
            if (!field) { return; }
            var submit = prompt('提交按钮 CSS 选择器（可留空，自动提交时使用）', '');
            var rules = getUserRules();
            var rule = { fieldSelector: field.trim() };
            if (submit && submit.trim()) { rule.submitSelector = submit.trim(); }
            rules[host] = rule;
            GM_setValue(RULES_KEY, JSON.stringify(rules));
            showToast('已添加规则：' + host, '#059669');
        });
        GM_registerMenuCommand('查看/清除自定义站点规则', function () {
            var rules = getUserRules();
            var keys = Object.keys(rules);
            if (keys.length === 0) { showToast('暂无自定义规则', '#059669'); return; }
            var list = keys.map(function (k, i) { return (i + 1) + '. ' + k + ' → ' + (rules[k].fieldSelector || '?'); }).join('\n');
            var del = prompt('当前自定义规则：\n' + list + '\n\n输入序号删除（回车跳过）');
            if (!del) { return; }
            var idx = parseInt(del, 10) - 1;
            if (idx >= 0 && idx < keys.length) {
                delete rules[keys[idx]];
                GM_setValue(RULES_KEY, JSON.stringify(rules));
                showToast('已删除规则：' + keys[idx], '#059669');
            }
        });
    }

    var filledLast = {};

    function tryAutofill() {
        if (!autoFill) { return; }
        var matches = matchAccountsForPage();
        if (matches.length !== 1) { return; }
        var field = findOtpField();
        if (!field) { return; }
        var acc = matches[0];
        var code = currentCode(acc);
        if (field.value === code) {
            if (autoSubmit) { submitIfNeeded(); }
            return;
        }
        if (filledLast[field] !== undefined && field.value !== '' && field.value !== filledLast[field]) {
            return;
        }
        fillCode(field, code);
        filledLast[field] = code;
        if (autoSubmit) { submitIfNeeded(); }
    }

    function submitIfNeeded() {
        var rule = getSiteRule();
        if (rule && rule.submitSelector) {
            var btn = document.querySelector(rule.submitSelector);
            if (btn) { btn.click(); }
        }
    }

    function boot() {
        if (typeof GM_registerMenuCommand === 'function') { setupMenus(); }
        buildFloatButton();
        buildPanel();
        panel.addEventListener('click', handlePanelClick);

        var obs = new MutationObserver(function () {
            tryAutofill();
        });
        obs.observe(document.body, { childList: true, subtree: true });
        setInterval(tryAutofill, 2000);
        setTimeout(tryAutofill, 500);
    }

    if (document.body) { boot(); }
    else { document.addEventListener('DOMContentLoaded', boot); }
})();
