{include file="frontend/components/header.tpl" pageTitle="Setup 2FA"}

<div class="page page_2fa_setup">
    <h1>Setup Google Authenticator</h1>

    {if $flashError}
        <div class="cmp_notification" style="color: #c62828; background: #ffebee; padding: 12px 15px; border-left: 4px solid #c62828; margin-bottom: 15px;">
            {$flashError}
        </div>
    {/if}

    <ol>
        <li>Buka aplikasi Google Authenticator, Authy, atau sejenisnya di HP Anda.</li>
        <li>Scan QR Code berikut ini:</li>
    </ol>

    <div id="qrcode" style="margin: 20px 0; padding: 20px; background: #fff; display: inline-block; border: 1px solid #ddd; min-width: 200px; min-height: 200px;"></div>

    <p>Atau masukkan kunci rahasia ini secara manual: <strong style="background: #eee; padding: 3px 6px; letter-spacing: 2px;">{$secret}</strong></p>

    <hr style="margin: 30px 0;" />

    <h3>Backup Codes</h3>
    <p style="color: #c62828;"><strong>PENTING:</strong> Simpan kode-kode ini di tempat aman. Setiap kode hanya bisa digunakan sekali sebagai pengganti OTP jika Anda kehilangan akses ke aplikasi authenticator.</p>
    <div style="background: #f5f5f5; padding: 15px; border: 1px solid #ddd; font-family: monospace; font-size: 14px; letter-spacing: 2px; margin-bottom: 20px; display: inline-block;">
        {foreach from=$backupCodes item=code}
            <div style="padding: 3px 0;">{$code}</div>
        {/foreach}
    </div>

    <hr style="margin: 30px 0;" />

    <h3>Konfirmasi</h3>
    <p>Masukkan 6 digit kode dari aplikasi untuk memverifikasi dan mengaktifkan 2FA.</p>
    <form class="cmp_form" method="post" action="{url page="gomit2fa" op="enable"}">
        {csrf}
        <fieldset class="fields">
            <div class="section form-group">
                <input type="text" name="otp_code" placeholder="123456" maxlength="6" required="required" class="field text" inputmode="numeric" pattern="[0-9]{ldelim}6{rdelim}" autocomplete="one-time-code" style="padding: 10px; font-size: 16px; letter-spacing: 2px;">
            </div>
            <div class="buttons" style="margin-top: 15px;">
                <button class="pkp_button" type="submit" style="background: #4caf50; color: white;">Aktifkan 2FA Sekarang</button>
            </div>
        </fieldset>
    </form>
</div>

<script src="{$qrJsUrl}"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {ldelim}
    var el = document.getElementById('qrcode');
    if (el && typeof QRCode !== 'undefined') {ldelim}
        new QRCode(el, {ldelim}
            text: "{$otpauthUri|escape:'javascript'}",
            width: 200,
            height: 200,
            correctLevel: QRCode.CorrectLevel.M
        {rdelim});
    {rdelim}
{rdelim});
</script>

{include file="frontend/components/footer.tpl"}
