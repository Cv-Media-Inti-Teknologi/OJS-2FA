{include file="frontend/components/header.tpl" pageTitle="Pengaturan 2FA"}

<div class="page page_2fa_settings">
    <h1>Pengaturan 2-Step Verification</h1>

    <div class="description" style="margin-bottom: 20px;">
        <p>Amankan akun Anda dengan 2-Step Verification (2FA) menggunakan aplikasi Google Authenticator, Authy, atau Microsoft Authenticator.</p>
    </div>

    {if $flashError}
        <div class="cmp_notification" style="color: #c62828; background: #ffebee; padding: 12px 15px; border-left: 4px solid #c62828; margin-bottom: 15px;">
            {$flashError}
        </div>
    {/if}

    {if $is2faEnabled}
        <div class="cmp_notification" style="background: #e8f5e9; padding: 15px; border-left: 5px solid #4caf50; margin-bottom: 20px;">
            Status: <strong style="color: #4caf50;">AKTIF</strong>
        </div>
        <p>Akun Anda saat ini terlindungi oleh 2FA.</p>
        {if $backupCodesCount > 0}
            <p>Backup codes tersisa: <strong>{$backupCodesCount}</strong></p>
        {else}
            <p style="color: #c62828;">Tidak ada backup codes tersisa. Pertimbangkan untuk generate ulang 2FA jika perlu.</p>
        {/if}

        <hr style="margin: 20px 0;" />
        <h3>Matikan 2FA</h3>
        <p>Masukkan kode OTP atau backup code untuk mengkonfirmasi penonaktifan.</p>
        <form method="post" action="{url page="gomit2fa" op="disable"}">
            {csrf}
            <fieldset class="fields">
                <div class="section form-group">
                    <input type="text" name="otp_code" placeholder="Kode OTP / backup code" maxlength="8" required="required" class="field text" inputmode="numeric" style="padding: 10px; font-size: 16px; letter-spacing: 2px;">
                </div>
                <div class="buttons" style="margin-top: 10px;">
                    <button class="pkp_button" style="background: #f44336; color: white;" type="submit" onclick="return confirm('Apakah Anda yakin ingin mematikan 2FA?');">Matikan 2FA</button>
                </div>
            </fieldset>
        </form>
    {else}
        <div class="cmp_notification" style="background: #fff3e0; padding: 15px; border-left: 5px solid #ff9800; margin-bottom: 20px;">
            Status: <strong style="color: #ff9800;">TIDAK AKTIF</strong>
        </div>
        <p>Kami sangat menyarankan Anda untuk mengaktifkan 2FA demi keamanan jurnal.</p>
        <br />
        <a class="pkp_button" href="{url page="gomit2fa" op="generate"}">Mulai Konfigurasi 2FA</a>
    {/if}
</div>

{include file="frontend/components/footer.tpl"}
