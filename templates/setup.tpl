{extends file="layouts/backend.tpl"}

{block name="page"}
    <h1 class="app__pageHeading">Setup Google Authenticator</h1>

    <div class="page page_2fa_setup" style="padding: 20px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
        {if $flashError}
            <div class="cmp_notification" style="color: #c62828; background: #ffebee; padding: 12px 15px; border-left: 4px solid #c62828; margin-bottom: 15px;">
                {$flashError}
            </div>
        {/if}

        <ol>
            <li>Open Google Authenticator, Authy, or a similar app on your phone.</li>
            <li>Scan the QR Code below:</li>
        </ol>

        <div id="qrcode" style="margin: 20px 0; padding: 20px; background: #fff; display: inline-block; border: 1px solid #ddd; min-width: 200px; min-height: 200px;"></div>

        <p>Or enter this secret key manually: <strong style="background: #eee; padding: 3px 6px; letter-spacing: 2px;">{$secret}</strong></p>

        <hr style="margin: 30px 0;" />

        <h3>Backup Codes</h3>
        <p style="color: #c62828;"><strong>IMPORTANT:</strong> Save these codes in a safe place. Each code can only be used once as a substitute for the OTP if you lose access to your authenticator app.</p>
        <div style="background: #f5f5f5; padding: 15px; border: 1px solid #ddd; font-family: monospace; font-size: 14px; letter-spacing: 2px; margin-bottom: 20px; display: inline-block;">
            {foreach from=$backupCodes item=code}
                <div style="padding: 3px 0;">{$code}</div>
            {/foreach}
        </div>

        <hr style="margin: 30px 0;" />

        <h3>Confirm</h3>
        <p>Enter the 6-digit code from the app to verify and activate 2FA.</p>
        <form class="cmp_form" method="post" action="{url page="gomit2fa" op="enable"}">
            {csrf}
            <fieldset class="fields">
                <div class="section form-group">
                    <input type="text" name="otp_code" placeholder="123456" maxlength="6" required="required" class="field text" inputmode="numeric" pattern="[0-9]{ldelim}6{rdelim}" autocomplete="one-time-code" style="padding: 10px; font-size: 16px; letter-spacing: 2px;">
                </div>
                <div class="buttons" style="margin-top: 15px;">
                    <button class="pkp_button" type="submit" style="background: #4caf50; color: white;">Activate 2FA Now</button>
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
{/block}
