{extends file="layouts/backend.tpl"}

{block name="page"}
    <h1 class="app__pageHeading">2-Step Verification Settings</h1>

    <div class="page page_2fa_settings" style="padding: 20px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
        <div class="description" style="margin-bottom: 20px;">
            <p>Secure your account with 2-Step Verification (2FA) using Google Authenticator, Authy, or Microsoft Authenticator.</p>
        </div>

        {if $flashError}
            <div class="cmp_notification" style="color: #c62828; background: #ffebee; padding: 12px 15px; border-left: 4px solid #c62828; margin-bottom: 15px;">
                {$flashError}
            </div>
        {/if}

        {if $is2faEnabled}
            <div class="cmp_notification" style="background: #e8f5e9; padding: 15px; border-left: 5px solid #4caf50; margin-bottom: 20px;">
                Status: <strong style="color: #4caf50;">ACTIVE</strong>
            </div>
            <p>Your account is currently protected by 2FA.</p>
            {if $backupCodesCount > 0}
                <p>Backup codes remaining: <strong>{$backupCodesCount}</strong></p>
            {else}
                <p style="color: #c62828;">No backup codes remaining. Consider regenerating 2FA if needed.</p>
            {/if}

            <hr style="margin: 20px 0;" />
            <h3>Disable 2FA</h3>
            <p>Enter your OTP code or a backup code to confirm deactivation.</p>
            <form method="post" action="{url page="gomit2fa" op="disable"}">
                {csrf}
                <fieldset class="fields">
                    <div class="section form-group">
                        <input type="text" name="otp_code" placeholder="OTP / backup code" maxlength="8" required="required" class="field text" inputmode="numeric" style="padding: 10px; font-size: 16px; letter-spacing: 2px;">
                    </div>
                    <div class="buttons" style="margin-top: 10px;">
                        <button class="pkp_button" style="background: #f44336; color: white;" type="submit" onclick="return confirm('Are you sure you want to disable 2FA?');">Disable 2FA</button>
                    </div>
                </fieldset>
            </form>
        {else}
            <div class="cmp_notification" style="background: #fff3e0; padding: 15px; border-left: 5px solid #ff9800; margin-bottom: 20px;">
                Status: <strong style="color: #ff9800;">INACTIVE</strong>
            </div>
            <p>We strongly recommend enabling 2FA to secure your journal account.</p>
            <br />
            <a class="pkp_button" href="{url page="gomit2fa" op="generate"}">Start 2FA Setup</a>
        {/if}
    </div>
{/block}
