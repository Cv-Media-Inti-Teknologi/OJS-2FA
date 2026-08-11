{include file="frontend/components/header.tpl" pageTitle="2FA Verification"}

<div class="page page_2fa_verify">
    <h1>2-Step Verification (Google Authenticator)</h1>
    <p>Please enter the 6-digit OTP code from your Google Authenticator app, or use one of your backup codes.</p>

    {if $error}
        <div class="cmp_notification" style="color: #c62828; background: #ffebee; padding: 12px 15px; border-left: 4px solid #c62828; margin-bottom: 15px;">
            {$error}
        </div>
    {/if}

    <form class="cmp_form" id="verifyForm" method="post" action="{url page="gomit2fa" op="verifySubmit"}">
        {csrf}
        <fieldset class="fields">
            <div class="section form-group">
                <label for="otp_code">OTP Code (6 digits) or Backup Code</label>
                <input type="text" id="otp_code" name="otp_code" value="" maxlength="8" required="required" class="field text" inputmode="numeric" pattern="[a-fA-F0-9]{ldelim}6,8{rdelim}" autocomplete="one-time-code" autofocus style="padding: 10px; font-size: 16px; letter-spacing: 2px;">
            </div>
            <div class="buttons" style="margin-top: 15px;">
                <button class="pkp_button" type="submit">Verify</button>
            </div>
        </fieldset>
    </form>
</div>

{include file="frontend/components/footer.tpl"}
