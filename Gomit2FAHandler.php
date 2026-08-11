<?php

namespace APP\plugins\generic\gomit2fa;

use PKP\handler\PKPHandler;
use PKP\security\Role;
use PKP\security\authorization\PKPSiteAccessPolicy;
use PKP\plugins\PluginRegistry;
use PKP\db\DAORegistry;
use APP\template\TemplateManager;

class Gomit2FAHandler extends PKPHandler {
    public function __construct() {
        parent::__construct();
        $this->addRoleAssignment(
            [
                Role::ROLE_ID_SITE_ADMIN,
                Role::ROLE_ID_MANAGER,
                Role::ROLE_ID_SUB_EDITOR,
                Role::ROLE_ID_AUTHOR,
                Role::ROLE_ID_REVIEWER,
                Role::ROLE_ID_ASSISTANT,
                Role::ROLE_ID_READER,
            ],
            ['verify', 'verifySubmit', 'settings', 'generate', 'enable', 'disable']
        );
    }

    public function authorize($request, &$args, $roleAssignments) {
        $this->addPolicy(new PKPSiteAccessPolicy($request, null, $roleAssignments));
        return parent::authorize($request, $args, $roleAssignments);
    }

    private function _getPlugin(): Gomit2FAPlugin {
        return PluginRegistry::getPlugin('generic', 'gomit2faplugin');
    }

    // ---- Verify page (2FA challenge after login) ----

    public function verify($args, $request) {
        $templateMgr = TemplateManager::getManager($request);
        $templateMgr->display($this->_getPlugin()->getTemplateResource('verify.tpl'));
    }

    public function verifySubmit($args, $request) {
        if (!$request->checkCSRF()) {
            $request->redirect(null, 'gomit2fa', 'verify');
            return;
        }

        $user = $request->getUser();
        if (!$user) {
            $request->redirect(null, 'login');
            return;
        }

        if (Gomit2FAPlugin::isOtpRateLimited($user->getId())) {
            $templateMgr = TemplateManager::getManager($request);
            $templateMgr->assign('error', 'Too many attempts. Please wait 15 minutes.');
            $templateMgr->display($this->_getPlugin()->getTemplateResource('verify.tpl'));
            return;
        }

        $code = trim($request->getUserVar('otp_code'));
        $userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
        $encryptedSecret = $userSettingsDao->getSetting($user->getId(), 'gomit2fa_secret');
        $secret = Gomit2FAPlugin::decryptSecret($encryptedSecret);

        require_once(dirname(__FILE__) . '/lib/GoogleAuthenticator.php');
        $ga = new \GoogleAuthenticator();

        // Try OTP first
        if ($ga->verifyCode($secret, $code, 2)) {
            Gomit2FAPlugin::clearOtpAttempts($user->getId());
            $session = $request->getSession();
            $session->setSessionVar('gomit2fa_verified', true);
            $request->redirect(null, 'index');
            return;
        }

        // Try backup code
        if (Gomit2FAPlugin::verifyAndConsumeBackupCode($user->getId(), $code)) {
            Gomit2FAPlugin::clearOtpAttempts($user->getId());
            $session = $request->getSession();
            $session->setSessionVar('gomit2fa_verified', true);
            $request->redirect(null, 'index');
            return;
        }

        // Failed
        Gomit2FAPlugin::recordOtpFailure($user->getId());
        $templateMgr = TemplateManager::getManager($request);
        $templateMgr->assign('error', 'Invalid OTP or backup code.');
        $templateMgr->display($this->_getPlugin()->getTemplateResource('verify.tpl'));
    }

    // ---- Settings page ----

    public function settings($args, $request) {
        $user = $request->getUser();
        $userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
        $is2faEnabled = $userSettingsDao->getSetting($user->getId(), 'gomit2fa_enabled');
        $backupCodesCount = Gomit2FAPlugin::getBackupCodesCount($user->getId());

        $templateMgr = TemplateManager::getManager($request);
        $templateMgr->assign('is2faEnabled', $is2faEnabled);
        $templateMgr->assign('backupCodesCount', $backupCodesCount);

        $session = $request->getSession();
        $flashError = $session->getSessionVar('gomit2fa_flash_error');
        if ($flashError) {
            $templateMgr->assign('flashError', $flashError);
            $session->unsetSessionVar('gomit2fa_flash_error');
        }

        $templateMgr->display($this->_getPlugin()->getTemplateResource('settings.tpl'));
    }

    // ---- Generate secret + QR + backup codes ----

    public function generate($args, $request) {
        $user = $request->getUser();
        $userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');

        require_once(dirname(__FILE__) . '/lib/GoogleAuthenticator.php');
        $ga = new \GoogleAuthenticator();
        $secret = $ga->createSecret();

        $userSettingsDao->updateSetting($user->getId(), 'gomit2fa_secret', Gomit2FAPlugin::encryptSecret($secret));
        $userSettingsDao->updateSetting($user->getId(), 'gomit2fa_enabled', false);

        $backupCodes = Gomit2FAPlugin::generateBackupCodes(8);
        $userSettingsDao->updateSetting($user->getId(), 'gomit2fa_backup_codes', json_encode(Gomit2FAPlugin::hashBackupCodes($backupCodes)));

        $context = $request->getContext();
        $title = $context ? $context->getLocalizedName() : 'OJS';
        $title = preg_replace('/[^A-Za-z0-9 ]/', '', $title);

        $otpauthUri = 'otpauth://totp/' . rawurlencode($user->getUsername()) . '?secret=' . $secret . '&issuer=' . rawurlencode($title);

        $plugin = $this->_getPlugin();
        $qrJsUrl = $request->getBaseUrl() . '/' . $plugin->getPluginPath() . '/js/qrcode.min.js';

        $templateMgr = TemplateManager::getManager($request);
        $templateMgr->assign('secret', $secret);
        $templateMgr->assign('otpauthUri', $otpauthUri);
        $templateMgr->assign('qrJsUrl', $qrJsUrl);
        $templateMgr->assign('backupCodes', $backupCodes);
        $templateMgr->display($plugin->getTemplateResource('setup.tpl'));
    }

    // ---- Enable 2FA ----

    public function enable($args, $request) {
        if (!$request->checkCSRF()) {
            $request->redirect(null, 'gomit2fa', 'settings');
            return;
        }

        $user = $request->getUser();
        $userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');

        if (Gomit2FAPlugin::isOtpRateLimited($user->getId())) {
            $session = $request->getSession();
            $session->setSessionVar('gomit2fa_flash_error', 'Too many attempts. Please wait 15 minutes.');
            $request->redirect(null, 'gomit2fa', 'settings');
            return;
        }

        $code = trim($request->getUserVar('otp_code'));
        $encryptedSecret = $userSettingsDao->getSetting($user->getId(), 'gomit2fa_secret');
        $secret = Gomit2FAPlugin::decryptSecret($encryptedSecret);

        require_once(dirname(__FILE__) . '/lib/GoogleAuthenticator.php');
        $ga = new \GoogleAuthenticator();

        if ($ga->verifyCode($secret, $code, 2)) {
            Gomit2FAPlugin::clearOtpAttempts($user->getId());
            $userSettingsDao->updateSetting($user->getId(), 'gomit2fa_enabled', true);
            $session = $request->getSession();
            $session->setSessionVar('gomit2fa_verified', true);
            $request->redirect(null, 'gomit2fa', 'settings');
        } else {
            Gomit2FAPlugin::recordOtpFailure($user->getId());
            $session = $request->getSession();
            $session->setSessionVar('gomit2fa_flash_error', 'Invalid OTP code. Try again — your QR Code and secret key have not changed.');
            $request->redirect(null, 'gomit2fa', 'generate');
        }
    }

    // ---- Disable 2FA (requires OTP confirmation) ----

    public function disable($args, $request) {
        if (!$request->checkCSRF()) {
            $request->redirect(null, 'gomit2fa', 'settings');
            return;
        }

        $user = $request->getUser();
        $code = trim($request->getUserVar('otp_code'));

        $userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
        $encryptedSecret = $userSettingsDao->getSetting($user->getId(), 'gomit2fa_secret');
        $secret = Gomit2FAPlugin::decryptSecret($encryptedSecret);

        require_once(dirname(__FILE__) . '/lib/GoogleAuthenticator.php');
        $ga = new \GoogleAuthenticator();

        $valid = $ga->verifyCode($secret, $code, 2) || Gomit2FAPlugin::verifyAndConsumeBackupCode($user->getId(), $code);

        if (!$valid) {
            $session = $request->getSession();
            $session->setSessionVar('gomit2fa_flash_error', 'Invalid OTP code. 2FA was not disabled.');
            $request->redirect(null, 'gomit2fa', 'settings');
            return;
        }

        $userSettingsDao->updateSetting($user->getId(), 'gomit2fa_enabled', false);
        $userSettingsDao->updateSetting($user->getId(), 'gomit2fa_secret', '');
        $userSettingsDao->updateSetting($user->getId(), 'gomit2fa_backup_codes', '');

        $request->redirect(null, 'gomit2fa', 'settings');
    }
}
