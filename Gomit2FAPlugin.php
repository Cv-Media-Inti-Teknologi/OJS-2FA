<?php

namespace APP\plugins\generic\gomit2fa;

use PKP\plugins\GenericPlugin;
use PKP\plugins\Hook;
use PKP\plugins\PluginRegistry;
use PKP\config\Config;
use PKP\db\DAORegistry;
use APP\core\Application;

class Gomit2FAPlugin extends GenericPlugin {
    public function register($category, $path, $mainContextId = null) {
        $success = parent::register($category, $path, $mainContextId);
        if ($success && $this->getEnabled($mainContextId)) {
            Hook::add('LoadHandler', [$this, 'handleLoadRequest']);
            Hook::add('TemplateManager::display', [$this, 'handleTemplateDisplay']);
        }
        return $success;
    }

    public function getName() {
        return 'Gomit2FAPlugin';
    }

    public function getDisplayName() {
        return 'Gomit 2FA Plugin';
    }

    public function getDescription() {
        return 'Adds Two-Factor Authentication (Google Authenticator) to OJS.';
    }

    // ---- Encryption helpers (AES-256-CBC, key from config salt) ----

    public static function encryptSecret(string $plaintext): string {
        $key = substr(hash('sha256', Config::getVar('security', 'salt')), 0, 32);
        $iv = openssl_random_pseudo_bytes(16);
        $cipher = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $cipher);
    }

    public static function decryptSecret(string $encoded): string {
        if (empty($encoded)) return '';
        $key = substr(hash('sha256', Config::getVar('security', 'salt')), 0, 32);
        $data = base64_decode($encoded);
        if ($data === false || strlen($data) < 17) return '';
        $iv = substr($data, 0, 16);
        $cipher = substr($data, 16);
        $result = openssl_decrypt($cipher, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return $result !== false ? $result : '';
    }

    // ---- Rate limiter for OTP attempts ----

    public static function isOtpRateLimited(int $userId): bool {
        $file = self::_otpAttemptsFile($userId);
        if (!file_exists($file)) return false;
        $data = json_decode(file_get_contents($file), true);
        if (!$data) return false;
        $cutoff = time() - 900;
        $recent = array_filter($data['attempts'], fn($t) => $t > $cutoff);
        return count($recent) >= 5;
    }

    public static function recordOtpFailure(int $userId): void {
        $dir = dirname(__FILE__) . '/../../../cache/2fa_attempts';
        if (!is_dir($dir)) @mkdir($dir, 0700, true);
        $file = self::_otpAttemptsFile($userId);
        $data = file_exists($file) ? json_decode(file_get_contents($file), true) : ['attempts' => []];
        if (!$data) $data = ['attempts' => []];
        $data['attempts'][] = time();
        $cutoff = time() - 900;
        $data['attempts'] = array_values(array_filter($data['attempts'], fn($t) => $t > $cutoff));
        file_put_contents($file, json_encode($data));
    }

    public static function clearOtpAttempts(int $userId): void {
        $file = self::_otpAttemptsFile($userId);
        if (file_exists($file)) @unlink($file);
    }

    private static function _otpAttemptsFile(int $userId): string {
        return dirname(__FILE__) . '/../../../cache/2fa_attempts/' . md5((string)$userId) . '.json';
    }

    // ---- Backup codes helpers ----

    public static function generateBackupCodes(int $count = 8): array {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $code = '';
            for ($j = 0; $j < 8; $j++) {
                $code .= dechex(random_int(0, 15));
            }
            $codes[] = $code;
        }
        return $codes;
    }

    public static function hashBackupCodes(array $codes): array {
        return array_map(fn($c) => password_hash($c, PASSWORD_DEFAULT), $codes);
    }

    public static function verifyAndConsumeBackupCode(int $userId, string $inputCode): bool {
        $userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
        $stored = $userSettingsDao->getSetting($userId, 'gomit2fa_backup_codes');
        if (empty($stored)) return false;
        $hashes = json_decode($stored, true);
        if (!is_array($hashes)) return false;
        foreach ($hashes as $i => $hash) {
            if (password_verify($inputCode, $hash)) {
                unset($hashes[$i]);
                $userSettingsDao->updateSetting($userId, 'gomit2fa_backup_codes', json_encode(array_values($hashes)));
                return true;
            }
        }
        return false;
    }

    public static function getBackupCodesCount(int $userId): int {
        $userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
        $stored = $userSettingsDao->getSetting($userId, 'gomit2fa_backup_codes');
        if (empty($stored)) return 0;
        $hashes = json_decode($stored, true);
        return is_array($hashes) ? count($hashes) : 0;
    }

    // ---- Hook handlers ----

    public function handleLoadRequest(string $hookName, array $args): bool {
        $page = $args[0];
        $op = $args[1];
        
        if ($page == 'gomit2fa') {
            define('HANDLER_CLASS', 'Gomit2FAHandler');
            define('GOMIT2FA_PLUGIN_NAME', $this->getName());
            $this->import('Gomit2FAHandler');
            return true;
        }

        if ($page == 'login' && in_array($op, ['signOut', 'lostPassword', 'requestResetPassword'])) {
            return false;
        }

        $request = Application::get()->getRequest();
        $user = $request->getUser();

        if ($user) {
            $userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
            $is2faEnabled = $userSettingsDao->getSetting($user->getId(), 'gomit2fa_enabled');
            
            if ($is2faEnabled) {
                $session = $request->getSession();
                $isVerified = $session->getSessionVar('gomit2fa_verified');
                if (!$isVerified) {
                    $request->redirect(null, 'gomit2fa', 'verify');
                }
            }
        }
        return false;
    }

    public function handleTemplateDisplay(string $hookName, array $args): bool {
        $templateMgr = $args[0];
        $template = $args[1];
        
        $request = Application::get()->getRequest();
        $user = $request->getUser();
        
        if ($user && str_contains($template, 'frontend') && !defined('GOMIT2FA_LINK_INJECTED')) {
            define('GOMIT2FA_LINK_INJECTED', true);
            $router = $request->getRouter();
            $settingsUrl = $router->url($request, null, 'gomit2fa', 'settings');
            
            $js = "<script>
                document.addEventListener('DOMContentLoaded', function() {
                    var nav = document.querySelector('.pkp_navigation_user');
                    if (nav) {
                        var li = document.createElement('li');
                        li.innerHTML = '<a href=\"" . $settingsUrl . "\">2FA Settings</a>';
                        nav.appendChild(li);
                    }
                });
            </script>";
            
            $templateMgr->addHeader('gomit2fa_js', $js);
        }
        return false;
    }
}
