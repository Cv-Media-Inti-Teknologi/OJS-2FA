<?php
import('lib.pkp.classes.plugins.GenericPlugin');

class Gomit2FAPlugin extends GenericPlugin {
    public function register($category, $path, $mainContextId = null) {
        $success = parent::register($category, $path, $mainContextId);
        if ($success && $this->getEnabled($mainContextId)) {
            HookRegistry::register('LoadHandler', array($this, 'handleLoadRequest'));
            HookRegistry::register('TemplateManager::display', array($this, 'handleTemplateDisplay'));
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

    public static function encryptSecret($plaintext) {
        $key = substr(hash('sha256', Config::getVar('security', 'salt')), 0, 32);
        $iv = openssl_random_pseudo_bytes(16);
        $cipher = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $cipher);
    }

    public static function decryptSecret($encoded) {
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

    public static function isOtpRateLimited($userId) {
        $file = self::_otpAttemptsFile($userId);
        if (!file_exists($file)) return false;
        $data = json_decode(file_get_contents($file), true);
        if (!$data) return false;
        $cutoff = time() - 900; // 15 minutes
        $recent = array_filter($data['attempts'], function($t) use ($cutoff) { return $t > $cutoff; });
        return count($recent) >= 5;
    }

    public static function recordOtpFailure($userId) {
        $dir = dirname(__FILE__) . '/../../../cache/2fa_attempts';
        if (!is_dir($dir)) @mkdir($dir, 0700, true);
        $file = self::_otpAttemptsFile($userId);
        $data = file_exists($file) ? json_decode(file_get_contents($file), true) : array('attempts' => array());
        if (!$data) $data = array('attempts' => array());
        $data['attempts'][] = time();
        // Keep only last 15 min
        $cutoff = time() - 900;
        $data['attempts'] = array_values(array_filter($data['attempts'], function($t) use ($cutoff) { return $t > $cutoff; }));
        file_put_contents($file, json_encode($data));
    }

    public static function clearOtpAttempts($userId) {
        $file = self::_otpAttemptsFile($userId);
        if (file_exists($file)) @unlink($file);
    }

    private static function _otpAttemptsFile($userId) {
        return dirname(__FILE__) . '/../../../cache/2fa_attempts/' . md5($userId) . '.json';
    }

    // ---- Backup codes helpers ----

    public static function generateBackupCodes($count = 8) {
        $codes = array();
        for ($i = 0; $i < $count; $i++) {
            $code = '';
            for ($j = 0; $j < 8; $j++) {
                $code .= dechex(random_int(0, 15));
            }
            $codes[] = $code;
        }
        return $codes;
    }

    public static function hashBackupCodes($codes) {
        return array_map(function($c) { return password_hash($c, PASSWORD_DEFAULT); }, $codes);
    }

    public static function verifyAndConsumeBackupCode($userId, $inputCode) {
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

    public static function getBackupCodesCount($userId) {
        $userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
        $stored = $userSettingsDao->getSetting($userId, 'gomit2fa_backup_codes');
        if (empty($stored)) return 0;
        $hashes = json_decode($stored, true);
        return is_array($hashes) ? count($hashes) : 0;
    }

    // ---- Hook handlers ----

    public function handleLoadRequest($hookName, $args) {
        $page = $args[0];
        $op = $args[1];
        
        if ($page == 'gomit2fa') {
            define('HANDLER_CLASS', 'Gomit2FAHandler');
            define('GOMIT2FA_PLUGIN_NAME', $this->getName());
            $this->import('Gomit2FAHandler');
            return true;
        }

        if ($page == 'login' && ($op == 'signOut' || $op == 'lostPassword' || $op == 'requestResetPassword')) {
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

    public function handleTemplateDisplay($hookName, $args) {
        $templateMgr = $args[0];
        $template = $args[1];
        
        $request = Application::get()->getRequest();
        $user = $request->getUser();
        
        if ($user && ($template === 'frontend/components/header.tpl' || $template === 'common/header.tpl') && !defined('GOMIT2FA_LINK_INJECTED')) {
            define('GOMIT2FA_LINK_INJECTED', true);
            $router = $request->getRouter();
            $settingsUrl = $router->url($request, null, 'gomit2fa', 'settings');
            
            $js = "<script>
                document.addEventListener('DOMContentLoaded', function() {
                    // Attempt to inject into frontend menu
                    var frontNav = document.querySelector('.pkp_navigation_user');
                    if (frontNav) {
                        var li = document.createElement('li');
                        li.innerHTML = '<a href=\"".$settingsUrl."\">2FA Settings</a>';
                        frontNav.appendChild(li);
                    }
                    
                    // Attempt to inject into backend menu (Dashboard)
                    var backNav = document.querySelector('.app__headerActions, .pkp_nav_user');
                    if (backNav) {
                        var btn = document.createElement('a');
                        btn.href = '".$settingsUrl."';
                        btn.style = 'color: white; font-weight: bold; margin-right: 15px; display: inline-block; padding: 5px 10px; background: #e02a2a; border-radius: 3px; text-decoration: none;';
                        btn.innerText = '🛡️ 2FA Settings';
                        backNav.insertBefore(btn, backNav.firstChild);
                    } else {
                        // Fallback: floating button if menu not found
                        var floatBtn = document.createElement('a');
                        floatBtn.href = '".$settingsUrl."';
                        floatBtn.style = 'position: fixed; bottom: 20px; left: 20px; z-index: 9999; background: #e02a2a; color: white; padding: 10px 15px; border-radius: 5px; font-weight: bold; box-shadow: 0 2px 4px rgba(0,0,0,0.2); text-decoration: none;';
                        floatBtn.innerHTML = '🛡️ 2FA Settings';
                        document.body.appendChild(floatBtn);
                    }
                });
            </script>";
            
            $templateMgr->addHeader('gomit2fa_js', $js);
        }
        return false;
    }
}
