<?php
namespace frieren\modules\wireless_assessment;

/**
 * Input-safety validators and MAC/format utilities.
 *
 * Extracted from Wireless_assessmentController to keep the controller lean and to
 * avoid parsing this code on request paths that don't need it. All methods are pure
 * static helpers (no controller/base-class state). Autoloaded by Frieren's PSR-4
 * fallback (class name == file name) — no registration required.
 */
class WaValidators
{
    public static function isSafeInterfaceName($name)
    {
        return is_string($name) && preg_match('/^[A-Za-z0-9_.:-]{1,32}$/', $name);
    }

    public static function isSafeJobId($jobId)
    {
        return is_string($jobId) && preg_match('/^[A-Za-z0-9_.-]{1,64}$/', $jobId);
    }

    public static function isSafeBssid($bssid)
    {
        return is_string($bssid) && preg_match('/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/', $bssid);
    }

    public static function isSafePhy($phy)
    {
        return is_string($phy) && preg_match('/^phy\d+$/', $phy);
    }

    public static function isSafeRadio($radio)
    {
        return is_string($radio) && preg_match('/^radio\d+$/', $radio);
    }

    public static function isSafeWordlistName($name)
    {
        return is_string($name) && preg_match('/^[A-Za-z0-9._-]{1,64}$/', $name) && strpos($name, '..') === false;
    }

    public static function isPrivateIpv4($ip)
    {
        // Plain octet math (no large hex literals / bitwise) so this is safe on the
        // router's 32-bit PHP build where 0xFFFFFFFF is a float.
        $o = explode('.', $ip);
        if (count($o) !== 4) {
            return false;
        }
        $a = (int)$o[0];
        $b = (int)$o[1];
        return ($a === 10)                        // 10.0.0.0/8
            || ($a === 172 && $b >= 16 && $b <= 31) // 172.16.0.0/12
            || ($a === 192 && $b === 168);          // 192.168.0.0/16
    }

    public static function macOui($mac)
    {
        return strtoupper(str_replace([':', '-'], '', substr((string)$mac, 0, 8)));
    }

    public static function sanitizeSsidForConf($ssid)
    {
        $ssid = preg_replace('/[\x00-\x1F\x7F]/', '', (string)$ssid);
        return substr($ssid, 0, 32);
    }

    public static function cleanMetadataText($value, $maxLength)
    {
        $text = is_string($value) ? $value : '';
        $text = preg_replace('/[\x00-\x1F\x7F]/', ' ', $text);
        $text = trim(preg_replace('/\s+/', ' ', $text));
        return substr($text, 0, $maxLength);
    }

    public static function redactWirelessConfig()
    {
        $output = (string)shell_exec('/sbin/uci show wireless 2>/dev/null');
        $output = preg_replace('/\.(key|password|sae_password)=.*/', '.$1=<redacted>', $output);
        return trim($output);
    }
}
