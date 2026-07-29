<?php
namespace frieren\modules\wireless_assessment;

/**
 * Static HTML/CSS templates for captive-portal and MITM awareness pages.
 *
 * Extracted from Wireless_assessmentController to keep the controller lean and to
 * avoid parsing this code on request paths that don't need it. All methods are pure
 * static helpers (no controller/base-class state). Autoloaded by Frieren's PSR-4
 * fallback (class name == file name) — no registration required.
 */
class WaTemplates
{
    public static function portalTemplateDefs()
    {
        // Neutral, non-brand-impersonating templates for authorized self-assessment.
        // Each declares the fields its form posts to /cgi-bin/submit.
        return [
            'wifi' => [
                'label' => 'Wi-Fi password',
                'description' => 'Asks for the network password (can verify offline against a captured handshake).',
                'fields' => ['password'],
            ],
            'router' => [
                'label' => 'Router admin login',
                'description' => 'Generic router administration sign-in (username + password).',
                'fields' => ['username', 'password'],
            ],
            'isp' => [
                'label' => 'Internet sign-in',
                'description' => 'Generic ISP / Wi-Fi account sign-in (email + password).',
                'fields' => ['email', 'password'],
            ],
            'custom' => [
                'label' => 'Custom HTML',
                'description' => 'Your own page. Must contain a <form method=post action=/cgi-bin/submit>.',
                'fields' => [],
            ],
        ];
    }

    public static function mitmCloneTemplateDefs()
    {
        return [
            'instagram' => ['label' => 'Instagram-style login', 'description' => 'Username/email + password clone login page.'],
            'google' => ['label' => 'Google-style sign-in', 'description' => 'Email + password clone sign-in page.'],
        ];
    }

    public static function mitmNoticePage($msg)
    {
        $m = htmlspecialchars($msg !== '' ? $msg : 'This site has been redirected as part of an authorized security assessment.', ENT_QUOTES);
        return "<!doctype html><html><head><meta charset=utf-8>"
            . "<meta name=viewport content='width=device-width,initial-scale=1'><title>Notice</title>"
            . "<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;"
            . "display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}"
            . ".b{max-width:440px;padding:28px;text-align:center}h1{font-size:20px}p{color:#94a3b8;font-size:15px}</style>"
            . "</head><body><div class=b><h1>Security assessment</h1><p>{$m}</p></div></body></html>";
    }

    public static function mitmGotchaPage()
    {
        return "<!doctype html><html><head><meta charset=utf-8>"
            . "<meta name=viewport content='width=device-width,initial-scale=1'><title>Security awareness test</title>"
            . "<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;"
            . "display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}"
            . ".b{max-width:460px;padding:32px;text-align:center}h1{color:#f87171;font-size:20px}p{color:#94a3b8;font-size:15px}</style>"
            . "</head><body><div class=b><h1>This was a simulated phishing test</h1>"
            . "<p>You just entered credentials into a fake login page as part of an authorized security assessment on this network. "
            . "If this had been a real attack, that account would now be compromised.</p>"
            . "<p>Check the address bar before signing in anywhere, and never reuse this password if it was real.</p></div></body></html>";
    }

    public static function renderMitmClonePage($template)
    {
        if ($template === 'instagram') {
            return "<!doctype html><html><head><meta charset=utf-8>"
                . "<meta name=viewport content='width=device-width,initial-scale=1'><title>Instagram</title>"
                . "<style>body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#fafafa;margin:0}"
                . ".wrap{max-width:350px;margin:60px auto;padding:0 20px}"
                . ".card{background:#fff;border:1px solid #dbdbdb;border-radius:1px;padding:36px 40px 20px;text-align:center}"
                . ".logo{font-size:42px;margin:22px 0 30px;font-weight:600;font-style:italic;"
                . "background:linear-gradient(45deg,#f09433,#e6683c,#dc2743,#cc2366,#bc1888);-webkit-background-clip:text;-webkit-text-fill-color:transparent}"
                . "input{width:100%;box-sizing:border-box;background:#fafafa;border:1px solid #dbdbdb;border-radius:3px;padding:9px 8px;margin:3px 0;font-size:14px}"
                . "button{width:100%;margin-top:10px;padding:9px;border:0;border-radius:8px;background:#4cb5f9;color:#fff;font-weight:600}"
                . ".sep{color:#8e8e8e;font-size:13px;margin:14px 0}"
                . ".foot{border:1px solid #dbdbdb;border-radius:1px;margin-top:12px;padding:18px;font-size:14px;text-align:center}</style>"
                . "</head><body><div class=wrap><div class=card><div class=logo>Instagram</div>"
                . "<form method=post action=/cgi-bin/submit>"
                . "<input type=text name=username placeholder='Phone number, username, or email' autofocus required>"
                . "<input type=password name=password placeholder='Password' required>"
                . "<button type=submit>Log in</button></form><div class=sep>Forgot password?</div></div>"
                . "<div class=foot>Don't have an account? <b>Sign up</b></div></div></body></html>";
        }
        if ($template === 'google') {
            return "<!doctype html><html><head><meta charset=utf-8>"
                . "<meta name=viewport content='width=device-width,initial-scale=1'><title>Sign in - Accounts</title>"
                . "<style>body{font-family:Roboto,Arial,sans-serif;background:#fff;margin:0}"
                . ".wrap{max-width:450px;margin:40px auto;padding:48px 40px;border:1px solid #dadce0;border-radius:8px;box-sizing:border-box}"
                . ".logo{font-size:24px;font-weight:400;margin-bottom:16px}.logo b{color:#4285F4}"
                . "h1{font-size:24px;font-weight:400;margin:8px 0}p{color:#5f6368;font-size:16px}"
                . "input{width:100%;box-sizing:border-box;border:1px solid #dadce0;border-radius:4px;padding:13px 15px;margin:8px 0;font-size:16px}"
                . "button{float:right;margin-top:20px;padding:10px 24px;border:0;border-radius:4px;background:#1a73e8;color:#fff;font-weight:600}</style>"
                . "</head><body><div class=wrap><div class=logo><b>G</b>oogle</div><h1>Sign in</h1><p>to continue</p>"
                . "<form method=post action=/cgi-bin/submit>"
                . "<input type=email name=email placeholder='Email or phone' autofocus required>"
                . "<input type=password name=password placeholder='Password' required>"
                . "<button type=submit>Next</button></form></div></body></html>";
        }
        return self::mitmNoticePage('');
    }

    public static function toolPurpose($tool)
    {
        $purposes = [
            'iw' => 'radio and AP scanning',
            'iwinfo' => 'OpenWrt wireless status',
            'wifi' => 'OpenWrt wireless control/status',
            'ubus' => 'OpenWrt runtime data',
            'uci' => 'configuration reads',
            'hcxdumptool' => 'unused — active injection crashed this hardware, retired from all attack paths',
            'nmap' => 'LAN/client service checks',
            'curl' => 'module integrations',
            'tcpdump' => 'packet capture workflows',
            'aircrack-ng' => 'handshake verification/cracking workflow',
            'airodump-ng' => 'monitor-mode capture engine (PMKID/handshake)',
            'aireplay-ng' => 'authorized deauth to force handshakes',
            'reaver' => 'WPS assessment',
            'wash' => 'WPS discovery',
            'bully' => 'alternate WPS assessment',
            'hcxpcapngtool' => 'capture -> hashcat 22000 conversion',
            'hcxhashtool' => 'hash utility workflows',
            'sqlite3' => 'CLI database inspection',
            'hostapd' => 'Evil Portal twin AP',
            'dnsmasq' => 'Evil Portal DHCP for twin subnet',
            'nft' => 'Evil Portal captive-portal redirect',
            'uhttpd' => 'Evil Portal captive-portal web server',
        ];
        return $purposes[$tool] ?? '';
    }
}
