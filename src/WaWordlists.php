<?php
namespace frieren\modules\wireless_assessment;

/**
 * Wordlist generation and WPS default-PIN computation.
 *
 * Extracted from Wireless_assessmentController to keep the controller lean and to
 * avoid parsing this code on request paths that don't need it. All methods are pure
 * static helpers (no controller/base-class state). Autoloaded by Frieren's PSR-4
 * fallback (class name == file name) — no registration required.
 */
class WaWordlists
{
    public static function commonPskList()
    {
        // Curated common WPA/WPA2 pre-shared keys (all >= 8 chars).
        return [
            '12345678', '123456789', '1234567890', 'password', 'password1', 'password123',
            'qwerty123', 'qwertyuiop', 'abcd1234', 'abc12345', '1qaz2wsx', 'q1w2e3r4',
            '11111111', '00000000', '123123123', '12341234', '87654321', 'iloveyou',
            'welcome1', 'welcome123', 'admin123', 'administrator', 'letmein1', 'changeme',
            'internet', 'wireless', 'password!', 'p@ssw0rd', 'passw0rd', 'sunshine1',
            'football1', 'baseball1', 'superman1', 'trustno1', 'whatever1', 'dragon123',
            'monkey123', 'master123', 'shadow123', 'michael1', 'jennifer1', 'computer1',
            'princess1', 'starwars1', 'freedom1', 'samsung1', 'default1', 'homewifi1',
            'mypassword', 'mypassword1', 'wifipassword', 'network1', 'router123', 'linksys1',
            'netgear1', 'dlink123', 'tplink123', 'connect1', 'guest1234', 'family123',
            'welcome2024', 'welcome2025', 'summer2024', 'winter2024', 'spring2024', 'autumn2024',
            '10203040', '13579246', '24681357', 'a1b2c3d4', 'asdfghjkl', 'zxcvbnm123',
            '55555555', '99999999', '12121212', '77777777', 'test1234', 'demo1234',
            'qazwsxedc', '1234qwer', 'qwer1234', 'pass1234', 'secret123', 'hello123',
            'love1234', 'money123', 'happy123', 'ninja123', 'ranger123', 'hunter123',
        ];
    }

    public static function digitsWordlist()
    {
        $out = [];
        for ($d = 0; $d <= 9; $d++) {
            $out[] = str_repeat((string)$d, 8);
        }
        $asc = '0123456789';
        for ($i = 0; $i + 8 <= 10; $i++) {
            $out[] = substr($asc, $i, 8);
        }
        $desc = '9876543210';
        for ($i = 0; $i + 8 <= 10; $i++) {
            $out[] = substr($desc, $i, 8);
        }
        // yyyymmdd birthdays — a realistic bounded PSK space (~19k entries).
        for ($y = 1960; $y <= 2015; $y++) {
            for ($m = 1; $m <= 12; $m++) {
                for ($day = 1; $day <= 28; $day++) {
                    $out[] = sprintf('%04d%02d%02d', $y, $m, $day);
                }
            }
        }
        return $out;
    }

    public static function ssidWordlist($ssid)
    {
        $bases = array_values(array_unique([$ssid, strtolower($ssid), strtoupper($ssid), ucfirst(strtolower($ssid))]));
        $suffixes = [
            '', '1', '12', '123', '1234', '12345', '123456', '1234567', '12345678',
            '2020', '2021', '2022', '2023', '2024', '2025', '@123', '@1234', '!', '!123',
            '#123', '00', '007', 'password', 'wifi', 'admin',
        ];
        $out = [];
        foreach ($bases as $b) {
            foreach ($suffixes as $s) {
                $out[] = $b . $s;
            }
            for ($n = 0; $n <= 999; $n++) {
                $out[] = $b . $n;
            }
        }
        return $out;
    }

    public static function macToFloat($bssid)
    {
        $hex = str_replace(':', '', strtolower($bssid));
        $val = 0.0;
        for ($i = 0; $i < strlen($hex); $i++) {
            $val = $val * 16 + hexdec($hex[$i]);
        }
        return $val;
    }

    public static function wpsChecksum($pin)
    {
        $accum = 0;
        $t = (int)$pin;
        while ($t) {
            $accum += 3 * ($t % 10);
            $t = intdiv($t, 10);
            $accum += $t % 10;
            $t = intdiv($t, 10);
        }
        return (10 - $accum % 10) % 10;
    }

    public static function wpsGenPin($seedFloat)
    {
        $pin = (int)fmod($seedFloat, 10000000.0);
        $pin = $pin * 10 + self::wpsChecksum($pin);
        return str_pad((string)$pin, 8, '0', STR_PAD_LEFT);
    }

    public static function wpsPinCandidates($bssid)
    {
        $mac = self::macToFloat($bssid);
        $out = [];
        $add = function ($algo, $pin) use (&$out) {
            $out[] = ['algo' => $algo, 'pin' => $pin];
        };

        // ComputePIN family — seed = the low N bits of the MAC.
        $masks = [
            24 => 16777216.0, 28 => 268435456.0, 32 => 4294967296.0,
            36 => 68719476736.0, 40 => 1099511627776.0, 44 => 17592186044416.0,
            48 => 281474976710656.0,
        ];
        foreach ($masks as $bits => $mod) {
            $add('ComputePIN-' . $bits, self::wpsGenPin(fmod($mac, $mod)));
        }

        // D-Link default algorithm (derived from the low 24 bits / NIC).
        $nic = (int)fmod($mac, 16777216.0);
        foreach ([0, 1] as $delta) {
            $n = $nic + $delta;
            $pin = $n ^ 0x55AA55;
            $pin ^= ((($pin & 0xF) << 4) + (($pin & 0xF) << 8) + (($pin & 0xF) << 12) + (($pin & 0xF) << 16) + (($pin & 0xF) << 20));
            $pin = $pin % 10000000;
            if ($pin < 1000000) {
                $pin += (($pin % 9) * 1000000) + 1000000;
            }
            $add('D-Link' . ($delta ? '+1' : ''), str_pad((string)($pin * 10 + self::wpsChecksum($pin)), 8, '0', STR_PAD_LEFT));
        }

        // Well-known static defaults.
        $add('Static default', '12345670');
        $add('Static default', '00000000');

        $seen = [];
        $res = [];
        foreach ($out as $c) {
            if (isset($seen[$c['pin']])) {
                continue;
            }
            $seen[$c['pin']] = true;
            $res[] = $c;
        }
        return $res;
    }
}
