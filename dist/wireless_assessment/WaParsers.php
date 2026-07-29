<?php
namespace frieren\modules\wireless_assessment;

/**
 * Parsers for wireless tool output (iw/iwinfo/airodump/reaver/tcpdump/radiotap).
 *
 * Extracted from Wireless_assessmentController to keep the controller lean and to
 * avoid parsing this code on request paths that don't need it. All methods are pure
 * static helpers (no controller/base-class state). Autoloaded by Frieren's PSR-4
 * fallback (class name == file name) — no registration required.
 */
class WaParsers
{
    public static function radiotapSignal($rt)
    {
        $len = strlen($rt);
        if ($len < 8) {
            return null;
        }
        // Read present word(s); bit 31 flags another 32-bit present word follows.
        $o = 4;
        $word0 = null;
        while ($o + 4 <= $len) {
            $w = ord($rt[$o]) | (ord($rt[$o + 1]) << 8) | (ord($rt[$o + 2]) << 16) | (ord($rt[$o + 3]) << 24);
            if ($word0 === null) {
                $word0 = $w;
            }
            $o += 4;
            if (!($w & 0x80000000)) {
                break;
            }
        }
        if ($word0 === null || !($word0 & (1 << 5))) {
            return null; // no antenna-signal field advertised
        }
        // Fixed-size fields that precede bit 5: [bit => [align, size]].
        $fields = [0 => [8, 8], 1 => [1, 1], 2 => [1, 1], 3 => [2, 4], 4 => [2, 2]];
        $pos = $o; // data area begins right after the present words
        foreach ($fields as $bit => $fs) {
            if ($word0 & (1 << $bit)) {
                list($align, $size) = $fs;
                if ($pos % $align !== 0) {
                    $pos += $align - ($pos % $align);
                }
                $pos += $size;
            }
        }
        if ($pos >= $len) {
            return null;
        }
        $b = ord($rt[$pos]);
        return $b >= 128 ? $b - 256 : $b; // signed int8, dBm
    }

    public static function cleanSsid($raw)
    {
        $raw = (string)$raw;
        if ($raw === '' || trim($raw) === '' || strspn($raw, "\0") === strlen($raw)) {
            return '<hidden>';
        }
        $clean = preg_replace('/[\x00-\x1F\x7F]/', '', $raw);
        return $clean !== '' ? $clean : '<hidden>';
    }

    public static function signalDbm($net)
    {
        if (preg_match('/-?\d+/', (string)($net['signal'] ?? ''), $m)) {
            return (int)$m[0];
        }
        return -999;
    }

    public static function freqToChannel($freq)
    {
        if ($freq === 2484) {
            return '14';
        }
        if ($freq >= 2412 && $freq <= 2472) {
            return (string)(($freq - 2407) / 5);
        }
        if ($freq >= 5000 && $freq <= 5900) {
            return (string)(($freq - 5000) / 5);
        }
        return '';
    }

    public static function ipFromToken($tok)
    {
        // tcpdump renders endpoints as "10.0.0.5.51000" (ip.port); strip the port.
        if (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.\d+)?$/', $tok, $m)) {
            return $m[1];
        }
        return $tok;
    }

    public static function parseIwinfoScan($output)
    {
        $networks = [];
        $blocks = preg_split('/\n(?=Cell\s+\d+\s+-\s+Address:)/', trim($output));
        foreach ($blocks as $block) {
            $block = trim($block);
            if ($block === '') {
                continue;
            }

            $network = [
                'bssid' => '',
                'ssid' => '<hidden>',
                'channel' => '',
                'frequency' => '',
                'security' => 'Open',
                'signal' => '',
                'lastSeen' => 'now',
                'capabilities' => [],
            ];

            if (preg_match('/Address:\s*([0-9A-F:]{17})/i', $block, $match)) {
                $network['bssid'] = strtolower($match[1]);
            }
            if (preg_match('/ESSID:\s*"([^"]*)"/', $block, $match)) {
                $network['ssid'] = $match[1] !== '' ? $match[1] : '<hidden>';
            }
            if (preg_match('/Frequency:\s*([0-9.]+\s*GHz).*Channel:\s*(\d+)/', $block, $match)) {
                $network['frequency'] = trim($match[1]);
                $network['channel'] = $match[2];
            }
            if (preg_match('/Signal:\s*([-0-9]+\s*dBm)/', $block, $match)) {
                $network['signal'] = trim($match[1]);
            }
            if (preg_match('/Encryption:\s*(.+)/', $block, $match)) {
                $security = trim($match[1]);
                $network['security'] = strtolower($security) === 'none' ? 'Open' : $security;
            }
            if (preg_match('/Channel Width:\s*(.+)/', $block, $match)) {
                $network['capabilities'][] = 'width=' . trim($match[1]);
            }

            if ($network['bssid'] !== '') {
                $networks[] = $network;
            }
        }
        return $networks;
    }

    public static function parseIwScan($output)
    {
        $networks = [];
        $blocks = preg_split('/\nBSS\s+/', "\n" . trim($output));
        foreach ($blocks as $block) {
            $block = trim($block);
            if ($block === '' || stripos($block, 'last seen') === false) {
                continue;
            }
            $network = [
                'bssid' => '',
                'ssid' => '<hidden>',
                'channel' => '',
                'frequency' => '',
                'signal' => '',
                'security' => 'Open',
                'capabilities' => [],
                'lastSeen' => '',
            ];
            if (preg_match('/^([0-9a-f:]{17})/i', $block, $match)) {
                $network['bssid'] = strtolower($match[1]);
            }
            if (preg_match('/SSID:\s*(.*)/', $block, $match)) {
                $ssid = trim($match[1]);
                $network['ssid'] = $ssid !== '' ? $ssid : '<hidden>';
            }
            if (preg_match('/freq:\s*(\d+)/', $block, $match)) {
                $network['frequency'] = $match[1] . ' MHz';
                $network['channel'] = self::freqToChannel((int)$match[1]);
            }
            if (preg_match('/signal:\s*([-0-9.]+)\s*dBm/', $block, $match)) {
                $network['signal'] = $match[1] . ' dBm';
            }
            if (preg_match('/last seen:\s*(\d+)\s*ms ago/', $block, $match)) {
                $network['lastSeen'] = $match[1] . ' ms ago';
            }
            $security = [];
            if (strpos($block, "\tRSN:") !== false) {
                $security[] = 'WPA2/RSN';
            }
            if (strpos($block, "\tWPA:") !== false) {
                $security[] = 'WPA';
            }
            if (stripos($block, 'Authentication suites: SAE') !== false) {
                $security[] = 'WPA3/SAE';
            }
            if (stripos($block, 'WPS:') !== false) {
                $security[] = 'WPS';
            }
            $network['security'] = empty($security) ? 'Open' : implode(', ', array_unique($security));
            if (preg_match('/capability:\s+(.+)/', $block, $match)) {
                $network['capabilities'] = preg_split('/\s+/', trim($match[1]));
            }
            if ($network['bssid'] !== '') {
                $networks[] = $network;
            }
        }
        return $networks;
    }

    public static function parseAirodumpCsv($csv)
    {
        $aps = [];
        $clients = [];
        $csv = str_replace("\r", '', (string)$csv);
        $lines = explode("\n", $csv);
        $section = 'none';
        foreach ($lines as $line) {
            $trim = trim($line);
            if ($trim === '') {
                continue;
            }
            if (strpos($trim, 'BSSID,') === 0 && stripos($trim, 'First time seen') !== false) {
                $section = 'ap';
                continue;
            }
            if (strpos($trim, 'Station MAC,') === 0) {
                $section = 'client';
                continue;
            }

            $cols = array_map('trim', explode(',', $line));
            if ($section === 'ap') {
                if (count($cols) < 14 || !WaValidators::isSafeBssid(strtolower($cols[0]))) {
                    continue;
                }
                $bssid = strtolower($cols[0]);
                $privacy = $cols[5];
                $cipher = $cols[6];
                $auth = $cols[7];
                $security = trim($privacy);
                if ($security === '' || strtoupper($security) === 'OPN') {
                    $security = 'Open';
                } else {
                    $security = trim($privacy . ($cipher !== '' ? ' ' . $cipher : '') . ($auth !== '' ? ' ' . $auth : ''));
                }
                $essid = isset($cols[13]) ? $cols[13] : '';
                $aps[] = [
                    'bssid' => $bssid,
                    'channel' => (string)((int)$cols[3]),
                    'security' => $security,
                    'signal' => ($cols[8] !== '' ? $cols[8] . ' dBm' : ''),
                    'beacons' => (int)($cols[9] ?? 0),
                    'ssid' => self::cleanSsid($essid),
                ];
            } elseif ($section === 'client') {
                if (count($cols) < 6 || !WaValidators::isSafeBssid(strtolower($cols[0]))) {
                    continue;
                }
                $mac = strtolower($cols[0]);
                $assoc = strtolower($cols[5]);
                $associated = WaValidators::isSafeBssid($assoc) ? $assoc : '';
                $probes = [];
                if (isset($cols[6])) {
                    for ($i = 6; $i < count($cols); $i++) {
                        $probe = trim($cols[$i]);
                        if ($probe !== '') {
                            $probes[] = $probe;
                        }
                    }
                }
                $clients[] = [
                    'mac' => $mac,
                    'bssid' => $associated,
                    'signal' => ($cols[3] !== '' ? $cols[3] . ' dBm' : ''),
                    'packets' => (int)($cols[4] ?? 0),
                    'probes' => $probes,
                ];
            }
        }
        return ['aps' => $aps, 'clients' => $clients];
    }

    public static function parseWpsCapture($pcapPath)
    {
        $data = @file_get_contents($pcapPath);
        if (!is_string($data) || strlen($data) < 24) {
            return [];
        }

        $magic = substr($data, 0, 4);
        if ($magic === "\xd4\xc3\xb2\xa1") {
            $le = true;
        } elseif ($magic === "\xa1\xb2\xc3\xd4") {
            $le = false;
        } else {
            return [];
        }
        $u32 = function ($s) use ($le) {
            $b = array_values(unpack('C4', $s));
            return $le
                ? ($b[0] | ($b[1] << 8) | ($b[2] << 16) | ($b[3] << 24))
                : (($b[0] << 24) | ($b[1] << 16) | ($b[2] << 8) | $b[3]);
        };

        $linktype = $u32(substr($data, 20, 4));
        $len = strlen($data);
        $off = 24;
        $found = [];

        while ($off + 16 <= $len) {
            $inclLen = $u32(substr($data, $off + 8, 4));
            $off += 16;
            if ($inclLen <= 0 || $off + $inclLen > $len) {
                break;
            }
            $pkt = substr($data, $off, $inclLen);
            $off += $inclLen;

            // Strip radiotap (linktype 127); its it_len at bytes 2-3 is always LE.
            // Pull the dBm antenna-signal field out of the header before discarding it.
            $frame = $pkt;
            $signal = null;
            if ($linktype === 127) {
                if (strlen($pkt) < 4) {
                    continue;
                }
                $rtLen = ord($pkt[2]) | (ord($pkt[3]) << 8);
                if ($rtLen < 8 || $rtLen >= strlen($pkt)) {
                    continue;
                }
                $signal = self::radiotapSignal(substr($pkt, 0, $rtLen));
                $frame = substr($pkt, $rtLen);
            }
            if (strlen($frame) < 38) {
                continue;
            }

            $fc = ord($frame[0]);
            // Management beacon (0x80) or probe response (0x50) carry the WPS IE.
            if ($fc !== 0x80 && $fc !== 0x50) {
                continue;
            }

            $bssidRaw = substr($frame, 16, 6);
            $bssid = strtolower(implode(':', str_split(bin2hex($bssidRaw), 2)));
            $ies = substr($frame, 36);

            $ssid = '';
            $channel = '';
            $hasWps = false;
            $locked = false;
            $version = '';

            $p = 0;
            $ieLen = strlen($ies);
            while ($p + 2 <= $ieLen) {
                $tag = ord($ies[$p]);
                $tlen = ord($ies[$p + 1]);
                $p += 2;
                if ($p + $tlen > $ieLen) {
                    break;
                }
                $val = substr($ies, $p, $tlen);
                $p += $tlen;

                if ($tag === 0) {
                    $ssid = $val;
                } elseif ($tag === 3 && $tlen >= 1) {
                    $channel = (string)ord($val[0]);
                } elseif ($tag === 221 && $tlen >= 4 && substr($val, 0, 4) === "\x00\x50\xf2\x04") {
                    $hasWps = true;
                    $wd = substr($val, 4);
                    $q = 0;
                    $wl = strlen($wd);
                    while ($q + 4 <= $wl) {
                        $atype = (ord($wd[$q]) << 8) | ord($wd[$q + 1]);
                        $alen = (ord($wd[$q + 2]) << 8) | ord($wd[$q + 3]);
                        $q += 4;
                        if ($q + $alen > $wl) {
                            break;
                        }
                        $aval = substr($wd, $q, $alen);
                        $q += $alen;
                        if ($atype === 0x1057 && $alen >= 1) {
                            $locked = (ord($aval[0]) === 1);
                        } elseif ($atype === 0x104A && $alen >= 1) {
                            $version = (ord($aval[0]) >= 0x20) ? '2.0' : '1.0';
                        }
                    }
                    if ($version === '') {
                        $version = '1.0';
                    }
                }
            }

            if (!$hasWps) {
                continue;
            }
            // Prefer the entry with the most information; keep first-seen SSID/channel.
            $prev = $found[$bssid] ?? null;
            // Track the strongest signal seen for this BSSID (closest to 0 dBm).
            $prevSig = ($prev !== null && $prev['signalVal'] !== null) ? $prev['signalVal'] : null;
            $bestSig = $prevSig;
            if ($signal !== null && ($bestSig === null || $signal > $bestSig)) {
                $bestSig = $signal;
            }
            $found[$bssid] = [
                'bssid' => $bssid,
                'channel' => $channel !== '' ? $channel : ($prev['channel'] ?? ''),
                'ssid' => self::cleanSsid($ssid !== '' ? $ssid : ($prev['ssidRaw'] ?? '')),
                'ssidRaw' => $ssid !== '' ? $ssid : ($prev['ssidRaw'] ?? ''),
                'wpsVersion' => $version,
                'wpsLocked' => $locked || (bool)($prev['wpsLocked'] ?? false),
                'signalVal' => $bestSig,
                'signal' => $bestSig !== null ? ($bestSig . ' dBm') : '',
            ];
        }

        $networks = array_values($found);
        foreach ($networks as &$n) {
            unset($n['ssidRaw'], $n['signalVal']);
        }
        return $networks;
    }

    public static function parseSniffCapture($paths)
    {
        $empty = [
            'dns' => [], 'http' => [], 'creds' => [], 'cookies' => [],
            'counts' => ['dns' => 0, 'http' => 0, 'creds' => 0, 'cookies' => 0],
            'pcapBytes' => 0, 'clients' => [],
        ];
        $files = glob($paths['pcap'] . '*');
        if (empty($files)) {
            return $empty;
        }
        $tcpdump = trim((string)shell_exec('command -v tcpdump 2>/dev/null')) ?: 'tcpdump';
        $text = '';
        $pcapBytes = 0;
        foreach ($files as $f) {
            $pcapBytes += (int)@filesize($f);
            if (strlen($text) < 700000) {
                $text .= (string)shell_exec($tcpdump . ' -r ' . escapeshellarg($f) . ' -A -n -s 0 2>/dev/null | head -c 400000');
                $text .= "\n";
            }
        }
        $empty['pcapBytes'] = $pcapBytes;
        if (trim($text) === '') {
            return $empty;
        }

        $dns = [];
        $http = [];
        $creds = [];
        $cookies = [];
        $clients = [];

        $curSrc = '';
        $curDst = '';
        $curHost = '';
        foreach (explode("\n", $text) as $raw) {
            $line = rtrim($raw, "\r");
            if (preg_match('/^\d\d:\d\d:\d\d\.\d+ IP6?\s+(\S+?)\s+>\s+(\S+?):/', $line, $m)) {
                $curSrc = self::ipFromToken($m[1]);
                $curDst = self::ipFromToken($m[2]);
                $curHost = '';
                if (preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $curSrc)) {
                    $clients[$curSrc] = true;
                }
                if (strpos($line, '.53:') !== false && preg_match_all('/\b(?:A|AAAA|CNAME)\??\s+([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)/', $line, $dm)) {
                    foreach ($dm[1] as $dom) {
                        $dom = strtolower(rtrim($dom, '.'));
                        if ($dom === '' || strpos($dom, '.') === false) {
                            continue;
                        }
                        $k = $curSrc . '|' . $dom;
                        $dns[$k] = ($dns[$k] ?? 0) + 1;
                    }
                }
                continue;
            }
            $t = trim($line);
            if ($t === '') {
                continue;
            }
            if (preg_match('#^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)\s+HTTP/#', $t, $rm)) {
                $http[] = ['client' => $curSrc, 'method' => $rm[1], 'url' => substr($rm[2], 0, 120), 'host' => '', 'ua' => ''];
                continue;
            }
            if (stripos($t, 'Host:') === 0) {
                $curHost = substr(trim(substr($t, 5)), 0, 80);
                for ($i = count($http) - 1; $i >= 0 && $i >= count($http) - 4; $i--) {
                    if ($http[$i]['client'] === $curSrc && $http[$i]['host'] === '') {
                        $http[$i]['host'] = $curHost;
                        break;
                    }
                }
                continue;
            }
            if (stripos($t, 'User-Agent:') === 0) {
                $ua = substr(trim(substr($t, 11)), 0, 120);
                for ($i = count($http) - 1; $i >= 0 && $i >= count($http) - 4; $i--) {
                    if ($http[$i]['client'] === $curSrc && $http[$i]['ua'] === '') {
                        $http[$i]['ua'] = $ua;
                        break;
                    }
                }
                continue;
            }
            if (stripos($t, 'Authorization: Basic ') === 0) {
                $dec = base64_decode(trim(substr($t, 21)), true);
                if ($dec !== false && strpos($dec, ':') !== false && ctype_print($dec)) {
                    $creds[] = ['client' => $curSrc, 'host' => $curHost, 'type' => 'HTTP Basic', 'detail' => substr($dec, 0, 120)];
                }
                continue;
            }
            if (stripos($t, 'Cookie:') === 0) {
                $k = $curSrc . '|' . $curHost;
                if (!isset($cookies[$k])) {
                    $cookies[$k] = ['client' => $curSrc, 'host' => $curHost, 'cookie' => substr(trim(substr($t, 7)), 0, 160)];
                }
                continue;
            }
            if (preg_match('/(?:^|&)(?:pass|passwd|password|pwd|pass1)=([^&\s]{1,64})/i', $t, $pm)) {
                $user = '';
                if (preg_match('/(?:^|&)(?:user|username|login|email|usr|log)=([^&\s]{1,64})/i', $t, $um)) {
                    $user = $um[1];
                }
                $creds[] = ['client' => $curSrc, 'host' => $curHost, 'type' => 'Form POST', 'detail' => ($user !== '' ? $user . ' : ' : '') . $pm[1]];
                continue;
            }
            if (preg_match('/^(USER|PASS)\s+(\S+)/', $t, $fm)) {
                $creds[] = ['client' => $curSrc, 'host' => $curDst, 'type' => 'FTP/Mail', 'detail' => $fm[1] . ' ' . substr($fm[2], 0, 60)];
                continue;
            }
        }

        $dnsList = [];
        foreach ($dns as $k => $count) {
            $parts = explode('|', $k, 2);
            $dnsList[] = ['client' => $parts[0], 'domain' => $parts[1] ?? '', 'count' => $count];
        }
        usort($dnsList, function ($a, $b) {
            return $b['count'] - $a['count'];
        });
        $dnsList = array_slice($dnsList, 0, 200);

        $seen = [];
        $httpList = [];
        foreach ($http as $e) {
            $sig = $e['client'] . '|' . $e['host'] . '|' . $e['method'] . '|' . $e['url'];
            if (isset($seen[$sig])) {
                continue;
            }
            $seen[$sig] = true;
            $httpList[] = $e;
            if (count($httpList) >= 200) {
                break;
            }
        }

        $seenC = [];
        $credList = [];
        foreach ($creds as $e) {
            $sig = $e['type'] . '|' . $e['detail'];
            if (isset($seenC[$sig])) {
                continue;
            }
            $seenC[$sig] = true;
            $credList[] = $e;
            if (count($credList) >= 100) {
                break;
            }
        }

        $cookieList = array_slice(array_values($cookies), 0, 100);

        return [
            'dns' => $dnsList,
            'http' => $httpList,
            'creds' => $credList,
            'cookies' => $cookieList,
            'counts' => [
                'dns' => count($dnsList),
                'http' => count($httpList),
                'creds' => count($credList),
                'cookies' => count($cookieList),
            ],
            'pcapBytes' => $pcapBytes,
            'clients' => array_keys($clients),
        ];
    }

    public static function parseWpsAttackResult($output)
    {
        $output = (string)$output;
        $pin = '';
        $psk = '';
        $ssid = '';
        if (preg_match("/WPS PIN:\s*'?([0-9]{4,8})'?/i", $output, $m)) {
            $pin = $m[1];
        }
        if ($pin === '' && preg_match("/WPS pin:\s*([0-9]{4,8})/i", $output, $m)) {
            $pin = $m[1];
        }
        if (preg_match("/WPA PSK:\s*'([^']*)'/i", $output, $m)) {
            $psk = $m[1];
        }
        if (preg_match("/AP SSID:\s*'([^']*)'/i", $output, $m)) {
            $ssid = $m[1];
        }
        $locked = (bool)preg_match('/WPS (?:transaction|lock)|AP (?:rate limiting|locked)|WARNING.*lock/i', $output);
        return [
            'success' => ($pin !== '' || $psk !== ''),
            'pin' => $pin,
            'psk' => $psk,
            'ssid' => $ssid,
            'locked' => $locked,
        ];
    }

    public static function wpsStopReason($log, $err, $result)
    {
        $t = (string)$log . "\n" . (string)$err;
        if (!empty($result['pin']) || !empty($result['psk'])) {
            return ['level' => 'success', 'text' => 'Recovered the WPS credentials.'];
        }
        if (preg_match('/stop requested/i', $t)) {
            return ['level' => 'warn', 'text' => 'Stopped by you.'];
        }
        if (preg_match('/failed to create monitor/i', $t)) {
            return ['level' => 'danger', 'text' => 'Could not put the radio into monitor mode. Free the radio (Lab mode) and retry.'];
        }
        if (preg_match('/Detected AP rate limiting|WPS.*lock|AP (?:locked|rate limiting)/i', $t)) {
            return ['level' => 'danger', 'text' => 'The AP is rate-limiting / locking WPS. It throttles guesses so the attack cannot proceed — most routers lock WPS after a few failed attempts. Wait for the lock to clear, or this AP has WPS lockout protection.'];
        }
        if (preg_match('/WPS pin not found|pixiewps.*fail/i', $t)) {
            return ['level' => 'danger', 'text' => 'Pixie-Dust did not recover the PIN — this AP is not vulnerable to the offline pixie-dust attack. Patched APs are immune. You can try PIN mode (online, slow), but it may be rate-limited.'];
        }
        if (preg_match('/Failed to associate/i', $t) && !preg_match('/Associated with/i', $t)) {
            return ['level' => 'danger', 'text' => 'Could not associate with the AP — out of range, wrong channel, or the AP is not responding. Re-scan to refresh the channel and check signal.'];
        }
        if (preg_match('/receive timeout occurred/i', $t)) {
            return ['level' => 'warn', 'text' => 'Timed out waiting for the AP to respond. It may be far away or busy — try again closer, or raise the timeout.'];
        }
        return ['level' => 'warn', 'text' => 'The attack ended without recovering the PIN (timed out or the AP stopped responding). Try a longer timeout, or PIN mode.'];
    }

    public static function captureStopReason($log, $err, $result)
    {
        $t = (string)$log . "\n" . (string)$err;
        if (!empty($result['handshakeCaptured'])) {
            $n = (int)($result['hashCount'] ?? 0);
            return ['level' => 'success', 'text' => 'Captured ' . $n . ' hash' . ($n === 1 ? '' : 'es') . ' — ready to download / crack.'];
        }
        if (preg_match('/stop requested/i', $t)) {
            return ['level' => 'warn', 'text' => 'Stopped by you.'];
        }
        if (preg_match('/failed to create monitor/i', $t)) {
            return ['level' => 'danger', 'text' => 'Could not put the radio into monitor mode. Free the radio (Lab mode) and retry.'];
        }
        if (preg_match('/no capture file was produced/i', $t)) {
            return ['level' => 'danger', 'text' => 'airodump-ng produced no capture — the monitor may have been on the wrong channel. Re-scan the target to refresh its channel and retry.'];
        }
        return ['level' => 'warn', 'text' => 'No handshake captured — no client re-authenticated during the window. Make sure a device is connected to the target, enable deauth, target a specific client MAC, or use a longer duration.'];
    }

    public static function stepEntry($key, $label, $status, $detail)
    {
        // status: pending | active | done | failed | warn | skipped
        return ['key' => $key, 'label' => $label, 'status' => $status, 'detail' => $detail];
    }

    public static function firstVerifiedPassword($credentials)
    {
        foreach ($credentials as $cred) {
            if (!empty($cred['verified'])) {
                return $cred['password'];
            }
        }
        return '';
    }
}
