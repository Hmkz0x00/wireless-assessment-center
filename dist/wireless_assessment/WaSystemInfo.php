<?php
namespace frieren\modules\wireless_assessment;

/**
 * System / hardware / wireless-interface introspection and static config data.
 *
 * Extracted from Wireless_assessmentController to keep the controller lean and to
 * avoid parsing this code on request paths that don't need it. All methods are pure
 * static helpers (no controller/base-class state). Autoloaded by Frieren's PSR-4
 * fallback (class name == file name) — no registration required.
 */
class WaSystemInfo
{
    public static function readOpenWrtRelease()
    {
        $release = [];
        $lines = @file('/etc/openwrt_release', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return $release;
        }
        foreach ($lines as $line) {
            if (strpos($line, '=') === false) {
                continue;
            }
            [$key, $value] = explode('=', $line, 2);
            $release[$key] = trim($value, "'");
        }
        return $release;
    }

    public static function getStorageInfo()
    {
        $rows = [];
        $output = shell_exec('/bin/df -h 2>/dev/null');
        foreach (explode("\n", trim((string)$output)) as $index => $line) {
            if ($index === 0 || trim($line) === '') {
                continue;
            }
            $parts = preg_split('/\s+/', trim($line));
            if (count($parts) >= 6) {
                $rows[] = [
                    'filesystem' => $parts[0],
                    'size' => $parts[1],
                    'used' => $parts[2],
                    'available' => $parts[3],
                    'usePercent' => $parts[4],
                    'mountedOn' => $parts[5],
                ];
            }
        }
        return $rows;
    }

    public static function getPackageStatus()
    {
        $wanted = ['aircrack-ng', 'hcxtools', 'reaver', 'tcpdump', 'tcpdump-mini', 'sqlite3-cli', 'git', 'php8-cli'];
        $installedRaw = (string)shell_exec('/bin/opkg list-installed 2>/dev/null');
        $packages = [];
        foreach ($wanted as $pkg) {
            $packages[] = [
                'name' => $pkg,
                'installed' => strpos($installedRaw, $pkg . ' -') !== false,
                'available' => true,
            ];
        }
        return $packages;
    }

    public static function getWirelessInterfaces()
    {
        $interfaces = [];
        $output = (string)shell_exec('/usr/sbin/iw dev 2>/dev/null');
        $currentPhy = '';
        $current = null;
        foreach (explode("\n", $output) as $line) {
            if (preg_match('/^phy#(\d+)/', trim($line), $match)) {
                $currentPhy = 'phy' . $match[1];
                continue;
            }
            if (preg_match('/^\s*Interface\s+(\S+)/', $line, $match)) {
                if ($current !== null) {
                    $interfaces[] = $current;
                }
                $current = [
                    'name' => $match[1],
                    'phy' => $currentPhy,
                    'type' => '',
                    'ssid' => '',
                    'channel' => '',
                    'frequency' => '',
                    'txpower' => '',
                ];
                continue;
            }
            if ($current === null) {
                continue;
            }
            if (preg_match('/^\s*ssid\s+(.+)$/', $line, $match)) {
                $current['ssid'] = trim($match[1]);
            } elseif (preg_match('/^\s*type\s+(.+)$/', $line, $match)) {
                $current['type'] = trim($match[1]);
            } elseif (preg_match('/^\s*channel\s+(\d+)\s+\(([^)]+)\)/', $line, $match)) {
                $current['channel'] = $match[1];
                $current['frequency'] = $match[2];
            } elseif (preg_match('/^\s*txpower\s+(.+)$/', $line, $match)) {
                $current['txpower'] = trim($match[1]);
            }
        }
        if ($current !== null) {
            $interfaces[] = $current;
        }
        return $interfaces;
    }

    public static function detectBands($chunk)
    {
        $bands = [];
        if (strpos($chunk, '2412.0 MHz') !== false) {
            $bands[] = '2.4 GHz';
        }
        if (strpos($chunk, '5180.0 MHz') !== false || strpos($chunk, '5745.0 MHz') !== false) {
            $bands[] = '5 GHz';
        }
        return $bands;
    }

    public static function detectModes($chunk)
    {
        $modes = [];
        foreach (['managed', 'AP', 'monitor', 'mesh point'] as $mode) {
            if (preg_match('/\*\s+' . preg_quote($mode, '/') . '\b/', $chunk)) {
                $modes[] = $mode;
            }
        }
        return $modes;
    }

    public static function extractPhyChunk($text, $phy)
    {
        if (!preg_match('/Wiphy\s+' . preg_quote($phy, '/') . '\b(.*?)(?=\nWiphy\s+phy|\z)/s', $text, $match)) {
            return '';
        }
        return $match[1];
    }

    public static function nmapProfileArgs($profile)
    {
        switch ($profile) {
            case 'ports':
                return '-n -Pn --top-ports 100 -T4 --max-retries 1 --host-timeout 60s';
            case 'services':
                return '-n -Pn --top-ports 50 -sV --version-light -T4 --max-retries 1 --host-timeout 90s';
            case 'discovery':
            default:
                return '-sn -n -T4';
        }
    }

    public static function uciRadioMap()
    {
        $radios = [];
        $output = (string)shell_exec('/sbin/uci show wireless 2>/dev/null');
        foreach (explode("\n", $output) as $line) {
            if (preg_match("/^wireless\.(radio\d+)\.(band|path|disabled)='?([^']*)'?/", trim($line), $m)) {
                $radios[$m[1]][$m[2]] = $m[3];
            }
        }
        return $radios;
    }

    public static function defaultReconDatabase()
    {
        return [
            'updatedAt' => '',
            'scans' => [],
            'targets' => [],
            'clients' => [],
        ];
    }

    public static function inventoryOutputHosts($hostsAssoc)
    {
        $out = [];
        foreach ($hostsAssoc as $host) {
            if (!is_array($host)) {
                continue;
            }
            $host['ports'] = is_array($host['ports'] ?? null) ? array_values($host['ports']) : [];
            $out[] = $host;
        }
        usort($out, function ($a, $b) {
            return strcmp($a['ip'] ?? '', $b['ip'] ?? '');
        });
        return $out;
    }
}
