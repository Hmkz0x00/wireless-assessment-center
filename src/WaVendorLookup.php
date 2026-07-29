<?php
namespace frieren\modules\wireless_assessment;

/**
 * OUI -> vendor name lookup and enrichment of host/AP lists.
 *
 * Extracted from Wireless_assessmentController to keep the controller lean and to
 * avoid parsing this code on request paths that don't need it. All methods are pure
 * static helpers (no controller/base-class state). Autoloaded by Frieren's PSR-4
 * fallback (class name == file name) — no registration required.
 */
class WaVendorLookup
{
    public static function ouiVendorMap(array $macs)
    {
        $wanted = [];
        foreach ($macs as $mac) {
            $oui = WaValidators::macOui($mac);
            if (strlen($oui) === 6) {
                $wanted[$oui] = '';
            }
        }
        if (empty($wanted)) {
            return [];
        }
        $file = '/usr/share/nmap/nmap-mac-prefixes';
        $fh = @fopen($file, 'r');
        if (!$fh) {
            return $wanted;
        }
        $remaining = count($wanted);
        while ($remaining > 0 && ($line = fgets($fh)) !== false) {
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $prefix = strtoupper(substr($line, 0, 6));
            if (isset($wanted[$prefix]) && $wanted[$prefix] === '') {
                $wanted[$prefix] = trim(substr($line, 7));
                $remaining--;
            }
        }
        fclose($fh);
        return $wanted;
    }

    public static function attachVendors($rows, $macKey = 'bssid')
    {
        if (!is_array($rows) || empty($rows)) {
            return $rows;
        }
        $macs = [];
        foreach ($rows as $row) {
            if (is_array($row) && isset($row[$macKey])) {
                $macs[] = $row[$macKey];
            }
        }
        $map = self::ouiVendorMap($macs);
        foreach ($rows as &$row) {
            if (is_array($row) && isset($row[$macKey])) {
                $row['vendor'] = $map[WaValidators::macOui($row[$macKey])] ?? '';
            }
        }
        unset($row);
        return $rows;
    }

    public static function attachVendorsFallback($hosts)
    {
        if (empty($hosts)) {
            return $hosts;
        }
        $macs = [];
        foreach ($hosts as $h) {
            if (!empty($h['mac']) && empty($h['vendor'])) {
                $macs[] = $h['mac'];
            }
        }
        if (empty($macs)) {
            return $hosts;
        }
        $map = self::ouiVendorMap($macs);
        foreach ($hosts as &$h) {
            if (!empty($h['mac']) && empty($h['vendor'])) {
                $h['vendor'] = $map[WaValidators::macOui($h['mac'])] ?? '';
            }
        }
        unset($h);
        return $hosts;
    }
}
