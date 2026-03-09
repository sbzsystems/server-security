<?php
/**
 * SBZ - Simple Baseline Integrity Checker for OpenCart
 * 
 * A CLI-based file integrity monitoring tool that detects unauthorized file modifications
 * in OpenCart installations. Creates and maintains SHA-256 hash baselines of all monitored
 * files (PHP, Twig, JS, CSS), then compares against them during scheduled integrity checks.
 * 
 * FEATURES:
 * - Automatic OpenCart root detection via config.php
 * - Excludes cache, logs, and .git directories to reduce false positives
 * - Stores baseline snapshots in JSON format with timestamps
 * - Detects added, deleted, and modified files
 * - Email alerts with detailed change reports on integrity violations
 * 
 * USAGE STEPS:
 * 
 * 1. INITIAL SETUP (Run once):
 *    cd /home/username/domains/domain.com
 *    php integrity.php init
 *    
 *    This creates an integrity-baseline.json file with hashes of all files.
 * 
 * 2. SCHEDULE MONITORING (Setup via cron):
 *    Add to crontab to run daily checks:
 *    
 *    0 2 * * * /usr/bin/php /home/username/domains/domain.com/integrity.php check >> /home/username/domains/domain.com/integrity.log 2>&1
 *    
 *    This runs the integrity check every day at 2 AM and logs results.
 * 
 * 3. REVIEW ALERTS:
 *    - Check integrity.log for modification reports
 *    - Review email alerts (sent to store email from config_email setting)
 *    - Investigate any unexpected file changes immediately
 * 
 * 4. UPDATE BASELINE (After legitimate changes):
 *    If legitimate updates are made to files, regenerate baseline:
 *    
 *    php integrity.php init
 * 
 * @version 1.0
 * @license MIT
 */

declare(strict_types=1);

const BASELINE_FILE = __DIR__ . '/integrity-baseline.json';

function requireCli(): void
{
    if (PHP_SAPI !== 'cli') {
        http_response_code(403);
        exit("CLI only\n");
    }
}

function rootPath(): string
{
    $candidates = [
        __DIR__,
        dirname(__DIR__),
        __DIR__ . DIRECTORY_SEPARATOR . 'public_html',
        dirname(__DIR__) . DIRECTORY_SEPARATOR . 'public_html',
    ];

    foreach ($candidates as $dir) {
        $real = realpath($dir);
        if ($real !== false && is_file($real . DIRECTORY_SEPARATOR . 'config.php')) {
            return rtrim($real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        }
    }

    throw new RuntimeException("Cannot locate OpenCart root with config.php");
}

function loadOcConfig(string $root): array
{
    $configFile = $root . 'config.php';
    if (!is_file($configFile)) {
        throw new RuntimeException("Missing config.php at: {$configFile}");
    }

    $content = file_get_contents($configFile);
    if ($content === false) {
        throw new RuntimeException("Cannot read config.php");
    }

    $keys = [
        'DB_DRIVER',
        'DB_HOSTNAME',
        'DB_USERNAME',
        'DB_PASSWORD',
        'DB_DATABASE',
        'DB_PORT',
        'DB_PREFIX',
    ];

    $out = [];
    foreach ($keys as $k) {
        if (!preg_match("/define\\(\\s*'{$k}'\\s*,\\s*'([^']*)'\\s*\\)\\s*;/", $content, $m)) {
            throw new RuntimeException("Cannot parse {$k} from config.php");
        }
        $out[$k] = $m[1];
    }

    return $out;
}

function pdoFromOc(array $cfg): PDO
{
    $driver = strtolower($cfg['DB_DRIVER']);
    if ($driver !== 'mysqli' && $driver !== 'pdo') {
        // OpenCart uses 'mysqli' in config but we connect via PDO mysql.
    }

    $host = $cfg['DB_HOSTNAME'];
    $db   = $cfg['DB_DATABASE'];
    $port = (int)($cfg['DB_PORT'] !== '' ? $cfg['DB_PORT'] : 3306);

    $dsn = "mysql:host={$host};port={$port};dbname={$db};charset=utf8mb4";

    $pdo = new PDO($dsn, $cfg['DB_USERNAME'], $cfg['DB_PASSWORD'], [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);

    return $pdo;
}

function fetchStoreEmail(PDO $pdo, string $prefix): string
{
    $sql = "SELECT `value` FROM `{$prefix}setting` WHERE `key` = 'config_email' ORDER BY `setting_id` DESC LIMIT 1";
    $stmt = $pdo->query($sql);
    $row = $stmt->fetch();
    $email = is_array($row) && isset($row['value']) ? (string)$row['value'] : '';
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new RuntimeException("Cannot determine store email (config_email).");
    }
    return $email;
}

function shouldScanFile(string $path): bool
{
    $lower = strtolower($path);
    if (str_contains($lower, DIRECTORY_SEPARATOR . '.git' . DIRECTORY_SEPARATOR)) return false;
    if (str_contains($lower, DIRECTORY_SEPARATOR . 'system' . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR)) return false;
    if (str_contains($lower, DIRECTORY_SEPARATOR . 'system' . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR)) return false;
    if (str_contains($lower, DIRECTORY_SEPARATOR . 'image' . DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR)) return false;

    return preg_match('/\.(php|twig|js|css)$/i', $path) === 1;
}

function listFiles(string $root): array
{
    $rii = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
    );

    $files = [];
    foreach ($rii as $file) {
        /** @var SplFileInfo $file */
        if (!$file->isFile()) continue;

        $path = $file->getPathname();
        if (!shouldScanFile($path)) continue;

        $rel = str_replace($root, '', $path);
        $files[] = $rel;
    }

    sort($files);
    return $files;
}

function hashFileSafe(string $abs): string
{
    $h = hash_file('sha256', $abs);
    if ($h === false) {
        throw new RuntimeException("Cannot hash: {$abs}");
    }
    return $h;
}

function buildBaseline(string $root): array
{
    $baseline = [
        'generated_at' => gmdate('c'),
        'root' => $root,
        'files' => [],
    ];

    foreach (listFiles($root) as $rel) {
        $abs = $root . $rel;
        $baseline['files'][$rel] = hashFileSafe($abs);
    }

    ksort($baseline['files']);
    return $baseline;
}

function loadBaseline(): array
{
    if (!is_file(BASELINE_FILE)) {
        throw new RuntimeException("Missing baseline file: " . BASELINE_FILE . " (run: php bin/integrity.php init)");
    }
    $json = file_get_contents(BASELINE_FILE);
    if ($json === false) {
        throw new RuntimeException("Cannot read baseline file.");
    }
    $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($data) || !isset($data['files']) || !is_array($data['files'])) {
        throw new RuntimeException("Invalid baseline format.");
    }
    return $data;
}

function saveBaseline(array $baseline): void
{
    $json = json_encode($baseline, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException("Cannot encode baseline JSON.");
    }
    if (file_put_contents(BASELINE_FILE, $json, LOCK_EX) === false) {
        throw new RuntimeException("Cannot write baseline file: " . BASELINE_FILE);
    }
}

function diffAgainstBaseline(string $root, array $baseline): array
{
    $currentFiles = [];
    foreach (listFiles($root) as $rel) {
        $currentFiles[$rel] = hashFileSafe($root . $rel);
    }

    $baseFiles = $baseline['files'];

    $added   = array_diff_key($currentFiles, $baseFiles);
    $deleted = array_diff_key($baseFiles, $currentFiles);

    $changed = [];
    foreach ($currentFiles as $rel => $hash) {
        if (isset($baseFiles[$rel]) && $baseFiles[$rel] !== $hash) {
            $changed[$rel] = ['baseline' => $baseFiles[$rel], 'current' => $hash];
        }
    }

    ksort($added);
    ksort($deleted);
    ksort($changed);

    return ['added' => $added, 'deleted' => $deleted, 'changed' => $changed];
}

function sendAlertEmail(string $to, string $subject, string $body): void
{
    $headers = [
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
    ];
    @mail($to, $subject, $body, implode("\r\n", $headers));
}

requireCli();

$cmd = $argv[1] ?? '';
$root = rootPath();

try {
    if ($cmd === 'init') {
        $baseline = buildBaseline($root);
        saveBaseline($baseline);
        echo "Baseline created: " . BASELINE_FILE . "\n";
        exit(0);
    }

    if ($cmd === 'check') {
        $baseline = loadBaseline();
        $diff = diffAgainstBaseline($root, $baseline);

        $hasChanges = !empty($diff['added']) || !empty($diff['deleted']) || !empty($diff['changed']);
        if (!$hasChanges) {
            echo "OK: no changes.\n";
            exit(0);
        }

        $lines = [];
        $lines[] = "OpenCart integrity alert: file changes detected";
        $lines[] = "Time (UTC): " . gmdate('c');
        $lines[] = "Root: " . $root;
        $lines[] = "";

        if (!empty($diff['added'])) {
            $lines[] = "ADDED:";
            foreach (array_keys($diff['added']) as $rel) {
                $lines[] = " + " . $rel;
            }
            $lines[] = "";
        }

        if (!empty($diff['deleted'])) {
            $lines[] = "DELETED:";
            foreach (array_keys($diff['deleted']) as $rel) {
                $lines[] = " - " . $rel;
            }
            $lines[] = "";
        }

        if (!empty($diff['changed'])) {
            $lines[] = "CHANGED:";
            foreach ($diff['changed'] as $rel => $info) {
                $lines[] = " * " . $rel;
            }
            $lines[] = "";
        }

        $body = implode("\n", $lines);
        echo $body . "\n";

        try {
            $cfg = loadOcConfig($root);
            $pdo = pdoFromOc($cfg);
            $email = fetchStoreEmail($pdo, $cfg['DB_PREFIX']);

            $subject = "[OpenCart] Integrity alert (" . parse_url($cfg['DB_HOSTNAME'], PHP_URL_HOST) . ")";
            sendAlertEmail($email, $subject, $body);
        } catch (Throwable $mailErr) {
            fwrite(STDERR, "Warning: alert email not sent: " . $mailErr->getMessage() . "\n");
        }

        exit(2);
    }

    echo "Usage:\n";
    echo "  php bin/integrity.php init\n";
    echo "  php bin/integrity.php check\n";
    exit(1);
} catch (Throwable $e) {
    fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
    exit(3);
}

