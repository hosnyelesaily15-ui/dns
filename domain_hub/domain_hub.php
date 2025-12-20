<?php
if (!defined("WHMCS")) die("This file cannot be accessed directly");

use WHMCS\Database\Capsule;

require_once __DIR__ . '/lib/autoload.php';
require_once __DIR__ . '/lib/Support/ModuleSettings.php';
CfModuleSettings::bootstrap();
require_once __DIR__ . '/lib/CloudflareAPI.php';
require_once __DIR__ . '/lib/ExternalRiskAPI.php';
require_once __DIR__ . '/lib/ErrorFormatter.php';
require_once __DIR__ . '/lib/TtlHelper.php';
require_once __DIR__ . '/lib/SecurityHelpers.php';
require_once __DIR__ . '/lib/CollectionHelper.php';
require_once __DIR__ . '/lib/ProviderResolver.php';


require_once __DIR__ . '/lib/PrivilegedHelpers.php';
require_once __DIR__ . '/lib/RootDomainLimitHelper.php';

function cf_ensure_module_settings_migrated() {
    CfModuleSettings::ensureMigrated();
}
function cf_is_module_request(string $param = 'm'): bool {
    $targets = [CF_MODULE_NAME, CF_MODULE_NAME_LEGACY];

    $value = $_REQUEST[$param] ?? null;
    if ($value !== null && in_array($value, $targets, true)) {
        return true;
    }

    if ($param === 'm') {
        if (isset($_REQUEST['module']) && in_array($_REQUEST['module'], $targets, true)) {
            if (!isset($_REQUEST['action']) || $_REQUEST['action'] === 'addon') {
                return true;
            }
        }

        $rp = $_REQUEST['rp'] ?? '';
        if (is_string($rp) && $rp !== '') {
            $rpTrim = trim($rp, '/');
            if ($rpTrim !== '') {
                $parts = explode('/', $rpTrim);
                if (isset($parts[0], $parts[1]) && strtolower($parts[0]) === 'addon' && in_array($parts[1], $targets, true)) {
                    return true;
                }
            }
        }
    }

    return false;
}

function cf_is_legacy_module_entry(): bool {
    $value = $_REQUEST['m'] ?? '';
    return $value === CF_MODULE_NAME || $value === CF_MODULE_NAME_LEGACY;
}

function cf_is_api_request(): bool {
    return CfApiRouter::isApiRequest();
}

function cf_dispatch_api_request(): void {
    CfApiRouter::dispatch();
}

function cf_get_module_settings_cached() {
    return CfSettingsRepository::instance()->getAll();
}

/**
 * 🚀 性能优化：清除配置缓存
 * 在更新配置后调用
 */
function cf_clear_settings_cache() {
    CfSettingsRepository::instance()->refresh();


}


function cfmod_mask_secret_preview(?string $plain): string {
    if ($plain === null || $plain === '') {
        return '未配置';
    }
    $length = strlen($plain);
    if ($length <= 4) {
        $repeat = max(4, $length);
        return str_repeat('•', $repeat);
    }
    $maskedLength = max(0, $length - 4);
    return substr($plain, 0, 2) . str_repeat('•', $maskedLength) . substr($plain, -2);
}

function cfmod_preview_provider_secret(?string $encrypted): string {
    if ($encrypted === null || $encrypted === '') {
        return '未配置';
    }
    $plain = cfmod_decrypt_sensitive($encrypted);
    if ($plain === '') {
        return '未配置';
    }
    return cfmod_mask_secret_preview($plain);
}


function cfmod_admin_current_url_without_action(): string {
    $requestUri = $_SERVER['REQUEST_URI'] ?? '';
    $redirectUrl = preg_replace('/[?&]action=[^&]*/', '', $requestUri);
    if ($redirectUrl === null || $redirectUrl === '') {
        $redirectUrl = $requestUri;
    }
    return rtrim($redirectUrl, '?&');
}

if (!function_exists('cfmod_setting_enabled')) {
    function cfmod_setting_enabled($value): bool {
        if (is_bool($value)) {
            return $value;
        }
        $normalized = strtolower(trim((string)$value));
        if ($normalized === '') {
            return false;
        }
        return in_array($normalized, ['1', 'on', 'yes', 'true', 'enabled'], true);
    }
}

if (!function_exists('cfmod_is_domain_gift_enabled')) {
    function cfmod_is_domain_gift_enabled(array $settings = null): bool {
        if ($settings === null && function_exists('cf_get_module_settings_cached')) {
            $settings = cf_get_module_settings_cached();
        }
        if ($settings === null) {
            $settings = [];
        }
        return cfmod_setting_enabled($settings['enable_domain_gift'] ?? '0');
    }
}

if (!function_exists('cfmod_get_domain_gift_ttl_hours')) {
    function cfmod_get_domain_gift_ttl_hours(array $settings = null): int {
        if ($settings === null && function_exists('cf_get_module_settings_cached')) {
            $settings = cf_get_module_settings_cached();
        }
        $ttl = (int)($settings['domain_gift_code_ttl_hours'] ?? 72);
        if ($ttl <= 0) {
            $ttl = 72;
        }
        return min($ttl, 24 * 14); // 上限 14 天，避免长时间锁定
    }
}

if (!function_exists('cfmod_generate_domain_gift_code')) {
    function cfmod_generate_domain_gift_code(int $length = 18): string {
        $characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $maxIndex = strlen($characters) - 1;
        $code = '';
        for ($i = 0; $i < $length; $i++) {
            $code .= $characters[random_int(0, $maxIndex)];
        }
        return $code;
    }
}

if (!function_exists('cfmod_generate_quota_redeem_code')) {
    function cfmod_generate_quota_redeem_code(int $length = 12): string {
        $characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $maxIndex = strlen($characters) - 1;
        $code = '';
        for ($i = 0; $i < $length; $i++) {
            $code .= $characters[random_int(0, $maxIndex)];
        }
        return $code;
    }
}

if (!function_exists('cfmod_mask_invite_code')) {
    function cfmod_mask_invite_code(string $code): string {
        $code = trim($code);
        if ($code === '') {
            return '***';
        }
        $len = strlen($code);
        $maskLen = 5;
        if ($len <= $maskLen) {
            return str_repeat('*', min($maskLen, $len));
        }
        $maxPrefix = min(3, max(0, $len - $maskLen - 1));
        $prefixLen = $maxPrefix;
        $suffixLen = $len - $prefixLen - $maskLen;
        if ($suffixLen < 1) {
            $suffixLen = 1;
            $prefixLen = max(0, $len - $suffixLen - $maskLen);
        }
        $prefix = $prefixLen > 0 ? substr($code, 0, $prefixLen) : '';
        $suffix = $suffixLen > 0 ? substr($code, -$suffixLen) : '';
        return $prefix . str_repeat('*', $maskLen) . $suffix;
    }
}

/**
 * 根据全局基础配额自动提升用户最大配额（仅向上调整）
 */


/**
 * 根据全局邀请加成上限自动提升用户加成上限（仅向上调整）
 */


/**
 * 🚀 性能优化：自动添加所有性能优化索引
 * 在激活插件时自动执行，提升查询性能10-100倍
 */
function cf_add_performance_indexes() {
    try {
        $indexesAdded = 0;
        
        // 1. mod_cloudflare_subdomain 表优化
        if (Capsule::schema()->hasTable('mod_cloudflare_subdomain')) {
            // 复合索引：userid + status（加速用户域名列表查询）
            if (!cf_index_exists('mod_cloudflare_subdomain', 'idx_userid_status')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_subdomain` ADD INDEX `idx_userid_status` (`userid`, `status`)');
                $indexesAdded++;
            }
            // 唯一索引：subdomain（防止重复，加速查询）
            if (!cf_index_exists('mod_cloudflare_subdomain', 'idx_subdomain_unique')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_subdomain` ADD UNIQUE INDEX `idx_subdomain_unique` (`subdomain`)');
                $indexesAdded++;
            }
            // 时间索引：created_at（加速时间范围查询）
            if (!cf_index_exists('mod_cloudflare_subdomain', 'idx_created_at')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_subdomain` ADD INDEX `idx_created_at` (`created_at`)');
                $indexesAdded++;
            }
            if (!cf_index_exists('mod_cloudflare_subdomain', 'idx_expiry_status')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_subdomain` ADD INDEX `idx_expiry_status` (`expires_at`, `status`)');
                $indexesAdded++;
            }
        }
        
        // 2. mod_cloudflare_dns_records 表优化（最重要！避免N+1查询）
        if (Capsule::schema()->hasTable('mod_cloudflare_dns_records')) {
            // 复合索引：subdomain_id + type（加速DNS记录查询）
            if (!cf_index_exists('mod_cloudflare_dns_records', 'idx_subdomain_type')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_dns_records` ADD INDEX `idx_subdomain_type` (`subdomain_id`, `type`)');
                $indexesAdded++;
            }
        }
        
        // 3. mod_cloudflare_invitation_claims 表优化（加速排行榜）
        if (Capsule::schema()->hasTable('mod_cloudflare_invitation_claims')) {
            // 时间索引：created_at（排行榜统计需要）
            if (!cf_index_exists('mod_cloudflare_invitation_claims', 'idx_created_at')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_invitation_claims` ADD INDEX `idx_created_at` (`created_at`)');
                $indexesAdded++;
            }
            // 复合索引：invitee_userid + code（防止重复使用）
            if (!cf_index_exists('mod_cloudflare_invitation_claims', 'idx_invitee_code')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_invitation_claims` ADD INDEX `idx_invitee_code` (`invitee_userid`, `code`)');
                $indexesAdded++;
            }
        }
        
        // 4. mod_cloudflare_api_keys 表优化
        if (Capsule::schema()->hasTable('mod_cloudflare_api_keys')) {
            // 唯一索引：api_key（加速API认证）
            if (!cf_index_exists('mod_cloudflare_api_keys', 'idx_api_key_unique')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_api_keys` ADD UNIQUE INDEX `idx_api_key_unique` (`api_key`)');
                $indexesAdded++;
            }
        }
        
        // 5. mod_cloudflare_api_logs 表优化
        if (Capsule::schema()->hasTable('mod_cloudflare_api_logs')) {
            // 时间索引：created_at（加速日志查询和清理）
            if (!cf_index_exists('mod_cloudflare_api_logs', 'idx_created_at')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_api_logs` ADD INDEX `idx_created_at` (`created_at`)');
                $indexesAdded++;
            }
            // 复合索引：api_key_id + created_at（加速API统计）
            if (!cf_index_exists('mod_cloudflare_api_logs', 'idx_api_key_created')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_api_logs` ADD INDEX `idx_api_key_created` (`api_key_id`, `created_at`)');
                $indexesAdded++;
            }
        }
        
        // 6. mod_cloudflare_domain_risk 表优化
        if (Capsule::schema()->hasTable('mod_cloudflare_domain_risk')) {
            // 唯一索引：subdomain_id（一对一关系）
            if (!cf_index_exists('mod_cloudflare_domain_risk', 'idx_subdomain_id_unique')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_domain_risk` ADD UNIQUE INDEX `idx_subdomain_id_unique` (`subdomain_id`)');
                $indexesAdded++;
            }
            // 风险等级索引：risk_level（加速风险筛选）
            if (!cf_index_exists('mod_cloudflare_domain_risk', 'idx_risk_level')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_domain_risk` ADD INDEX `idx_risk_level` (`risk_level`)');
                $indexesAdded++;
            }
        }
        
        return $indexesAdded;
    } catch (\Exception $e) {
        // 如果出错不影响激活，只记录
        return 0;
    }
}

/**
 * 检查索引是否存在
 */
function cf_index_exists($table, $indexName) {
    try {
        $result = Capsule::select("
            SELECT COUNT(*) as cnt
            FROM information_schema.statistics 
            WHERE table_schema = DATABASE() 
            AND table_name = ? 
            AND index_name = ?
        ", [$table, $indexName]);
        return $result[0]->cnt > 0;
    } catch (\Exception $e) {
        return false;
    }
}

function cfmod_convert_rows_to_array($rows): array {
    if ($rows instanceof \Illuminate\Support\Collection) {
        $rows = $rows->all();
    }
    if ($rows === null) {
        return [];
    }
    if (!is_array($rows)) {
        $rows = [$rows];
    }
    $result = [];
    foreach ($rows as $row) {
        if (is_object($row)) {
            $row = (array) $row;
        }
        if (is_array($row)) {
            $result[] = $row;
        }
    }
    return $result;
}

function cfmod_normalize_rootdomain(string $rootdomain): string {
    return strtolower(trim($rootdomain));
}

function cfmod_table_exists(string $table): bool {
    try {
        return Capsule::schema()->hasTable($table);
    } catch (\Throwable $e) {
        return false;
    }
}

function cfmod_get_known_rootdomains(?array $moduleSettings = null): array {
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $domains = [];
    try {
        if (cfmod_table_exists('mod_cloudflare_rootdomains')) {
            $rows = Capsule::table('mod_cloudflare_rootdomains')
                ->select('domain')
                ->orderBy('display_order', 'asc')
                ->orderBy('id', 'asc')
                ->get();
            foreach ($rows as $row) {
                $value = trim(strtolower($row->domain ?? ''));
                if ($value !== '') {
                    $domains[$value] = $value;
                }
            }
        }
    } catch (\Throwable $e) {
        // ignore
    }

    try {
        if (cfmod_table_exists('mod_cloudflare_subdomain')) {
            $rows = Capsule::table('mod_cloudflare_subdomain')->select('rootdomain')->distinct()->get();
            foreach ($rows as $row) {
                $value = trim(strtolower($row->rootdomain ?? ''));
                if ($value !== '') {
                    $domains[$value] = $value;
                }
            }
        }
    } catch (\Throwable $e) {
        // ignore
    }


    $cache = array_values($domains);
    return $cache;
}

function cfmod_next_rootdomain_display_order(): int {
    static $nextOrder = null;
    if ($nextOrder === null) {
        $nextOrder = 0;
        try {
            if (cfmod_table_exists('mod_cloudflare_rootdomains')) {
                $max = Capsule::table('mod_cloudflare_rootdomains')->max('display_order');
                if (is_numeric($max)) {
                    $nextOrder = (int) $max;
                }
            }
        } catch (\Throwable $e) {
            $nextOrder = 0;
        }
    }
    $nextOrder++;
    return $nextOrder;
}

function cfmod_migrate_legacy_rootdomains(array &$settings): void {
    static $migrated = false;
    if ($migrated) {
        return;
    }
    $migrated = true;

    $legacyValue = isset($settings['root_domains']) ? trim((string) $settings['root_domains']) : '';
    if ($legacyValue === '') {
        return;
    }

    if (!cfmod_table_exists('mod_cloudflare_rootdomains')) {
        return;
    }

    $candidates = array_filter(array_map(function ($item) {
        return cfmod_normalize_rootdomain($item);
    }, explode(',', $legacyValue)));

    if (empty($candidates)) {
        $settings['root_domains'] = '';
        return;
    }

    $defaultProviderId = null;
    try {
        $defaultProviderId = cfmod_get_default_provider_account_id($settings);
    } catch (\Throwable $ignored) {
    }

    $now = date('Y-m-d H:i:s');
    foreach (array_unique($candidates) as $domain) {
        if ($domain === '') {
            continue;
        }
        try {
            $exists = Capsule::table('mod_cloudflare_rootdomains')
                ->whereRaw('LOWER(domain) = ?', [$domain])
                ->exists();
            if ($exists) {
                continue;
            }
            Capsule::table('mod_cloudflare_rootdomains')->insert([
                'domain' => $domain,
                'cloudflare_zone_id' => null,
                'status' => 'active',
                'display_order' => cfmod_next_rootdomain_display_order(),
                'description' => '导入自 legacy root_domains 配置',
                'max_subdomains' => 1000,
                'per_user_limit' => 0,
                'default_term_years' => 0,
                'provider_account_id' => $defaultProviderId,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
        } catch (\Throwable $ignored) {
        }
    }

    try {
        Capsule::table('tbladdonmodules')->updateOrInsert([
            'module' => CF_MODULE_NAME,
            'setting' => 'root_domains'
        ], ['value' => '']);
    } catch (\Throwable $ignored) {
    }

    $settings['root_domains'] = '';
    if (function_exists('cfmod_clear_rootdomain_limits_cache')) {
        cfmod_clear_rootdomain_limits_cache();
    }
}

function cfmod_collect_rootdomain_dataset(string $rootdomain): array {
    $normalized = cfmod_normalize_rootdomain($rootdomain);
    if ($normalized === '') {
        throw new \InvalidArgumentException('根域名不能为空');
    }
    if (!cfmod_table_exists('mod_cloudflare_subdomain')) {
        throw new \RuntimeException('子域名数据表不存在，无法导出');
    }

    try {
        $subdomains = Capsule::table('mod_cloudflare_subdomain')
            ->whereRaw('LOWER(rootdomain) = ?', [$normalized])
            ->orderBy('id', 'asc')
            ->get();
    } catch (\Throwable $e) {
        throw new \RuntimeException('读取子域名数据失败：' . $e->getMessage(), 0, $e);
    }

    $subdomainArray = cfmod_convert_rows_to_array($subdomains);
    if (empty($subdomainArray)) {
        throw new \RuntimeException('未找到该根域名的数据');
    }

    $subdomainIds = [];
    $userIds = [];
    foreach ($subdomainArray as $row) {
        $sid = isset($row['id']) ? (int) $row['id'] : 0;
        if ($sid > 0) {
            $subdomainIds[] = $sid;
        }
        $uid = isset($row['userid']) ? (int) $row['userid'] : 0;
        if ($uid > 0) {
            $userIds[$uid] = true;
        }
    }

    $dataset = [
        'schema_version' => 1,
        'generated_at' => date('c'),
        'rootdomain' => $normalized,
        'module' => CF_MODULE_NAME,
        'subdomains' => $subdomainArray,
        'dns_records' => [],
        'domain_risk' => [],
        'risk_events' => [],
        'sync_results' => [],
        'quotas' => [],
        'counts' => [],
    ];

    if (!empty($subdomainIds) && cfmod_table_exists('mod_cloudflare_dns_records')) {
        try {
            $dnsRecords = Capsule::table('mod_cloudflare_dns_records')
                ->whereIn('subdomain_id', $subdomainIds)
                ->orderBy('subdomain_id', 'asc')
                ->orderBy('id', 'asc')
                ->get();
            $dataset['dns_records'] = cfmod_convert_rows_to_array($dnsRecords);
        } catch (\Throwable $e) {
            throw new \RuntimeException('读取DNS记录失败：' . $e->getMessage(), 0, $e);
        }
    }

    if (!empty($subdomainIds) && cfmod_table_exists('mod_cloudflare_domain_risk')) {
        try {
            $domainRisk = Capsule::table('mod_cloudflare_domain_risk')
                ->whereIn('subdomain_id', $subdomainIds)
                ->orderBy('subdomain_id', 'asc')
                ->get();
            $dataset['domain_risk'] = cfmod_convert_rows_to_array($domainRisk);
        } catch (\Throwable $e) {
            throw new \RuntimeException('读取域名风险数据失败：' . $e->getMessage(), 0, $e);
        }
    }

    if (!empty($subdomainIds) && cfmod_table_exists('mod_cloudflare_risk_events')) {
        try {
            $riskEvents = Capsule::table('mod_cloudflare_risk_events')
                ->whereIn('subdomain_id', $subdomainIds)
                ->orderBy('subdomain_id', 'asc')
                ->orderBy('id', 'asc')
                ->get();
            $dataset['risk_events'] = cfmod_convert_rows_to_array($riskEvents);
        } catch (\Throwable $e) {
            throw new \RuntimeException('读取风险事件数据失败：' . $e->getMessage(), 0, $e);
        }
    }

    if (!empty($subdomainIds) && cfmod_table_exists('mod_cloudflare_sync_results')) {
        try {
            $syncResults = Capsule::table('mod_cloudflare_sync_results')
                ->whereIn('subdomain_id', $subdomainIds)
                ->orderBy('subdomain_id', 'asc')
                ->orderBy('id', 'asc')
                ->get();
            $dataset['sync_results'] = cfmod_convert_rows_to_array($syncResults);
        } catch (\Throwable $e) {
            throw new \RuntimeException('读取校准记录失败：' . $e->getMessage(), 0, $e);
        }
    }

    if (!empty($userIds) && cfmod_table_exists('mod_cloudflare_subdomain_quotas')) {
        try {
            $quotaRows = Capsule::table('mod_cloudflare_subdomain_quotas')
                ->whereIn('userid', array_keys($userIds))
                ->orderBy('userid', 'asc')
                ->get();
            $dataset['quotas'] = cfmod_convert_rows_to_array($quotaRows);
        } catch (\Throwable $e) {
            throw new \RuntimeException('读取用户配额失败：' . $e->getMessage(), 0, $e);
        }
    }

    $dataset['counts'] = [
        'subdomains' => count($dataset['subdomains']),
        'dns_records' => count($dataset['dns_records']),
        'domain_risk' => count($dataset['domain_risk']),
        'risk_events' => count($dataset['risk_events']),
        'sync_results' => count($dataset['sync_results']),
        'quotas' => count($dataset['quotas']),
    ];

    return $dataset;
}

function cfmod_stream_export_dataset(array $dataset, string $rootdomain): void {
    $safeDomain = preg_replace('/[^A-Za-z0-9_.-]+/', '_', $rootdomain);
    if ($safeDomain === '' || $safeDomain === null) {
        $safeDomain = 'rootdomain';
    }
    $filename = 'domain_hub_export_' . $safeDomain . '_' . date('Ymd_His') . '.json';
    $json = json_encode($dataset, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    if ($json === false) {
        throw new \RuntimeException('JSON 编码失败：' . json_last_error_msg());
    }
    if (function_exists('ob_get_level')) {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
    }
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Content-Length: ' . strlen($json));
    echo $json;
    exit;
}

function cfmod_import_rootdomain_dataset(array $dataset): array {
    if (!isset($dataset['rootdomain'])) {
        throw new \InvalidArgumentException('导入文件缺少 rootdomain 字段');
    }
    $normalized = cfmod_normalize_rootdomain((string) $dataset['rootdomain']);
    if ($normalized === '') {
        throw new \InvalidArgumentException('导入文件中的根域名无效');
    }
    if (!cfmod_table_exists('mod_cloudflare_subdomain')) {
        throw new \RuntimeException('子域名数据表不存在，无法导入');
    }

    $subdomainsData = isset($dataset['subdomains']) && is_array($dataset['subdomains']) ? $dataset['subdomains'] : [];
    if (empty($subdomainsData)) {
        throw new \RuntimeException('导入文件中没有子域名数据');
    }

    $providerAccountIdForRoot = cfmod_resolve_provider_account_id(null, $normalized);

    $dnsRecordsData = isset($dataset['dns_records']) && is_array($dataset['dns_records']) ? $dataset['dns_records'] : [];
    $domainRiskData = isset($dataset['domain_risk']) && is_array($dataset['domain_risk']) ? $dataset['domain_risk'] : [];
    $riskEventsData = isset($dataset['risk_events']) && is_array($dataset['risk_events']) ? $dataset['risk_events'] : [];
    $syncResultsData = isset($dataset['sync_results']) && is_array($dataset['sync_results']) ? $dataset['sync_results'] : [];
    $quotasData = isset($dataset['quotas']) && is_array($dataset['quotas']) ? $dataset['quotas'] : [];

    $summary = [
        'rootdomain' => $normalized,
        'deleted' => [
            'subdomains' => 0,
            'dns_records' => 0,
            'domain_risk' => 0,
            'risk_events' => 0,
            'sync_results' => 0,
        ],
        'subdomains_inserted' => 0,
        'dns_records_inserted' => 0,
        'domain_risk_inserted' => 0,
        'risk_events_inserted' => 0,
        'sync_results_inserted' => 0,
        'quota_created' => 0,
        'quota_updates' => 0,
        'warnings' => [],
    ];

    $warnings = [];

    Capsule::connection()->transaction(function () use (
        $normalized,
        $subdomainsData,
        $providerAccountIdForRoot,
        $dnsRecordsData,
        $domainRiskData,
        $riskEventsData,
        $syncResultsData,
        $quotasData,
        &$summary,
        &$warnings
    ) {
        $now = date('Y-m-d H:i:s');
        $idMapping = [];
        $nameMapping = [];
        $affectedUserIds = [];
        $jobsTableExists = cfmod_table_exists('mod_cloudflare_jobs');

        $existingSubRows = Capsule::table('mod_cloudflare_subdomain')
            ->whereRaw('LOWER(rootdomain) = ?', [$normalized])
            ->select('id', 'userid')
            ->get();
        $existingSubdomainIds = [];
        foreach ($existingSubRows as $row) {
            $sid = (int) ($row->id ?? 0);
            if ($sid > 0) {
                $existingSubdomainIds[] = $sid;
            }
            $uid = (int) ($row->userid ?? 0);
            if ($uid > 0) {
                $affectedUserIds[$uid] = true;
            }
        }

        if (!empty($existingSubdomainIds)) {
            if (cfmod_table_exists('mod_cloudflare_dns_records')) {
                $summary['deleted']['dns_records'] += Capsule::table('mod_cloudflare_dns_records')->whereIn('subdomain_id', $existingSubdomainIds)->delete();
            }
            if (cfmod_table_exists('mod_cloudflare_domain_risk')) {
                $summary['deleted']['domain_risk'] += Capsule::table('mod_cloudflare_domain_risk')->whereIn('subdomain_id', $existingSubdomainIds)->delete();
            }
            if (cfmod_table_exists('mod_cloudflare_risk_events')) {
                $summary['deleted']['risk_events'] += Capsule::table('mod_cloudflare_risk_events')->whereIn('subdomain_id', $existingSubdomainIds)->delete();
            }
            if (cfmod_table_exists('mod_cloudflare_sync_results')) {
                $summary['deleted']['sync_results'] += Capsule::table('mod_cloudflare_sync_results')->whereIn('subdomain_id', $existingSubdomainIds)->delete();
            }
            $summary['deleted']['subdomains'] += Capsule::table('mod_cloudflare_subdomain')->whereIn('id', $existingSubdomainIds)->delete();
        }

        $allowedSubdomainColumns = [
            'userid','subdomain','rootdomain','cloudflare_zone_id','dns_record_id','status','expires_at','renewed_at','auto_deleted_at','never_expires','provider_account_id','notes','created_at','updated_at'
        ];

        foreach ($subdomainsData as $row) {
            if (!is_array($row)) {
                continue;
            }
            $subdomainName = trim((string) ($row['subdomain'] ?? ''));
            if ($subdomainName === '') {
                $warnings[] = '跳过空子域名条目';
                continue;
            }
            $subLower = strtolower($subdomainName);
            if (isset($nameMapping[$subLower])) {
                $warnings[] = '检测到重复子域名：' . $subdomainName;
                continue;
            }
            $data = [];
            foreach ($allowedSubdomainColumns as $column) {
                if ($column === 'rootdomain') {
                    continue;
                }
                if (array_key_exists($column, $row)) {
                    $data[$column] = $row[$column];
                }
            }
            $providerAccountForRow = isset($data['provider_account_id']) ? (int) $data['provider_account_id'] : 0;
            if ($providerAccountForRow > 0) {
                $data['provider_account_id'] = $providerAccountForRow;
            } elseif ($providerAccountIdForRoot) {
                $data['provider_account_id'] = $providerAccountIdForRoot;
            } else {
                unset($data['provider_account_id']);
            }
            $data['userid'] = isset($data['userid']) ? (int) $data['userid'] : 0;
            $data['rootdomain'] = $normalized;
            $data['subdomain'] = $subdomainName;
            $data['never_expires'] = !empty($row['never_expires']) ? 1 : 0;
            if (!isset($data['created_at'])) {
                $data['created_at'] = $now;
            }
            if (!isset($data['updated_at'])) {
                $data['updated_at'] = $data['created_at'];
            }
            $newId = Capsule::table('mod_cloudflare_subdomain')->insertGetId($data);
            $summary['subdomains_inserted']++;
            $oldId = isset($row['id']) ? (int) $row['id'] : 0;
            if ($oldId > 0) {
                $idMapping[$oldId] = $newId;
            }
            $nameMapping[$subLower] = $newId;
            if ($data['userid'] > 0) {
                $affectedUserIds[$data['userid']] = true;
            }
        }

        $allowedDnsColumns = ['zone_id','record_id','name','type','content','ttl','proxied','line','status','priority','created_at','updated_at'];
        if (!empty($dnsRecordsData) && cfmod_table_exists('mod_cloudflare_dns_records')) {
            foreach ($dnsRecordsData as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $oldSubId = isset($row['subdomain_id']) ? (int) $row['subdomain_id'] : 0;
                $newSubId = $idMapping[$oldSubId] ?? null;
                if ($newSubId === null) {
                    $warnings[] = '跳过DNS记录（缺少子域名映射）: ' . ($row['name'] ?? '');
                    continue;
                }
                $data = ['subdomain_id' => $newSubId];
                foreach ($allowedDnsColumns as $column) {
                    if (!array_key_exists($column, $row)) {
                        continue;
                    }
                    $value = $row[$column];
                    switch ($column) {
                        case 'ttl':
                            $value = (int) $value;
                            if ($value <= 0) {
                                $value = 120;
                            }
                            break;
                        case 'proxied':
                            $value = !empty($value) ? 1 : 0;
                            break;
                        case 'priority':
                            if ($value === null || $value === '') {
                                $value = null;
                            } else {
                                $value = (int) $value;
                            }
                            break;
                    }
                    $data[$column] = $value;
                }
                if (!isset($data['created_at'])) {
                    $data['created_at'] = $now;
                }
                if (!isset($data['updated_at'])) {
                    $data['updated_at'] = $data['created_at'];
                }
                Capsule::table('mod_cloudflare_dns_records')->insert($data);
                CfSubdomainService::markHasDnsHistory($newSubId);
                $summary['dns_records_inserted']++;
            }
        }

        if (!empty($domainRiskData) && cfmod_table_exists('mod_cloudflare_domain_risk')) {
            $allowedRiskColumns = ['risk_score','risk_level','reasons_json','last_checked_at','created_at','updated_at'];
            foreach ($domainRiskData as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $oldSubId = isset($row['subdomain_id']) ? (int) $row['subdomain_id'] : 0;
                $newSubId = $idMapping[$oldSubId] ?? null;
                if ($newSubId === null) {
                    $warnings[] = '跳过域名风险记录（缺少子域名映射）';
                    continue;
                }
                $data = ['subdomain_id' => $newSubId];
                foreach ($allowedRiskColumns as $column) {
                    if (!array_key_exists($column, $row)) {
                        continue;
                    }
                    $value = $row[$column];
                    if ($column === 'risk_score') {
                        $value = (int) $value;
                    }
                    $data[$column] = $value;
                }
                if (!isset($data['created_at'])) {
                    $data['created_at'] = $now;
                }
                if (!isset($data['updated_at'])) {
                    $data['updated_at'] = $data['created_at'];
                }
                Capsule::table('mod_cloudflare_domain_risk')->insert($data);
                $summary['domain_risk_inserted']++;
            }
        }

        if (!empty($riskEventsData) && cfmod_table_exists('mod_cloudflare_risk_events')) {
            $allowedRiskEventColumns = ['source','score','level','reason','details_json','created_at','updated_at'];
            foreach ($riskEventsData as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $oldSubId = isset($row['subdomain_id']) ? (int) $row['subdomain_id'] : 0;
                $newSubId = $idMapping[$oldSubId] ?? null;
                if ($newSubId === null) {
                    $warnings[] = '跳过风险事件（缺少子域名映射）';
                    continue;
                }
                $data = ['subdomain_id' => $newSubId];
                foreach ($allowedRiskEventColumns as $column) {
                    if (!array_key_exists($column, $row)) {
                        continue;
                    }
                    $value = $row[$column];
                    if ($column === 'score') {
                        $value = (int) $value;
                    }
                    $data[$column] = $value;
                }
                if (!isset($data['created_at'])) {
                    $data['created_at'] = $now;
                }
                if (!isset($data['updated_at'])) {
                    $data['updated_at'] = $data['created_at'];
                }
                Capsule::table('mod_cloudflare_risk_events')->insert($data);
                $summary['risk_events_inserted']++;
            }
        }

        if (!empty($syncResultsData) && cfmod_table_exists('mod_cloudflare_sync_results')) {
            $allowedSyncColumns = ['job_id','kind','action','detail','created_at','updated_at'];
            foreach ($syncResultsData as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $oldSubId = isset($row['subdomain_id']) ? (int) $row['subdomain_id'] : 0;
                $newSubId = $idMapping[$oldSubId] ?? null;
                if ($newSubId === null) {
                    $warnings[] = '跳过同步差异记录（缺少子域名映射）';
                    continue;
                }
                $jobId = isset($row['job_id']) ? (int) $row['job_id'] : null;
                if ($jobId !== null && $jobId > 0) {
                    $jobExists = $jobsTableExists
                        ? Capsule::table('mod_cloudflare_jobs')->where('id', $jobId)->exists()
                        : false;
                    if (!$jobExists) {
                        $jobId = null;
                    }
                } else {
                    $jobId = null;
                }
                $data = ['subdomain_id' => $newSubId, 'job_id' => $jobId];
                foreach ($allowedSyncColumns as $column) {
                    if ($column === 'job_id') {
                        continue;
                    }
                    if (!array_key_exists($column, $row)) {
                        continue;
                    }
                    $data[$column] = $row[$column];
                }
                if (!isset($data['created_at'])) {
                    $data['created_at'] = $now;
                }
                if (!isset($data['updated_at'])) {
                    $data['updated_at'] = $data['created_at'];
                }
                Capsule::table('mod_cloudflare_sync_results')->insert($data);
                $summary['sync_results_inserted']++;
            }
        }

        $quotaMap = [];
        foreach ($quotasData as $row) {
            if (!is_array($row)) {
                continue;
            }
            $uid = isset($row['userid']) ? (int) $row['userid'] : 0;
            if ($uid > 0) {
                $quotaMap[$uid] = $row;
                $affectedUserIds[$uid] = true;
            }
        }

        if (!empty($affectedUserIds) && cfmod_table_exists('mod_cloudflare_subdomain_quotas')) {
            foreach (array_keys($affectedUserIds) as $uid) {
                if ($uid <= 0) {
                    continue;
                }
                $actualCount = Capsule::table('mod_cloudflare_subdomain')
                    ->where('userid', $uid)
                    ->where(function ($query) {
                        $query->whereNull('status')->orWhere('status', '!=', 'deleted');
                    })
                    ->count();
                $quotaRow = $quotaMap[$uid] ?? [];
                $existing = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $uid)->first();
                if ($existing) {
                    $update = [
                        'used_count' => $actualCount,
                        'updated_at' => $now,
                    ];
                    if (isset($quotaRow['max_count'])) {
                        $update['max_count'] = max((int) ($existing->max_count ?? 0), (int) $quotaRow['max_count']);
                    }
                    if (isset($quotaRow['invite_bonus_count'])) {
                        $update['invite_bonus_count'] = max((int) ($existing->invite_bonus_count ?? 0), (int) $quotaRow['invite_bonus_count']);
                    }
                    if (isset($quotaRow['invite_bonus_limit'])) {
                        $update['invite_bonus_limit'] = max((int) ($existing->invite_bonus_limit ?? 0), (int) $quotaRow['invite_bonus_limit']);
                    }
                    Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $uid)->update($update);
                    $summary['quota_updates']++;
                } else {
                    $insert = [
                        'userid' => $uid,
                        'used_count' => $actualCount,
                        'max_count' => max($actualCount, isset($quotaRow['max_count']) ? (int) $quotaRow['max_count'] : $actualCount),
                        'invite_bonus_count' => isset($quotaRow['invite_bonus_count']) ? (int) $quotaRow['invite_bonus_count'] : 0,
                        'invite_bonus_limit' => isset($quotaRow['invite_bonus_limit']) ? max(0, (int) $quotaRow['invite_bonus_limit']) : 5,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ];
                    Capsule::table('mod_cloudflare_subdomain_quotas')->insert($insert);
                    $summary['quota_created']++;
                }
            }
        }
    });

    $summary['warnings'] = array_values(array_unique(array_filter($warnings)));

    if (function_exists('cloudflare_subdomain_log')) {
        try {
            cloudflare_subdomain_log('admin_import_rootdomain_local', ['rootdomain' => $summary['rootdomain'], 'summary' => $summary]);
        } catch (\Throwable $e) {
            // ignore log failure
        }
    }

    return $summary;
}

if (!function_exists('cfmod_fetch_dns_records_for_subdomains')) {
    function cfmod_fetch_dns_records_for_subdomains(array $subdomainRows, string $filterType = '', string $filterName = '', array $options = []): array {
        $subdomainIds = [];
        $subdomainNames = [];
        foreach ($subdomainRows as $row) {
            if (is_object($row)) {
                $sid = isset($row->id) ? (int) $row->id : 0;
                $name = isset($row->subdomain) ? strtolower(trim((string) $row->subdomain)) : '';
            } elseif (is_array($row)) {
                $sid = isset($row['id']) ? (int) $row['id'] : 0;
                $name = isset($row['subdomain']) ? strtolower(trim((string) $row['subdomain'])) : '';
            } else {
                $sid = 0;
                $name = '';
            }
            if ($sid <= 0) {
                continue;
            }
            $subdomainIds[] = $sid;
            if ($name !== '') {
                $subdomainNames[$sid] = $name;
            }
        }
        $subdomainIds = array_values(array_unique(array_filter($subdomainIds)));

        $result = [
            'records' => [],
            'ns' => [],
            'totals' => [],
        ];

        if (empty($subdomainIds)) {
            return $result;
        }

        $pageSize = intval($options['page_size'] ?? 20);
        if ($pageSize <= 0) {
            $pageSize = 20;
        }
        $pageSize = max(1, min(200, $pageSize));
        $dnsPage = max(1, intval($options['dns_page'] ?? 1));
        $dnsPageFor = intval($options['dns_page_for'] ?? 0);

        $filterTypeNormalized = strtoupper(trim($filterType));
        if ($filterTypeNormalized === '') {
            $filterTypeNormalized = null;
        }
        $filterNameLike = trim($filterName);

        try {
            $totalQuery = Capsule::table('mod_cloudflare_dns_records')
                ->select('subdomain_id', Capsule::raw('COUNT(*) as aggregate_count'))
                ->whereIn('subdomain_id', $subdomainIds);
            if ($filterTypeNormalized !== null) {
                $totalQuery->where('type', $filterTypeNormalized);
            }
            if ($filterNameLike !== '') {
                $totalQuery->where('name', 'like', '%' . $filterNameLike . '%');
            }
            $totalRows = $totalQuery->groupBy('subdomain_id')->get();
            foreach ($totalRows as $row) {
                $sid = (int) ($row->subdomain_id ?? 0);
                if ($sid > 0) {
                    $result['totals'][$sid] = (int) ($row->aggregate_count ?? 0);
                }
            }
        } catch (\Throwable $e) {
            // ignore count errors to keep UI rendering
        }

        foreach ($subdomainIds as $sid) {
            if (!array_key_exists($sid, $result['totals'])) {
                $result['totals'][$sid] = 0;
            }
        }

        try {
            $nsRows = Capsule::table('mod_cloudflare_dns_records')
                ->select('subdomain_id', 'name', 'content')
                ->whereIn('subdomain_id', $subdomainIds)
                ->where('type', 'NS')
                ->orderBy('subdomain_id', 'asc')
                ->orderBy('id', 'asc')
                ->get();
            foreach ($nsRows as $row) {
                $sid = (int) ($row->subdomain_id ?? 0);
                if ($sid <= 0) {
                    continue;
                }
                $expected = $subdomainNames[$sid] ?? '';
                $recordName = strtolower(trim((string) ($row->name ?? '')));
                if ($recordName === '' || $recordName === '@' || ($expected !== '' && $recordName === $expected)) {
                    $result['ns'][$sid] = $result['ns'][$sid] ?? [];
                    $result['ns'][$sid][] = $row->content;
                }
            }
        } catch (\Throwable $e) {
            // ignore ns errors
        }

        $recordsBySubdomain = [];
        try {
            $recordsQuery = Capsule::table('mod_cloudflare_dns_records')
                ->whereIn('subdomain_id', $subdomainIds);
            if ($filterTypeNormalized !== null) {
                $recordsQuery->where('type', $filterTypeNormalized);
            }
            if ($filterNameLike !== '') {
                $recordsQuery->where('name', 'like', '%' . $filterNameLike . '%');
            }
            $recordsRows = $recordsQuery
                ->orderBy('subdomain_id', 'asc')
                ->orderBy('id', 'desc')
                ->get();
            foreach ($recordsRows as $row) {
                $sid = (int) ($row->subdomain_id ?? 0);
                if ($sid <= 0) {
                    continue;
                }
                if (!isset($recordsBySubdomain[$sid])) {
                    $recordsBySubdomain[$sid] = [];
                }
                $recordsBySubdomain[$sid][] = $row;
            }
        } catch (\Throwable $e) {
            $recordsBySubdomain = [];
        }

        foreach ($subdomainIds as $sid) {
            $totalForSubdomain = $result['totals'][$sid] ?? 0;
            $pageForSubdomain = ($dnsPageFor === $sid) ? $dnsPage : 1;
            $maxPages = $totalForSubdomain > 0 ? max(1, (int) ceil($totalForSubdomain / $pageSize)) : 1;
            if ($pageForSubdomain > $maxPages) {
                $pageForSubdomain = $maxPages;
            }

            $recordsList = $recordsBySubdomain[$sid] ?? [];
            $offset = $pageForSubdomain > 1 ? ($pageForSubdomain - 1) * $pageSize : 0;
            $records = $totalForSubdomain > 0 ? array_slice($recordsList, $offset, $pageSize) : [];

            $result['records'][$sid] = [
                'items' => $records,
                'page' => $pageForSubdomain,
                'page_size' => $pageSize,
            ];
        }

        return $result;
    }
}

function domain_hub_config() {
    return [
        "name" => "阿里云DNS 二级域名分发",
        "description" => "用户可注册二级域名并进行DNS解析操作，支持多种记录类型和CDN管理",
        "version" => "2.0",
        "author" => "你的名字",
        "fields" => [
            "cloudflare_api_key" => [
                "FriendlyName" => "阿里云 AccessKey Secret",
                "Type" => "text",
                "Size" => "50",
                "Description" => "填写阿里云 AccessKey Secret",
            ],
            "cloudflare_email" => [
                "FriendlyName" => "阿里云 AccessKey ID",
                "Type" => "text",
                "Size" => "50",
                "Description" => "填写阿里云 AccessKey ID",
            ],
            "max_subdomain_per_user" => [
                "FriendlyName" => "每用户最大二级域名数量",
                "Type" => "text",
                "Size" => "5",
                "Default" => "5",
                "Description" => "每个用户最多可以注册的二级域名数量",
            ],
            "subdomain_prefix_min_length" => [
                "FriendlyName" => "子域名前缀最小长度",
                "Type" => "text",
                "Size" => "3",
                "Default" => "2",
                "Description" => "用户注册子域名前缀允许的最小字符长度（1-63）",
            ],
            "subdomain_prefix_max_length" => [
                "FriendlyName" => "子域名前缀最大长度",
                "Type" => "text",
                "Size" => "3",
                "Default" => "63",
                "Description" => "用户注册子域名前缀允许的最大字符长度（1-63，需大于或等于最小长度）",
            ],
            "root_domains" => [
                "FriendlyName" => "（已废弃）老版根域名配置",
                "Type" => "textarea",
                "Rows" => "3",
                "Cols" => "50",
                "Description" => "仅用于兼容旧版本，当前版本会自动将此处内容迁移到“根域名白名单”数据库后再忽略。请在插件后台管理根域名。",
            ],
            "forbidden_prefix" => [
                "FriendlyName" => "禁止前缀，逗号分隔",
                "Type" => "textarea",
                "Rows" => "3",
                "Cols" => "50",
                "Default" => "www,mail,ftp,admin,root,gov,pay,bank",
                "Description" => "禁止用户注册的前缀，多个用逗号分隔",
            ],
            "default_ip" => [
                "FriendlyName" => "默认解析IP地址",
                "Type" => "text",
                "Size" => "20",
                "Default" => "192.0.2.1",
                "Description" => "用户设置解析时的默认IP地址",
            ],
            "domain_registration_term_years" => [
                "FriendlyName" => "默认注册年限（年）",
                "Type" => "text",
                "Size" => "3",
                "Default" => "1",
                "Description" => "新注册的二级域名默认有效期，单位：年",
            ],
            "domain_free_renew_window_days" => [
                "FriendlyName" => "免费续期窗口（天）",
                "Type" => "text",
                "Size" => "3",
                "Default" => "30",
                "Description" => "到期前多少天向用户开放免费续期操作",
            ],
            "domain_grace_period_days" => [
                "FriendlyName" => "宽限期（天）",
                "Type" => "text",
                "Size" => "3",
                "Default" => "45",
                "Description" => "域名到期后进入宽限期，在该期间内用户仍可自助续期",
            ],
            "domain_redemption_days" => [
                "FriendlyName" => "赎回期（天）",
                "Type" => "text",
                "Size" => "3",
                "Default" => "0",
                "Description" => "超过宽限期后进入赎回期，具体处理方式由下方的赎回期处理方式设置决定（0 表示无赎回期）",
            ],
            "domain_redemption_mode" => [
                "FriendlyName" => "赎回期处理方式",
                "Type" => "dropdown",
                "Options" => [
                    "manual" => "需人工处理（保持提交工单流程）",
                    "auto_charge" => "自动扣费续期",
                ],
                "Default" => "manual",
                "Description" => "选择赎回期的处理方式。选择“自动扣费续期”后，用户可在赎回期内自助续期，系统会按照设定金额自动扣费。",
            ],
            "domain_redemption_fee_amount" => [
                "FriendlyName" => "赎回期扣费金额",
                "Type" => "text",
                "Size" => "6",
                "Default" => "0",
                "Description" => "当赎回期选择自动扣费时，需要扣除的金额（单位：账户余额货币）。设置为 0 表示不扣费。",
            ],
            "domain_redemption_cleanup_days" => [
                "FriendlyName" => "赎回期后自动删除延迟（天）",
                "Type" => "text",
                "Size" => "3",
                "Default" => "0",
                "Description" => "赎回期结束后等待多少天自动删除域名（0 表示赎回期结束后立即删除）",
            ],
            "redeem_ticket_url" => [
                "FriendlyName" => "赎回期工单链接",
                "Type" => "text",
                "Size" => "120",
                "Default" => "submitticket.php",
                "Description" => "当域名进入赎回期时，引导用户提交工单的 URL，留空时默认使用 WHMCS 提交工单页面",
            ],
            "domain_expiry_enable_legacy_never" => [
                "FriendlyName" => "旧域名保持永不过期",
                "Type" => "yesno",
                "Default" => "yes",
                "Description" => "开启后，已存在的历史域名保持永不过期状态",
            ],
            "domain_cleanup_batch_size" => [
                "FriendlyName" => "自动清理批量大小",
                "Type" => "text",
                "Size" => "3",
                "Default" => "50",
                "Description" => "每次自动清理任务处理的域名数量上限（建议 20-200）",
            ],
            "domain_cleanup_deep_delete" => [
                "FriendlyName" => "自动清理深度删除DNS记录",
                "Type" => "yesno",
                "Default" => "yes",
                "Description" => "开启后，自动清理会删除该子域名下所有DNS记录（含子记录）",
            ],
            "enable_auto_sync" => [
                "FriendlyName" => "启用自动同步",
                "Type" => "yesno",
                "Default" => "yes",
                "Description" => "是否启用与阿里云DNS的自动同步功能",
            ],
            "sync_interval" => [
                "FriendlyName" => "同步间隔（分钟）",
                "Type" => "text",
                "Size" => "5",
                "Default" => "60",
                "Description" => "与阿里云DNS同步的间隔时间（分钟）",
            ],
            "sync_authoritative_source" => [
                "FriendlyName" => "同步优先级",
                "Type" => "dropdown",
                "Options" => [
                    "local" => "以本地记录为准",
                    "aliyun" => "以阿里云记录为准"
                ],
                "Default" => "local",
                "Description" => "选择同步校准时优先生效的数据来源。\n以本地记录为准：修复阿里云缺失并删除阿里云多出的记录。\n以阿里云记录为准：仅补齐本地记录，不会删除阿里云多出的记录。",
            ],
            "calibration_batch_size" => [
                "FriendlyName" => "校准批量大小",
                "Type" => "text",
                "Size" => "4",
                "Default" => "150",
                "Description" => "每个校准作业处理的子域数量，建议 100-500，数值越大单次作业耗时越久。",
            ],
            // 邀请全局配置
            "invite_bonus_limit_global" => [
                "FriendlyName" => "邀请加成上限（全局）",
                "Type" => "text",
                "Size" => "5",
                "Default" => "5",
                "Description" => "通过邀请码可增加的注册额度上限（默认 5，可在用户配额中单独覆盖）",
            ],
            "enable_invite_leaderboard" => [
                "FriendlyName" => "启用邀请排行榜",
                "Type" => "yesno",
                "Default" => "yes",
                "Description" => "开启后显示每周邀请码使用次数排行榜",
            ],
            "invite_leaderboard_top" => [
                "FriendlyName" => "排行榜人数（TOP N）",
                "Type" => "text",
                "Size" => "3",
                "Default" => "5",
                "Description" => "每周显示前 N 名",
            ],
            "invite_leaderboard_period_days" => [
                "FriendlyName" => "排行榜周期（天）",
                "Type" => "text",
                "Size" => "3",
                "Default" => "7",
                "Description" => "每期统计周期（默认 7 天）",
            ],
            "invite_reward_instructions" => [
                "FriendlyName" => "礼品兑换说明",
                "Type" => "textarea",
                "Rows" => "3",
                "Cols" => "50",
                "Description" => "展示在用户端的兑换说明（可选）",
            ],
            "invite_reward_prize_1" => [
                "FriendlyName" => "第1名奖品",
                "Type" => "text",
                "Size" => "50",
                "Default" => "一等奖礼品",
                "Description" => "排行榜第1名奖品描述",
            ],
            "invite_reward_prize_2" => [
                "FriendlyName" => "第2名奖品",
                "Type" => "text",
                "Size" => "50",
                "Default" => "二等奖礼品",
                "Description" => "排行榜第2名奖品描述",
            ],
            "invite_reward_prize_3" => [
                "FriendlyName" => "第3名奖品",
                "Type" => "text",
                "Size" => "50",
                "Default" => "三等奖礼品",
                "Description" => "排行榜第3名奖品描述",
            ],
            "invite_reward_prize_4" => [
                "FriendlyName" => "第4名奖品",
                "Type" => "text",
                "Size" => "50",
                "Default" => "四等奖礼品",
                "Description" => "排行榜第4名奖品描述",
            ],
            "invite_reward_prize_5" => [
                "FriendlyName" => "第5名奖品",
                "Type" => "text",
                "Size" => "50",
                "Default" => "五等奖礼品",
                "Description" => "排行榜第5名奖品描述",
            ],
            "invite_reward_prizes" => [
                "FriendlyName" => "奖品配置（多名次）",
                "Type" => "textarea",
                "Rows" => "5",
                "Cols" => "60",
                "Description" => "一行一条，支持单名次或范围，格式如：\n1=一等奖\n2=二等奖\n3=三等奖\n4=四等奖\n5=五等奖\n6-10=参与奖",
            ],
            "invite_cycle_start" => [
                "FriendlyName" => "周期开始日期",
                "Type" => "text",
                "Size" => "12",
                "Description" => "指定一个周期开始日期（YYYY-MM-DD）。设置后系统将以该日起按周期天数计算周期，并在周期结束后自动生成前N名榜单与奖励。留空则按每周一规则执行。",
            ],
            "max_dns_records_per_subdomain" => [
                "FriendlyName" => "每个二级域名最大解析记录数(0不限制)",
                "Type" => "text",
                "Size" => "6",
                "Default" => "0",
                "Description" => "为每个已注册的二级域名限制可添加的解析记录数量；0 表示不限制",
            ],
            "ns_max_per_domain" => [
                "FriendlyName" => "每个域名 NS 记录上限",
                "Type" => "text",
                "Size" => "6",
                "Default" => "8",
                "Description" => "限制每个域名(@)的 NS 记录数量上限，建议 4-8",
            ],
            "enable_async_dns_operations" => [
                "FriendlyName" => "启用 DNS 异步执行",
                "Type" => "yesno",
                "Default" => "no",
                "Description" => "开启后，用户的解析新增/修改/删除将进入后台队列，由独立 worker/cron 处理，前端会提示稍后生效。",
            ],
            "risk_api_endpoint" => [
                "FriendlyName" => "外部风险扫描 API 地址",
                "Type" => "text",
                "Size" => "120",
                "Description" => "例如：https://risk-probe.example.com/api",
            ],
            "risk_api_key" => [
                "FriendlyName" => "外部风险扫描 API Key",
                "Type" => "text",
                "Size" => "120",
                "Description" => "可选。用于鉴权，不填写则匿名访问",
            ],
            "risk_scan_enabled" => [
                "FriendlyName" => "启用周期性风险扫描",
                "Type" => "yesno",
                "Default" => "yes",
                "Description" => "开启后将周期性通过外部探测节点完成 HTTP/HTTPS 探测、关键词/指纹与落地跳转检查，避免暴露 WHMCS 服务器 IP",
            ],
            "risk_scan_interval" => [
                "FriendlyName" => "风险扫描间隔（分钟）",
                "Type" => "text",
                "Size" => "5",
                "Default" => "120",
                "Description" => "建议 ≥ 60 分钟",
            ],
            "risk_scan_batch_size" => [
                "FriendlyName" => "风险扫描批量大小",
                "Type" => "text",
                "Size" => "5",
                "Default" => "50",
                "Description" => "每次风险扫描处理的子域数量，建议 50-500，最高 1000",
            ],
            "risk_keywords" => [
                "FriendlyName" => "风险关键词（逗号分隔）",
                "Type" => "textarea",
                "Rows" => "3",
                "Cols" => "60",
                "Description" => "留空则使用外部探测服务默认关键词；示例：phishing,login,verify your account,验证码,支付,银行",
            ],
            "risk_include_records" => [
                "FriendlyName" => "扫描包含解析主机名",
                "Type" => "yesno",
                "Default" => "no",
                "Description" => "开启后，扫描时将同时探测该子域名下的解析主机名（如 123.aa.aaa.com）",
            ],
            "risk_record_types" => [
                "FriendlyName" => "纳入扫描的记录类型",
                "Type" => "text",
                "Size" => "30",
                "Default" => "A,CNAME",
                "Description" => "逗号分隔，支持：A,AAAA,CNAME,TXT",
            ],
            "risk_record_limit" => [
                "FriendlyName" => "每子域最多扫描主机名数",
                "Type" => "text",
                "Size" => "5",
                "Default" => "10",
                "Description" => "限制每个子域名下附加扫描的主机名数量，上限建议 50",
            ],
            "risk_parallel_requests" => [
                "FriendlyName" => "风险扫描并发请求数",
                "Type" => "text",
                "Size" => "3",
                "Default" => "5",
                "Description" => "同时向外部风险 API 发起的最大请求数，建议 1-10，过大可能触发限速",
            ],
            "risk_auto_action" => [
                "FriendlyName" => "风险自动处置",
                "Type" => "dropdown",
                "Options" => ["none"=>"不自动","suspend"=>"高风险自动冻结子域"],
                "Default" => "none",
            ],
            "risk_auto_threshold" => [
                "FriendlyName" => "高风险阈值(0-100)",
                "Type" => "text",
                "Size" => "3",
                "Default" => "80",
                "Description" => "达到该分数及以上视为高风险",
            ],
            "risk_notify_email" => [
                "FriendlyName" => "风险告警邮箱",
                "Type" => "text",
                "Size" => "64",
                "Description" => "可选，命中高风险时发送通知",
            ],
            // API功能配置
            "enable_user_api" => [
                "FriendlyName" => "启用用户API功能",
                "Type" => "yesno",
                "Default" => "yes",
                "Description" => "开启后用户可以创建API密钥进行域名管理",
            ],
            "api_keys_per_user" => [
                "FriendlyName" => "每用户API密钥数量上限",
                "Type" => "text",
                "Size" => "5",
                "Default" => "3",
                "Description" => "每个用户最多可创建的API密钥数量",
            ],
            "api_require_quota" => [
                "FriendlyName" => "API使用配额要求",
                "Type" => "text",
                "Size" => "5",
                "Default" => "1",
                "Description" => "用户注册配额必须大于此值才能创建API密钥（0表示无限制）",
            ],
            "api_rate_limit" => [
                "FriendlyName" => "API请求速率限制（每分钟）",
                "Type" => "text",
                "Size" => "5",
                "Default" => "60",
                "Description" => "每个API密钥每分钟最多请求次数",
            ],
            "api_enable_ip_whitelist" => [
                "FriendlyName" => "启用API IP白名单",
                "Type" => "yesno",
                "Default" => "no",
                "Description" => "开启后用户可以为API密钥设置IP白名单",
            ],
            // 公共 WHOIS 查询
            "whois_require_api_key" => [
                "FriendlyName" => "WHOIS 查询需要 API Key",
                "Type" => "yesno",
                "Default" => "no",
                "Description" => "开启后 WHOIS 查询必须携带有效的 API Key；默认对外开放无需鉴权",
            ],
            "whois_email_mode" => [
                "FriendlyName" => "WHOIS 邮件显示模式",
                "Type" => "dropdown",
                "Options" => [
                    "anonymous" => "匿名邮箱（统一邮箱）",
                    "masked" => "遮罩真实邮箱",
                    "real" => "显示真实邮箱"
                ],
                "Default" => "anonymous",
                "Description" => "根据需要决定返回注册邮箱的呈现方式",
            ],
            "whois_anonymous_email" => [
                "FriendlyName" => "WHOIS 匿名邮箱",
                "Type" => "text",
                "Size" => "60",
                "Default" => "whois@example.com",
                "Description" => "当邮件模式为匿名或需要回退值时使用",
            ],
            "whois_default_nameservers" => [
                "FriendlyName" => "WHOIS 默认NS列表",
                "Type" => "textarea",
                "Rows" => "3",
                "Cols" => "60",
                "Description" => "当子域名没有自定义NS记录时返回此列表（每行一个）",
            ],
            "whois_rate_limit_per_minute" => [
                "FriendlyName" => "WHOIS 每分钟查询上限",
                "Type" => "text",
                "Size" => "4",
                "Default" => "2",
                "Description" => "针对同一IP的公共WHOIS调用限制（<=0 表示不限）",
            ],
            // 前端分页 & 日志保留
            "client_page_size" => [
                "FriendlyName" => "用户端每页子域名数量",
                "Type" => "text",
                "Size" => "4",
                "Default" => "20",
                "Description" => "用户端列表每页显示数量（1-20，每页最多 20 条）",
            ],
            "enable_domain_gift" => [
                "FriendlyName" => "启用域名转赠",
                "Type" => "yesno",
                "Default" => "no",
                "Description" => "开启后，用户可在前台将已注册的域名转赠给其他账号。",
            ],
            "domain_gift_code_ttl_hours" => [
                "FriendlyName" => "转赠码有效期（小时）",
                "Type" => "text",
                "Size" => "4",
                "Default" => "72",
                "Description" => "生成的域名转赠接收码有效时长（单位：小时）。",
            ],
            "api_logs_retention_days" => [
                "FriendlyName" => "API日志保留天数",
                "Type" => "text",
                "Size" => "4",
                "Default" => "30",
                "Description" => "定期清理早于该天数的 API 日志（1-365，0 表示保留全部）",
            ],
            "general_logs_retention_days" => [
                "FriendlyName" => "通用日志保留天数",
                "Type" => "text",
                "Size" => "4",
                "Default" => "90",
                "Description" => "定期清理早于该天数的通用操作日志（1-365，0 表示保留全部）",
            ],
            "sync_logs_retention_days" => [
                "FriendlyName" => "差异日志保留天数",
                "Type" => "text",
                "Size" => "4",
                "Default" => "30",
                "Description" => "定期清理早于该天数的对账差异日志（1-365，0 表示保留全部）",
            ],
            "cron_max_jobs_per_pass" => [
                "FriendlyName" => "每次 Cron 执行的作业数量",
                "Type" => "text",
                "Size" => "3",
                "Default" => "2",
                "Description" => "每次 Cron/Worker 触发时最多执行的后台作业数量，建议 1-50，默认 2。",
            ],
            "run_inline_worker" => [
                "FriendlyName" => "在 Cron 内联执行队列",
                "Type" => "yesno",
                "Default" => "no",
                "Description" => "开启后，WHMCS Cron 会直接执行队列任务。建议保持关闭，并通过 CLI worker（worker.php）独立运行队列，避免 Cron 被长任务阻塞。",
            ],
        ]
    ];
}

// 激活插件
function domain_hub_activate() {
    return CfModuleInstaller::activate();
}


// 停用插件
function domain_hub_deactivate() {
    return CfModuleInstaller::deactivate();
}




// 卸载插件
function domain_hub_uninstall() {
    return CfModuleInstaller::uninstall();
}


// 后台管理菜单
function domain_hub_adminlink($vars) {
    return ["管理子域名" => "addonmodules.php?module=" . CF_MODULE_NAME];
}

// 后台管理页面
function domain_hub_output($vars) {
    $dispatcher = CfApiDispatcher::instance();
    if ($dispatcher->shouldDispatch()) {
        $dispatcher->dispatch();
        return;
    }

    $action = strtolower((string)($_REQUEST['action'] ?? ''));
    if ($action === 'client' && isset($_SESSION['uid'])) {
        CfClientController::instance()->handle($vars, false, true);
        return;
    }

    CfAdminController::instance()->handle($vars);
}

function domain_hub_handle_clientarea_page(array $vars = [], bool $isLegacyEntry = false) {
    CfClientController::instance()->handle($vars, $isLegacyEntry);
}

if (!function_exists('domain_hub_clientarea')) {
    function domain_hub_clientarea($vars) {
        domain_hub_handle_clientarea_page(is_array($vars) ? $vars : [], false);
        return ['requirelogin' => true];
    }
}

if (!function_exists('cloudflare_subdomain_clientarea')) {
    function cloudflare_subdomain_clientarea($vars) {
        return domain_hub_clientarea($vars);
    }
}

// Cron Hook removed here to avoid duplication. See hooks.php for job enqueueing logic.

// 增强的日志记录函数


// 升级函数
function domain_hub_upgrade($vars) {
    try {
        cfmod_ensure_provider_schema();
        // 检查并创建新表
        $tables_to_check = [
            'mod_cloudflare_subdomain' => function($table) {
                $table->increments('id');
                $table->integer('userid')->unsigned();
                $table->string('subdomain', 255);
                $table->string('rootdomain', 255);
                $table->integer('provider_account_id')->unsigned()->nullable();
                $table->string('cloudflare_zone_id', 50);
                $table->string('dns_record_id', 50)->nullable();
                $table->string('status', 20)->default('active');
                $table->dateTime('expires_at')->nullable();
                $table->dateTime('renewed_at')->nullable();
                $table->dateTime('auto_deleted_at')->nullable();
                $table->boolean('never_expires')->default(0);
                $table->text('notes')->nullable();
                $table->timestamps();
                $table->index('userid');
                $table->index('subdomain');
                $table->index('status');
                $table->index('rootdomain');
                $table->index('provider_account_id');
                $table->index(['expires_at', 'status'], 'idx_expiry_status');
            },
            'mod_cloudflare_rootdomains' => function($table) {
                $table->increments('id');
                $table->string('domain', 255)->unique();
                $table->integer('provider_account_id')->unsigned()->nullable();
                $table->string('cloudflare_zone_id', 50)->nullable();
                $table->string('status', 20)->default('active');
                $table->text('description')->nullable();
                $table->integer('max_subdomains')->default(1000);
                $table->integer('per_user_limit')->default(0);
                $table->timestamps();
                $table->index('status');
                $table->index('provider_account_id');
            },
            'mod_cloudflare_logs' => function($table) {
                $table->increments('id');
                $table->integer('userid')->unsigned()->nullable();
                $table->integer('subdomain_id')->unsigned()->nullable();
                $table->string('action', 100);
                $table->text('details')->nullable();
                $table->string('ip', 45)->nullable();
                $table->string('user_agent')->nullable();
                $table->timestamps();
                $table->index('userid');
                $table->index('subdomain_id');
                $table->index('action');
                $table->index('created_at');
            },
            'mod_cloudflare_domain_gifts' => function($table) {
                $table->increments('id');
                $table->string('code', 32)->unique();
                $table->integer('subdomain_id')->unsigned();
                $table->integer('from_userid')->unsigned();
                $table->integer('to_userid')->unsigned()->nullable();
                $table->string('full_domain', 255);
                $table->string('status', 20)->default('pending');
                $table->dateTime('expires_at');
                $table->dateTime('completed_at')->nullable();
                $table->dateTime('cancelled_at')->nullable();
                $table->integer('cancelled_by_admin')->unsigned()->nullable();
                $table->timestamps();
                $table->index('subdomain_id');
                $table->index('from_userid');
                $table->index('to_userid');
                $table->index('status');
                $table->index('expires_at');
            },
            'mod_cloudflare_forbidden_domains' => function($table) {
                $table->increments('id');
                $table->string('domain', 255)->unique();
                $table->string('rootdomain', 255)->nullable();
                $table->string('reason', 255)->nullable();
                $table->string('added_by', 100)->nullable();
                $table->timestamps();
                $table->index('rootdomain');
            },
            'mod_cloudflare_dns_records' => function($table) {
                $table->increments('id');
                $table->integer('subdomain_id')->unsigned();
                $table->string('zone_id', 50);
                $table->string('record_id', 50);
                $table->string('name', 255);
                $table->string('type', 10);
                $table->text('content');
                $table->integer('ttl')->default(120);
                $table->boolean('proxied')->default(false);
                $table->string('line', 32)->nullable();
                $table->string('status', 20)->default('active');
                $table->integer('priority')->nullable();
                $table->timestamps();
                $table->index('subdomain_id');
                $table->index('record_id');
                $table->index('name');
                $table->index('type');
            },
            'mod_cloudflare_jobs' => function($table) {
                $table->increments('id');
                $table->string('type', 50);
                $table->text('payload_json');
                $table->integer('priority')->default(10);
                $table->string('status', 20)->default('pending');
                $table->integer('attempts')->default(0);
                $table->dateTime('next_run_at')->nullable();
                $table->text('last_error')->nullable();
                $table->timestamps();
                $table->index('status');
                $table->index('type');
                $table->index('priority');
                $table->index('next_run_at');
            },
            'mod_cloudflare_sync_results' => function($table) {
                $table->increments('id');
                $table->integer('job_id')->unsigned();
                $table->integer('subdomain_id')->unsigned()->nullable();
                $table->string('kind', 50);
                $table->string('action', 50);
                $table->text('detail')->nullable();
                $table->timestamps();
                $table->index('job_id');
                $table->index('subdomain_id');
                $table->index('kind');
            },
            'mod_cloudflare_user_stats' => function($table) {
                $table->increments('id');
                $table->integer('userid')->unsigned();
                $table->integer('subdomains_created')->default(0);
                $table->integer('dns_records_created')->default(0);
                $table->integer('dns_records_updated')->default(0);
                $table->integer('dns_records_deleted')->default(0);
                $table->dateTime('last_activity')->nullable();
                $table->timestamps();
                $table->index('userid');
            },
            'mod_cloudflare_user_bans' => function($table) {
                $table->increments('id');
                $table->integer('userid')->unsigned();
                $table->text('ban_reason');
                $table->string('banned_by', 100);
                $table->dateTime('banned_at');
                $table->dateTime('unbanned_at')->nullable();
                $table->string('status', 20)->default('banned');
                $table->string('ban_type', 20)->default('permanent');
                $table->dateTime('ban_expires_at')->nullable();
                $table->timestamps();
                $table->index('userid');
                $table->index('status');
                $table->index('banned_at');
            }
        ];
        
        foreach ($tables_to_check as $table_name => $table_definition) {
            if (!Capsule::schema()->hasTable($table_name)) {
                Capsule::schema()->create($table_name, $table_definition);
            }
        }

        if (Capsule::schema()->hasTable('mod_cloudflare_subdomain')) {
            try {
                if (!Capsule::schema()->hasColumn('mod_cloudflare_subdomain', 'expires_at')) {
                    Capsule::schema()->table('mod_cloudflare_subdomain', function ($table) {
                        $table->dateTime('expires_at')->nullable();
                    });
                }
                if (!Capsule::schema()->hasColumn('mod_cloudflare_subdomain', 'renewed_at')) {
                    Capsule::schema()->table('mod_cloudflare_subdomain', function ($table) {
                        $table->dateTime('renewed_at')->nullable();
                    });
                }
                if (!Capsule::schema()->hasColumn('mod_cloudflare_subdomain', 'auto_deleted_at')) {
                    Capsule::schema()->table('mod_cloudflare_subdomain', function ($table) {
                        $table->dateTime('auto_deleted_at')->nullable();
                    });
                }
                if (!Capsule::schema()->hasColumn('mod_cloudflare_subdomain', 'never_expires')) {
                    Capsule::schema()->table('mod_cloudflare_subdomain', function ($table) {
                        $table->boolean('never_expires')->default(0);
                    });
                }
                if (!Capsule::schema()->hasColumn('mod_cloudflare_subdomain', 'gift_lock_id')) {
                    Capsule::schema()->table('mod_cloudflare_subdomain', function ($table) {
                        $table->integer('gift_lock_id')->unsigned()->nullable()->after('notes');
                        $table->index('gift_lock_id');
                    });
                } elseif (!cf_index_exists('mod_cloudflare_subdomain', 'mod_cloudflare_subdomain_gift_lock_id_index')) {
                    Capsule::schema()->table('mod_cloudflare_subdomain', function ($table) {
                        $table->index('gift_lock_id');
                    });
                }
                if (!Capsule::schema()->hasColumn('mod_cloudflare_subdomain', 'provider_account_id')) {
                    Capsule::schema()->table('mod_cloudflare_subdomain', function ($table) {
                        $table->integer('provider_account_id')->unsigned()->nullable()->after('rootdomain');
                        $table->index('provider_account_id');
                    });
                } elseif (!cf_index_exists('mod_cloudflare_subdomain', 'mod_cloudflare_subdomain_provider_account_id_index')) {
                    Capsule::schema()->table('mod_cloudflare_subdomain', function ($table) {
                        $table->index('provider_account_id');
                    });
                }
                if (!cf_index_exists('mod_cloudflare_subdomain', 'idx_expiry_status')) {
                    Capsule::statement('ALTER TABLE `mod_cloudflare_subdomain` ADD INDEX `idx_expiry_status` (`expires_at`, `status`)');
                }
            } catch (\Exception $e) {}
            try {
                Capsule::table('mod_cloudflare_subdomain')
                    ->whereNull('expires_at')
                    ->update(['never_expires' => 1]);
            } catch (\Exception $e) {}
        }
        try {
            $defaultProviderIdSetting = cf_get_module_settings_cached()['default_provider_account_id'] ?? null;
            if (is_numeric($defaultProviderIdSetting) && (int)$defaultProviderIdSetting > 0) {
                Capsule::table('mod_cloudflare_subdomain')
                    ->whereNull('provider_account_id')
                    ->update(['provider_account_id' => (int) $defaultProviderIdSetting]);
            }
        } catch (\Throwable $ignored) {}

        if (Capsule::schema()->hasTable('mod_cloudflare_rootdomains')) {
            try {
                if (!Capsule::schema()->hasColumn('mod_cloudflare_rootdomains', 'per_user_limit')) {
                    Capsule::schema()->table('mod_cloudflare_rootdomains', function ($table) {
                        $table->integer('per_user_limit')->default(0)->after('max_subdomains');
                    });
                }
                if (!Capsule::schema()->hasColumn('mod_cloudflare_rootdomains', 'provider_account_id')) {
                    Capsule::schema()->table('mod_cloudflare_rootdomains', function ($table) {
                        $table->integer('provider_account_id')->unsigned()->nullable()->after('domain');
                        $table->index('provider_account_id');
                    });
                } elseif (!cf_index_exists('mod_cloudflare_rootdomains', 'mod_cloudflare_rootdomains_provider_account_id_index')) {
                    Capsule::schema()->table('mod_cloudflare_rootdomains', function ($table) {
                        $table->index('provider_account_id');
                    });
                }
            } catch (\Exception $e) {}
        }
        try {
            $defaultProviderIdSetting = cf_get_module_settings_cached()['default_provider_account_id'] ?? null;
            if (is_numeric($defaultProviderIdSetting) && (int)$defaultProviderIdSetting > 0) {
                Capsule::table('mod_cloudflare_rootdomains')
                    ->whereNull('provider_account_id')
                    ->update(['provider_account_id' => (int) $defaultProviderIdSetting]);
            }
        } catch (\Throwable $ignored) {}

        // 风险表（升级路径）
        if (!Capsule::schema()->hasTable('mod_cloudflare_domain_risk')) {
            Capsule::schema()->create('mod_cloudflare_domain_risk', function ($table) {
                $table->increments('id');
                $table->integer('subdomain_id')->unsigned();
                $table->integer('risk_score')->default(0);
                $table->string('risk_level', 16)->default('low');
                $table->text('reasons_json')->nullable();
                $table->dateTime('last_checked_at')->nullable();
                $table->timestamps();
                $table->unique('subdomain_id');
                $table->index(['risk_score','risk_level']);
            });
        }
        if (!Capsule::schema()->hasTable('mod_cloudflare_risk_events')) {
            Capsule::schema()->create('mod_cloudflare_risk_events', function ($table) {
                $table->increments('id');
                $table->integer('subdomain_id')->unsigned();
                $table->string('source', 32);
                $table->integer('score')->default(0);
                $table->string('level', 16)->default('low');
                $table->string('reason', 255)->nullable();
                $table->text('details_json')->nullable();
                $table->timestamps();
                $table->index(['subdomain_id','created_at']);
                $table->index(['level','created_at']);
            });
        }

        if (!Capsule::schema()->hasTable('mod_cloudflare_whois_rate_limit')) {
            Capsule::schema()->create('mod_cloudflare_whois_rate_limit', function ($table) {
                $table->increments('id');
                $table->string('ip', 45);
                $table->string('window_key', 64);
                $table->integer('request_count')->default(0);
                $table->dateTime('window_start');
                $table->dateTime('window_end');
                $table->timestamps();
                $table->unique(['ip', 'window_key'], 'uniq_cf_whois_ip_window');
                $table->index('window_end');
            });
        } else {
            if (!cf_index_exists('mod_cloudflare_whois_rate_limit', 'uniq_cf_whois_ip_window')) {
                Capsule::statement('ALTER TABLE `mod_cloudflare_whois_rate_limit` ADD UNIQUE INDEX `uniq_cf_whois_ip_window` (`ip`, `window_key`)');
            }
        }
        
        if (Capsule::schema()->hasTable('mod_cloudflare_dns_records')) {
            if (!Capsule::schema()->hasColumn('mod_cloudflare_dns_records', 'priority')) {
                Capsule::schema()->table('mod_cloudflare_dns_records', function($table) {
                    $table->integer('priority')->nullable()->after('proxied');
                });
            }
            if (!Capsule::schema()->hasColumn('mod_cloudflare_dns_records', 'line')) {
                Capsule::schema()->table('mod_cloudflare_dns_records', function($table) {
                    $table->string('line', 32)->nullable()->after('proxied');
                });
            }
        }
        
        try {
            cfmod_sync_default_provider_account(cf_get_module_settings_cached());
        } catch (\Throwable $ignored) {
        }
        
        return ['status' => 'success', 'description' => '升级完成，新增数据表已校验/创建'];
    } catch (\Exception $e) {
        return ['status' => 'error', 'description' => '升级失败: '.$e->getMessage()];
    }
}

if (!function_exists('cloudflare_subdomain_config')) {
    function cloudflare_subdomain_config() {
        return domain_hub_config();
    }
}
if (!function_exists('cloudflare_subdomain_activate')) {
    function cloudflare_subdomain_activate() {
        return domain_hub_activate();
    }
}
if (!function_exists('cloudflare_subdomain_deactivate')) {
    function cloudflare_subdomain_deactivate() {
        return domain_hub_deactivate();
    }
}
if (!function_exists('cloudflare_subdomain_uninstall')) {
    function cloudflare_subdomain_uninstall() {
        return domain_hub_uninstall();
    }
}
if (!function_exists('cloudflare_subdomain_adminlink')) {
    function cloudflare_subdomain_adminlink($vars) {
        return domain_hub_adminlink($vars);
    }
}
if (!function_exists('cloudflare_subdomain_output')) {
    function cloudflare_subdomain_output($vars) {
        return domain_hub_output($vars);
    }
}
if (!function_exists('cloudflare_subdomain_upgrade')) {
    function cloudflare_subdomain_upgrade($vars) {
        return domain_hub_upgrade($vars);
    }
}

CfHookRegistrar::registerAll();


