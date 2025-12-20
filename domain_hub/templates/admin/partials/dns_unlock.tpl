<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$moduleSlug = $moduleSlug ?? (defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub');
$dnsUnlockView = $dnsUnlockView ?? ($cfAdminViewModel['dnsUnlock'] ?? []);
$enabled = !empty($dnsUnlockView['enabled']);
$stats = $dnsUnlockView['stats'] ?? [];
$logsMeta = $dnsUnlockView['logs'] ?? [];
$logs = $logsMeta['items'] ?? [];
$page = max(1, intval($logsMeta['page'] ?? 1));
$totalPages = max(1, intval($logsMeta['totalPages'] ?? 1));
$totalLogs = intval($logsMeta['total'] ?? (is_countable($logs) ? count($logs) : 0));
$searchKeyword = trim((string) ($dnsUnlockView['search']['keyword'] ?? ''));

$cardTitle = $lang['dns_unlock_card_title'] ?? 'DNS 解锁控制';
$toggleLabel = $lang['dns_unlock_enable_label'] ?? '启用 DNS 解锁码功能';
$toggleHint = $lang['dns_unlock_enable_hint'] ?? '启用后，前台用户需先完成一次解锁才能管理 NS 记录。';
$saveLabel = $lang['dns_unlock_save_button'] ?? '保存设置';
$statsCodesLabel = $lang['dns_unlock_stats_codes'] ?? '已生成解锁码';
$statsUnlockedLabel = $lang['dns_unlock_stats_unlocked'] ?? '已解锁用户';
$statsLogsLabel = $lang['dns_unlock_stats_logs'] ?? '累计解锁记录';
$logsTitle = $lang['dns_unlock_logs_title'] ?? 'DNS 解锁日志';
$searchPlaceholder = $lang['dns_unlock_logs_search_placeholder'] ?? '按邮箱或解锁码搜索';
$searchButton = $lang['dns_unlock_logs_search_button'] ?? '搜索';
$headerCode = $lang['dns_unlock_logs_header_code'] ?? '解锁码';
$headerOwner = $lang['dns_unlock_logs_header_owner'] ?? '解锁码所属用户';
$headerUnlocker = $lang['dns_unlock_logs_header_unlocker'] ?? '使用者';
$headerTime = $lang['dns_unlock_logs_header_time'] ?? '使用时间';
$headerIp = $lang['dns_unlock_logs_header_ip'] ?? 'IP 地址';
$emptyText = $lang['dns_unlock_logs_empty'] ?? '暂无解锁记录';
$prevLabel = $lang['common_prev'] ?? '上一页';
$nextLabel = $lang['common_next'] ?? '下一页';
$paginationText = $lang['dns_unlock_logs_pagination'] ?? '第 %1$d/%2$d 页，共 %3$d 条';

$totalCodes = intval($stats['totalCodes'] ?? 0);
$totalUnlocked = intval($stats['totalUnlocked'] ?? 0);
$statsLogsCount = intval($stats['totalLogs'] ?? $totalLogs);

$paginationBase = ['module' => $moduleSlug];
if ($searchKeyword !== '') {
    $paginationBase['dns_unlock_kw'] = $searchKeyword;
}
$buildDnsUnlockAdminUrl = static function (int $targetPage) use ($paginationBase): string {
    $params = $paginationBase;
    $params['dns_unlock_log_page'] = max(1, $targetPage);
    return '?' . http_build_query($params) . '#dnsUnlock';
};
?>
<div class="card mb-4" id="dnsUnlock">
    <div class="card-header d-flex justify-content-between align-items-center">
        <h5 class="mb-0"><i class="fas fa-unlock-alt text-warning me-2"></i><?php echo htmlspecialchars($cardTitle, ENT_QUOTES, 'UTF-8'); ?></h5>
    </div>
    <div class="card-body">
        <form method="post" class="mb-3">
            <input type="hidden" name="action" value="save_dns_unlock_settings">
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" name="enable_dns_unlock" id="dnsUnlockSwitch" value="1" <?php echo $enabled ? 'checked' : ''; ?>>
                <label class="form-check-label" for="dnsUnlockSwitch"><?php echo htmlspecialchars($toggleLabel, ENT_QUOTES, 'UTF-8'); ?></label>
            </div>
            <div class="form-text text-muted mb-2"><?php echo htmlspecialchars($toggleHint, ENT_QUOTES, 'UTF-8'); ?></div>
            <button type="submit" class="btn btn-primary btn-sm"><?php echo htmlspecialchars($saveLabel, ENT_QUOTES, 'UTF-8'); ?></button>
        </form>

        <div class="row text-center mb-4 g-3">
            <div class="col-md-4">
                <div class="border rounded p-3 h-100">
                    <div class="small text-muted"><?php echo htmlspecialchars($statsCodesLabel, ENT_QUOTES, 'UTF-8'); ?></div>
                    <div class="h3 mb-0"><?php echo $totalCodes; ?></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="border rounded p-3 h-100">
                    <div class="small text-muted"><?php echo htmlspecialchars($statsUnlockedLabel, ENT_QUOTES, 'UTF-8'); ?></div>
                    <div class="h3 mb-0"><?php echo $totalUnlocked; ?></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="border rounded p-3 h-100">
                    <div class="small text-muted"><?php echo htmlspecialchars($statsLogsLabel, ENT_QUOTES, 'UTF-8'); ?></div>
                    <div class="h3 mb-0"><?php echo $statsLogsCount; ?></div>
                </div>
            </div>
        </div>

        <h6 class="fw-bold mb-3"><?php echo htmlspecialchars($logsTitle, ENT_QUOTES, 'UTF-8'); ?></h6>
        <form method="get" class="row g-2 align-items-center mb-3">
            <input type="hidden" name="module" value="<?php echo htmlspecialchars($moduleSlug, ENT_QUOTES, 'UTF-8'); ?>">
            <div class="col-md-4">
                <input type="text" class="form-control" name="dns_unlock_kw" placeholder="<?php echo htmlspecialchars($searchPlaceholder, ENT_QUOTES, 'UTF-8'); ?>" value="<?php echo htmlspecialchars($searchKeyword, ENT_QUOTES, 'UTF-8'); ?>">
            </div>
            <div class="col-auto">
                <button type="submit" class="btn btn-secondary"><?php echo htmlspecialchars($searchButton, ENT_QUOTES, 'UTF-8'); ?></button>
            </div>
        </form>

        <div class="table-responsive">
            <table class="table table-sm table-striped align-middle">
                <thead>
                    <tr>
                        <th class="text-nowrap">ID</th>
                        <th class="text-nowrap"><?php echo htmlspecialchars($headerCode, ENT_QUOTES, 'UTF-8'); ?></th>
                        <th class="text-nowrap"><?php echo htmlspecialchars($headerOwner, ENT_QUOTES, 'UTF-8'); ?></th>
                        <th class="text-nowrap"><?php echo htmlspecialchars($headerUnlocker, ENT_QUOTES, 'UTF-8'); ?></th>
                        <th class="text-nowrap"><?php echo htmlspecialchars($headerTime, ENT_QUOTES, 'UTF-8'); ?></th>
                        <th class="text-nowrap"><?php echo htmlspecialchars($headerIp, ENT_QUOTES, 'UTF-8'); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (!empty($logs)): ?>
                    <?php foreach ($logs as $row): ?>
                        <tr>
                            <td class="text-muted small"><?php echo intval($row['id'] ?? 0); ?></td>
                            <td><code><?php echo htmlspecialchars($row['unlockCode'] ?? '-', ENT_QUOTES, 'UTF-8'); ?></code></td>
                            <td>
                                <?php echo htmlspecialchars($row['ownerEmail'] ?? '-', ENT_QUOTES, 'UTF-8'); ?>
                                <?php if (!empty($row['ownerUserId'])): ?>
                                    <div class="text-muted small">ID: <?php echo intval($row['ownerUserId']); ?></div>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php echo htmlspecialchars($row['unlockerEmail'] ?? '-', ENT_QUOTES, 'UTF-8'); ?>
                                <?php if (!empty($row['unlockerUserId'])): ?>
                                    <div class="text-muted small">ID: <?php echo intval($row['unlockerUserId']); ?></div>
                                <?php endif; ?>
                            </td>
                            <td class="text-muted small"><?php echo htmlspecialchars($row['unlockedAt'] ?? '-', ENT_QUOTES, 'UTF-8'); ?></td>
                            <td class="text-muted small"><?php echo htmlspecialchars($row['clientIp'] ?? '-', ENT_QUOTES, 'UTF-8'); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="6" class="text-center text-muted py-3"><?php echo htmlspecialchars($emptyText, ENT_QUOTES, 'UTF-8'); ?></td>
                    </tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>

        <?php if ($totalPages > 1): ?>
        <div class="d-flex justify-content-between align-items-center mt-3 flex-wrap gap-2">
            <div class="text-muted small"><?php echo sprintf($paginationText, $page, $totalPages, $totalLogs); ?></div>
            <nav>
                <ul class="pagination pagination-sm mb-0">
                    <li class="page-item <?php echo $page <= 1 ? 'disabled' : ''; ?>">
                        <a class="page-link" href="<?php echo $page <= 1 ? 'javascript:void(0);' : htmlspecialchars($buildDnsUnlockAdminUrl($page - 1), ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($prevLabel, ENT_QUOTES, 'UTF-8'); ?></a>
                    </li>
                    <li class="page-item <?php echo $page >= $totalPages ? 'disabled' : ''; ?>">
                        <a class="page-link" href="<?php echo $page >= $totalPages ? 'javascript:void(0);' : htmlspecialchars($buildDnsUnlockAdminUrl($page + 1), ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($nextLabel, ENT_QUOTES, 'UTF-8'); ?></a>
                    </li>
                </ul>
            </nav>
        </div>
        <?php endif; ?>
    </div>
</div>
