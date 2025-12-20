<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfDnsUnlockException extends \RuntimeException
{
    private string $reason;

    public function __construct(string $reason, string $message = '', ?\Throwable $previous = null)
    {
        $this->reason = $reason;
        parent::__construct($message !== '' ? $message : $reason, 0, $previous);
    }

    public function getReason(): string
    {
        return $this->reason;
    }
}

class CfDnsUnlockService
{
    private const CODE_LENGTH = 8;

    private static ?self $instance = null;

    private function __construct()
    {
    }

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public static function ensureSchema(): void
    {
        try {
            $schema = Capsule::schema();

            if (!$schema->hasTable('mod_cloudflare_dns_unlock_codes')) {
                $schema->create('mod_cloudflare_dns_unlock_codes', static function ($table): void {
                    $table->increments('id');
                    $table->integer('userid')->unsigned()->unique();
                    $table->string('unlock_code', 32)->unique();
                    $table->string('status', 20)->default('active');
                    $table->timestamps();
                    $table->index('status');
                });
            } else {
                if (!$schema->hasColumn('mod_cloudflare_dns_unlock_codes', 'status')) {
                    $schema->table('mod_cloudflare_dns_unlock_codes', static function ($table): void {
                        $table->string('status', 20)->default('active')->after('unlock_code');
                    });
                }
                if (!cf_index_exists('mod_cloudflare_dns_unlock_codes', 'mod_cloudflare_dns_unlock_codes_status_index')) {
                    $schema->table('mod_cloudflare_dns_unlock_codes', static function ($table): void {
                        $table->index('status');
                    });
                }
            }

            if (!$schema->hasTable('mod_cloudflare_dns_unlock_status')) {
                $schema->create('mod_cloudflare_dns_unlock_status', static function ($table): void {
                    $table->increments('id');
                    $table->integer('userid')->unsigned()->unique();
                    $table->integer('unlocked_by_code_id')->unsigned()->nullable();
                    $table->integer('unlocked_by_userid')->unsigned()->nullable();
                    $table->dateTime('unlocked_at');
                    $table->timestamps();
                    $table->index('unlocked_by_userid');
                });
            } else {
                if (!$schema->hasColumn('mod_cloudflare_dns_unlock_status', 'unlocked_by_code_id')) {
                    $schema->table('mod_cloudflare_dns_unlock_status', static function ($table): void {
                        $table->integer('unlocked_by_code_id')->unsigned()->nullable()->after('userid');
                    });
                }
                if (!$schema->hasColumn('mod_cloudflare_dns_unlock_status', 'unlocked_by_userid')) {
                    $schema->table('mod_cloudflare_dns_unlock_status', static function ($table): void {
                        $table->integer('unlocked_by_userid')->unsigned()->nullable()->after('unlocked_by_code_id');
                    });
                }
                if (!$schema->hasColumn('mod_cloudflare_dns_unlock_status', 'unlocked_at')) {
                    $schema->table('mod_cloudflare_dns_unlock_status', static function ($table): void {
                        $table->dateTime('unlocked_at')->after('unlocked_by_userid');
                    });
                }
                if (!cf_index_exists('mod_cloudflare_dns_unlock_status', 'mod_cloudflare_dns_unlock_status_unlocked_by_userid_index')) {
                    $schema->table('mod_cloudflare_dns_unlock_status', static function ($table): void {
                        $table->index('unlocked_by_userid');
                    });
                }
            }

            if (!$schema->hasTable('mod_cloudflare_dns_unlock_logs')) {
                $schema->create('mod_cloudflare_dns_unlock_logs', static function ($table): void {
                    $table->increments('id');
                    $table->integer('code_id')->unsigned();
                    $table->integer('code_owner_userid')->unsigned();
                    $table->integer('unlocked_userid')->unsigned();
                    $table->string('unlock_code', 32);
                    $table->dateTime('unlocked_at');
                    $table->string('client_ip', 45)->nullable();
                    $table->timestamps();
                    $table->index('code_id');
                    $table->index('code_owner_userid');
                    $table->index('unlocked_userid');
                    $table->index('unlock_code');
                    $table->index('unlocked_at');
                });
            } else {
                if (!$schema->hasColumn('mod_cloudflare_dns_unlock_logs', 'client_ip')) {
                    $schema->table('mod_cloudflare_dns_unlock_logs', static function ($table): void {
                        $table->string('client_ip', 45)->nullable()->after('unlocked_at');
                    });
                }
                if (!cf_index_exists('mod_cloudflare_dns_unlock_logs', 'mod_cloudflare_dns_unlock_logs_unlocked_at_index')) {
                    $schema->table('mod_cloudflare_dns_unlock_logs', static function ($table): void {
                        $table->index('unlocked_at');
                    });
                }
            }
        } catch (\Throwable $e) {
            // ignore schema errors to avoid breaking runtime
        }
    }

    public function isEnabled(?array $settings = null): bool
    {
        if ($settings === null) {
            $settings = $this->loadModuleSettings();
        }

        return cfmod_setting_enabled($settings['enable_dns_unlock'] ?? '0');
    }

    public function ensureUserCode(int $userId): array
    {
        self::ensureSchema();

        $row = Capsule::table('mod_cloudflare_dns_unlock_codes')
            ->where('userid', $userId)
            ->first();

        if ($row) {
            return (array) $row;
        }

        $code = $this->generateUniqueCode();
        $now = date('Y-m-d H:i:s');
        $id = Capsule::table('mod_cloudflare_dns_unlock_codes')->insertGetId([
            'userid' => $userId,
            'unlock_code' => $code,
            'status' => 'active',
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        return [
            'id' => $id,
            'userid' => $userId,
            'unlock_code' => $code,
            'status' => 'active',
            'created_at' => $now,
            'updated_at' => $now,
        ];
    }

    public function getUserStatus(int $userId): array
    {
        self::ensureSchema();

        $row = Capsule::table('mod_cloudflare_dns_unlock_status')
            ->where('userid', $userId)
            ->first();

        if (!$row) {
            return [
                'is_unlocked' => false,
                'unlocked_at' => null,
                'unlock_by_userid' => null,
                'unlock_by_code_id' => null,
            ];
        }

        return [
            'is_unlocked' => true,
            'unlocked_at' => $row->unlocked_at ?? null,
            'unlock_by_userid' => $row->unlocked_by_userid ?? null,
            'unlock_by_code_id' => $row->unlocked_by_code_id ?? null,
        ];
    }

    public function unlockUserWithCode(int $userId, string $codeInput, string $clientIp = ''): array
    {
        self::ensureSchema();

        $code = strtoupper(trim($codeInput));
        if ($code === '') {
            throw new CfDnsUnlockException('empty_code');
        }
        if (!preg_match('/^[A-Z0-9]{8}$/', $code)) {
            throw new CfDnsUnlockException('invalid_code');
        }

        $now = date('Y-m-d H:i:s');

        $result = Capsule::connection()->transaction(function () use ($userId, $code, $clientIp, $now) {
            $codeRow = Capsule::table('mod_cloudflare_dns_unlock_codes')
                ->where('unlock_code', $code)
                ->lockForUpdate()
                ->first();

            if (!$codeRow) {
                throw new CfDnsUnlockException('code_not_found');
            }

            $ownerUserId = (int) ($codeRow->userid ?? 0);
            if ($ownerUserId === $userId) {
                throw new CfDnsUnlockException('self_code');
            }

            $owner = Capsule::table('tblclients')->select('id')->where('id', $ownerUserId)->first();
            if (!$owner) {
                throw new CfDnsUnlockException('code_owner_missing');
            }

            $targetUser = Capsule::table('tblclients')->select('id')->where('id', $userId)->first();
            if (!$targetUser) {
                throw new CfDnsUnlockException('user_missing');
            }

            $statusRow = Capsule::table('mod_cloudflare_dns_unlock_status')
                ->where('userid', $userId)
                ->lockForUpdate()
                ->first();

            $alreadyUnlocked = $statusRow !== null;
            $primaryUnlockAt = $alreadyUnlocked ? ($statusRow->unlocked_at ?? $now) : $now;

            if (!$alreadyUnlocked) {
                Capsule::table('mod_cloudflare_dns_unlock_status')->insert([
                    'userid' => $userId,
                    'unlocked_by_code_id' => $codeRow->id,
                    'unlocked_by_userid' => $ownerUserId,
                    'unlocked_at' => $now,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
            }

            Capsule::table('mod_cloudflare_dns_unlock_logs')->insert([
                'code_id' => $codeRow->id,
                'code_owner_userid' => $ownerUserId,
                'unlocked_userid' => $userId,
                'unlock_code' => $codeRow->unlock_code,
                'unlocked_at' => $now,
                'client_ip' => $clientIp !== '' ? substr($clientIp, 0, 45) : null,
                'created_at' => $now,
                'updated_at' => $now,
            ]);

            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('client_dns_unlock', [
                    'code_owner_userid' => $ownerUserId,
                    'unlock_code' => $codeRow->unlock_code,
                    'already_unlocked' => $alreadyUnlocked ? 1 : 0,
                ], $userId, null);
            }

            return [
                'alreadyUnlocked' => $alreadyUnlocked,
                'unlockedAt' => $primaryUnlockAt,
                'codeOwnerId' => $ownerUserId,
                'unlockCode' => $codeRow->unlock_code,
            ];
        });

        return $result;
    }

    public function getLogsForCodeOwner(int $ownerUserId, int $page = 1, int $perPage = 10): array
    {
        self::ensureSchema();
        $page = max(1, $page);
        $perPage = max(1, $perPage);

        $baseQuery = Capsule::table('mod_cloudflare_dns_unlock_logs as l')
            ->leftJoin('tblclients as u', 'l.unlocked_userid', '=', 'u.id')
            ->select('l.*', 'u.email as unlocked_email')
            ->where('l.code_owner_userid', $ownerUserId);

        $total = (clone $baseQuery)->count();
        $totalPages = max(1, (int) ceil($total / $perPage));
        if ($page > $totalPages) {
            $page = $totalPages;
        }
        $offset = ($page - 1) * $perPage;

        $items = (clone $baseQuery)
            ->orderBy('l.unlocked_at', 'desc')
            ->offset($offset)
            ->limit($perPage)
            ->get();

        $formatted = [];
        foreach ($items as $item) {
            $email = $item->unlocked_email ?? '';
            $formatted[] = [
                'userId' => (int) ($item->unlocked_userid ?? 0),
                'email' => $email,
                'maskedEmail' => function_exists('cfmod_mask_email') ? cfmod_mask_email($email) : (function_exists('cfmod_client_mask_leaderboard_email') ? cfmod_client_mask_leaderboard_email($email) : '***'),
                'unlockedAt' => $item->unlocked_at ?? '',
            ];
        }

        return [
            'items' => $formatted,
            'page' => $page,
            'perPage' => $perPage,
            'total' => $total,
            'totalPages' => $totalPages,
        ];
    }

    public function getAdminLogs(string $keyword, int $page = 1, int $perPage = 20): array
    {
        self::ensureSchema();
        $page = max(1, $page);
        $perPage = max(1, $perPage);
        $keyword = trim($keyword);

        $base = Capsule::table('mod_cloudflare_dns_unlock_logs as l')
            ->leftJoin('tblclients as owner', 'l.code_owner_userid', '=', 'owner.id')
            ->leftJoin('tblclients as unlocker', 'l.unlocked_userid', '=', 'unlocker.id')
            ->select(
                'l.*',
                'owner.email as owner_email',
                'unlocker.email as unlocker_email'
            );

        if ($keyword !== '') {
            $like = '%' . $keyword . '%';
            $base->where(static function ($query) use ($like): void {
                $query->where('l.unlock_code', 'like', $like)
                    ->orWhere('owner.email', 'like', $like)
                    ->orWhere('unlocker.email', 'like', $like);
            });
        }

        $total = (clone $base)->count();
        $totalPages = max(1, (int) ceil($total / $perPage));
        if ($page > $totalPages) {
            $page = $totalPages;
        }
        $offset = ($page - 1) * $perPage;

        $items = (clone $base)
            ->orderBy('l.unlocked_at', 'desc')
            ->offset($offset)
            ->limit($perPage)
            ->get();

        $formatted = [];
        foreach ($items as $item) {
            $formatted[] = [
                'id' => (int) ($item->id ?? 0),
                'unlockCode' => (string) ($item->unlock_code ?? ''),
                'ownerUserId' => (int) ($item->code_owner_userid ?? 0),
                'ownerEmail' => $item->owner_email ?? '',
                'unlockerUserId' => (int) ($item->unlocked_userid ?? 0),
                'unlockerEmail' => $item->unlocker_email ?? '',
                'unlockedAt' => $item->unlocked_at ?? '',
                'clientIp' => $item->client_ip ?? '',
            ];
        }

        return [
            'items' => $formatted,
            'page' => $page,
            'perPage' => $perPage,
            'total' => $total,
            'totalPages' => $totalPages,
        ];
    }

    public function getAdminStats(): array
    {
        self::ensureSchema();

        try {
            $totalCodes = Capsule::table('mod_cloudflare_dns_unlock_codes')->count();
        } catch (\Throwable $e) {
            $totalCodes = 0;
        }

        try {
            $totalUnlocked = Capsule::table('mod_cloudflare_dns_unlock_status')->count();
        } catch (\Throwable $e) {
            $totalUnlocked = 0;
        }

        try {
            $totalLogs = Capsule::table('mod_cloudflare_dns_unlock_logs')->count();
        } catch (\Throwable $e) {
            $totalLogs = 0;
        }

        return [
            'totalCodes' => $totalCodes,
            'totalUnlocked' => $totalUnlocked,
            'totalLogs' => $totalLogs,
        ];
    }

    private function loadModuleSettings(): array
    {
        if (function_exists('cf_get_module_settings_cached')) {
            $settings = cf_get_module_settings_cached();
            if (is_array($settings) && !empty($settings)) {
                return $settings;
            }
        }

        try {
            $rows = Capsule::table('tbladdonmodules')
                ->where('module', defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub')
                ->get();
            $settings = [];
            foreach ($rows as $row) {
                $settings[$row->setting] = $row->value;
            }
            return $settings;
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function generateUniqueCode(): string
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $attempts = 0;
        do {
            $code = '';
            for ($i = 0; $i < self::CODE_LENGTH; $i++) {
                $code .= $alphabet[random_int(0, strlen($alphabet) - 1)];
            }
            $exists = Capsule::table('mod_cloudflare_dns_unlock_codes')
                ->where('unlock_code', $code)
                ->exists();
            $attempts++;
        } while ($exists && $attempts < 5);

        if ($exists) {
            $code = $code . substr(strtoupper(bin2hex(random_bytes(2))), 0, 2);
        }

        return $code;
    }
}
