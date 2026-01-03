<?php
/*
Plugin Name: Advanced Security IP Blocker
Description: Продвинутая система безопасности: блокировка IP, защита wp‑login.php и xmlrpc.php, блокировка опасных файлов и ботов с поддержкой ASN, гео‑блокировки, honeypot‑страниц, интеграция с внешними черными листами, Fail2Ban, Redis, Cloudflare, Аналитикой и REST API.
Plugin URI: https://github.com/RobertoBennett/IP-Blocker-Manager
Version: 2.2.0 FINAL
Author: Robert Bennett
Text Domain: ip-blocker-manager
*/

defined('ABSPATH') || exit;

// Обновление версии плагина
if (!defined('ASB_BLOCKER_VERSION')) {
    define('ASB_BLOCKER_VERSION', '2.2.0 FINAL');
}

/* ============================================================
   Основной класс плагина
============================================================ */
class Advanced_Security_Blocker {

    /* ----------------------------------------------------------
   Основные свойства
---------------------------------------------------------- */
private $htaccess_path;
private $marker_ip      = '# IP_BLOCKER_SAFE_MARKER';
private $marker_login   = '# LOGIN_PROTECTION_MARKER';
private $marker_files   = '# DANGEROUS_FILES_MARKER';
private $marker_bots    = '# BOT_PROTECTION_MARKER';
private $marker_honeypot= '# HONEYPOT_PROTECTION_MARKER';
private $marker_nginx   = '# NGINX_RULES_MARKER';
// Новый маркер для Myip.ms
private $marker_myipms  = '# MYIPMS_BLACKLIST_MARKER';

private $backup_dir;
private $cache_dir;
public $log = []; // Сделано public для доступа из REST API
private $cache_handler;
private $geo_reader;
private $redis;

// Файл для хранения IP списка Myip.ms в режиме WP
private $myipms_list_file;

// Ключи настроек Cloudflare
private $cf_email_key   = 'asb_cloudflare_email';
private $cf_api_key     = 'asb_cloudflare_api_key';
private $cf_zone_id     = 'asb_cloudflare_zone_id';

// Ключ для журнала атак
const ASB_ATTACK_LOG_KEY = 'asb_attack_log';

/* ----------------------------------------------------------
   Конструктор – регистрация хуков
---------------------------------------------------------- */
public function __construct() {
    $this->htaccess_path = ABSPATH . '.htaccess';
    $this->backup_dir    = WP_CONTENT_DIR . '/security-blocker-backups/';
    $this->cache_dir     = WP_CONTENT_DIR . '/security-blocker-cache/';
    $this->myipms_list_file = WP_CONTENT_DIR . '/asb-myipms-blocked.txt'; // Файл для WP режима
    $this->cache_handler = new ASB_Cache_Handler();

    // Хуки WordPress
    add_action('admin_menu',            [$this, 'admin_menu']);
    add_action('admin_init',            [$this, 'create_backup_dir']);
    add_action('admin_init',            [$this, 'init_default_settings']);
    add_action('admin_init',            [$this, 'handle_backup_request']);
    add_action('admin_init',            [$this, 'handle_cache_clear']);
    add_action('admin_init',            [$this, 'handle_unblock_request']);
    add_action('admin_init',            [$this, 'handle_manual_block_request']);
    add_action('admin_init',            [$this, 'handle_whitelist_request']);
    add_action('admin_init',            [$this, 'generate_nginx_fragment']);
    add_action('admin_init',            [$this, 'check_and_create_tables']);
    add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
    
    // Хук CRON для Myip.ms
    add_action('asb_myipms_update_event', [$this, 'process_myipms_update']);

    // Хук для загрузки GeoIP перенесен в admin_init для безопасности
    add_action('admin_init',            [$this, 'init_geo_reader_download']);

    // Защита от брутфорса
    add_action('wp_login_failed',       [$this, 'handle_failed_login']);
    add_action('wp_authenticate_user',  [$this, 'check_blocked_ip'], 10, 2);
    add_action('init',                  [$this, 'init_brute_force_protection']);
    add_action('init',                  [$this, 'check_ip_access'], 1);
    add_action('init',                  [$this, 'honeypot_init']);
    add_action('template_redirect',     [$this, 'template_redirect']);

    // AJAX‑обработчики
    add_action('wp_ajax_asb_get_login_stats',       [$this, 'ajax_get_login_stats']);
    add_action('wp_ajax_asb_get_recent_attempts',   [$this, 'ajax_get_recent_attempts']);
    add_action('wp_ajax_asb_get_block_history',     [$this, 'ajax_get_block_history']);
    add_action('wp_ajax_asb_get_blocked_ips_table', [$this, 'ajax_get_blocked_ips_table']);
	add_action('wp_ajax_asb_batch_block_ip', 		[$this, 'ajax_batch_block_ip']);
    // AJAX для ручного запуска обновления Myip.ms
    add_action('wp_ajax_asb_run_myipms_update',     [$this, 'ajax_run_myipms_update']);

    // Таблицы БД
    register_activation_hook(__FILE__, [$this, 'create_login_attempts_table']);
    register_activation_hook(__FILE__, [$this, 'create_unblock_history_table']);

    // Деактивация / Удаление
    register_deactivation_hook(__FILE__, [$this, 'deactivate']);
    register_uninstall_hook(__FILE__,    [__CLASS__, 'uninstall']);

    // Инициализация вспомогательных компонентов (только чтение, скачивание - отдельно)
    $this->init_geo_reader_instance();
    $this->init_redis_client();

    // REST API
    add_action('rest_api_init', [$this, 'register_rest_routes']);

    // Регистрация настроек Cloudflare
    add_action('admin_init', [$this, 'asb_register_settings']);
    
    // Подключение скриптов для страницы аналитики
    add_action('admin_enqueue_scripts', [$this, 'enqueue_analytics_scripts']);
}

/* ==========================================================
   0. Инициализация и настройки по умолчанию
   ========================================================== */

public function init_default_settings() {
    $defaults = [
        'asb_brute_force_enabled'      => '1',
        'asb_max_attempts'             => '5',
        'asb_time_window'              => '15',
        'asb_block_duration'           => '60',
        'asb_auto_add_to_htaccess'     => '1',
        'asb_email_notifications'      => '0',
        'asb_fail2ban_enabled'         => '0',
        'asb_external_blacklist'       => '0',
        'asb_clear_cache_enabled'      => '1',
        'asb_redis_shared_blocklist'   => '0',
        'asb_rate_limit_enabled'       => '0',
        'asb_geo_block_countries'      => '',
        'asb_telegram_token'           => '',
        'asb_telegram_chat_id'         => '',
        'asb_cloudflare_email'         => '',
        'asb_cloudflare_api_key'       => '',
        'asb_cloudflare_zone_id'       => '',
        // Настройки Myip.ms
        'asb_myipms_enabled'           => '0',
        'asb_myipms_mode'              => 'htaccess', // 'htaccess' или 'wp'
        'asb_myipms_last_update'       => 'Никогда'
    ];

    foreach ($defaults as $key => $value) {
        if (get_option($key) === false) {
            add_option($key, $value);
        }
    }
}

    /**
     * Логика скачивания БД GeoIP (вынесена отдельно для безопасности)
     */
    public function init_geo_reader_download() {
        $db_file = $this->cache_dir . 'GeoLite2-Country.mmdb';
        if (!file_exists($db_file)) {
            // Подключаем необходимые файлы для работы download_url
            if (!function_exists('download_url')) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
            }
            
            $url = 'https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz';
            $tmp = download_url($url);
            
            if (!is_wp_error($tmp)) {
                try {
                    $phar = new PharData($tmp);
                    $phar->extractTo($this->cache_dir, null, true);
                    @unlink($tmp);
                } catch (Exception $e) {
                    error_log('ASB: Ошибка распаковки GeoIP: ' . $e->getMessage());
                }
            }
        }
    }

    /**
     * Инициализация объекта Reader (только если файл существует)
     */
    private function init_geo_reader_instance() {
        // Локальный Reader больше не используется
    }

    private function init_redis_client() {
        if (class_exists('Redis')) {
            $redis = new Redis();
            try {
                if ($redis->connect('127.0.0.1', 6379, 1.5)) {
                    $this->redis = $redis;
                }
            } catch (Exception $e) {
                // Redis недоступен, продолжаем без него
            }
        }
    }

    public function init_brute_force_protection() {
        // Заглушка для init-хука, если нужна отдельная логика
    }

   /* ==========================================================
   1. UI и стили
   ========================================================== */

    public function admin_menu() {
        add_options_page(
            'Продвинутая безопасность',
            'Безопасность',
            'manage_options',
            'advanced-security-blocker',
            [$this, 'settings_page']
        );
        
        // Добавляем подменю для аналитики и Cloudflare
        add_submenu_page(
            'options-general.php',
            'Аналитика атак',
            'Аналитика атак',
            'manage_options',
            'asb-analytics',
            [$this, 'analytics_page']
        );
        
        add_submenu_page(
            'options-general.php',
            'Cloudflare интеграция',
            'Cloudflare',
            'manage_options',
            'asb-cloudflare',
            [$this, 'cloudflare_settings_page']
        );
    }

    private function output_admin_styles() {
        ?>
        <style>
        .security-tabs{margin:20px 0}
        .security-tab-nav{border-bottom:1px solid #ccc;margin-bottom:20px;background:#f9f9f9;padding:0}
        .security-tab-nav button{display:inline-block;padding:12px 20px;border:none;background:#f1f1f1;color:#333;cursor:pointer;margin-right:2px;font-size:14px;border-top:3px solid transparent}
        .security-tab-nav button:hover{background:#e8e8e8}
        .security-tab-nav button.active{background:#fff;border-top:3px solid #0073aa;color:#0073aa;font-weight:600}
        .security-tab-content{display:none;padding:20px 0}
        .security-tab-content.active{display:block}
        .ip-blocker-textarea-wrapper{position:relative;width:100%;max-width:800px;display:block;clear:both}
        .ip-blocker-line-numbers{position:absolute;left:0;top:1px;bottom:1px;width:45px;overflow:hidden;background:#f5f5f5;border-right:1px solid #ddd;text-align:right;padding:11px 8px 11px 5px;font-family:Consolas,Monaco,monospace;font-size:13px;line-height:1.4;color:#666;user-select:none;pointer-events:none;z-index:1;box-sizing:border-box}
        .ip-blocker-textarea-wrapper textarea{padding:10px 10px 10px 55px!important;box-sizing:border-box;font-family:Consolas,Monaco,monospace;font-size:13px;line-height:1.4;width:100%;resize:vertical;border:1px solid #ddd;border-radius:3px;background:#fff}
        .simple-textarea{width:100%;max-width:800px;font-family:Consolas,Monaco,monospace;font-size:13px;line-height:1.4;padding:10px;border:1px solid #ddd;border-radius:3px}
        .operation-log{background:#f8f8f8;border-left:4px solid #0073aa;padding:10px 15px;margin:15px 0}
        .operation-log ul{margin:5px 0;padding-left:20px}
        .security-warning{background:#fff3cd;border:1px solid #ffeaa7;border-left:4px solid #f39c12;padding:10px 15px;margin:15px 0}
        .security-info{background:#d1ecf1;border:1px solid #bee5eb;border-left:4px solid #17a2b8;padding:10px 15px;margin:15px 0}
        .card{background:#fff;border:1px solid #ccd0d4;border-radius:4px;padding:15px;margin:15px 0}
        .card h3{margin-top:0}
        .asn-info{background:#e8f4fd;border:1px solid #b8daff;border-left:4px solid #007cba;padding:10px 15px;margin:15px 0}
        .brute-force-info{background:#fff2cc;border:1px solid #ffd700;border-left:4px solid #ff8c00;padding:10px 15px;margin:15px 0}
        .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px;margin:20px 0}
        .stat-card{background:#fff;border:1px solid #ddd;border-radius:4px;padding:15px;text-align:center}
        .stat-number{font-size:2em;font-weight:bold;color:#0073aa;margin-bottom:5px}
        .stat-label{color:#666}
        .attempts-table{width:100%;border-collapse:collapse;margin:15px 0}
        .attempts-table th,.attempts-table td{border:1px solid #ddd;padding:8px;text-align:left}
        .attempts-table th{background:#f2f2f2;font-weight:bold}
        .attempts-table tr:nth-child(even){background:#f9f9f9}
        .blocked-ip{color:#d63384;font-weight:bold}
        .normal-ip{color:#198754}
        .refresh-button{background:#0073aa;color:#fff;border:none;padding:5px 10px;border-radius:3px;cursor:pointer;margin-left:10px}
        .refresh-button:hover{background:#005a87}
        .auto-refresh-controls{margin:10px 0;padding:10px;background:#f8f9fa;border:1px solid #e9ecef;border-radius:4px}
        .loading-spinner{display:inline-block;width:16px;height:16px;border:2px solid #f3f3f3;border-top:2px solid #0073aa;border-radius:50%;animation:spin 1s linear infinite;margin-left:10px;vertical-align:middle}
        @keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}
        .view-history-btn{background:#6c757d;color:#fff;border:none;padding:3px 8px;border-radius:3px;cursor:pointer;font-size:12px;margin-left:5px}
        .view-history-btn:hover{background:#5a6268}
        .modal{display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;overflow:auto;background:rgba(0,0,0,0.4)}
        .modal-content{background:#fefefe;margin:10% auto;padding:20px;border:1px solid #888;width:80%;max-width:800px;border-radius:5px;position:relative}
        .close{color:#aaa;float:right;font-size:28px;font-weight:bold;cursor:pointer;position:absolute;top:10px;right:15px}
        .close:hover{color:#000}
        .history-table{width:100%;border-collapse:collapse}
        .history-table th,.history-table td{border:1px solid #ddd;padding:8px;text-align:left}
        .history-table th{background:#f2f2f2}
        .tablenav{height:30px;margin:10px 0}
        .tablenav .actions{float:left}
        .tablenav .pagination{float:right}
        .tablenav .displaying-num{margin-right:10px;line-height:30px}
        .tablenav .pagination-links a{display:inline-block;padding:3px 5px;margin:0 2px;border:1px solid #ccc;background:#e5e5e5;text-decoration:none}
        .tablenav .pagination-links a:hover{background:#d5d5d5}
        .tablenav .paging-input{display:inline-block;margin:0 5px;line-height:30px}
        /* Дополнительные стили для кнопок пагинации */
        .tablenav .pagination-links .button{display:inline-block;padding:3px 5px;margin:0 2px;border:1px solid #ccc;background:#e5e5e5;text-decoration:none;cursor:pointer}
        .tablenav .pagination-links .button:hover{background:#d5d5d5}
        </style>
        <?php
    }

/* ==========================================================
   2. Создание каталогов и таблиц
   ========================================================== */

    public function create_backup_dir() {
        foreach ([$this->backup_dir, $this->cache_dir] as $dir) {
            if (!is_dir($dir)) {
                wp_mkdir_p($dir);
                file_put_contents($dir . '.htaccess', "Order deny,allow\nDeny from all\n");
            }
        }
    }

    public function create_login_attempts_table() {
        global $wpdb;
        $table = $wpdb->prefix . 'security_login_attempts';
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            username varchar(60) NOT NULL,
            attempt_time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            user_agent text,
            blocked tinyint(1) DEFAULT 0,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY attempt_time (attempt_time),
            KEY blocked (blocked)
        ) $charset;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    public function create_unblock_history_table() {
        global $wpdb;
        $table = $wpdb->prefix . 'security_unblock_history';
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            unblock_time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            unblock_reason text,
            unblocked_by varchar(100) DEFAULT 'admin',
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY unblock_time (unblock_time)
        ) $charset;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    public function check_and_create_tables() {
        global $wpdb;
        foreach ([
            $wpdb->prefix . 'security_login_attempts',
            $wpdb->prefix . 'security_unblock_history'
        ] as $tbl) {
            if ($wpdb->get_var("SHOW TABLES LIKE '$tbl'") != $tbl) {
                $this->create_login_attempts_table();
                $this->create_unblock_history_table();
            }
        }
    }

    /* ==========================================================
       3. Деактивация и удаление
       ========================================================== */

    public function deactivate() {
    $this->update_ip_rules('');
    $this->update_login_protection('', false, false);
    $this->update_file_protection('');
    $this->update_bot_protection('');
    $this->update_honeypot_rules('');
    $this->clean_myipms_rules(); // Очистка Myip.ms
    $this->remove_nginx_rules();
    wp_clear_scheduled_hook('asb_myipms_update_event'); // Удаление крона
}

    public static function uninstall() {
        global $wpdb;
        
        // Удаляем таблицы
        foreach ([
            $wpdb->prefix . 'security_login_attempts',
            $wpdb->prefix . 'security_unblock_history'
        ] as $tbl) {
            $wpdb->query("DROP TABLE IF EXISTS $tbl");
        }

        // Очищаем все опции
        $options = [
            'asb_dangerous_files','asb_blocked_bots','asb_brute_force_enabled',
            'asb_max_attempts','asb_time_window','asb_block_duration',
            'asb_auto_add_to_htaccess','asb_email_notifications',
            'asb_blocked_ips_list','asb_wp_blocked_ips','asb_whitelist_ips',
            'asb_clear_cache_enabled','asb_external_blacklist','asb_geo_block_countries',
            'asb_fail2ban_enabled','asb_redis_shared_blocklist','asb_telegram_token',
            'asb_telegram_chat_id','asb_nginx_mode','asb_rate_limit_enabled',
            'asb_cloudflare_email','asb_cloudflare_api_key','asb_cloudflare_zone_id',
            self::ASB_ATTACK_LOG_KEY
        ];
        foreach ($options as $opt) {
            delete_option($opt);
        }

        // Восстанавливаем .htaccess без маркеров
        $htaccess_path = ABSPATH . '.htaccess';
        if (file_exists($htaccess_path)) {
            $markers = [
                "# IP_BLOCKER_SAFE_MARKER",
                "# LOGIN_PROTECTION_MARKER",
                "# DANGEROUS_FILES_MARKER",
                "# BOT_PROTECTION_MARKER",
                "# HONEYPOT_PROTECTION_MARKER",
                "# NGINX_RULES_MARKER"
            ];
            $content = file_get_contents($htaccess_path);
            foreach ($markers as $m) {
                $content = preg_replace('/\n?' . preg_quote($m, '/') . '.*?' . preg_quote($m, '/') . '/s', '', $content);
            }
            file_put_contents($htaccess_path, $content);
        }

        // Удаляем каталоги
        foreach ([WP_CONTENT_DIR . '/security-blocker-backups/', WP_CONTENT_DIR . '/security-blocker-cache/'] as $dir) {
            if (is_dir($dir)) {
                array_map('unlink', glob("$dir/*.*"));
                @rmdir($dir);
            }
        }
    }

    /* ==========================================================
       4. Работа с .htaccess
       ========================================================== */

/**
 * Обновление правил IP (поддержка ASN, CIDR)
 */
private function update_ip_rules($ips) {
    $this->log = [];
    try {
        $this->create_backup();
        $this->log[] = 'Создана резервная копия .htaccess';

        $ip_list = array_filter(array_map('trim', explode("\n", $ips)));
        
        // Удаление дублей с нормализацией
        $unique_entries = [];
        foreach ($ip_list as $entry) {
            $normalized = $this->normalize_ip_entry($entry);
            $unique_entries[$normalized] = $entry;
        }
        $ip_list = array_values($unique_entries);
        
        $valid = []; $invalid = []; $rules = []; $asn_ranges = [];

        foreach ($ip_list as $entry) {
            // ASN ?
            if (preg_match('/^AS?(\d+)$/i', $entry, $m)) {
                $asn = $m[1];
                if (!$this->validate_asn($asn)) {
                    $invalid[] = $entry;
                    continue;
                }
                $this->log[] = "Обрабатываем ASN AS{$asn}";
                $ranges = $this->get_asn_ip_ranges($asn);
                if ($ranges) {
                    foreach ($ranges as $r) {
                        $rules[] = "deny from {$r}";
                        $asn_ranges[] = $r;
                    }
                    $this->log[] = "ASN AS{$asn}: добавлено " . count($ranges) . " диапазонов";
                    $valid[] = $entry;
                } else {
                    $invalid[] = $entry;
                }
            }
            // CIDR ?
            elseif (strpos($entry, '/') !== false) {
                list($ip, $mask) = explode('/', $entry, 2);
                if (filter_var($ip, FILTER_VALIDATE_IP) && is_numeric($mask) && $mask >= 0 && $mask <= 32) {
                    $rules[] = "deny from {$entry}";
                    $valid[] = $entry;
                } else {
                    $invalid[] = $entry;
                }
            }
            // обычный IP
            elseif (filter_var($entry, FILTER_VALIDATE_IP)) {
                $rules[] = "deny from {$entry}";
                $valid[] = $entry;
            } else {
                $invalid[] = $entry;
            }
        }

        if (!empty($invalid)) {
            $this->log[] = "Некорректные записи: " . implode(', ', $invalid);
        }

        // Считываем текущий .htaccess и убираем старый блок
        $htaccess = file_exists($this->htaccess_path) ? file_get_contents($this->htaccess_path) : '';
        $htaccess = preg_replace('/\n?' . preg_quote($this->marker_ip, '/') . '.*?' . preg_quote($this->marker_ip, '/') . '/s', '', $htaccess);

        if (!empty($rules)) {
            $block = "\n{$this->marker_ip}\n" . implode("\n", $rules) . "\n{$this->marker_ip}\n";
            $htaccess = $block . $htaccess;
            $this->log[] = "Добавлено правил: " . count($rules) . " (IP:" . count($valid) . ", ASN:" . count(array_unique($asn_ranges)) . ")";
            $this->log[] = "Удалено дублей: " . (count($ip_list) - count($unique_entries));
        } else {
            $this->log[] = "Все правила IP удалены";
        }

        if (!file_put_contents($this->htaccess_path, $htaccess)) {
            throw new Exception('Не удалось записать в .htaccess');
        }

        $this->log[] = 'Настройки IP успешно сохранены';
        return true;

    } catch (Exception $e) {
        $this->restore_backup();
        $this->log[] = 'Ошибка: ' . $e->getMessage() . ' – восстановлена резервная копия';
        return $e->getMessage();
    }
}

    /**
     * Защита wp-login.php / xmlrpc.php
     */
    private function update_login_protection($whitelist_ips, $protect_wp_login = false, $protect_xmlrpc = false) {
        $this->log = [];
        try {
            $this->create_backup();
            $this->log[] = 'Создана резервная копия .htaccess';

            $htaccess = file_exists($this->htaccess_path) ? file_get_contents($this->htaccess_path) : '';
            $htaccess = preg_replace('/\n?' . preg_quote($this->marker_login, '/') . '.*?' . preg_quote($this->marker_login, '/') . '/s', '', $htaccess);

            // Если ничего не включено – просто удаляем блок
            if (!$protect_wp_login && !$protect_xmlrpc) {
                $this->log[] = 'Защита wp-login и xmlrpc отключена';
                if (!file_put_contents($this->htaccess_path, $htaccess)) {
                    throw new Exception('Не удалось записать в .htaccess');
                }
                $this->log[] = 'Настройки сохранены';
                return true;
            }

            if (empty(trim($whitelist_ips))) {
                $this->log[] = 'Белый список пуст – защита не будет работать';
                return 'Необходимо указать хотя бы один IP/ASN в белом списке';
            }

            $ip_list = array_filter(array_map('trim', explode("\n", $whitelist_ips)));
            $ip_list = array_unique($ip_list);

            $files_to_protect = [];
            if ($protect_wp_login) $files_to_protect[] = 'wp-login.php';
            if ($protect_xmlrpc) $files_to_protect[] = 'xmlrpc.php';

            $rules = [];

            foreach ($files_to_protect as $file) {
                $rules[] = "<Files \"{$file}\">";
                $rules[] = 'Order Deny,Allow';
                $rules[] = 'Deny from all';

                foreach ($ip_list as $entry) {
                    $added = false;
                    // ASN
                    if (preg_match('/^AS?(\d+)$/i', $entry, $m)) {
                        $asn = $m[1];
                        $ranges = $this->get_asn_ip_ranges($asn);
                        if ($ranges) {
                            foreach ($ranges as $r) $rules[] = "Allow from {$r}";
                            $added = true;
                            $this->log[] = "ASN AS{$asn} добавлен в whitelist для {$file}";
                        }
                    }
                    // CIDR
                    elseif (strpos($entry, '/') !== false) {
                        list($ip, $mask) = explode('/', $entry, 2);
                        if (filter_var($ip, FILTER_VALIDATE_IP) && is_numeric($mask) && $mask >= 0 && $mask <= 32) {
                            $rules[] = "Allow from {$entry}";
                            $added = true;
                        }
                    }
                    // обычный IP
                    elseif (filter_var($entry, FILTER_VALIDATE_IP)) {
                        $rules[] = "Allow from {$entry}";
                        $added = true;
                    }
                    // IP + маска подсети
                    elseif (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/', $entry, $m)) {
                        $rules[] = "Allow from {$m[1]} {$m[2]}";
                        $added = true;
                    }
                    // частичный IP
                    elseif (preg_match('/^(\d{1,3}\.){1,3}\d{0,3}$/', $entry)) {
                        $rules[] = "Allow from {$entry}";
                        $added = true;
                    }

                    if (!$added) $this->log[] = "Запись в whitelist пропущена (невалидна): {$entry}";
                }

                $rules[] = '</Files>';
                $rules[] = '';
            }

            if (end($rules) === '') array_pop($rules);

            $block = "\n{$this->marker_login}\n" . implode("\n", $rules) . "\n{$this->marker_login}\n";
            $htaccess = $block . $htaccess;

            if (!file_put_contents($this->htaccess_path, $htaccess)) {
                throw new Exception('Не удалось записать в .htaccess');
            }

            $this->log[] = 'Защита wp-login/xmlrpc успешно обновлена';
            return true;

        } catch (Exception $e) {
            $this->restore_backup();
            $this->log[] = 'Ошибка: ' . $e->getMessage();
            return $e->getMessage();
        }
    }

    /**
     * Защита от опасных файлов
     */
    private function update_file_protection($dangerous_files) {
        $this->log = [];
        try {
            $this->create_backup();
            $htaccess = file_exists($this->htaccess_path) ? file_get_contents($this->htaccess_path) : '';
            $htaccess = preg_replace('/\n?' . preg_quote($this->marker_files, '/') . '.*?' . preg_quote($this->marker_files, '/') . '/s', '', $htaccess);

            if (!empty(trim($dangerous_files))) {
                $files = array_filter(array_map('trim', explode("\n", $dangerous_files)));
                $files = array_unique($files);
                $escaped = array_map(function($f) { return str_replace(['*', '.'], '[.*]', preg_quote($f, '/')); }, $files);
                $rules = [
                    '<FilesMatch "(' . implode('|', $escaped) . ')$">',
                    'Order Allow,Deny',
                    'Deny from all',
                    '</FilesMatch>'
                ];
                $block = "\n{$this->marker_files}\n" . implode("\n", $rules) . "\n{$this->marker_files}\n";
                $htaccess = $block . $htaccess;
                $this->log[] = "Блокировка файлов настроена для " . count($files) . " записей";
            } else {
                $this->log[] = "Блокировка файлов отключена";
            }

            if (!file_put_contents($this->htaccess_path, $htaccess)) {
                throw new Exception('Не удалось записать в .htaccess');
            }
            $this->log[] = 'Настройки файловой защиты сохранены';
            return true;
        } catch (Exception $e) {
            $this->restore_backup();
            $this->log[] = 'Ошибка: ' . $e->getMessage();
            return $e->getMessage();
        }
    }

    /**
     * Защита от ботов
     */
    private function update_bot_protection($blocked_bots) {
        $this->log = [];
        try {
            $this->create_backup();
            $htaccess = file_exists($this->htaccess_path) ? file_get_contents($this->htaccess_path) : '';
            $htaccess = preg_replace('/\n?' . preg_quote($this->marker_bots, '/') . '.*?' . preg_quote($this->marker_bots, '/') . '/s', '', $htaccess);

            if (!empty(trim($blocked_bots))) {
                $list = array_filter(array_map('trim', explode('|', $blocked_bots)));
                $list = array_unique($list);

                $cleaned = [];
                foreach ($list as $bot) {
                    $bot = preg_replace('/["\'\\\\]/', '', $bot);
                    if (strlen($bot) > 1) $cleaned[] = preg_quote($bot, '/');
                }

                if (empty($cleaned)) {
                    $this->log[] = 'Все User‑Agent оказались некорректными';
                } else {
                    $chunks = array_chunk($cleaned, 100);
                    $rules = [];
                    foreach ($chunks as $i => $grp) {
                        $pattern = implode('|', $grp);
                        $rules[] = 'SetEnvIfNoCase User-Agent "' . $pattern . '" block_bot' . ($i ? ('_' . $i) : '');
                    }
                    $rules[] = '';
                    $rules[] = '<Limit GET POST HEAD>';
                    $rules[] = '    Order Allow,Deny';
                    $rules[] = '    Allow from all';
                    foreach (array_keys($chunks) as $i) {
                        $rules[] = '    Deny from env=block_bot' . ($i ? ('_' . $i) : '');
                    }
                    $rules[] = '</Limit>';

                    $block = "\n{$this->marker_bots}\n" . implode("\n", $rules) . "\n{$this->marker_bots}\n";
                    $htaccess = $block . $htaccess;
                    $this->log[] = 'Блокировка ботов настроена для ' . count($cleaned) . ' User‑Agent в ' . count($chunks) . ' группах';
                }
            } else {
                $this->log[] = 'Защита от ботов отключена';
            }

            if (!file_put_contents($this->htaccess_path, $htaccess)) {
                throw new Exception('Не удалось записать в .htaccess');
            }
            $this->log[] = 'Настройки ботов сохранены';
            return true;
        } catch (Exception $e) {
            $this->restore_backup();
            $this->log[] = 'Ошибка: ' . $e->getMessage();
            return $e->getMessage();
        }
    }

    /**
     * Honeypot инициализация
     */
    public function honeypot_init() {
        add_rewrite_rule('^wp-admin-honeypot/?$', 'index.php?asb_honeypot=1', 'top');
        add_filter('query_vars', function($vars) {
            $vars[] = 'asb_honeypot';
            return $vars;
        });
    }

    /**
     * Honeypot обработчик
     */
    public function template_redirect() {
        if (get_query_var('asb_honeypot')) {
            $ip = $this->get_user_ip();
            $this->block_ip_address($ip, 'honeypot', 'honeypot');
            // Записываем атаку в журнал
            $this->log_attack($ip, 'honeypot', $_SERVER['REQUEST_URI']);
            status_header(403);
            exit('Forbidden');
        }
    }

    /**
     * Обновление honeypot правил
     */
    private function update_honeypot_rules($content) {
        $htaccess = file_exists($this->htaccess_path) ? file_get_contents($this->htaccess_path) : '';
        $htaccess = preg_replace('/\n?' . preg_quote($this->marker_honeypot, '/') . '.*?' . preg_quote($this->marker_honeypot, '/') . '/s', '', $htaccess);
        if (!empty($content)) {
            $block = "\n{$this->marker_honeypot}\n{$content}\n{$this->marker_honeypot}\n";
            $htaccess = $block . $htaccess;
        }
        file_put_contents($this->htaccess_path, $htaccess);
    }

    /**
     * Генерация nginx правил
     */
    private function generate_nginx_rules() {
        $rules = [];
        $ips = $this->get_current_ips();
        if (!empty($ips)) {
            foreach (explode("\n", $ips) as $ip) {
                $ip = trim($ip);
                if ($ip) $rules[] = "deny {$ip};";
            }
        }
        if (get_option('asb_rate_limit_enabled')) {
            $rules[] = "limit_req_zone \$binary_remote_addr zone=asb:10m rate=30r/s;";
            $rules[] = "limit_req zone=asb burst=10 nodelay;";
        }
        return implode("\n", $rules);
    }

    private function write_nginx_rules_file() {
        $file = WP_CONTENT_DIR . '/asb_nginx.conf';
        $content = $this->generate_nginx_rules();
        file_put_contents($file, $content);
    }

    private function remove_nginx_rules() {
        $file = WP_CONTENT_DIR . '/asb_nginx.conf';
        if (file_exists($file)) @unlink($file);
    }

    /**
     * Резервное копирование .htaccess
     */
    private function create_backup() {
        if (file_exists($this->htaccess_path)) {
            $backup = $this->backup_dir . 'htaccess-' . date('Ymd-His') . '.bak';
            if (copy($this->htaccess_path, $backup)) {
                $this->log[] = "Резервная копия создана: " . basename($backup);
                $files = glob($this->backup_dir . 'htaccess-*.bak');
                if (count($files) > 10) {
                    rsort($files);
                    foreach (array_slice($files, 10) as $old) @unlink($old);
                }
            } else {
                $this->log[] = 'Не удалось создать резервную копию .htaccess';
            }
        }
    }

    private function restore_backup() {
        $backups = glob($this->backup_dir . 'htaccess-*.bak');
        if (!empty($backups)) {
            rsort($backups);
            if (copy($backups[0], $this->htaccess_path)) {
                $this->log[] = 'Восстановлена резервная копия: ' . basename($backups[0]);
            }
        }
    }

    /* ==========================================================
       5. Получение текущих правил
       ========================================================== */

    // ИЗМЕНЕНО НА PUBLIC для доступа из WP-CLI и REST API
    public function get_current_ips() {
        if (!file_exists($this->htaccess_path)) return '';
        $ht = file_get_contents($this->htaccess_path);
        if (preg_match('/' . preg_quote($this->marker_ip, '/') . '(.*?)' . preg_quote($this->marker_ip, '/') . '/s', $ht, $m)) {
            preg_match_all('/deny from ([^\r\n]+)/', $m[1], $ips);
            return implode("\n", array_unique($ips[1]));
        }
        return '';
    }

    private function get_current_login_whitelist() {
        if (!file_exists($this->htaccess_path)) return '';
        $ht = file_get_contents($this->htaccess_path);
        if (preg_match('/' . preg_quote($this->marker_login, '/') . '(.*?)' . preg_quote($this->marker_login, '/') . '/s', $ht, $m)) {
            preg_match_all('/Allow from ([^\r\n]+)/', $m[1], $allows);
            if (!empty($allows[1])) return implode("\n", array_unique($allows[1]));
        }
        return '';
    }

    private function get_current_protection_settings() {
        if (!file_exists($this->htaccess_path)) return ['wp_login' => false, 'xmlrpc' => false];
        $ht = file_get_contents($this->htaccess_path);
        preg_match('/' . preg_quote($this->marker_login, '/') . '(.*?)' . preg_quote($this->marker_login, '/') . '/s', $ht, $m);
        if (empty($m[1])) return ['wp_login' => false, 'xmlrpc' => false];
        $content = $m[1];
        return [
            'wp_login' => strpos($content, 'wp-login.php') !== false,
            'xmlrpc'   => strpos($content, 'xmlrpc.php') !== false
        ];
    }

/* ==========================================================
   6. Блокировка / разблокировка IP
   ========================================================== */

/**
 * Валидация IP/CIDR/ASN записи
 */
private function validate_ip_entry($entry) {
    $entry = trim($entry);
    
    // IP
    if (filter_var($entry, FILTER_VALIDATE_IP)) return true;
    // CIDR
    if (strpos($entry, '/') !== false) {
        list($ip, $mask) = explode('/', $entry, 2);
        return filter_var($ip, FILTER_VALIDATE_IP) && is_numeric($mask) && $mask >= 0 && $mask <= 32;
    }
    // ASN
    if (preg_match('/^AS?(\d+)$/i', $entry, $m)) {
        return $this->validate_asn($m[1]);
    }
    return false;
}

/**
 * Валидация ASN
 */
private function validate_asn($asn) {
    $asn = str_replace(['AS', 'as'], '', $asn);
    return is_numeric($asn) && $asn > 0 && $asn < 4294967296;
}

/**
 * Нормализует IP запись для сравнения (удаляет дубли)
 */
private function normalize_ip_entry($entry) {
    $entry = trim($entry);
    
    // ASN - приводим к единому формату
    if (preg_match('/^AS?(\d+)$/i', $entry, $m)) {
        return 'AS' . $m[1]; // Формат: AS1234
    }
    
    // CIDR - нормализуем IP и маску
    if (strpos($entry, '/') !== false) {
        list($ip, $mask) = explode('/', $entry, 2);
        $mask = intval($mask);
        // Приводим IP к нормальной форме
        $ip = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 
              $ip : 
              (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? $ip : '');
        
        if ($ip) {
            // Для IPv4 CIDR нормализуем маску (0-32)
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $mask = max(0, min(32, $mask));
            }
            return $ip . '/' . $mask;
        }
    }
    
    // Обычный IP
    if (filter_var($entry, FILTER_VALIDATE_IP)) {
        return $entry;
    }
    
    return $entry; // Возвращаем как есть, если не распознали
}

/**
 * Получить тип записи (IP, CIDR, ASN)
 */
private function get_entry_type($entry) {
    $entry = trim($entry);
    
    if (preg_match('/^AS?(\d+)$/i', $entry)) {
        return 'ASN';
    } elseif (strpos($entry, '/') !== false) {
        return 'CIDR';
    } elseif (filter_var($entry, FILTER_VALIDATE_IP)) {
        return 'IP';
    }
    
    return 'UNKNOWN';
}

/**
 * Блокировка только на уровне WordPress (без .htaccess)
 */
private function block_ip_wordpress_only($ip_address, $username = '', $reason = '') {
    global $wpdb;
    
    // Валидация IP/CIDR/ASN
    if (!$this->validate_ip_entry($ip_address)) {
        error_log("Security Blocker: Попытка заблокировать невалидную запись: {$ip_address}");
        return false;
    }

    $entry_type = $this->get_entry_type($ip_address);
    
    // 1. Добавляем в постоянный список WordPress (для ВСЕХ типов - IP, CIDR, ASN)
    $this->add_to_permanent_blocklist($ip_address);
    
    // 2. Для обычных IP также добавляем в файл блокировок
    if ($entry_type === 'IP') {
        $this->add_to_block_file($ip_address);
        
        // Помечаем в БД (только для IP)
        $table = $wpdb->prefix . 'security_login_attempts';
        $wpdb->update($table, ['blocked' => 1], ['ip_address' => $ip_address]);
    }
    
    // 3. Redis‑шаред‑блоклист (только для IP)
    if (get_option('asb_redis_shared_blocklist') && $this->redis && $entry_type === 'IP') {
        try {
            $ttl = 31536000; // 1 год для постоянных блокировок
            $this->redis->set("asb:block:{$ip_address}", 1, $ttl);
        } catch (Exception $e) {
            error_log("ASB Redis error: " . $e->getMessage());
        }
    }
    
    // 4. Cloudflare блокировка (работает для всех типов)
    $this->block_ip_cloudflare($ip_address, "Ручная блокировка WordPress: {$reason}");
    
    // 5. Уведомления
    if (get_option('asb_email_notifications')) {
        $this->send_block_notification($ip_address, $username, 0);
    }
    if (get_option('asb_telegram_token') && get_option('asb_telegram_chat_id')) {
        $site_name = get_bloginfo('name');
        $this->send_telegram_message("🔒 [{$site_name}] {$ip_address} заблокирован (ручная блокировка WordPress)");
    }
    
    error_log("Security Blocker: {$ip_address} заблокирован на уровне WordPress (type={$entry_type}, reason: {$reason})");
    return true;
}

// ИЗМЕНЕНО НА PUBLIC для доступа из WP-CLI и REST API
public function block_ip_address($ip_address, $username = '', $attempts = 0) {
    global $wpdb;
    
    // Валидация IP/CIDR/ASN
    if (!$this->validate_ip_entry($ip_address)) {
        error_log("Security Blocker: Попытка заблокировать невалидную запись: {$ip_address}");
        return false;
    }

    $table = $wpdb->prefix . 'security_login_attempts';
    $entry_type = $this->get_entry_type($ip_address);

    // 1. Помечаем в БД (только для IP)
    if ($entry_type === 'IP') {
        $wpdb->update($table, ['blocked' => 1], ['ip_address' => $ip_address]);
    }

    // 2. Добавляем в постоянный список WordPress (для ВСЕХ типов - IP, CIDR, ASN)
    $block_duration = intval(get_option('asb_block_duration', 60));
    if ($block_duration === 0) {
        $this->add_to_permanent_blocklist($ip_address);
        
        // Для обычных IP также добавляем в файл блокировок
        if ($entry_type === 'IP') {
            $this->add_to_block_file($ip_address);
        }
    }

    // 3. Добавляем в .htaccess (если включено) - работает для всех типов
    if (get_option('asb_auto_add_to_htaccess')) {
        $this->add_ip_to_htaccess($ip_address);
    }

    // 4. Fail2Ban – запись в syslog
    if (get_option('asb_fail2ban_enabled')) {
        $block_type = ($block_duration === 0) ? 'PERMANENT' : 'TEMPORARY';
        error_log("asb: BLOCKED {$block_type} {$ip_address} ({$username})");
    }

    // 5. Redis‑шаред‑блоклист (только для IP)
    if (get_option('asb_redis_shared_blocklist') && $this->redis && $entry_type === 'IP') {
        try {
            // Для постоянных блокировок ставим большее время
            $ttl = ($block_duration === 0) ? 31536000 : 86400; // 1 год или 1 день
            $this->redis->set("asb:block:{$ip_address}", 1, $ttl);
        } catch (Exception $e) {
            error_log("ASB Redis error: " . $e->getMessage());
        }
    }

    // 6. Cloudflare блокировка (работает для всех типов)
    $this->block_ip_cloudflare($ip_address, "Блокировка через плагин: {$username}");

    // 7. Уведомления
    if (get_option('asb_email_notifications')) {
        $this->send_block_notification($ip_address, $username, $attempts);
    }
    if (get_option('asb_telegram_token') && get_option('asb_telegram_chat_id')) {
        $site_name = get_bloginfo('name');
        $block_type_text = ($block_duration === 0) ? 'постоянно' : 'временно';
        $this->send_telegram_message("🔒 [{$site_name}] {$ip_address} заблокирован {$block_type_text} ({$username}) попыток: {$attempts}");
    }

    $block_type_log = ($block_duration === 0) ? 'постоянно' : 'временно';
    error_log("Security Blocker: {$ip_address} заблокирован {$block_type_log} (type={$entry_type}, user={$username}, attempts={$attempts})");
    return true;
}

// ИЗМЕНЕНО НА PUBLIC для доступа из WP-CLI и REST API
public function unblock_ip_address($ip_address, $reason = '') {
    global $wpdb;
    $table = $wpdb->prefix . 'security_login_attempts';
    $entry_type = $this->get_entry_type($ip_address);

    // 1. Снимаем флаг blocked в БД (только для IP)
    if ($entry_type === 'IP') {
        $wpdb->update($table, ['blocked' => 0], ['ip_address' => $ip_address, 'blocked' => 1]);
    }

    // 2. Удаляем из списка WP (для всех типов записей)
    $list = get_option('asb_wp_blocked_ips', '');
    if ($list) {
        $arr = array_filter(array_map('trim', explode("\n", $list)));
        
        // Удаляем с нормализацией для всех типов записей
        $new_arr = [];
        $normalized_target = $this->normalize_ip_entry($ip_address);
        
        foreach ($arr as $entry) {
            if ($this->normalize_ip_entry($entry) !== $normalized_target) {
                $new_arr[] = $entry;
            }
        }
        
        update_option('asb_wp_blocked_ips', implode("\n", $new_arr));
    }

    // 3. Удаляем из .htaccess (для всех типов)
    $current = $this->get_current_ips();
    if (!empty($current)) {
        $arr = array_filter(array_map('trim', explode("\n", $current)));
        
        // Удаляем с нормализацией
        $new_arr = [];
        $normalized_target = $this->normalize_ip_entry($ip_address);
        
        foreach ($arr as $entry) {
            if ($this->normalize_ip_entry($entry) !== $normalized_target) {
                $new_arr[] = $entry;
            }
        }
        
        $this->update_ip_rules(implode("\n", $new_arr));
    }

    // 4. Записываем в историю разблокировок (для всех типов)
    $unblock_tbl = $wpdb->prefix . 'security_unblock_history';
    $user = wp_get_current_user();
    $wpdb->insert($unblock_tbl, [
        'ip_address'     => $ip_address,
        'unblock_reason' => $reason,
        'unblocked_by'   => $user->user_login
    ]);

    // 5. Redis‑очистка (только для IP)
    if (get_option('asb_redis_shared_blocklist') && $this->redis && $entry_type === 'IP') {
        try {
            $this->redis->del("asb:block:{$ip_address}");
        } catch (Exception $e) {
            error_log("ASB Redis error: " . $e->getMessage());
        }
    }

    // 6. Cloudflare разблокировка (для всех типов)
    $this->unblock_ip_cloudflare($ip_address);

    error_log("Security Blocker: {$ip_address} разблокирован (type={$entry_type}, reason: {$reason})");
}

private function add_ip_to_htaccess($ip_address) {
    $current = $this->get_current_ips();
    $list = array_filter(array_map('trim', explode("\n", $current)));
    
    // Проверяем на дублирование (нормализация для сравнения)
    $normalized_list = [];
    foreach ($list as $entry) {
        $normalized_list[$this->normalize_ip_entry($entry)] = $entry;
    }
    
    $normalized_ip = $this->normalize_ip_entry($ip_address);
    if (!isset($normalized_list[$normalized_ip])) {
        $list[] = $ip_address;
        $this->update_ip_rules(implode("\n", $list));
    }
}

private function add_to_permanent_blocklist($ip_address) {
    $list = get_option('asb_wp_blocked_ips', '');
    $arr = array_filter(array_map('trim', explode("\n", $list)));
    
    // Проверяем на дублирование с нормализацией
    $normalized_new = $this->normalize_ip_entry($ip_address);
    $is_duplicate = false;
    
    foreach ($arr as $existing) {
        if ($this->normalize_ip_entry($existing) === $normalized_new) {
            $is_duplicate = true;
            break;
        }
    }
    
    if (!$is_duplicate) {
        $arr[] = $ip_address;
        update_option('asb_wp_blocked_ips', implode("\n", $arr));
    }
}

/**
 * Записать IP в файл блокировок (для wp-config.php проверки)
 */
private function add_to_block_file($ip_address) {
    $file = ABSPATH . 'wp-content/blocked-ips.txt';
    
    // Создаем директорию если её нет
    if (!is_dir(dirname($file))) {
        wp_mkdir_p(dirname($file));
    }
    
    $ips = [];
    if (file_exists($file)) {
        $ips = array_filter(array_map('trim', file($file)));
    }
    
    if (!in_array($ip_address, $ips)) {
        $ips[] = $ip_address;
        $content = implode("\n", $ips);
        
        if (!file_put_contents($file, $content)) {
            error_log("Security Blocker: Не удалось записать IP {$ip_address} в файл блокировок");
            return false;
        }
        
        // Защищаем файл от прямого доступа
        $htaccess = dirname($file) . '/.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "Order deny,allow\nDeny from all\n");
        }
        
        error_log("Security Blocker: IP {$ip_address} добавлен в файл блокировок");
        return true;
    }
    
    return false;
}

/**
 * Проверка IP на уровне WordPress (расширенная для CIDR и ASN)
 */
private function is_ip_blocked_at_wp_level($ip) {
    $list = get_option('asb_wp_blocked_ips', '');
    if (empty($list)) return false;

    $blocked_entries = array_filter(array_map('trim', explode("\n", $list)));
    
    // Сначала проверяем точное совпадение
    if (in_array($ip, $blocked_entries)) {
        return true;
    }
    
    // Проверяем все записи
    foreach ($blocked_entries as $entry) {
        $entry_type = $this->get_entry_type($entry);
        
        switch ($entry_type) {
            case 'IP':
                if ($entry === $ip) return true;
                break;
                
            case 'CIDR':
                if (strpos($entry, '/') !== false && $this->ip_in_cidr($ip, $entry)) {
                    return true;
                }
                break;
                
            case 'ASN':
                // Для ASN получаем диапазоны и проверяем вхождение
                $asn_ranges = $this->get_asn_ip_ranges($entry);
                if ($asn_ranges) {
                    foreach ($asn_ranges as $range) {
                        if ($this->ip_in_cidr($ip, $range)) {
                            return true;
                        }
                    }
                }
                break;
        }
    }
    
    return false;
}

    /* ==========================================================
       7. Обработка попыток входа (брутфорс) - ПОЛНОСТЬЮ ПЕРЕПИСАНО
       ========================================================== */

    /**
 * Ранняя проверка доступа - САМЫЙ РАННИЙ ХУК
 * Вызывается ДО загрузки темы и плагинов
 */
public function check_ip_access() {
    // Пропускаем cron и CLI
    if (wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
        return;
    }

    if (!get_option('asb_brute_force_enabled')) {
        return;
    }

    $ip = $this->get_user_ip();
    
    // Проверяем блокировку
    $block_status = $this->get_ip_block_status($ip);
    
    if ($block_status) {
        $this->block_access_and_die($ip, $block_status);
    }
    
    // Проверка Myip.ms в режиме WP
    if (get_option('asb_myipms_enabled') === '1' && get_option('asb_myipms_mode') === 'wp') {
        if ($this->check_myipms_file_block($ip)) {
            $this->log_attack($ip, 'myipms_blacklist', 'WP Mode Block');
            $this->block_access_and_die($ip, [
                'blocked' => true,
                'type' => 'myipms',
                'message' => 'Ваш IP находится в черном списке Myip.ms'
            ]);
        }
    }

    // Geo-блокировка
    $this->check_geo_blocking($ip);
}

/**
 * Проверяет IP по локальному файлу Myip.ms (для режима WP)
 */
private function check_myipms_file_block($ip) {
    if (!file_exists($this->myipms_list_file)) return false;
    
    // Читаем файл в массив (это может быть ресурсоемко при больших файлах, 
    // но для myipms списка ~60-100КБ это допустимо)
    $ips = file($this->myipms_list_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$ips) return false;

    foreach ($ips as $blocked_ip) {
        $blocked_ip = trim($blocked_ip);
        if ($blocked_ip === $ip) return true;
        // Если в списке есть CIDR, проверяем его
        if (strpos($blocked_ip, '/') !== false && $this->ip_in_cidr($ip, $blocked_ip)) {
            return true;
        }
    }
    return false;
}

    /**
     * Получить статус блокировки IP (универсальный метод)
     * Возвращает массив с информацией о блокировке или false
     */
    private function get_ip_block_status($ip) {
        // 1. Проверка белого списка
        if ($this->is_ip_whitelisted($ip)) {
            return false;
        }
        
        // 2. ПРИОРИТЕТ: Проверка постоянных блокировок в списке WP
        if ($this->is_ip_blocked_at_wp_level($ip)) {
            return [
                'blocked' => true,
                'type' => 'permanent',
                'message' => 'Ваш IP заблокирован.'
            ];
        }
        
        // 3. Redis-быстрая проверка
        if (get_option('asb_redis_shared_blocklist') && $this->redis) {
            try {
                $redis_data = $this->redis->get("asb:block:{$ip}");
                if ($redis_data) {
                    return [
                        'blocked' => true,
                        'type' => 'redis',
                        'message' => 'Ваш IP временно заблокирован.',
                        'data' => $redis_data
                    ];
                }
            } catch (Exception $e) {
                error_log("ASB Redis error: " . $e->getMessage());
            }
        }
        
        // 4. Проверка временных блокировок в БД (ТОЛЬКО если duration > 0)
        $duration = intval(get_option('asb_block_duration', 60));
        
        // ИСПРАВЛЕНИЕ: Пропускаем проверку БД если установлена постоянная блокировка
        if ($duration > 0) {
            global $wpdb;
            $table = $wpdb->prefix . 'security_login_attempts';
            
            $blocked = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM $table
                 WHERE ip_address = %s
                   AND blocked = 1
                   AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)
                 ORDER BY attempt_time DESC
                 LIMIT 1",
                $ip, $duration
            ));
            
            if ($blocked) {
                $remaining = $duration - floor((time() - strtotime($blocked->attempt_time)) / 60);
                return [
                    'blocked' => true,
                    'type' => 'temporary',
                    'remaining' => max(1, $remaining),
                    'message' => sprintf(
                        'Ваш IP временно заблокирован. Попробуйте снова через %d мин.', 
                        max(1, $remaining)
                    )
                ];
            }
        }
        
        return false;
    }

    /**
     * Блокировка доступа с правильными заголовками
     */
    private function block_access_and_die($ip, $block_status) {
        // Устанавливаем заголовки до любого вывода
        if (!headers_sent()) {
            status_header(403);
            header('HTTP/1.1 403 Forbidden');
            header('Content-Type: text/html; charset=utf-8');
            header('X-Blocked-By: ASB-Security');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: 0');
            
            // Retry-After для временных блокировок
            if ($block_status['type'] === 'temporary' && isset($block_status['remaining'])) {
                header('Retry-After: ' . ($block_status['remaining'] * 60));
            }
        }
        
        // Логирование
        if (get_option('asb_fail2ban_enabled')) {
            error_log("asb: BLOCKED {$ip} [{$block_status['type']}]");
        }
        
        // Показываем страницу блокировки
        $this->show_block_page($block_status);
        
        // Полностью останавливаем выполнение
        exit;
    }

    /**
     * Страница блокировки
     */
    private function show_block_page($block_status) {
        $message = esc_html($block_status['message']);
        
        echo '<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>418 - Я чайник</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container { 
            text-align: center; 
            padding: 40px; 
            max-width: 600px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.3);
        }
        .teapot-image {
            max-width: 300px;
            width: 100%;
            height: auto;
            margin: 0 auto 30px;
            border-radius: 15px;
            display: block;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
        }
        h1 { 
            font-size: 48px; 
            margin-bottom: 15px; 
            color: #ffcc00;
            text-shadow: 0 2px 10px rgba(255, 204, 0, 0.3);
        }
        .status-code {
            display: inline-block;
            background: rgba(255, 204, 0, 0.15);
            padding: 5px 15px;
            border-radius: 30px;
            margin-bottom: 20px;
            font-weight: bold;
            color: #ffcc00;
        }
        p { 
            font-size: 18px; 
            color: #a0a0a0; 
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .message {
            background: rgba(255, 204, 0, 0.1);
            border: 1px solid rgba(255, 204, 0, 0.3);
            border-radius: 12px;
            padding: 25px;
            margin-top: 25px;
            font-style: italic;
        }
        .protocol-info {
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 14px;
            color: #888;
        }
        @media (max-width: 480px) {
            .container { padding: 25px; }
            h1 { font-size: 36px; }
            .teapot-image { max-width: 250px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="https://sexandrelationships.ru/wp-content/uploads/2025/12/69429e6948a7d-1765973609.webp" 
             alt="Чайник" 
             class="teapot-image"
             onerror="this.style.display=\'none\';">
        
        <h1>418</h1>
        <div class="status-code">I\'m a teapot</div>
        <p>Извините, я всего лишь чайник и не могу выполнить ваш запрос.</p>
        <div class="message">' . $message . '</div>
        <div class="protocol-info">
            RFC 2324: Hyper Text Coffee Pot Control Protocol (HTCPCP/1.0)
        </div>
    </div>
</body>
</html>';
    }

    /**
     * Geo-блокировка
     */
    private function check_geo_blocking($ip) {
        $blocked_countries = get_option('asb_geo_block_countries');
        
        if (!$blocked_countries) {
            return;
        }
        
        $countries = array_map('trim', explode(',', $blocked_countries));
        $country = $this->get_ip_country($ip);
        
        if ($country && in_array($country, $countries, true)) {
            $this->log_attack($ip, 'geo_block', $country);
            
            $this->block_access_and_die($ip, [
                'blocked' => true,
                'type' => 'geo',
                'message' => 'Доступ из вашего региона ограничен.'
            ]);
        }
    }

    /**
     * Проверка при аутентификации
     */
    public function check_blocked_ip($user, $password) {
        if (!get_option('asb_brute_force_enabled')) {
            return $user;
        }
        
        // Если уже ошибка - пропускаем
        if (is_wp_error($user)) {
            return $user;
        }
        
        $ip = $this->get_user_ip();
        $block_status = $this->get_ip_block_status($ip);
        
        if ($block_status) {
            return new WP_Error('ip_blocked', $block_status['message']);
        }
        
        return $user;
    }

    /**
     * Обработка неудачных попыток входа
     */
    public function handle_failed_login($username) {
        if (!get_option('asb_brute_force_enabled')) {
            return;
        }
        
        $ip = $this->get_user_ip();
        
        if ($this->is_ip_whitelisted($ip)) {
            return;
        }
        
        global $wpdb;
        $table = $wpdb->prefix . 'security_login_attempts';
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        
        // Записываем попытку
        $wpdb->insert($table, [
            'ip_address'   => $ip,
            'username'     => sanitize_user($username),
            'user_agent'   => sanitize_text_field($ua),
            'attempt_time' => current_time('mysql'),
            'blocked'      => 0
        ], ['%s', '%s', '%s', '%s', '%d']);
        
        $max    = intval(get_option('asb_max_attempts', 5));
        $window = intval(get_option('asb_time_window', 15));
        
        // Считаем попытки за окно времени
        $cnt = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table
             WHERE ip_address = %s
               AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)",
            $ip, $window
        ));
        
        // Fail2Ban логирование
        if (get_option('asb_fail2ban_enabled')) {
            error_log("asb: FAILED_LOGIN {$ip} user={$username} attempts={$cnt}/{$max}");
        }
        
        // Блокируем если превышен лимит
        if ($cnt >= $max) {
            // Используем существующий метод block_ip_address
            $this->block_ip_address($ip, $username, $cnt);
            $this->log_attack($ip, 'brute_force', "User: {$username}, Attempts: {$cnt}");
            
            // Блокируем сразу после превышения
            $block_status = $this->get_ip_block_status($ip);
            if ($block_status) {
                $this->block_access_and_die($ip, $block_status);
            }
        }
        
        // Проверка внешней репутации
        if (get_option('asb_external_blacklist') && $cnt >= 2) {
            $reputation = $this->check_external_reputation($ip);
            if ($reputation && isset($reputation['score']) && $reputation['score'] < 30) {
                $this->block_ip_address($ip, 'bad_reputation', 0);
                $this->log_attack($ip, 'bad_reputation', "Score: {$reputation['score']}");
            }
        }
    }

    /**
     * Проверка внешней репутации IP
     */
    private function check_external_reputation($ip) {
        // Используем IPQualityScore API (бесплатный план)
        $url = "https://ipqualityscore.com/api/json/ip/reputation?ip={$ip}&strictness=1&allow_public_access=true";
        $response = $this->fetch_url($url, 5);
        
        if ($response) {
            $data = json_decode($response, true);
            return $data;
        }
        return false;
    }

    /* ==========================================================
       8. Белый список
       ========================================================== */

    private function is_ip_whitelisted($ip) {
        $list = $this->get_whitelist_ips();
        foreach ($list as $entry) {
            if ($entry === $ip) return true;
            if (strpos($entry, '/') !== false && $this->ip_in_cidr($ip, $entry)) return true;
            if (preg_match('/^AS?(\d+)$/i', $entry, $m)) {
                $asn_ranges = $this->get_asn_ip_ranges($m[1]);
                foreach ($asn_ranges as $r) if ($this->ip_in_cidr($ip, $r)) return true;
            }
        }
        return false;
    }

    private function add_to_whitelist($ip, $reason = '') {
        $list = $this->get_whitelist_ips();
        if (!in_array($ip, $list)) {
            $list[] = $ip;
            update_option('asb_whitelist_ips', implode("\n", $list));
            error_log("Security Blocker: IP {$ip} добавлен в whitelist (reason: {$reason})");
        }
    }

    private function remove_from_whitelist($ip) {
        $list = $this->get_whitelist_ips();
        $list = array_diff($list, [$ip]);
        update_option('asb_whitelist_ips', implode("\n", $list));
        error_log("Security Blocker: IP {$ip} удалён из whitelist");
    }

    // ИЗМЕНЕНО НА PUBLIC для доступа из WP-CLI
    public function get_whitelist_ips() {
        $opt = get_option('asb_whitelist_ips', '');
        return $opt ? array_filter(array_map('trim', explode("\n", $opt))) : [];
    }

    /* ==========================================================
       9. GeoIP (Интеграция ipinfo.io)
       ========================================================== */

    private function get_ip_country($ip) {
        // Ваш API ключ
        $api_key = 'd3992412cdd465';
        
        // 1. Проверяем локальный файловый кеш (чтобы экономить лимиты API и ускорить работу)
        // Используем хеш IP для имени файла
        $cache_key = 'geo_ipinfo_' . md5($ip);
        $cache_file = $this->cache_dir . $cache_key . '.json';
        
        if (file_exists($cache_file)) {
            $cached_content = file_get_contents($cache_file);
            if ($cached_content) {
                $data = json_decode($cached_content, true);
                // Кеш валиден 7 дней (604800 секунд)
                if (isset($data['timestamp']) && (time() - $data['timestamp']) < 604800) {
                    return $data['country'] ?? null;
                }
            }
        }

        // 2. Если в кеше нет, делаем запрос к API
        $url = "https://ipinfo.io/{$ip}?token={$api_key}";
        
        // Используем существующий в классе метод fetch_url с таймаутом 3 секунды
        $response = $this->fetch_url($url, 3);
        
        if ($response) {
            $json = json_decode($response, true);
            
            // ipinfo возвращает код страны в поле 'country' (напр. "RU", "US")
            if (isset($json['country'])) {
                $country = $json['country'];
                
                // Сохраняем результат в кеш
                if (!is_dir($this->cache_dir)) {
                    wp_mkdir_p($this->cache_dir);
                }
                
                // Записываем данные
                file_put_contents($cache_file, json_encode([
                    'timestamp' => time(),
                    'country'   => $country
                ]));
                
                return $country;
            }
        }

        return null;
    }

    /* ==========================================================
       10. ASN‑обработка (caching)
       ========================================================== */

    private function get_asn_cache_file($asn) {
        return $this->cache_dir . 'asn_' . $asn . '.json';
    }

    private function get_cached_asn_ranges($asn) {
        $file = $this->get_asn_cache_file($asn);
        if (!file_exists($file)) return false;
        $data = json_decode(file_get_contents($file), true);
        if (isset($data['timestamp']) && (time() - $data['timestamp']) < 86400) {
            $this->log[] = "ASN AS{$asn}: использованы кешированные диапазоны";
            return $data['ranges'];
        }
        return false;
    }

    private function cache_asn_ranges($asn, $ranges) {
        $file = $this->get_asn_cache_file($asn);
        $data = ['timestamp' => time(), 'asn' => $asn, 'ranges' => $ranges];
        file_put_contents($file, json_encode($data));
        $this->log[] = "ASN AS{$asn}: кешировано " . count($ranges) . " диапазонов";
    }

    private function clear_asn_cache() {
        $files = glob($this->cache_dir . 'asn_*.json');
        if ($files) {
            foreach ($files as $f) @unlink($f);
        }
        $this->log[] = 'Кеш ASN очищен';
    }

    /**
     * Получение IP‑диапазонов по ASN
     */
    private function get_asn_ip_ranges($asn) {
        $asn = str_replace(['AS', 'as'], '', $asn);
        if (!is_numeric($asn)) return false;

        $cached = $this->get_cached_asn_ranges($asn);
        if ($cached !== false) return $cached;

        $ranges = [];
        $sources = [
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{$asn}",
            "https://api.hackertarget.com/aslookup/?q=AS{$asn}"
        ];

        foreach ($sources as $url) {
            $resp = $this->fetch_url($url);
            if (!$resp) continue;

            if (strpos($url, 'ripe.net') !== false) {
                $json = json_decode($resp, true);
                if (!empty($json['data']['prefixes'])) {
                    foreach ($json['data']['prefixes'] as $p) {
                        if (!empty($p['prefix'])) $ranges[] = $p['prefix'];
                    }
                }
            } else {
                foreach (explode("\n", $resp) as $line) {
                    if (preg_match('/(\d+\.\d+\.\d+\.\d+\/\d+)/', $line, $m)) $ranges[] = $m[1];
                }
            }

            if (!empty($ranges)) break;
        }

        $unique = array_unique($ranges);
        if (!empty($unique)) $this->cache_asn_ranges($asn, $unique);
        return $unique;
    }

    /**
     * Загрузка URL с улучшенной обработкой ошибок
     */
    private function fetch_url($url, $timeout = 10) {
        try {
            if (function_exists('curl_init')) {
                $ch = curl_init($url);
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT => $timeout,
                    CURLOPT_CONNECTTIMEOUT => 5,
                    CURLOPT_USERAGENT => 'WordPress Security Plugin',
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_FOLLOWLOCATION => true
                ]);
                $out = curl_exec($ch);
                $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $error = curl_error($ch);
                curl_close($ch);

                if ($error) {
                    $this->log[] = "CURL ошибка при запросе к {$url}: {$error}";
                    return false;
                }
                if ($code === 200) return $out;
            }

            if (ini_get('allow_url_fopen')) {
                $ctx = stream_context_create([
                    'http' => [
                        'timeout' => $timeout,
                        'user_agent' => 'WordPress Security Plugin'
                    ]
                ]);
                $result = @file_get_contents($url, false, $ctx);
                if ($result === false) {
                    $this->log[] = "Не удалось загрузить {$url}";
                    return false;
                }
                return $result;
            }
        } catch (Exception $e) {
            $this->log[] = "Исключение при загрузке {$url}: " . $e->getMessage();
            return false;
        }

        return false;
    }

 /* ==========================================================
   11. IP‑в‑CIDR проверка
   ========================================================== */

private function ip_in_cidr($ip, $cidr) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    if (strpos($cidr, '/') === false) return $ip === $cidr;

    list($subnet, $mask) = explode('/', $cidr);
    if (!filter_var($subnet, FILTER_VALIDATE_IP) || !is_numeric($mask)) return false;
    
    // Для IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask_long = -1 << (32 - (int)$mask);
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }
    
    // Для IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $ip_bin = inet_pton($ip);
        $subnet_bin = inet_pton($subnet);
        
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }
        
        // Сравниваем первые $mask бит
        $mask_bytes = (int)$mask / 8;
        $mask_remainder = (int)$mask % 8;
        
        // Сравниваем полные байты
        if (strncmp($ip_bin, $subnet_bin, $mask_bytes) !== 0) {
            return false;
        }
        
        // Сравниваем остаточные биты
        if ($mask_remainder > 0) {
            $last_byte_ip = ord($ip_bin[$mask_bytes]);
            $last_byte_subnet = ord($subnet_bin[$mask_bytes]);
            $bitmask = 0xFF << (8 - $mask_remainder);
            return ($last_byte_ip & $bitmask) === ($last_byte_subnet & $bitmask);
        }
        
        return true;
    }
    
    return false;
}

    /* ==========================================================
       12. Уведомления
       ========================================================== */

    private function send_block_notification($ip, $username, $attempts, $method = 'htaccess + WordPress') {
        $admin = get_option('admin_email');
        $site  = get_bloginfo('name');
        $url   = get_site_url();
        $time  = current_time('mysql');

        $subject = "[$site] IP $ip заблокирован";
        $msg = <<<EOT
Внимание! На сайте $site обнаружена попытка брутфорса.

IP: $ip
Пользователь: $username
Попыток: $attempts
Метод: $method
Время: $time

Ссылка в админ‑панели: {$url}/options-general.php?page=advanced-security-blocker
EOT;
        wp_mail($admin, $subject, $msg);
    }

    private function send_telegram_message($text) {
        $token = get_option('asb_telegram_token');
        $chat  = get_option('asb_telegram_chat_id');
        if (!$token || !$chat) return;

        $url = "https://api.telegram.org/bot{$token}/sendMessage";
        wp_remote_post($url, [
            'body'    => ['chat_id' => $chat, 'text' => $text, 'parse_mode' => 'HTML'],
            'timeout' => 5
        ]);
    }

    /* ==========================================================
       13. Статистика и AJAX
       ========================================================== */

    private function get_login_attempts_stats() {
        global $wpdb;
        $tbl = $wpdb->prefix . 'security_login_attempts';

        $total = $wpdb->get_var("SELECT COUNT(*) FROM $tbl WHERE attempt_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        $blocked = $wpdb->get_var("SELECT COUNT(DISTINCT ip_address) FROM $tbl WHERE blocked=1 AND attempt_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)");

        $top = $wpdb->get_results(
            "SELECT ip_address, COUNT(*) AS attempts, MAX(blocked) AS is_blocked
             FROM $tbl
             WHERE attempt_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)
             GROUP BY ip_address
             ORDER BY attempts DESC
             LIMIT 10"
        );

        $recent = $wpdb->get_results(
            "SELECT ip_address, username, attempt_time, blocked, user_agent
             FROM $tbl
             ORDER BY attempt_time DESC
             LIMIT 20"
        );

        return [
            'total_attempts' => (int)$total,
            'blocked_ips'    => (int)$blocked,
            'top_ips'        => $top,
            'recent_attempts'=> $recent
        ];
    }

    /**
     * История разблокировок
     */
    private function get_unblock_history($limit = 20) {
        global $wpdb;
        $tbl = $wpdb->prefix . 'security_unblock_history';
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM $tbl ORDER BY unblock_time DESC LIMIT %d",
                $limit
            )
        );
    }

    /**
     * История блокировок IP
     */
    private function get_block_history($ip) {
        global $wpdb;
        $tbl = $wpdb->prefix . 'security_login_attempts';
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT username, attempt_time, user_agent, blocked
                 FROM $tbl
                 WHERE ip_address = %s
                 ORDER BY attempt_time DESC
                 LIMIT 10",
                $ip
            )
        );
    }

    public function ajax_get_login_stats() {
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        check_ajax_referer('asb_ajax_nonce', 'nonce');
        $stats = $this->get_login_attempts_stats();
        wp_send_json_success($stats);
    }

    public function ajax_get_recent_attempts() {
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        check_ajax_referer('asb_ajax_nonce', 'nonce');
        $stats = $this->get_login_attempts_stats();
        wp_send_json_success(['recent_attempts' => $stats['recent_attempts']]);
    }

    public function ajax_get_block_history() {
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        check_ajax_referer('asb_ajax_nonce', 'nonce');
        if (!isset($_POST['ip'])) wp_send_json_error('IP not provided');

        $ip = sanitize_text_field($_POST['ip']);
        $hist = $this->get_block_history($ip);
        wp_send_json_success($hist);
    }

    public function ajax_get_blocked_ips_table() {
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        check_ajax_referer('asb_ajax_nonce', 'nonce');

        $search = sanitize_text_field($_POST['search'] ?? '');
        $page   = max(1, intval($_POST['page'] ?? 1));
        $per    = 20;

        $data = $this->get_all_blocked_ips($search, $page, $per);
        ob_start();
        ?>
        <?php if (empty($data['blocks'])): ?>
            <p>Нет заблокированных IP.</p>
        <?php else: ?>
            <div class="tablenav top">
                <div class="tablenav-pages">
                    <span class="displaying-num"><?php echo $data['total']; ?> элементов</span>
                    <?php if ($data['pages'] > 1): ?>
                        <span class="pagination-links">
                            <?php if ($page > 1): ?>
                                <a class="first-page button" href="#" data-page="1">«</a>
                                <a class="prev-page button" href="#" data-page="<?php echo $page - 1; ?>">‹</a>
                            <?php endif; ?>
                            <span class="paging-input"><span class="current-page"><?php echo $page; ?></span> из <span class="total-pages"><?php echo $data['pages']; ?></span></span>
                            <?php if ($page < $data['pages']): ?>
                                <a class="next-page button" href="#" data-page="<?php echo $page + 1; ?>">›</a>
                                <a class="last-page button" href="#" data-page="<?php echo $data['pages']; ?>">»</a>
                            <?php endif; ?>
                        </span>
                    <?php endif; ?>
                </div>
            </div>

            <table class="attempts-table">
                <thead>
                    <tr>
                        <th>IP / ASN</th>
                        <th>Тип блокировки</th>
                        <th>Запись</th>
                        <th>Последняя попытка</th>
                        <th>Действия</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($data['blocks'] as $b): ?>
                    <tr>
                        <td><?php echo esc_html($b['ip']); ?></td>
                        <td><?php
                            $labels = [
                                'temporary' => '<span style="color:orange;">Временная</span>',
                                'permanent'=> '<span style="color:red;">Постоянная</span>',
                                'htaccess' => '<span style="color:purple;">.htaccess</span>'
                            ];
                            echo $labels[$b['type']] ?? $b['type'];
                        ?></td>
                        <td><?php
                            $type = 'IP';
                            if (strpos($b['ip'], 'AS') === 0) $type = 'ASN';
                            elseif (strpos($b['ip'], '/') !== false) $type = 'CIDR';
                            echo $type;
                        ?></td>
                        <td><?php echo esc_html($b['last_attempt']); ?></td>
                        <td>
                            <a href="<?php echo wp_nonce_url(
                                admin_url('options-general.php?page=advanced-security-blocker&unblock_ip=' . $b['ip'] . '&tab=manage-blocks&paged=' . $page . '&s=' . urlencode($search)), 'unblock_ip'); ?>" class="button" onclick="return confirm('Разблокировать?');">Разблокировать</a>
                            <button class="button view-history-btn" data-ip="<?php echo esc_attr($b['ip']); ?>">История</button>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>

            <div class="tablenav bottom">
                <div class="tablenav-pages">
                    <span class="displaying-num"><?php echo $data['total']; ?> элементов</span>
                    <?php if ($data['pages'] > 1): ?>
                        <span class="pagination-links">
                            <?php if ($page > 1): ?>
                                <a class="first-page button" href="#" data-page="1">«</a>
                                <a class="prev-page button" href="#" data-page="<?php echo $page - 1; ?>">‹</a>
                            <?php endif; ?>
                            <span class="paging-input"><span class="current-page"><?php echo $page; ?></span> из <span class="total-pages"><?php echo $data['pages']; ?></span></span>
                            <?php if ($page < $data['pages']): ?>
                                <a class="next-page button" href="#" data-page="<?php echo $page + 1; ?>">›</a>
                                <a class="last-page button" href="#" data-page="<?php echo $data['pages']; ?>">»</a>
                            <?php endif; ?>
                        </span>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>
        <?php
        $html = ob_get_clean();
        wp_send_json_success([
            'table_html'   => $html,
            'total'        => $data['total'],
            'pages'        => $data['pages'],
            'current_page' => $page
        ]);
    }

    private function get_all_blocked_ips($search = '', $page = 1, $per_page = 20) {
        global $wpdb;
        $result = [
            'temporary' => [],
            'permanent' => [],
            'htaccess'  => []
        ];

        $tbl = $wpdb->prefix . 'security_login_attempts';
        $duration = intval(get_option('asb_block_duration', 60));

        // Временные из БД - только если длительность блокировки > 0
        if ($duration > 0) {
            $temp = $wpdb->get_results($wpdb->prepare(
                "SELECT DISTINCT ip_address, MAX(attempt_time) AS last_attempt
                 FROM $tbl
                 WHERE blocked=1 AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)
                 GROUP BY ip_address",
                $duration
            ));
            foreach ($temp as $r) {
                $result['temporary'][] = ['ip' => $r->ip_address, 'last_attempt' => $r->last_attempt, 'type' => 'temporary'];
            }
        }

        // Постоянные из опции (когда длительность = 0)
        $perm = get_option('asb_wp_blocked_ips', '');
        if ($perm) {
            foreach (array_filter(array_map('trim', explode("\n", $perm))) as $ip) {
                // Проверяем, есть ли этот IP во временных блокировках
                $is_temporary = false;
                foreach ($result['temporary'] as $temp_ip) {
                    if ($temp_ip['ip'] === $ip) {
                        $is_temporary = true;
                        break;
                    }
                }
                if (!$is_temporary) {
                    $result['permanent'][] = ['ip' => $ip, 'last_attempt' => 'N/A', 'type' => 'permanent'];
                }
            }
        }

        // .htaccess
        $ht = $this->get_current_ips();
        if ($ht) {
            foreach (array_filter(explode("\n", $ht)) as $ip) {
                // Проверяем, есть ли этот IP уже в постоянных или временных
                $exists = false;
                foreach ($result['permanent'] as $p) {
                    if ($p['ip'] === $ip) {
                        $exists = true;
                        break;
                    }
                }
                foreach ($result['temporary'] as $t) {
                    if ($t['ip'] === $ip) {
                        $exists = true;
                        break;
                    }
                }
                if (!$exists) {
                    $result['htaccess'][] = ['ip' => $ip, 'last_attempt' => 'N/A', 'type' => 'htaccess'];
                }
            }
        }

        // Объединяем
        $all = array_merge($result['temporary'], $result['permanent'], $result['htaccess']);

        // Поиск
        if (!empty($search)) {
            $all = array_filter($all, fn($b) => stripos($b['ip'], $search) !== false);
        }

        $total = count($all);
        $offset = ($page - 1) * $per_page;
        $paged = array_slice($all, $offset, $per_page);

        return [
            'blocks' => $paged,
            'total' => $total,
            'pages' => ceil($total / $per_page)
        ];
    }
	
	/* ==========================================================
   Myip.ms Integration Logic (Улучшенная версия с альтернативами)
   ========================================================== */

public function ajax_run_myipms_update() {
    if (!current_user_can('manage_options')) wp_send_json_error(['message' => 'Нет прав']);
    check_ajax_referer('asb_ajax_nonce', 'nonce');
    
    if (get_option('asb_myipms_enabled') !== '1') {
        wp_send_json_error(['message' => 'Функция отключена в настройках']);
    }
    
    // Запуск процесса
    $result = $this->process_myipms_update();
    
    if ($result === true) {
        $log_messages = isset($this->log) ? implode("\n", $this->log) : 'Успешно';
        wp_send_json_success([
            'message' => 'Списки Myip.ms успешно обновлены!',
            'log' => $log_messages
        ]);
    } else {
        wp_send_json_error([
            'message' => 'Ошибка обновления: ' . $result,
            'log' => isset($this->log) ? implode("\n", $this->log) : ''
        ]);
    }
}

public function process_myipms_update() {
    if (get_option('asb_myipms_enabled') !== '1') return 'Disabled';

    $this->log = []; // Очищаем лог для этого запуска
    $mode = get_option('asb_myipms_mode', 'htaccess');
    $this->log[] = "Запуск обновления Myip.ms (Режим: $mode) в " . date('Y-m-d H:i:s');
    
    // Проверка доступности серверов
    $this->log[] = "Проверка доступности Myip.ms...";
    if (!$this->check_myipms_availability()) {
        $this->log[] = "Myip.ms недоступен, используем альтернативные методы...";
        return $this->try_alternative_methods($mode);
    }

    // 1. Основные URL для загрузки
    $urls = [
        'https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt',
        'https://myip.ms/files/blacklist/htaccess/latest_blacklist_users_submitted.txt',
        // Альтернативные URL на тот же самый список
        'http://myip.ms/files/blacklist/htaccess/latest_blacklist.txt',
        'https://myip.ms/files/blacklist/csf/latest_blacklist.txt',
        'https://myip.ms/files/blacklist/apache_deny/latest_blacklist.txt'
    ];

    $all_data = '';
    $success_count = 0;
    
    foreach ($urls as $index => $url) {
        $this->log[] = "Попытка $index: $url";
        $data = $this->myipms_fetch_and_validate($url);
        
        if ($data !== false && !empty(trim($data))) {
            $all_data .= trim($data) . "\n";
            $success_count++;
            $this->log[] = "✓ Данные получены с $url";
            
            // Если получили достаточно данных, можно остановиться
            if ($success_count >= 2) {
                break;
            }
        } else {
            $this->log[] = "✗ Не удалось получить данные с $url";
        }
        
        // Небольшая пауза между запросами
        if ($index < count($urls) - 1) {
            sleep(1);
        }
    }

    // Если не получили данные обычным способом
    if (empty(trim($all_data))) {
        $this->log[] = "Обычные методы не сработали, пробуем прямой cURL...";
        $all_data = $this->try_direct_fetch_methods();
    }
    
    // Если все еще нет данных, пробуем альтернативные источники
    if (empty(trim($all_data))) {
        $this->log[] = "Пробуем альтернативные источники...";
        $all_data = $this->fetch_from_alternative_sources();
    }

    // Если совсем нет данных
    if (empty(trim($all_data))) {
        $err = 'Не удалось получить данные ни с одного источника';
        $this->log[] = $err;
        // Пробуем использовать кэшированные данные
        return $this->use_cached_data_if_available($mode);
    }

    // 2. Обработка в зависимости от режима
    try {
        $this->log[] = "Обработка " . count(explode("\n", $all_data)) . " строк данных...";
        
        if ($mode === 'htaccess') {
            // В режиме .htaccess удаляем файл кеша WP, чтобы не занимал место
            if (file_exists($this->myipms_list_file)) {
                @unlink($this->myipms_list_file);
                $this->log[] = "Файл кеша удален";
            }
            
            $result = $this->update_myipms_htaccess($all_data);
            if ($result !== true) throw new Exception($result);
            
        } elseif ($mode === 'wp') {
            // В режиме WP удаляем правила из .htaccess
            $this->clean_myipms_rules(true); 
            
            $result = $this->update_myipms_file($all_data);
            if ($result !== true) throw new Exception($result);
        }
        
        // Сохраняем данные в кэш на будущее
        $this->save_to_cache($all_data);
        
        update_option('asb_myipms_last_update', current_time('mysql'));
        update_option('asb_myipms_last_count', count(array_filter(explode("\n", $all_data), function($line) {
            return strpos($line, 'Deny from') === 0;
        })));
        
        $this->log[] = 'Обновление Myip.ms завершено успешно!';
        $this->log[] = 'Время выполнения: ' . timer_stop(0) . ' сек.';
        
        return true;

    } catch (Exception $e) {
        $this->log[] = 'Критическая ошибка: ' . $e->getMessage();
        
        // Пробуем откатиться к кэшированным данным
        $this->log[] = 'Пробуем восстановить из кэша...';
        $cache_result = $this->use_cached_data_if_available($mode);
        
        if ($cache_result === true) {
            $this->log[] = 'Успешно восстановлено из кэша';
            return true;
        }
        
        return $e->getMessage();
    }
}

private function check_myipms_availability() {
    // Проверяем несколько способов доступности
    
    // Способ 1: DNS проверка
    if (!gethostbyname('myip.ms')) {
        $this->log[] = "DNS myip.ms не разрешается";
        return false;
    }
    
    // Способ 2: Быстрый HTTP HEAD запрос
    $test_urls = [
        'https://myip.ms',
        'http://myip.ms',
        'https://myip.ms/files/blacklist/'
    ];
    
    foreach ($test_urls as $test_url) {
        $args = [
            'timeout' => 5,
            'sslverify' => false,
            'method' => 'HEAD'
        ];
        
        $response = wp_remote_head($test_url, $args);
        
        if (!is_wp_error($response)) {
            $code = wp_remote_retrieve_response_code($response);
            $this->log[] = "Проверка $test_url: HTTP $code";
            
            if ($code == 200 || $code == 301 || $code == 302) {
                return true;
            }
        }
    }
    
    return false;
}

private function myipms_fetch_and_validate($url) {
    $this->log[] = "Загрузка: " . parse_url($url, PHP_URL_HOST);
    
    // Пробуем разные методы
    $methods = [
        'wp_remote_get_ssl_false',
        'wp_remote_get_ssl_true',
        'curl_direct',
        'file_get_contents'
    ];
    
    foreach ($methods as $method) {
        $this->log[] = "  Метод: $method";
        
        switch ($method) {
            case 'wp_remote_get_ssl_false':
                $args = [
                    'timeout' => 15,
                    'sslverify' => false,
                    'redirection' => 5,
                    'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'headers' => [
                        'Accept' => 'text/plain,text/html,application/xhtml+xml',
                        'Accept-Language' => 'en-US,en;q=0.9',
                        'Accept-Encoding' => 'gzip, deflate',
                        'Cache-Control' => 'no-cache',
                        'Connection' => 'keep-alive',
                        'Pragma' => 'no-cache'
                    ]
                ];
                $response = wp_remote_get($url, $args);
                break;
                
            case 'wp_remote_get_ssl_true':
                $args['sslverify'] = true;
                $args['timeout'] = 20;
                $response = wp_remote_get($url, $args);
                break;
                
            case 'curl_direct':
                $response = $this->curl_fetch_direct($url);
                break;
                
            case 'file_get_contents':
                $response = $this->file_get_contents_fetch($url);
                break;
        }
        
        if ($method == 'curl_direct' || $method == 'file_get_contents') {
            if ($response !== false) {
                $content = $response;
                $code = 200;
            } else {
                continue;
            }
        } else {
            if (is_wp_error($response)) {
                $this->log[] = "    Ошибка: " . $response->get_error_message();
                continue;
            }
            
            $code = wp_remote_retrieve_response_code($response);
            $content = wp_remote_retrieve_body($response);
            
            if ($code !== 200) {
                $this->log[] = "    HTTP код: $code";
                continue;
            }
        }
        
        // Проверяем содержимое
        if (empty($content)) {
            $this->log[] = "    Пустой ответ";
            continue;
        }
        
        $size = strlen($content);
        $this->log[] = "    Получено: " . $size . " байт";
        
        // Проверяем, что это действительно blacklist
        if (strpos($content, 'Deny from') !== false || 
            strpos($content, 'myip.ms') !== false ||
            preg_match('/[0-9a-fA-F:]{2,}/', $content)) { // Исправлена проверка для IPv6
            
            $validated = $this->validate_and_parse_content($content);
            if ($validated !== false) {
                $this->log[] = "    ✓ Валидация успешна";
                return $validated;
            }
        } else {
            $this->log[] = "    Не похоже на blacklist";
            // Сохраняем для отладки
            file_put_contents(WP_CONTENT_DIR . '/debug_myipms_' . time() . '.txt', $content);
        }
    }
    
    return false;
}

private function curl_fetch_direct($url) {
    if (!function_exists('curl_init')) {
        $this->log[] = "cURL не доступен";
        return false;
    }
    
    $ch = curl_init();
    
    $options = [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 25,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        CURLOPT_ENCODING => 'gzip, deflate',
        CURLOPT_HTTPHEADER => [
            'Accept: text/plain,text/html,application/xhtml+xml',
            'Accept-Language: en-US,en;q=0.9',
            'Cache-Control: no-cache',
            'Pragma: no-cache'
        ],
        CURLOPT_HEADER => false,
        CURLOPT_FAILONERROR => true
    ];
    
    // Пробуем разные SSL варианты
    static $ssl_try = 0;
    if ($ssl_try++ % 2 == 0) {
        $options[CURLOPT_SSL_VERIFYPEER] = true;
        $options[CURLOPT_SSL_VERIFYHOST] = 2;
    }
    
    curl_setopt_array($ch, $options);
    
    $content = curl_exec($ch);
    
    if (curl_errno($ch)) {
        $this->log[] = "cURL ошибка: " . curl_error($ch);
        curl_close($ch);
        return false;
    }
    
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code !== 200) {
        $this->log[] = "cURL HTTP код: $http_code";
        return false;
    }
    
    return $content;
}

private function file_get_contents_fetch($url) {
    // Пробуем file_get_contents с контекстом
    $context_options = [
        'http' => [
            'method' => 'GET',
            'timeout' => 15,
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'header' => "Accept: text/plain\r\n"
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false
        ]
    ];
    
    $context = stream_context_create($context_options);
    
    // Пробуем обернуть в try-catch
    try {
        $content = @file_get_contents($url, false, $context);
        return $content !== false ? $content : false;
    } catch (Exception $e) {
        $this->log[] = "file_get_contents ошибка: " . $e->getMessage();
        return false;
    }
}

private function validate_and_parse_content($content) {
    $lines = explode("\n", $content);
    $valid_lines = [];
    $ip_count = 0;
    $comment_count = 0;
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        
        // Разные форматы Myip.ms
        // UPDATED: Добавлена поддержка IPv6 символов (двоеточие и hex) в регулярное выражение
        if (preg_match('/^Deny from\s+([0-9a-fA-F\.\/:]+)/i', $line, $matches)) {
            $valid_lines[] = "Deny from " . trim($matches[1]);
            $ip_count++;
        }
        // Просто IP/CIDR (IPv4)
        elseif (preg_match('/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\/[0-9]{1,2})?)$/', $line, $matches)) {
            $valid_lines[] = "Deny from " . $matches[1];
            $ip_count++;
        }
        // IPv6 (простая проверка)
        elseif (strpos($line, ':') !== false && preg_match('/^([0-9a-fA-F:\/]+)$/i', $line, $matches)) {
            // Простейшая проверка, что это похоже на IP
            if (strpos($line, ':') !== false && strlen($line) > 2) {
                $valid_lines[] = "Deny from " . trim($matches[1]);
                $ip_count++;
            }
        }
        // Формат: 1.2.3.4/24 # комментарий или IPv6 # комментарий
        // UPDATED: Добавлена поддержка IPv6
        elseif (preg_match('/^([0-9a-fA-F\.\/:]+)\s*#/', $line, $matches)) {
            $valid_lines[] = "Deny from " . trim($matches[1]);
            $ip_count++;
        }
        // Комментарии сохраняем
        elseif (strpos($line, '#') === 0 || strpos($line, '//') === 0 || strpos($line, '##') === 0) {
            $valid_lines[] = $line;
            $comment_count++;
        }
        // Пропускаем HTML теги если они есть
        elseif (strpos($line, '<') === false && strpos($line, '>') === false) {
            // Пробуем найти IPv4 в строке
            if (preg_match('/(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)/', $line, $matches)) {
                $valid_lines[] = "Deny from " . $matches[1];
                $ip_count++;
            }
            // Пробуем найти IPv6 в строке (эвристика: группы hex с двоеточиями)
            elseif (preg_match('/([0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:\/]+/', $line, $matches)) {
                 $valid_lines[] = "Deny from " . $matches[0];
                 $ip_count++;
            }
        }
    }
    
    $this->log[] = "Найдено IP: $ip_count, комментариев: $comment_count";
    
    if ($ip_count > 0) {
        return implode("\n", $valid_lines);
    }
    
    // Если не нашли IP, но есть контент, возможно другой формат
    if (!empty($content) && strlen($content) > 100) {
        $this->log[] = "Контент получен, но не распознан. Сохраняем для анализа.";
        file_put_contents(WP_CONTENT_DIR . '/myipms_raw_' . time() . '.txt', $content);
    }
    
    return false;
}

private function try_direct_fetch_methods() {
    $this->log[] = "Прямой сбор данных с Myip.ms...";
    
    // Попробуем получить со страницы списков
    $methods = [
        'https://myip.ms/files/blacklist/general/latest_blacklist.txt',
        'https://myip.ms/files/blacklist/csf/latest_blacklist.txt',
        'https://myip.ms/files/blacklist/apache_deny/latest_blacklist.txt'
    ];
    
    $all_data = '';
    
    foreach ($methods as $url) {
        $this->log[] = "Прямая загрузка: $url";
        
        // Используем cURL с более агрессивными настройками
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            CURLOPT_ENCODING => 'gzip, deflate',
            CURLOPT_HTTPHEADER => [
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.5',
                'Connection: keep-alive',
                'Upgrade-Insecure-Requests: 1',
                'Cache-Control: max-age=0'
            ],
            CURLOPT_COOKIEJAR => '/tmp/myipms_cookie.txt',
            CURLOPT_COOKIEFILE => '/tmp/myipms_cookie.txt'
        ]);
        
        $content = curl_exec($ch);
        
        if (!curl_errno($ch)) {
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            if ($http_code == 200) {
                $parsed = $this->validate_and_parse_content($content);
                if ($parsed !== false) {
                    $all_data .= $parsed . "\n";
                    $this->log[] = "✓ Прямая загрузка успешна";
                }
            }
        }
        
        curl_close($ch);
        
        if (!empty($all_data)) {
            break;
        }
    }
    
    return $all_data;
}

private function fetch_from_alternative_sources() {
    $this->log[] = "Используем альтернативные источники...";
    
    $alternative_sources = [
        [
            'url' => 'https://www.badips.com/get/list/any/1',
            'format' => 'ip_only'
        ],
        [
            'url' => 'https://lists.blocklist.de/lists/apache.txt',
            'format' => 'ip_only'
        ],
        [
            'url' => 'https://www.spamhaus.org/drop/drop.txt',
            'format' => 'spamhaus'
        ],
        [
            'url' => 'https://www.spamhaus.org/drop/edrop.txt',
            'format' => 'spamhaus'
        ],
        [
            'url' => 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
            'format' => 'ip_only'
        ],
        [
            'url' => 'https://check.torproject.org/torbulkexitlist',
            'format' => 'ip_only'
        ]
    ];
    
    $all_ips = [];
    $source_count = 0;
    
    foreach ($alternative_sources as $source) {
        $this->log[] = "Альтернативный источник: " . parse_url($source['url'], PHP_URL_HOST);
        
        $args = [
            'timeout' => 15,
            'sslverify' => false,
            'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        ];
        
        $response = wp_remote_get($source['url'], $args);
        
        if (is_wp_error($response)) {
            $this->log[] = "  Ошибка: " . $response->get_error_message();
            continue;
        }
        
        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            $this->log[] = "  HTTP код: $code";
            continue;
        }
        
        $content = wp_remote_retrieve_body($response);
        
        if (empty($content)) {
            continue;
        }
        
        $ips = $this->parse_alternative_source($content, $source['format']);
        if (!empty($ips)) {
            $all_ips = array_merge($all_ips, $ips);
            $source_count++;
            $this->log[] = "  ✓ Добавлено " . count($ips) . " IP";
        }
        
        if ($source_count >= 2) {
            break; // Достаточно источников
        }
        
        sleep(1); // Пауза между запросами
    }
    
    if (!empty($all_ips)) {
        $all_ips = array_unique($all_ips);
        $result = "# Blacklist from alternative sources (" . date('Y-m-d') . ")\n";
        $result .= "# Total IPs: " . count($all_ips) . "\n";
        
        foreach ($all_ips as $ip) {
            $result .= "Deny from $ip\n";
        }
        
        $this->log[] = "Альтернативные источники: собрано " . count($all_ips) . " уникальных IP";
        return $result;
    }
    
    return '';
}

private function parse_alternative_source($content, $format) {
    $ips = [];
    $lines = explode("\n", $content);
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line) || strpos($line, '#') === 0) {
            continue;
        }
        
        switch ($format) {
            case 'ip_only':
                // UPDATED: Добавлена поддержка IPv6
                if (preg_match('/^([0-9a-fA-F\.\/:]+)$/', $line, $matches)) {
                    $ips[] = $matches[1];
                }
                break;
                
            case 'spamhaus':
                // UPDATED: Добавлена поддержка IPv6
                if (preg_match('/^([0-9a-fA-F\.\/:]+)\s*;\s*S/', $line, $matches)) {
                    $ips[] = $matches[1];
                }
                break;
                
            default:
                // Пробуем найти любой IP/CIDR (включая IPv6)
                if (preg_match('/([0-9a-fA-F\.\/:]+)/', $line, $matches)) {
                    // Базовая валидация длины, чтобы не цеплять мусор
                    if(strlen($matches[1]) >= 7) {
                         $ips[] = $matches[1];
                    }
                }
        }
    }
    
    return $ips;
}

private function use_cached_data_if_available($mode) {
    $cache_file = WP_CONTENT_DIR . '/uploads/myipms_cache.txt';
    $backup_file = WP_CONTENT_DIR . '/uploads/myipms_backup.txt';
    
    // Пробуем основной кэш
    if (file_exists($cache_file) && filesize($cache_file) > 100) {
        $cache_time = filemtime($cache_file);
        $age = time() - $cache_time;
        
        if ($age < 604800) { // Не старше 7 дней
            $cached_data = file_get_contents($cache_file);
            $this->log[] = "Используем кэшированные данные (возраст: " . floor($age/3600) . " часов)";
            
            try {
                if ($mode === 'htaccess') {
                    $this->update_myipms_htaccess($cached_data);
                } else {
                    $this->update_myipms_file($cached_data);
                }
                
                $this->log[] = "Система восстановлена из кэша";
                return true;
            } catch (Exception $e) {
                $this->log[] = "Ошибка восстановления из кэша: " . $e->getMessage();
            }
        }
    }
    
    // Пробуем backup
    if (file_exists($backup_file) && filesize($backup_file) > 100) {
        $cached_data = file_get_contents($backup_file);
        $this->log[] = "Используем backup данные";
        
        try {
            if ($mode === 'htaccess') {
                $this->update_myipms_htaccess($cached_data);
            } else {
                $this->update_myipms_file($cached_data);
            }
            
            $this->log[] = "Система восстановлена из backup";
            return true;
        } catch (Exception $e) {
            $this->log[] = "Ошибка восстановления из backup: " . $e->getMessage();
        }
    }
    
    return "Нет доступных данных (ни онлайн, ни в кэше)";
}

private function save_to_cache($data) {
    $cache_file = WP_CONTENT_DIR . '/uploads/myipms_cache.txt';
    $backup_file = WP_CONTENT_DIR . '/uploads/myipms_backup.txt';
    
    // Создаем директорию если нужно
    $upload_dir = WP_CONTENT_DIR . '/uploads';
    if (!file_exists($upload_dir)) {
        mkdir($upload_dir, 0755, true);
    }
    
    // Сохраняем в кэш
    if (file_put_contents($cache_file, $data) !== false) {
        $this->log[] = "Данные сохранены в кэш: " . basename($cache_file);
    }
    
    // Делаем backup раз в день
    if (!file_exists($backup_file) || (time() - filemtime($backup_file)) > 86400) {
        copy($cache_file, $backup_file);
        $this->log[] = "Backup создан";
    }
}

private function update_myipms_htaccess($content) {
    if (!file_exists($this->htaccess_path)) {
        // Создаем .htaccess если его нет
        file_put_contents($this->htaccess_path, "# WordPress\n");
    }
    
    if (!is_writable($this->htaccess_path)) {
        // Пробуем изменить права
        @chmod($this->htaccess_path, 0644);
        
        if (!is_writable($this->htaccess_path)) {
            throw new Exception('.htaccess недоступен для записи. Права: ' . decoct(fileperms($this->htaccess_path)));
        }
    }

    $htaccess = file_get_contents($this->htaccess_path);
    if ($htaccess === false) {
        throw new Exception('Не удалось прочитать .htaccess');
    }
    
    // Удаляем старый блок (используем более надежный паттерн)
    $pattern = '/\n?' . preg_quote($this->marker_myipms, '/') . '.*?' . preg_quote($this->marker_myipms, '/') . '/s';
    $htaccess = preg_replace($pattern, '', $htaccess);
    
    // Формируем новый блок
    $block = "\n{$this->marker_myipms}\n";
    $block .= "# Myip.ms Blacklist Auto Update (" . date('Y-m-d H:i:s') . ")\n";
    $block .= "# Generated by Anti-Spam Bot\n";
    $block .= $content;
    $block .= "\n{$this->marker_myipms}\n";
    
    // Вставляем блок после RewriteEngine On если есть
    if (strpos($htaccess, 'RewriteEngine On') !== false) {
        $htaccess = preg_replace(
            '/(RewriteEngine On\s*)/',
            "$1\n" . $block,
            $htaccess
        );
    } else {
        // Или в начало файла
        $htaccess = $block . $htaccess;
    }
    
    // Создаем backup .htaccess
    $backup_path = $this->htaccess_path . '.backup_' . date('Ymd');
    if (!file_exists($backup_path)) {
        copy($this->htaccess_path, $backup_path);
    }
    
    if (file_put_contents($this->htaccess_path, $htaccess) === false) {
        throw new Exception('Не удалось записать в .htaccess');
    }

    $this->log[] = '.htaccess успешно обновлен (' . strlen($htaccess) . ' байт)';
    return true;
}

private function update_myipms_file($raw_content) {
    // Проверка прав на директорию
    $dir = dirname($this->myipms_list_file);
    if (!file_exists($dir)) {
        if (!mkdir($dir, 0755, true)) {
            throw new Exception('Не удалось создать директорию для файла кеша');
        }
    }

    $lines = explode("\n", $raw_content);
    $clean_ips = [];
    
    foreach ($lines as $line) {
        // Парсим только IP/CIDR из строк "Deny from X.X.X.X"
        // UPDATED: Регулярное выражение теперь захватывает и IPv6
        if (preg_match('/^Deny from\s+([0-9a-fA-F\.\/:]+)/i', trim($line), $matches)) {
            $clean_ips[] = trim($matches[1]);
        }
    }
    
    if (!empty($clean_ips)) {
        $clean_ips = array_unique($clean_ips);
        $content = implode("\n", $clean_ips);
        $result = file_put_contents($this->myipms_list_file, $content);
        
        if ($result === false) {
            throw new Exception('Не удалось записать в файл: ' . $this->myipms_list_file . '. Проверьте права доступа.');
        }
        
        $this->log[] = 'Файл списка WP обновлен. Записей: ' . count($clean_ips);
        return true;
    } else {
        $this->log[] = 'Предупреждение: Не найдено валидных IP для записи в файл.';
        return false;
    }
}

private function clean_myipms_rules($htaccess_only = false) {
    // Очистка .htaccess
    if (file_exists($this->htaccess_path) && is_readable($this->htaccess_path)) {
        $htaccess = file_get_contents($this->htaccess_path);
        $pattern = '/\n?' . preg_quote($this->marker_myipms, '/') . '.*?' . preg_quote($this->marker_myipms, '/') . '/s';
        
        if (preg_match($pattern, $htaccess)) {
            $htaccess = preg_replace($pattern, '', $htaccess);
            if (file_put_contents($this->htaccess_path, $htaccess) !== false) {
                $this->log[] = 'Правила Myip.ms удалены из .htaccess';
            }
        }
    }
    
    // Очистка файла кеша (только если не запрошена очистка только htaccess)
    if (!$htaccess_only) {
        if (file_exists($this->myipms_list_file)) {
            if (@unlink($this->myipms_list_file)) {
                $this->log[] = 'Файл кеша Myip.ms удален';
            }
        }
    }
}

private function try_alternative_methods($mode) {
    $this->log[] = "Пробуем обходные методы...";
    
    // Метод 1: Через proxy если есть
    $proxy_data = $this->fetch_via_proxy();
    if (!empty($proxy_data)) {
        $this->log[] = "Получено данных через proxy";
        return $this->process_alternative_data($proxy_data, $mode);
    }
    
    // Метод 2: Генерация на основе старых данных
    $generated_data = $this->generate_based_on_history();
    if (!empty($generated_data)) {
        $this->log[] = "Сгенерировано на основе истории";
        return $this->process_alternative_data($generated_data, $mode);
    }
    
    return "Все методы не сработали";
}

private function fetch_via_proxy() {
    // Список публичных proxy (осторожно, они могут быть медленными)
    $proxies = [
        'https://corsproxy.io/?',
        'https://api.allorigins.win/raw?url=',
        'https://cors-anywhere.herokuapp.com/'
    ];
    
    $target_url = urlencode('https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt');
    
    foreach ($proxies as $proxy) {
        $url = $proxy . $target_url;
        $this->log[] = "Пробуем proxy: " . parse_url($proxy, PHP_URL_HOST);
        
        $response = wp_remote_get($url, ['timeout' => 20, 'sslverify' => false]);
        
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200) {
            $content = wp_remote_retrieve_body($response);
            if (!empty($content)) {
                return $this->validate_and_parse_content($content);
            }
        }
        
        sleep(1);
    }
    
    return '';
}

private function generate_based_on_history() {
    // Генерируем базовый список на основе известных плохих IP
    $basic_ips = [
        // Известные спам-сети и ботнеты
        '1.0.0.0/8',
        '2.0.0.0/8',
        '5.0.0.0/8',
        '45.0.0.0/8',
        '46.0.0.0/8',
        '77.0.0.0/8',
        '78.0.0.0/8',
        '79.0.0.0/8',
        '89.0.0.0/8',
        '93.0.0.0/8',
        '109.0.0.0/8',
        '176.0.0.0/8',
        '178.0.0.0/8',
        '185.0.0.0/8',
        '188.0.0.0/8',
        '193.0.0.0/8',
        '194.0.0.0/8',
        '195.0.0.0/8',
        '212.0.0.0/8',
        '213.0.0.0/8',
        '217.0.0.0/8'
    ];
    
    $result = "# Экстренный blacklist (сгенерирован " . date('Y-m-d') . ")\n";
    $result .= "# Myip.ms недоступен, используем базовую защиту\n";
    
    foreach ($basic_ips as $ip) {
        $result .= "Deny from $ip\n";
    }
    
    return $result;
}

private function process_alternative_data($data, $mode) {
    try {
        if ($mode === 'htaccess') {
            $this->update_myipms_htaccess($data);
        } else {
            $this->update_myipms_file($data);
        }
        
        update_option('asb_myipms_last_update', current_time('mysql'));
        update_option('asb_myipms_source', 'alternative_' . date('Ymd'));
        
        $this->log[] = 'Обновлено из альтернативных источников';
        $this->save_to_cache($data);
        
        return true;
    } catch (Exception $e) {
        return $e->getMessage();
    }
}
	
		/* ----------------------------------------------------------
       Новый AJAX-обработчик для массовой блокировки
    ---------------------------------------------------------- */
    public function ajax_batch_block_ip() {
        // Проверка прав и nonce
        if (!current_user_can('manage_options')) wp_send_json_error('Unauthorized');
        check_ajax_referer('asb_ajax_nonce', 'nonce');

        $ip = sanitize_text_field($_POST['ip'] ?? '');
        $reason = sanitize_text_field($_POST['reason'] ?? '');

        if (empty($ip)) {
            wp_send_json_error(['message' => 'Пустой IP']);
        }

        if (!$this->validate_ip_entry($ip)) {
            wp_send_json_error(['message' => "Некорректный формат: $ip"]);
        }

        // Блокируем
        $result = $this->block_ip_wordpress_only($ip, '(ручная блокировка WordPress)', $reason);

        if ($result) {
            wp_send_json_success(['message' => "Заблокирован: $ip"]);
        } else {
            // Если block_ip_wordpress_only вернул false (например, дубль)
            wp_send_json_success(['message' => "Пропущен (уже есть или ошибка): $ip"]);
        }
    }

    /* ==========================================================
   14. Обработчики форм и запросов
   ========================================================== */

/**
 * Обработчик разблокировки IP
 */
public function handle_unblock_request() {
    if (!isset($_GET['page']) || $_GET['page'] !== 'advanced-security-blocker') return;
    if (!isset($_GET['unblock_ip'])) return;
    if (!current_user_can('manage_options')) return;

    check_admin_referer('unblock_ip');

    $ip = sanitize_text_field($_GET['unblock_ip']);
    $reason = 'Разблокировано администратором';

    $this->unblock_ip_address($ip, $reason);

    $redirect = admin_url('options-general.php?page=advanced-security-blocker&tab=manage-blocks&unblocked=1');
    if (isset($_GET['paged'])) $redirect .= '&paged=' . intval($_GET['paged']);
    if (isset($_GET['s'])) $redirect .= '&s=' . urlencode($_GET['s']);

    wp_redirect($redirect);
    exit;
}

/**
 * Обработчик ручной блокировки IP
 */
public function handle_manual_block_request() {
    if (!isset($_POST['submit_manual_block'])) return;
    if (!current_user_can('manage_options')) return;

    check_admin_referer('security_blocker_update');

    $ip = sanitize_text_field($_POST['manual_block_ip'] ?? '');
    $reason = sanitize_text_field($_POST['block_reason'] ?? '');

    if (empty($ip)) {
        wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&error=invalid_ip'));
        exit;
    }

    if (!$this->validate_ip_entry($ip)) {
        wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&error=invalid_ip'));
        exit;
    }

    // Используем метод блокировки только на уровне WordPress
    $this->block_ip_wordpress_only($ip, 'manual', $reason);

    $entry_type = $this->get_entry_type($ip);
    $type_label = ($entry_type === 'ASN') ? 'ASN' : (($entry_type === 'CIDR') ? 'диапазон' : 'IP');
    
    wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=manage-blocks&manual_block=1&message=' . urlencode("{$type_label} добавлен в чёрный список (WordPress)")));
    exit;
}

/**
 * Обработчик белого списка
 */
public function handle_whitelist_request() {
    if (!isset($_GET['page']) || $_GET['page'] !== 'advanced-security-blocker') return;

    // Добавление в whitelist
    if (isset($_POST['submit_whitelist'])) {
        if (!current_user_can('manage_options')) return;
        check_admin_referer('security_blocker_update');

        $ip = sanitize_text_field($_POST['whitelist_ip'] ?? '');
        $reason = sanitize_text_field($_POST['whitelist_reason'] ?? '');

        if (!empty($ip) && $this->validate_ip_entry($ip)) {
            $this->add_to_whitelist($ip, $reason);
            wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=whitelist&whitelist_added=1'));
            exit;
        }
    }

    // Удаление из whitelist
    if (isset($_GET['remove_whitelist'])) {
        if (!current_user_can('manage_options')) return;
        check_admin_referer('remove_whitelist');

        $ip = sanitize_text_field($_GET['remove_whitelist']);
        $this->remove_from_whitelist($ip);

        wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=whitelist&whitelist_removed=1'));
        exit;
    }
}

public function handle_backup_request() {
    if (isset($_GET['page']) && $_GET['page'] === 'advanced-security-blocker' && isset($_GET['backup'])) {
        if (current_user_can('manage_options')) {
            $this->create_backup();
            wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&backup_created=1'));
            exit;
        }
    }
}

public function handle_cache_clear() {
    if (isset($_GET['page']) && $_GET['page'] === 'advanced-security-blocker' && isset($_GET['clear_cache'])) {
        if (current_user_can('manage_options')) {
            $this->clear_asn_cache();
            $this->cache_handler->clear_all_caches();
            wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&cache_cleared=1'));
            exit;
        }
    }
}

public function generate_nginx_fragment() {
    if (isset($_GET['page']) && $_GET['page'] === 'advanced-security-blocker' && isset($_GET['generate_nginx'])) {
        if (current_user_can('manage_options')) {
            $this->write_nginx_rules_file();
            wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&nginx_generated=1'));
            exit;
        }
    }
}

    /* ==========================================================
       15. Вспомогательные методы
       ========================================================== */

    private function get_user_ip() {
        // Проверка заголовка Cloudflare в первую очередь
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        $keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        foreach ($keys as $k) {
            if (!empty($_SERVER[$k])) {
                $ips = explode(',', $_SERVER[$k]);
                foreach ($ips as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $ip;
                    }
                }
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function cleanup_old_attempts() {
        global $wpdb;
        $tbl = $wpdb->prefix . 'security_login_attempts';
        $wpdb->query($wpdb->prepare(
            "DELETE FROM $tbl WHERE attempt_time < DATE_SUB(NOW(), INTERVAL %d DAY)",
            30
        ));
        $this->log[] = 'Старые попытки удалены (30 дней)';
    }

    public function enqueue_scripts($hook) {
        if ($hook !== 'settings_page_advanced-security-blocker') return;
        wp_enqueue_script('jquery');
        wp_localize_script('jquery', 'asb_ajax', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('asb_ajax_nonce')
        ]);
    }

    /* ==========================================================
       16. REST API
       ========================================================== */

    /**
     * Регистрирует маршруты REST API для управления блокировками.
     */
    public function register_rest_routes() {
        register_rest_route('asb/v1', '/block', [
            'methods'  => 'POST',
            'callback' => [$this, 'rest_block_ip'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
            'args' => [
                'target' => [
                    'required' => true,
                    'validate_callback' => function($param) { return is_string($param) && !empty($param); }
                ],
                'reason' => [
                    'required' => false,
                    'default'  => 'REST API',
                    'sanitize_callback' => 'sanitize_text_field'
                ]
            ]
        ]);
        
        register_rest_route('asb/v1', '/unblock', [
            'methods'  => 'POST',
            'callback' => [$this, 'rest_unblock_ip'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
            'args' => [
                'target' => [
                    'required' => true,
                    'validate_callback' => function($param) { return is_string($param) && !empty($param); }
                ]
            ]
        ]);

        register_rest_route('asb/v1', '/list', [
            'methods'  => 'GET',
            'callback' => [$this, 'rest_list_ips'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            }
        ]);
    }

    /**
     * REST API Callback: Блокировка IP.
     */
    public function rest_block_ip(WP_REST_Request $request) {
        $target = $request->get_param('target');
        $reason = $request->get_param('reason');
        
        $this->block_ip_address($target, 'REST API', $reason);
        
        return new WP_REST_Response([
            'success' => true,
            'message' => sprintf('IP/ASN %s заблокирован. Проверьте лог для Cloudflare.', $target),
            'log'     => $this->log,
        ], 200);
    }

    /**
     * REST API Callback: Разблокировка IP.
     */
    public function rest_unblock_ip(WP_REST_Request $request) {
        $target = $request->get_param('target');
        
        $this->unblock_ip_address($target, 'REST API');
        
        return new WP_REST_Response([
            'success' => true,
            'message' => sprintf('IP %s разблокирован. Проверьте лог для Cloudflare.', $target),
            'log'     => $this->log,
        ], 200);
    }

    /**
     * REST API Callback: Список заблокированных IP.
     */
    public function rest_list_ips(WP_REST_Request $request) {
        $list_raw = $this->get_current_ips();
        $list = array_filter(array_map('trim', explode("\n", $list_raw)));
        
        return new WP_REST_Response([
            'success' => true,
            'blocked_ips' => $list,
            'count'   => count($list),
        ], 200);
    }

    /* ==========================================================
       17. Cloudflare интеграция
       ========================================================== */

    /**
     * Проверяет, настроена ли интеграция с Cloudflare.
     */
    private function is_cloudflare_configured() {
        return (
            get_option($this->cf_email_key) &&
            get_option($this->cf_api_key) &&
            get_option($this->cf_zone_id)
        );
    }

    /**
     * Возвращает заголовки для Cloudflare API.
     */
    private function get_cf_headers() {
        return [
            'X-Auth-Email' => get_option($this->cf_email_key),
            'X-Auth-Key'   => get_option($this->cf_api_key),
            'Content-Type' => 'application/json',
        ];
    }

    /**
     * Блокирует IP/ASN в Cloudflare через Firewall Rules API.
     */
    private function block_ip_cloudflare($target, $reason) {
        if (!$this->is_cloudflare_configured()) return false;

        $zone_id = get_option($this->cf_zone_id);
        $is_asn = strpos($target, 'AS') === 0;
        $target_type = $is_asn ? 'asn' : 'ip';

        $url = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/firewall/access_rules/rules";

        $body = [
            'mode' => 'block',
            'configuration' => [
                'target' => $target_type,
                'value'  => $target,
            ],
            'notes' => "ASB: {$reason} - {$target}",
        ];

        $response = wp_remote_post($url, [
            'headers' => $this->get_cf_headers(),
            'body'    => json_encode($body),
            'data_format' => 'body',
            'timeout' => 30,
        ]);

        if (is_wp_error($response)) {
            $this->log[] = "Cloudflare Block Error: " . $response->get_error_message();
            return false;
        }

        $response_code = wp_remote_retrieve_response_code($response);
        $response_body = json_decode(wp_remote_retrieve_body($response), true);

        if ($response_code !== 200 || ($response_body['success'] ?? false) !== true) {
            $error_msg = isset($response_body['errors'][0]['message']) ? $response_body['errors'][0]['message'] : 'Неизвестная ошибка Cloudflare API.';
            $this->log[] = "Cloudflare Block Failed (Code {$response_code}): {$error_msg}";
            return false;
        }

        $this->log[] = "Cloudflare Block Success for {$target}. Rule ID: " . ($response_body['result']['id'] ?? 'N/A');
        return true;
    }

    /**
     * Разблокирует IP/ASN в Cloudflare (путем поиска и удаления правила).
     */
    private function unblock_ip_cloudflare($target) {
        if (!$this->is_cloudflare_configured()) return false;

        $zone_id = get_option($this->cf_zone_id);
        $is_asn = strpos($target, 'AS') === 0;
        $target_type = $is_asn ? 'asn' : 'ip';

        // 1. Найти Rule ID
        $search_url = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/firewall/access_rules/rules?mode=block&configuration.target={$target_type}&configuration.value={$target}&per_page=1";
        $response_search = wp_remote_get($search_url, [
            'headers' => $this->get_cf_headers(),
            'timeout' => 30,
        ]);

        if (is_wp_error($response_search) || wp_remote_retrieve_response_code($response_search) !== 200) {
            $this->log[] = "Cloudflare Unblock Error (Search): " . (is_wp_error($response_search) ? $response_search->get_error_message() : 'Ошибка поиска правила.');
            return false;
        }

        $search_body = json_decode(wp_remote_retrieve_body($response_search), true);
        $rule = $search_body['result'][0] ?? null;

        if (!$rule) {
            $this->log[] = "Cloudflare Unblock Warning: Правило не найдено для {$target}.";
            return true;
        }

        $rule_id = $rule['id'];

        // 2. Удалить правило
        $delete_url = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/firewall/access_rules/rules/{$rule_id}";
        $response_delete = wp_remote_request($delete_url, [
            'method'  => 'DELETE',
            'headers' => $this->get_cf_headers(),
            'timeout' => 30,
        ]);

        if (is_wp_error($response_delete) || wp_remote_retrieve_response_code($response_delete) !== 200) {
            $this->log[] = "Cloudflare Unblock Failed (Delete): " . (is_wp_error($response_delete) ? $response_delete->get_error_message() : 'Неизвестная ошибка Cloudflare API при удалении.');
            return false;
        }

        $this->log[] = "Cloudflare Unblock Success for {$target} (Rule ID: {$rule_id}).";
        return true;
    }

    /* ==========================================================
       18. Журнал и Аналитика Атак
       ========================================================== */

    /**
     * Записывает попытку атаки в журнал.
     *
     * @param string $ip IP-адрес атакующего.
     * @param string $type Тип атаки.
     * @param string $target Цель (файл, имя пользователя).
     */
    public function log_attack($ip, $type, $target = '') {
        $log_entry = [
            'time'   => time(),
            'ip'     => $ip,
            'type'   => sanitize_text_field($type), // e.g., 'login_fail', '404_access', 'honeypot'
            'target' => sanitize_text_field($target), // e.g., requested file, username
        ];

        $log = get_option(self::ASB_ATTACK_LOG_KEY, []);

        // Ограничение размера журнала (например, 5000 записей)
        if (count($log) > 5000) {
            // Удаляем 100 старых записей
            $log = array_slice($log, 100);
        }

        $log[] = $log_entry;
        update_option(self::ASB_ATTACK_LOG_KEY, $log, 'no');
    }

    /**
     * Получает агрегированные данные для аналитики
     */
    private function get_analytics_data() {
        $log = get_option(self::ASB_ATTACK_LOG_KEY, []);
        
        if (!is_array($log)) {
            $log = [];
        }

        $data = [
            'total_attacks' => count($log),
            'attacks_by_type' => [],
            'attacks_by_day' => [],
            'blocked_ips_count' => count(array_filter(explode("\n", $this->get_current_ips()))),
            'unique_attackers' => [],
            'unique_attackers_count' => 0
        ];

        // Инициализируем массивы для последних 30 дней
        $last_30_days = [];
        $today = strtotime('today');
        for ($i = 29; $i >= 0; $i--) {
            $date = date('Y-m-d', strtotime("-$i days", $today));
            $last_30_days[$date] = 0;
        }

        // Обрабатываем каждую запись в логе
        foreach ($log as $entry) {
            if (!is_array($entry) || !isset($entry['time'], $entry['type'], $entry['ip'])) {
                continue;
            }

            $type = sanitize_text_field($entry['type']);
            $time = intval($entry['time']);
            $ip = sanitize_text_field($entry['ip']);
            $day = gmdate('Y-m-d', $time);

            // По типу атаки
            if (!isset($data['attacks_by_type'][$type])) {
                $data['attacks_by_type'][$type] = 0;
            }
            $data['attacks_by_type'][$type]++;

            // По дням (только последние 30 дней)
            if (isset($last_30_days[$day])) {
                $last_30_days[$day]++;
            }

            // Уникальные IP
            $data['unique_attackers'][$ip] = true;
        }

        // Форматируем данные для графиков
        $data['attacks_by_day'] = $last_30_days;
        $data['unique_attackers_count'] = count($data['unique_attackers']);

        return $data;
    }

/* ==========================================================
       19. Страница настроек (основная UI)
       ========================================================== */

    public function settings_page() {
    if (!current_user_can('manage_options')) return;

    // Обработка сообщений
    $error = $success = '';
    if (isset($_GET['backup_created']))    $success = 'Резервная копия создана';
    if (isset($_GET['cache_cleared']))     $success = 'Кеш очищен';
    if (isset($_GET['unblocked']))         $success = 'IP разблокирован';
    if (isset($_GET['manual_block']))      $success = isset($_GET['message']) ? urldecode($_GET['message']) : 'IP добавлен в чёрный список';
    if (isset($_GET['whitelist_added']))   $success = 'IP добавлен в белый список';
    if (isset($_GET['whitelist_removed'])) $success = 'IP удалён из белого списка';
    if (isset($_GET['error']) && $_GET['error'] === 'invalid_ip') $error = 'Неверный формат IP/ASN/CIDR';

    // Обновление IP‑блоков
    if (isset($_POST['submit_ip_blocker'])) {
        check_admin_referer('security_blocker_update');
        $ips = sanitize_textarea_field($_POST['ip_addresses'] ?? '');
        $res = $this->update_ip_rules($ips);
        if ($res === true) $success = 'IP‑правила обновлены (дубли удалены)';
        else $error = 'Ошибка IP‑правил: ' . $res;
    }

        // Защита wp‑login / xmlrpc
        if (isset($_POST['submit_login_protection'])) {
            check_admin_referer('security_blocker_update');
            $whitelist   = sanitize_textarea_field($_POST['login_whitelist_ips'] ?? '');
            $protect_wp  = (isset($_POST['protect_wp_login']) && $_POST['protect_wp_login'] === '1');
            $protect_xml = (isset($_POST['protect_xmlrpc']) && $_POST['protect_xmlrpc'] === '1');
            $res = $this->update_login_protection($whitelist, $protect_wp, $protect_xml);
            if ($res === true) $success = 'Защита wp-login/xmlrpc обновлена';
            else $error = 'Ошибка защиты входа: ' . $res;
        }

        // Блокировка опасных файлов
        if (isset($_POST['submit_file_protection'])) {
            check_admin_referer('security_blocker_update');
            $files = sanitize_textarea_field($_POST['dangerous_files'] ?? '');
            update_option('asb_dangerous_files', $files);
            $res = $this->update_file_protection($files);
            if ($res === true) $success = 'Защита файлов обновлена';
            else $error = 'Ошибка защиты файлов: ' . $res;
        }

        // Защита от ботов
        if (isset($_POST['submit_bot_protection'])) {
            check_admin_referer('security_blocker_update');
            $bots = sanitize_textarea_field($_POST['blocked_bots'] ?? '');
            update_option('asb_blocked_bots', $bots);
            $res = $this->update_bot_protection($bots);
            if ($res === true) $success = 'Защита от ботов обновлена';
            else $error = 'Ошибка защиты от ботов: ' . $res;
        }

        // Настройки брутфорс‑защиты
        if (isset($_POST['submit_brute_force_protection'])) {
            check_admin_referer('security_blocker_update');
            update_option('asb_brute_force_enabled', (isset($_POST['brute_force_enabled']) && $_POST['brute_force_enabled'] === '1') ? '1' : '0');
            update_option('asb_max_attempts', max(1, intval($_POST['max_attempts'] ?? 5)));
            update_option('asb_time_window', max(1, intval($_POST['time_window'] ?? 15)));
            update_option('asb_block_duration', max(0, intval($_POST['block_duration'] ?? 60)));
            update_option('asb_auto_add_to_htaccess', (isset($_POST['auto_add_to_htaccess']) && $_POST['auto_add_to_htaccess'] === '1') ? '1' : '0');
            update_option('asb_email_notifications', (isset($_POST['email_notifications']) && $_POST['email_notifications'] === '1') ? '1' : '0');
            update_option('asb_fail2ban_enabled', (isset($_POST['fail2ban_enabled']) && $_POST['fail2ban_enabled'] === '1') ? '1' : '0');
            update_option('asb_external_blacklist', (isset($_POST['external_blacklist']) && $_POST['external_blacklist'] === '1') ? '1' : '0');
            update_option('asb_geo_block_countries', sanitize_text_field($_POST['geo_block_countries'] ?? ''));
            update_option('asb_rate_limit_enabled', (isset($_POST['rate_limit_enabled']) && $_POST['rate_limit_enabled'] === '1') ? '1' : '0');
            $success = 'Настройки брутфорс‑защиты сохранены';
        }

        // Настройки кеша
        if (isset($_POST['submit_cache_settings'])) {
            check_admin_referer('security_blocker_update');
            update_option('asb_clear_cache_enabled', (isset($_POST['clear_cache_enabled']) && $_POST['clear_cache_enabled'] === '1') ? '1' : '0');
            update_option('asb_redis_shared_blocklist', (isset($_POST['redis_shared']) && $_POST['redis_shared'] === '1') ? '1' : '0');
            $success = 'Настройки кеша сохранены';
        }

        // Очистка старых записей
        if (isset($_POST['cleanup_attempts'])) {
            check_admin_referer('security_blocker_update');
            $this->cleanup_old_attempts();
            $success = 'Старые записи удалены';
        }

        // Обновление Telegram‑настроек
        if (isset($_POST['submit_telegram'])) {
            check_admin_referer('security_blocker_update');
            update_option('asb_telegram_token', sanitize_text_field($_POST['telegram_token'] ?? ''));
            update_option('asb_telegram_chat_id', sanitize_text_field($_POST['telegram_chat_id'] ?? ''));
            $success = 'Настройки Telegram сохранены';
        }

        // Получаем текущие данные для UI
        $current_ips        = $this->get_current_ips();
        $current_whitelist  = $this->get_current_login_whitelist();
        $current_files      = get_option('asb_dangerous_files', '');
        $current_bots       = get_option('asb_blocked_bots', '');
        $current_user_ip    = $this->get_user_ip();
        $current_prot       = $this->get_current_protection_settings();
        $login_stats        = $this->get_login_attempts_stats();
        $unblock_history    = $this->get_unblock_history(20);
        $whitelist_ips      = $this->get_whitelist_ips();

        // Пагинация в управлении блокировками
        $per_page   = 20;
        $cur_page   = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $search_q   = isset($_GET['s']) ? sanitize_text_field($_GET['s']) : '';
        $blocked_data = $this->get_all_blocked_ips($search_q, $cur_page, $per_page);
        $blocks_to_show = $blocked_data['blocks'];
        $total_blocks   = $blocked_data['total'];
        $total_pages    = $blocked_data['pages'];

        global $wpdb;
        ?>
        <div class="wrap">
            <h1>Продвинутая система безопасности v<?php echo ASB_BLOCKER_VERSION; ?></h1>
            <?php if ($error): ?>
                <div class="notice notice-error"><p><?php echo esc_html($error); ?></p></div>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="notice notice-success"><p><?php echo esc_html($success); ?></p></div>
                <?php if (!empty($this->log)) {
                    echo '<div class="operation-log"><strong>Журнал операций:</strong><ul>';
                    foreach ($this->log as $l) echo '<li class="log-entry">' . esc_html($l) . '</li>';
                    echo '</ul></div>';
                } ?>
            <?php endif; ?>

            <?php $this->output_admin_styles(); ?>

            <div class="security-tabs">
            <div class="security-tab-nav">
                <button data-tab="tab-ip-blocking" class="active">Блокировка IP</button>
                <button data-tab="tab-login-protection">Защита wp-login/xmlrpc</button>
                <button data-tab="tab-file-protection">Блокировка файлов</button>
                <button data-tab="tab-bot-protection">Защита от ботов</button>
                <button data-tab="tab-brute-force">Брутфорс‑защита</button>
                <button data-tab="tab-myipms">Myip.ms Blacklist</button> <!-- НОВАЯ ВКЛАДКА -->
                <button data-tab="tab-manage-blocks">Управление блокировками</button>
                <button data-tab="tab-whitelist">Белый список</button>
                <button data-tab="tab-status">Статус</button>
                <button data-tab="tab-telegram">Telegram‑уведомления</button>
            </div>

            <!-- 1. IP‑блокировка -->

                <!-- 1. IP‑блокировка -->
                <div id="tab-ip-blocking" class="security-tab-content active">
                    <h2>Блокировка IP‑адресов / ASN</h2>
                    <div class="asn-info"><strong>Новинка!</strong> Можно указывать ASN (например, <code>AS15169</code>) – автоматически добавляются все диапазоны.</div>
                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="ip_addresses">Заблокированные IP/ASN:</label></th>
                                <td>
                                    <div class="ip-blocker-textarea-wrapper">
                                        <div class="ip-blocker-line-numbers"></div>
                                        <textarea name="ip_addresses" id="ip_addresses" rows="15" class="large-text code"
                                            placeholder="192.168.0.1&#10;192.168.1.0/24&#10;AS15169"><?php echo esc_textarea($current_ips); ?></textarea>
                                    </div>
                                    <p class="description">По одной записи на строку. Поддерживаются IP, CIDR, ASN.</p>
                                </td>
                            </tr>
                        </table>
                        <p><button type="submit" name="submit_ip_blocker" class="button button-primary">Обновить IP‑правила</button></p>
                    </form>
                </div>

                <!-- 2. Защита wp‑login/xmlrpc -->
                <div id="tab-login-protection" class="security-tab-content">
                    <h2>Ограничение доступа к wp-login.php и xmlrpc.php</h2>
                    <div class="security-warning">
                        <strong>Внимание!</strong> Добавьте свой IP в белый список, иначе вы потеряете доступ к админке!<br>
                        Ваш текущий IP: <strong><?php echo esc_html($current_user_ip); ?></strong>
                    </div>
                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <input type="hidden" name="protect_wp_login" value="0">
                        <input type="hidden" name="protect_xmlrpc" value="0">
                        <div class="protection-options">
                            <h3>Выберите, что защищать</h3>
                            <div class="protection-checkbox">
                                <input type="checkbox" id="protect_wp_login" name="protect_wp_login" value="1" <?php checked($current_prot['wp_login']); ?>>
                                <label for="protect_wp_login"><strong>wp-login.php</strong> – защита страницы входа</label>
                            </div>
                            <div class="protection-checkbox">
                                <input type="checkbox" id="protect_xmlrpc" name="protect_xmlrpc" value="1" <?php checked($current_prot['xmlrpc']); ?>>
                                <label for="protect_xmlrpc"><strong>xmlrpc.php</strong> – защита XML‑RPC</label>
                            </div>
                        </div>

                        <table class="form-table">
                            <tr>
                                <th><label for="login_whitelist_ips">Разрешённые IP/ASN:</label></th>
                                <td>
                                    <div class="ip-blocker-textarea-wrapper">
                                        <div class="ip-blocker-line-numbers"></div>
                                        <textarea name="login_whitelist_ips" id="login_whitelist_ips" rows="10" class="large-text code"
                                            placeholder="<?php echo esc_attr($current_user_ip); ?>&#10;192.168.1.0/24&#10;AS15169"><?php echo esc_textarea($current_whitelist); ?></textarea>
                                    </div>
                                    <p class="description">По одной записи на строку. Поддерживаются IP, CIDR, ASN.</p>
                                </td>
                            </tr>
                        </table>
                        <p>
                            <button type="submit" name="submit_login_protection" class="button button-primary">Сохранить защиту</button>
                            <button type="button" class="button add-my-ip-btn" onclick="addCurrentIP();">Добавить мой IP</button>
                        </p>
                    </form>
                </div>

                <!-- 3. Защита файлов -->
                <div id="tab-file-protection" class="security-tab-content">
                    <h2>Блокировка опасных файлов</h2>
                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="dangerous_files">Файлы/маски:</label></th>
                                <td>
                                    <textarea name="dangerous_files" id="dangerous_files" rows="15" class="simple-textarea"><?php echo esc_textarea($current_files); ?></textarea>
                                    <p class="description">Один файл/маска на строку. Поддерживается <code>*.log</code>, <code>*.bak</code> и т.п.</p>
                                </td>
                            </tr>
                        </table>
                        <p><button type="submit" name="submit_file_protection" class="button button-primary">Обновить файлы</button></p>
                    </form>
                </div>

                <!-- 4. Защита от ботов -->
                <div id="tab-bot-protection" class="security-tab-content">
                    <h2>Блокировка ботов (User‑Agent)</h2>
                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="blocked_bots">User‑Agent (через |):</label></th>
                                <td>
                                    <textarea name="blocked_bots" id="blocked_bots" rows="10" class="simple-textarea"><?php echo esc_textarea($current_bots); ?></textarea>
                                    <p class="description">Разделяйте через символ <code>|</code>. Поддерживаются частичные совпадения.</p>
                                </td>
                            </tr>
                        </table>
                        <p><button type="submit" name="submit_bot_protection" class="button button-primary">Обновить ботов</button></p>
                    </form>
                </div>

                <!-- 5. Брутфорс‑защита -->
                <div id="tab-brute-force" class="security-tab-content">
                    <h2>Брутфорс‑защита</h2>
                    <div class="brute-force-info"><strong>Автоматическая защита!</strong> При достижении лимита IP будет блокирован.</div>

                    <div class="stats-grid">
                        <div class="stat-card"><div class="stat-number" id="stat-total-attempts"><?php echo $login_stats['total_attempts']; ?></div><div class="stat-label">Попыток за 24 ч</div></div>
                        <div class="stat-card"><div class="stat-number" id="stat-blocked-ips"><?php echo $login_stats['blocked_ips']; ?></div><div class="stat-label">Заблокировано IP за 24 ч</div></div>
                    </div>

                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <input type="hidden" name="brute_force_enabled" value="0">
                        <input type="hidden" name="auto_add_to_htaccess" value="0">
                        <input type="hidden" name="email_notifications" value="0">
                        <input type="hidden" name="fail2ban_enabled" value="0">
                        <input type="hidden" name="external_blacklist" value="0">
                        <input type="hidden" name="rate_limit_enabled" value="0">

                        <table class="form-table">
                            <tr>
                                <th><label for="brute_force_enabled">Включить защиту:</label></th>
                                <td><input type="checkbox" id="brute_force_enabled" name="brute_force_enabled" value="1" <?php checked(get_option('asb_brute_force_enabled')); ?>></td>
                            </tr>
                            <tr>
                                <th><label for="max_attempts">Максимум попыток:</label></th>
                                <td><input type="number" id="max_attempts" name="max_attempts" min="1" max="50" value="<?php echo esc_attr(get_option('asb_max_attempts', 5)); ?>"></td>
                            </tr>
                            <tr>
                                <th><label for="time_window">Время окна (мин):</label></th>
                                <td><input type="number" id="time_window" name="time_window" min="1" max="1440" value="<?php echo esc_attr(get_option('asb_time_window', 15)); ?>"></td>
                            </tr>
                            <tr>
                                <th><label for="block_duration">Длительность блокировки (мин, 0 = постоянно):</label></th>
                                <td><input type="number" id="block_duration" name="block_duration" min="0" max="10080" value="<?php echo esc_attr(get_option('asb_block_duration', 60)); ?>"></td>
                            </tr>
                            <tr>
                                <th><label for="auto_add_to_htaccess">Добавлять в .htaccess:</label></th>
                                <td><input type="checkbox" id="auto_add_to_htaccess" name="auto_add_to_htaccess" value="1" <?php checked(get_option('asb_auto_add_to_htaccess')); ?>></td>
                            </tr>
                            <tr>
                                <th><label for="email_notifications">Email‑уведомления:</label></th>
                                <td><input type="checkbox" id="email_notifications" name="email_notifications" value="1" <?php checked(get_option('asb_email_notifications')); ?>></td>
                            </tr>
                            <tr>
                                <th><label for="fail2ban_enabled">Fail2Ban‑логирование:</label></th>
                                <td><input type="checkbox" id="fail2ban_enabled" name="fail2ban_enabled" value="1" <?php checked(get_option('asb_fail2ban_enabled')); ?>></td>
                            </tr>
                            <tr>
                                <th><label for="external_blacklist">Внешний черный список (IPQualityScore):</label></th>
                                <td><input type="checkbox" id="external_blacklist" name="external_blacklist" value="1" <?php checked(get_option('asb_external_blacklist')); ?>></td>
                            </tr>
                            <tr>
                                <th><label for="geo_block_countries">Блокировать страны (ISO, через запятую):</label></th>
                                <td><input type="text" id="geo_block_countries" name="geo_block_countries" value="<?php echo esc_attr(get_option('asb_geo_block_countries', '')); ?>" placeholder="RU,CN,IR"></td>
                            </tr>
                            <tr>
                                <th><label for="rate_limit_enabled">Rate‑limit (30 req/s):</label></th>
                                <td><input type="checkbox" id="rate_limit_enabled" name="rate_limit_enabled" value="1" <?php checked(get_option('asb_rate_limit_enabled')); ?>></td>
                            </tr>
                        </table>
                        <p>
                            <button type="submit" name="submit_brute_force_protection" class="button button-primary">Сохранить</button>
                            <button type="submit" name="cleanup_attempts" class="button" onclick="return confirm('Очистить старые записи?');">Очистить старые записи</button>
                        </p>
                    </form>

                    <div class="auto-refresh-controls">
                        <label><input type="checkbox" id="auto-refresh-stats" checked> Автообновление каждые 30 сек</label>
                        <button id="manual-refresh-stats" class="refresh-button">Обновить сейчас</button>
                        <span id="last-updated">Последнее обновление: <?php echo date('H:i:s'); ?></span>
                    </div>

                    <h3>Топ IP за 24 ч</h3>
                    <table class="attempts-table">
                        <thead><tr><th>IP</th><th>Попыток</th><th>Статус</th></tr></thead>
                        <tbody id="top-ips-body">
                            <?php foreach ($login_stats['top_ips'] as $ip): ?>
                                <tr>
                                    <td><?php echo esc_html($ip->ip_address); ?></td>
                                    <td><?php echo esc_html($ip->attempts); ?></td>
                                    <td><?php echo $ip->is_blocked ? '<span class="blocked-ip">Заблокирован</span>' : '<span class="normal-ip">Активен</span>'; ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>

                    <h3>Последние попытки входа</h3>
                    <table class="attempts-table">
                        <thead><tr><th>Время</th><th>IP</th><th>Пользователь</th><th>Статус</th><th>User‑Agent</th></tr></thead>
                        <tbody id="recent-attempts-body">
                            <?php foreach ($login_stats['recent_attempts'] as $a): ?>
                                <tr>
                                    <td><?php echo esc_html(date('d.m.Y H:i:s', strtotime($a->attempt_time))); ?></td>
                                    <td><?php echo esc_html($a->ip_address); ?></td>
                                    <td><?php echo esc_html($a->username); ?></td>
                                    <td><?php echo $a->blocked ? '<span class="blocked-ip">Заблокирован</span>' : '<span class="normal-ip">Неудачная попытка</span>'; ?></td>
                                    <td title="<?php echo esc_attr($a->user_agent); ?>">
                                        <?php echo esc_html(substr($a->user_agent, 0, 50)) . (strlen($a->user_agent) > 50 ? '...' : ''); ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
				
				<!-- 5a. Myip.ms Blacklist -->
            <div id="tab-myipms" class="security-tab-content">
                <h2>Интеграция с Myip.ms Blacklist</h2>
                <p>Автоматическая загрузка и блокировка IP из черных списков Myip.ms. Обновляется ежечасно.</p>
                
                <?php
                // Обработка сохранения настроек Myip.ms
                if (isset($_POST['submit_myipms_settings'])) {
                    check_admin_referer('security_blocker_update');
                    
                    $enabled = (isset($_POST['myipms_enabled']) && $_POST['myipms_enabled'] === '1') ? '1' : '0';
                    $mode = sanitize_text_field($_POST['myipms_mode']);
                    
                    $old_enabled = get_option('asb_myipms_enabled');
                    
                    update_option('asb_myipms_enabled', $enabled);
                    update_option('asb_myipms_mode', $mode);
                    
                    // Управление CRON
                    if ($enabled === '1' && $old_enabled !== '1') {
                        if (!wp_next_scheduled('asb_myipms_update_event')) {
                            wp_schedule_event(time(), 'hourly', 'asb_myipms_update_event');
                        }
                        // Запуск обновления сразу при включении
                        $this->process_myipms_update();
                        echo '<div class="notice notice-success"><p>Myip.ms включен и обновление запущено.</p></div>';
                    } elseif ($enabled === '0') {
                        wp_clear_scheduled_hook('asb_myipms_update_event');
                        // Очистка при отключении
                        $this->clean_myipms_rules(); 
                        echo '<div class="notice notice-success"><p>Myip.ms отключен, правила удалены.</p></div>';
                    } else {
                        // Если просто поменяли настройки, но он был включен - обновляем
                        $this->process_myipms_update();
                        echo '<div class="notice notice-success"><p>Настройки сохранены и применены.</p></div>';
                    }
                }
                ?>

                <form method="post">
                    <?php wp_nonce_field('security_blocker_update'); ?>
                    <table class="form-table">
                        <tr>
                            <th><label for="myipms_enabled">Включить обновление:</label></th>
                            <td>
                                <input type="checkbox" id="myipms_enabled" name="myipms_enabled" value="1" <?php checked(get_option('asb_myipms_enabled')); ?>>
                                <p class="description">Включает ежечасное скачивание черных списков с Myip.ms.</p>
                            </td>
                        </tr>
                        <tr>
                            <th><label>Режим блокировки:</label></th>
                            <td>
                                <fieldset>
                                    <label>
                                        <input type="radio" name="myipms_mode" value="htaccess" <?php checked(get_option('asb_myipms_mode'), 'htaccess'); ?>>
                                        <strong>.htaccess (Рекомендуется)</strong> — Блокировка на уровне сервера. Быстро, но увеличивает размер файла .htaccess.
                                    </label><br><br>
                                    <label>
                                        <input type="radio" name="myipms_mode" value="wp" <?php checked(get_option('asb_myipms_mode'), 'wp'); ?>>
                                        <strong>WP Blocking (PHP)</strong> — Блокировка на уровне WordPress. Не нагружает .htaccess, но требует запуска PHP.
                                    </label>
                                </fieldset>
                            </td>
                        </tr>
                        <tr>
                            <th>Последнее обновление:</th>
                            <td>
                                <strong><?php echo esc_html(get_option('asb_myipms_last_update', 'Никогда')); ?></strong>
                            </td>
                        </tr>
                    </table>
                    <p>
                        <button type="submit" name="submit_myipms_settings" class="button button-primary">Сохранить настройки</button>
                        <button type="button" id="force_update_myipms" class="button">Обновить сейчас</button>
                        <span class="spinner" id="myipms_spinner" style="float:none;"></span>
                    </p>
                </form>
                
                <script>
                jQuery(document).ready(function($){
                    $('#force_update_myipms').click(function(e){
                        e.preventDefault();
                        $('#myipms_spinner').addClass('is-active');
                        $.post(asb_ajax.ajax_url, {
                            action: 'asb_run_myipms_update',
                            nonce: asb_ajax.nonce
                        }, function(response) {
                            $('#myipms_spinner').removeClass('is-active');
                            alert(response.data.message);
                            location.reload();
                        });
                    });
                });
                </script>
            </div>

                <!-- 6. Управление блокировками -->
                <div id="tab-manage-blocks" class="security-tab-content">
                    <h2>Управление заблокированными IP</h2>

                    <div class="card">
                        <h3>Поиск IP</h3>
                        <form method="get" id="ip-search-form">
                            <input type="hidden" name="page" value="advanced-security-blocker">
                            <input type="hidden" name="tab" value="manage-blocks">
                            <table class="form-table">
                                <tr>
                                    <th><label for="ip-search">IP:</label></th>
                                    <td>
                                        <input type="text" id="ip-search" name="s" value="<?php echo esc_attr($search_q); ?>" placeholder="Введите IP">
										<input type="hidden" name="paged" value="<?php echo esc_attr($cur_page); ?>">
                                        <button type="submit" class="button">Поиск</button>
                                        <?php if (!empty($search_q)): ?>
                                            <a href="<?php echo admin_url('options-general.php?page=advanced-security-blocker&tab=manage-blocks'); ?>" class="button">Сбросить</a>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            </table>
                        </form>
                    </div>

                    <div class="card">
                        <h3>Список заблокированных IP</h3>
                        <div id="blocked-ips-table-container">
                            <?php if (empty($blocks_to_show)): ?>
                                <p>Нет заблокированных IP.</p>
                            <?php else: ?>
                                <div class="tablenav top">
                                    <div class="tablenav-pages">
                                        <span class="displaying-num"><?php echo $total_blocks; ?> элементов</span>
                                        <?php if ($total_pages > 1): ?>
                                            <span class="pagination-links">
                                                <?php if ($cur_page > 1): ?>
                                                    <a class="first-page button" href="#" data-page="1">«</a>
                                                    <a class="prev-page button" href="#" data-page="<?php echo $cur_page - 1; ?>">‹</a>
                                                <?php endif; ?>
                                                <span class="paging-input"><span class="current-page"><?php echo $cur_page; ?></span> из <span class="total-pages"><?php echo $total_pages; ?></span></span>
                                                <?php if ($cur_page < $total_pages): ?>
                                                    <a class="next-page button" href="#" data-page="<?php echo $cur_page + 1; ?>">›</a>
                                                    <a class="last-page button" href="#" data-page="<?php echo $total_pages; ?>">»</a>
                                                <?php endif; ?>
                                            </span>
                                        <?php endif; ?>
                                    </div>
                                </div>

                                <table class="attempts-table">
                                    <thead><tr><th>IP / ASN</th><th>Тип блокировки</th><th>Запись</th><th>Последняя попытка</th><th>Действия</th></tr></thead>
                                    <tbody>
                                        <?php foreach ($blocks_to_show as $b): ?>
                                            <tr>
                                                <td><?php echo esc_html($b['ip']); ?></td>
                                                <td><?php
                                                    $labels = [
                                                        'temporary' => '<span style="color:orange;">Временная</span>',
                                                        'permanent'=> '<span style="color:red;">Постоянная</span>',
                                                        'htaccess' => '<span style="color:purple;">.htaccess</span>'
                                                    ];
                                                    echo $labels[$b['type']] ?? $b['type'];
                                                ?></td>
                                                <td><?php
                                                    $type = 'IP';
                                                    if (strpos($b['ip'], 'AS') === 0) $type = 'ASN';
                                                    elseif (strpos($b['ip'], '/') !== false) $type = 'CIDR';
                                                    echo $type;
                                                ?></td>
                                                <td><?php echo esc_html($b['last_attempt']); ?></td>
                                                <td>
                                                    <a href="<?php echo wp_nonce_url(
                                                        admin_url('options-general.php?page=advanced-security-blocker&unblock_ip=' . $b['ip'] . '&tab=manage-blocks&paged=' . $cur_page . '&s=' . urlencode($search_q)), 'unblock_ip'); ?>" class="button" onclick="return confirm('Разблокировать?');">Разблокировать</a>
                                                    <button class="button view-history-btn" data-ip="<?php echo esc_attr($b['ip']); ?>">История</button>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                        </tbody>
                                </table>

                                <div class="tablenav bottom">
                                    <div class="tablenav-pages">
                                        <span class="displaying-num"><?php echo $total_blocks; ?> элементов</span>
                                        <?php if ($total_pages > 1): ?>
                                            <span class="pagination-links">
                                                <?php if ($cur_page > 1): ?>
                                                    <a class="first-page button" href="#" data-page="1">«</a>
                                                    <a class="prev-page button" href="#" data-page="<?php echo $cur_page - 1; ?>">‹</a>
                                                <?php endif; ?>
                                                <span class="paging-input"><span class="current-page"><?php echo $cur_page; ?></span> из <span class="total-pages"><?php echo $total_pages; ?></span></span>
                                                <?php if ($cur_page < $total_pages): ?>
                                                    <a class="next-page button" href="#" data-page="<?php echo $cur_page + 1; ?>">›</a>
                                                    <a class="last-page button" href="#" data-page="<?php echo $total_pages; ?>">»</a>
                                                <?php endif; ?>
                                            </span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="card">
                        <h3>История разблокировок</h3>
                        <?php if (empty($unblock_history)): ?>
                            <p>История пуста.</p>
                        <?php else: ?>
                            <table class="attempts-table">
                                <thead><tr><th>IP</th><th>Время</th><th>Причина</th><th>Кем</th></tr></thead>
                                <tbody>
                                    <?php foreach ($unblock_history as $u): ?>
                                        <tr>
                                            <td><?php echo esc_html($u->ip_address); ?></td>
                                            <td><?php echo esc_html(date('d.m.Y H:i:s', strtotime($u->unblock_time))); ?></td>
                                            <td><?php echo esc_html($u->unblock_reason); ?></td>
                                            <td><?php echo esc_html($u->unblocked_by); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>
                    </div>

                    <div class="card">
                        <h3>Ручная блокировка IP (Массовая + AJAX)</h3>
                        
                        <!-- Стили для прогресс-бара -->
                        <style>
                            #asb-progress-wrapper { display: none; margin-top: 15px; border: 1px solid #ccd0d4; background: #fff; padding: 15px; }
                            .asb-progress-container { width: 100%; background-color: #f0f0f1; border-radius: 3px; height: 20px; overflow: hidden; margin-bottom: 10px; box-shadow: inset 0 1px 2px rgba(0,0,0,.1); }
                            .asb-progress-bar { width: 0%; height: 100%; background-color: #2271b1; transition: width 0.2s; }
                            #asb-process-log { max-height: 150px; overflow-y: auto; background: #f6f7f7; padding: 10px; border: 1px solid #dcdcde; font-size: 12px; font-family: monospace; white-space: pre-wrap; }
                            .log-success { color: green; }
                            .log-error { color: red; }
                            .asb-working { opacity: 0.6; pointer-events: none; }
                        </style>

                        <form method="post" id="asb_manual_block_form">
                            <table class="form-table">
                                <tr>
                                    <th><label for="manual_block_ip">IP / CIDR / ASN:<br><span class="description">(по одному в строке)</span></label></th>
                                    <td>
                                        <textarea name="manual_block_ip" id="manual_block_ip" rows="5" class="large-text code" placeholder="192.168.0.1&#10;192.168.0.0/24&#10;AS15169"></textarea>
                                    </td>
                                </tr>
                                <tr>
                                    <th><label for="block_reason">Причина:</label></th>
                                    <td><input type="text" name="block_reason" id="block_reason" class="regular-text" placeholder="Спам / Атака"></td>
                                </tr>
                            </table>
                            <p>
                                <button type="submit" id="asb_start_block_btn" class="button button-primary">Заблокировать список</button>
                                <span class="spinner" id="asb_spinner" style="float:none;"></span>
                            </p>
                        </form>

                        <!-- Контейнер прогресса -->
                        <div id="asb-progress-wrapper">
                            <div style="margin-bottom: 5px;"><strong>Прогресс:</strong> <span id="asb-progress-text">0%</span></div>
                            <div class="asb-progress-container">
                                <div class="asb-progress-bar" id="asb-progress-bar"></div>
                            </div>
                            <div id="asb-process-log"></div>
                        </div>

                        <!-- Скрипт обработки -->
                        <script>
                        jQuery(document).ready(function($){
                            $('#asb_manual_block_form').on('submit', function(e){
                                e.preventDefault();
                                
                                var rawText = $('#manual_block_ip').val();
                                var reason = $('#block_reason').val();
                                
                                // Разбиваем текст на строки и убираем пустые
                                var lines = rawText.split('\n').map(function(item){ return item.trim(); }).filter(function(item){ return item.length > 0; });
                                
                                if(lines.length === 0) {
                                    alert('Введите хотя бы один IP адрес.');
                                    return;
                                }

                                if(!confirm('Вы собираетесь обработать ' + lines.length + ' записей. Продолжить?')) {
                                    return;
                                }

                                // Интерфейс
                                var $form = $(this);
                                var $btn = $('#asb_start_block_btn');
                                var $wrapper = $('#asb-progress-wrapper');
                                var $bar = $('#asb-progress-bar');
                                var $text = $('#asb-progress-text');
                                var $log = $('#asb-process-log');
                                var $spinner = $('#asb_spinner');

                                $form.addClass('asb-working');
                                $spinner.addClass('is-active');
                                $wrapper.slideDown();
                                $log.html(''); // Очистка лога
                                $bar.css('width', '0%');
                                
                                var total = lines.length;
                                var processed = 0;
                                var errors = 0;

                                // Рекурсивная функция для обработки очереди
                                function processNext(index) {
                                    if (index >= total) {
                                        // Завершено
                                        $bar.css('width', '100%');
                                        $text.text('100% (Готово)');
                                        $log.append('<div><strong>Обработка завершена!</strong></div>');
                                        $form.removeClass('asb-working');
                                        $spinner.removeClass('is-active');
                                        $('#manual_block_ip').val(''); // Очистить поле ввода
                                        
                                        // Обновить таблицу блокировок через 2 сек (если есть функция обновления)
                                        if(typeof fetchBlockedIps === 'function') {
                                            setTimeout(function(){ fetchBlockedIps(1, ''); }, 1500);
                                        } else {
                                            // Если нет, просто перезагружаем страницу
                                            setTimeout(function(){ location.reload(); }, 2000);
                                        }
                                        return;
                                    }

                                    var ip = lines[index];
                                    var percent = Math.round(((index) / total) * 100);
                                    
                                    $bar.css('width', percent + '%');
                                    $text.text(percent + '% (' + (index + 1) + '/' + total + ')');

                                    $.ajax({
                                        url: asb_ajax.ajax_url,
                                        type: 'POST',
                                        data: {
                                            action: 'asb_batch_block_ip',
                                            nonce: asb_ajax.nonce,
                                            ip: ip,
                                            reason: reason
                                        },
                                        success: function(response) {
                                            if(response.success) {
                                                $log.append('<div class="log-success">✓ ' + response.data.message + '</div>');
                                            } else {
                                                errors++;
                                                var msg = response.data ? response.data.message : 'Ошибка';
                                                $log.append('<div class="log-error">✗ ' + msg + '</div>');
                                            }
                                            // Прокрутка лога вниз
                                            $log.scrollTop($log[0].scrollHeight);
                                            // Следующий
                                            processNext(index + 1);
                                        },
                                        error: function() {
                                            errors++;
                                            $log.append('<div class="log-error">✗ Ошибка сети: ' + ip + '</div>');
                                            processNext(index + 1);
                                        }
                                    });
                                }

                                // Запуск
                                $log.append('<div>Начало обработки...</div>');
                                processNext(0);
                            });
                        });
                        </script>
                    </div>
                </div>

                <!-- 7. Белый список -->
                <div id="tab-whitelist" class="security-tab-content">
                    <h2>Белый список IP</h2>
                    <div class="card">
                        <h3>Текущий список</h3>
                        <?php if (empty($whitelist_ips)): ?>
                            <p>Белый список пуст.</p>
                        <?php else: ?>
                            <table class="attempts-table"><thead><tr><th>IP</th><th>Действия</th></tr></thead><tbody>
                                <?php foreach ($whitelist_ips as $ip): ?>
                                    <tr>
                                        <td><?php echo esc_html($ip); ?></td>
                                        <td><a href="<?php echo wp_nonce_url(admin_url('options-general.php?page=advanced-security-blocker&remove_whitelist=' . $ip), 'remove_whitelist'); ?>" class="button" onclick="return confirm('Удалить?');">Удалить</a></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody></table>
                        <?php endif; ?>
                    </div>

                    <div class="card">
                        <h3>Добавить в белый список</h3>
                        <form method="post">
                            <?php wp_nonce_field('security_blocker_update'); ?>
                            <table class="form-table">
                                <tr>
                                    <th><label for="whitelist_ip">IP/ CIDR / ASN:</label></th>
                                    <td><input type="text" name="whitelist_ip" id="whitelist_ip" class="regular-text" placeholder="192.168.0.1 или AS15169"></td>
                                </tr>
                                <tr>
                                    <th><label for="whitelist_reason">Причина:</label></th>
                                    <td><input type="text" name="whitelist_reason" id="whitelist_reason" class="regular-text" placeholder="Доверенный пользователь"></td>
                                </tr>
                            </table>
                            <p><button type="submit" name="submit_whitelist" class="button button-primary">Добавить</button></p>
                        </form>
                    </div>
                </div>

                <!-- 8. Статус системы -->
                <div id="tab-status" class="security-tab-content">
                    <h2>Статус системы безопасности</h2>

                    <div class="cache-settings">
                        <h3>Настройки кеша</h3>
                        <form method="post">
                            <?php wp_nonce_field('security_blocker_update'); ?>
                            <table class="form-table">
                                <tr>
                                    <th><label for="clear_cache_enabled">Авто‑очистка кеша:</label></th>
                                    <td><input type="checkbox" id="clear_cache_enabled" name="clear_cache_enabled" value="1" <?php checked(get_option('asb_clear_cache_enabled', '1')); ?>></td>
                                </tr>
                                <tr>
                                    <th><label for="redis_shared">Общий Redis‑блоклист:</label></th>
                                    <td><input type="checkbox" id="redis_shared" name="redis_shared" value="1" <?php checked(get_option('asb_redis_shared_blocklist')); ?>></td>
                                </tr>
                            </table>
                            <p><button type="submit" name="submit_cache_settings" class="button button-primary">Сохранить</button></p>
                        </form>
                    </div>

                    <div class="card">
                        <h3>Компоненты</h3>
                        <ul>
                            <li>.htaccess: <?php echo is_writable($this->htaccess_path) ? '<span style="color:green">✓ записываем</span>' : '<span style="color:red">✗ нет доступа</span>'; ?></li>
                            <li>Бекапы: <?php echo is_writable($this->backup_dir) ? '<span style="color:green">✓ доступны</span>' : '<span style="color:red">✗ недоступны</span>'; ?></li>
                            <li>Кеш ASN: <?php echo is_writable($this->cache_dir) ? '<span style="color:green">✓ доступен</span>' : '<span style="color:red">✗ недоступен</span>'; ?></li>
                            <li>Таблица попыток: <?php echo $wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}security_login_attempts'") ? '<span style="color:green">✓ создана</span>' : '<span style="color:red">✗ нет</span>'; ?></li>
                            <li>Таблица разблокировок: <?php echo $wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}security_unblock_history'") ? '<span style="color:green">✓ создана</span>' : '<span style="color:red">✗ нет</span>'; ?></li>
                            <li>Последняя резервная копия: <?php
                                $bks = glob($this->backup_dir . 'htaccess-*.bak');
                                echo $bks ? '<span style="color:green">' . date('d.m.Y H:i:s', filemtime($bks[0])) . '</span>' : '<span style="color:orange">не создана</span>'; ?></li>
                            <li>Кешированных ASN‑файлов: <?php echo count(glob($this->cache_dir . 'asn_*.json')); ?></li>
                            <li>Ваш IP: <strong><?php echo esc_html($current_user_ip); ?></strong></li>
                            <li>Cloudflare настроен: <?php echo $this->is_cloudflare_configured() ? '<span style="color:green">✓</span>' : '<span style="color:orange">✗ не настроен</span>'; ?></li>
                        </ul>
                    </div>

                    <div class="card">
                        <h3>Активные защиты</h3>
                        <ul>
                            <li>IP‑блок: <?php echo !empty($current_ips) ? '<span style="color:green">✓ (' . count(array_filter(explode("\n", $current_ips))) . ' записей)</span>' : '<span style="color:gray">○ нет</span>'; ?></li>
                            <li>wp‑login.php: <?php echo $current_prot['wp_login'] ? '<span style="color:green">✓</span>' : '<span style="color:gray">○ нет</span>'; ?></li>
                            <li>xmlrpc.php: <?php echo $current_prot['xmlrpc'] ? '<span style="color:green">✓</span>' : '<span style="color:gray">○ нет</span>'; ?></li>
                            <li>Whitelist: <?php echo !empty($whitelist_ips) ? '<span style="color:green">' . count($whitelist_ips) . ' записей</span>' : '<span style="color:gray">0</span>'; ?></li>
                            <li>Блокировка файлов: <?php echo !empty($current_files) ? '<span style="color:green">' . count(array_filter(explode("\n", $current_files))) . ' файлов</span>' : '<span style="color:gray">○ нет</span>'; ?></li>
                            <li>Блокировка ботов: <?php echo !empty($current_bots) ? '<span style="color:green">✓</span>' : '<span style="color:gray">○ нет</span>'; ?></li>
                            <li>Брутфорс‑защита: <?php echo get_option('asb_brute_force_enabled') ? '<span style="color:green">✓</span>' : '<span style="color:gray">○ нет</span>'; ?></li>
                            <li>Fail2Ban‑лог: <?php echo get_option('asb_fail2ban_enabled') ? '<span style="color:green">✓</span>' : '<span style="color:gray">○ нет</span>'; ?></li>
                            <li>REST API: <span style="color:green">✓ доступен</span></li>
                        </ul>
                    </div>

                    <div class="card">
                        <h3>REST API Endpoints</h3>
                        <p>Вы можете использовать следующие конечные точки REST API для удаленного управления блокировками:</p>
                        <ul>
                            <li><strong>GET /wp-json/asb/v1/list</strong> - Получить список заблокированных IP/ASN.</li>
                            <li><strong>POST /wp-json/asb/v1/block</strong> - Заблокировать IP/ASN. Требуются параметры: <code>target</code> (IP/ASN), <code>reason</code> (необязательно).</li>
                            <li><strong>POST /wp-json/asb/v1/unblock</strong> - Разблокировать IP/ASN. Требуется параметр: <code>target</code> (IP/ASN).</li>
                        </ul>
                        <p class="description">Для использования требуется аутентификация с правами "manage_options".</p>
                    </div>

                    <p>
                        <a href="<?php echo esc_url(admin_url('options-general.php?page=advanced-security-blocker&backup=1')); ?>" class="button">Создать резервную копию .htaccess</a>
                        <a href="<?php echo esc_url(admin_url('options-general.php?page=advanced-security-blocker&clear_cache=1')); ?>" class="button">Очистить весь кеш</a>
                        <?php if (get_option('asb_nginx_mode')): ?>
                            <a href="<?php echo esc_url(admin_url('options-general.php?page=advanced-security-blocker&generate_nginx=1')); ?>" class="button">Пересоздать nginx‑фрагмент</a>
                        <?php endif; ?>
                    </p>
                </div>

                <!-- 9. Telegram‑уведомления -->
                <div id="tab-telegram" class="security-tab-content">
                    <h2>Telegram‑уведомления</h2>
                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="telegram_token">Bot Token:</label></th>
                                <td><input type="text" id="telegram_token" name="telegram_token" class="regular-text" value="<?php echo esc_attr(get_option('asb_telegram_token', '')); ?>" placeholder="123456:ABC..."></td>
                            </tr>
                            <tr>
                                <th><label for="telegram_chat_id">Chat ID:</label></th>
                                <td><input type="text" id="telegram_chat_id" name="telegram_chat_id" class="regular-text" value="<?php echo esc_attr(get_option('asb_telegram_chat_id', '')); ?>" placeholder="-1001234567890"></td>
                            </tr>
                        </table>
                        <p><button type="submit" name="submit_telegram" class="button button-primary">Сохранить Telegram‑настройки</button></p>
                    </form>
                </div>
            </div>

            <!-- Модальное окно истории -->
            <div id="history-modal" class="modal">
                <div class="modal-content">
                    <span class="close">&times;</span>
                    <h2>История блокировок <span id="modal-ip"></span></h2>
                    <div id="modal-history-content"><p>Загрузка...</p></div>
                </div>
            </div>
        </div>

        <script>
        jQuery(document).ready(function($){
            /* Нумерация в textarea */
            function updateLineNumbers(txt,ln){
                var lines = txt.value.split('\n').length, txt = '';
                for(var i=1;i<=lines;i++) txt += i+"\n";
                ln.textContent = txt;
                ln.scrollTop = txt.scrollTop;
            }
            $('.ip-blocker-textarea-wrapper').each(function(){
                var $wrap=$(this), $ta=$wrap.find('textarea')[0], $ln=$wrap.find('.ip-blocker-line-numbers')[0];
                if($ta && $ln){
                    updateLineNumbers($ta,$ln);
                    $ta.addEventListener('input',function(){updateLineNumbers($ta,$ln);});
                    $ta.addEventListener('scroll',function(){ $ln.scrollTop=$ta.scrollTop; });
                }
            });

            /* Переключение вкладок */
            function showTab(id){
                $('.security-tab-content').removeClass('active').hide();
                $('.security-tab-nav button').removeClass('active');
                $('#'+id).addClass('active').show();
                $('button[data-tab="'+id+'"]').addClass('active');
                if(id==='tab-brute-force') initAutoRefresh();
            }
            $('.security-tab-nav button').on('click',function(e){
                e.preventDefault();
                showTab($(this).data('tab'));
            });
            showTab('tab-ip-blocking');

            /* Авто‑обновление статистики */
            var statsTimer=null;
            function updateStats(){
                $('#manual-refresh-stats').prop('disabled',true);
                $('#last-updated').html('<span class="loading-spinner"></span> Обновление...');
                $.post(asb_ajax.ajax_url,{action:'asb_get_login_stats',nonce:asb_ajax.nonce},function(r){
                    if(r.success){
                        $('#stat-total-attempts').text(r.data.total_attempts);
                        $('#stat-blocked-ips').text(r.data.blocked_ips);
                        var top=''; r.data.top_ips.forEach(function(i){
                            top+='<tr><td>'+i.ip_address+'</td><td>'+i.attempts+'</td><td>'+(i.is_blocked?'<span class="blocked-ip">Заблокирован</span>':'<span class="normal-ip">Активен</span>')+'</td></tr>';
                        });
                        $('#top-ips-body').html(top||'<tr><td colspan="3">Нет данных</td></tr>');
                        var recent=''; r.data.recent_attempts.forEach(function(a){
                            var date = new Date(a.attempt_time);
                            var ua   = a.user_agent ? a.user_agent.substring(0,50)+(a.user_agent.length>50?'...':'') : '';
                            recent += '<tr><td>'+date.toLocaleString()+'</td><td>'+a.ip_address+'</td><td>'+a.username+'</td><td>'+(a.blocked?'<span class="blocked-ip">Заблокирован</span>':'<span class="normal-ip">Неудачная попытка</span>')+'</td><td title="'+(a.user_agent||'')+'">'+ua+'</td></tr>';
                        });
                        $('#recent-attempts-body').html(recent||'<tr><td colspan="5">Нет данных</td></tr>');
                        $('#last-updated').text('Последнее обновление: '+new Date().toLocaleTimeString());
                    } else {
                        $('#last-updated').text('Ошибка обновления');
                    }
                }).always(function(){
                    $('#manual-refresh-stats').prop('disabled',false);
                });
            }

            function initAutoRefresh(){
                clearInterval(statsTimer);
                if($('#auto-refresh-stats').is(':checked')){
                    statsTimer = setInterval(updateStats,30000);
                }
            }

            $('#manual-refresh-stats').on('click',function(e){
                e.preventDefault();
                updateStats();
            });
            $('#auto-refresh-stats').on('change',function(){
                initAutoRefresh();
                if($(this).is(':checked')) updateStats();
            });
            if($('#tab-brute-force').is(':visible') && $('#auto-refresh-stats').is(':checked')){
                initAutoRefresh();
                updateStats();
            }

            /* Модальное окно истории */
            var $modal = $('#history-modal');
            var $modalIp = $('#modal-ip');
            var $modalContent = $('#modal-history-content');
            var $close = $modal.find('.close');

            function showHistoryModal(ip){
                $modalIp.text(ip);
                $modalContent.html('<p>Загрузка...</p>');
                $modal.show();

                $.post(asb_ajax.ajax_url,{
                    action:'asb_get_block_history',
                    nonce:asb_ajax.nonce,
                    ip:ip
                },function(resp){
                    if(resp.success && resp.data.length){
                        var html = '<table class="history-table"><thead><tr><th>Время</th><th>Пользователь</th><th>User‑Agent</th><th>Блокировка</th></tr></thead><tbody>';
                        resp.data.forEach(function(row){
                            var date = new Date(row.attempt_time);
                            var ua   = row.user_agent ? row.user_agent.substring(0,50)+(row.user_agent.length>50?'...':'') : '';
                            html += '<tr><td>'+date.toLocaleString()+'</td><td>'+row.username+'</td><td title="'+(row.user_agent||'')+'">'+ua+'</td><td>'+(row.blocked?'<span class="blocked-ip">Да</span>':'<span class="normal-ip">Нет</span>')+'</td></tr>';
                        });
                        html += '</tbody></table>';
                        $modalContent.html(html);
                    }else{
                        $modalContent.html('<p>История отсутствует.</p>');
                    }
                }).fail(function(){
                    $modalContent.html('<p>Ошибка получения истории.</p>');
                });
            }

            $close.on('click',function(){ $modal.hide(); });
            $(window).on('click',function(e){
                if($(e.target).is($modal)) $modal.hide();
            });

            /* Добавление текущего IP */
            window.addCurrentIP = function(){
                var textarea = document.getElementById('login_whitelist_ips');
                var ip = '<?php echo esc_js($current_user_ip); ?>';
                if(textarea && textarea.value.indexOf(ip)===-1){
                    textarea.value = textarea.value.trim() ? textarea.value+"\n"+ip : ip;
                }
            };

            /* Обработка чекбоксов */
            $('form').each(function(){
                var $form = $(this);
                $form.find('input[type="checkbox"]').each(function(){
                    var $cb = $(this);
                    var name = $cb.attr('name');
                    var $hidden = $form.find('input[type="hidden"][name="'+name+'"]');
                    $cb.on('change',function(){
                        if($cb.is(':checked')){
                            $hidden.prop('disabled',true);
                        }else{
                            $hidden.prop('disabled',false);
                        }
                    });
                    if($cb.is(':checked')){
                        $hidden.prop('disabled',true);
                    }
                });
            });

            /* Обработчик истории */
            $(document).on('click', '.view-history-btn', function(){
                var ip = $(this).data('ip');
                showHistoryModal(ip);
            });
			
			/* ========================================================
               AJAX Пагинация в управлении блокировками
            ======================================================== */
            function fetchBlockedIps(page, search) {
                var $container = $('#blocked-ips-table-container');
                $container.css('opacity', '0.5'); // Визуальная индикация загрузки
                
                $.post(asb_ajax.ajax_url, {
                    action: 'asb_get_blocked_ips_table',
                    nonce: asb_ajax.nonce,
                    page: page,
                    search: search
                }, function(response) {
                    $container.css('opacity', '1');
                    if (response.success) {
                        $container.html(response.data.table_html);
                    } else {
                        alert('Ошибка загрузки данных');
                    }
                }).fail(function() {
                    $container.css('opacity', '1');
                    alert('Ошибка соединения с сервером');
                });
            }

            // Клик по ссылкам пагинации
            $(document).on('click', '.tablenav .pagination-links a', function(e){
                e.preventDefault();
                var $link = $(this);
                var page = $link.data('page');
                if (!page) return;
                
                var search = $('#ip-search').val(); // Берем текущее значение поиска
                fetchBlockedIps(page, search);
            });

            // AJAX поиск
            $('#ip-search-form').on('submit', function(e){
                e.preventDefault();
                var search = $('#ip-search').val();
                fetchBlockedIps(1, search); // При поиске всегда переходим на 1 страницу
            });
        });
						
        </script>
        <?php
    }
	
    /* ==========================================================
       20. Регистрация настроек Cloudflare
       ========================================================== */

    public function asb_register_settings() {
        // Новые настройки Cloudflare
        register_setting('asb_cloudflare_settings', $this->cf_email_key, ['sanitize_callback' => 'sanitize_email']);
        register_setting('asb_cloudflare_settings', $this->cf_api_key, ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('asb_cloudflare_settings', $this->cf_zone_id, ['sanitize_callback' => 'sanitize_text_field']);

        add_settings_section(
            'asb_cloudflare_section',
            __('Cloudflare Integration Settings', 'ip-blocker-manager'),
            null,
            'asb_cloudflare'
        );

        add_settings_field(
            $this->cf_email_key,
            __('Cloudflare Email', 'ip-blocker-manager'),
            [$this, 'cf_email_callback'],
            'asb_cloudflare',
            'asb_cloudflare_section'
        );
        add_settings_field(
            $this->cf_api_key,
            __('Cloudflare Global API Key', 'ip-blocker-manager'),
            [$this, 'cf_api_key_callback'],
            'asb_cloudflare',
            'asb_cloudflare_section'
        );
        add_settings_field(
            $this->cf_zone_id,
            __('Cloudflare Zone ID', 'ip-blocker-manager'),
            [$this, 'cf_zone_id_callback'],
            'asb_cloudflare',
            'asb_cloudflare_section'
        );
    }
    
    // Callback функции для полей настроек Cloudflare
    public function cf_email_callback() {
        $value = get_option($this->cf_email_key);
        echo "<input type='email' name='{$this->cf_email_key}' value='" . esc_attr($value) . "' class='regular-text' />";
        echo "<p class='description'>" . __('Email, связанный с вашей учетной записью Cloudflare.', 'ip-blocker-manager') . "</p>";
    }
    
    public function cf_api_key_callback() {
        $value = get_option($this->cf_api_key);
        // Не отображаем ключ полностью для безопасности
        $display_value = $value ? substr($value, 0, 4) . str_repeat('*', 30) : '';
        echo "<input type='password' name='{$this->cf_api_key}' value='" . esc_attr($value) . "' class='regular-text' />";
        echo "<p class='description'>" . __('Ваш глобальный ключ API Cloudflare. Будьте осторожны.', 'ip-blocker-manager') . "</p>";
    }
    
    public function cf_zone_id_callback() {
        $value = get_option($this->cf_zone_id);
        echo "<input type='text' name='{$this->cf_zone_id}' value='" . esc_attr($value) . "' class='regular-text' />";
        echo "<p class='description'>" . __('ID зоны сайта в Cloudflare (находится на странице обзора сайта).', 'ip-blocker-manager') . "</p>";
    }

    /* ==========================================================
       21. Страница Cloudflare настроек
       ========================================================== */

    public function cloudflare_settings_page() {
        if (!current_user_can('manage_options')) return;
        ?>
        <div class="wrap">
            <h1><?php _e('Cloudflare Integration', 'ip-blocker-manager'); ?></h1>
            <p><?php _e('Интеграция с Cloudflare позволяет управлять правилами брандмауэра Cloudflare, синхронизируя блокировки с плагином.', 'ip-blocker-manager'); ?></p>
            <form method="post" action="options.php">
                <?php
                settings_fields('asb_cloudflare_settings');
                do_settings_sections('asb_cloudflare');
                submit_button();
                ?>
            </form>
            <p class="description">
                <?php _e('Примечание: Используйте глобальный ключ API или токен с правами на редактирование правил брандмауэра зоны.', 'ip-blocker-manager'); ?>
            </p>
            <div class="card">
                <h3>Статус Cloudflare</h3>
                <p>Интеграция <?php echo $this->is_cloudflare_configured() ? '<span style="color:green">настроена</span>' : '<span style="color:red">не настроена</span>'; ?></p>
                <p>При блокировке IP через плагин, он будет автоматически добавлен в правила брандмауэра Cloudflare.</p>
            </div>
        </div>
        <?php
    }

    /* ==========================================================
       22. Страница аналитики атак - ИСПРАВЛЕННАЯ ВЕРСИЯ
       ========================================================== */

    /**
     * Подключение скриптов для страницы аналитики
     */
    public function enqueue_analytics_scripts($hook) {
        // Проверяем, что мы на нужной странице
        if ($hook !== 'settings_page_asb-analytics') {
            return;
        }
        
        // Подключаем Chart.js локально или через CDN с fallback
        wp_enqueue_script(
            'chart-js',
            'https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js',
            [],
            '4.4.2',
            true
        );
        
        // Добавляем inline стили для страницы аналитики
        wp_add_inline_style('wp-admin', '
            .asb-analytics-container {
                max-width: 1200px;
                margin: 20px auto;
            }
            .asb-stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .asb-stat-card {
                background: #fff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-align: center;
            }
            .asb-stat-number {
                font-size: 2.5em;
                font-weight: bold;
                margin: 10px 0;
            }
            .asb-stat-label {
                color: #666;
                font-size: 0.9em;
            }
            .asb-charts-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
                gap: 30px;
                margin-bottom: 30px;
            }
            @media (max-width: 1200px) {
                .asb-charts-grid {
                    grid-template-columns: 1fr;
                }
            }
            .asb-chart-container {
                background: #fff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .asb-chart-title {
                margin-top: 0;
                margin-bottom: 20px;
                color: #1d2327;
            }
            .asb-chart-wrapper {
                position: relative;
                height: 300px;
                width: 100%;
            }
        ');
    }

    public function analytics_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('У вас недостаточно прав для доступа к этой странице.', 'ip-blocker-manager'));
        }
        
        $data = $this->get_analytics_data();
        
        // Проверяем наличие данных для отображения
        if (empty($data) || !is_array($data)) {
            $data = [
                'total_attacks' => 0,
                'attacks_by_type' => [],
                'attacks_by_day' => array_fill_keys(array_map(function($i) {
                    return date('Y-m-d', strtotime("-$i days"));
                }, range(29, 0)), 0),
                'blocked_ips_count' => 0,
                'unique_attackers_count' => 0
            ];
        }
        
        // Подготавливаем данные для JavaScript
        $attacks_by_day_labels = array_keys($data['attacks_by_day']);
        $attacks_by_day_values = array_values($data['attacks_by_day']);
        
        $attacks_by_type_labels = array_keys($data['attacks_by_type']);
        $attacks_by_type_values = array_values($data['attacks_by_type']);
        ?>
        <div class="wrap asb-analytics-container">
            <h1><?php _e('Аналитика атак', 'ip-blocker-manager'); ?></h1>
            
            <div class="asb-stats-grid">
                <div class="asb-stat-card">
                    <h3><?php _e('Всего атак', 'ip-blocker-manager'); ?></h3>
                    <div class="asb-stat-number"><?php echo number_format($data['total_attacks']); ?></div>
                    <div class="asb-stat-label"><?php _e('За все время', 'ip-blocker-manager'); ?></div>
                </div>
                
                <div class="asb-stat-card">
                    <h3><?php _e('Заблокировано IP', 'ip-blocker-manager'); ?></h3>
                    <div class="asb-stat-number" style="color: #d63638;"><?php echo number_format($data['blocked_ips_count']); ?></div>
                    <div class="asb-stat-label"><?php _e('Текущие блокировки', 'ip-blocker-manager'); ?></div>
                </div>
                
                <div class="asb-stat-card">
                    <h3><?php _e('Уникальных атакующих', 'ip-blocker-manager'); ?></h3>
                    <div class="asb-stat-number" style="color: #00a32a;"><?php echo number_format($data['unique_attackers_count']); ?></div>
                    <div class="asb-stat-label"><?php _e('Разные IP-адреса', 'ip-blocker-manager'); ?></div>
                </div>
            </div>

            <div class="asb-charts-grid">
                <div class="asb-chart-container">
                    <h2 class="asb-chart-title"><?php _e('Атаки за последние 30 дней', 'ip-blocker-manager'); ?></h2>
                    <div class="asb-chart-wrapper">
                        <canvas id="asb-attacks-over-time-chart"></canvas>
                    </div>
                </div>
                
                <div class="asb-chart-container">
                    <h2 class="asb-chart-title"><?php _e('Распределение по типам атак', 'ip-blocker-manager'); ?></h2>
                    <div class="asb-chart-wrapper">
                        <canvas id="asb-attacks-by-type-chart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="asb-chart-container">
                <h2 class="asb-chart-title"><?php _e('Детальная статистика', 'ip-blocker-manager'); ?></h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th><?php _e('Тип атаки', 'ip-blocker-manager'); ?></th>
                            <th><?php _e('Количество', 'ip-blocker-manager'); ?></th>
                            <th><?php _e('Процент', 'ip-blocker-manager'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($attacks_by_type_labels)): ?>
                            <tr>
                                <td colspan="3" style="text-align: center;"><?php _e('Нет данных об атаках', 'ip-blocker-manager'); ?></td>
                            </tr>
                        <?php else: ?>
                            <?php 
                            $total_attacks = array_sum($attacks_by_type_values);
                            foreach ($attacks_by_type_labels as $index => $type):
                                $count = $attacks_by_type_values[$index];
                                $percentage = $total_attacks > 0 ? round(($count / $total_attacks) * 100, 1) : 0;
                                $type_label = $this->get_attack_type_label($type);
                            ?>
                                <tr>
                                    <td><?php echo esc_html($type_label); ?></td>
                                    <td><?php echo number_format($count); ?></td>
                                    <td><?php echo $percentage; ?>%</td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Проверяем, загружен ли Chart.js
            if (typeof Chart === 'undefined') {
                console.error('Chart.js не загружен!');
                alert('Ошибка загрузки библиотеки графиков. Пожалуйста, обновите страницу.');
                return;
            }
            
            // Данные для графика атак по дням
            const attacksByDayLabels = <?php echo json_encode($attacks_by_day_labels); ?>;
            const attacksByDayValues = <?php echo json_encode($attacks_by_day_values); ?>;
            
            // Данные для графика атак по типам
            const attacksByTypeLabels = <?php echo json_encode($attacks_by_type_labels); ?>;
            const attacksByTypeValues = <?php echo json_encode($attacks_by_type_values); ?>;
            
            // Цвета для графиков
            const chartColors = {
                blue: 'rgba(54, 162, 235, 0.8)',
                red: 'rgba(255, 99, 132, 0.8)',
                green: 'rgba(75, 192, 192, 0.8)',
                orange: 'rgba(255, 159, 64, 0.8)',
                purple: 'rgba(153, 102, 255, 0.8)',
                yellow: 'rgba(255, 205, 86, 0.8)',
                grey: 'rgba(201, 203, 207, 0.8)'
            };
            
            const typeColors = [
                chartColors.red,    // login_fail
                chartColors.blue,   // honeypot
                chartColors.green,  // geo_block
                chartColors.orange, // file_access
                chartColors.purple, // brute_force
                chartColors.yellow  // other
            ];
            
            // График 1: Атаки по дням
            const timeCtx = document.getElementById('asb-attacks-over-time-chart');
            if (timeCtx) {
                try {
                    new Chart(timeCtx, {
                        type: 'line',
                        data: {
                            labels: attacksByDayLabels,
                            datasets: [{
                                label: '<?php _e('Количество атак', 'ip-blocker-manager'); ?>',
                                data: attacksByDayValues,
                                borderColor: chartColors.blue,
                                backgroundColor: chartColors.blue.replace('0.8', '0.2'),
                                borderWidth: 2,
                                tension: 0.3,
                                fill: true
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    display: true,
                                    position: 'top'
                                },
                                tooltip: {
                                    mode: 'index',
                                    intersect: false
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    title: {
                                        display: true,
                                        text: '<?php _e('Количество атак', 'ip-blocker-manager'); ?>'
                                    },
                                    ticks: {
                                        stepSize: 1
                                    }
                                },
                                x: {
                                    title: {
                                        display: true,
                                        text: '<?php _e('Дата', 'ip-blocker-manager'); ?>'
                                    }
                                }
                            }
                        }
                    });
                } catch (error) {
                    console.error('Ошибка создания графика атак по дням:', error);
                    timeCtx.parentElement.innerHTML = '<p style="color: red;">Ошибка создания графика. Пожалуйста, обновите страницу.</p>';
                }
            }
            
            // График 2: Атаки по типам
            const typeCtx = document.getElementById('asb-attacks-by-type-chart');
            if (typeCtx && attacksByTypeLabels.length > 0) {
                try {
                    new Chart(typeCtx, {
                        type: 'pie',
                        data: {
                            labels: attacksByTypeLabels.map(label => {
                                const labelsMap = {
                                    'login_fail': '<?php _e('Неудачные входы', 'ip-blocker-manager'); ?>',
                                    'honeypot': '<?php _e('Honeypot', 'ip-blocker-manager'); ?>',
                                    'geo_block': '<?php _e('Гео-блокировка', 'ip-blocker-manager'); ?>',
                                    'file_access': '<?php _e('Доступ к файлам', 'ip-blocker-manager'); ?>',
                                    'brute_force': '<?php _e('Брутфорс', 'ip-blocker-manager'); ?>',
                                    'other': '<?php _e('Другие', 'ip-blocker-manager'); ?>'
                                };
                                return labelsMap[label] || label;
                            }),
                            datasets: [{
                                data: attacksByTypeValues,
                                backgroundColor: typeColors.slice(0, attacksByTypeLabels.length),
                                borderColor: '#fff',
                                borderWidth: 2,
                                hoverOffset: 10
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    position: 'right',
                                    labels: {
                                        padding: 20,
                                        usePointStyle: true
                                    }
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            const label = context.label || '';
                                            const value = context.raw || 0;
                                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                                            return `${label}: ${value} (${percentage}%)`;
                                        }
                                    }
                                }
                            }
                        }
                    });
                } catch (error) {
                    console.error('Ошибка создания графика атак по типам:', error);
                    typeCtx.parentElement.innerHTML = '<p style="color: red;">Ошибка создания графика. Пожалуйста, обновите страницу.</p>';
                }
            } else if (typeCtx) {
                typeCtx.parentElement.innerHTML = '<p style="text-align: center; color: #666;"><?php _e('Нет данных об атаках для отображения', 'ip-blocker-manager'); ?></p>';
            }
        });
        </script>
        <?php
    }
    
    /**
     * Получить читаемое название типа атаки
     */
    private function get_attack_type_label($type) {
        $labels = [
            'login_fail' => __('Неудачные попытки входа', 'ip-blocker-manager'),
            'honeypot' => __('Активация Honeypot', 'ip-blocker-manager'),
            'geo_block' => __('Гео-блокировка', 'ip-blocker-manager'),
            'file_access' => __('Доступ к опасным файлам', 'ip-blocker-manager'),
            'brute_force' => __('Брутфорс атака', 'ip-blocker-manager'),
            'other' => __('Другие атаки', 'ip-blocker-manager')
        ];
        
        return $labels[$type] ?? ucfirst(str_replace('_', ' ', $type));
    }

}

/* ============================================================
   Класс кеш‑обработчика
============================================================ */
class ASB_Cache_Handler {

    public function __construct() {}

    public function clear_all_caches() {
        $this->clear_browser_cache();
        $this->clear_opcache();
        $this->clear_redis_cache();
        $this->clear_memcached_cache();
        $this->clear_wordpress_cache();
    }

    private function clear_browser_cache() {
        if (!headers_sent()) {
            header('Cache-Control: no-cache, must-revalidate');
            header('Expires: Sat, 26 Jul 1997 05:00:00 GMT');
            header('Pragma: no-cache');
        }
    }

    private function clear_opcache() {
        if (function_exists('opcache_reset')) {
            opcache_reset();
            error_log('Security Blocker: OPcache очищен');
        }
    }

    private function clear_redis_cache() {
        if (class_exists('Redis')) {
            try {
                $r = new Redis();
                if ($r->connect('127.0.0.1', 6379)) {
                    $r->flushAll();
                    $r->close();
                    error_log('Security Blocker: Redis кеш очищен');
                }
            } catch (Exception $e) {}
        }
    }

    private function clear_memcached_cache() {
        if (class_exists('Memcached')) {
            try {
                $m = new Memcached();
                $m->addServer('127.0.0.1', 11211);
                $m->flush();
                error_log('Security Blocker: Memcached кеш очищен');
            } catch (Exception $e) {}
        }
    }

    private function clear_wordpress_cache() {
        if (function_exists('wp_cache_flush')) wp_cache_flush();
        if (function_exists('wp_cache_clear_cache')) wp_cache_clear_cache();
        if (function_exists('w3tc_flush_all')) w3tc_flush_all();
        if (function_exists('rocket_clean_domain')) rocket_clean_domain();
        error_log('Security Blocker: WordPress кеш очищен');
    }
}

/* ============================================================
   WP‑CLI команды
============================================================ */
if (defined('WP_CLI') && WP_CLI) {
    class ASB_CLI_Command {
        public function block($args, $assoc) {
            list($target) = $args;
            $asb = new Advanced_Security_Blocker();
            $asb->block_ip_address($target, 'cli', 'cli');
            WP_CLI::success("IP/ASN {$target} заблокирован.");
        }

        public function unblock($args, $assoc) {
            list($target) = $args;
            $asb = new Advanced_Security_Blocker();
            $asb->unblock_ip_address($target, 'CLI‑разблокировка');
            WP_CLI::success("IP {$target} разблокирован.");
        }

        public function list($args, $assoc) {
            $asb = new Advanced_Security_Blocker();
            $list = $asb->get_current_ips();
            WP_CLI::log("Заблокированные IP:\n" . $list);
        }

        public function whitelist($args, $assoc) {
            $asb = new Advanced_Security_Blocker();
            $list = $asb->get_whitelist_ips();
            WP_CLI::log("Белый список:\n" . implode("\n", $list));
        }
    }
    WP_CLI::add_command('asb', 'ASB_CLI_Command');
}

/* ============================================================
   Инициализация плагина
============================================================ */
new Advanced_Security_Blocker();
