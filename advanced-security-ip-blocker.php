<?php
/*
Plugin Name: Advanced Security IP Blocker
Description: Продвинутая система безопасности: блокировка IP, защита wp‑login.php и xmlrpc.php, блокировка опасных файлов и ботов с поддержкой ASN, гео‑блокировки, honeypot‑страниц, интеграция с внешними черными листами, Fail2Ban, Redis и WP‑CLI.
Plugin URI: https://github.com/RobertoBennett/IP-Blocker-Manager
Version: 2.0.2
Author: Robert Bennett
Text Domain: ip-blocker-manager
*/

defined('ABSPATH') || exit;

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
    private $backup_dir;
    private $cache_dir;
    private $log = [];
    private $cache_handler;
    private $geo_reader;
    private $redis;

    /* ----------------------------------------------------------
       Конструктор – регистрация хуков
    ---------------------------------------------------------- */
    public function __construct() {
        $this->htaccess_path = ABSPATH . '.htaccess';
        $this->backup_dir    = WP_CONTENT_DIR . '/security-blocker-backups/';
        $this->cache_dir     = WP_CONTENT_DIR . '/security-blocker-cache/';
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

        // Таблицы БД
        register_activation_hook(__FILE__, [$this, 'create_login_attempts_table']);
        register_activation_hook(__FILE__, [$this, 'create_unblock_history_table']);

        // Деактивация / Удаление
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        register_uninstall_hook(__FILE__,    [__CLASS__, 'uninstall']);

        // Инициализация вспомогательных компонентов (только чтение, скачивание - отдельно)
        $this->init_geo_reader_instance();
        $this->init_redis_client();
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
            'asb_telegram_chat_id'         => ''
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
        $db_file = $this->cache_dir . 'GeoLite2-Country.mmdb';
        if (file_exists($db_file) && class_exists('\MaxMind\Db\Reader')) {
            try {
                $this->geo_reader = new \MaxMind\Db\Reader($db_file);
            } catch (Exception $e) {
                error_log('ASB: Ошибка инициализации GeoIP reader: ' . $e->getMessage());
            }
        }
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
        $this->remove_nginx_rules();
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
            'asb_telegram_chat_id','asb_nginx_mode','asb_rate_limit_enabled'
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
            $ip_list = array_unique($ip_list);

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

    // ИЗМЕНЕНО НА PUBLIC для доступа из WP-CLI
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

    // ИЗМЕНЕНО НА PUBLIC для доступа из WP-CLI
    public function block_ip_address($ip_address, $username = '', $attempts = 0) {
        global $wpdb;
        
        // Валидация IP
        if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
            error_log("Security Blocker: Попытка заблокировать невалидный IP: {$ip_address}");
            return false;
        }

        $table = $wpdb->prefix . 'security_login_attempts';

        // 1. Помечаем в БД
        $wpdb->update($table, ['blocked' => 1], ['ip_address' => $ip_address]);

        // 2. Добавляем в .htaccess (если включено)
        if (get_option('asb_auto_add_to_htaccess')) {
            $this->add_ip_to_htaccess($ip_address);
        }

        // 3. Добавляем в постоянный список WordPress (если длительность 0)
        if (intval(get_option('asb_block_duration', 60)) === 0) {
            $this->add_to_permanent_blocklist($ip_address);
        }

        // 4. Fail2Ban – запись в syslog
        if (get_option('asb_fail2ban_enabled')) {
            error_log("asb: BLOCKED {$ip_address} ({$username})");
        }

        // 5. Redis‑шаред‑блоклист
        if (get_option('asb_redis_shared_blocklist') && $this->redis) {
            try {
                $this->redis->set("asb:block:{$ip_address}", 1, 86400);
            } catch (Exception $e) {
                error_log("ASB Redis error: " . $e->getMessage());
            }
        }

        // 6. Уведомления
        if (get_option('asb_email_notifications')) {
            $this->send_block_notification($ip_address, $username, $attempts);
        }
        if (get_option('asb_telegram_token') && get_option('asb_telegram_chat_id')) {
            $this->send_telegram_message("🔒 IP {$ip_address} заблокирован ({$username}) попыток: {$attempts}");
        }

        error_log("Security Blocker: IP {$ip_address} заблокирован (user={$username}, attempts={$attempts})");
        return true;
    }

    // ИЗМЕНЕНО НА PUBLIC для доступа из WP-CLI
    public function unblock_ip_address($ip_address, $reason = '') {
        global $wpdb;
        $table = $wpdb->prefix . 'security_login_attempts';

        // 1. Снимаем флаг blocked в БД
        $wpdb->update($table, ['blocked' => 0], ['ip_address' => $ip_address, 'blocked' => 1]);

        // 2. Удаляем из списка WP
        $list = get_option('asb_wp_blocked_ips', '');
        if ($list) {
            $arr = array_filter(array_map('trim', explode("\n", $list)));
            $new = array_diff($arr, [$ip_address]);
            update_option('asb_wp_blocked_ips', implode("\n", $new));
        }

        // 3. Удаляем из .htaccess
        $current = $this->get_current_ips();
        if (!empty($current)) {
            $arr = array_filter(array_map('trim', explode("\n", $current)));
            $new = array_diff($arr, [$ip_address]);
            $this->update_ip_rules(implode("\n", $new));
        }

        // 4. Записываем в историю разблокировок
        $unblock_tbl = $wpdb->prefix . 'security_unblock_history';
        $user = wp_get_current_user();
        $wpdb->insert($unblock_tbl, [
            'ip_address'     => $ip_address,
            'unblock_reason' => $reason,
            'unblocked_by'   => $user->user_login
        ]);

        // 5. Redis‑очистка
        if (get_option('asb_redis_shared_blocklist') && $this->redis) {
            try {
                $this->redis->del("asb:block:{$ip_address}");
            } catch (Exception $e) {
                error_log("ASB Redis error: " . $e->getMessage());
            }
        }

        error_log("Security Blocker: IP {$ip_address} разблокирован (reason: {$reason})");
    }

    private function add_ip_to_htaccess($ip_address) {
        $current = $this->get_current_ips();
        $list = array_filter(array_map('trim', explode("\n", $current)));
        if (!in_array($ip_address, $list)) {
            $list[] = $ip_address;
            $this->update_ip_rules(implode("\n", $list));
        }
    }

    private function add_to_permanent_blocklist($ip_address) {
        $list = get_option('asb_wp_blocked_ips', '');
        $arr = array_filter(array_map('trim', explode("\n", $list)));
        if (!in_array($ip_address, $arr)) {
            $arr[] = $ip_address;
            update_option('asb_wp_blocked_ips', implode("\n", $arr));
        }
    }

    /**
     * Проверка IP на уровне WordPress
     */
    private function is_ip_blocked_at_wp_level($ip) {
        $list = get_option('asb_wp_blocked_ips', '');
        if (empty($list)) return false;

        $blocked = array_filter(array_map('trim', explode("\n", $list)));
        foreach ($blocked as $entry) {
            if ($entry === $ip) return true;
            if (strpos($entry, '/') !== false && $this->ip_in_cidr($ip, $entry)) return true;
        }
        return false;
    }

    /* ==========================================================
       7. Обработка попыток входа (брутфорс)
       ========================================================== */

    public function handle_failed_login($username) {
        if (!get_option('asb_brute_force_enabled')) return;
        $ip = $this->get_user_ip();

        if ($this->is_ip_whitelisted($ip)) return;

        global $wpdb;
        $table = $wpdb->prefix . 'security_login_attempts';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $wpdb->insert($table, [
            'ip_address'  => $ip,
            'username'    => sanitize_user($username),
            'user_agent'  => sanitize_text_field($ua),
            'attempt_time'=> current_time('mysql')
        ]);

        $max    = intval(get_option('asb_max_attempts', 5));
        $window = intval(get_option('asb_time_window', 15));

        $cnt = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table
             WHERE ip_address = %s
               AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)",
            $ip, $window
        ));

        if ($cnt >= $max) {
            $this->block_ip_address($ip, $username, $cnt);
        }

        if (get_option('asb_external_blacklist')) {
            $reputation = $this->check_external_reputation($ip);
            if ($reputation && isset($reputation['score']) && $reputation['score'] < 30) {
                $this->block_ip_address($ip, 'reputation', 0);
            }
        }
    }

    private function check_external_reputation($ip) {
        $api_key = get_option('asb_external_api_key', '');
        if (!$api_key) return false;
        $url = "https://ipqualityscore.com/api/json/ip/{$api_key}/{$ip}";
        $resp = wp_remote_get($url, ['timeout' => 10]);
        if (is_wp_error($resp)) return false;
        $data = json_decode(wp_remote_retrieve_body($resp), true);
        return $data;
    }

    public function check_blocked_ip($user, $password) {
        if (!get_option('asb_brute_force_enabled')) return $user;
        $ip = $this->get_user_ip();
        if ($this->is_ip_whitelisted($ip)) return $user;

        // Redis‑быстрая проверка
        if (get_option('asb_redis_shared_blocklist') && $this->redis) {
            try {
                if ($this->redis->exists("asb:block:{$ip}")) {
                    return new WP_Error('ip_blocked_redis', 'Ваш IP временно заблокирован');
                }
            } catch (Exception $e) {
                error_log("ASB Redis error: " . $e->getMessage());
            }
        }

        // Проверка в базе (временный бан)
        global $wpdb;
        $table = $wpdb->prefix . 'security_login_attempts';
        $duration = intval(get_option('asb_block_duration', 60));

        $blocked = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table
             WHERE ip_address = %s
               AND blocked = 1
               AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)",
            $ip, $duration
        ));

        if ($blocked) {
            $remaining = $duration - floor((time() - strtotime($blocked->attempt_time)) / 60);
            return new WP_Error('ip_blocked_temporary',
                sprintf('Ваш IP временно заблокирован. Попробуйте снова через %d минут.', max(1, $remaining)));
        }

        // Проверка постоянных блокировок
        if ($this->is_ip_blocked_at_wp_level($ip)) {
            return new WP_Error('ip_blocked_permanent', 'Ваш IP заблокирован.');
        }

        return $user;
    }

    public function check_ip_access() {
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) return;
        if (!get_option('asb_brute_force_enabled')) return;

        $ip = $this->get_user_ip();
        if ($this->is_ip_whitelisted($ip)) return;

        // Fail2Ban‑лог
        if (get_option('asb_fail2ban_enabled')) {
            error_log("asb: ACCESS {$ip}");
        }

        // Geo‑блокировка
        if (get_option('asb_geo_block_countries')) {
            $blocked_countries = explode(',', get_option('asb_geo_block_countries'));
            $country = $this->get_ip_country($ip);
            if (in_array($country, $blocked_countries)) {
                wp_die('Доступ запрещён (региональная блокировка).', '403', ['response' => 403]);
            }
        }

        // Проверка уровня WP
        if ($this->is_ip_blocked_at_wp_level($ip)) {
            wp_die('Доступ запрещён (IP заблокирован).', '403', ['response' => 403]);
        }
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
       9. GeoIP
       ========================================================== */

    private function get_ip_country($ip) {
        if (!$this->geo_reader) return null;
        try {
            $record = $this->geo_reader->get($ip);
            return $record['country']['iso_code'] ?? null;
        } catch (Exception $e) {
            return null;
        }
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
        $ip_long     = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask_long   = -1 << (32 - (int)$mask);
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }

    /* ==========================================================
       12. Уведомления
       ========================================================== */

    private function send_block_notification($ip, $username, $attempts, $method = 'htaccess + WordPress') {
        $admin = get_option('admin_email');
        $site  = get_bloginfo('name');
        $url   = get_site_url();

        $subject = "[$site] IP $ip заблокирован";
        $msg = <<<EOT
Внимание! На сайте $site обнаружена попытка брутфорса.

IP: $ip
Пользователь: $username
Попыток: $attempts
Метод: $method
Время: " . current_time('mysql') . "

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
                        <td>
                            <?php
                            $labels = [
                                'temporary' => '<span style="color:orange;">Временная</span>',
                                'permanent'=> '<span style="color:red;">Постоянная</span>',
                                'htaccess' => '<span style="color:purple;">.htaccess</span>'
                            ];
                            echo $labels[$b['type']] ?? $b['type'];
                            ?>
                        </td>
                        <td>
                            <?php
                            $type = 'IP';
                            if (strpos($b['ip'], 'AS') === 0) $type = 'ASN';
                            elseif (strpos($b['ip'], '/') !== false) $type = 'CIDR';
                            echo $type;
                            ?>
                        </td>
                        <td><?php echo esc_html($b['last_attempt']); ?></td>
                        <td>
                            <a href="<?php echo wp_nonce_url(
                                admin_url('options-general.php?page=advanced-security-blocker&unblock_ip=' . $b['ip'] . '&tab=manage-blocks&paged=' . $page . '&s=' . urlencode($search)),
                                'unblock_ip'); ?>" class="button" onclick="return confirm('Разблокировать?');">Разблокировать</a>
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

        // Временные из БД
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

        // Постоянные из опции
        $perm = get_option('asb_wp_blocked_ips', '');
        if ($perm) {
            foreach (array_filter(array_map('trim', explode("\n", $perm))) as $ip) {
                $result['permanent'][] = ['ip' => $ip, 'last_attempt' => 'N/A', 'type' => 'permanent'];
            }
        }

        // .htaccess
        $ht = $this->get_current_ips();
        if ($ht) {
            foreach (array_filter(explode("\n", $ht)) as $ip) {
                $exists = false;
                foreach ($result['permanent'] as $p) {
                    if ($p['ip'] === $ip) {
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

        $this->block_ip_address($ip, 'manual', 0);

        wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=manage-blocks&manual_block=1'));
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
       16. Страница настроек (основная UI)
       ========================================================== */

    public function settings_page() {
        if (!current_user_can('manage_options')) return;

        // Обработка сообщений
        $error = $success = '';
        if (isset($_GET['backup_created']))    $success = 'Резервная копия создана';
        if (isset($_GET['cache_cleared']))     $success = 'Кеш очищен';
        if (isset($_GET['unblocked']))         $success = 'IP разблокирован';
        if (isset($_GET['manual_block']))      $success = 'IP добавлен в чёрный список';
        if (isset($_GET['whitelist_added']))   $success = 'IP добавлен в белый список';
        if (isset($_GET['whitelist_removed'])) $success = 'IP удалён из белого списка';
        if (isset($_GET['error']) && $_GET['error'] === 'invalid_ip') $error = 'Неверный формат IP/ASN';

        // Обновление IP‑блоков
        if (isset($_POST['submit_ip_blocker'])) {
            check_admin_referer('security_blocker_update');
            $ips = sanitize_textarea_field($_POST['ip_addresses'] ?? '');
            $res = $this->update_ip_rules($ips);
            if ($res === true) $success = 'IP‑правила обновлены';
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
            <h1>Продвинутая система безопасности</h1>
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
                    <button data-tab="tab-manage-blocks">Управление блокировками</button>
                    <button data-tab="tab-whitelist">Белый список</button>
                    <button data-tab="tab-status">Статус</button>
                    <button data-tab="tab-telegram">Telegram‑уведомления</button>
                </div>

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
                                    <thead><tr><th>IP / ASN</th><th>Тип</th><th>Запись</th><th>Последняя попытка</th><th>Действия</th></tr></thead>
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
                                                        admin_url('options-general.php?page=advanced-security-blocker&unblock_ip=' . $b['ip'] . '&tab=manage-blocks&paged=' . $cur_page . '&s=' . urlencode($search_q)),
                                                        'unblock_ip'); ?>" class="button" onclick="return confirm('Разблокировать?');">Разблокировать</a>
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
                        <h3>Ручная блокировка IP</h3>
                        <form method="post">
                            <?php wp_nonce_field('security_blocker_update'); ?>
                            <table class="form-table">
                                <tr>
                                    <th><label for="manual_block_ip">IP/ CIDR / ASN:</label></th>
                                    <td><input type="text" name="manual_block_ip" id="manual_block_ip" class="regular-text" placeholder="192.168.0.1 или 192.168.0.0/24 или AS15169"></td>
                                </tr>
                                <tr>
                                    <th><label for="block_reason">Причина:</label></th>
                                    <td><input type="text" name="block_reason" id="block_reason" class="regular-text" placeholder="Нежелательный трафик"></td>
                                </tr>
                            </table>
                            <p><button type="submit" name="submit_manual_block" class="button button-primary">Заблокировать</button></p>
                        </form>
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
                                echo $bks ? '<span style="color:green">' . date('d.m.Y H:i:s', filemtime($bks[0])) . '</span>' : '<span style="color:orange">не создана</span>';
                                ?></li>
                            <li>Кешированных ASN‑файлов: <?php echo count(glob($this->cache_dir . 'asn_*.json')); ?></li>
                            <li>Ваш IP: <strong><?php echo esc_html($current_user_ip); ?></strong></li>
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
                        </ul>
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
        });
        </script>
        <?php
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
