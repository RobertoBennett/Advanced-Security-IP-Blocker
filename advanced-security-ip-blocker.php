<?php
/*
Plugin Name: Advanced Security IP Blocker
Description: Продвинутая система безопасности: блокировка IP, защита wp-login.php и xmlrpc.php, блокировка опасных файлов и ботов с поддержкой ASN, автоматическая блокировка при брутфорс атаках
Plugin URI: https://github.com/RobertoBennett/IP-Blocker-Manager
Version: 1.0.0
Author: Robert Bennett
Text Domain: IP Blocker Manager
*/

defined('ABSPATH') || exit;

class Advanced_Security_Blocker {
    private $htaccess_path;
    private $marker_ip = "# IP_BLOCKER_SAFE_MARKER";
    private $marker_login = "# LOGIN_PROTECTION_MARKER";
    private $marker_files = "# DANGEROUS_FILES_MARKER";
    private $marker_bots = "# BOT_PROTECTION_MARKER";
    private $backup_dir;
    private $cache_dir;
    private $log = [];
    private $cache_handler;

    public function __construct() {
        $this->htaccess_path = ABSPATH . '.htaccess';
        $this->backup_dir = WP_CONTENT_DIR . '/security-blocker-backups/';
        $this->cache_dir = WP_CONTENT_DIR . '/security-blocker-cache/';
        $this->cache_handler = new ASB_Cache_Handler();

        add_action('admin_menu', [$this, 'admin_menu']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        register_uninstall_hook(__FILE__, [__CLASS__, 'uninstall']);
        add_action('admin_init', [$this, 'create_backup_dir']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('admin_init', [$this, 'init_default_settings']);
        add_action('admin_init', [$this, 'handle_backup_request']);
        add_action('admin_init', [$this, 'handle_cache_clear']);
        add_action('admin_init', [$this, 'handle_unblock_request']);
        add_action('admin_init', [$this, 'handle_manual_block_request']);
        add_action('admin_init', [$this, 'handle_whitelist_request']);

        // Новые хуки для защиты от брутфорс атак
        add_action('wp_login_failed', [$this, 'handle_failed_login']);
        add_action('wp_authenticate_user', [$this, 'check_blocked_ip'], 10, 2);
        add_action('init', [$this, 'init_brute_force_protection']);
        // Проверка блокировки для всех запросов (не только логин)
        add_action('init', [$this, 'check_ip_access'], 1);

        // AJAX обработчики для обновления в реальном времени
        add_action('wp_ajax_asb_get_login_stats', [$this, 'ajax_get_login_stats']);
        add_action('wp_ajax_asb_get_recent_attempts', [$this, 'ajax_get_recent_attempts']);
        add_action('wp_ajax_asb_get_block_history', [$this, 'ajax_get_block_history']);

        // Создаем таблицу для логирования попыток входа
        register_activation_hook(__FILE__, [$this, 'create_login_attempts_table']);
        register_activation_hook(__FILE__, [$this, 'create_unblock_history_table']);

        // Проверяем и создаем таблицы при необходимости
        add_action('admin_init', [$this, 'check_and_create_tables']);
    }

    // Проверка и создание необходимых таблиц
    public function check_and_create_tables() {
        global $wpdb;

        // Проверяем таблицу попыток входа
        $table_name = $wpdb->prefix . 'security_login_attempts';
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            $this->create_login_attempts_table();
        }

        // Проверяем таблицу истории разблокировок
        $unblock_table = $wpdb->prefix . 'security_unblock_history';
        if ($wpdb->get_var("SHOW TABLES LIKE '$unblock_table'") != $unblock_table) {
            $this->create_unblock_history_table();
        }
    }

    // Функция удаления плагина (полная очистка)
    public static function uninstall() {
        global $wpdb;

        // Удаляем таблицу с попытками входа
        $table_name = $wpdb->prefix . 'security_login_attempts';
        $wpdb->query("DROP TABLE IF EXISTS $table_name");

        // Удаляем таблицу с историей разблокировок
        $unblock_table = $wpdb->prefix . 'security_unblock_history';
        $wpdb->query("DROP TABLE IF EXISTS $unblock_table");

        // Удаляем все опции плагина
        delete_option('asb_dangerous_files');
        delete_option('asb_blocked_bots');
        delete_option('asb_brute_force_enabled');
        delete_option('asb_max_attempts');
        delete_option('asb_time_window');
        delete_option('asb_block_duration');
        delete_option('asb_auto_add_to_htaccess');
        delete_option('asb_email_notifications');
        delete_option('asb_blocked_ips_list');
        delete_option('asb_wp_blocked_ips');
        delete_option('asb_whitelist_ips');

        // Восстанавливаем чистый .htaccess
        $htaccess_path = ABSPATH . '.htaccess';
        if (file_exists($htaccess_path)) {
            $markers = [
                "# IP_BLOCKER_SAFE_MARKER",
                "# LOGIN_PROTECTION_MARKER",
                "# DANGEROUS_FILES_MARKER",
                "# BOT_PROTECTION_MARKER"
            ];

            $content = file_get_contents($htaccess_path);
            foreach ($markers as $marker) {
                $pattern = '/\n?' . preg_quote($marker, '/') . '.*?' . preg_quote($marker, '/') . '/s';
                $content = preg_replace($pattern, '', $content);
            }

            file_put_contents($htaccess_path, $content);
        }

        // Удаляем директории кеша и бекапов
        $backup_dir = WP_CONTENT_DIR . '/security-blocker-backups/';
        $cache_dir = WP_CONTENT_DIR . '/security-blocker-cache/';

        if (is_dir($backup_dir)) {
            array_map('unlink', glob("$backup_dir/*.*"));
            @rmdir($backup_dir);
        }

        if (is_dir($cache_dir)) {
            array_map('unlink', glob("$cache_dir/*.*"));
            @rmdir($cache_dir);
        }
    }

    // Создание таблицы для истории разблокировок
    public function create_unblock_history_table() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'security_unblock_history';

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            unblock_time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            unblock_reason text,
            unblocked_by varchar(100) DEFAULT 'admin',
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY unblock_time (unblock_time)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    // AJAX: Получение статистики попыток входа
    public function ajax_get_login_stats() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        check_ajax_referer('asb_ajax_nonce', 'nonce');

        $stats = $this->get_login_attempts_stats();
        wp_send_json_success([
            'total_attempts' => $stats['total_attempts'],
            'blocked_ips' => $stats['blocked_ips'],
            'top_ips' => $stats['top_ips'],
            'recent_attempts' => $stats['recent_attempts']
        ]);
    }

    // AJAX: Получение последних попыток входа
    public function ajax_get_recent_attempts() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        check_ajax_referer('asb_ajax_nonce', 'nonce');

        $stats = $this->get_login_attempts_stats();
        wp_send_json_success([
            'recent_attempts' => $stats['recent_attempts']
        ]);
    }

    // AJAX: Получение истории блокировок IP
    public function ajax_get_block_history() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        check_ajax_referer('asb_ajax_nonce', 'nonce');

        if (isset($_POST['ip'])) {
            $ip = sanitize_text_field($_POST['ip']);
            $history = $this->get_block_history($ip);
            wp_send_json_success($history);
        } else {
            wp_send_json_error('IP not provided');
        }
    }

    // Обработчик запроса на разблокировку IP
    public function handle_unblock_request() {
        if (isset($_GET['page']) && $_GET['page'] === 'advanced-security-blocker' && isset($_GET['unblock_ip'])) {
            if (current_user_can('manage_options') && check_admin_referer('unblock_ip')) {
                $ip_to_unblock = sanitize_text_field($_GET['unblock_ip']);
                $reason = isset($_GET['reason']) ? sanitize_text_field($_GET['reason']) : 'Ручная разблокировка администратором';
                $this->unblock_ip_address($ip_to_unblock, $reason);
                wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=manage-blocks&unblocked=1'));
                exit;
            }
        }
    }

    // Обработчик запроса на добавление в белый список
    public function handle_whitelist_request() {
        if (isset($_POST['submit_whitelist']) && isset($_POST['_wpnonce'])) {
            if (current_user_can('manage_options') && wp_verify_nonce($_POST['_wpnonce'], 'security_blocker_update')) {
                $ip_to_whitelist = sanitize_text_field($_POST['whitelist_ip']);
                $reason = sanitize_text_field($_POST['whitelist_reason']);

                if (!empty($ip_to_whitelist)) {
                    // Проверяем валидность IP или CIDR
                    if ($this->validate_ip_or_cidr($ip_to_whitelist)) {
                        // Добавляем в белый список
                        $this->add_to_whitelist($ip_to_whitelist, $reason);

                        wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=whitelist&whitelist_added=1'));
                        exit;
                    } else {
                        wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=whitelist&error=invalid_ip'));
                        exit;
                    }
                }
            }
        }

        // Обработка удаления из белого списка
        if (isset($_GET['page']) && $_GET['page'] === 'advanced-security-blocker' && isset($_GET['remove_whitelist'])) {
            if (current_user_can('manage_options') && check_admin_referer('remove_whitelist')) {
                $ip_to_remove = sanitize_text_field($_GET['remove_whitelist']);
                $this->remove_from_whitelist($ip_to_remove);
                wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=whitelist&whitelist_removed=1'));
                exit;
            }
        }
    }

    // Обработчик запроса на ручную блокировку IP
    public function handle_manual_block_request() {
        if (isset($_POST['submit_manual_block']) && isset($_POST['_wpnonce'])) {
            if (current_user_can('manage_options') && wp_verify_nonce($_POST['_wpnonce'], 'security_blocker_update')) {
                $ip_to_block = sanitize_text_field($_POST['manual_block_ip']);
                $reason = sanitize_text_field($_POST['block_reason']);

                if (!empty($ip_to_block)) {
                    // Проверяем валидность IP или CIDR
                    if ($this->validate_ip_or_cidr($ip_to_block)) {
                        // Добавляем в постоянный список блокировки WordPress
                        $this->add_to_permanent_blocklist($ip_to_block);

                        // Логируем действие
                        error_log("Security Blocker: IP $ip_to_block заблокирован вручную. Причина: $reason");

                        wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=manage-blocks&manual_block=1'));
                        exit;
                    } else {
                        wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&tab=manage-blocks&error=invalid_ip'));
                        exit;
                    }
                }
            }
        }
    }

    // Функция разблокировки IP-адреса
    private function unblock_ip_address($ip_address, $reason = '') {
        global $wpdb;

        // 1. Удаляем из базы данных (снимаем флаг blocked)
        $table_name = $wpdb->prefix . 'security_login_attempts';
        $wpdb->update(
            $table_name,
            ['blocked' => 0],
            ['ip_address' => $ip_address, 'blocked' => 1],
            ['%d'],
            ['%s', '%d']
        );

        // 2. Удаляем из постоянного списка блокировки WordPress
        $blocked_ips = get_option('asb_wp_blocked_ips', '');
        if (!empty($blocked_ips)) {
            $blocked_list = array_map('trim', explode("\n", $blocked_ips));
            $new_list = array_diff($blocked_list, [$ip_address]);
            update_option('asb_wp_blocked_ips', implode("\n", $new_list));
        }

        // 3. Удаляем из .htaccess если есть
        $current_ips = $this->get_current_ips();
        $ip_list = array_filter(explode("\n", $current_ips));
        if (in_array($ip_address, $ip_list)) {
            $new_ips = array_diff($ip_list, [$ip_address]);
            $this->update_ip_rules(implode("\n", $new_ips));
        }

        // 4. Добавляем запись в истории разблокировок
        $unblock_table = $wpdb->prefix . 'security_unblock_history';
        $current_user = wp_get_current_user();
        $unblocked_by = $current_user->user_login;

        $wpdb->insert(
            $unblock_table,
            [
                'ip_address' => $ip_address,
                'unblock_reason' => $reason,
                'unblocked_by' => $unblocked_by
            ]
        );

        // Логируем действие
        error_log("Security Blocker: IP $ip_address разблокирован администратором. Причина: $reason");

        // Очищаем кеш
        $this->cache_handler->clear_all_caches();
    }

    // Добавление IP в белый список
    private function add_to_whitelist($ip_address, $reason = '') {
        $current_whitelist = get_option('asb_whitelist_ips', '');
        $whitelist = array_filter(explode("\n", $current_whitelist));

        // Проверяем, не добавлен ли уже этот IP
        if (!in_array($ip_address, $whitelist)) {
            $whitelist[] = $ip_address;
            $new_whitelist = implode("\n", $whitelist);

            // Обновляем опцию с белым списком IP
            update_option('asb_whitelist_ips', $new_whitelist);

            // Логируем действие
            error_log("Security Blocker: IP $ip_address добавлен в белый список. Причина: $reason");
        }
    }

    // Удаление IP из белого списка
    private function remove_from_whitelist($ip_address) {
        $current_whitelist = get_option('asb_whitelist_ips', '');
        if (!empty($current_whitelist)) {
            $whitelist = array_map('trim', explode("\n", $current_whitelist));
            $new_whitelist = array_diff($whitelist, [$ip_address]);

            // Обновляем опцию с белым списком IP
            update_option('asb_whitelist_ips', implode("\n", $new_whitelist));

            // Логируем действие
            error_log("Security Blocker: IP $ip_address удален из белого списка");
        }
    }

    // Получаем список всех заблокированных IP-адресов с поддержкой поиска и пагинации
    private function get_all_blocked_ips($search = '', $page = 1, $per_page = 20) {
        global $wpdb;

        $result = [
            'temporary' => [], // Временные блокировки из БД
            'permanent' => [], // Постоянные блокировки из опции
            'htaccess' => []   // Заблокированные в .htaccess
        ];

        // Временные блокировки из базы данных
        $table_name = $wpdb->prefix . 'security_login_attempts';
        $block_duration = intval(get_option('asb_block_duration', 60));

        $temporary_blocks = $wpdb->get_results($wpdb->prepare(
            "SELECT DISTINCT ip_address, MAX(attempt_time) as last_attempt
             FROM $table_name
             WHERE blocked = 1
             AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)
             GROUP BY ip_address",
            $block_duration
        ));

        foreach ($temporary_blocks as $block) {
            $result['temporary'][] = [
                'ip' => $block->ip_address,
                'last_attempt' => $block->last_attempt,
                'type' => 'temporary'
            ];
        }

        // Постоянные блокировки из опции
        $permanent_blocks = get_option('asb_wp_blocked_ips', '');
        if (!empty($permanent_blocks)) {
            $permanent_list = array_map('trim', explode("\n", $permanent_blocks));
            foreach ($permanent_list as $ip) {
                if (!empty($ip)) {
                    $result['permanent'][] = [
                        'ip' => $ip,
                        'last_attempt' => 'N/A',
                        'type' => 'permanent'
                    ];
                }
            }
        }

        // Блокировки из .htaccess
        $htaccess_ips = $this->get_current_ips();
        if (!empty($htaccess_ips)) {
            $htaccess_list = array_filter(explode("\n", $htaccess_ips));
            foreach ($htaccess_list as $ip) {
                if (!empty($ip) && !in_array($ip, array_column($result['permanent'], 'ip'))) {
                    $result['htaccess'][] = [
                        'ip' => $ip,
                        'last_attempt' => 'N/A',
                        'type' => 'htaccess'
                    ];
                }
            }
        }

        // Объединяем все блокировки
        $all_blocks = array_merge(
            $result['temporary'],
            $result['permanent'],
            $result['htaccess']
        );

        // Применяем поиск, если указан
        if (!empty($search)) {
            $all_blocks = array_filter($all_blocks, function($block) use ($search) {
                return stripos($block['ip'], $search) !== false;
            });
        }

        // Применяем пагинацию
        $total = count($all_blocks);
        $offset = ($page - 1) * $per_page;
        $paged_blocks = array_slice($all_blocks, $offset, $per_page);

        return [
            'blocks' => $paged_blocks,
            'total' => $total,
            'pages' => ceil($total / $per_page)
        ];
    }

    // Получаем историю блокировок для конкретного IP
    private function get_block_history($ip_address) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'security_login_attempts';

        $history = $wpdb->get_results($wpdb->prepare(
            "SELECT username, attempt_time, user_agent, blocked
             FROM $table_name
             WHERE ip_address = %s
             ORDER BY attempt_time DESC
             LIMIT 10",
            $ip_address
        ));

        return $history;
    }

    // Получаем историю разблокировок
    private function get_unblock_history($limit = 20) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'security_unblock_history';

        $history = $wpdb->get_results(
            "SELECT ip_address, unblock_time, unblock_reason, unblocked_by
             FROM $table_name
             ORDER BY unblock_time DESC
             LIMIT $limit"
        );

        return $history;
    }

    // Получаем белый список IP
    private function get_whitelist_ips() {
        $whitelist = get_option('asb_whitelist_ips', '');
        if (!empty($whitelist)) {
            return array_filter(array_map('trim', explode("\n", $whitelist)));
        }
        return [];
    }

    // Валидация IP или CIDR
    private function validate_ip_or_cidr($ip) {
        if (strpos($ip, '/') !== false) {
            list($ip, $mask) = explode('/', $ip, 2);
            if (!is_numeric($mask) || $mask < 0 || $mask > 32) {
                return false;
            }
        }
        return filter_var($ip, FILTER_VALIDATE_IP);
    }

    // Создание таблицы для логирования попыток входа
    public function create_login_attempts_table() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'security_login_attempts';

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
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
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    // Инициализация настроек защиты от брутфорс атак
    public function init_brute_force_protection() {
        // Настройки по умолчанию для защиты от брутфорс атак
        if (get_option('asb_brute_force_enabled') === false) {
            update_option('asb_brute_force_enabled', '1');
        }
        if (get_option('asb_max_attempts') === false) {
            update_option('asb_max_attempts', '5');
        }
        if (get_option('asb_time_window') === false) {
            update_option('asb_time_window', '15');
        }
        if (get_option('asb_block_duration') === false) {
            update_option('asb_block_duration', '60');
        }
        if (get_option('asb_auto_add_to_htaccess') === false) {
            update_option('asb_auto_add_to_htaccess', '1');
        }
        if (get_option('asb_email_notifications') === false) {
            update_option('asb_email_notifications', '1');
        }
        if (get_option('asb_whitelist_ips') === false) {
            update_option('asb_whitelist_ips', '');
        }
    }

    // Обработка неудачных попыток входа - ИСПРАВЛЕННАЯ ЛОГИКА БЛОКИРОВКИ
    public function handle_failed_login($username) {
        if (!get_option('asb_brute_force_enabled')) {
            return;
        }

        global $wpdb;

        $ip_address = $this->get_user_ip();

        // Проверяем, не находится ли IP в белом списке
        if ($this->is_ip_whitelisted($ip_address)) {
            return;
        }

        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $table_name = $wpdb->prefix . 'security_login_attempts';

        // Записываем попытку в базу данных
        $wpdb->insert(
            $table_name,
            [
                'ip_address' => $ip_address,
                'username' => sanitize_user($username),
                'user_agent' => sanitize_text_field($user_agent),
                'attempt_time' => current_time('mysql')
            ]
        );

        // Проверяем количество попыток за указанный период
        $max_attempts = intval(get_option('asb_max_attempts', 5));
        $time_window = intval(get_option('asb_time_window', 15));

        $attempts_count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table_name
             WHERE ip_address = %s
             AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)",
            $ip_address,
            $time_window
        ));

        // ИСПРАВЛЕНИЕ: Блокируем при достижении лимита (>= вместо >)
        if ($attempts_count >= $max_attempts) {
            $this->block_ip_address($ip_address, $username, $attempts_count);
        }
    }

    // Блокировка IP адреса
    private function block_ip_address($ip_address, $username, $attempts_count) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'security_login_attempts';

        // Отмечаем IP как заблокированный в базе данных
        $wpdb->update(
            $table_name,
            ['blocked' => 1],
            ['ip_address' => $ip_address]
        );

        // Добавляем IP в .htaccess если включена соответствующая опция
        if (get_option('asb_auto_add_to_htaccess')) {
            $this->add_ip_to_htaccess($ip_address);
            $block_method = 'htaccess + WordPress';
        } else {
            // Если длительность блокировки = 0, сразу добавляем в постоянный список
            if (get_option('asb_block_duration', 60) === 0) {
                $this->add_to_permanent_blocklist($ip_address);
                $block_method = 'постоянная блокировка WordPress';
            } else {
                $block_method = 'временная блокировка WordPress';

                // Проверяем частые блокировки для добавления в постоянный список
                $recent_blocks = $wpdb->get_var($wpdb->prepare(
                    "SELECT COUNT(*) FROM $table_name
                     WHERE ip_address = %s
                     AND blocked = 1
                     AND attempt_time > DATE_SUB(NOW(), INTERVAL 7 DAY)",
                    $ip_address
                ));

                if ($recent_blocks >= 2) {
                    $this->add_to_permanent_blocklist($ip_address);
                    $block_method = 'постоянная блокировка WordPress (частые нарушения)';
                }
            }
        }

        // Отправляем уведомление администратору
        if (get_option('asb_email_notifications')) {
            $this->send_block_notification($ip_address, $username, $attempts_count, $block_method);
        }

        // Логируем событие
        error_log("Security Blocker: IP $ip_address заблокирован после $attempts_count неудачных попыток входа (пользователь: $username, метод: $block_method)");
    }

    // Проверка, находится ли IP в белом списке
    private function is_ip_whitelisted($ip_address) {
        $whitelist = $this->get_whitelist_ips();

        foreach ($whitelist as $whitelist_entry) {
            // Проверяем точное совпадение IP
            if ($whitelist_entry === $ip_address) {
                return true;
            }

            // Проверяем CIDR диапазоны
            if (strpos($whitelist_entry, '/') !== false) {
                if ($this->ip_in_cidr($ip_address, $whitelist_entry)) {
                    return true;
                }
            }
        }

        return false;
    }

    // Добавление в постоянный список блокировки
    private function add_to_permanent_blocklist($ip_address) {
        $current_ips = get_option('asb_wp_blocked_ips', '');
        $ip_list = array_filter(explode("\n", $current_ips));

        // Проверяем, не заблокирован ли уже этот IP
        if (!in_array($ip_address, $ip_list)) {
            $ip_list[] = $ip_address;
            $new_ips = implode("\n", $ip_list);

            // Обновляем опцию с заблокированными IP
            update_option('asb_wp_blocked_ips', $new_ips);

            error_log("Security Blocker: IP $ip_address добавлен в постоянный список блокировки");
        }
    }

    // Добавление IP в .htaccess
    private function add_ip_to_htaccess($ip_address) {
        $current_ips = $this->get_current_ips();
        $ip_list = array_filter(explode("\n", $current_ips));

        // Проверяем, не заблокирован ли уже этот IP
        if (!in_array($ip_address, $ip_list)) {
            $ip_list[] = $ip_address;
            $new_ips = implode("\n", $ip_list);
            $this->update_ip_rules($new_ips);
        }
    }

    // Отправка уведомления администратору
    private function send_block_notification($ip_address, $username, $attempts_count, $block_method = 'htaccess + WordPress') {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        $site_url = get_site_url();

        $subject = "[$site_name] IP адрес заблокирован за брутфорс атаку";

        $message = "Внимание! На вашем сайте $site_name была обнаружена брутфорс атаку.\n\n";
        $message .= "Детали блокировки:\n";
        $message .= "Метод блокировки: $block_method\n";
        $message .= "IP адрес: $ip_address\n";
        $message .= "Попытки входа под именем: $username\n";
        $message .= "Количество попыток: $attempts_count\n";
        $message .= "Время блокировки: " . current_time('mysql') . "\n";
        $message .= "User-Agent: " . (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Неизвестно') . "\n\n";
        $message .= "IP адрес был автоматически добавлен в чёрный список.\n\n";
        $message .= "Для управления заблокированными IP перейдите в админ-панель:\n";
        $message .= admin_url('options-general.php?page=advanced-security-blocker') . "\n\n";
        $message .= "Сайт: $site_url";

        wp_mail($admin_email, $subject, $message);
    }

    // Проверка заблокированных IP при попытке входа
    public function check_blocked_ip($user, $password) {
        if (!get_option('asb_brute_force_enabled')) {
            return $user;
        }

        global $wpdb;

        $ip_address = $this->get_user_ip();

        // Проверяем, не находится ли IP в белом списке
        if ($this->is_ip_whitelisted($ip_address)) {
            return $user;
        }

        $table_name = $wpdb->prefix . 'security_login_attempts';
        $block_duration = intval(get_option('asb_block_duration', 60));

        // 1. Проверяем временные блокировки из базы данных
        $blocked_attempt = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table_name
             WHERE ip_address = %s
             AND blocked = 1
             AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)
             ORDER BY attempt_time DESC
             LIMIT 1",
            $ip_address,
            $block_duration
        ));

        if ($blocked_attempt) {
            $remaining_time = $block_duration - floor((time() - strtotime($blocked_attempt->attempt_time)) / 60);

            return new WP_Error(
                'ip_blocked_temporary',
                sprintf(
                    'Ваш IP адрес временно заблокирован за превышение лимита попыток входа. Попробуйте снова через %d минут.',
                    max(1, $remaining_time)
                )
            );
        }

        // 2. Проверяем блокировку на уровне WordPress
        if ($this->is_ip_blocked_at_wp_level($ip_address)) {
            return new WP_Error(
                'ip_blocked_permanent',
                'Ваш IP адрес заблокирован за множественные нарушения безопасности. Обратитесь к администратору сайта.'
            );
        }

        return $user;
    }

    // Проверка доступа IP для всех запросов
    public function check_ip_access() {
        // Не проверяем в админке и для AJAX запросов
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) {
            return;
        }

        if (!get_option('asb_brute_force_enabled')) {
            return;
        }

        $ip_address = $this->get_user_ip();

        // Проверяем, не находится ли IP в белом списке
        if ($this->is_ip_whitelisted($ip_address)) {
            return;
        }

        // Проверяем блокировку на уровне WordPress
        if ($this->is_ip_blocked_at_wp_level($ip_address)) {
            wp_die(
                'Доступ запрещен. Ваш IP адрес заблокирован за нарушения безопасности.',
                'Доступ запрещен',
                ['response' => 403]
            );
        }
    }

    // Проверка блокировки IP на уровне WordPress
    private function is_ip_blocked_at_wp_level($ip_address) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'security_login_attempts';
        $block_duration = intval(get_option('asb_block_duration', 60));

        // Если длительность блокировки = 0, проверяем только постоянные блокировки
        if ($block_duration === 0) {
            // Проверяем постоянные блокировки из опции
            $blocked_ips = get_option('asb_wp_blocked_ips', '');
            if (!empty($blocked_ips)) {
                $blocked_list = array_map('trim', explode("\n", $blocked_ips));

                foreach ($blocked_list as $blocked_entry) {
                    // Проверяем точное совпадение IP
                    if ($blocked_entry === $ip_address) {
                        return true;
                    }

                    // Проверяем CIDR диапазоны
                    if (strpos($blocked_entry, '/') !== false) {
                        if ($this->ip_in_cidr($ip_address, $blocked_entry)) {
                            return true;
                        }
                    }
                }
            }
        } else {
            // Проверяем временные блокировки из базы данных
            $blocked_attempt = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM $table_name
                 WHERE ip_address = %s
                 AND blocked = 1
                 AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)
                 ORDER BY attempt_time DESC
                 LIMIT 1",
                $ip_address,
                $block_duration
            ));

            if ($blocked_attempt) {
                return true;
            }

            // Проверяем постоянные блокировки из опции (для обратной совместимости)
            $blocked_ips = get_option('asb_wp_blocked_ips', '');
            if (!empty($blocked_ips)) {
                $blocked_list = array_map('trim', explode("\n", $blocked_ips));

                foreach ($blocked_list as $blocked_entry) {
                    // Проверяем точное совпадение IP
                    if ($blocked_entry === $ip_address) {
                        return true;
                    }

                    // Проверяем CIDR диапазоны
                    if (strpos($blocked_entry, '/') !== false) {
                        if ($this->ip_in_cidr($ip_address, $blocked_entry)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    // Проверка IP в CIDR диапазоне
    private function ip_in_cidr($ip, $cidr) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }

        list($subnet, $mask) = explode('/', $cidr);

        if (!filter_var($subnet, FILTER_VALIDATE_IP) || !is_numeric($mask)) {
            return false;
        }

        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask_long = -1 << (32 - (int)$mask);

        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }

    // Очистка старых записей из базы данных
    public function cleanup_old_attempts() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'security_login_attempts';
        $cleanup_days = 30; // Удаляем записи старше 30 дней

        $wpdb->query($wpdb->prepare(
            "DELETE FROM $table_name WHERE attempt_time < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $cleanup_days
        ));
    }

    // Получение статистики попыток входа
    private function get_login_attempts_stats() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'security_login_attempts';

        // Общее количество попыток за последние 24 часа
        $total_attempts = $wpdb->get_var(
            "SELECT COUNT(*) FROM $table_name
             WHERE attempt_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );

        // Количество заблокированных IP за последние 24 часа
        $blocked_ips = $wpdb->get_var(
            "SELECT COUNT(DISTINCT ip_address) FROM $table_name
             WHERE blocked = 1
             AND attempt_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );

        // Топ IP по количеству попыток за последние 24 часа
        $top_ips = $wpdb->get_results(
            "SELECT ip_address, COUNT(*) as attempts, MAX(blocked) as is_blocked
             FROM $table_name
             WHERE attempt_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)
             GROUP BY ip_address
             ORDER BY attempts DESC
             LIMIT 10"
        );

        // Последние попытки входа
        $recent_attempts = $wpdb->get_results(
            "SELECT ip_address, username, attempt_time, blocked, user_agent
             FROM $table_name
             ORDER BY attempt_time DESC
             LIMIT 20"
        );

        return [
            'total_attempts' => intval($total_attempts),
            'blocked_ips' => intval($blocked_ips),
            'top_ips' => $top_ips,
            'recent_attempts' => $recent_attempts
        ];
    }

    public function init_default_settings() {
        // Настройки по умолчанию для опасных файлов
        if (!get_option('asb_dangerous_files')) {
            $default_files = ".htaccess\n.htpasswd\nwp-config.php\nreadme.html\nlicense.txt\nwp-config-sample.php\n.DS_Store\nThumbs.db\n*.sql\n*.log\n*.bak\n*.tmp\n*.swp\n*.old\n*.orig\n*.save\nerror_log\ndebug.log";
            update_option('asb_dangerous_files', $default_files);
        }

        // Настройки по умолчанию для ботов
        if (!get_option('asb_blocked_bots')) {
            $default_bots = "360Spider|404checker|80legs|Abonti|Aboundex|AhrefsBot|Alexibot|Applebot|Arachni|ASPSeek|Asterias|BackDoorBot|BackStreet|BackWeb|Badass|Bandit|Baiduspider|BatchFTP|Bigfoot|BotALot|Buddy|BuiltBotTough|Bullseye|BunnySlippers|CheeseBot|CherryPicker|ChinaClaw|Collector|Copier|CopyRightCheck|cosmos|Crescent|Custo|CyberSpyder|DISCo|DIIbot|DittoSpyder|Download|Downloader|Dumbot|EasouSpider|eCatch|EirGrabber|EmailCollector|EmailSiphon|EmailWolf|Express|Extractor|EyeNetIE|FlashGet|GetRight|GetWeb|Grafula|HMView|HTTrack|InterGET|JetCar|larbin|LeechFTP|Mister|Navroad|NearSite|NetAnts|NetSpider|NetZIP|Nutch|Octopus|PageGrabber|pavuk|pcBrowser|PeoplePal|planetwork|psbot|purebot|pycurl|RealDownload|ReGet|Rippers|SiteSnagger|SmartDownload|SuperBot|SuperHTTP|Surfbot|tAkeOut|VoidEYE|WebAuto|WebBandit|WebCopier|WebFetch|WebLeacher|WebReaper|WebSauger|WebStripper|WebWhacker|WebZIP|Wget|Widow|WWWOFFLE|Xenu|Zeus";
            update_option('asb_blocked_bots', $default_bots);
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

    public function enqueue_scripts($hook) {
        if ($hook !== 'settings_page_advanced-security-blocker') return;

        // Подключаем jQuery если еще не подключен
        wp_enqueue_script('jquery');

        // Локализация для AJAX
        wp_localize_script('jquery', 'asb_ajax', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('asb_ajax_nonce')
        ]);
    }

    // ASN кеширование и API методы
    private function get_asn_cache_file($asn) {
        return $this->cache_dir . 'asn_' . $asn . '.json';
    }

    private function get_cached_asn_ranges($asn) {
        $cache_file = $this->get_asn_cache_file($asn);

        if (file_exists($cache_file)) {
            $cache_data = json_decode(file_get_contents($cache_file), true);

            // Проверяем, не устарел ли кеш (24 часа)
            if (isset($cache_data['timestamp']) &&
                (time() - $cache_data['timestamp']) < 86400) {

                $this->log[] = "ASN AS{$asn}: использованы кешированные данные";
                return $cache_data['ranges'];
            }
        }

        return false;
    }

    private function cache_asn_ranges($asn, $ranges) {
        $cache_file = $this->get_asn_cache_file($asn);
        $cache_data = [
            'timestamp' => time(),
            'asn' => $asn,
            'ranges' => $ranges
        ];

        file_put_contents($cache_file, json_encode($cache_data));
        $this->log[] = "ASN AS{$asn}: данные кешированы";
    }

    private function clear_asn_cache() {
        $cache_files = glob($this->cache_dir . 'asn_*.json');
        $cleared = 0;

        foreach ($cache_files as $file) {
            if (unlink($file)) {
                $cleared++;
            }
        }

        $this->log[] = "Очищен кеш данных ASN: {$cleared}";
        return $cleared;
    }

    // Получение IP диапазонов по ASN
    private function get_asn_ip_ranges($asn) {
        // Сначала проверяем кеш
        $cached_ranges = $this->get_cached_asn_ranges($asn);
        if ($cached_ranges !== false) {
            return $cached_ranges;
        }

        $ip_ranges = [];

        // Убираем префикс AS если есть
        $asn = str_replace(['AS', 'as'], '', $asn);

        if (!is_numeric($asn)) {
            return false;
        }

        // Используем несколько источников для получения информации
        $sources = [
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{$asn}",
            "https://api.hackertarget.com/aslookup/?q=AS{$asn}"
        ];

        foreach ($sources as $url) {
            $response = $this->fetch_url($url);
            if ($response) {
                if (strpos($url, 'ripe.net') !== false) {
                    $data = json_decode($response, true);
                    if (isset($data['data']['prefixes'])) {
                        foreach ($data['data']['prefixes'] as $prefix) {
                            if (isset($prefix['prefix'])) {
                                $ip_ranges[] = $prefix['prefix'];
                            }
                        }
                    }
                } else if (strpos($url, 'hackertarget.com') !== false) {
                    $lines = explode("\n", $response);
                    foreach ($lines as $line) {
                        if (preg_match('/(\d+\.\d+\.\d+\.\d+\/\d+)/', $line, $matches)) {
                            $ip_ranges[] = $matches[1];
                        }
                    }
                }

                if (!empty($ip_ranges)) {
                    break; // Если получили данные, то больше источники не проверяем
                }
            }
        }

        $unique_ranges = array_unique($ip_ranges);

        // Кешируем результат
        if (!empty($unique_ranges)) {
            $this->cache_asn_ranges($asn, $unique_ranges);
        }

        return $unique_ranges;
    }

    // Функция HTTP запроса
    private function fetch_url($url, $timeout = 10) {
        // Используем cURL если доступен
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_USERAGENT, 'WordPress Security Plugin');
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

            $response = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($http_code === 200) {
                return $response;
            }
        }

        // Fallback на file_get_contents
        if (ini_get('allow_url_fopen')) {
            $context = stream_context_create([
                'http' => [
                    'timeout' => $timeout,
                    'user_agent' => 'WordPress Security Plugin'
                ]
            ]);

            return @file_get_contents($url, false, $context);
        }

        return false;
    }

    private function output_admin_styles() {
        ?>
        <style>
        .security-tabs {
            margin: 20px 0;
        }
        .security-tab-nav {
            border-bottom: 1px solid #ccc;
            margin-bottom: 20px;
            background: #f9f9f9;
            padding: 0;
        }
        .security-tab-nav button {
            display: inline-block;
            padding: 12px 20px;
            border: none;
            background: #f1f1f1;
            color: #333;
            cursor: pointer;
            margin-right: 2px;
            font-size: 14px;
            border-top: 3px solid transparent;
        }
        .security-tab-nav button:hover {
            background: #e8e8e8;
        }
        .security-tab-nav button.active {
            background: #fff;
            border-top: 3px solid #0073aa;
            color: #0073aa;
            font-weight: 600;
        }
        .security-tab-content {
            display: none;
            padding: 20px 0;
        }
        .security-tab-content.active {
            display: block;
        }
        .ip-blocker-textarea-wrapper {
            position: relative;
            width: 100%;
            max-width: 800px;
            display: block;
            clear: both;
        }
        .ip-blocker-line-numbers {
            position: absolute;
            left: 0;
            top: 1px;
            bottom: 1px;
            width: 45px;
            overflow: hidden;
            background-color: #f5f5f5;
            border-right: 1px solid #ddd;
            text-align: right;
            padding: 11px 8px 11px 5px;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
            line-height: 1.4;
            color: #666;
            user-select: none;
            pointer-events: none;
            z-index: 1;
            box-sizing: border-box;
        }
        .ip-blocker-textarea-wrapper textarea {
            padding: 10px 10px 10px 55px !important;
            box-sizing: border-box;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
            line-height: 1.4;
            width: 100%;
            resize: vertical;
            border: 1px solid #ddd;
            border-radius: 3px;
            background-color: #fff;
        }
        .simple-textarea {
            width: 100%;
            max-width: 800px;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
            line-height: 1.4;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        .ip-blocker-description {
            margin-top: 10px !important;
            margin-bottom: 0 !important;
            clear: both;
            display: block;
            width: 100%;
            }
        .operation-log {
            background: #f8f8f8;
            border-left: 4px solid #0073aa;
            padding: 10px 15px;
            margin: 15px 0;
        }
        .operation-log ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .log-entry {
            margin: 3px 0;
        }
        .security-warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-left: 4px solid #f39c12;
            padding: 10px 15px;
            margin: 15px 0;
        }
        .security-info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-left: 4px solid #17a2b8;
            padding: 10px 15px;
            margin: 15px 0;
        }
        .card {
            background: #fff;
            border: 1px solid #ccd0d4;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
        }
        .card h3 {
            margin-top: 0;
        }
        .card ul {
            margin: 10px 0;
        }
        .card li {
            margin: 5px 0;
        }
        .asn-info {
            background: #e8f4fd;
            border: 1px solid #b8daff;
            border-left: 4px solid #007cba;
            padding: 10px 15px;
            margin: 15px 0;
        }
        .protection-options {
            background: #f0f8ff;
            border: 1px solid #b8daff;
            border-left: 4px solid #0073aa;
            padding: 15px;
            margin: 15px 0;
        }
        .protection-checkbox {
            margin: 10px 0;
        }
        .protection-checkbox input[type="checkbox"] {
            margin-right: 8px;
        }
        .protection-checkbox label {
            font-weight: 500;
        }
        .brute-force-info {
            background: #fff2cc;
            border: 1px solid #ffd700;
            border-left: 4px solid #ff8c00;
            padding: 10px 15px;
            margin: 15px 0;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #0073aa;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        .attempts-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .attempts-table th,
        .attempts-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .attempts-table th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        .attempts-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .blocked-ip {
            color: #d63384;
            font-weight: bold;
        }
        .normal-ip {
            color: #198754;
        }
        .refresh-button {
            background: #0073aa;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            margin-left: 10px;
        }
        .refresh-button:hover {
            background: #005a87;
        }
        .auto-refresh-controls {
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
        }
        .loading-spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid #f3f3f3;
            border-top: 2px solid #0073aa;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-left: 10px;
            vertical-align: middle;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .add-my-ip-btn {
            margin-left: 10px !important;
        }
        .view-history-btn {
            background: #6c757d;
            color: white;
            border: none;
            padding: 3px 8px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }
        .view-history-btn:hover {
            background: #5a6268;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
        }
        .modal-content {
            background-color: #fefefe;
            margin: 10% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 80%;
            max-width: 800px;
            border-radius: 5px;
        }
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        .close:hover {
            color: black;
        }
        .history-table {
            width: 100%;
            border-collapse: collapse;
        }
        .history-table th,
        .history-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .history-table th {
            background-color: #f2f2f2;
        }
        .tablenav {
            height: 30px;
            margin: 10px 0;
        }
        .tablenav .actions {
            float: left;
        }
        .tablenav .pagination {
            float: right;
        }
        .tablenav .displaying-num {
            margin-right: 10px;
        }
        </style>
        <?php
    }

    public function create_backup_dir() {
        if (!is_dir($this->backup_dir)) {
            wp_mkdir_p($this->backup_dir);
            // Создаем .htaccess для защиты папки с бекапами
            $htaccess_content = "Order deny,allow\nDeny from all\n";
            file_put_contents($this->backup_dir . '.htaccess', $htaccess_content);
        }

        if (!is_dir($this->cache_dir)) {
            wp_mkdir_p($this->cache_dir);
            // Создаем .htaccess для защиты папки с кешем
            $htaccess_content = "Order deny,allow\nDeny from all\n";
            file_put_contents($this->cache_dir . '.htaccess', $htaccess_content);
        }
    }

    public function admin_menu() {
        add_options_page(
            'Продвинутая безопасность',
            'Безопасность',
            'manage_options',
            'advanced-security-blocker',
            [$this, 'settings_page']
        );
    }

    public function settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Проверяем и создаем таблицы при необходимости
        $this->check_and_create_tables();

        $error = $success = '';
        $operation_log = '';

        // Обработчики уведомлений
        if (isset($_GET['backup_created'])) {
            $success = 'Резервная копия .htaccess успешно создана!';
        }

        if (isset($_GET['cache_cleared'])) {
            $success = 'Кеш успешно очищен!';
        }

        if (isset($_GET['unblocked'])) {
            $success = 'IP адрес успешно разблокирован!';
        }

        if (isset($_GET['manual_block'])) {
            $success = 'IP адрес успешно добавлен в черный список!';
        }

        if (isset($_GET['whitelist_added'])) {
            $success = 'IP адрес успешно добавлен в белый список!';
        }

        if (isset($_GET['whitelist_removed'])) {
            $success = 'IP адрес успешно удален из белого списка!';
        }

        if (isset($_GET['error'])) {
            if ($_GET['error'] === 'invalid_ip') {
                $error = 'Неверный формат IP адреса или CIDR диапазона!';
            }
        }

        // Обработка форм
        if (isset($_POST['submit_ip_blocker'])) {
            check_admin_referer('security_blocker_update');
            $ips = isset($_POST['ip_addresses']) ? sanitize_textarea_field($_POST['ip_addresses']) : '';
            $result = $this->update_ip_rules($ips);
            if ($result === true) {
                $this->cache_handler->clear_all_caches();
                $success = 'IP правила успешно обновлены!';
            } else {
                $error = 'Ошибка IP правил: ' . $result;
            }
        }

        if (isset($_POST['submit_login_protection'])) {
            check_admin_referer('security_blocker_update');
            $whitelist_ips = isset($_POST['login_whitelist_ips']) ? sanitize_textarea_field($_POST['login_whitelist_ips']) : '';

            // ИСПРАВЛЕНИЕ: Правильная обработка чекбоксов
            $protect_wp_login = isset($_POST['protect_wp_login']) && $_POST['protect_wp_login'] === '1';
            $protect_xmlrpc = isset($_POST['protect_xmlrpc']) && $_POST['protect_xmlrpc'] === '1';

            $result = $this->update_login_protection($whitelist_ips, $protect_wp_login, $protect_xmlrpc);
            if ($result === true) {
                $this->cache_handler->clear_all_caches();
                $success = 'Защита wp-login.php и xmlrpc.php успешно обновлена!';
            } else {
                $error = 'Ошибка защиты входа: ' . $result;
            }
        }

        if (isset($_POST['submit_file_protection'])) {
            check_admin_referer('security_blocker_update');
            $dangerous_files = isset($_POST['dangerous_files']) ? sanitize_textarea_field($_POST['dangerous_files']) : '';
            update_option('asb_dangerous_files', $dangerous_files);
            $result = $this->update_file_protection($dangerous_files);
            if ($result === true) {
                $this->cache_handler->clear_all_caches();
                $success = 'Защита от опасных файлов успешно обновлена!';
            } else {
                $error = 'Ошибка защиты файлов: ' . $result;
            }
        }

        if (isset($_POST['submit_bot_protection'])) {
            check_admin_referer('security_blocker_update');
            $blocked_bots = isset($_POST['blocked_bots']) ? sanitize_textarea_field($_POST['blocked_bots']) : '';
            update_option('asb_blocked_bots', $blocked_bots);
            $result = $this->update_bot_protection($blocked_bots);
            if ($result === true) {
                $this->cache_handler->clear_all_caches();
                $success = 'Защита от ботов успешно обновлена!';
            } else {
                $error = 'Ошибка защиты от ботов: ' . $result;
            }
        }

        // Обработка настроек защиты от брутфорс атак
        if (isset($_POST['submit_brute_force_protection'])) {
            check_admin_referer('security_blocker_update');

            // Правильная обработка чекбоксов с проверкой значений
            update_option('asb_brute_force_enabled', (isset($_POST['brute_force_enabled']) && $_POST['brute_force_enabled'] === '1') ? '1' : '0');
            update_option('asb_max_attempts', max(1, intval($_POST['max_attempts'])));
            update_option('asb_time_window', max(1, intval($_POST['time_window'])));
            $block_duration = max(0, intval($_POST['block_duration']));
            update_option('asb_block_duration', $block_duration);
            update_option('asb_auto_add_to_htaccess', (isset($_POST['auto_add_to_htaccess']) && $_POST['auto_add_to_htaccess'] === '1') ? '1' : '0');
            update_option('asb_email_notifications', (isset($_POST['email_notifications']) && $_POST['email_notifications'] === '1') ? '1' : '0');

            $this->cache_handler->clear_all_caches();
            $success = 'Настройки защиты от брутфорс атак успешно обновлены!';
        }

        // Очистка старых записей
        if (isset($_POST['cleanup_attempts'])) {
            check_admin_referer('security_blocker_update');
            $this->cleanup_old_attempts();
            $this->cache_handler->clear_all_caches();
            $success = 'Старые записи попыток входа успешно очищены!';
        }

        // Формируем лог операций
        if (!empty($this->log)) {
            $operation_log = '<div class="operation-log"><strong>Журнал операций:</strong><ul>';
            foreach ($this->log as $entry) {
                $operation_log .= '<li class="log-entry">' . esc_html($entry) . '</li>';
            }
            $operation_log .= '</ul></div>';
        }

        // Получаем текущие данные
        $current_ips = $this->get_current_ips();
        $current_whitelist = $this->get_current_login_whitelist();
        $current_files = get_option('asb_dangerous_files', '');
        $current_bots = get_option('asb_blocked_bots', '');
        $current_user_ip = $this->get_user_ip();

        // Получаем текущие настройки защиты
        $current_protection = $this->get_current_protection_settings();

        // Получаем статистику попыток входа
        $login_stats = $this->get_login_attempts_stats();

        // Получаем историю разблокировок
        $unblock_history = $this->get_unblock_history(20);

        // Получаем белый список IP
        $whitelist_ips = $this->get_whitelist_ips();

        // Получаем параметры пагинации и поиска для вкладки управления блокировками
        $per_page = 20;
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $search = isset($_GET['s']) ? sanitize_text_field($_GET['s']) : '';

        // Получаем список всех заблокированных IP с пагинацией и поиском
        $blocked_ips_data = $this->get_all_blocked_ips($search, $current_page, $per_page);
        $blocks_to_show = $blocked_ips_data['blocks'];
        $total_blocks = $blocked_ips_data['total'];
        $total_pages = $blocked_ips_data['pages'];
        ?>
        <div class="wrap">
            <h1>Продвинутая система безопасности</h1>

            <?php if ($error) : ?>
                <div class="notice notice-error"><p><?php echo esc_html($error); ?></p></div>
            <?php endif; ?>

            <?php if ($success) : ?>
                <div class="notice notice-success"><p><?php echo esc_html($success); ?></p></div>
                <?php echo $operation_log; ?>
            <?php endif; ?>

            <?php $this->output_admin_styles(); ?>

            <div class="security-tabs">
    <div class="security-tab-nav">
        <button type="button" data-tab="tab-ip-blocking" class="active">Блокировка IP</button>
        <button type="button" data-tab="tab-login-protection">Защита wp-login.php и xmlrpc.php</button>
        <button type="button" data-tab="tab-file-protection">Блокировка файлов</button>
        <button type="button" data-tab="tab-bot-protection">Защита от ботов</button>
        <button type="button" data-tab="tab-brute-force">Защита от брутфорс атак</button>
        <button type="button" data-tab="tab-manage-blocks">Управление блокировками</button>
        <button type="button" data-tab="tab-whitelist">Белый список</button>
        <button type="button" data-tab="tab-status">Статус системы</button>
    </div>

    <!-- Вкладка блокировки IP -->
    <div id="tab-ip-blocking" class="security-tab-content active" style="display: block;">
        <h2>Блокировка IP-адресов</h2>
        <div class="asn-info">
            <strong>Новая функция!</strong> Теперь поддерживается блокировка по ASN (Autonomous System Number).
            Просто укажите номер ASN в формате <code>AS15169</code> или <code>15169</code>
        </div>
        <form method="post">
            <?php wp_nonce_field('security_blocker_update'); ?>
            <table class="form-table">
                <tr>
                    <th><label for="ip_addresses">Заблокированные IP:</label></th>
                    <td>
                        <div class="ip-blocker-textarea-wrapper">
                            <div class="ip-blocker-line-numbers"></div>
                            <textarea name="ip_addresses" id="ip_addresses" rows="15" cols="50"
                                class="large-text code" placeholder="192.168.0.1&#10;192.168.1.0/24&#10;AS15169"><?php
                                echo esc_textarea($current_ips);
                            ?></textarea>
                        </div>
                        <p class="description ip-blocker-description">
                            По одной записи на строку. Поддерживаемые форматы:<br>
                            • Отдельные IP: <code>192.168.1.100</code><br>
                            • CIDR диапазоны: <code>192.168.1.0/24</code><br>
                            • ASN (автономные системы): <code>AS15169</code> или <code>15169</code><br>
                            <em>ASN автоматически преобразуются в списки IP диапазонов</em><br>
                            <strong>Примечание:</strong> IP адреса также могут добавляться автоматически при брутфорс атаках
                        </p>
                    </td>
                </tr>
            </table>
            <p>
                <button type="submit" name="submit_ip_blocker" class="button button-primary">
                    Обновить блокировку IP
                </button>
            </p>
        </form>
    </div>

    <!-- Вкладка защиты wp-login.php и xmlrpc.php -->
    <<div id="tab-login-protection" class="security-tab-content">
    <h2>Ограничение доступа к wp-login.php и xmlrpc.php</h2>
    <div class="security-warning">
        <strong>Внимание!</strong> Убедитесь, что ваш IP-адрес включен в белый список, чтобы вы не потеряли доступ к админ-панели!
        <br>Ваш текущий IP: <strong><?php echo esc_html($current_user_ip); ?></strong>
    </div>
    <div class="asn-info">
        <strong>Поддержка ASN!</strong> Можно добавлять целые сети провайдеров, например <code>AS15169</code> для Google.
    </div>

    <form method="post">
        <?php wp_nonce_field('security_blocker_update'); ?>
        <!-- Скрытые поля для правильной обработки чекбоксов -->
        <input type="hidden" name="protect_wp_login" value="0">
        <input type="hidden" name="protect_xmlrpc" value="0">

        <div class="protection-options">
            <h3>Выберите файлы для защиты:</h3>
            <div class="protection-checkbox">
                <input type="checkbox" id="protect_wp_login" name="protect_wp_login" value="1"
                    <?php checked($current_protection['wp_login']); ?>>
                <label for="protect_wp_login">
                    <strong>wp-login.php</strong> - защита страницы входа в админ-панель
                </label>
            </div>
            <div class="protection-checkbox">
                <input type="checkbox" id="protect_xmlrpc" name="protect_xmlrpc" value="1"
                    <?php checked($current_protection['xmlrpc']); ?>>
                    <label for="protect_xmlrpc">
        <strong>xmlrpc.php</strong> - защита XML-RPC интерфейса (используется для мобильных приложений)
    </label>
    </div>
    <p class="description">
        <strong>xmlrpc.php</strong> может использоваться для атак методом перебора паролей.
        Рекомендуется заблокировать его, если вы не используете мобильные приложения WordPress или внешние сервисы.
    </p>
    </div>

    <table class="form-table">
        <tr>
            <th><label for="login_whitelist_ips">Разрешенные IP:</label></th>
            <td>
                <div class="ip-blocker-textarea-wrapper">
                    <div class="ip-blocker-line-numbers"></div>
                    <textarea name="login_whitelist_ips" id="login_whitelist_ips" rows="10" cols="50"
                        class="large-text code" placeholder="<?php echo esc_attr($current_user_ip); ?>&#10;192.168.1.0/24&#10;AS15169"><?php
                        echo esc_textarea($current_whitelist);
                    ?></textarea>
                </div>
                <p class="description ip-blocker-description">
                    По одной записи на строку. Поддерживаемые форматы:<br>
                    • Отдельные IP: <code>192.168.1.100</code><br>
                    • CIDR диапазоны: <code>192.168.1.0/24</code><br>
                    • ASN (автономные системы): <code>AS15169</code> или <code>15169</code><br>
                    • Маска подсети: <code>192.168.1.0 255.255.255.0</code><br>
                    • Частичные IP: <code>192.168.1</code><br>
                    <em>ASN автоматически преобразуются в списки разрешенных диапазонов</em>
                </p>
            </td>
        </tr>
    </table>
    <p>
        <button type="submit" name="submit_login_protection" class="button button-primary">
            Обновить защиту
        </button>
        <button type="button" class="button add-my-ip-btn" onclick="addCurrentIP();">
            Добавить мой IP
        </button>
    </p>
    </form>
    </div>

    <!-- Вкладка блокировки файлов -->
    <div id="tab-file-protection" class="security-tab-content">
        <h2>Блокировка опасных файлов</h2>
        <div class="security-info">
            Эта функция блокирует доступ к потенциально опасным файлам. Можно использовать маски файлов (например, *.log для всех .log файлов).
        </div>
        <form method="post">
            <?php wp_nonce_field('security_blocker_update'); ?>
            <table class="form-table">
                <tr>
                    <th><label for="dangerous_files">Заблокированные файлов:</label></th>
                    <td>
                        <textarea name="dangerous_files" id="dangerous_files" rows="15" cols="80"
                            class="simple-textarea" placeholder=".htaccess"><?php
                            echo esc_textarea($current_files);
                        ?></textarea>
                        <p class="description">По одному файлу/маске на строку. Поддерживаются маски с * (например, *.log, *.bak)</p>
                    </td>
                </tr>
            </table>
            <p>
                <button type="submit" name="submit_file_protection" class="button button-primary">
                    Обновить защиту файлов
                </button>
            </p>
        </form>
    </div>

    <!-- Вкладка защиты от ботов -->
    <div id="tab-bot-protection" class="security-tab-content">
        <h2>Блокировка ботов и нежелательных User-Agent</h2>
        <div class="security-info">
            Список User-Agent ботов, разделенных символом "|". Частичные и точные User-Agent будут заблокированы.
        </div>
        <form method="post">
            <?php wp_nonce_field('security_blocker_update'); ?>
            <table class="form-table">
                <tr>
                    <th><label for="blocked_bots">Заблокированные User-Agent:</label></th>
                    <td>
                        <textarea name="blocked_bots" id="blocked_bots" rows="10" cols="80"
                            class="simple-textarea" placeholder="BadBot|SpamBot|Crawler"><?php
                            echo esc_textarea($current_bots);
                        ?></textarea>
                        <p class="description">User-Agent строки, разделенные символом "|". Поддерживаются частичные совпадения.</p>
                    </td>
                </tr>
            </table>
            <p>
                <button type="submit" name="submit_bot_protection" class="button button-primary">
                    Обновить защиту от ботов
                </button>
            </p>
        </form>
    </div>

    <!-- Вкладка защиты от брутфорс атак -->
    <div id="tab-brute-force" class="security-tab-content">
        <h2>Защита от брутфорс атак</h2>
        <div class="brute-force-info">
            <strong>Автоматическая защита!</strong> Система автоматически блокирует IP адреса при превышении лимита неудачных попыток входа.
        </div>

        <!-- Статистика -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="stat-total-attempts"><?php echo $login_stats['total_attempts']; ?></div>
                <div class="stat-label">Попыток входа за 24 часа</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="stat-blocked-ips"><?php echo $login_stats['blocked_ips']; ?></div>
                <div class="stat-label">Заблокированных IP за 24 часа</div>
            </div>
        </div>

        <!-- Настройки -->
        <form method="post">
            <?php wp_nonce_field('security_blocker_update'); ?>
            <!-- Скрытые поля для правильной обработки чекбоксов -->
            <input type="hidden" name="brute_force_enabled" value="0">
            <input type="hidden" name="auto_add_to_htaccess" value="0">
            <input type="hidden" name="email_notifications" value="0">

            <table class="form-table">
                <tr>
                    <th><label for="brute_force_enabled">Включить защиту:</label></th>
                    <td>
                        <input type="checkbox" id="brute_force_enabled" name="brute_force_enabled" value="1"
                            <?php checked(get_option('asb_brute_force_enabled')); ?>>
                        <label for="brute_force_enabled">Автоматически блокировать IP при брутфорс атаках</label>
                    </td>
                </tr>
                <tr>
                    <th><label for="max_attempts">Максимум попыток:</label></th>
                    <td>
                        <input type="number" id="max_attempts" name="max_attempts" min="1" max="50"
                            value="<?php echo esc_attr(get_option('asb_max_attempts', 5)); ?>">
                        <p class="description">Количество неудачных попыток входа перед блокировкой</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="time_window">Временное окно (минуты):</label></th>
                    <td>
                        <input type="number" id="time_window" name="time_window" min="1" max="1440"
                            value="<?php echo esc_attr(get_option('asb_time_window', 15)); ?>">
                        <p class="description">Период времени для подсчёта попыток входа</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="block_duration">Длительность блокировки (минуты):</label></th>
                    <td>
                        <input type="number" id="block_duration" name="block_duration" min="0" max="10080"
                            value="<?php echo esc_attr(get_option('asb_block_duration', 60)); ?>">
                        <p class="description">0 = постоянная блокировка (требует ручного разблокирования)</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="auto_add_to_htaccess">Добавлять в .htaccess:</label></th>
                    <td>
                        <input type="checkbox" id="auto_add_to_htaccess" name="auto_add_to_htaccess" value="1"
                            <?php checked(get_option('asb_auto_add_to_htaccess')); ?>>
                        <label for="auto_add_to_htaccess">Автоматически добавлять заблокированные IP в .htaccess</label>
                        <p class="description">Если отключено, блокировка будет работать только на уровне WordPress</p>
                    </td>
                </tr>
                <tr>
                    <th><label for="email_notifications">Email уведомления:</label></th>
                    <td>
                        <input type="checkbox" id="email_notifications" name="email_notifications" value="1"
                            <?php checked(get_option('asb_email_notifications')); ?>>
                        <label for="email_notifications">Отправлять уведомления администратору о блокировках</label>
                    </td>
                </tr>
            </table>
            <p>
                <button type="submit" name="submit_brute_force_protection" class="button button-primary">
                    Сохранить настройки
                </button>
                <button type="submit" name="cleanup_attempts" class="button"
                    onclick="return confirm('Удалить все старые записи попыток входа?');">
                    Очистить старые записи
                </button>
            </p>
        </form>

        <!-- Контролы обновления -->
        <div class="auto-refresh-controls">
            <label>
                <input type="checkbox" id="auto-refresh-stats" checked>
                Автоматическое обновление каждые 30 секунд
            </label>
            <button id="manual-refresh-stats" class="refresh-button">Обновить сейчас</button>
            <span id="last-updated">Последнее обновление: <?php echo date('H:i:s'); ?></span>
        </div>

        <!-- Топ IP по попыткам -->
        <div id="top-ips-container">
            <h3>Топ IP адресов по попыток входа (24 часа)</h3>
            <table class="attempts-table">
                <thead>
                    <tr>
                        <th>IP адрес</th>
                        <th>Попыток</th>
                        <th>Статус</th>
                    </tr>
                </thead>
                <tbody id="top-ips-body">
                    <?php foreach ($login_stats['top_ips'] as $ip_stat) : ?>
                        <tr>
                            <td><?php echo esc_html($ip_stat->ip_address); ?></td>
                            <td><?php echo esc_html($ip_stat->attempts); ?></td>
                            <td>
                                <?php if ($ip_stat->is_blocked) : ?>
                                    <span class="blocked-ip">Заблокирован</span>
                                <?php else : ?>
                                    <span class="normal-ip">Активен</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <!-- Последние попытки входа -->
        <div id="recent-attempts-container">
            <h3>Последние попытки входа</h3>
            <table class="attempts-table">
                <thead>
                    <tr>
                        <th>Время</th>
                        <th>IP адрес</th>
                        <th>Пользователь</th>
                        <th>Статус</th>
                        <th>User-Agent</th>
                    </tr>
                </thead>
                <tbody id="recent-attempts-body">
                    <?php foreach ($login_stats['recent_attempts'] as $attempt) : ?>
                        <tr>
                            <td><?php echo esc_html(date('d.m.Y H:i:s', strtotime($attempt->attempt_time))); ?></td>
                            <td><?php echo esc_html($attempt->ip_address); ?></td>
                            <td><?php echo esc_html($attempt->username); ?></td>
                            <td>
                                <?php if ($attempt->blocked) : ?>
                                    <span class="blocked-ip">Заблокирован</span>
                                <?php else : ?>
                                    <span class="normal-ip">Неудачная попытка</span>
                                <?php endif; ?>
                            </td>
                            <td title="<?php echo esc_attr($attempt->user_agent); ?>">
                                <?php echo esc_html(substr($attempt->user_agent, 0, 50)) . (strlen($attempt->user_agent) > 50 ? '...' : ''); ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Вкладка управления блокировками -->
    <div id="tab-manage-blocks" class="security-tab-content">
        <h2>Управление заблокированными IP адресами</h2>

        <div class="security-info">
            На этой странице вы можете управлять всеми заблокированными IP адресами.
            Вы можете разблокировать IP адреса, которые были заблокированы автоматически или вручную.
        </div>

        <!-- Поиск по IP -->
        <div class="card">
            <h3>Поиск по IP адресам</h3>
            <form method="get">
                <input type="hidden" name="page" value="advanced-security-blocker">
                <input type="hidden" name="tab" value="manage-blocks">
                <table class="form-table">
                    <tr>
                        <th><label for="ip-search">Поиск IP:</label></th>
                        <td>
                            <input type="text" id="ip-search" name="s" value="<?php echo esc_attr($search); ?>"
                                class="regular-text" placeholder="Введите IP адрес для поиска">
                            <button type="submit" class="button">Поиск</button>
                            <?php if (!empty($search)) : ?>
                                <a href="<?php echo admin_url('options-general.php?page=advanced-security-blocker&tab=manage-blocks'); ?>" class="button">Сбросить</a>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
            </form>
        </div>

        <div class="card">
            <h3>Заблокированные IP адреса</h3>

            <?php if (empty($blocks_to_show)) : ?>
                <p>Нет заблокированных IP адресов.</p>
            <?php else : ?>
                <!-- Пагинация -->
                <div class="tablenav top">
                    <div class="tablenav-pages">
                        <span class="displaying-num"><?php echo $total_blocks; ?> элементов</span>
                        <?php if ($total_pages > 1) : ?>
                            <span class="pagination-links">
                                <?php if ($current_page > 1) : ?>
                                    <a class="first-page button" href="<?php echo add_query_arg('paged', 1); ?>">«</a>
                                    <a class="prev-page button" href="<?php echo add_query_arg('paged', $current_page - 1); ?>">‹</a>
                                <?php endif; ?>

                                <span class="paging-input">
                                    <span class="current-page"><?php echo $current_page; ?></span> из
                                    <span class="total-pages"><?php echo $total_pages; ?></span>
                                </span>

                                <?php if ($current_page < $total_pages) : ?>
                                    <a class="next-page button" href="<?php echo add_query_arg('paged', $current_page + 1); ?>">›</a>
                                    <a class="last-page button" href="<?php echo add_query_arg('paged', $total_pages); ?>">»</a>
                                <?php endif; ?>
                            </span>
                        <?php endif; ?>
                    </div>
                </div>

                <table class="attempts-table">
                    <thead>
                        <tr>
                            <th>IP адрес</th>
                            <th>Тип блокировки</th>
                            <th>Последняя попытка</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($blocks_to_show as $block) : ?>
                            <tr>
                                <td><?php echo esc_html($block['ip']); ?></td>
                                <td>
                                    <?php
                                    $type_labels = [
                                        'temporary' => '<span style="color: orange;">Временная</span>',
                                        'permanent' => '<span style="color: red;">Постоянная</span>',
                                        'htaccess' => '<span style="color: purple;">Через .htaccess</span>'
                                    ];
                                    echo $type_labels[$block['type']];
                                    ?>
                                </td>
                                <td><?php echo esc_html($block['last_attempt']); ?></td>
                                <td>
                                    <a href="<?php echo wp_nonce_url(
                                        admin_url('options-general.php?page=advanced-security-blocker&unblock_ip=' . $block['ip'] . '&tab=manage-blocks&paged=' . $current_page . '&s=' . urlencode($search)),
                                        'unblock_ip'
                                    ); ?>" class="button" onclick="return confirm('Вы уверены, что хотите разблокировать этот IP адрес?');">
                                        Разблокировать
                                    </a>
                                    <button class="button view-history-btn" data-ip="<?php echo esc_attr($block['ip']); ?>">
                                        История
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <!-- Пагинация внизу -->
                <div class="tablenav bottom">
                    <div class="tablenav-pages">
                        <span class="displaying-num"><?php echo $total_blocks; ?> элементов</span>
                        <?php if ($total_pages > 1) : ?>
                            <span class="pagination-links">
                                <?php if ($current_page > 1) : ?>
                                    <a class="first-page button" href="<?php echo add_query_arg('paged', 1); ?>">«</a>
                                    <a class="prev-page button" href="<?php echo add_query_arg('paged', $current_page - 1); ?>">‹</a>
                                <?php endif; ?>

                                <span class="paging-input">
                                    <span class="current-page"><?php echo $current_page; ?></span> из
                                    <span class="total-pages"><?php echo $total_pages; ?></span>
                                </span>

                                <?php if ($current_page < $total_pages) : ?>
                                    <a class="next-page button" href="<?php echo add_query_arg('paged', $current_page + 1); ?>">›</a>
                                    <a class="last-page button" href="<?php echo add_query_arg('paged', $total_pages); ?>">»</a>
                                <?php endif; ?>
                            </span>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <div class="card">
            <h3>История разблокировок</h3>

            <?php if (empty($unblock_history)) : ?>
                <p>Нет записей в истории разблокировок.</p>
            <?php else : ?>
                <table class="attempts-table">
                    <thead>
                        <tr>
                            <th>IP адрес</th>
                            <th>Время разблокировки</th>
                            <th>Причина</th>
                            <th>Кем разблокирован</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($unblock_history as $unblock) : ?>
                            <tr>
                                <td><?php echo esc_html($unblock->ip_address); ?></td>
                                <td><?php echo esc_html(date('d.m.Y H:i:s', strtotime($unblock->unblock_time))); ?></td>
                                <td><?php echo esc_html($unblock->unblock_reason); ?></td>
                                <td><?php echo esc_html($unblock->unblocked_by); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <div class="card">
            <h3>Добавить IP в черный список</h3>
            <form method="post">
                <?php wp_nonce_field('security_blocker_update'); ?>
                <table class="form-table">
                    <tr>
                        <th><label for="manual_block_ip">IP адрес:</label></th>
                        <td>
                            <input type="text" name="manual_block_ip" id="manual_block_ip" class="regular-text"
                                placeholder="192.168.0.1 или 192.168.0.0/24">
                            <p class="description">Введите IP адрес или CIDR диапазон для блокировки</p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="block_reason">Причина блокировки:</label></th>
                        <td>
                            <input type="text" name="block_reason" id="block_reason" class="regular-text"
                                placeholder="Нежелательный трафик">
                            <p class="description">Укажите причину блокировки для ведения лога</p>
                        </td>
                    </tr>
                </table>
                <p>
                    <button type="submit" name="submit_manual_block" class="button button-primary">
                        Заблокировать IP
                    </button>
                </p>
            </form>
        </div>
    </div>

    <!-- Вкладка белого списка -->
    <div id="tab-whitelist" class="security-tab-content">
        <h2>Белый список IP адресов</h2>

        <div class="security-info">
            IP адреса в белом списке никогда не будут заблокированы системой, даже при множественных неудачных попыток входа.
        </div>

        <div class="card">
            <h3>Текущий белый список</h3>

            <?php if (empty($whitelist_ips)) : ?>
                <p>Белый список пуст.</p>
            <?php else : ?>
                <table class="attempts-table">
                    <thead>
                        <tr>
                            <th>IP адрес</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($whitelist_ips as $ip) : ?>
                            <tr>
                                <td><?php echo esc_html($ip); ?></td>
                                <td>
                                    <a href="<?php echo wp_nonce_url(
                                        admin_url('options-general.php?page=advanced-security-blocker&remove_whitelist=' . $ip),
                                        'remove_whitelist'
                                    ); ?>" class="button" onclick="return confirm('Вы уверены, что хотите удалить этот IP адрес из белого списка?');">
                                        Удалить
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <div class="card">
            <h3>Добавить IP в белый список</h3>
            <form method="post">
                <?php wp_nonce_field('security_blocker_update'); ?>
                <table class="form-table">
                    <tr>
                        <th><label for="whitelist_ip">IP адрес:</label></th>
                        <td>
                            <input type="text" name="whitelist_ip" id="whitelist_ip" class="regular-text"
                                placeholder="192.168.0.1 или 192.168.0.0/24">
                            <p class="description">Введите IP адрес или CIDR диапазон для добавления в белый список</p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="whitelist_reason">Причина добавления:</label></th>
                        <td>
                            <input type="text" name="whitelist_reason" id="whitelist_reason" class="regular-text"
                                placeholder="Доверенный пользователь">
                            <p class="description">Укажите причину добавления в белый список</p>
                        </td>
                    </tr>
                </table>
                <p>
                    <button type="submit" name="submit_whitelist" class="button button-primary">
                        Добавить в белый список
                    </button>
                </p>
            </form>
        </div>
    </div>

    <!-- Вкладка статуса -->
    <div id="tab-status" class="security-tab-content">
        <h2>Статус системы безопасности</h2>
        <div class="card">
            <h3>Состояние компонентов</h3>
            <ul>
                <li>Файл .htaccess: <?php echo is_writable($this->htaccess_path) ?
                    '<span style="color:green">✓ доступен для записи</span>' :
                    '<span style="color:red">✗ недоступен для записи</span>'; ?></li>
                <li>Резервные копии: <?php echo is_writable($this->backup_dir) ?
                    '<span style="color:green">✓ доступны</span>' :
                    '<span style="color:red">✗ недоступны</span>'; ?></li>
                <li>Кеш ASN: <?php echo is_writable($this->cache_dir) ?
                    '<span style="color:green">✓ доступен</span>' :
                    '<span style="color:red">✗ недоступен</span>'; ?></li>
                <li>База данных попыток входа: <?php
                    global $wpdb;
                    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}security_login_attempts'");
                    echo $table_exists ?
                        '<span style="color:green">✓ создана</span>' :
                        '<span style="color:red">✗ не создана</span>';
                ?></li>
                <li>База данных разблокировок: <?php
                    $unblock_table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}security_unblock_history'");
                    echo $unblock_table_exists ?
                        '<span style="color:green">✓ создана</span>' :
                        '<span style="color:red">✗ не создана</span>';
                ?></li>
                <li>Последняя резервная копия: <?php
                    $backups = glob($this->backup_dir . 'htaccess-*.bak');
                    if (!empty($backups)) {
                        rsort($backups);
                        echo '<span style="color:green">' . date('d.m.Y H:i:s', filemtime($backups[0])) . '</span>';
                    } else {
                        echo '<span style="color:orange">не создана</span>';
                    }
                ?></li>
                <li>Кешированные ASN: <?php
                    $cache_files = glob($this->cache_dir . 'asn_*.json');
                    echo '<span style="color:blue">' . count($cache_files) . '</span>';
                ?></li>
                <li>Ваш текущий IP: <strong><?php echo esc_html($current_user_ip); ?></strong></li>
            </ul>
        </div>

        <div class="card">
            <h3>Активные защиты</h3>
            <ul>
                <li>Блокировка IP: <?php echo !empty($current_ips) ?
                    '<span style="color:green">✓ активна (' . count(array_filter(explode("\n", trim($current_ips)))) . ' записей)</span>' :
                    '<span style="color:gray">○ неактивна</span>'; ?></li>
                <li>Защита wp-login.php: <?php echo $current_protection['wp_login'] ?
                    '<span style="color:green">✓ активна</span>' :
                    '<span style="color:gray">○ неактивна</span>'; ?></li>
                <li>Защита xmlrpc.php: <?php echo $current_protection['xmlrpc'] ?
                    '<span style="color:green">✓ активна</span>' :
                    '<span style="color:gray">○ неактивна</span>'; ?></li>
                <li>Разрешенные IP: <?php echo !empty($current_whitelist) ?
                    '<span style="color:green">' . count(array_filter(explode("\n", trim($current_whitelist)))) . ' записей</span>' :
                    '<span style="color:gray">0 записей</span>'; ?></li>
                <li>Блокировка файлов: <?php echo !empty($current_files) ?
                    '<span style="color:green">✓ активна (' . count(array_filter(explode("\n", trim($current_files)))) . ' файлов)</span>' :
                    '<span style="color:gray">○ неактивна</span>'; ?></li>
                <li>Защита от ботов: <?php echo !empty($current_bots) ?
                    '<span style="color:green">✓ активна</span>' :
                    '<span style="color:gray">○ неактивна</span>'; ?></li>
                <li>Защита от брутфорс атак: <?php echo get_option('asb_brute_force_enabled') ?
                    '<span style="color:green">✓ активна</span>' :
                    '<span style="color:gray">○ неактивна</span>'; ?></li>
                <li>Белый список: <?php echo !empty($whitelist_ips) ?
                    '<span style="color:green">✓ активен (' . count($whitelist_ips) . ' записей)</span>' :
                    '<span style="color:gray">○ неактивен</span>'; ?></li>
            </ul>
        </div>

        <p>
            <a href="<?php echo esc_url(admin_url('options-general.php?page=advanced-security-blocker&backup=1')); ?>"
               class="button">
                Создать резервную копию .htaccess
            </a>
            <a href="<?php echo esc_url(admin_url('options-general.php?page=advanced-security-blocker&clear_cache=1')); ?>"
               class="button">
                Очистить весь кеш
            </a>
        </p>
    </div>
    </div>
    </div>

    <!-- Модальное окно для истории блокировок -->
    <div id="history-modal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h2>История блокировок для IP: <span id="modal-ip"></span></h2>
            <div id="modal-history-content">
                <p>Загрузка истории...</p>
            </div>
        </div>
    </div>

    <script>
    function addCurrentIP() {
        var textarea = document.getElementById('login_whitelist_ips');
        var currentIP = '<?php echo esc_js($current_user_ip); ?>';
        if (textarea && textarea.value.indexOf(currentIP) === -1) {
            textarea.value += (textarea.value ? '\n' : '') + currentIP;
        }
    }

    // Инициализация после загрузки DOM
    document.addEventListener('DOMContentLoaded', function() {
        // Функция переключения вкладки
        function showTab(tabId) {
            var contents = document.querySelectorAll('.security-tab-content');
            var buttons = document.querySelectorAll('.security-tab-nav button');

            contents.forEach(function(content) {
                content.classList.remove('active');
                content.style.display = 'none';
            });

            buttons.forEach(function(button) {
                button.classList.remove('active');
            });

            var targetTab = document.getElementById(tabId);
            var targetButton = document.querySelector('.security-tab-nav button[data-tab="' + tabId + '"]');

            if (targetTab) {
                targetTab.classList.add('active');
                targetTab.style.display = 'block';
            }

            if (targetButton) {
                targetButton.classList.add('active');
            }
        }

        // Обработчики кликов по кнопкам вкладок
        var tabButtons = document.querySelectorAll('.security-tab-nav button');
        tabButtons.forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                var tabId = this.getAttribute('data-tab');
                showTab(tabId);
            });
        });

        // Показываем первую вкладку по умолчанию
        showTab("tab-ip-blocking");

        // Настройка номеров строк для textarea
        function setupLineNumbers(wrapper) {
            var textarea = wrapper.querySelector('textarea');
            var lineNumbersDiv = wrapper.querySelector('.ip-blocker-line-numbers');

            if (!textarea || !lineNumbersDiv) return;

            function updateLineNumbers() {
                var text = textarea.value;
                var lines = text ? text.split('\n').length : 1;
                var lineNumbers = '';

                for (var i = 1; i <= lines; i++) {
                    lineNumbers += i + (i < lines ? '\n' : '');
                  }

lineNumbersDiv.textContent = lineNumbers;
}

textarea.addEventListener('input', updateLineNumbers);
textarea.addEventListener('keyup', updateLineNumbers);
textarea.addEventListener('paste', updateLineNumbers);
textarea.addEventListener('scroll', function() {
lineNumbersDiv.scrollTop = textarea.scrollTop;
});

updateLineNumbers();
}

// Инициализация нумерации строк
var wrappers = document.querySelectorAll('.ip-blocker-textarea-wrapper');
wrappers.forEach(setupLineNumbers);

// AJAX обновление статистики брутфорс атак
var autoRefreshEnabled = true;
var refreshInterval;

function updateBruteForceStats() {
var refreshButton = document.getElementById('manual-refresh-stats');
var lastUpdated = document.getElementById('last-updated');

if (refreshButton) refreshButton.disabled = true;
if (lastUpdated) lastUpdated.innerHTML = '<span class="loading-spinner"></span> Обновление...';

jQuery.ajax({
url: asb_ajax.ajax_url,
type: 'POST',
data: {
  action: 'asb_get_login_stats',
  nonce: asb_ajax.nonce
},
success: function(response) {
  if (response.success) {
      var data = response.data;

      // Обновляем общую статистику
      document.getElementById('stat-total-attempts').textContent = data.total_attempts;
      document.getElementById('stat-blocked-ips').textContent = data.blocked_ips;

      // Обновляем топ IP
      var topIpsHtml = '';
      data.top_ips.forEach(function(ip) {
          topIpsHtml += '<tr>' +
              '<td>' + ip.ip_address + '</td>' +
              '<td>' + ip.attempts + '</td>' +
              '<td>' + (ip.is_blocked ? '<span class="blocked-ip">Заблокирован</span>' : '<span class="normal-ip">Активен</span>') + '</td>' +
          '</tr>';
      });
      document.getElementById('top-ips-body').innerHTML = topIpsHtml;

      // Обновляем последние попытки
      var recentHtml = '';
      data.recent_attempts.forEach(function(attempt) {
          var date = new Date(attempt.attempt_time);
          recentHtml += '<tr>' +
              '<td>' + date.toLocaleString() + '</td>' +
              '<td>' + attempt.ip_address + '</td>' +
              '<td>' + attempt.username + '</td>' +
              '<td>' + (attempt.blocked ? '<span class="blocked-ip">Заблокирован</span>' : '<span class="normal-ip">Неудачная попытка</span>') + '</td>' +
              '<td title="' + (attempt.user_agent || '') + '">' +
                  (attempt.user_agent ? (attempt.user_agent.substring(0, 50) + (attempt.user_agent.length > 50 ? '...' : '')) : '') +
              '</td>' +
          '</tr>';
      });
      document.getElementById('recent-attempts-body').innerHTML = recentHtml;

      // Обновляем время последнего обновления
      var now = new Date();
      if (lastUpdated) lastUpdated.textContent = 'Последнее обновление: ' + now.toLocaleTimeString();
  }
},
error: function(xhr, status, error) {
  console.error('Ошибка при обновлении статистики:', error);
  if (lastUpdated) lastUpdated.textContent = 'Ошибка обновления';
},
complete: function() {
  if (refreshButton) refreshButton.disabled = false;
}
});
}

// Обработчики для ручного и автоматического обновления
var manualRefreshBtn = document.getElementById('manual-refresh-stats');
var autoRefreshCheckbox = document.getElementById('auto-refresh-stats');

if (manualRefreshBtn) {
manualRefreshBtn.addEventListener('click', updateBruteForceStats);
}

if (autoRefreshCheckbox) {
autoRefreshCheckbox.addEventListener('change', function() {
autoRefreshEnabled = this.checked;
if (autoRefreshEnabled) {
  startAutoRefresh();
} else {
  clearInterval(refreshInterval);
}
});
}

function startAutoRefresh() {
clearInterval(refreshInterval);
refreshInterval = setInterval(updateBruteForceStats, 30000); // 30 секунд
}

// Запускаем автоматическое обновление если на вкладке брутфорс атак
if (document.getElementById('tab-brute-force').style.display !== 'none') {
    startAutoRefresh();
    updateBruteForceStats();
}

// Модальное окно для истории блокировок
var modal = document.getElementById('history-modal');
var span = document.getElementsByClassName('close')[0];
var modalIp = document.getElementById('modal-ip');
var modalContent = document.getElementById('modal-history-content');

// Обработчик для кнопок просмотра истории
document.querySelectorAll('.view-history-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
        var ip = this.getAttribute('data-ip');
        modalIp.textContent = ip;
        modalContent.innerHTML = '<p>Загрузка истории...</p>';
        modal.style.display = 'block';

        jQuery.ajax({
            url: asb_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'asb_get_block_history',
                ip: ip,
                nonce: asb_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    var history = response.data;
                    if (history.length > 0) {
                        var html = '<table class="history-table"><thead><tr><th>Время</th><th>Пользователь</th><th>User-Agent</th><th>Блокировка</th></tr></thead><tbody>';
                        history.forEach(function(entry) {
                            html += '<tr>' +
                                '<td>' + new Date(entry.attempt_time).toLocaleString() + '</td>' +
                                '<td>' + entry.username + '</td>' +
                                '<td title="' + (entry.user_agent || '') + '">' +
                                    (entry.user_agent ? (entry.user_agent.substring(0, 50) + (entry.user_agent.length > 50 ? '...' : '')) : '') +
                                '</td>' +
                                '<td>' + (entry.blocked ? 'Да' : 'Нет') + '</td>' +
                            '</tr>';
                        });
                        html += '</tbody></table>';
                        modalContent.innerHTML = html;
                    } else {
                        modalContent.innerHTML = '<p>Нет данных о попытках входа для этого IP.</p>';
                    }
                } else {
                    modalContent.innerHTML = '<p>Ошибка загрузки истории.</p>';
                }
            },
            error: function() {
                modalContent.innerHTML = '<p>Ошибка загрузки истории.</p>';
            }
        });
    });
});

// Закрытие модального окна
span.onclick = function() {
    modal.style.display = 'none';
}

window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}
});

// Исправление обработки чекбоксов
document.addEventListener('DOMContentLoaded', function() {
// Обработчик для всех чекбоксов в форме защиты от брутфорс атак
var bruteForceForm = document.querySelector('form input[name="submit_brute_force_protection"]');
if (bruteForceForm) {
    var form = bruteForceForm.closest('form');
    var checkboxes = form.querySelectorAll('input[type="checkbox"]');

    checkboxes.forEach(function(checkbox) {
        // Убираем скрытые поля при отправке если чекбокс отмечен
        checkbox.addEventListener('change', function() {
            var hiddenField = form.querySelector('input[type="hidden"][name="' + this.name + '"]');
            if (hiddenField) {
                if (this.checked) {
                    hiddenField.disabled = true;
                } else {
                    hiddenField.disabled = false;
                }
            }
        });

        // Инициализация при загрузке страницы
        var hiddenField = form.querySelector('input[type="hidden"][name="' + checkbox.name + '"]');
        if (hiddenField && checkbox.checked) {
            hiddenField.disabled = true;
        }
    });
}
});
</script>
<?php
}

private function get_user_ip() {
// Получаем реальный IP пользователя с учетом прокси
$ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];

foreach ($ip_keys as $key) {
    if (!empty($_SERVER[$key])) {
        $ips = explode(',', $_SERVER[$key]);
        $ip = trim($ips[0]);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $ip;
        }
    }
}

return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
}

// Получение текущих настроек защиты
private function get_current_protection_settings() {
if (!file_exists($this->htaccess_path)) {
    return ['wp_login' => false, 'xmlrpc' => false];
}

$htaccess = file_get_contents($this->htaccess_path);
preg_match('/' . preg_quote($this->marker_login, '/') . '(.*?)' . preg_quote($this->marker_login, '/') . '/s', $htaccess, $matches);

if (empty($matches[1])) {
    return ['wp_login' => false, 'xmlrpc' => false];
}

$content = $matches[1];

return [
    'wp_login' => strpos($content, 'wp-login.php') !== false,
    'xmlrpc' => strpos($content, 'xmlrpc.php') !== false
];
}

// Обновленная функция блокировки IP с поддержкой ASN
private function update_ip_rules($ips) {
$this->log = [];

try {
    $this->create_backup();
    $this->log[] = 'Создана резервная копия .htaccess';

    $ip_list = explode("\n", $ips);
    $ip_list = array_map('trim', $ip_list);
    $ip_list = array_filter($ip_list);

    $original_count = count($ip_list);
    $ip_list = array_unique($ip_list);
    $duplicates_count = $original_count - count($ip_list);

    if ($duplicates_count > 0) {
        $this->log[] = "Удалены дубликаты: $duplicates_count";
    }

    $rules = [];
    $valid_ips = [];
    $invalid_ips = [];
    $asn_ranges = [];

    foreach ($ip_list as $entry) {
        // Проверяем, является ли это ASN
        if (preg_match('/^AS?(\d+)$/i', $entry, $matches)) {
            $asn = $matches[1];
            $this->log[] = "Обработка ASN: AS{$asn}";

            $ranges = $this->get_asn_ip_ranges($asn);
            if ($ranges && !empty($ranges)) {
                foreach ($ranges as $range) {
                    $rules[] = "deny from {$range}";
                    $asn_ranges[] = $range;
                }
                $this->log[] = "ASN AS{$asn}: добавлено " . count($ranges) . " диапазонов";
            } else {
                $this->log[] = "ASN AS{$asn}: не удалось получить диапазоны";
                $invalid_ips[] = $entry;
            }
        }
        // Обработка CIDR диапазонов
        else if (strpos($entry, '/') !== false) {
            list($ip, $mask) = explode('/', $entry, 2);
            if (filter_var($ip, FILTER_VALIDATE_IP) &&
                is_numeric($mask) && $mask >= 0 && $mask <= 32) {
                $rules[] = "deny from {$entry}";
                $valid_ips[] = $entry;
            } else {
                $invalid_ips[] = $entry;
            }
        }
        // Простые IP
        else if (filter_var($entry, FILTER_VALIDATE_IP)) {
            $rules[] = "deny from {$entry}";
            $valid_ips[] = $entry;
        } else {
            $invalid_ips[] = $entry;
        }
    }

    if (!empty($invalid_ips)) {
        $this->log[] = "Некорректные записи (проигнорированы): " . implode(', ', $invalid_ips);
    }

    $htaccess = file_exists($this->htaccess_path) ?
        file_get_contents($this->htaccess_path) : '';

    $pattern = '/\n?' . preg_quote($this->marker_ip, '/') . '.*?' . preg_quote($this->marker_ip, '/') . '/s';
    $htaccess = preg_replace($pattern, '', $htaccess);

    if (!empty($rules)) {
        $block = "\n" . $this->marker_ip . "\n" . implode("\n", $rules) . "\n" . $this->marker_ip . "\n";
        $htaccess = $block . $htaccess;
        $this->log[] = "Добавлено IP: " . count($valid_ips) . ", ASN диапазонов: " . count(array_unique($asn_ranges));
    } else {
        $this->log[] = "Все правила блокировки IP удалены";
    }

    if (!file_put_contents($this->htaccess_path, $htaccess)) {
        throw new Exception('Не удалось записать в .htaccess');
    }

    $this->log[] = "Настройки успешно сохранены";
    return true;

} catch (Exception $e) {
    $this->restore_backup();
    $this->log[] = "Ошибка: восстановлена резервная копия";
    return $e->getMessage();
}
}

// Обновленная функция защиты wp-login.php и xmlrpc.php с поддержкой ASN
private function update_login_protection($whitelist_ips, $protect_wp_login = false, $protect_xmlrpc = false) {
$this->log = [];

try {
    $this->create_backup();
    $this->log[] = 'Создана резервная копия .htaccess';

    $htaccess = file_exists($this->htaccess_path) ?
        file_get_contents($this->htaccess_path) : '';

    $pattern = '/\n?' . preg_quote($this->marker_login, '/') . '.*?' . preg_quote($this->marker_login, '/') . '/s';
    $htaccess = preg_replace($pattern, '', $htaccess);

    // Если ни один файл не выбран для защиты, просто удаляем правила
    if (!$protect_wp_login && !$protect_xmlrpc) {
        $this->log[] = "Защита wp-login.php и xmlrpc.php отключена";

        if (!file_put_contents($this->htaccess_path, $htaccess)) {
            throw new Exception('Не удалось записать в .htaccess');
        }

        $this->log[] = "Настройки успешно сохранены";
        return true;
    }

    if (!empty(trim($whitelist_ips))) {
        $ip_list = explode("\n", $whitelist_ips);
        $ip_list = array_map('trim', $ip_list);
        $ip_list = array_filter($ip_list);
        $ip_list = array_unique($ip_list);

        $files_to_protect = [];
        if ($protect_wp_login) $files_to_protect[] = 'wp-login.php';
        if ($protect_xmlrpc) $files_to_protect[] = 'xmlrpc.php';

        $rules = [];

        // Создаем отдельные блоки для каждого файла
        foreach ($files_to_protect as $file) {
            $rules[] = "<Files \"{$file}\">";
            $rules[] = 'Order Deny,Allow';
            $rules[] = 'Deny from all';

            $valid_ips = [];
            $invalid_ips = [];
            $asn_ranges = [];

            foreach ($ip_list as $entry) {
                $is_valid = false;

                // Обработка ASN
                if (preg_match('/^AS?(\d+)$/i', $entry, $matches)) {
                    $asn = $matches[1];
                    $this->log[] = "Обработка ASN для whitelist: AS{$asn}";

                    $ranges = $this->get_asn_ip_ranges($asn);
                    if ($ranges && !empty($ranges)) {
                        foreach ($ranges as $range) {
                            $rules[] = "Allow from {$range}";
                            $asn_ranges[] = $range;
                        }
                        $this->log[] = "ASN AS{$asn}: добавлено в whitelist " . count($ranges) . " диапазонов для {$file}";
                        $is_valid = true;
                    }
                }
                // CIDR диапазоны
                else if (strpos($entry, '/') !== false) {
                    list($ip, $mask) = explode('/', $entry, 2);
                    if (filter_var($ip, FILTER_VALIDATE_IP) &&
                        is_numeric($mask) && $mask >= 0 && $mask <= 32) {
                        $rules[] = "Allow from {$entry}";
                        $valid_ips[] = $entry;
                        $is_valid = true;
                    }
                }
                // Простые IP
                else if (filter_var($entry, FILTER_VALIDATE_IP)) {
                    $rules[] = "Allow from {$entry}";
                    $valid_ips[] = $entry;
                    $is_valid = true;
                }
                // Диапазон с маской подсети
                else if (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/', $entry, $matches)) {
                    $ip = $matches[1];
                    $netmask = $matches[2];

                    if (filter_var($ip, FILTER_VALIDATE_IP) && filter_var($netmask, FILTER_VALIDATE_IP)) {
                        $rules[] = "Allow from {$ip} {$netmask}";
                        $valid_ips[] = $entry;
                        $is_valid = true;
                    }
                }
                // Частичные IP
                else if (preg_match('/^(\d{1,3}\.){1,3}\d{1,3}$/', $entry) &&
                         !filter_var($entry, FILTER_VALIDATE_IP)) {
                    $parts = explode('.', $entry);
                    $valid_partial = true;

                    foreach ($parts as $part) {
                        if (!is_numeric($part) || $part < 0 || $part > 255) {
                            $valid_partial = false;
                            break;
                        }
                    }

                    if ($valid_partial && count($parts) >= 1 && count($parts) <= 3) {
                        $rules[] = "Allow from {$entry}";
                        $valid_ips[] = $entry;
                        $is_valid = true;
                    }
                }

                if (!$is_valid && !in_array($entry, $invalid_ips)) {
                    $invalid_ips[] = $entry;
                }
            }

            $rules[] = '</Files>';
            $rules[] = ''; // Пустая строка между блоками
        }

        if (!empty($invalid_ips)) {
            $this->log[] = "Некорректные записи (проигнорированы): " . implode(', ', $invalid_ips);
        }

        // Удаляем последнюю пустую строку
        if (end($rules) === '') {
            array_pop($rules);
        }

        $block = "\n" . $this->marker_login . "\n" . implode("\n", $rules) . "\n" . $this->marker_login . "\n";
        $htaccess = $block . $htaccess;

        $protected_files = implode(', ', $files_to_protect);
        $this->log[] = "Защита настроена для: {$protected_files}";
        $this->log[] = "IP/диапазонов: " . count(array_unique($valid_ips)) . ", ASN диапазонов: " . count(array_unique($asn_ranges));
    } else {
        $this->log[] = "Не указаны разрешенные IP адреса";
        return "Необходимо указать хотя бы один разрешенный IP адрес";
    }

    if (!file_put_contents($this->htaccess_path, $htaccess)) {
        throw new Exception('Не удалось записать в .htaccess');
    }

    $this->log[] = "Настройки успешно сохранены";
    return true;

} catch (Exception $e) {
    $this->restore_backup();
    $this->log[] = "Ошибка: восстановлена резервная копия";
    return $e->getMessage();
}
}

// Обновление защиты от опасных файлов
private function update_file_protection($dangerous_files) {
$this->log = [];

try {
    $this->create_backup();
    $this->log[] = 'Создана резервная копия .htaccess';

    $htaccess = file_exists($this->htaccess_path) ?
        file_get_contents($this->htaccess_path) : '';

    // Удаляем старые правила
    $pattern = '/\n?' . preg_quote($this->marker_files, '/') . '.*?' . preg_quote($this->marker_files, '/') . '/s';
    $htaccess = preg_replace($pattern, '', $htaccess);

    if (!empty(trim($dangerous_files))) {
        $file_list = explode("\n", $dangerous_files);
        $file_list = array_map('trim', $file_list);
        $file_list = array_filter($file_list);
        $file_list = array_unique($file_list);

        $escaped_files = array_map(function($file) {
            return str_replace(['*', '.'], ['.*', '\.'], preg_quote($file, '/'));
        }, $file_list);

        $rules = ['<FilesMatch "(' . implode('|', $escaped_files) . ')$">'];
        $rules[] = 'Order Allow,Deny';
        $rules[] = 'Deny from all';
        $rules[] = '</FilesMatch>';

        $block = "\n" . $this->marker_files . "\n" . implode("\n", $rules) . "\n" . $this->marker_files . "\n";
        $htaccess = $block . $htaccess;

        $this->log[] = "Защита файлов настроена для " . count($file_list) . " файлов";
    } else {
        $this->log[] = "Защита файлов отключена";
    }

    if (!file_put_contents($this->htaccess_path, $htaccess)) {
        throw new Exception('Не удалось записать в .htaccess');
    }

    $this->log[] = "Настройки успешно сохранены";
    return true;

} catch (Exception $e) {
    $this->restore_backup();
    $this->log[] = "Ошибка: восстановлена резервная копия";
    return $e->getMessage();
}
}

// Обновление защиты от ботов (с SetEnvIfNoCase)
private function update_bot_protection($blocked_bots) {
$this->log = [];

try {
    $this->create_backup();
    $this->log[] = 'Создана резервная копия .htaccess';

    $htaccess = file_exists($this->htaccess_path) ?
        file_get_contents($this->htaccess_path) : '';

    // Удаляем старые правила
    $pattern = '/\n?' . preg_quote($this->marker_bots, '/') . '.*?' . preg_quote($this->marker_bots, '/') . '/s';
    $htaccess = preg_replace($pattern, '', $htaccess);

    if (!empty(trim($blocked_bots))) {
        $bot_list = explode('|', $blocked_bots);
        $bot_list = array_map('trim', $bot_list);
        $bot_list = array_filter($bot_list);
        $bot_list = array_unique($bot_list);

        // Убираем из списка некорректные символы
        $cleaned_bots = [];
        $skipped_bots = [];

        foreach ($bot_list as $bot) {
            if (strlen($bot) < 2) {
                $skipped_bots[] = $bot;
                continue;
            }

            // Для SetEnvIfNoCase нужно экранировать только кавычки
            $cleaned_bot = preg_replace('/["\'\\\]/', '', $bot);

            if (!empty($cleaned_bot) && strlen($cleaned_bot) > 1) {
                $cleaned_bots[] = $cleaned_bot;
            } else {
                $skipped_bots[] = $bot;
            }
        }

        if (!empty($skipped_bots)) {
            $this->log[] = "Пропущены некорректные User-Agent: " . count($skipped_bots);
        }

        if (!empty($cleaned_bots)) {
            // Разбиваем на группы для избежания слишком длинных строк регекса
            $bot_groups = array_chunk($cleaned_bots, 100);
            $rules = [];

            foreach ($bot_groups as $group_index => $group) {
                $bot_string = implode('|', $group);
                $rules[] = 'SetEnvIfNoCase User-Agent "' . $bot_string . '" block_bot' . ($group_index > 0 ? '_' . $group_index : '');
            }

            // Добавляем правила блокировки
            $rules[] = '';
            $rules[] = '<Limit GET POST HEAD>';
            $rules[] = '    Order Allow,Deny';
            $rules[] = '    Allow from all';

            // Блокируем все переменные окружения
            for ($i = 0; $i < count($bot_groups); $i++) {
                $rules[] = '    Deny from env=block_bot' . ($i > 0 ? '_' . $i : '');
            }

            $rules[] = '</Limit>';

            $block = "\n" . $this->marker_bots . "\n" . implode("\n", $rules) . "\n" . $this->marker_bots . "\n";
            $htaccess = $block . $htaccess;

            $this->log[] = "Защита от ботов настроена для " . count($cleaned_bots) . " User-Agent в " . count($bot_groups) . " группах";
        } else {
            $this->log[] = "Все User-Agent оказались некорректными и были проигнорированы";
        }
    } else {
        $this->log[] = "Защита от ботов отключена";
    }

    if (!file_put_contents($this->htaccess_path, $htaccess)) {
        throw new Exception('Не удалось записать в .htaccess');
    }

    $this->log[] = "Настройки успешно сохранены";
    return true;

} catch (Exception $e) {
    $this->restore_backup();
    $this->log[] = "Ошибка: восстановлена резервная копия - " . $e->getMessage();
    return $e->getMessage();
}
}

// Получение текущих заблокированных IP
private function get_current_ips() {
if (!file_exists($this->htaccess_path)) return '';

$htaccess = file_get_contents($this->htaccess_path);
preg_match('/' . preg_quote($this->marker_ip, '/') . '(.*?)' . preg_quote($this->marker_ip, '/') . '/s', $htaccess, $matches);

if (empty($matches[1])) return '';

preg_match_all('/deny from ([^\r\n]+)/', $matches[1], $ips);
return implode("\n", array_unique($ips[1]));
}

// Получение текущего белого списка для wp-login.php и xmlrpc.php
private function get_current_login_whitelist() {
if (!file_exists($this->htaccess_path)) return '';

$htaccess = file_get_contents($this->htaccess_path);
preg_match('/' . preg_quote($this->marker_login, '/') . '(.*?)' . preg_quote($this->marker_login, '/') . '/s', $htaccess, $matches);

if (empty($matches[1])) return '';

preg_match_all('/Allow from ([^\r\n]+)/', $matches[1], $allows);

if (!empty($allows[1])) {
    return implode("\n", array_unique($allows[1]));
}

return '';
}

// Создание резервной копия
private function create_backup() {
if (file_exists($this->htaccess_path)) {
    $backup_file = $this->backup_dir . 'htaccess-' . date('Ymd-His') . '.bak';
    if (copy($this->htaccess_path, $backup_file)) {
        $this->log[] = "Резервная копия создана: " . basename($backup_file);

        // Удаляем старые бекапы (оставляем только последние 10)
        $backups = glob($this->backup_dir . 'htaccess-*.bak');
        if (count($backups) > 10) {
            rsort($backups);
            $old_backups = array_slice($backups, 10);
            foreach ($old_backups as $old_backup) {
                unlink($old_backup);
            }
        }
    } else {
        $this->log[] = "Ошибка создания резервной копия";
    }
}
}

// Восстановление из резервной копии
private function restore_backup() {
$backups = glob($this->backup_dir . 'htaccess-*.bak');
if (!empty($backups)) {
    rsort($backups);
    if (copy($backups[0], $this->htaccess_path)) {
        $this->log[] = "Восстановлена резервная копия: " . basename($backups[0]);
    } else {
        $this->log[] = "Ошибка восстановления из резервной копия";
    }
}
}

// Деактивация плагина - удаляем всех правил
public function deactivate() {
$this->update_ip_rules('');
$this->update_login_protection('', false, false);
$this->update_file_protection('');
$this->update_bot_protection('');
}
}

// Класс для обработки кэширования
class ASB_Cache_Handler {
public function __construct() {
// Инициализация обработчика кэша
}

// Очистка всех типов кэша
public function clear_all_caches() {
$this->clear_browser_cache();
$this->clear_opcache();
$this->clear_redis_cache();
$this->clear_memcached_cache();
$this->clear_wordpress_cache();
}

// Очистка браузерного кэша (через заголовки)
private function clear_browser_cache() {
// Добавляем заголовки для предотвращения кэширования
if (!headers_sent()) {
    header("Cache-Control: no-cache, must-revalidate");
    header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");
    header("Pragma: no-cache");
}
}

// Очистка OPcache
private function clear_opcache() {
if (function_exists('opcache_reset')) {
    opcache_reset();
    error_log("Security Blocker: OPcache очищен");
}
}

// Очистка Redis кэша
private function clear_redis_cache() {
if (class_exists('Redis')) {
    try {
        $redis = new Redis();
        // Попытка подключения к стандартному хосту и порту
        if ($redis->connect('127.0.0.1', 6379)) {
            $redis->flushAll();
            $redis->close();
            error_log("Security Blocker: Redis кэш очищен");
        }
    } catch (Exception $e) {
        // Redis не доступен, игнорируем ошибку
    }
}
}

// Очистка Memcached кэша
private function clear_memcached_cache() {
if (class_exists('Memcached')) {
    try {
        $memcached = new Memcached();
        $memcached->addServer('127.0.0.1', 11211);
        $memcached->flush();
        error_log("Security Blocker: Memcached кэш очищен");
    } catch (Exception $e) {
        // Memcached не доступен, игнорируем ошибку
    }
}
}

// Очистка WordPress кэша
private function clear_wordpress_cache() {
// Очистка кэша трансляций
if (function_exists('wp_cache_flush')) {
    wp_cache_flush();
}

// Очистка кэша популярных плагинов
$this->clear_w3_total_cache();
$this->clear_wp_super_cache();
$this->clear_wp_rocket_cache();

error_log("Security Blocker: WordPress кэш очищен");
}

// Очистка W3 Total Cache
private function clear_w3_total_cache() {
if (function_exists('w3tc_flush_all')) {
    w3tc_flush_all();
}
}

// Очистка WP Super Cache
private function clear_wp_super_cache() {
if (function_exists('wp_cache_clear_cache')) {
    wp_cache_clear_cache();
}
}

// Очистка WP Rocket
private function clear_wp_rocket_cache() {
if (function_exists('rocket_clean_domain')) {
    rocket_clean_domain();
}
}
}

new Advanced_Security_Blocker();
