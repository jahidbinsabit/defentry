<?php
/*
Plugin Name: Defentry - Smart Security & Login Protection
Description: Defentry is a lightweight WordPress device-based login protection plugin. When an admin, editor or author logs in from a new device, a verification overlay blocks the dashboard until a stop password is entered, while other users get a real-time alert banner. Includes master admin control, trusted device management, IP attempt limiting and email alerts.
Version: 1.2.3
Author: Md Jahid Bin Sabit
Author URI: https://jbsabit.com
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: defentry
Domain Path: /languages
*/

if (!defined('ABSPATH')) exit;

class SCBR_Security_Control_Master {
    private $opt_key = 'scbr_settings';
    private $cookie = 'scbr_device_id';
    private $nonce_action = 'scbr_nonce';
    private $transient_prefix = 'scbr_trigger_';
    private $transient_broadcast = 'scbr_broadcast';
    private $attempts_meta = 'scbr_attempts';
    private $ip_attempts_prefix = 'scbr_ip_attempts_';
    private $ip_blocked_prefix = 'scbr_ip_blocked_';
    private $blocked_users_key = 'scbr_blocked_users';
    private $max_attempts = 3;

    public function __construct() {
        try {
            // Bootstrap options and activation
            add_action('plugins_loaded', [$this, 'maybe_bootstrap_options'], 1);
            register_activation_hook(__FILE__, [$this, 'on_activate']);

            // Cookie + detection
            add_action('init', [$this, 'ensure_device_cookie']);
            add_action('admin_init', [$this, 'maybe_handle_new_device_detection']);

            // UI + scripts
            add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
            add_action('admin_footer', [$this, 'maybe_render_new_device_overlay']);
            add_action('admin_notices', [$this, 'maybe_render_broadcast_banner']);
            add_action('in_admin_header', [$this, 'maybe_admin_header_siren']);

            // AJAX endpoints
            add_action('wp_ajax_scbr_stop_siren', [$this, 'ajax_stop_siren']);
            add_action('wp_ajax_scbr_block_user', [$this, 'ajax_block_user']);
            add_action('wp_ajax_scbr_unblock_user', [$this, 'ajax_unblock_user']);
            add_action('wp_ajax_scbr_trust_device', [$this, 'ajax_trust_device']);
            add_action('wp_ajax_scbr_remove_device', [$this, 'ajax_remove_device']);
            add_action('wp_ajax_scbr_mute_siren', [$this, 'ajax_mute_siren']);

            // Security headers (was dead code — now actually hooked).
            add_action('send_headers', [$this, 'set_security_headers']);

            // Settings & master admin
            add_action('admin_menu', [$this, 'register_settings_page']);
            add_action('admin_notices', [$this, 'maybe_prompt_master_admin']);
            add_action('admin_post_scbr_set_master', [$this, 'handle_set_master_admin']);
            add_action('admin_post_scbr_save_settings', [$this, 'handle_save_settings']);
            add_action('admin_post_scbr_trust_reset', [$this, 'handle_trust_reset']);
        } catch (Exception $e) {
            // Log error silently - don't show admin notice to avoid annoying users
        }
    }

    /* ---------------------------- Bootstrap / Options ---------------------------- */

    public function on_activate() {
        global $wp_version;
        if (version_compare($wp_version, '5.5', '<')) {
            wp_die('This plugin requires WordPress 5.5 or higher. Please upgrade WordPress.');
        }

        // Migrate old options
        $old_opts = get_option('wrs_sc_settings');
        if ($old_opts) {
            update_option('scbr_settings', $old_opts);
            delete_option('wrs_sc_settings');
        }

        $old_blocked_users = get_option('wrs_sc_blocked_users');
        if ($old_blocked_users) {
            update_option('scbr_blocked_users', $old_blocked_users);
            delete_option('wrs_sc_blocked_users');
        }

        // Migrate old user meta
        $users = get_users(['fields' => ['ID']]);
        foreach ($users as $user) {
            $old_trusted_devices = get_user_meta($user->ID, 'wrs_sc_trusted_devices', true);
            if ($old_trusted_devices) {
                update_user_meta($user->ID, 'scbr_trusted_devices', $old_trusted_devices);
                delete_user_meta($user->ID, 'wrs_sc_trusted_devices');
            }
            $old_siren_muted = get_user_meta($user->ID, 'wrs_sc_siren_muted', true);
            if ($old_siren_muted) {
                update_user_meta($user->ID, 'scbr_siren_muted', $old_siren_muted);
                delete_user_meta($user->ID, 'wrs_sc_siren_muted');
            }
        }

        $opts = get_option($this->opt_key);
        if (!$opts) {
            try {
                $this->maybe_bootstrap_options();
                $opts = get_option($this->opt_key);
            } catch (Exception $e) {
                // Log error silently - don't show admin notice to avoid annoying users
            }
        }

        if (!empty($opts) && empty($opts['master_admin_id'])) {
            $opts['needs_master_admin'] = 1;
            update_option($this->opt_key, $opts);
        }

        // Initialize blocked users option
        if (!get_option($this->blocked_users_key)) {
            update_option($this->blocked_users_key, []);
        }
    }

    public function maybe_bootstrap_options() {
        $defaults = [
            'master_admin_id'    => 0,
            'needs_master_admin' => 1,
            'status'             => 'off',
            // NOTE: the stop password is NEVER stored in plaintext. Only its
            // hash (via wp_hash_password) is kept in siren_password_hash.
            'siren_password_hash' => '',
            'custom_audio_url'   => '',
            'features' => [
                'siren_enabled'   => 1,
                'email_alerts'    => 1,
                'overlay_enabled' => 1,
                'broadcast_siren' => 1,
            ],
            'overlay_text' => 'Security Verification: Please enter the Siren Stop Password to continue.',
        ];

        $existing = get_option($this->opt_key);
        if (!$existing) {
            $defaults['siren_password_hash'] = wp_hash_password('2210');
            update_option($this->opt_key, $defaults);
            return;
        }

        // One-time migration: hash any legacy plaintext password, then drop it.
        if (empty($existing['siren_password_hash']) && !empty($existing['siren_password'])) {
            $existing['siren_password_hash'] = wp_hash_password($existing['siren_password']);
            unset($existing['siren_password']);
            update_option($this->opt_key, $existing);
        } elseif (!empty($existing['siren_password'])) {
            unset($existing['siren_password']);
            update_option($this->opt_key, $existing);
        }

        if (empty($existing['siren_password_hash'])) {
            $existing['siren_password_hash'] = wp_hash_password('2210');
            update_option($this->opt_key, $existing);
        }

        if (!isset($existing['custom_audio_url'])) {
            $existing['custom_audio_url'] = '';
            update_option($this->opt_key, $existing);
        }
    }

    /* ---------------------------- Utilities ---------------------------- */

    private function get_opts() {
        return get_option($this->opt_key, []);
    }

    private function is_master_admin($user_id = null) {
        $user_id = $user_id ?: get_current_user_id();
        $opts = $this->get_opts();
        return !empty($opts['master_admin_id']) && intval($opts['master_admin_id']) === intval($user_id);
    }

    private function admins_list() {
        return get_users([
            'role__in' => ['administrator', 'editor', 'author'],
            'fields' => ['ID', 'user_login', 'user_email']
        ]);
    }

    private function current_device_id() {
        return isset($_COOKIE[$this->cookie]) ? sanitize_text_field(wp_unslash($_COOKIE[$this->cookie])) : '';
    }

    private function trusted_devices($user_id) {
        $list = get_user_meta($user_id, 'scbr_trusted_devices', true);
        return is_array($list) ? $list : [];
    }

    private function trust_device($user_id, $device_id) {
        $list = $this->trusted_devices($user_id);
        if ($device_id && !in_array($device_id, $list, true)) {
            $list[] = $device_id;
            update_user_meta($user_id, 'scbr_trusted_devices', $list);
        }
    }

    private function remove_device($user_id, $device_id) {
        $list = $this->trusted_devices($user_id);
        if (($key = array_search($device_id, $list, true)) !== false) {
            unset($list[$key]);
            update_user_meta($user_id, 'scbr_trusted_devices', array_values($list));
        }
    }

    private function broadcast_new_device_event($by_user_id, $device_id) {
        $token = $this->generate_uuid();
        set_transient($this->transient_broadcast, [
            'token' => $token,
            'user'  => $by_user_id,
            'device_id' => $device_id,
            'time'  => time(),
        ], 15 * MINUTE_IN_SECONDS);
    }

    private function admin_emails_except($exclude_user_id) {
        $emails = [];
        foreach ($this->admins_list() as $u) {
            if (intval($u->ID) !== intval($exclude_user_id) && is_email($u->user_email)) {
                $emails[] = $u->user_email;
            }
        }
        return $emails;
    }

    private function ip_address() {
        // Only REMOTE_ADDR is trusted. X-Forwarded-For / Client-IP headers are
        // client-controlled and would let an attacker rotate IPs to evade the
        // attempt limiter, so they are deliberately ignored.
        $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
        return 'unknown';
    }

    private function is_ip_blocked($ip) {
        return get_transient($this->ip_blocked_prefix . $ip) ? true : false;
    }

    private function increment_ip_attempts($ip) {
        $attempts = (int) get_transient($this->ip_attempts_prefix . $ip);
        $attempts++;
        set_transient($this->ip_attempts_prefix . $ip, $attempts, HOUR_IN_SECONDS);
        if ($attempts >= $this->max_attempts) {
            set_transient($this->ip_blocked_prefix . $ip, 1, HOUR_IN_SECONDS);
            delete_transient($this->ip_attempts_prefix . $ip);
        }
        return $attempts;
    }

    private function is_user_blocked($user_id) {
        $blocked_users = get_option($this->blocked_users_key, []);
        return in_array(intval($user_id), $blocked_users, true);
    }

    private function block_user($user_id) {
        $blocked_users = get_option($this->blocked_users_key, []);
        if (!in_array(intval($user_id), $blocked_users, true)) {
            $blocked_users[] = intval($user_id);
            update_option($this->blocked_users_key, $blocked_users);
        }
    }

    private function unblock_user($user_id) {
        $blocked_users = get_option($this->blocked_users_key, []);
        if (($key = array_search(intval($user_id), $blocked_users, true)) !== false) {
            unset($blocked_users[$key]);
            update_option($this->blocked_users_key, array_values($blocked_users));
        }
    }

    private function generate_uuid() {
        return wp_generate_uuid4();
    }

    public function set_security_headers() {
        if (is_admin()) {
            header('X-Frame-Options: SAMEORIGIN');
            header('X-Content-Type-Options: nosniff');
            header('Referrer-Policy: no-referrer-when-downgrade');
        }
    }

    /* ------------------------- Script Enqueue ------------------------- */

    public function enqueue_scripts($hook) {
        $opts = $this->get_opts();
        $user_id = get_current_user_id();
        $device_id = $this->current_device_id();

        // Enqueue styles for relevant admin pages
        if ($opts['status'] === 'on' && (
            $hook === 'toplevel_page_scbr_settings' ||
            get_transient($this->transient_prefix . $user_id . '_' . $device_id) ||
            get_transient($this->transient_broadcast)
        )) {
            wp_enqueue_style(
                'scbr-admin',
                plugin_dir_url(__FILE__) . 'css/scbr-admin.css',
                [],
                '1.2.3'
            );
        }

        // Enqueue overlay script for new device detection.
        // NOTE: the stop-password hash is NEVER printed to the page. The
        // browser only collects the password; verification happens
        // server-side in ajax_stop_siren() via wp_check_password().
        if ($opts['status'] === 'on' && get_transient($this->transient_prefix . $user_id . '_' . $device_id)) {
            wp_enqueue_script(
                'scbr-overlay',
                plugin_dir_url(__FILE__) . 'js/scbr-overlay.js',
                [],
                '1.2.3',
                true
            );
            wp_localize_script('scbr-overlay', 'scbr_ajax', [
                'ajaxurl' => admin_url('admin-ajax.php'),
                'nonce'   => wp_create_nonce($this->nonce_action),
            ]);
        }

        // Enqueue settings script for settings page
        if ($hook === 'toplevel_page_scbr_settings') {
            wp_enqueue_media();
            wp_enqueue_script(
                'scbr-settings',
                plugin_dir_url(__FILE__) . 'js/scbr-settings.js',
                ['jquery', 'wp-mediaelement'],
                '1.2.3',
                true
            );
            wp_localize_script('scbr-settings', 'scbr_ajax', [
                'ajaxurl' => admin_url('admin-ajax.php'),
            ]);
        }

        // Enqueue broadcast script for broadcast banner
        if ($opts['status'] === 'on' && get_transient($this->transient_broadcast)) {
            wp_enqueue_script(
                'scbr-broadcast',
                plugin_dir_url(__FILE__) . 'js/scbr-broadcast.js',
                [],
                '1.2.3',
                true
            );
        }

        // Enqueue inline style for scroll blocking
        if ($opts['status'] === 'on' && get_transient($this->transient_prefix . $user_id . '_' . $device_id)) {
            wp_add_inline_style('scbr-admin', 'html,body{overflow:hidden !important;}');
        }
    }

    /* ------------------------- Cookie Handling ------------------------- */

    public function ensure_device_cookie() {
        if (!is_admin() || !is_user_logged_in()) return;

        if (empty($_COOKIE[$this->cookie])) {
            $uuid = $this->generate_uuid();
            $secure = is_ssl();
            $httponly = true;
            $path = defined('ADMIN_COOKIE_PATH') ? ADMIN_COOKIE_PATH : '/';
            $domain = COOKIE_DOMAIN ?: '';
            setcookie($this->cookie, $uuid, time() + YEAR_IN_SECONDS, $path, $domain, $secure, $httponly);
            $_COOKIE[$this->cookie] = $uuid;
        }
    }

    /* ----------------------- New Device Detection ----------------------- */

    public function maybe_handle_new_device_detection() {
        $opts = $this->get_opts();
        if (empty($opts) || empty($opts['status']) || $opts['status'] !== 'on') {
            return;
        }
        $this->handle_new_device_detection();
    }

    public function handle_new_device_detection() {
        if (!current_user_can('edit_posts')) return;

        $opts = $this->get_opts();
        if (empty($opts['features']['overlay_enabled'])) return;

        $user_id = get_current_user_id();
        $device_id = $this->current_device_id();
        $ip = $this->ip_address();
        if (!$device_id || $this->is_ip_blocked($ip)) {
            return;
        }

        if ($this->is_user_blocked($user_id)) {
            wp_logout();
            wp_die('Your account has been blocked. Please contact the master admin.');
        }

        $trusted = $this->trusted_devices($user_id);
        $is_trusted = in_array($device_id, $trusted, true);

        if (!$is_trusted) {
            $trigger_key = $this->transient_prefix . $user_id . '_' . $device_id;
            $already_triggered = (bool) get_transient($trigger_key);
            // Keep the overlay active while the user keeps browsing, but only
            // notify ONCE per new device (not on every admin page load).
            set_transient($trigger_key, 1, 10 * MINUTE_IN_SECONDS);

            if (!$already_triggered) {
                $this->broadcast_new_device_event($user_id, $device_id);

                if (!empty($opts['features']['email_alerts'])) {
                    $by = wp_get_current_user();
                    $subject = sprintf('[%s] New Device Login Detected', wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES));
                    $body = sprintf(
                        "User: %s (ID %d)\nTime: %s\nIP: %s\nUser Agent: %s\nDevice ID: %s\n\nThis user logged in from a NEW device and must verify with the Siren Stop Password.",
                        $by->user_login,
                        $by->ID,
                        date_i18n('Y-m-d H:i:s'),
                        $ip,
                        isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'unknown',
                        $device_id
                    );
                    foreach ($this->admin_emails_except($user_id) as $email) {
                        wp_mail($email, $subject, $body);
                    }
                }
            }

        }
    }

    /* ------------------------- Overlay Handling ------------------------- */

    public function maybe_render_new_device_overlay() {
        $uid = get_current_user_id();
        $device_id = $this->current_device_id();
        $opts = $this->get_opts();
        if (empty($opts) || empty($opts['status']) || $opts['status'] !== 'on') return;
        if (!$uid || !$device_id || !get_transient($this->transient_prefix . $uid . '_' . $device_id)) return;
        if (empty($opts['features']['overlay_enabled'])) return;

        $ip = $this->ip_address();
        if ($this->is_ip_blocked($ip)) {
            wp_die('Your IP has been temporarily blocked due to multiple failed password attempts. Please try again later.');
        }

        $this->render_new_device_overlay();
    }

    public function render_new_device_overlay() {
        $opts = $this->get_opts();
        $message = esc_html($opts['overlay_text'] ?? 'Security Verification: Enter Siren Stop Password.');

        $audio_src = !empty($opts['custom_audio_url']) ? esc_url($opts['custom_audio_url']) : 'data:audio/mpeg;base64,' . $this->base64_siren();
        $audio_type = !empty($opts['custom_audio_url']) ? esc_attr('audio/mpeg') : esc_attr('audio/mpeg');
        ?>
        <div id="scbr-overlay">
            <div class="scbr-overlay-bg"></div>
            <div role="dialog" aria-modal="true" aria-labelledby="scbr-title" class="scbr-dialog">
                <h2 id="scbr-title">Security Verification</h2>
                <p><?php echo esc_html($message); ?></p>

                <div class="scbr-input-group">
                    <input type="password" id="scbr-pass" placeholder="Siren Stop Password" autocomplete="off">
                    <button id="scbr-submit" class="button button-primary">Verify & Continue</button>
                </div>
                <div id="scbr-feedback"></div>
            </div>

            <?php if (!empty($opts['features']['siren_enabled'])): ?>
                <audio id="scbr-audio" autoplay loop>
                    <source src="<?php echo esc_url($audio_src); ?>" type="<?php echo esc_attr($audio_type); ?>">
                </audio>
            <?php endif; ?>
        </div>
        <?php
    }

    /* ------------------------- Broadcast UI ------------------------- */

    public function maybe_admin_header_siren() {
        $opts = $this->get_opts();
        if (empty($opts) || empty($opts['status']) || $opts['status'] !== 'on') {
            return;
        }
        if (empty($opts['features']['broadcast_siren'])) {
            return;
        }
        $this->admin_header_siren();
    }

    public function admin_header_siren() {
        if (!current_user_can('edit_posts')) return;
        $opts = $this->get_opts();
        if (empty($opts['features']['broadcast_siren'])) return;

        $broadcast = get_transient($this->transient_broadcast);
        if (!$broadcast) return;

        $muted = get_user_meta(get_current_user_id(), 'scbr_siren_muted', true);
        if ($muted) return;

        $audio_src = !empty($opts['custom_audio_url']) ? esc_url($opts['custom_audio_url']) : 'data:audio/mpeg;base64,' . $this->base64_siren();
        $audio_type = !empty($opts['custom_audio_url']) ? esc_attr('audio/mpeg') : esc_attr('audio/mpeg');

        // Output audio tag
        ?>
        <audio id="scbr-broadcast" style="display:none" loop>
            <source src="<?php echo esc_url($audio_src); ?>" type="<?php echo esc_attr($audio_type); ?>">
        </audio>
        <?php
    }

    public function maybe_render_broadcast_banner() {
        $opts = $this->get_opts();
        if (empty($opts) || empty($opts['status']) || $opts['status'] !== 'on') {
            return;
        }
        if (empty($opts['features']['broadcast_siren'])) {
            return;
        }
        $this->render_broadcast_banner();
    }

    public function render_broadcast_banner() {
        if (!current_user_can('edit_posts')) return;
        $broadcast = get_transient($this->transient_broadcast);
        if (!$broadcast) {
            return;
        }

        $trigger_user = intval($broadcast['user'] ?? 0);
        $current_user_id = get_current_user_id();
        $is_same_user = ($trigger_user === $current_user_id);
        $device_id = $this->current_device_id();
        $is_trigger_device = ($device_id === ($broadcast['device_id'] ?? ''));

        if ($is_trigger_device && !$is_same_user) return;

        $nonce = wp_create_nonce($this->nonce_action);
        $u = get_user_by('id', $trigger_user);
        $name = $u ? esc_html($u->user_login) : esc_html('Unknown User');
        $is_blocked = $this->is_user_blocked($trigger_user);
        $action = $is_blocked ? 'unblock' : 'block';
        $action_label = $is_blocked ? 'Unblock User' : 'Block User';
        ?>
        <div class="notice notice-error is-dismissible scbr-broadcast-notice">
            <?php if ($is_same_user): ?>
                <p><strong>ALERT:</strong> New device login detected for your account (Device ID: <?php echo esc_html($broadcast['device_id'] ?? ''); ?>). Trust the device or contact the master admin to protect the website.</p>
                <p>
                    <button class="button button-primary scbr-action" data-action="trust" data-user-id="<?php echo esc_attr($trigger_user); ?>" data-device-id="<?php echo esc_attr($broadcast['device_id'] ?? ''); ?>" data-nonce="<?php echo esc_attr($nonce); ?>">Trust Device</button>
                    <button class="button scbr-mute" data-nonce="<?php echo esc_attr($nonce); ?>">Mute Siren</button>
                </p>
            <?php else: ?>
                <p><strong>ALERT:</strong> New device login detected for <code><?php echo esc_html($name); ?></code> (ID: <?php echo esc_attr($trigger_user); ?>). Siren active until verified or action taken.</p>
                <p>
                    <?php if ($this->is_master_admin()): ?>
                        <button class="button button-primary scbr-action" data-action="<?php echo esc_attr($action); ?>" data-user-id="<?php echo esc_attr($trigger_user); ?>" data-nonce="<?php echo esc_attr($nonce); ?>"><?php echo esc_html($action_label); ?></button>
                        <button class="button scbr-action" data-action="trust" data-user-id="<?php echo esc_attr($trigger_user); ?>" data-device-id="<?php echo esc_attr($broadcast['device_id'] ?? ''); ?>" data-nonce="<?php echo esc_attr($nonce); ?>">Trust Device</button>
                    <?php endif; ?>
                    <button class="button scbr-mute" data-nonce="<?php echo esc_attr($nonce); ?>">Mute Siren</button>
                </p>
            <?php endif; ?>
        </div>
        <?php
    }

    /* ------------------------- AJAX Handlers ------------------------- */

    public function ajax_stop_siren() {
        if (!is_user_logged_in() || !current_user_can('edit_posts')) {
            wp_send_json_error('Not allowed.', 403);
        }

        check_ajax_referer($this->nonce_action, 'nonce');

        $ip = $this->ip_address();
        if ($this->is_ip_blocked($ip)) {
            wp_send_json_error('Your IP is temporarily blocked due to multiple failed attempts.', 403);
        }

        $opts = $this->get_opts();
        $hash = !empty($opts['siren_password_hash']) ? $opts['siren_password_hash'] : '';

        // The password is verified ONLY here, server-side, with
        // wp_check_password(). The browser never sees the hash and there is
        // no client-computed token path (that was a full bypass).
        $provided = isset($_POST['pass']) ? sanitize_text_field(wp_unslash($_POST['pass'])) : '';

        if ($provided !== '' && $hash !== '' && wp_check_password($provided, $hash)) {
            $user_id = get_current_user_id();
            $device_id = $this->current_device_id();
            if ($device_id) $this->trust_device($user_id, $device_id);
            delete_transient($this->transient_prefix . $user_id . '_' . $device_id);
            delete_user_meta($user_id, $this->attempts_meta);
            delete_transient($this->ip_attempts_prefix . $ip);
            delete_transient($this->transient_broadcast);
            wp_send_json_success(['ok' => 1]);
        }

        $attempts = $this->increment_ip_attempts($ip);
        $remaining = max(0, $this->max_attempts - $attempts);
        wp_send_json_error('Wrong password. Attempts remaining: ' . $remaining);
    }

    public function ajax_block_user() {
        if (!is_user_logged_in() || !$this->is_master_admin()) {
            wp_send_json_error('Not allowed. Only Master Admin can block users.', 403);
        }

        check_ajax_referer($this->nonce_action, 'nonce');

        $target_user_id = isset($_POST['target_user_id']) ? intval($_POST['target_user_id']) : 0;
        if (!$target_user_id || !user_can($target_user_id, 'edit_posts')) {
            wp_send_json_error('Invalid user or user does not have required role.', 400);
        }

        if ($target_user_id === get_current_user_id()) {
            wp_send_json_error('Cannot block yourself.', 400);
        }

        $this->block_user($target_user_id);
        $sessions = WP_Session_Tokens::get_instance($target_user_id);
        $sessions->destroy_all();
        delete_user_meta($target_user_id, 'scbr_trusted_devices');
        delete_transient($this->transient_broadcast);

        $opts = $this->get_opts();
        if (!empty($opts['features']['email_alerts'])) {
            $by = wp_get_current_user();
            $target = get_user_by('id', $target_user_id);
            $subject = sprintf('[%s] User Blocked', wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES));
            $body = sprintf(
                "User %s (ID %d) has been blocked by %s (ID %d) due to a suspicious login.\nTime: %s\nIP: %s",
                $target->user_login,
                $target->ID,
                $by->user_login,
                $by->ID,
                date_i18n('Y-m-d H:i:s'),
                $this->ip_address()
            );
            foreach ($this->admin_emails_except($by->ID) as $email) {
                wp_mail($email, $subject, $body);
            }
        }

        wp_send_json_success(['ok' => 1]);
    }

    public function ajax_unblock_user() {
        if (!is_user_logged_in() || !$this->is_master_admin()) {
            wp_send_json_error('Not allowed. Only Master Admin can unblock users.', 403);
        }

        check_ajax_referer($this->nonce_action, 'nonce');

        $target_user_id = isset($_POST['target_user_id']) ? intval($_POST['target_user_id']) : 0;
        if (!$target_user_id || !user_can($target_user_id, 'edit_posts')) {
            wp_send_json_error('Invalid user or user does not have required role.', 400);
        }

        if ($target_user_id === get_current_user_id()) {
            wp_send_json_error('Cannot unblock yourself.', 400);
        }

        $this->unblock_user($target_user_id);

        $opts = $this->get_opts();
        if (!empty($opts['features']['email_alerts'])) {
            $by = wp_get_current_user();
            $target = get_user_by('id', $target_user_id);
            $subject = sprintf('[%s] User Unblocked', wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES));
            $body = sprintf(
                "User %s (ID %d) has been unblocked by %s (ID %d).\nTime: %s\nIP: %s",
                $target->user_login,
                $target->ID,
                $by->user_login,
                $by->ID,
                date_i18n('Y-m-d H:i:s'),
                $this->ip_address()
            );
            foreach ($this->admin_emails_except($by->ID) as $email) {
                wp_mail($email, $subject, $body);
            }
        }

        wp_send_json_success(['ok' => 1]);
    }

    public function ajax_trust_device() {
        if (!is_user_logged_in() || !current_user_can('edit_posts')) {
            wp_send_json_error('Not allowed.', 403);
        }

        check_ajax_referer($this->nonce_action, 'nonce');

        $target_user_id = isset($_POST['target_user_id']) ? intval($_POST['target_user_id']) : 0;
        $device_id = isset($_POST['device_id']) ? sanitize_text_field(wp_unslash($_POST['device_id'])) : '';

        if (!$target_user_id || !user_can($target_user_id, 'edit_posts') || !$device_id) {
            wp_send_json_error('Invalid user or device.', 400);
        }

        // A user may trust their OWN device; trusting anyone else's device
        // requires the Master Admin.
        if ($target_user_id !== get_current_user_id() && !$this->is_master_admin()) {
            wp_send_json_error('Not allowed. Only the Master Admin can trust devices for other users.', 403);
        }

        $this->trust_device($target_user_id, $device_id);
        delete_transient($this->transient_prefix . $target_user_id . '_' . $device_id);
        delete_transient($this->transient_broadcast);

        $opts = $this->get_opts();
        if (!empty($opts['features']['email_alerts'])) {
            $by = wp_get_current_user();
            $target = get_user_by('id', $target_user_id);
            $subject = sprintf('[%s] Device Trusted', wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES));
            $body = sprintf(
                "Device for user %s (ID %d) has been trusted by %s (ID %d).\nTime: %s\nIP: %s",
                $target->user_login,
                $target->ID,
                $by->user_login,
                $by->ID,
                date_i18n('Y-m-d H:i:s'),
                $this->ip_address()
            );
            foreach ($this->admin_emails_except($by->ID) as $email) {
                wp_mail($email, $subject, $body);
            }
        }

        wp_send_json_success(['ok' => 1]);
    }

    public function ajax_remove_device() {
        if (!is_user_logged_in() || !current_user_can('administrator') || !$this->is_master_admin()) {
            wp_send_json_error('Not allowed.', 403);
        }

        check_ajax_referer($this->nonce_action, 'nonce');

        $target_user_id = isset($_POST['target_user_id']) ? intval($_POST['target_user_id']) : 0;
        $device_id = isset($_POST['device_id']) ? sanitize_text_field(wp_unslash($_POST['device_id'])) : '';

        if (!$target_user_id || !user_can($target_user_id, 'edit_posts') || !$device_id) {
            wp_send_json_error('Invalid user or device.', 400);
        }

        if ($target_user_id === get_current_user_id()) {
            wp_send_json_error('Cannot remove your own devices.', 400);
        }

        $this->remove_device($target_user_id, $device_id);

        $opts = $this->get_opts();
        if (!empty($opts['features']['email_alerts'])) {
            $by = wp_get_current_user();
            $target = get_user_by('id', $target_user_id);
            $subject = sprintf('[%s] Device Removed', wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES));
            $body = sprintf(
                "A trusted device for user %s (ID %d) was removed by %s (ID %d).\nTime: %s\nIP: %s",
                $target->user_login,
                $target->ID,
                $by->user_login,
                $by->ID,
                date_i18n('Y-m-d H:i:s'),
                $this->ip_address()
            );
            foreach ($this->admin_emails_except($by->ID) as $email) {
                wp_mail($email, $subject, $body);
            }
        }

        wp_send_json_success(['ok' => 1]);
    }

    public function ajax_mute_siren() {
        if (!is_user_logged_in() || !current_user_can('edit_posts')) {
            wp_send_json_error('Not allowed.', 403);
        }

        check_ajax_referer($this->nonce_action, 'nonce');

        update_user_meta(get_current_user_id(), 'scbr_siren_muted', 1);
        wp_send_json_success(['ok' => 1]);
    }

    /* ------------------------------ Settings UI ------------------------------ */

    public function register_settings_page() {
        add_menu_page(
            'Defentry',
            'Defentry',
            'manage_options',
            'scbr_settings',
            [$this, 'render_settings_page'],
            'dashicons-shield',
            65
        );
    }

    public function render_settings_page() {
        if (!$this->is_master_admin()) {
            wp_die(esc_html(__('Only the Master Admin can access Defentry settings.', 'defentry')));
        }
        $opts = $this->get_opts();
        $nonce = wp_create_nonce($this->nonce_action);

        wp_enqueue_media();
        ?>
        <div class="wrap">
            <h1>Defentry — Master Control Panel</h1>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data">
                <input type="hidden" name="action" value="scbr_save_settings">
                <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">Status</th>
                        <td>
                            <label><input type="radio" name="status" value="on" <?php checked(!empty($opts['status']) && $opts['status'] === 'on'); ?>> ON</label>
                            &nbsp;&nbsp;
                            <label><input type="radio" name="status" value="off" <?php checked(empty($opts['status']) || $opts['status'] === 'off'); ?>> OFF</label>
                            <p class="description">When OFF the plugin does not monitor logins or trigger siren. Only Master Admin can toggle.</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="siren_password">Siren Stop Password</label></th>
                        <td>
                            <input name="siren_password" id="siren_password" type="password" class="regular-text" value="" placeholder="Leave blank to keep the current password" autocomplete="new-password" />
                            <p class="description">For security the current password is never shown. Enter a new one only to change it.</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="custom_audio">Custom Siren Audio</label></th>
                        <td>
                            <input type="text" name="custom_audio_url" id="custom_audio_url" class="regular-text" value="<?php echo esc_attr($opts['custom_audio_url'] ?? ''); ?>" readonly />
                            <input type="button" class="button" id="upload_audio_button" value="Upload Audio" />
                            <p class="description">Upload an MP3 file for the siren sound. Leave empty to use the default siren.</p>
                            <?php if (!empty($opts['custom_audio_url'])): ?>
                                <p><a href="<?php echo esc_url($opts['custom_audio_url']); ?>" target="_blank">Listen to current audio</a> | <a href="#" id="clear_audio">Clear custom audio</a></p>
                            <?php endif; ?>
                        </td>
                    </tr>

                    <tr><th>Features</th><td>
                        <label><input type="checkbox" name="features[siren_enabled]" value="1" <?php checked(!empty($opts['features']['siren_enabled'])); ?>> Enable Siren Sound</label><br>
                        <label><input type="checkbox" name="features[overlay_enabled]" value="1" <?php checked(!empty($opts['features']['overlay_enabled'])); ?>> Full-Screen Overlay on New Device</label><br>
                        <label><input type="checkbox" name="features[broadcast_siren]" value="1" <?php checked(!empty($opts['features']['broadcast_siren'])); ?>> Siren for Other Users</label><br>
                        <label><input type="checkbox" name="features[email_alerts]" value="1" <?php checked(!empty($opts['features']['email_alerts'])); ?>> Email Alerts to Other Users</label>
                    </td></tr>

                    <tr>
                        <th scope="row"><label for="overlay_text">Overlay Message</label></th>
                        <td><input name="overlay_text" id="overlay_text" type="text" class="regular-text" value="<?php echo esc_attr($opts['overlay_text'] ?? ''); ?>"></td>
                    </tr>

                    <tr>
                        <th scope="row">Master Admin</th>
                        <td>
                            <?php
                            $current = intval($opts['master_admin_id'] ?? 0);
                            $admins = get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login', 'user_email']]);
                            ?>
                            <select name="master_admin_id">
                                <?php foreach ($admins as $a): ?>
                                    <option value="<?php echo esc_attr($a->ID); ?>" <?php selected($current === intval($a->ID)); ?>>
                                        <?php echo esc_html($a->user_login . " (ID {$a->ID})"); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                            <p class="description">Only the Master Admin can change these settings.</p>
                            <p class="description">Note: Master Admin must be an Administrator, not an Editor or Author.</p>
                        </td>
                    </tr>
                </table>

                <?php submit_button('Save Settings'); ?>
            </form>

            <hr />

            <h2>Manage Trusted Devices</h2>
            <p>Remove trusted devices for any user account or reset all devices.</p>
            <?php
            foreach ($this->admins_list() as $admin) {
                $devices = $this->trusted_devices($admin->ID);
                if (!empty($devices)) {
                    echo '<h3>' . esc_html($admin->user_login) . ' (ID ' . esc_attr($admin->ID) . ')</h3>';
                    echo '<ul>';
                    foreach ($devices as $device_id) {
                        echo '<li>Device ID: ' . esc_html($device_id) . ' <button class="button scbr-remove-device" data-user-id="' . esc_attr($admin->ID) . '" data-device-id="' . esc_attr($device_id) . '" data-nonce="' . esc_attr($nonce) . '">Remove</button></li>';
                    }
                    echo '</ul>';
                } else {
                    echo '<p>No trusted devices for ' . esc_html($admin->user_login) . ' (ID ' . esc_attr($admin->ID) . ').</p>';
                }
            }
            ?>

            <h2>Manage Blocked Users</h2>
            <p>Unblock users who have been previously blocked.</p>
            <?php
            $blocked_users = get_option($this->blocked_users_key, []);
            if (!empty($blocked_users)) {
                echo '<ul>';
                foreach ($blocked_users as $user_id) {
                    $user = get_user_by('id', $user_id);
                    if ($user) {
                        echo '<li>User: ' . esc_html($user->user_login) . ' (ID ' . esc_attr($user_id) . ') <button class="button scbr-unblock-user" data-user-id="' . esc_attr($user_id) . '" data-nonce="' . esc_attr($nonce) . '">Unblock</button></li>';
                    }
                }
                echo '</ul>';
            } else {
                echo '<p>No users are currently blocked.</p>';
            }
            ?>

            <h3>Reset All Trusted Devices</h3>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:flex;gap:10px;align-items:center">
                <input type="hidden" name="action" value="scbr_trust_reset">
                <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">
                <select name="target_user_id">
                    <?php foreach ($this->admins_list() as $a): ?>
                        <option value="<?php echo esc_attr($a->ID); ?>"><?php echo esc_html($a->user_login . " (ID {$a->ID})"); ?></option>
                    <?php endforeach; ?>
                </select>
                <?php submit_button('Reset Trusted Devices', 'delete', 'submit', false); ?>
            </form>
        </div>
        <?php
    }

    public function handle_save_settings() {
        if (!current_user_can('manage_options')) wp_die('No permission');
        check_admin_referer($this->nonce_action, 'nonce');
        if (!$this->is_master_admin()) wp_die('Only Master Admin can save settings');

        $opts = $this->get_opts();

        $opts['status'] = isset($_POST['status']) && $_POST['status'] === 'on' ? 'on' : 'off';

        $new_pwd = isset($_POST['siren_password']) ? sanitize_text_field(wp_unslash($_POST['siren_password'])) : '';
        if ($new_pwd !== '') {
            // Hashed with wp_hash_password(); the plaintext is never stored.
            $opts['siren_password_hash'] = wp_hash_password($new_pwd);
        }
        unset($opts['siren_password']); // legacy plaintext key must not survive

        $opts['custom_audio_url'] = isset($_POST['custom_audio_url']) ? esc_url_raw(wp_unslash($_POST['custom_audio_url'])) : '';

        $features = isset($_POST['features']) && is_array($_POST['features']) ? array_map('intval', $_POST['features']) : [];
        $opts['features'] = [
            'siren_enabled'   => !empty($features['siren_enabled']) ? 1 : 0,
            'email_alerts'    => !empty($features['email_alerts']) ? 1 : 0,
            'overlay_enabled' => !empty($features['overlay_enabled']) ? 1 : 0,
            'broadcast_siren' => !empty($features['broadcast_siren']) ? 1 : 0,
        ];

        if (isset($_POST['overlay_text'])) {
            $opts['overlay_text'] = sanitize_text_field(wp_unslash($_POST['overlay_text']));
        }

        if (isset($_POST['master_admin_id'])) {
            $opts['master_admin_id'] = intval($_POST['master_admin_id']);
            $opts['needs_master_admin'] = 0;
        }

        update_option($this->opt_key, $opts);
        wp_safe_redirect(add_query_arg(['page' => 'scbr_settings', 'updated' => '1'], admin_url('admin.php')));
        exit;
    }

    public function handle_trust_reset() {
        if (!current_user_can('manage_options')) wp_die('No permission');
        check_admin_referer($this->nonce_action, 'nonce');
        if (!$this->is_master_admin()) wp_die('Only Master Admin can reset');

        $target = isset($_POST['target_user_id']) ? intval($_POST['target_user_id']) : 0;
        if ($target) delete_user_meta($target, 'scbr_trusted_devices');
        wp_safe_redirect(add_query_arg(['page' => 'scbr_settings', 'reset' => '1'], admin_url('admin.php')));
        exit;
    }

    /* ---------------------- Master Admin First-Run UI ---------------------- */

    public function maybe_prompt_master_admin() {
        if (!current_user_can('manage_options')) return;
        $opts = $this->get_opts();
        if (empty($opts['needs_master_admin'])) return;

        $admins = get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login', 'user_email']]);
        $nonce = wp_create_nonce($this->nonce_action);

        echo '<div class="notice notice-warning">';
        echo '<p><strong>Defentry:</strong> Select a <em>Master Admin</em> to finalize setup. Plugin is OFF by default. After setup, change the siren stop password in the Defentry settings.</p>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="scbr_set_master">';
        echo '<input type="hidden" name="nonce" value="' . esc_attr($nonce) . '">';
        echo '<select name="master_admin_id">';
        foreach ($admins as $a) {
            echo '<option value="' . esc_attr($a->ID) . '">' . esc_html($a->user_login . " (ID {$a->ID})") . '</option>';
        }
        echo '</select> ';
        submit_button('Set Master Admin', 'primary', 'submit', false);
        echo '</form>';
        echo '</div>';
    }

    public function handle_set_master_admin() {
        if (!current_user_can('manage_options')) wp_die('No permission');
        check_admin_referer($this->nonce_action, 'nonce');
        $opts = $this->get_opts();
        $mid = isset($_POST['master_admin_id']) ? intval($_POST['master_admin_id']) : 0;
        if ($mid > 0) {
            $opts['master_admin_id'] = $mid;
            $opts['needs_master_admin'] = 0;
            update_option($this->opt_key, $opts);
        }
        wp_safe_redirect(admin_url('index.php'));
        exit;
    }

    /* ----------------------- Embedded Audio (Base64) ----------------------- */

    private function base64_siren() {
        return 'SUQzAwAAAAAAFlRTU0UAAAAPAAADTGF2ZjU2LjQwLjEwMAAAAAAAAAAAAAAA//tQxAADBQAAQAAAABEVmVyc2lvbiB0aW55IGJpcCBhbGFybQAA//uQZAAAAAD6AAAAAAAACQAAABJbmZvAAAACAAAAG1wMyB0aW55AAACAAAB//uQZAAAABkAABp6AAACAAABAAAAP///8AAAP//AAAAP///8AAAAD//wA=';
    }
}

new SCBR_Security_Control_Master();
?>