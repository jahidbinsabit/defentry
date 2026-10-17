<?php
/*
Plugin Name: Defentry - Smart Security & Login Protection
Description: Defentry is a lightweight WordPress device-based login protection plugin. When an admin, editor or author logs in from a new device, a verification overlay blocks the dashboard until a stop password is entered, while other users get a real-time alert banner. Includes master admin control, trusted device management, IP attempt limiting and email alerts.
Version: 2.0.5
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
            add_action('wp_ajax_scbr_check_broadcast', [$this, 'ajax_check_broadcast']);
            add_action('wp_ajax_scbr_block_ip', [$this, 'ajax_block_ip']);
            add_action('wp_ajax_scbr_unmute_siren', [$this, 'ajax_unmute_siren']);

            // Security headers (was dead code — now actually hooked).
            add_action('send_headers', [$this, 'set_security_headers']);

            // Settings & master admin
            add_action('admin_menu', [$this, 'register_settings_page']);
            add_action('admin_notices', [$this, 'maybe_prompt_master_admin']);
            add_action('admin_post_scbr_set_master', [$this, 'handle_set_master_admin']);
            add_action('admin_post_scbr_save_settings', [$this, 'handle_save_settings']);
            add_action('admin_post_scbr_trust_reset', [$this, 'handle_trust_reset']);

            // Dashboard widget (read-only security overview).
            add_action('wp_dashboard_setup', [$this, 'register_dashboard_widget']);
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
            'ip'    => $this->ip_address(),
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

        // Enqueue styles for relevant admin pages. The settings page and the
        // dashboard widget always need the v2 styles, even when protection is
        // off; when protection is on, every admin page needs them (broadcast
        // banner, overlay, realtime alerts).
        if ($hook === 'toplevel_page_scbr_settings' ||
            $hook === 'dashboard' ||
            $opts['status'] === 'on'
        ) {
            wp_enqueue_style(
                'scbr-admin',
                plugin_dir_url(__FILE__) . 'css/scbr-admin.css',
                [],
                '2.0.5'
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
                '2.0.5',
                true
            );
            wp_localize_script('scbr-overlay', 'scbr_ajax', [
                'ajaxurl' => admin_url('admin-ajax.php'),
                'nonce'   => wp_create_nonce($this->nonce_action),
            ]);
        }

        // Enqueue settings script. Banner action buttons (trust/block/mute)
        // render on every admin page via admin_notices, so their handlers must
        // be present globally whenever protection is on (delegated binding).
        if ($hook === 'toplevel_page_scbr_settings' || $opts['status'] === 'on') {
            wp_enqueue_media();
            wp_enqueue_script(
                'scbr-settings',
                plugin_dir_url(__FILE__) . 'js/scbr-settings.js',
                ['jquery', 'wp-mediaelement'],
                '2.0.5',
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
                '2.0.5',
                true
            );
        }

        // Realtime broadcast poller: lets other logged-in admins see and hear
        // a new-device alert without reloading the page.
        if ($opts['status'] === 'on' && !empty($opts['features']['broadcast_siren']) && current_user_can('edit_posts')) {
            wp_enqueue_script(
                'scbr-broadcast-poll',
                plugin_dir_url(__FILE__) . 'js/scbr-broadcast-poll.js',
                [],
                '2.0.5',
                true
            );
            wp_localize_script('scbr-broadcast-poll', 'scbrPoll', [
                'ajaxurl' => admin_url('admin-ajax.php'),
                'nonce'   => wp_create_nonce($this->nonce_action),
            ]);
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
        $siren_muted = (bool) get_user_meta(get_current_user_id(), 'scbr_siren_muted', true);

        $audio_src = !empty($opts['custom_audio_url']) ? esc_url($opts['custom_audio_url']) : 'data:audio/mpeg;base64,' . $this->base64_siren();
        $audio_type = !empty($opts['custom_audio_url']) ? esc_attr('audio/mpeg') : esc_attr('audio/mpeg');
        ?>
        <div id="scbr-overlay">
            <div class="scbr-overlay-bg"></div>
            <div class="scbr2-overlay-center">
                <div role="dialog" aria-modal="true" aria-labelledby="scbr-title" class="scbr-dialog scbr2-dialog">
                    <div class="scbr2-dialog-shield" aria-hidden="true">
                        <svg viewBox="0 0 24 24" width="44" height="44" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-3.6 8-10V5l-8-3-8 3v7c0 6.4 8 10 8 10z"/><path d="M9 11.5l2 2 4-4.5"/></svg>
                    </div>
                    <h2 id="scbr-title"><?php esc_html_e('Security Verification', 'defentry'); ?></h2>
                    <p class="scbr2-dialog-sub"><?php echo esc_html($message); ?></p>

                    <div class="scbr-input-group">
                        <label class="screen-reader-text" for="scbr-pass"><?php esc_html_e('Siren Stop Password', 'defentry'); ?></label>
                        <input type="password" id="scbr-pass" placeholder="<?php esc_attr_e('Siren Stop Password', 'defentry'); ?>" autocomplete="off">
                        <button id="scbr-submit" class="button button-primary scbr2-verify-btn"><?php esc_html_e('Verify & Continue', 'defentry'); ?></button>
                    </div>
                    <div id="scbr-feedback" role="alert" aria-live="polite"></div>
                    <p class="scbr2-dialog-hint"><?php esc_html_e('This device is not recognized. Verification is required before you can continue.', 'defentry'); ?></p>
                    <p class="scbr2-dialog-sound">
                        <button type="button" id="scbr-sound-toggle" class="scbr2-link-btn" data-muted="<?php echo $siren_muted ? '1' : '0'; ?>" data-label-on="<?php esc_attr_e('Turn siren sound on', 'defentry'); ?>" data-label-off="<?php esc_attr_e('Turn siren sound off', 'defentry'); ?>" title="<?php esc_attr_e('Mute or unmute the siren on your browsers', 'defentry'); ?>">
                            <?php echo $siren_muted ? esc_html__('Turn siren sound on', 'defentry') : esc_html__('Turn siren sound off', 'defentry'); ?>
                        </button>
                    </p>
                </div>
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

    /**
     * Siren audio source for the broadcast alert, or '' when it must not play
     * (feature off, no active alert, user muted, or insufficient caps).
     */
    private function get_broadcast_audio_src() {
        if (!current_user_can('edit_posts')) return '';
        $opts = $this->get_opts();
        if (empty($opts['features']['broadcast_siren'])) return '';

        if (!get_transient($this->transient_broadcast)) return '';

        $muted = get_user_meta(get_current_user_id(), 'scbr_siren_muted', true);
        if ($muted) return '';

        $opts = $this->get_opts();
        return !empty($opts['custom_audio_url']) ? esc_url($opts['custom_audio_url']) : 'data:audio/mpeg;base64,' . $this->base64_siren();
    }

    public function admin_header_siren() {
        $audio_src = $this->get_broadcast_audio_src();
        if (!$audio_src) return;

        // Output audio tag
        ?>
        <audio id="scbr-broadcast" style="display:none" loop>
            <source src="<?php echo esc_url($audio_src); ?>" type="audio/mpeg">
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
        $siren_muted = (bool) get_user_meta(get_current_user_id(), 'scbr_siren_muted', true);
        $mute_class = $siren_muted ? 'scbr-unmute' : 'scbr-mute';
        $mute_label = $siren_muted ? __('Unmute Siren', 'defentry') : __('Mute Siren', 'defentry');
        ?>
        <div class="notice notice-error is-dismissible scbr-broadcast-notice scbr2-banner" data-scbr-token="<?php echo esc_attr($broadcast['token'] ?? ''); ?>">
            <span class="scbr2-banner-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg></span>
            <div class="scbr2-banner-body">
            <?php if ($is_same_user): ?>
                <p><strong>ALERT:</strong> New device login detected for your account (Device ID: <?php echo esc_html($broadcast['device_id'] ?? ''); ?>). Trust the device or contact the master admin to protect the website.</p>
                <p>
                    <button class="button button-primary scbr-action" data-action="trust" data-user-id="<?php echo esc_attr($trigger_user); ?>" data-device-id="<?php echo esc_attr($broadcast['device_id'] ?? ''); ?>" data-nonce="<?php echo esc_attr($nonce); ?>">Trust Device</button>
                    <button class="button <?php echo esc_attr($mute_class); ?>" data-nonce="<?php echo esc_attr($nonce); ?>"><?php echo esc_html($mute_label); ?></button>
                    <?php if ($this->is_master_admin() && !$is_trigger_device): ?>
                    <button class="button scbr-block-ip" data-nonce="<?php echo esc_attr($nonce); ?>" title="<?php esc_attr_e('Instantly block the IP of the new device for 1 hour', 'defentry'); ?>">Block IP</button>
                    <?php endif; ?>
                </p>
            <?php else: ?>
                <p><strong>ALERT:</strong> New device login detected for <code><?php echo esc_html($name); ?></code> (ID: <?php echo esc_attr($trigger_user); ?>). Siren active until verified or action taken.</p>
                <p>
                    <?php if ($this->is_master_admin()): ?>
                        <button class="button button-primary scbr-action" data-action="<?php echo esc_attr($action); ?>" data-user-id="<?php echo esc_attr($trigger_user); ?>" data-nonce="<?php echo esc_attr($nonce); ?>"><?php echo esc_html($action_label); ?></button>
                        <button class="button scbr-action" data-action="trust" data-user-id="<?php echo esc_attr($trigger_user); ?>" data-device-id="<?php echo esc_attr($broadcast['device_id'] ?? ''); ?>" data-nonce="<?php echo esc_attr($nonce); ?>">Trust Device</button>
                    <?php endif; ?>
                    <button class="button <?php echo esc_attr($mute_class); ?>" data-nonce="<?php echo esc_attr($nonce); ?>"><?php echo esc_html($mute_label); ?></button>
                </p>
            <?php endif; ?>
            </div><!-- .scbr2-banner-body -->
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

        // Instantly block the IP tied to the active new-device alert for this
        // user, so the suspicious device is locked out immediately.
        $broadcast = get_transient($this->transient_broadcast);
        if (!empty($broadcast['ip'])
            && intval($broadcast['user'] ?? 0) === $target_user_id
            && filter_var($broadcast['ip'], FILTER_VALIDATE_IP)
        ) {
            set_transient($this->ip_blocked_prefix . $broadcast['ip'], 1, HOUR_IN_SECONDS);
            delete_transient($this->ip_attempts_prefix . $broadcast['ip']);
        }

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

    /**
     * Realtime broadcast check for the admin poller. Returns the rendered
     * warning banner HTML plus the siren audio source so other logged-in
     * admins see and hear a new-device alert without reloading the page.
     */
    public function ajax_check_broadcast() {
        if (!is_user_logged_in() || !current_user_can('edit_posts')) {
            wp_send_json_error('Not allowed.', 403);
        }

        check_ajax_referer($this->nonce_action, 'nonce');

        $opts = $this->get_opts();
        if (empty($opts['status']) || $opts['status'] !== 'on' || empty($opts['features']['broadcast_siren'])) {
            wp_send_json_success(['active' => false]);
        }

        $broadcast = get_transient($this->transient_broadcast);
        if (!$broadcast) {
            wp_send_json_success(['active' => false]);
        }

        ob_start();
        $this->render_broadcast_banner();
        $html = ob_get_clean();

        wp_send_json_success([
            'active'    => true,
            'token'     => $broadcast['token'] ?? '',
            'html'      => $html,
            'audio_src' => $this->get_broadcast_audio_src(),
        ]);
    }

    /**
     * Instantly block the IP tied to the active new-device alert.
     * Master Admin only. Used by the "Block IP" banner button.
     */
    public function ajax_block_ip() {
        if (!is_user_logged_in() || !$this->is_master_admin()) {
            wp_send_json_error('Not allowed. Only Master Admin can block IPs.', 403);
        }

        check_ajax_referer($this->nonce_action, 'nonce');

        $broadcast = get_transient($this->transient_broadcast);
        $ip = $broadcast['ip'] ?? '';
        if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error('No active alert IP to block.', 400);
        }

        set_transient($this->ip_blocked_prefix . $ip, 1, HOUR_IN_SECONDS);
        delete_transient($this->ip_attempts_prefix . $ip);

        wp_send_json_success(['ok' => 1, 'ip' => $ip]);
    }

    /**
     * Re-enable the broadcast siren after it was muted. Any user who could
     * mute it can unmute it.
     */
    public function ajax_unmute_siren() {
        if (!is_user_logged_in() || !current_user_can('edit_posts')) {
            wp_send_json_error('Not allowed.', 403);
        }

        check_ajax_referer($this->nonce_action, 'nonce');

        delete_user_meta(get_current_user_id(), 'scbr_siren_muted');
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
        // The control plane is Master-Admin-exclusive: once setup is done,
        // secondary admins don't even see the menu. (First-run wizard stays
        // open to all admins; direct URL access still hits the wp_die guard.)
        $opts = $this->get_opts();
        if (empty($opts['needs_master_admin']) && !$this->is_master_admin()) {
            remove_menu_page('scbr_settings');
        }
    }

    public function render_settings_page() {
        $opts = $this->get_opts();
        $needs_setup = !empty($opts['needs_master_admin']);

        // First run: any administrator may open the setup wizard (the same
        // audience the existing admin-notice form already serves). Once a
        // Master Admin exists, only they may open these settings.
        if ($needs_setup) {
            if (!current_user_can('manage_options')) {
                wp_die(esc_html(__('Only an administrator can set up Defentry.', 'defentry')));
            }
        } elseif (!$this->is_master_admin()) {
            wp_die(esc_html(__('Only the Master Admin can access Defentry settings.', 'defentry')));
        }

        $nonce = wp_create_nonce($this->nonce_action);
        wp_enqueue_media();

        // First-run setup wizard.
        if ($needs_setup) {
            $this->render_setup_wizard($nonce);
            return;
        }
        // Wizard steps 2-3, shown right after step 1 was saved.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only render-path switch; state changes happen in nonce-verified admin_post handlers.
        if (isset($_GET['scbr_wizard'])) {
            $this->render_setup_wizard_steps_23($opts, $nonce);
            return;
        }

        $tabs = [
            'overview'     => __('Overview', 'defentry'),
            'verification' => __('Verification', 'defentry'),
            'devices'      => __('Devices', 'defentry'),
            'protection'   => __('Protection', 'defentry'),
            'master'       => __('Master Admin', 'defentry'),
        ];
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only tab switch; value is sanitized with sanitize_key() and whitelisted against $tabs.
        $tab = isset($_GET['scbr_tab']) ? sanitize_key(wp_unslash($_GET['scbr_tab'])) : 'overview';
        if (!isset($tabs[$tab])) {
            $tab = 'overview';
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only success notice; the save itself is nonce-verified in handle_save_settings().
        if (isset($_GET['updated'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html(__('Defentry settings saved.', 'defentry')) . '</p></div>';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only success notice; the reset itself is nonce-verified in handle_trust_reset().
        if (isset($_GET['reset'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html(__('Trusted devices have been reset.', 'defentry')) . '</p></div>';
        }
        ?>
        <div class="wrap scbr2-wrap">
            <h1 class="scbr2-title"><span class="dashicons dashicons-shield scbr2-title-icon"></span> <?php esc_html_e('Defentry — Master Control Panel', 'defentry'); ?></h1>

            <h2 class="nav-tab-wrapper scbr2-tabs">
                <?php foreach ($tabs as $id => $label): ?>
                    <a href="<?php echo esc_url(add_query_arg('scbr_tab', $id)); ?>"
                       class="nav-tab <?php echo $tab === $id ? 'nav-tab-active' : ''; ?>"
                       data-scbr-tab="<?php echo esc_attr($id); ?>"><?php echo esc_html($label); ?></a>
                <?php endforeach; ?>
            </h2>

            <div class="scbr2-panels">
                <div class="scbr2-panel" data-scbr-panel="overview" <?php echo $tab !== 'overview' ? 'hidden' : ''; ?>>
                    <?php $this->render_overview_tab($opts, $nonce); ?>
                </div>
                <div class="scbr2-panel" data-scbr-panel="verification" <?php echo $tab !== 'verification' ? 'hidden' : ''; ?>>
                    <?php $this->render_verification_tab($opts, $nonce); ?>
                </div>
                <div class="scbr2-panel" data-scbr-panel="devices" <?php echo $tab !== 'devices' ? 'hidden' : ''; ?>>
                    <?php $this->render_devices_tab($nonce); ?>
                </div>
                <div class="scbr2-panel" data-scbr-panel="protection" <?php echo $tab !== 'protection' ? 'hidden' : ''; ?>>
                    <?php $this->render_protection_tab($nonce); ?>
                </div>
                <div class="scbr2-panel" data-scbr-panel="master" <?php echo $tab !== 'master' ? 'hidden' : ''; ?>>
                    <?php $this->render_master_tab($opts, $nonce); ?>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Total trusted devices across all monitored users.
     * Presentation helper only — reads existing user meta.
     */
    private function count_trusted_devices() {
        $total = 0;
        foreach ($this->admins_list() as $u) {
            $total += count($this->trusted_devices($u->ID));
        }
        return $total;
    }

    /**
     * Hidden fields that carry the current feature flags and siren audio URL
     * through partial settings forms (Overview toggle, Master Admin tab,
     * setup wizard). Without them, saving a partial form would reset the
     * untouched settings to their defaults. Presentation only.
     */
    private function render_passthrough_fields($opts) {
        $features = $opts['features'] ?? [];
        foreach (['siren_enabled', 'email_alerts', 'overlay_enabled', 'broadcast_siren'] as $key) {
            printf(
                '<input type="hidden" name="features[%s]" value="%d">' . "\n",
                esc_attr($key),
                !empty($features[$key]) ? 1 : 0
            );
        }
        printf(
            '<input type="hidden" name="custom_audio_url" value="%s">' . "\n",
            esc_attr($opts['custom_audio_url'] ?? '')
        );
    }

    private function render_overview_tab($opts, $nonce) {
        $is_on = !empty($opts['status']) && $opts['status'] === 'on';
        $trusted_total = $this->count_trusted_devices();
        $blocked_total = count(get_option($this->blocked_users_key, []));
        ?>
        <div class="scbr2-card scbr2-status-card">
            <div class="scbr2-status-main">
                <span class="scbr2-pill <?php echo $is_on ? 'scbr2-pill-on' : 'scbr2-pill-off'; ?>">
                    <?php echo $is_on ? esc_html__('Protection ON', 'defentry') : esc_html__('Protection OFF', 'defentry'); ?>
                </span>
                <p class="scbr2-muted">
                    <?php
                    echo $is_on
                        ? esc_html__('New-device verification, siren alerts, and IP attempt limiting are active.', 'defentry')
                        : esc_html__('Defentry is not monitoring logins. Turn protection on to activate verification.', 'defentry');
                    ?>
                </p>
            </div>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="scbr2-status-form">
                <input type="hidden" name="action" value="scbr_save_settings">
                <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">
                <?php $this->render_passthrough_fields($opts); ?>
                <label class="scbr2-switch" title="<?php esc_attr_e('Toggle protection', 'defentry'); ?>">
                    <input type="checkbox" name="status" value="on" <?php checked($is_on); ?>>
                    <span class="scbr2-slider" aria-hidden="true"></span>
                    <span class="screen-reader-text"><?php esc_html_e('Protection status', 'defentry'); ?></span>
                </label>
                <?php submit_button(__('Save', 'defentry'), 'primary', 'submit', false); ?>
            </form>
        </div>

        <div class="scbr2-tiles">
            <div class="scbr2-tile">
                <span class="scbr2-tile-num"><?php echo esc_html(number_format_i18n($trusted_total)); ?></span>
                <span class="scbr2-tile-label"><?php esc_html_e('Trusted devices', 'defentry'); ?></span>
                <a class="scbr2-tile-link" href="<?php echo esc_url(add_query_arg('scbr_tab', 'devices')); ?>" data-scbr-tab="devices"><?php esc_html_e('Manage →', 'defentry'); ?></a>
            </div>
            <div class="scbr2-tile">
                <span class="scbr2-tile-num"><?php echo esc_html(number_format_i18n($blocked_total)); ?></span>
                <span class="scbr2-tile-label"><?php esc_html_e('Blocked users', 'defentry'); ?></span>
                <a class="scbr2-tile-link" href="<?php echo esc_url(add_query_arg('scbr_tab', 'protection')); ?>" data-scbr-tab="protection"><?php esc_html_e('Manage →', 'defentry'); ?></a>
            </div>
            <div class="scbr2-tile">
                <span class="scbr2-tile-num">3</span>
                <span class="scbr2-tile-label"><?php esc_html_e('Failed attempts before IP block', 'defentry'); ?></span>
                <a class="scbr2-tile-link" href="<?php echo esc_url(add_query_arg('scbr_tab', 'protection')); ?>" data-scbr-tab="protection"><?php esc_html_e('Details →', 'defentry'); ?></a>
            </div>
        </div>
        <?php
    }

    private function render_verification_tab($opts, $nonce) {
        $features = $opts['features'] ?? [];
        $feature_defs = [
            'siren_enabled'   => [__('Enable Siren Sound', 'defentry'), __('Play the siren when a new device needs verification.', 'defentry')],
            'overlay_enabled' => [__('Full-Screen Overlay', 'defentry'), __('Block the screen with the red verification prompt on new devices.', 'defentry')],
            'broadcast_siren' => [__('Siren for Other Admins', 'defentry'), __('Other logged-in admins hear the siren and see the blinking alert banner.', 'defentry')],
            'email_alerts'    => [__('Email Alerts', 'defentry'), __('Notify other admins by email about new device logins.', 'defentry')],
        ];
        ?>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data" class="scbr2-form">
            <input type="hidden" name="action" value="scbr_save_settings">
            <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">

            <div class="scbr2-card">
                <h2><span class="dashicons dashicons-lock"></span><?php esc_html_e('Siren Stop Password', 'defentry'); ?></h2>
                <div class="scbr2-field">
                    <label class="scbr2-label" for="siren_password"><?php esc_html_e('New stop password', 'defentry'); ?></label>
                    <input name="siren_password" id="siren_password" type="password" class="regular-text" value="" placeholder="<?php esc_attr_e('Leave blank to keep the current password', 'defentry'); ?>" autocomplete="new-password" />
                    <p class="scbr2-hint"><?php esc_html_e('For security the current password is never shown. Enter a new one only to change it.', 'defentry'); ?></p>
                </div>
                <div class="scbr2-field">
                    <label class="scbr2-label" for="overlay_text"><?php esc_html_e('Overlay message', 'defentry'); ?></label>
                    <input name="overlay_text" id="overlay_text" type="text" class="regular-text" value="<?php echo esc_attr($opts['overlay_text'] ?? ''); ?>">
                </div>
            </div>

            <div class="scbr2-card">
                <h2><span class="dashicons dashicons-megaphone"></span><?php esc_html_e('Siren Audio', 'defentry'); ?></h2>
                <div class="scbr2-field">
                    <label class="scbr2-label" for="custom_audio_url"><?php esc_html_e('Custom siren sound (MP3)', 'defentry'); ?></label>
                    <input type="text" name="custom_audio_url" id="custom_audio_url" class="regular-text" value="<?php echo esc_attr($opts['custom_audio_url'] ?? ''); ?>" readonly />
                    <input type="button" class="button" id="upload_audio_button" value="<?php esc_attr_e('Upload Audio', 'defentry'); ?>" />
                    <p class="scbr2-hint"><?php esc_html_e('Leave empty to use the default siren.', 'defentry'); ?></p>
                    <?php if (!empty($opts['custom_audio_url'])): ?>
                        <p><a href="<?php echo esc_url($opts['custom_audio_url']); ?>" target="_blank" rel="noopener"><?php esc_html_e('Listen to current audio', 'defentry'); ?></a> &middot; <a href="#" id="clear_audio"><?php esc_html_e('Clear custom audio', 'defentry'); ?></a></p>
                    <?php endif; ?>
                </div>
            </div>

            <div class="scbr2-card">
                <h2><span class="dashicons dashicons-bell"></span><?php esc_html_e('Alert Features', 'defentry'); ?></h2>
                <div class="scbr2-toggle-list">
                    <?php foreach ($feature_defs as $key => $def): ?>
                    <div class="scbr2-toggle-row">
                        <div class="scbr2-toggle-text">
                            <strong><?php echo esc_html($def[0]); ?></strong>
                            <span><?php echo esc_html($def[1]); ?></span>
                        </div>
                        <label class="scbr2-switch">
                            <input type="checkbox" name="features[<?php echo esc_attr($key); ?>]" value="1" <?php checked(!empty($features[$key])); ?>>
                            <span class="scbr2-slider" aria-hidden="true"></span>
                            <span class="screen-reader-text"><?php echo esc_html($def[0]); ?></span>
                        </label>
                    </div>
                    <?php endforeach; ?>
                </div>
                <div class="scbr2-card-actions">
                    <?php submit_button(__('Save Settings', 'defentry'), 'primary', 'submit', false); ?>
                </div>
            </div>
        </form>
        <?php
    }

    private function render_devices_tab($nonce) {
        ?>
        <div class="scbr2-form">
            <div class="scbr2-card">
                <h2><span class="dashicons dashicons-smartphone"></span><?php esc_html_e('Trusted Devices', 'defentry'); ?></h2>
                <p class="scbr2-muted"><?php esc_html_e('Every admin account below lists its trusted devices. Remove any device you no longer recognize.', 'defentry'); ?></p>
                <?php foreach ($this->admins_list() as $admin):
                    $devices = $this->trusted_devices($admin->ID);
                    $is_self = intval($admin->ID) === get_current_user_id();
                ?>
                    <div class="scbr2-subcard">
                        <div class="scbr2-user-head">
                            <span class="dashicons dashicons-admin-users"></span>
                            <strong><?php echo esc_html($admin->user_login); ?><?php echo $is_self ? ' ' . esc_html__('(you)', 'defentry') : ''; ?></strong>
                            <span class="scbr2-count-badge"><?php echo esc_html(number_format_i18n(count($devices))); ?></span>
                        </div>
                        <?php if (!empty($devices)): ?>
                            <?php foreach ($devices as $device_id): ?>
                            <div class="scbr2-row">
                                <code><?php echo esc_html($device_id); ?></code>
                                <button class="button scbr-remove-device" data-user-id="<?php echo esc_attr($admin->ID); ?>" data-device-id="<?php echo esc_attr($device_id); ?>" data-nonce="<?php echo esc_attr($nonce); ?>"><?php esc_html_e('Remove', 'defentry'); ?></button>
                            </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <p class="scbr2-muted"><?php esc_html_e('No trusted devices yet.', 'defentry'); ?></p>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>

            <div class="scbr2-card scbr2-danger">
                <h2><span class="dashicons dashicons-warning"></span><?php esc_html_e('Danger Zone', 'defentry'); ?></h2>
                <p class="scbr2-muted"><?php esc_html_e('Reset all trusted devices for a user. They will need to verify with the Siren Stop Password on their next visit.', 'defentry'); ?></p>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="scbr2-inline-form">
                    <input type="hidden" name="action" value="scbr_trust_reset">
                    <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">
                    <select name="target_user_id" aria-label="<?php esc_attr_e('User', 'defentry'); ?>">
                        <?php foreach ($this->admins_list() as $a): ?>
                            <option value="<?php echo esc_attr($a->ID); ?>"><?php echo esc_html($a->user_login . " (ID {$a->ID})"); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <?php submit_button(__('Reset Trusted Devices', 'defentry'), 'delete', 'submit', false); ?>
                </form>
            </div>
        </div>
        <?php
    }

    private function render_protection_tab($nonce) {
        $blocked_users = get_option($this->blocked_users_key, []);
        ?>
        <div class="scbr2-form">
            <div class="scbr2-card">
                <h2><span class="dashicons dashicons-dismiss"></span><?php esc_html_e('Blocked Users', 'defentry'); ?></h2>
                <p class="scbr2-muted"><?php esc_html_e('Blocked users are logged out instantly on their next visit. Unblock them here when the threat is over.', 'defentry'); ?></p>
                <?php if (!empty($blocked_users)): ?>
                    <?php foreach ($blocked_users as $user_id):
                        $user = get_user_by('id', $user_id);
                        if (!$user) continue;
                    ?>
                    <div class="scbr2-row">
                        <div class="scbr2-user-head" style="margin-bottom:0;">
                            <span class="dashicons dashicons-admin-users"></span>
                            <strong><?php echo esc_html($user->user_login); ?></strong>
                            <span class="scbr2-muted">(ID <?php echo esc_html($user_id); ?>)</span>
                        </div>
                        <button class="button scbr-unblock-user" data-user-id="<?php echo esc_attr($user_id); ?>" data-nonce="<?php echo esc_attr($nonce); ?>"><?php esc_html_e('Unblock', 'defentry'); ?></button>
                    </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div class="scbr2-empty">
                        <span class="dashicons dashicons-shield-alt"></span>
                        <p><?php esc_html_e('No users are currently blocked. All clear.', 'defentry'); ?></p>
                    </div>
                <?php endif; ?>
            </div>

            <div class="scbr2-card">
                <h2><span class="dashicons dashicons-shield"></span><?php esc_html_e('IP Attempt Limiting', 'defentry'); ?></h2>
                <div class="scbr2-tiles">
                    <div class="scbr2-tile">
                        <span class="scbr2-tile-num"><?php echo esc_html(number_format_i18n($this->max_attempts)); ?></span>
                        <span class="scbr2-tile-label"><?php esc_html_e('Failed attempts before IP block', 'defentry'); ?></span>
                    </div>
                    <div class="scbr2-tile">
                        <span class="scbr2-tile-num"><?php esc_html_e('1 hour', 'defentry'); ?></span>
                        <span class="scbr2-tile-label"><?php esc_html_e('IP block duration', 'defentry'); ?></span>
                    </div>
                </div>
                <p class="scbr2-muted"><?php esc_html_e('After too many wrong stop-password attempts from the same IP address, that IP is temporarily blocked. Detection uses REMOTE_ADDR only, so attackers cannot evade it by spoofing forwarded headers.', 'defentry'); ?></p>
            </div>
        </div>
        <?php
    }

    private function render_master_tab($opts, $nonce) {
        $current = intval($opts['master_admin_id'] ?? 0);
        $current_user = $current ? get_user_by('id', $current) : null;
        $admins = get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login']]);
        ?>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="scbr2-form">
            <input type="hidden" name="action" value="scbr_save_settings">
            <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">
            <?php $this->render_passthrough_fields($opts); ?>
            <div class="scbr2-card">
                <h2><span class="dashicons dashicons-super-admin"></span><?php esc_html_e('Master Admin', 'defentry'); ?></h2>
                <p class="scbr2-muted"><?php esc_html_e('Only the Master Admin can open these settings, block users or IPs, and trust devices for other users. Other admins are still protected by verification, but cannot change anything.', 'defentry'); ?></p>
                <?php if ($current_user): ?>
                <div class="scbr2-current">
                    <span class="dashicons dashicons-super-admin"></span>
                    <div>
                        <strong><?php echo esc_html($current_user->user_login); ?></strong>
                        <span><?php esc_html_e('Current Master Admin', 'defentry'); ?></span>
                    </div>
                </div>
                <?php endif; ?>
                <div class="scbr2-field">
                    <label class="scbr2-label" for="master_admin_id"><?php esc_html_e('Transfer the Master Admin role', 'defentry'); ?></label>
                    <select name="master_admin_id" id="master_admin_id">
                        <?php foreach ($admins as $a): ?>
                            <option value="<?php echo esc_attr($a->ID); ?>" <?php selected($current === intval($a->ID)); ?>>
                                <?php echo esc_html($a->user_login . " (ID {$a->ID})"); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <p class="scbr2-hint"><?php esc_html_e('The Master Admin must be an Administrator. Transferring takes effect immediately.', 'defentry'); ?></p>
                </div>
                <div class="scbr2-card-actions">
                    <?php submit_button(__('Save Settings', 'defentry'), 'primary', 'submit', false); ?>
                </div>
            </div>
        </form>
        <?php
    }

    /* ------------------------- Setup Wizard (first run) ------------------------- */

    private function render_setup_wizard($nonce) {
        $admins = get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login']]);
        $current_user = get_current_user_id();
        $return_url = add_query_arg(['page' => 'scbr_settings', 'scbr_wizard' => 2], admin_url('admin.php'));
        ?>
        <div class="wrap scbr2-wrap">
            <h1 class="scbr2-title"><span class="dashicons dashicons-shield scbr2-title-icon"></span> <?php esc_html_e('Defentry — Setup Wizard', 'defentry'); ?></h1>
            <div class="scbr2-card scbr2-wizard">
                <ol class="scbr2-steps">
                    <li class="scbr2-step is-active"><span class="scbr2-step-n">1</span> <?php esc_html_e('Master Admin', 'defentry'); ?></li>
                    <li class="scbr2-step"><span class="scbr2-step-n">2</span> <?php esc_html_e('Stop Password', 'defentry'); ?></li>
                    <li class="scbr2-step"><span class="scbr2-step-n">3</span> <?php esc_html_e('Turn On', 'defentry'); ?></li>
                </ol>
                <div class="scbr2-wizard-body">
                    <h2><?php esc_html_e('Step 1 of 3 — Choose the Master Admin', 'defentry'); ?></h2>
                    <p class="scbr2-muted"><?php esc_html_e('The Master Admin owns Defentry settings and is the only one who can block users or trust devices for others.', 'defentry'); ?></p>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="scbr_set_master">
                        <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">
                        <input type="hidden" name="scbr_return" value="<?php echo esc_attr($return_url); ?>">
                        <p>
                            <select name="master_admin_id" aria-label="<?php esc_attr_e('Master Admin', 'defentry'); ?>">
                                <?php foreach ($admins as $a): ?>
                                    <option value="<?php echo esc_attr($a->ID); ?>" <?php selected(intval($current_user) === intval($a->ID)); ?>>
                                        <?php echo esc_html($a->user_login . " (ID {$a->ID})"); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </p>
                        <p>
                            <?php submit_button(__('Continue →', 'defentry'), 'primary', 'submit', false); ?>
                            <a class="scbr2-skip" href="<?php echo esc_url(admin_url('index.php')); ?>"><?php esc_html_e('Skip for now', 'defentry'); ?></a>
                        </p>
                    </form>
                </div>
            </div>
        </div>
        <?php
    }

    private function render_setup_wizard_steps_23($opts, $nonce) {
        // Only the newly chosen Master Admin can finish the setup.
        if (!$this->is_master_admin()) {
            $mid = intval($opts['master_admin_id'] ?? 0);
            $mu = $mid ? get_user_by('id', $mid) : null;
            $who = $mu ? $mu->user_login : __('the Master Admin', 'defentry');
            ?>
            <div class="wrap scbr2-wrap">
                <h1 class="scbr2-title"><span class="dashicons dashicons-shield scbr2-title-icon"></span> <?php esc_html_e('Defentry — Setup Wizard', 'defentry'); ?></h1>
                <div class="scbr2-card">
                    <h2><?php esc_html_e('Almost done', 'defentry'); ?></h2>
                    <p><?php echo sprintf(
                        /* translators: %s: master admin login */
                        esc_html__('Please ask %s to open the Defentry settings to finish the setup (steps 2 and 3).', 'defentry'),
                        '<strong>' . esc_html($who) . '</strong>'
                    ); ?></p>
                </div>
            </div>
            <?php
            return;
        }
        ?>
        <div class="wrap scbr2-wrap">
            <h1 class="scbr2-title"><span class="dashicons dashicons-shield scbr2-title-icon"></span> <?php esc_html_e('Defentry — Setup Wizard', 'defentry'); ?></h1>
            <div class="scbr2-card scbr2-wizard">
                <ol class="scbr2-steps">
                    <li class="scbr2-step is-done"><span class="scbr2-step-n">✓</span> <?php esc_html_e('Master Admin', 'defentry'); ?></li>
                    <li class="scbr2-step is-active" data-scbr-wstep="2"><span class="scbr2-step-n">2</span> <?php esc_html_e('Stop Password', 'defentry'); ?></li>
                    <li class="scbr2-step" data-scbr-wstep="3"><span class="scbr2-step-n">3</span> <?php esc_html_e('Turn On', 'defentry'); ?></li>
                </ol>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" id="scbr2-wizard-form">
                    <input type="hidden" name="action" value="scbr_save_settings">
                    <input type="hidden" name="nonce" value="<?php echo esc_attr($nonce); ?>">
                    <input type="hidden" name="status" value="on">
                    <?php $this->render_passthrough_fields($opts); ?>
                    <div class="scbr2-wizard-body" data-scbr-wpane="2">
                        <h2><?php esc_html_e('Step 2 of 3 — Set the Siren Stop Password', 'defentry'); ?></h2>
                        <p class="scbr2-muted"><?php esc_html_e('This password stops the siren and verifies new devices. The default (2210) must be changed — pick something only you know.', 'defentry'); ?></p>
                        <p><input name="siren_password" id="scbr2-wizard-pass" type="password" class="regular-text" value="" autocomplete="new-password" required minlength="4" /></p>
                        <p><button type="button" class="button button-primary" data-scbr-wnext="3"><?php esc_html_e('Continue →', 'defentry'); ?></button></p>
                    </div>
                    <div class="scbr2-wizard-body" data-scbr-wpane="3" hidden>
                        <h2><?php esc_html_e('Step 3 of 3 — Turn protection ON', 'defentry'); ?></h2>
                        <p class="scbr2-muted"><?php esc_html_e('Defentry will start verifying new devices immediately: unknown devices face the stop-password overlay and siren, and other users get a real-time alert banner.', 'defentry'); ?></p>
                        <p>
                            <button type="button" class="button" data-scbr-wprev="2"><?php esc_html_e('← Back', 'defentry'); ?></button>
                            <?php submit_button(__('Finish Setup', 'defentry'), 'primary', 'submit', false); ?>
                        </p>
                    </div>
                </form>
            </div>
        </div>
        <?php
    }

    /* ------------------------- Dashboard Widget ------------------------- */

    public function register_dashboard_widget() {
        if (!current_user_can('edit_posts')) {
            return;
        }
        // Dashboard widget is part of the control plane: Master Admin only
        // once setup is complete.
        $opts = $this->get_opts();
        if (empty($opts['needs_master_admin']) && !$this->is_master_admin()) {
            return;
        }
        wp_add_dashboard_widget(
            'scbr_security_widget',
            __('Defentry Security', 'defentry'),
            [$this, 'render_dashboard_widget']
        );
    }

    public function render_dashboard_widget() {
        $opts = $this->get_opts();
        $is_on = !empty($opts['status']) && $opts['status'] === 'on';
        $trusted_total = $this->count_trusted_devices();
        $blocked_total = count(get_option($this->blocked_users_key, []));
        ?>
        <div class="scbr2-widget">
            <p>
                <span class="scbr2-pill <?php echo $is_on ? 'scbr2-pill-on' : 'scbr2-pill-off'; ?>">
                    <?php echo $is_on ? esc_html__('Protection ON', 'defentry') : esc_html__('Protection OFF', 'defentry'); ?>
                </span>
            </p>
            <ul class="scbr2-widget-stats">
                <li><strong><?php echo esc_html(number_format_i18n($trusted_total)); ?></strong> <?php esc_html_e('trusted devices', 'defentry'); ?></li>
                <li><strong><?php echo esc_html(number_format_i18n($blocked_total)); ?></strong> <?php esc_html_e('blocked users', 'defentry'); ?></li>
            </ul>
            <?php if ($this->is_master_admin()): ?>
                <p><a href="<?php echo esc_url(admin_url('admin.php?page=scbr_settings')); ?>"><?php esc_html_e('Open Defentry settings →', 'defentry'); ?></a></p>
            <?php endif; ?>
        </div>
        <?php
    }

    public function handle_save_settings() {
        if (!current_user_can('manage_options')) wp_die('No permission');
        check_admin_referer($this->nonce_action, 'nonce');
        if (!$this->is_master_admin()) wp_die('Only Master Admin can save settings');

        $opts = $this->get_opts();

        // Only touch the status when the submitted form manages it (Overview
        // toggle, setup wizard). Other tabs must never silently flip it.
        if (isset($_POST['status'])) {
            $opts['status'] = $_POST['status'] === 'on' ? 'on' : 'off';
        }

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
        // Optional same-admin return URL (used by the setup wizard).
        // Restricted to admin URLs only; defaults to the dashboard.
        $redirect = admin_url('index.php');
        if (!empty($_POST['scbr_return'])) {
            $candidate = esc_url_raw(wp_unslash($_POST['scbr_return']));
            if (is_string($candidate) && strpos($candidate, admin_url()) === 0) {
                $redirect = $candidate;
            }
        }
        wp_safe_redirect($redirect);
        exit;
    }

    /* ----------------------- Embedded Audio (Base64) ----------------------- */

    private function base64_siren() {
        return 'SUQzAwAAAAAAFlRTU0UAAAAPAAADTGF2ZjU2LjQwLjEwMAAAAAAAAAAAAAAA//tQxAADBQAAQAAAABEVmVyc2lvbiB0aW55IGJpcCBhbGFybQAA//uQZAAAAAD6AAAAAAAACQAAABJbmZvAAAACAAAAG1wMyB0aW55AAACAAAB//uQZAAAABkAABp6AAACAAABAAAAP///8AAAP//AAAAP///8AAAAD//wA=';
    }
}

new SCBR_Security_Control_Master();
?>