<?php
/**
 * Defentry uninstall cleanup.
 *
 * Removes all options, transients and user meta created by the plugin
 * (including legacy wrs_ prefixed data from pre-1.1 installs).
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// Options.
delete_option('scbr_settings');
delete_option('scbr_blocked_users');
delete_option('wrs_sc_settings');
delete_option('wrs_sc_blocked_users');

// Transients (both timeout and value rows, current + legacy prefixes).
// Caching is deliberately not used: this runs once at uninstall, when the
// plugin (and its cache groups) are being removed, so there is nothing to cache for.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall cleanup, no user input.
$wpdb->query(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_scbr_%' OR option_name LIKE '_transient_timeout_scbr_%' OR option_name LIKE '_transient_wrs_%' OR option_name LIKE '_transient_timeout_wrs_%'"
);

// User meta.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall cleanup, no user input.
$wpdb->query(
    "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN ('scbr_trusted_devices','scbr_siren_muted','scbr_attempts','wrs_sc_trusted_devices','wrs_sc_siren_muted')"
);
