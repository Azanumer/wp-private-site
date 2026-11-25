<?php
/**
 * Uninstall WP Private Site.
 *
 * Deletes the plugin option. No content is touched.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

delete_option( 'wps_settings' );
