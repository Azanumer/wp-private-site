<?php
/**
 * Plugin Name:       WP Private Site
 * Plugin URI:        https://github.com/Azanumer/wp-private-site
 * Description:       Makes the whole site private: visitors must log in to see anything. Public allow-list for chosen pages, plus optional IP allow-list and REST/feed blocking.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Azan Umer
 * Author URI:        https://github.com/Azanumer
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-private-site
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WPS_VERSION', '1.0.0' );
define( 'WPS_OPTION', 'wps_settings' );

/**
 * Default settings.
 *
 * @return array
 */
function wps_default_settings() {
    return array(
        'enabled'       => true,
        'allow_pages'   => '',
        'allow_ips'     => '',
        'block_rest'    => true,
        'block_feeds'   => true,
        'redirect_page' => 0, // 0 = wp-login.php.
    );
}

/**
 * Get a setting value.
 *
 * @param string $key Setting key.
 * @return mixed
 */
function wps_get_setting( $key ) {
    $settings = get_option( WPS_OPTION, array() );
    $defaults = wps_default_settings();
    if ( isset( $settings[ $key ] ) ) {
        return $settings[ $key ];
    }
    return isset( $defaults[ $key ] ) ? $defaults[ $key ] : null;
}

/**
 * Client IP, honouring the common proxy headers only when the request
 * actually came through a trusted proxy is out of scope here; the direct
 * remote address is used, with X-Forwarded-For honoured only as a
 * last-resort convenience for sites known to sit behind a proxy.
 * Filter 'wps_client_ip' lets a site override this entirely.
 *
 * @return string
 */
function wps_client_ip() {
    $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
    return (string) apply_filters( 'wps_client_ip', $ip );
}

/**
 * Check an IP against an allow-list of single IPs and CIDR ranges.
 *
 * @param string $ip    Client IP.
 * @param string $list  Newline-separated IPs / CIDR ranges.
 * @return bool
 */
function wps_ip_allowed( $ip, $list ) {
    if ( '' === $ip ) {
        return false;
    }
    $ip_bin = @inet_pton( $ip );
    if ( false === $ip_bin ) {
        return false;
    }
    foreach ( explode( "\n", $list ) as $entry ) {
        $entry = trim( $entry );
        if ( '' === $entry ) {
            continue;
        }
        if ( false !== strpos( $entry, '/' ) ) {
            list( $range, $bits ) = explode( '/', $entry, 2 );
            $bits     = (int) $bits;
            $range_bin = @inet_pton( trim( $range ) );
            if ( false === $range_bin || strlen( $range_bin ) !== strlen( $ip_bin ) ) {
                continue;
            }
            $max_bits = strlen( $ip_bin ) * 8;
            if ( $bits < 0 || $bits > $max_bits ) {
                continue;
            }
            // Compare the first $bits bits.
            $full_bytes = (int) ( $bits / 8 );
            $rem_bits   = $bits % 8;
            if ( 0 !== $full_bytes && substr( $ip_bin, 0, $full_bytes ) !== substr( $range_bin, 0, $full_bytes ) ) {
                continue;
            }
            if ( 0 !== $rem_bits ) {
                $mask = ( 0xFF << ( 8 - $rem_bits ) ) & 0xFF;
                if ( ( ord( $ip_bin[ $full_bytes ] ) & $mask ) !== ( ord( $range_bin[ $full_bytes ] ) & $mask ) ) {
                    continue;
                }
            }
            return true;
        }
        if ( $ip === $entry ) {
            return true;
        }
    }
    return false;
}

/**
 * Is the current request allowed to stay public?
 *
 * @return bool
 */
function wps_request_is_public() {
    // Login, registration, password reset and admin-ajax always stay open.
    $script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) : '';
    if ( in_array( $script, array( 'wp-login.php', 'wp-register.php', 'wp-cron.php', 'xmlrpc.php' ), true ) ) {
        return true;
    }
    if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
        return true;
    }
    if ( is_admin() ) {
        return true;
    }
    // Allow-listed pages (slugs, one per line).
    $allow = array_filter( array_map( 'trim', explode( "\n", (string) wps_get_setting( 'allow_pages' ) ) ) );
    if ( ! empty( $allow ) ) {
        global $wp;
        $path = isset( $wp->request ) ? trim( (string) $wp->request, '/' ) : '';
        foreach ( $allow as $slug ) {
            $slug = trim( $slug, '/' );
            if ( $path === $slug || 0 === strpos( $path, $slug . '/' ) ) {
                return true;
            }
        }
        if ( is_page() ) {
            $page = get_queried_object();
            if ( $page && isset( $page->post_name ) && in_array( $page->post_name, $allow, true ) ) {
                return true;
            }
        }
    }
    return (bool) apply_filters( 'wps_request_is_public', false );
}

/**
 * Enforce privacy on the front end.
 */
function wps_enforce_privacy() {
    if ( ! wps_get_setting( 'enabled' ) ) {
        return;
    }
    if ( is_user_logged_in() ) {
        return;
    }
    // IP allow-list bypasses the login wall entirely.
    $allow_ips = (string) wps_get_setting( 'allow_ips' );
    if ( '' !== trim( $allow_ips ) && wps_ip_allowed( wps_client_ip(), $allow_ips ) ) {
        return;
    }
    if ( wps_request_is_public() ) {
        return;
    }
    $redirect_page = (int) wps_get_setting( 'redirect_page' );
    if ( $redirect_page > 0 && get_post( $redirect_page ) ) {
        wp_safe_redirect( get_permalink( $redirect_page ), 302 );
        exit;
    }
    auth_redirect();
}
add_action( 'template_redirect', 'wps_enforce_privacy' );

/**
 * Block the REST API for anonymous visitors when enabled.
 *
 * @param WP_Error|null|bool $result Authentication result.
 * @return WP_Error|null|bool
 */
function wps_rest_block( $result ) {
    if ( ! wps_get_setting( 'enabled' ) || ! wps_get_setting( 'block_rest' ) ) {
        return $result;
    }
    if ( is_user_logged_in() ) {
        return $result;
    }
    if ( wps_ip_allowed( wps_client_ip(), (string) wps_get_setting( 'allow_ips' ) ) ) {
        return $result;
    }
    return new WP_Error(
        'rest_forbidden',
        __( 'This site is private. Please log in to use the REST API.', 'wp-private-site' ),
        array( 'status' => 401 )
    );
}
add_filter( 'rest_authentication_errors', 'wps_rest_block' );

/**
 * Block RSS/Atom feeds for anonymous visitors when enabled.
 */
function wps_block_feeds() {
    if ( ! wps_get_setting( 'enabled' ) || ! wps_get_setting( 'block_feeds' ) ) {
        return;
    }
    if ( is_user_logged_in() ) {
        return;
    }
    if ( is_feed() ) {
        wp_die(
            esc_html__( 'This site is private. Please log in to view the feed.', 'wp-private-site' ),
            esc_html__( 'Private Site', 'wp-private-site' ),
            array( 'response' => 401 )
        );
    }
}
add_action( 'template_redirect', 'wps_block_feeds', 5 );

/**
 * Hide the site from search engines while it is private.
 *
 * @param bool $public Whether the site is public.
 * @return bool
 */
function wps_blog_public( $public ) {
    if ( wps_get_setting( 'enabled' ) ) {
        return false;
    }
    return $public;
}
add_filter( 'pre_option_blog_public', 'wps_blog_public' );

/**
 * Register the settings page.
 */
function wps_admin_menu() {
    add_options_page(
        __( 'Private Site', 'wp-private-site' ),
        __( 'Private Site', 'wp-private-site' ),
        'manage_options',
        'wp-private-site',
        'wps_settings_page'
    );
}
add_action( 'admin_menu', 'wps_admin_menu' );

/**
 * Register settings.
 */
function wps_admin_init() {
    register_setting(
        'wps_settings_group',
        WPS_OPTION,
        array( 'sanitize_callback' => 'wps_sanitize_settings' )
    );
    add_settings_section( 'wps_main', __( 'Privacy Settings', 'wp-private-site' ), '__return_false', 'wp-private-site' );
    add_settings_field( 'wps_enabled', __( 'Make site private', 'wp-private-site' ), 'wps_field_enabled', 'wp-private-site', 'wps_main' );
    add_settings_field( 'wps_allow_pages', __( 'Public pages (slugs, one per line)', 'wp-private-site' ), 'wps_field_allow_pages', 'wp-private-site', 'wps_main' );
    add_settings_field( 'wps_allow_ips', __( 'IP allow-list (one per line, CIDR ok)', 'wp-private-site' ), 'wps_field_allow_ips', 'wp-private-site', 'wps_main' );
    add_settings_field( 'wps_block_rest', __( 'Block REST API for guests', 'wp-private-site' ), 'wps_field_block_rest', 'wp-private-site', 'wps_main' );
    add_settings_field( 'wps_block_feeds', __( 'Block feeds for guests', 'wp-private-site' ), 'wps_field_block_feeds', 'wp-private-site', 'wps_main' );
    add_settings_field( 'wps_redirect_page', __( 'Redirect guests to this page (0 = login)', 'wp-private-site' ), 'wps_field_redirect_page', 'wp-private-site', 'wps_main' );
}
add_action( 'admin_init', 'wps_admin_init' );

/**
 * Sanitize settings input.
 *
 * @param array $input Raw input.
 * @return array
 */
function wps_sanitize_settings( $input ) {
    $out                    = wps_default_settings();
    $out['enabled']         = ! empty( $input['enabled'] );
    $out['block_rest']      = ! empty( $input['block_rest'] );
    $out['block_feeds']     = ! empty( $input['block_feeds'] );
    $out['redirect_page']   = isset( $input['redirect_page'] ) ? absint( $input['redirect_page'] ) : 0;
    $pages                  = array();
    if ( isset( $input['allow_pages'] ) ) {
        foreach ( explode( "\n", (string) $input['allow_pages'] ) as $line ) {
            $line = trim( $line, " \t\r\n/" );
            if ( '' !== $line ) {
                $pages[] = sanitize_title( $line );
            }
        }
    }
    $out['allow_pages'] = implode( "\n", $pages );
    $ips                = array();
    if ( isset( $input['allow_ips'] ) ) {
        foreach ( explode( "\n", (string) $input['allow_ips'] ) as $line ) {
            $line = trim( $line );
            if ( '' === $line ) {
                continue;
            }
            // Keep only valid IPs or valid CIDR ranges.
            if ( false !== strpos( $line, '/' ) ) {
                list( $range, $bits ) = explode( '/', $line, 2 );
                if ( false === @inet_pton( trim( $range ) ) || ! is_numeric( $bits ) ) {
                    continue;
                }
                $ips[] = trim( $range ) . '/' . (int) $bits;
            } elseif ( false !== @inet_pton( $line ) ) {
                $ips[] = $line;
            }
        }
    }
    $out['allow_ips'] = implode( "\n", $ips );
    return $out;
}

function wps_field_enabled() {
    printf(
        '<input type="checkbox" name="%s[enabled]" value="1" %s />',
        esc_attr( WPS_OPTION ),
        checked( wps_get_setting( 'enabled' ), true, false )
    );
}

function wps_field_allow_pages() {
    printf(
        '<textarea name="%s[allow_pages]" rows="4" cols="50" class="large-text code">%s</textarea>',
        esc_attr( WPS_OPTION ),
        esc_textarea( (string) wps_get_setting( 'allow_pages' ) )
    );
    echo '<p class="description">' . esc_html__( 'e.g. "contact" stays public, and so do its children like "contact/thanks".', 'wp-private-site' ) . '</p>';
}

function wps_field_allow_ips() {
    printf(
        '<textarea name="%s[allow_ips]" rows="4" cols="50" class="large-text code">%s</textarea>',
        esc_attr( WPS_OPTION ),
        esc_textarea( (string) wps_get_setting( 'allow_ips' ) )
    );
    echo '<p class="description">' . esc_html__( 'Single IPs (203.0.113.5) or CIDR ranges (203.0.113.0/24). These visitors skip the login wall.', 'wp-private-site' ) . '</p>';
}

function wps_field_block_rest() {
    printf(
        '<input type="checkbox" name="%s[block_rest]" value="1" %s />',
        esc_attr( WPS_OPTION ),
        checked( wps_get_setting( 'block_rest' ), true, false )
    );
}

function wps_field_block_feeds() {
    printf(
        '<input type="checkbox" name="%s[block_feeds]" value="1" %s />',
        esc_attr( WPS_OPTION ),
        checked( wps_get_setting( 'block_feeds' ), true, false )
    );
}

function wps_field_redirect_page() {
    printf(
        '<input type="number" min="0" name="%s[redirect_page]" value="%d" class="small-text" />',
        esc_attr( WPS_OPTION ),
        (int) wps_get_setting( 'redirect_page' )
    );
    echo '<p class="description">' . esc_html__( 'Post ID of a page to send guests to (e.g. a "Request Access" page). 0 sends them to wp-login.php.', 'wp-private-site' ) . '</p>';
}

/**
 * Render the settings page.
 */
function wps_settings_page() {
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'Private Site', 'wp-private-site' ); ?></h1>
        <form method="post" action="options.php">
            <?php
            settings_fields( 'wps_settings_group' );
            do_settings_sections( 'wp-private-site' );
            submit_button();
            ?>
        </form>
        <p class="description"><?php esc_html_e( 'While private, the site is also hidden from search engines (blog_public is forced to 0). Logged-in users, wp-login.php, wp-cron.php and admin-ajax.php are never blocked.', 'wp-private-site' ); ?></p>
    </div>
    <?php
}
