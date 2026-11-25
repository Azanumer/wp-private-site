# WP Private Site

Makes the whole WordPress site private: anonymous visitors are sent to the login screen (or a page of your choice) before they can see any content. Ideal for staging sites, intranets, client previews, and sites under development.

## What gets blocked

- **Every front-end page** for logged-out visitors (`template_redirect` → `auth_redirect()`).
- **REST API** for guests (401 `rest_forbidden`), unless you turn it off.
- **RSS/Atom feeds** for guests (401), unless you turn it off.
- **Search engines**: `blog_public` is forced to `0` while the site is private, so no indexing.

## What stays open

- `wp-login.php`, `wp-register.php`, `wp-cron.php`, `admin-ajax.php` — the site can still function.
- Logged-in users see everything normally.
- Pages you allow-list by slug (e.g. `contact` — children like `contact/thanks` stay public too).
- IPs on the allow-list skip the login wall entirely.

## Settings

**Settings → Private Site**

| Setting | Default |
|---|---|
| Make site private | On |
| Public pages (slugs, one per line) | — |
| IP allow-list (one per line, CIDR ok) | — |
| Block REST API for guests | On |
| Block feeds for guests | On |
| Redirect guests to this page (0 = login) | 0 |

The IP allow-list accepts single IPv4/IPv6 addresses (`203.0.113.5`) and CIDR ranges (`203.0.113.0/24`, `2001:db8::/32`). Invalid entries are dropped on save.

## Filters

- `wps_client_ip( string $ip )` — override how the client IP is determined (e.g. behind a trusted proxy).
- `wps_request_is_public( bool $public )` — mark a request public from code.

## Requirements

- WordPress 5.8+
- PHP 7.4+

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
