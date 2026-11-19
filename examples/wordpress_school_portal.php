<?php

/**
 * Plugin Name: AI Agent Link Check
 * Description: Holds comments and posts that link to AI agent domains for review, and adds a [aab_check] form for staff.
 * Version: 1.0.0
 *
 * A must-use plugin for a school or intranet WordPress site. Put the
 * Composer autoloader and a synced aab_full.json next to it, then copy this
 * file to wp-content/mu-plugins/.
 */

declare(strict_types=1);

use AiAgentBlocklist\Blocklist;

require_once __DIR__ . '/aiagentblocklist/vendor/autoload.php';

const AAB_JSON = WP_CONTENT_DIR . '/uploads/aab/aab_full.json';

function aab_blocklist(): ?Blocklist
{
    static $list = null;
    if ($list === null && is_readable(AAB_JSON)) {
        $list = Blocklist::fromFile(AAB_JSON);
    }

    return $list;
}

/** Returns the first listed host found in a block of HTML or text, or null. */
function aab_first_listed_host(string $content): ?string
{
    $list = aab_blocklist();
    if ($list === null) {
        return null;
    }
    preg_match_all('#https?://[^\s"\'<>]+#i', $content, $m);
    foreach ($m[0] as $url) {
        if ($list->checkDomain($url) !== null) {
            return Blocklist::normalizeHost($url);
        }
    }

    return null;
}

// Comments with a link to a listed AI agent domain wait for moderation.
add_filter('pre_comment_approved', static function ($approved, array $comment) {
    if ($approved === 1 && aab_first_listed_host((string) $comment['comment_content']) !== null) {
        return 0;
    }

    return $approved;
}, 20, 2);

// Student posts with such links go to "pending" instead of being published.
add_filter('wp_insert_post_data', static function (array $data) {
    if ($data['post_status'] === 'publish' && !current_user_can('edit_others_posts')
        && aab_first_listed_host((string) $data['post_content']) !== null) {
        $data['post_status'] = 'pending';
    }

    return $data;
});

// [aab_check] shows a small form for teachers: paste a URL, extension ID or app name.
add_shortcode('aab_check', static function (): string {
    if (!current_user_can('edit_posts')) {
        return '';
    }
    $out = '<form method="post"><input name="aab_q" size="50" placeholder="URL, extension ID or process name"> '
        . wp_nonce_field('aab_check', '_aab', true, false) . '<button>Check</button></form>';
    if (isset($_POST['aab_q'], $_POST['_aab']) && wp_verify_nonce($_POST['_aab'], 'aab_check')) {
        $q = sanitize_text_field(wp_unslash($_POST['aab_q']));
        $list = aab_blocklist();
        $hit = $list ? $list->check($q) : null;
        $out .= $hit
            ? sprintf('<p>Listed: %s (%s, %s)</p>', esc_html($hit->toolName), esc_html($hit->agentType), esc_html($hit->kind))
            : '<p>Not on the list.</p>';
    }

    return $out;
});
