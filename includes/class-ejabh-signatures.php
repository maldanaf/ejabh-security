<?php
/**
 * Malware signatures for the file and database scanners.
 *
 * Three kinds of rule are used:
 *
 *  - `patterns()`  a single regex is enough to raise a finding.
 *  - `combos()`    several regexes must all hit inside the same file. This is
 *                  how the noisy-but-meaningful indicators (base64, superglobal
 *                  access, silenced errors) are turned into a real signal
 *                  without drowning the report in false positives.
 *  - `filenames()` the path alone is the indicator.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Signature definitions.
 */
class Ejabh_Signatures {

	/**
	 * Single-regex content rules.
	 *
	 * @return array
	 */
	public static function patterns() {
		return array(

			/* ---------- CRITICAL: near-certain remote code execution ---------- */

			array(
				'id'       => 'eval_on_decoder',
				'severity' => 'critical',
				'title'    => 'تنفيذ كود مشفّر (eval على دالة فك تشفير) — بصمة باب خلفي',
				'regex'    => '/\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|stripslashes|urldecode|rawurldecode|hex2bin|convert_uudecode|pack)\s*\(/i',
			),
			array(
				// The `[` is required so English prose such as "we require $_GET"
				// inside a code comment cannot match. Every real exploit indexes
				// the superglobal.
				'id'       => 'exec_on_superglobal',
				'severity' => 'critical',
				'title'    => 'تنفيذ مباشر لمُدخلات المستخدم (eval/system على $_GET/$_POST)',
				'regex'    => '/\b(?:eval|assert|create_function|system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(\s*(?:@\s*)?(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[|\$\{\s*[\'"]?_(?:GET|POST|REQUEST|COOKIE))/i',
			),
			array(
				'id'       => 'callable_superglobal',
				'severity' => 'critical',
				'title'    => 'استدعاء دالة يأتي اسمها من مُدخلات المستخدم (GET/POST)',
				'regex'    => '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/',
			),
			array(
				'id'       => 'call_user_func_superglobal',
				'severity' => 'critical',
				'title'    => 'call_user_func على مُدخلات المستخدم',
				'regex'    => '/\bcall_user_func(?:_array)?\s*\(\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE)/i',
			),
			array(
				'id'       => 'eval_php_input',
				'severity' => 'critical',
				'title'    => 'تنفيذ محتوى جسم الطلب (php://input) — باب خلفي صامت',
				'regex'    => '/\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:file_get_contents|fread|stream_get_contents)\s*\(\s*[\'"]php:\/\/input/i',
			),
			array(
				// Same reason as above: "we require $_GET" appears verbatim in
				// WPForms' comments. Requiring the index makes it code-only.
				'id'       => 'include_superglobal',
				'severity' => 'critical',
				'title'    => 'تضمين ملف يحدده المستخدم (LFI/RFI)',
				'regex'    => '/\b(?:include|require)(?:_once)?\s*\(?\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
			),
			array(
				'id'       => 'include_disguised_ext',
				'severity' => 'critical',
				'title'    => 'تضمين كود من ملف بامتداد غير تنفيذي (صورة/نص) — مُحمِّل باب خلفي',
				'regex'    => '/\b(?:include|require)(?:_once)?\s*\(?\s*[\'"][^\'"\n]{1,120}\.(?:ico|jpe?g|png|gif|bmp|txt|log|css|json|xml|dat|cache)[\'"]/i',
			),
			array(
				'id'       => 'password_gated_shell',
				'severity' => 'critical',
				'title'    => 'باب خلفي محمي بكلمة مرور (مقارنة هاش لمُدخل المستخدم)',
				'regex'    => '/\bif\s*\(\s*(?:@\s*)?(?:md5|sha1|crc32|hash)\s*\(\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE)/i',
			),
			array(
				'id'       => 'write_from_request',
				'severity' => 'critical',
				'title'    => 'كتابة ملف من مُدخلات المستخدم — رفع باب خلفي',
				'regex'    => '/\b(?:file_put_contents|fwrite|fputs)\s*\(\s*[^;)]{0,100}\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/i',
			),
			array(
				'id'       => 'known_shell_marker',
				'severity' => 'critical',
				'title'    => 'بصمة شِل معروف (WSO / c99 / r57 / b374k / Alfa / AnonymousFox …)',
				'regex'    => '/\b(?:FilesMan|wso_ver|WSOsetcookie|c99sh|r57shell|b374k|IndoXploit|ALFA_DATA|AlfaTeam|Alfa\s?Shell|AnonymousFox|0byt3m1n1|MonsterShell|GhostShell|priv8\s?shell|mini\s?shell|Symlink\s?Bypass|SyLoRT|Bypass\s?Shell)\b/i',
			),
			array(
				// `wp-feed.php` and `wp-tmp.php` were dropped from this list:
				// WordPress core lists both as legacy feed filenames in
				// canonical.php and update-core.php, so they matched untouched
				// core files. The remaining markers are unique to the malware.
				'id'       => 'wpvcd_marker',
				'severity' => 'critical',
				'title'    => 'بصمة عائلة wp-vcd (إصابة قوالب/إضافات مقرصنة)',
				'regex'    => '/\b(?:wp_temp_setupx|wp_vcd|class\.plugin-modules\.php)\b|\$install_code\s*=\s*stripslashes|\$tmpcontent\s*=\s*(?:@?file_get_contents|str_replace)/i',
			),
			array(
				// move_uploaded_file($_FILES['f']['tmp_name'], $_FILES['f']['name'])
				// — the destination comes straight from the request, so the
				// visitor chooses the name *and* the extension. No upload handler
				// that cares about security is written this way.
				'id'       => 'uploader_request_destination',
				'severity' => 'critical',
				'title'    => 'شِل رافع ملفات: الزائر يحدد اسم الملف المحفوظ ومكانه',
				'regex'    => '/\b(?:move_uploaded_file|copy|rename)\s*\(\s*[^,;]{1,200},\s*(?:@\s*)?\$_(?:FILES|GET|POST|REQUEST|COOKIE)\s*\[/i',
			),
			array(
				'id'       => 'uploader_shell_marker',
				'severity' => 'critical',
				'title'    => 'بصمة شِل رافع ملفات معروف (File Uploaded !!! / _upl)',
				'regex'    => '/File\s+Uploaded\s*!{2,}|Upload\s+Failed\s*!{2,}|name\s*=\s*[\'"]_upl[\'"]|\bif\s*\(\s*\$_POST\s*\[\s*[\'"]_upl[\'"]\s*\]/i',
			),
			array(
				// Phishing kits ship stolen credentials to a Telegram bot. A bot
				// token in a file served from a charity's site has one purpose.
				'id'       => 'telegram_exfiltration',
				'severity' => 'critical',
				'title'    => 'إرسال بيانات إلى بوت تيليجرام — بصمة صفحة تصيّد تسرق كلمات المرور',
				'regex'    => '/api\.telegram\.org\/bot\d{6,12}:[A-Za-z0-9_-]{30,}/',
			),

			/* ---------- HIGH: strong obfuscation / suspicious capability ---------- */

			array(
				'id'       => 'hex_string_blob',
				'severity' => 'high',
				'title'    => 'نص مُشفّر بالنظام السداسي عشري (تعمية كود)',
				'regex'    => '/(?:\\\\x[0-9a-fA-F]{2}){12,}/',
			),
			array(
				'id'       => 'chr_chain',
				'severity' => 'high',
				'title'    => 'سلسلة chr() لبناء كود مخفي',
				'regex'    => '/(?:chr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){6,}/i',
			),
			array(
				'id'       => 'assert_variable',
				'severity' => 'high',
				'title'    => 'assert() على متغير — بديل شائع عن eval',
				'regex'    => '/\bassert\s*\(\s*\$[a-zA-Z_]/',
			),
			array(
				'id'       => 'create_function',
				'severity' => 'high',
				'title'    => 'create_function() — دالة محذوفة من PHP وتُستخدم للتعمية',
				'regex'    => '/\bcreate_function\s*\(/i',
			),
			array(
				'id'       => 'preg_replace_eval',
				'severity' => 'high',
				'title'      => 'preg_replace بمُعدِّل /e (تنفيذ كود)',
				'regex'    => '/preg_replace\s*\(\s*([\'"])[#\/~|!].{0,200}?[#\/~|!][a-zA-Z]{0,6}e[a-zA-Z]{0,6}\1/s',
			),
			array(
				'id'       => 'curl_to_bare_ip',
				'severity' => 'high',
				'title'    => 'اتصال صادر إلى عنوان IP مباشر (قناة سيطرة محتملة)',
				'regex'    => '/(?:CURLOPT_URL\s*,\s*|fsockopen\s*\(\s*)[\'"](?:https?:\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i',
			),
			array(
				'id'       => 'globals_underscore',
				'severity' => 'high',
				'title'    => 'وصول ملتوٍ للمتغيرات العامة ($GLOBALS["_..."]) — تعمية',
				'regex'    => '/\$GLOBALS\s*\[\s*[\'"]_{1,3}[\'"]\s*\]/',
			),
			array(
				'id'       => 'obfuscated_var_var',
				'severity' => 'high',
				'title'    => 'دالة متغيرة مبنية من نص مُقسّم — تعمية نموذجية',
				'regex'    => '/\$[a-zA-Z_][a-zA-Z0-9_]{0,20}\s*=\s*[\'"](?:base64_decode|eval|assert|system|shell_exec|passthru|exec)[\'"]\s*;/i',
			),
			array(
				'id'       => 'eval_generic',
				'severity' => 'high',
				'title'    => 'استخدام eval()',
				'regex'    => '/\beval\s*\(/i',
			),

			/* ---------- MEDIUM: worth a look, common in legitimate code too ---------- */

			array(
				'id'       => 'shell_exec_generic',
				'severity' => 'medium',
				'title'    => 'تنفيذ أوامر نظام (system/exec/shell_exec/passthru)',
				'regex'    => '/\b(?:shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(/i',
			),
			array(
				'id'       => 'base64_decode_generic',
				'severity' => 'medium',
				'title'    => 'استخدام base64_decode',
				'regex'    => '/\bbase64_decode\s*\(/i',
			),
			array(
				'id'       => 'error_silencing',
				'severity' => 'medium',
				'title'    => 'إخفاء الأخطاء بالكامل (شائع في بداية ملفات الشِل)',
				'regex'    => '/@?\bini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*(?:0|[\'"]0?[\'"]|false)\s*\)|\berror_reporting\s*\(\s*0\s*\)/i',
			),
			array(
				'id'       => 'uploaded_file_handling',
				'severity' => 'medium',
				'title'    => 'معالجة ملف مرفوع (تأكد من وجود تحقق صلاحيات ونونس)',
				'regex'    => '/\bmove_uploaded_file\s*\(/i',
			),
			array(
				'id'       => 'user_creation',
				'severity' => 'medium',
				'title'    => 'إنشاء مستخدم برمجياً',
				'regex'    => '/\b(?:wp_insert_user|wp_create_user)\s*\(/i',
			),
		);
	}

	/**
	 * Rules that require several indicators inside the same file.
	 *
	 * @return array
	 */
	public static function combos() {
		return array(
			array(
				'id'       => 'combo_long_b64_eval',
				'severity' => 'critical',
				'title'    => 'كتلة Base64 ضخمة مع تنفيذ كود — حِمل خبيث مُعمّى',
				'all'      => array(
					'/[\'"][A-Za-z0-9+\/]{300,}={0,2}[\'"]/',
					'/\b(?:eval|assert|create_function|preg_replace)\s*\(/i',
				),
			),
			array(
				'id'       => 'combo_shell_toolkit',
				'severity' => 'critical',
				'title'    => 'مجموعة أدوات شِل: إخفاء أخطاء + تنفيذ أوامر + مُدخلات مستخدم',
				'all'      => array(
					'/\berror_reporting\s*\(\s*0\s*\)|@?ini_set\s*\(\s*[\'"]display_errors/i',
					'/\b(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i',
					'/\$_(?:GET|POST|REQUEST|COOKIE)\b/',
				),
			),
			array(
				// Previously this only required the three indicators to appear
				// anywhere in the file, which matched core's own
				// wpmu_create_user(). Now the administrator role must be set in
				// the same call, which is what a backdoor actually does.
				'id'       => 'combo_silent_admin_creation',
				'severity' => 'critical',
				'title'    => 'إنشاء حساب مدير برمجياً — بصمة استعادة صلاحيات للمخترق',
				'all'      => array(
					'/\bwp_insert_user\s*\(\s*(?:array\s*\(|\[)[^;]{0,400}?[\'"]role[\'"]\s*=>\s*[\'"]administrator[\'"]/is',
				),
			),
			array(
				// A self-contained page that both renders an upload form and
				// saves what it receives, with no WordPress bootstrap and no
				// permission check: that is an uploader shell, not a feature.
				'id'       => 'combo_standalone_uploader',
				'severity' => 'critical',
				'title'    => 'صفحة رفع ملفات مستقلة خارج ووردبريس — شِل رافع',
				'all'      => array(
					'/\bmove_uploaded_file\s*\(/i',
					'/enctype\s*=\s*[\'"]?multipart\/form-data/i',
					'/\$_FILES\b/',
				),
				'none'     => array(
					'/\b(?:current_user_can|wp_verify_nonce|check_admin_referer|check_ajax_referer|is_user_logged_in)\s*\(/i',
					'/defined\s*\(\s*[\'"](?:ABSPATH|WPINC)[\'"]\s*\)/i',
					// Code written against the WordPress API (Contact Form 7's
					// file handling, core's wp-admin/includes/file.php). A
					// standalone shell never calls these.
					'/\b(?:apply_filters|do_action|wp_die|wp_handle_upload|wp_upload_dir|esc_html__|esc_attr__)\s*\(/i',
				),
			),
			array(
				// The reconnaissance header every uploader prints first: which OS
				// and which directory the attacker landed in.
				'id'       => 'combo_recon_uploader',
				'severity' => 'critical',
				'title'    => 'شِل يكشف معلومات السيرفر ويستقبل ملفات (php_uname / getcwd + رفع)',
				'all'      => array(
					'/\b(?:php_uname|getcwd|posix_getpwuid|disk_free_space)\s*\(/i',
					'/\$_FILES\b/',
					'/\bmove_uploaded_file\s*\(/i',
				),
				'none'     => array(
					// Core's wp-admin/includes/file.php checks free disk space
					// next to its upload handling; it is WordPress API code.
					'/\b(?:apply_filters|do_action|wp_die|wp_handle_upload|wp_upload_dir|esc_html__|esc_attr__)\s*\(/i',
				),
			),
			array(
				'id'       => 'combo_unauth_upload',
				'severity' => 'high',
				'title'    => 'رفع ملفات بدون تحقق صلاحيات أو نونس',
				'all'      => array(
					'/\bmove_uploaded_file\s*\(/i',
					'/\$_FILES\b/',
				),
				'none'     => array(
					'/\b(?:current_user_can|wp_verify_nonce|check_admin_referer|check_ajax_referer)\s*\(/i',
				),
			),
			array(
				'id'       => 'combo_remote_fetch_exec',
				'severity' => 'high',
				'title'    => 'تحميل كود من الإنترنت ثم تنفيذه',
				'all'      => array(
					'/\b(?:file_get_contents|curl_exec|wp_remote_get|wp_remote_post|fsockopen)\s*\(/i',
					'/\b(?:eval|assert|create_function)\s*\(/i',
				),
			),
			array(
				'id'       => 'combo_nopriv_ajax_exec',
				'severity' => 'high',
				'title'    => 'نقطة AJAX مفتوحة للزوار مع عمليات ملفات — سطح هجوم مباشر',
				'all'      => array(
					'/add_action\s*\(\s*[\'"]wp_ajax_nopriv_/i',
					'/\b(?:file_put_contents|move_uploaded_file|unlink|fwrite|copy|rename)\s*\(/i',
				),
			),
		);
	}

	/**
	 * Path-based rules, evaluated against the site-relative path.
	 *
	 * @return array
	 */
	public static function filenames() {
		return array(
			array(
				'id'       => 'php_in_uploads',
				'severity' => 'critical',
				'title'    => 'ملف PHP داخل مجلد الوسائط (uploads) — لا يوجد سبب مشروع لذلك',
				'regex'    => '#^wp-content/uploads/.+\.(?:php|phtml|php[3457]|pht|phar|phps|inc)$#i',
			),
			array(
				// The media library never produces web pages. Phishing kits are
				// most often dropped here because uploads is writable.
				'id'       => 'html_in_uploads',
				'severity' => 'high',
				'title'    => 'صفحة HTML داخل مجلد الوسائط (uploads) — مكان شائع لصفحات التصيّد',
				'regex'    => '#^wp-content/uploads/(?!.*(?:^|/)index\.html?$).+\.(?:html?|shtml|xhtml)$#i',
			),
			array(
				'id'       => 'double_extension',
				'severity' => 'critical',
				'title'    => 'امتداد مزدوج لتجاوز فلاتر الرفع',
				'regex'    => '#\.(?:jpe?g|png|gif|bmp|pdf|zip|txt|ico|svg|webp)\.(?:php|phtml|php[3457]|pht|phar)$#i',
			),
			array(
				'id'       => 'known_shell_filename',
				'severity' => 'critical',
				'title'    => 'اسم ملف مطابق لشِل معروف',
				'regex'    => '#(?:^|/)(?:wso|alfa|alfa-?rex|c99|r57|b374k|indoxploit|0byt3m1n1|mini|marijuana|priv8|cmd|adminer|radio|up|upl|uploader|shell|backdoor|bypass|wp-l0gin|wp-conflg|wp-conflg_class|wp-cache-base|wp-vcd|wp-tmp|wp-feed|class\.api|wp-atom|xmrlpc|xleet|leaf|sh3ll)\.(?:php|phtml|php[3457]|pht|phar)$#i',
			),
			array(
				'id'       => 'suspected_extension',
				'severity' => 'critical',
				'title'    => 'ملف حجَره سكانر الاستضافة سابقاً (.suspected) — دليل إصابة مؤكدة',
				'regex'    => '#\.suspected$#i',
			),
			array(
				'id'       => 'hidden_php_file',
				'severity' => 'high',
				'title'    => 'ملف PHP مخفي (يبدأ بنقطة)',
				'regex'    => '#(?:^|/)\.[^/]+\.(?:php|phtml|php[3457]|pht|phar)$#i',
			),
			array(
				'id'       => 'alt_php_extension',
				'severity' => 'high',
				'title'    => 'امتداد PHP بديل داخل wp-content (يتجاوز قواعد الحماية المعتادة)',
				'regex'    => '#^wp-content/.+\.(?:phtml|php[3457]|pht|phar|phps)$#i',
			),
			array(
				// Requires both letters and digits: that is the shape of a
				// machine-generated name (hex hashes, "a1b2c3d4"), and it keeps
				// legitimate all-letter filenames out of the report.
				'id'       => 'random_name_php_root',
				'severity' => 'high',
				'title'    => 'ملف PHP باسم مُولَّد عشوائياً في جذر الموقع',
				'regex'    => '#^(?=[a-z0-9]{8,}\.php$)(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])[a-z0-9]+\.php$#',
			),
			array(
				'id'       => 'exposed_dump',
				'severity' => 'critical',
				'title'    => 'نسخة قاعدة بيانات أو أرشيف مكشوف للتنزيل من الإنترنت',
				'regex'    => '#^[^/]*\.(?:sql|sql\.gz|sql\.zip|tar|tar\.gz|tgz|zip|wpress|bak|old|save|swp)$#i',
			),
			array(
				'id'       => 'exposed_log',
				'severity' => 'high',
				'title'    => 'ملف سجل مكشوف يفصح عن مسارات السيرفر',
				'regex'    => '#^(?:error_log|debug\.log|access_log|[^/]*\.log)$#i',
			),
		);
	}

	/**
	 * Rules for phishing pages planted on the site.
	 *
	 * Applied to markup files (.html, .htm, .shtml, .svg …) and to PHP files.
	 * A WordPress site serves its pages from the database, so a standalone HTML
	 * page dressed up as Adobe Sign, DocuSign or a Microsoft login is either a
	 * phishing kit or something nobody on the team put there.
	 *
	 * Same shape as combos(): every regex in `all` must match, none in `none`.
	 *
	 * @return array
	 */
	public static function phishing() {
		$brands = '/\b(?:Adobe\s+(?:Acrobat\s+)?Sign|Acrobat\s+Sign|Adobe\s+Document\s+Cloud|DocuSign|Docu\s?Sign|SharePoint|OneDrive|Office\s?365|Microsoft\s?365|Outlook\s+Web|Webmail|Dropbox|WeTransfer|Wells\s?Fargo|PayPal|Netflix|DHL\s+Express|Excel\s+Online)\b/i';

		return array(
			array(
				// Hot-linking the real vendor's branding images is how these
				// pages look genuine without shipping the files.
				'id'       => 'phish_vendor_assets',
				'severity' => 'critical',
				'title'    => 'صفحة تصيّد: تستعرض شعارات وصور منصة توقيع/دخول حقيقية من خوادمها',
				'all'      => array(
					'/\b(?:src|href)\s*=\s*[\'"]https?:\/\/[^\'"]*(?:documents\.adobe\.com|adobesign\.com|echosign\.com|docusign\.(?:net|com)|aadcdn\.msa?u?th\.net|aadcdn\.msftauth\.net|logincdn\.msauth\.net|login\.microsoftonline\.com|secure\.aadcdn\.microsoftonline-p\.com|res\.cdn\.office\.net)/i',
				),
			),
			array(
				'id'       => 'phish_document_lure',
				'severity' => 'critical',
				'title'    => 'صفحة تصيّد: "مستند بانتظار التوقيع" بانتحال علامة تجارية',
				'all'      => array(
					$brands,
					'/Document\s+Title\s*:|CONFIDENTIALITY\s+NOTICE|(?:View|Review|Open|Access|Download)\s+(?:the\s+)?(?:Shared\s+)?(?:Document|File|PDF)s?\b|shared\s+(?:a\s+)?(?:document|file)\s+with\s+you|Sign\s+in\s+to\s+(?:view|access|continue)|(?:Sub\s+)?Agreement\s+[A-Z][a-z]+\s*,?\s*20\d\d|Remittance\s+Advice|Payment\s+Advice/i',
				),
			),
			array(
				// Markup lifted from an e-mail client (Gmail's "gmail-…" ids,
				// Outlook's divRplyFwdMsg) has no business being a web page.
				'id'       => 'phish_email_markup',
				'severity' => 'high',
				'title'    => 'صفحة منسوخة من رسالة بريد (Gmail/Outlook) ومنشورة على الموقع',
				'all'      => array(
					'/\bid\s*=\s*[\'"](?:gmail-|x_)?divRplyFwdMsg|\bid\s*=\s*[\'"]gmail-[A-Za-z_]+[\'"]|\bclass\s*=\s*[\'"]gmail_(?:quote|attr|signature)/i',
					'/<a\s[^>]*href\s*=\s*[\'"]https?:\/\//i',
				),
			),
			array(
				'id'       => 'phish_offsite_password_form',
				'severity' => 'critical',
				'title'    => 'نموذج يطلب كلمة مرور ويرسلها إلى موقع آخر',
				'all'      => array(
					'/<input\b[^>]*type\s*=\s*[\'"]?password/i',
					'/<form\b[^>]*action\s*=\s*[\'"]https?:\/\//i',
				),
				'none'     => array(
					'/wp-login\.php|wp_login_form|login_form_/i',
				),
			),
			array(
				'id'       => 'phish_brand_login',
				'severity' => 'critical',
				'title'    => 'صفحة دخول مزيفة بانتحال علامة تجارية',
				'all'      => array(
					$brands,
					'/<input\b[^>]*type\s*=\s*[\'"]?password/i',
				),
				'none'     => array(
					'/wp-login\.php|wp_login_form|login_form_/i',
				),
			),
		);
	}

	/**
	 * Content rules for database values.
	 *
	 * @return array
	 */
	public static function db_patterns() {
		return array(
			array(
				'id'       => 'db_php_code',
				'severity' => 'critical',
				'title'    => 'كود PHP مخزّن في قاعدة البيانات',
				'regex'    => '/<\?php|<\?=/i',
			),
			array(
				'id'       => 'db_eval',
				'severity' => 'critical',
				'title'    => 'دالة تنفيذ كود داخل قيمة في قاعدة البيانات',
				'regex'    => '/\b(?:eval|assert|create_function|shell_exec|passthru|proc_open)\s*\(/i',
			),
			array(
				'id'       => 'db_js_obfuscation',
				'severity' => 'critical',
				'title'    => 'جافاسكربت مُعمّاة محقونة (atob / fromCharCode / unescape)',
				'regex'    => '/\batob\s*\(|String\.fromCharCode\s*\(|document\.write\s*\(\s*unescape|eval\s*\(\s*(?:atob|unescape|decodeURIComponent)/i',
			),
			array(
				'id'       => 'db_data_uri_html',
				'severity' => 'critical',
				'title'    => 'إعادة توجيه عبر data: URI مُشفّرة',
				'regex'    => '/data:text\/html;base64,/i',
			),
			array(
				'id'       => 'db_external_script',
				'severity' => 'high',
				'title'    => 'سكربت خارجي محقون في المحتوى',
				'regex'    => '/<script[^>]{0,200}\bsrc\s*=\s*[\'"]?(?:https?:)?\/\//i',
			),
			array(
				'id'       => 'db_hidden_links',
				'severity' => 'high',
				'title'    => 'روابط مخفية (سبام SEO أسود)',
				'regex'    => '/(?:display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute\s*;\s*left\s*:\s*-\d{3,})[^<]{0,200}<a\s/i',
			),
			array(
				'id'       => 'db_onion',
				'severity' => 'high',
				'title'    => 'إشارة إلى نطاق .onion',
				'regex'    => '/[a-z2-7]{16,56}\.onion/i',
			),
			array(
				'id'       => 'db_base64_blob',
				'severity' => 'medium',
				'title'    => 'كتلة Base64 كبيرة مخزّنة في قاعدة البيانات',
				'regex'    => '/[A-Za-z0-9+\/]{400,}={0,2}/',
			),
			array(
				'id'       => 'db_iframe',
				'severity' => 'medium',
				'title'    => 'إطار مدمج (iframe) — تحقق من الجهة المصدر',
				'regex'    => '/<iframe/i',
			),
		);
	}

	/**
	 * What to actually do about each rule.
	 *
	 * A finding without an instruction is just anxiety. Every rule maps to one
	 * of five actions so the report can be worked top to bottom without having
	 * to judge each line from scratch:
	 *
	 *   delete  — confirmed malicious, remove it
	 *   restore — authentic file was altered, replace with the official copy
	 *   review  — could go either way, a human must open it
	 *   verify  — legitimate mechanism, confirm *you* are the one who did it
	 *   fix     — a configuration weakness, fixable from the hardening screen
	 *   info    — context only, no action
	 *
	 * @return array Rule ID => array{action: string, text: string}.
	 */
	public static function remediation() {
		return array(

			/* ---------- delete ---------- */
			'eval_on_decoder'            => array( 'delete', __( 'هذا نمط باب خلفي لا يوجد له استخدام مشروع. احجُر الملف ثم احذفه، وابحث عن نسخ أخرى منه، وغيّر كل كلمات المرور.', 'ejabh-security' ) ),
			'exec_on_superglobal'        => array( 'delete', __( 'الملف ينفّذ ما يرسله الزائر مباشرة. هذا باب خلفي — احجُره واحذفه فوراً.', 'ejabh-security' ) ),
			'callable_superglobal'       => array( 'delete', __( 'يسمح للزائر باستدعاء أي دالة في PHP. باب خلفي مؤكد — احذفه.', 'ejabh-security' ) ),
			'call_user_func_superglobal' => array( 'delete', __( 'استدعاء دالة يتحكم بها الزائر. باب خلفي — احذفه.', 'ejabh-security' ) ),
			'eval_php_input'             => array( 'delete', __( 'ينفّذ محتوى جسم الطلب مباشرة، وهو أسلوب أبواب خلفية صامتة لا تظهر في سجلات الوصول. احذفه.', 'ejabh-security' ) ),
			'include_superglobal'        => array( 'delete', __( 'ثغرة تضمين ملفات (LFI/RFI): الزائر يحدد أي ملف يُنفَّذ. إن كان في إضافة، حدّثها أو احذفها؛ وإن كان ملفاً غريباً فاحذفه.', 'ejabh-security' ) ),
			'include_disguised_ext'      => array( 'delete', __( 'يُحمّل كوداً من ملف يتظاهر بأنه صورة أو نص. هذا مُحمِّل باب خلفي — احذف هذا الملف والملف الذي يستدعيه.', 'ejabh-security' ) ),
			'password_gated_shell'       => array( 'delete', __( 'باب خلفي محمي بكلمة مرور يعرفها المخترق وحده. احذفه فوراً.', 'ejabh-security' ) ),
			'write_from_request'         => array( 'delete', __( 'يكتب ملفاً بمحتوى يرسله الزائر — أي أنه يستطيع زرع أبواب خلفية جديدة. احذفه.', 'ejabh-security' ) ),
			'known_shell_marker'         => array( 'delete', __( 'بصمة شِل معروف. احذف الملف، ثم افترض أن كل كلمات المرور مسربة وغيّرها.', 'ejabh-security' ) ),
			'wpvcd_marker'               => array( 'delete', __( 'إصابة عائلة wp-vcd، وتأتي عادةً من قالب أو إضافة مقرصنة. احذف الملف، وابحث عن مصدر الإصابة في الإضافات غير الرسمية.', 'ejabh-security' ) ),
			'combo_shell_toolkit'        => array( 'delete', __( 'مجموعة أدوات شِل كاملة. احذف الملف.', 'ejabh-security' ) ),
			'combo_silent_admin_creation'=> array( 'delete', __( 'كود ينشئ حساب مدير تلقائياً — هكذا يستعيد المخترق صلاحياته بعد حذف حسابه. احذفه وراجع قائمة المديرين.', 'ejabh-security' ) ),
			'php_in_uploads'             => array( 'delete', __( 'لا يوجد سبب مشروع لوجود ملف PHP في مجلد الوسائط. احجُره واحذفه، وفعّل منع تنفيذ PHP في uploads من لوحة التحصين.', 'ejabh-security' ) ),
			'double_extension'           => array( 'delete', __( 'امتداد مزدوج للتحايل على فلاتر الرفع. احذفه.', 'ejabh-security' ) ),
			'known_shell_filename'       => array( 'delete', __( 'اسم ملف مطابق لشِل معروف. افتحه للتأكد ثم احذفه.', 'ejabh-security' ) ),
			'suspected_extension'        => array( 'delete', __( 'سكانر الاستضافة عزل هذا الملف مسبقاً لأنه مصاب. احذفه — وهو دليل على إصابة سابقة مؤكدة.', 'ejabh-security' ) ),
			'uploader_request_destination' => array( 'delete', __( 'شِل رافع: يحفظ أي ملف يرسله الزائر بالاسم الذي يختاره، أي أنه يزرع أبواباً خلفية جديدة متى شاء. احجُره واحذفه، ثم افحص المجلد نفسه بحثاً عمّا رُفع عبره.', 'ejabh-security' ) ),
			'uploader_shell_marker'      => array( 'delete', __( 'بصمة شِل رافع معروف. احذفه، وابحث عن ملفات أُنشئت في نفس الوقت تقريباً — فهي ما رفعه المخترق عبره.', 'ejabh-security' ) ),
			'combo_standalone_uploader'  => array( 'delete', __( 'صفحة رفع ملفات مستقلة لا تمرّ بووردبريس ولا تتحقق من أي صلاحية. هذا شِل رافع — احذفه.', 'ejabh-security' ) ),
			'combo_recon_uploader'       => array( 'delete', __( 'يعرض نظام السيرفر ومساره ثم يستقبل ملفات: الخطوة الأولى المعتادة بعد الاختراق. احذفه وغيّر كلمات المرور.', 'ejabh-security' ) ),
			'telegram_exfiltration'      => array( 'delete', __( 'يرسل بيانات الزوار (غالباً كلمات مرور) إلى بوت تيليجرام. هذه صفحة تصيّد تعمل الآن من موقعكم — احذفها فوراً، فقد تؤدي إلى إدراج النطاق في القوائم السوداء.', 'ejabh-security' ) ),
			'phish_vendor_assets'        => array( 'delete', __( 'صفحة تنتحل منصة توقيع أو دخول حقيقية (Adobe Sign / DocuSign / Microsoft) لسرقة كلمات المرور. احذفها فوراً، ثم ابحث عن ملفات أخرى في نفس المجلد.', 'ejabh-security' ) ),
			'phish_document_lure'        => array( 'delete', __( 'صفحة "مستند بانتظارك" بانتحال علامة تجارية — نمط التصيّد الأشيع. احذفها، واعلم أن روابط إليها قد تكون أُرسلت بالبريد باسم موقعكم.', 'ejabh-security' ) ),
			'phish_email_markup'         => array( 'review', __( 'صفحة ويب منسوخة من رسالة بريد. افتحها: إن كانت تقود الزائر إلى رابط خارجي فهي تصيّد ويجب حذفها.', 'ejabh-security' ) ),
			'phish_offsite_password_form'=> array( 'delete', __( 'نموذج يجمع كلمات المرور ويرسلها إلى موقع آخر. لا يوجد استخدام مشروع لهذا داخل موقعكم — احذفه.', 'ejabh-security' ) ),
			'phish_brand_login'          => array( 'delete', __( 'صفحة دخول مزيفة باسم علامة تجارية معروفة. احذفها فوراً.', 'ejabh-security' ) ),
			'html_in_uploads'            => array( 'review', __( 'مكتبة الوسائط لا تُنتج صفحات HTML. افتح الملف: إن لم يرفعه أحد من فريقكم عمداً فاحذفه.', 'ejabh-security' ) ),
			'upload_blocked'             => array( 'info', __( 'اعتُرض ملف خبيث لحظة رفعه ولم يُحفظ على السيرفر. راجع الصفحة المستهدفة في السجل — قد تكون إضافة فيها ثغرة رفع.', 'ejabh-security' ) ),
			'watcher_neutralised'        => array( 'verify', __( 'ظهر ملف خبيث على السيرفر فحُجر تلقائياً. اعرف كيف وصل: راجع سجل الوصول في ذلك الوقت، وغيّر كلمات مرور FTP/cPanel.', 'ejabh-security' ) ),
			'php_in_non_php_file'        => array( 'review', __( 'كود PHP داخل ملف ليس امتداده PHP. في ملفات .js و .html هذا خطر ويجب حذفه. أما في الصور فقد يكون بيانات EXIF غير ضارة — افتح الملف وتأكد قبل الحذف.', 'ejabh-security' ) ),

			/* ---------- restore ---------- */
			'core_file_modified'         => array( 'restore', __( 'ملف من نواة ووردبريس تغيّر محتواه. لا تحرّره: نزّل نفس إصدار ووردبريس من wordpress.org واستبدل الملف بنسخته الأصلية.', 'ejabh-security' ) ),
			'core_unknown_file'          => array( 'review', __( 'ووردبريس لا يضيف ملفات إلى wp-admin أو wp-includes، والإضافات كذلك. افتح الملف — إن لم تتعرّف عليه فهو باب خلفي، احجُره واحذفه.', 'ejabh-security' ) ),
			'core_file_missing'          => array( 'restore', __( 'ملف أساسي مفقود. أعِد رفعه من نسخة ووردبريس الرسمية لنفس الإصدار.', 'ejabh-security' ) ),
			'plugin_file_modified'       => array( 'restore', __( 'ملف إضافة لا يطابق النسخة الرسمية. افحص الفرق أولاً، ثم أعد تثبيت الإضافة من مصدرها الرسمي (سيستبدل الملفات دون فقدان الإعدادات).', 'ejabh-security' ) ),
			'plugin_extra_file'          => array( 'review', __( 'ملف PHP غير موجود في النسخة الرسمية للإضافة. هذا أسلوب شائع لإخفاء باب خلفي وسط ملفات حقيقية — افتحه، وإن لم يكن مبرّراً فاحذفه.', 'ejabh-security' ) ),
			'plugin_file_missing'        => array( 'info', __( 'ملفات ناقصة من الإضافة، غالباً بسبب تنظيف سابق أو سكانر الاستضافة. أعد تثبيت الإضافة إن ظهر خلل في عملها.', 'ejabh-security' ) ),

			/* ---------- verify ---------- */
			'fim_new_code_file'          => array( 'verify', __( 'ملف PHP جديد لم يكن موجوداً في الفحص السابق. إن كان ناتجاً عن تحديث إضافة أو قالب قمتم به فهو طبيعي؛ وإن لم تُجروا أي تحديث فافتحه فوراً.', 'ejabh-security' ) ),
			'fim_modified_code_file'     => array( 'verify', __( 'ملف PHP تغيّر محتواه. طابِق التاريخ مع آخر تحديث أجريتموه — إن لم يتطابق فافتح الملف وراجعه.', 'ejabh-security' ) ),
			'fim_deleted_code_file'      => array( 'info', __( 'ملف اختفى منذ الفحص السابق. طبيعي بعد التحديثات؛ ومقلق إن لم تُجروا أياً منها.', 'ejabh-security' ) ),
			'rogue_admin'                => array( 'delete', __( 'حساب مدير تنطبق عليه بصمات الحسابات التي ينشئها المخترقون. تحقق منه مع فريقكم، وإن لم يعرفه أحد فاحذفه فوراً وألغِ كل جلساته.', 'ejabh-security' ) ),
			'new_admin_account'          => array( 'verify', __( 'حساب مدير حديث. اسأل فريقكم: هل أنشأتموه؟ إن كان الجواب لا، احذفه وألغِ جلساته فوراً.', 'ejabh-security' ) ),
			'unexpected_admin_detected'  => array( 'verify', __( 'ظهر حساب مدير خارج القائمة المعتمدة. تحقق منه فوراً.', 'ejabh-security' ) ),
			'ghost_active_plugin'        => array( 'review', __( 'إضافة مُدرَجة كمُفعّلة لكن ملفاتها محذوفة. نظّف السجل من قائمة الإضافات المفعّلة — ووجودها يدل على إضافة كانت تعمل سابقاً، فإن كانت مصابة فهي مسار الاختراق المرجَّح.', 'ejabh-security' ) ),
			'blocked_plugin_active'      => array( 'fix', __( 'إضافة محظورة ما زالت مُدرَجة كمُفعّلة. ستُزال تلقائياً، وتأكد من حذف مجلدها.', 'ejabh-security' ) ),
			'suspicious_cron'            => array( 'review', __( 'مهمة مجدولة باسم مشبوه. المهام المجدولة تُعيد زرع الأبواب الخلفية بعد حذفها — راجعها واحذفها إن لم تتعرّف عليها.', 'ejabh-security' ) ),
			'role_privilege_escalation'  => array( 'review', __( 'دور غير المدير يملك صلاحيات خطيرة. إن لم تكونوا من منحها فهي وسيلة المخترق للاحتفاظ بصلاحياته — أزِلها.', 'ejabh-security' ) ),

			/* ---------- fix (hardening screen) ---------- */
			'config_default_salts'       => array( 'fix', __( 'اذهب إلى «التحصين» واضغط «ولّد مفاتيح جديدة». سيُخرج الجميع من الموقع ويُبطل أي كوكي مزوّر.', 'ejabh-security' ) ),
			'config_file_edit_allowed'   => array( 'fix', __( 'اذهب إلى «التحصين» واضغط «تعطيل محرر الملفات».', 'ejabh-security' ) ),
			'config_open_registration'   => array( 'verify', __( 'التسجيل مفتوح. إن كان موقعكم يستقبل تسجيل متبرعين أو عملاء (GiveWP، WooCommerce) فهذا مطلوب ولا تُغلقه؛ وإن لم يكن، أغلقه من الإعدادات العامة.', 'ejabh-security' ) ),
			'config_no_https'            => array( 'fix', __( 'اضبط عنوان الموقع على https من الإعدادات العامة.', 'ejabh-security' ) ),
			'config_xmlrpc_open'         => array( 'fix', __( 'فعّل «حظر XML-RPC» من إعدادات هذه الإضافة.', 'ejabh-security' ) ),
			'exposed_dump'               => array( 'fix', __( 'ملف قابل للتنزيل من الإنترنت ويحتوي بيانات حسّاسة. احذفه من «التحصين»، أو انقله خارج مجلد الموقع.', 'ejabh-security' ) ),
			'exposed_log'                => array( 'fix', __( 'سجل مكشوف يفصح عن مسارات السيرفر. من «التحصين» اضغط «حظره وتفريغ محتواه».', 'ejabh-security' ) ),

			/* ---------- review ---------- */
			'hex_string_blob'            => array( 'review', __( 'نص مُشفّر سداسياً. تستخدمه بعض المكتبات لجداول الترميز بشكل مشروع — افتح الملف: إن كان مكتبة معروفة فتجاهله، وإن كان ملفاً غامضاً فهو تعمية.', 'ejabh-security' ) ),
			'chr_chain'                  => array( 'review', __( 'سلسلة chr() تبني نصاً حرفاً بحرف. شائعة في مكتبات الباركود و PDF بشكل مشروع — راجع سياق الملف.', 'ejabh-security' ) ),
			'assert_variable'            => array( 'review', __( 'assert() على متغير. في المكتبات الحديثة تُستخدم للتحقق البرمجي؛ وفي الأبواب الخلفية تُستخدم بديلاً عن eval. راجع السطر.', 'ejabh-security' ) ),
			'create_function'            => array( 'review', __( 'دالة محذوفة من PHP 8. وجودها يعني كوداً قديماً جداً أو تعمية — راجعه.', 'ejabh-security' ) ),
			'preg_replace_eval'          => array( 'review', __( 'مُعدِّل /e أُزيل من PHP 7. غالباً كود قديم غير عامل، لكن راجعه.', 'ejabh-security' ) ),
			'curl_to_bare_ip'            => array( 'review', __( 'اتصال صادر إلى عنوان IP مباشر بدل نطاق. مشروع في مكتبات معينة، ومؤشر قناة سيطرة في غيرها — راجع الوجهة.', 'ejabh-security' ) ),
			'globals_underscore'         => array( 'review', __( 'وصول ملتوٍ للمتغيرات العامة، أسلوب تعمية شائع. راجع الملف.', 'ejabh-security' ) ),
			'obfuscated_var_var'         => array( 'review', __( 'اسم دالة مخزّن في متغير نصي للتحايل على الفحص. راجعه.', 'ejabh-security' ) ),
			'eval_generic'               => array( 'review', __( 'استخدام eval(). موجود في بعض المكتبات القديمة بشكل مشروع (محرّكات القوالب مثلاً) — افتح السطر وتأكد أن ما يُنفَّذ ليس مُدخلات مستخدم.', 'ejabh-security' ) ),
			'combo_long_b64_eval'        => array( 'review', __( 'كتلة Base64 ضخمة مع تنفيذ كود. هذا نمط الحِمل المُعمّى — راجعه بعناية، والأرجح أنه خبيث.', 'ejabh-security' ) ),
			'combo_unauth_upload'        => array( 'review', __( 'رفع ملفات دون تحقق ظاهر من الصلاحيات. قد تكون ثغرة حقيقية في الإضافة — حدّثها، وإن لم يتوفر تحديث ففكّر في استبدالها.', 'ejabh-security' ) ),
			'combo_remote_fetch_exec'    => array( 'review', __( 'تحميل محتوى من الإنترنت مع وجود تنفيذ كود في نفس الملف. راجع ما إذا كان المُنفَّذ هو المُحمَّل فعلاً.', 'ejabh-security' ) ),
			'combo_nopriv_ajax_exec'     => array( 'review', __( 'نقطة AJAX مفتوحة للزوار تُجري عمليات على الملفات. سطح هجوم مباشر — راجعها وحدّث الإضافة.', 'ejabh-security' ) ),
			'hidden_php_file'            => array( 'review', __( 'ملف PHP مخفي يبدأ بنقطة. غير معتاد إطلاقاً — افتحه.', 'ejabh-security' ) ),
			'alt_php_extension'          => array( 'review', __( 'امتداد PHP بديل يتجاوز قواعد الحماية المعتادة. راجعه.', 'ejabh-security' ) ),
			'random_name_php_root'       => array( 'review', __( 'اسم ملف يبدو مُولَّداً آلياً في جذر الموقع. افتحه — إن لم تتعرّف عليه فاحذفه.', 'ejabh-security' ) ),
			'theme_unverifiable'         => array( 'info', __( 'لا توجد بصمات رسمية للقوالب، فلا يمكن إثبات سلامته آلياً. تأكد أن مصدره رسمي وليس نسخة مقرصنة، واشترِ الترخيص لتصلكم التحديثات الأمنية.', 'ejabh-security' ) ),
			'plugin_unverifiable'        => array( 'info', __( 'إضافة غير منشورة على wordpress.org (مدفوعة أو مخصصة)، فلا مرجع لمقارنتها. إن كانت نسخة مقرصنة فاستبدلها بنسخة مرخّصة — النسخ المقرصنة أشيع مصدر للأبواب الخلفية.', 'ejabh-security' ) ),

			/* ---------- low-signal, context only ---------- */
			'shell_exec_generic'         => array( 'info', __( 'تنفيذ أوامر نظام. مشروع في أدوات النسخ الاحتياطي ومعالجة الصور. لا إجراء إلا إذا كان الملف نفسه مشبوهاً.', 'ejabh-security' ) ),
			'base64_decode_generic'      => array( 'info', __( 'base64_decode شائعة جداً في الكود المشروع (الصور المضمّنة، بيانات الاعتماد، التخزين المؤقت). لا تقلق منها وحدها.', 'ejabh-security' ) ),
			'error_silencing'            => array( 'info', __( 'إخفاء الأخطاء. شائع في المكتبات، ومؤشر إضافي فقط عندما يجتمع مع مؤشرات أخرى.', 'ejabh-security' ) ),
			'uploaded_file_handling'     => array( 'info', __( 'معالجة ملف مرفوع. طبيعية في نماذج التواصل ورفع الوسائط.', 'ejabh-security' ) ),
			'user_creation'              => array( 'info', __( 'إنشاء مستخدم برمجياً. طبيعي في إضافات العضوية والمتاجر والتبرعات.', 'ejabh-security' ) ),
			'core_file_line_endings'     => array( 'info', __( 'اختلاف في نهايات الأسطر فقط — المحتوى مطابق للنسخة الرسمية. غير خطير، ولا يحتاج أي إجراء.', 'ejabh-security' ) ),
			'php_file_too_large'         => array( 'review', __( 'أكبر من حد الفحص. افتحه يدوياً إن كان في مكان غير متوقع.', 'ejabh-security' ) ),
			'core_checksums_unavailable' => array( 'info', __( 'تعذّر الاتصال بـ api.wordpress.org، فلم يُتحقق من سلامة النواة. تأكد أن السيرفر يستطيع الاتصال بالإنترنت وأعد الفحص.', 'ejabh-security' ) ),

			/* ---------- database ---------- */
			'db_php_code'                => array( 'review', __( 'كود PHP مخزّن في قاعدة البيانات. مهم: إضافات المقتطفات مثل WPCode تخزّن أكواد PHP هنا بشكل مشروع تماماً. القاعدة: افتح الكود — إن كان مقتطفاً كتبتموه أنتم وتتعرّفون عليه فهو سليم، وإن لم تتعرّف عليه فهو محقون فاحذفه.', 'ejabh-security' ) ),
			'db_eval'                    => array( 'review', __( 'دالة تنفيذ كود داخل قيمة مخزّنة. راجع القيمة: إن كانت في إعدادات إضافة تعرفها وتتعرّف على الكود فهي سليمة، وإلا فاحذف الصف.', 'ejabh-security' ) ),
			'db_js_obfuscation'          => array( 'delete', __( 'جافاسكربت مُعمّاة محقونة في المحتوى. لا يوجد سبب مشروع لتعمية سكربت داخل قاعدة البيانات — احذف هذا الجزء من المحتوى.', 'ejabh-security' ) ),
			'db_data_uri_html'           => array( 'delete', __( 'إعادة توجيه مُشفّرة. احذف هذا الجزء من المحتوى.', 'ejabh-security' ) ),
			'db_external_script'         => array( 'review', __( 'سكربت من نطاق خارجي غير معروف. إن كان أداة تتبع ركّبتموها (إحصاءات، دردشة) فأضِف نطاقها للقائمة الموثوقة؛ وإن لم تتعرّف عليه فاحذفه فوراً.', 'ejabh-security' ) ),
			'db_hidden_links'            => array( 'delete', __( 'روابط مخفية عن الزائر ومرئية لمحركات البحث (سبام SEO). احذفها — وجودها يعني أن الموقع يُستغل للترويج.', 'ejabh-security' ) ),
			'db_onion'                   => array( 'review', __( 'إشارة إلى نطاق على شبكة Tor. راجع الصف — نادراً ما يكون مشروعاً.', 'ejabh-security' ) ),
			'db_base64_blob'             => array( 'info', __( 'كتلة Base64 كبيرة. عادةً صور مضمّنة أو تخزين مؤقت لإضافة. لا إجراء إلا مع مؤشرات أخرى.', 'ejabh-security' ) ),
			'db_iframe'                  => array( 'review', __( 'إطار مدمج من مصدر غير موثوق. إن كان فيديو أو خريطة ركّبتموها فأضِف نطاقها للقائمة الموثوقة؛ وإلا فاحذفه.', 'ejabh-security' ) ),
			'db_serialized_object'       => array( 'info', __( 'كائن PHP مُسلسل في الإعدادات. تستخدمه إضافات كثيرة بشكل مشروع. يصبح خطراً فقط مع ثغرة إلغاء تسلسل — راجعه إن كان اسم الإعداد غريباً.', 'ejabh-security' ) ),
			'md5_password_hash'          => array( 'delete', __( 'أحدهم كتب كلمة المرور مباشرة في قاعدة البيانات. إن كان الحساب غير معروف فاحذفه؛ وإن كان معروفاً فغيّر كلمة مروره فوراً من «المستخدمون»، ثم غيّر كلمة مرور قاعدة البيانات لأن من كتبها كان يملك وصولاً إليها.', 'ejabh-security' ) ),
			'predictable_admin_username' => array( 'review', __( 'اسم المستخدم "admin" أول ما يُجرَّب. أنشئ حساب مدير باسم آخر، انقل المحتوى إليه، ثم احذف القديم.', 'ejabh-security' ) ),
			'too_many_admins'            => array( 'review', __( 'كل حساب مدير هو باب دخول إضافي. أنزِل غير الضروري منها إلى دور محرر أو أقل.', 'ejabh-security' ) ),
		);
	}

	/**
	 * Remediation entry for a rule, with a sensible fallback.
	 *
	 * @param string $rule_id  Rule identifier.
	 * @param string $severity Finding severity.
	 * @return array{action: string, text: string}
	 */
	public static function remediation_for( $rule_id, $severity = 'medium' ) {
		$map = self::remediation();

		if ( isset( $map[ $rule_id ] ) ) {
			return array(
				'action' => $map[ $rule_id ][0],
				'text'   => $map[ $rule_id ][1],
			);
		}

		if ( 'critical' === $severity ) {
			return array(
				'action' => 'review',
				'text'   => __( 'نتيجة حرجة بلا إرشاد محدد. افتح الملف أو الصف وراجعه يدوياً قبل أي حذف.', 'ejabh-security' ),
			);
		}

		return array(
			'action' => 'info',
			'text'   => __( 'راجع السياق عند الحاجة. لا إجراء مطلوب بذاته.', 'ejabh-security' ),
		);
	}

	/**
	 * Display metadata for each action type.
	 *
	 * @return array
	 */
	public static function actions() {
		return array(
			'delete'  => array(
				'label' => __( 'احذفه', 'ejabh-security' ),
				'class' => 'critical',
			),
			'restore' => array(
				'label' => __( 'استبدله بالنسخة الرسمية', 'ejabh-security' ),
				'class' => 'high',
			),
			'review'  => array(
				'label' => __( 'راجعه يدوياً', 'ejabh-security' ),
				'class' => 'medium',
			),
			'verify'  => array(
				'label' => __( 'تأكّد أنه منكم', 'ejabh-security' ),
				'class' => 'medium',
			),
			'fix'     => array(
				'label' => __( 'أصلحه من التحصين', 'ejabh-security' ),
				'class' => 'high',
			),
			'info'    => array(
				'label' => __( 'للعلم فقط', 'ejabh-security' ),
				'class' => 'low',
			),
		);
	}

	/**
	 * Hosts allowed to appear in iframes / script tags without a warning.
	 *
	 * @return array
	 */
	public static function trusted_hosts() {
		$hosts = array(
			'youtube.com',
			'www.youtube.com',
			'youtube-nocookie.com',
			'www.youtube-nocookie.com',
			'player.vimeo.com',
			'maps.google.com',
			'www.google.com',
			'www.google.com/maps',
			'google.com',
			'docs.google.com',
			'w.soundcloud.com',
			'open.spotify.com',
			'facebook.com',
			'www.facebook.com',
			'platform.twitter.com',
			'js.stripe.com',
			'checkout.stripe.com',
			'www.paypal.com',
			'www.gstatic.com',
			'fonts.googleapis.com',
			'fonts.gstatic.com',
			'www.googletagmanager.com',
			'www.google-analytics.com',
		);

		$home = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( $home ) {
			$hosts[] = $home;
		}

		/**
		 * Filter the hosts considered safe in embedded content.
		 *
		 * @param array $hosts Host names.
		 */
		return apply_filters( 'dys_sec_trusted_hosts', $hosts );
	}

	/**
	 * Disposable / obviously fake e-mail domains seen on injected accounts.
	 *
	 * @return array
	 */
	public static function suspicious_email_domains() {
		return array(
			'shellcode.lol',
			'mailinator.com',
			'guerrillamail.com',
			'10minutemail.com',
			'yopmail.com',
			'tempmail.com',
			'temp-mail.org',
			'trashmail.com',
			'sharklasers.com',
			'getnada.com',
			'dropmail.me',
			'maildrop.cc',
			'throwawaymail.com',
			'fakeinbox.com',
			'mvrht.net',
			'spam4.me',
		);
	}

	/**
	 * Username shapes used by automated WordPress exploitation kits.
	 *
	 * @return array
	 */
	public static function suspicious_username_patterns() {
		return array(
			'/^w2s_[a-f0-9]{8,}$/i'    => 'بادئة w2s_ — بصمة أداة استغلال آلية لووردبريس',
			'/^[a-f0-9]{10,}$/i'       => 'اسم مستخدم سداسي عشري عشوائي بالكامل',
			'/^wp[-_]?(?:admin|user)[0-9]{2,}$/i' => 'اسم مستخدم مُولَّد آلياً',
			'/^(?:admin|administrator)[0-9]{1,4}$/i' => 'حساب مدير مُرقَّم مُولَّد آلياً',
			'/^[a-z]{4,10}[0-9]{6,}$/i' => 'نمط اسم مُولَّد آلياً',
		);
	}
}
