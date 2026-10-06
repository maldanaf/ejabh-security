<?php
/**
 * Settings screen.
 *
 * @package Ejabh_Security
 *
 * @var Ejabh_Admin $admin
 * @var array     $settings
 * @var array     $admins
 * @var array     $invalid_emails Entries rejected on the last save.
 * @var array     $test_result    Address => accepted, after a test send.
 */

defined( 'ABSPATH' ) || exit;

$notice = isset( $_GET['dys_notice'] ) ? sanitize_key( wp_unslash( $_GET['dys_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
?>
<div class="wrap ejabh-wrap">
	<h1><span class="dashicons dashicons-admin-generic"></span> <?php esc_html_e( 'إعدادات الحماية', 'ejabh-security' ); ?></h1>

	<?php if ( 'saved' === $notice ) : ?>
		<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'تم حفظ الإعدادات.', 'ejabh-security' ); ?></p></div>
	<?php endif; ?>

	<?php if ( $invalid_emails ) : ?>
		<div class="notice notice-warning is-dismissible"><p>
			<?php esc_html_e( 'تجاهلنا هذه المدخلات لأنها ليست عناوين بريد صحيحة:', 'ejabh-security' ); ?>
			<code dir="ltr"><?php echo esc_html( implode( '، ', $invalid_emails ) ); ?></code>
		</p></div>
	<?php endif; ?>

	<?php if ( $test_result ) : ?>
		<div class="notice notice-<?php echo in_array( false, $test_result, true ) ? 'warning' : 'success'; ?> is-dismissible">
			<p><strong><?php esc_html_e( 'نتيجة إرسال التقرير التجريبي:', 'ejabh-security' ); ?></strong></p>
			<ul style="list-style:disc;padding-right:20px;">
				<?php foreach ( $test_result as $address => $accepted ) : ?>
					<li><code dir="ltr"><?php echo esc_html( $address ); ?></code> —
						<?php echo $accepted ? esc_html__( 'قبله خادم البريد', 'ejabh-security' ) : esc_html__( 'رُفض — تحقق من إعدادات SMTP', 'ejabh-security' ); ?></li>
				<?php endforeach; ?>
			</ul>
			<p class="description"><?php esc_html_e( '«قبله خادم البريد» يعني أن الرسالة خرجت من الموقع؛ إن لم تصل فابحث في مجلد الرسائل غير المرغوبة.', 'ejabh-security' ); ?></p>
		</div>
	<?php endif; ?>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<?php wp_nonce_field( 'dys_sec_settings' ); ?>
		<input type="hidden" name="action" value="dys_sec_save_settings" />

		<h2 class="title"><?php esc_html_e( '١. المصادقة الثنائية بالبريد', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'التفعيل', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="2fa_enabled" value="1" <?php checked( $settings['2fa_enabled'] ); ?> />
						<?php esc_html_e( 'اطلب رمز تحقق بالبريد من كل مستخدم بعد كلمة المرور', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'إجبارية على كل الحسابات بجميع الأدوار. الاستثناء الوحيد هو قائمة الاستثناءات أدناه وثابت الطوارئ في wp-config.php.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="2fa_code_length"><?php esc_html_e( 'طول الرمز', 'ejabh-security' ); ?></label></th>
				<td><input type="number" min="4" max="10" id="2fa_code_length" name="2fa_code_length" value="<?php echo esc_attr( $settings['2fa_code_length'] ); ?>" class="small-text" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="2fa_code_ttl"><?php esc_html_e( 'صلاحية الرمز (ثانية)', 'ejabh-security' ); ?></label></th>
				<td><input type="number" min="60" max="3600" step="30" id="2fa_code_ttl" name="2fa_code_ttl" value="<?php echo esc_attr( $settings['2fa_code_ttl'] ); ?>" class="small-text" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="2fa_max_attempts"><?php esc_html_e( 'عدد المحاولات الخاطئة المسموحة', 'ejabh-security' ); ?></label></th>
				<td>
					<input type="number" min="1" max="20" id="2fa_max_attempts" name="2fa_max_attempts" value="<?php echo esc_attr( $settings['2fa_max_attempts'] ); ?>" class="small-text" />
					<p class="description"><?php esc_html_e( 'بعد تجاوز العدد تُلغى محاولة الدخول بالكامل ويُبلَّغ صاحب الحساب بالبريد.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="2fa_resend_wait"><?php esc_html_e( 'المدة بين طلبَي رمز (ثانية)', 'ejabh-security' ); ?></label></th>
				<td><input type="number" min="15" max="600" id="2fa_resend_wait" name="2fa_resend_wait" value="<?php echo esc_attr( $settings['2fa_resend_wait'] ); ?>" class="small-text" /></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'إغلاق مسارات التجاوز', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="2fa_block_xmlrpc" value="1" <?php checked( $settings['2fa_block_xmlrpc'] ); ?> />
						<?php esc_html_e( 'حظر مصادقة XML-RPC', 'ejabh-security' ); ?></label><br />
					<label><input type="checkbox" name="2fa_block_app_pw" value="1" <?php checked( $settings['2fa_block_app_pw'] ); ?> />
						<?php esc_html_e( 'تعطيل كلمات مرور التطبيقات (Application Passwords)', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'هذان المسارَان يصادقان بدون شاشة رمز، أي أنهما يتجاوزان المصادقة الثنائية بالكامل. أبقهما مغلقَين إلا إذا كان لديك تكامل يعتمد عليهما.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="2fa_exempt_user_ids"><?php esc_html_e( 'حسابات مستثناة', 'ejabh-security' ); ?></label></th>
				<td>
					<input type="text" id="2fa_exempt_user_ids" name="2fa_exempt_user_ids" class="regular-text" dir="ltr"
						value="<?php echo esc_attr( implode( ', ', (array) $settings['2fa_exempt_user_ids'] ) ); ?>" />
					<p class="description"><?php esc_html_e( 'أرقام المستخدمين مفصولة بفاصلة. اتركها فارغة لتطبيق المصادقة على الجميع (الوضع الموصى به).', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'عند فشل إرسال البريد', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="2fa_fail_open" value="1" <?php checked( $settings['2fa_fail_open'] ); ?> />
						<?php esc_html_e( 'اسمح بالدخول إذا تعذّر إرسال البريد (غير موصى به)', 'ejabh-security' ); ?></label>
					<p class="description">
						<?php esc_html_e( 'الوضع الافتراضي هو المنع عند فشل البريد. إن قلقت من الحجب الكامل، الحل الأسلم هو ضبط SMTP سليم بدل تفعيل هذا الخيار.', 'ejabh-security' ); ?>
						<br /><strong><?php esc_html_e( 'للطوارئ:', 'ejabh-security' ); ?></strong>
						<code dir="ltr">define( 'EJABH_SEC_2FA_BYPASS', true );</code>
						<?php esc_html_e( 'في wp-config.php يعطّل المصادقة مؤقتاً.', 'ejabh-security' ); ?>
					</p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( '٢. حظر إضافات مدير الملفات', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'التفعيل', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="guard_enabled" value="1" <?php checked( $settings['guard_enabled'] ); ?> />
						<?php esc_html_e( 'امنع الإضافات المحظورة من التثبيت والتفعيل والتحميل', 'ejabh-security' ); ?></label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'الحذف التلقائي', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="guard_autodelete" value="1" <?php checked( $settings['guard_autodelete'] ); ?> />
						<?php esc_html_e( 'احذف مجلد الإضافة المحظورة فوراً عند ظهوره على السيرفر', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'يعمل عند كل دخول للوحة التحكم وكل ساعة عبر مهمة مجدولة. يشمل الملفات المرفوعة عبر FTP أو shell. عند التعطيل يُسجَّل الرصد فقط دون حذف.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="guard_blocked_slugs"><?php esc_html_e( 'قائمة الإضافات المحظورة', 'ejabh-security' ); ?></label></th>
				<td>
					<textarea id="guard_blocked_slugs" name="guard_blocked_slugs" rows="6" class="large-text code" dir="ltr"><?php echo esc_textarea( implode( "\n", (array) $settings['guard_blocked_slugs'] ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'اسم مجلد الإضافة (slug) في كل سطر.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="guard_blocked_files"><?php esc_html_e( 'أسماء ملفات محظورة', 'ejabh-security' ); ?></label></th>
				<td>
					<textarea id="guard_blocked_files" name="guard_blocked_files" rows="4" class="large-text code" dir="ltr"><?php echo esc_textarea( implode( "\n", (array) $settings['guard_blocked_files'] ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'تُمنع أي إضافة ملفها الرئيسي بهذا الاسم، حتى لو غُيّر اسم المجلد للتحايل.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( '٣. تقييد إدارة الإضافات والقوالب', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'التفعيل', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="caps_enabled" value="1" <?php checked( $settings['caps_enabled'] ); ?> />
						<?php esc_html_e( 'اقصر إدارة الكود على حساب واحد', 'ejabh-security' ); ?></label>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="caps_owner_id"><?php esc_html_e( 'الحساب المالك', 'ejabh-security' ); ?></label></th>
				<td>
					<select id="caps_owner_id" name="caps_owner_id">
						<?php foreach ( $admins as $user ) : ?>
							<option value="<?php echo esc_attr( $user->ID ); ?>" <?php selected( Ejabh_Settings::owner_id(), $user->ID ); ?>>
								<?php echo esc_html( sprintf( '#%d — %s (%s)', $user->ID, $user->display_name, $user->user_login ) ); ?>
							</option>
						<?php endforeach; ?>
					</select>
					<p class="description"><?php esc_html_e( 'هذا الحساب فقط يستطيع تثبيت/تفعيل/حذف الإضافات والقوالب. كل المديرين الآخرين يُمنعون.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'ما يُقيَّد', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="caps_lock_plugins" value="1" <?php checked( $settings['caps_lock_plugins'] ); ?> />
						<?php esc_html_e( 'الإضافات (تثبيت، تفعيل، تعطيل، تحديث، حذف)', 'ejabh-security' ); ?></label><br />
					<label><input type="checkbox" name="caps_lock_themes" value="1" <?php checked( $settings['caps_lock_themes'] ); ?> />
						<?php esc_html_e( 'القوالب (تثبيت، تبديل، تحديث، حذف)', 'ejabh-security' ); ?></label><br />
					<label><input type="checkbox" name="caps_lock_file_edit" value="1" <?php checked( $settings['caps_lock_file_edit'] ); ?> />
						<?php esc_html_e( 'محرر ملفات الإضافات والقوالب', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'صلاحية edit_theme_options (القوائم والودجات والمخصص) تبقى متاحة كي لا يتعطّل عمل المحررين.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( '٤. حماية الحسابات', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'قفل إنشاء المديرين', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="admin_guard_enabled" value="1" <?php checked( $settings['admin_guard_enabled'] ); ?> />
						<?php esc_html_e( 'امنع أي شخص غير المالك من إنشاء أو ترقية حساب مدير', 'ejabh-security' ); ?></label><br />
					<label><input type="checkbox" name="admin_guard_revert" value="1" <?php checked( $settings['admin_guard_revert'] ); ?> />
						<?php esc_html_e( 'وأرجِع الحساب فوراً إلى دوره السابق عند حدوث ذلك', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'هذا يمنع بالتحديد ما فعله المخترق: إنشاء حسابَي مدير. كما تُقارَن قائمة المديرين دورياً بقائمة معتمدة، فأي حساب يظهر عبر كتابة مباشرة في قاعدة البيانات يُرصَد ويُرسَل عنه تنبيه.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'تحديد محاولات الدخول', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="login_limit_enabled" value="1" <?php checked( $settings['login_limit_enabled'] ); ?> />
						<?php esc_html_e( 'احظر العنوان بعد عدة محاولات فاشلة', 'ejabh-security' ); ?></label>
					<p style="margin-top:8px;">
						<label><?php esc_html_e( 'عدد المحاولات:', 'ejabh-security' ); ?>
							<input type="number" min="1" max="50" name="login_max_attempts" value="<?php echo esc_attr( $settings['login_max_attempts'] ); ?>" class="small-text" /></label>
						&nbsp;
						<label><?php esc_html_e( 'خلال (دقيقة):', 'ejabh-security' ); ?>
							<input type="number" min="1" max="1440" name="login_window_mins" value="<?php echo esc_attr( $settings['login_window_mins'] ); ?>" class="small-text" /></label>
						&nbsp;
						<label><?php esc_html_e( 'مدة الحظر (دقيقة):', 'ejabh-security' ); ?>
							<input type="number" min="1" max="1440" name="login_lockout_mins" value="<?php echo esc_attr( $settings['login_lockout_mins'] ); ?>" class="small-text" /></label>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="login_ip_allowlist"><?php esc_html_e( 'عناوين معفاة من الحظر', 'ejabh-security' ); ?></label></th>
				<td>
					<textarea id="login_ip_allowlist" name="login_ip_allowlist" rows="4" class="large-text code" dir="ltr"><?php echo esc_textarea( implode( "\n", (array) $settings['login_ip_allowlist'] ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'عنوان في كل سطر. تُقبل ثلاث صيغ: عنوان كامل (203.0.113.25)، أو بادئة تنتهي بنقطة (198.51.100.)، أو نطاق CIDR (203.0.113.0/24). ضع عناوين فريقكم هنا حتى لا تُحظروا بالخطأ.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'تنبيه الدخول من مكان جديد', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="new_ip_alert_enabled" value="1" <?php checked( $settings['new_ip_alert_enabled'] ); ?> />
						<?php esc_html_e( 'أرسل بريداً عند دخول حساب من عنوان IP لم يُستخدم من قبل', 'ejabh-security' ); ?></label>
					<p style="margin-top:8px;">
						<?php esc_html_e( 'يُطبَّق على الأدوار:', 'ejabh-security' ); ?><br />
						<?php foreach ( wp_roles()->roles as $slug => $role ) : ?>
							<label style="display:inline-block;margin:4px 12px 0 0;">
								<input type="checkbox" name="new_ip_alert_roles[]" value="<?php echo esc_attr( $slug ); ?>"
									<?php checked( in_array( $slug, (array) $settings['new_ip_alert_roles'], true ) ); ?> />
								<?php echo esc_html( translate_user_role( $role['name'] ) ); ?>
							</label>
						<?php endforeach; ?>
					</p>
					<p class="description"><?php esc_html_e( 'لا يُرسَل تنبيه عند أول دخول مسجَّل للحساب، لأن ذلك هو ما يبني القائمة المرجعية.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'منع تعداد المستخدمين', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="enum_block_enabled" value="1" <?php checked( $settings['enum_block_enabled'] ); ?> />
						<?php esc_html_e( 'أغلق ?author=1 و /wp-json/wp/v2/users وخريطة مؤلفي الموقع', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'هذه المسارات تُسلّم قائمة أسماء المستخدمين لأي زائر، وهي نصف عملية تخمين كلمات المرور.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( '٥. المراقبة والنزاهة', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'مراقبة تغيّر الملفات', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="fim_enabled" value="1" <?php checked( $settings['fim_enabled'] ); ?> />
						<?php esc_html_e( 'سجّل بصمة كل ملف وقارنها في كل فحص', 'ejabh-security' ); ?></label><br />
					<label><input type="checkbox" name="fim_alert_new_php" value="1" <?php checked( $settings['fim_alert_new_php'] ); ?> />
						<?php esc_html_e( 'ونبّه عند ظهور أي ملف PHP جديد', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'الفحص بالبصمات يجد ما يعرفه فقط. مراقبة التغيّر تجد الجديد أياً كان محتواه — وهي التي كانت ستكشف اختراقكم من أول يوم.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'تدقيق نزاهة الإضافات', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="integrity_enabled" value="1" <?php checked( $settings['integrity_enabled'] ); ?> />
						<?php esc_html_e( 'قارن ملفات الإضافات ببصماتها الرسمية على wordpress.org', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'يحتاج اتصال السيرفر بالإنترنت. الإضافات المدفوعة لا بصمات لها فتُدرَج كغير قابلة للتحقق.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'الحجر الصحي', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="quarantine_enabled" value="1" <?php checked( $settings['quarantine_enabled'] ); ?> />
						<?php esc_html_e( 'احفظ نسخة من الملفات المحظورة قبل حذفها', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'عند حذف إضافة مدير ملفات، تُحفَظ نسخة من ملفها الرئيسي في مجلد محمي — لأن حذفها الصامت يمحو الدليل الوحيد على طريقة الدخول.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'الفحص التلقائي المجدول', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="sched_scan_enabled" value="1" <?php checked( $settings['sched_scan_enabled'] ); ?> />
						<?php esc_html_e( 'شغّل الفحوصات تلقائياً', 'ejabh-security' ); ?></label>
					<p style="margin-top:8px;">
						<label><?php esc_html_e( 'التكرار:', 'ejabh-security' ); ?>
							<select name="sched_scan_freq">
								<option value="daily" <?php selected( $settings['sched_scan_freq'], 'daily' ); ?>><?php esc_html_e( 'يومياً (موصى به)', 'ejabh-security' ); ?></option>
								<option value="weekly" <?php selected( $settings['sched_scan_freq'], 'weekly' ); ?>><?php esc_html_e( 'أسبوعياً', 'ejabh-security' ); ?></option>
							</select>
						</label>
					</p>
					<p class="description"><?php esc_html_e( 'يبدأ الساعة ٣:٣٠ فجراً ويعمل على دفعات في الخلفية. يصل بريد فوري عند ظهور أي ملف PHP جديد أو تعديل ملف قائم، أو عند ظهور نتيجة حرجة جديدة. ملخص اليوم كله يأتي في التقرير اليومي (القسم ٨).', 'ejabh-security' ); ?></p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( '٦. تنظيف لوحة التحكم', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'إخفاء إشعارات الإضافات', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="clean_admin_enabled" value="1" <?php checked( $settings['clean_admin_enabled'] ); ?> />
						<?php esc_html_e( 'اجمع إشعارات ودعايات الإضافات في صندوق واحد قابل للطي', 'ejabh-security' ); ?></label>
					<p class="description">
						<?php esc_html_e( 'لا يُحذف أي إشعار — تُجمَع فقط في سطر واحد مع زر «إظهارها». تبقى ظاهرة دائماً: رسائل الخطأ، نتائج ما نفّذته للتو، تنبيهات تحديث ووردبريس، وإشعارات هذه الإضافة. كما تُترك صفحات الإضافات والقوالب والتحديثات كما هي لأن الإشعار فيها هو المقصود.', 'ejabh-security' ); ?>
					</p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( '٧. إعدادات الفحص', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="scan_time_budget"><?php esc_html_e( 'زمن كل دفعة فحص (ثانية)', 'ejabh-security' ); ?></label></th>
				<td>
					<input type="number" min="3" max="60" id="scan_time_budget" name="scan_time_budget" value="<?php echo esc_attr( $settings['scan_time_budget'] ); ?>" class="small-text" />
					<p class="description"><?php esc_html_e( 'قيمة أعلى = فحص أسرع لكن ضغط أكبر على السيرفر. أنقِصها إذا ظهرت أخطاء 504.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="scan_max_file_size"><?php esc_html_e( 'أقصى حجم ملف يُفحص (بايت)', 'ejabh-security' ); ?></label></th>
				<td>
					<input type="number" min="65536" max="33554432" step="65536" id="scan_max_file_size" name="scan_max_file_size" value="<?php echo esc_attr( $settings['scan_max_file_size'] ); ?>" class="regular-text" />
					<p class="description"><?php esc_html_e( 'الملفات الأكبر يُبلَّغ عنها للمراجعة اليدوية بدل قراءتها بالكامل.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="scan_skip_dirs"><?php esc_html_e( 'مجلدات تُستثنى من الفحص', 'ejabh-security' ); ?></label></th>
				<td>
					<textarea id="scan_skip_dirs" name="scan_skip_dirs" rows="6" class="large-text code" dir="ltr"><?php echo esc_textarea( implode( "\n", (array) $settings['scan_skip_dirs'] ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'مسار نسبي من جذر الموقع في كل سطر. لا تستثنِ uploads أو plugins — هذه أهم الأماكن.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( '٨. التنبيهات والتقرير اليومي', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="notify_emails"><?php esc_html_e( 'المستلمون', 'ejabh-security' ); ?></label></th>
				<td>
					<textarea id="notify_emails" name="notify_emails" rows="4" class="large-text code" dir="ltr" placeholder="security@example.org&#10;it@example.org"><?php echo esc_textarea( implode( "\n", Ejabh_Settings::notify_recipients() ) ); ?></textarea>
					<p class="description">
						<?php
						printf(
							/* translators: %d: maximum recipients. */
							esc_html__( 'بريد واحد في كل سطر (حتى %d). كل من في القائمة يستلم التنبيهات الفورية والتقرير اليومي، وتُرسل لكل شخص رسالة منفصلة فلا يرى أحد عناوين الآخرين.', 'ejabh-security' ),
							(int) Ejabh_Settings::MAX_RECIPIENTS
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'التنبيهات الفورية', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="notify_on_critical" value="1" <?php checked( $settings['notify_on_critical'] ); ?> />
						<?php esc_html_e( 'أرسل تنبيهاً فورياً عند كل حدث حرج', 'ejabh-security' ); ?></label>
					<p class="description">
						<?php
						printf(
							/* translators: %d: alerts per hour. */
							esc_html__( 'بحد أقصى %d رسالة في الساعة، كي لا يُغرق هجومٌ صناديق البريد؛ ما يزيد يظهر في السجل وفي التقرير اليومي.', 'ejabh-security' ),
							(int) Ejabh_Mailer::ALERTS_PER_HOUR
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'التقرير اليومي', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="report_daily_enabled" value="1" <?php checked( $settings['report_daily_enabled'] ); ?> />
						<?php esc_html_e( 'أرسل تقرير أمان يومياً لكل المستلمين', 'ejabh-security' ); ?></label>
					<p style="margin-top:8px;">
						<label><?php esc_html_e( 'الساعة:', 'ejabh-security' ); ?>
							<select name="report_daily_hour">
								<?php for ( $h = 0; $h < 24; $h++ ) : ?>
									<option value="<?php echo (int) $h; ?>" <?php selected( (int) $settings['report_daily_hour'], $h ); ?>><?php echo esc_html( sprintf( '%02d:00', $h ) ); ?></option>
								<?php endfor; ?>
							</select>
						</label>
						<span class="description"><?php echo esc_html( sprintf( /* translators: %s: timezone. */ __( '(بتوقيت الموقع: %s)', 'ejabh-security' ), wp_timezone_string() ) ); ?></span>
					</p>
					<p class="description"><?php esc_html_e( 'يلخّص آخر 24 ساعة: النتائج المفتوحة، تسجيلات الدخول الناجحة والفاشلة، العناوين المحظورة، الملفات الخبيثة التي اعتُرضت أو عُزلت، الأحداث الحرجة، وبنود التحصين الناقصة. يصل يومياً حتى لو كان اليوم هادئاً — فغيابه يعني أن البريد أو المهام المجدولة معطّلة.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( '٩. الحماية الفورية من الشِلّات وصفحات التصيّد', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'اعتراض الرفع', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="upload_guard_enabled" value="1" <?php checked( $settings['upload_guard_enabled'] ); ?> />
						<?php esc_html_e( 'افحص كل ملف يُرفع إلى الموقع قبل أن تستلمه أي إضافة، واحذف الخبيث فوراً', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'يُرفض أي ملف PHP يُرفع عبر الويب، وأي ملف يحمل بصمة شِل (رافع ملفات، باب خلفي) أو صفحة تصيّد، وأي كود PHP مخبّأ داخل صورة. الأرشيفات (zip و wpress) لا تُفحص هنا لأنها لا تُنفَّذ — ما يُستخرج منها يلتقطه المراقب. تُحفظ نسخة من الملف المحظور في مجلد الحجر كدليل.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'مراقب الملفات الجديدة', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="watch_enabled" value="1" <?php checked( $settings['watch_enabled'] ); ?> />
						<?php esc_html_e( 'افحص كل ٥ دقائق ملفات PHP و HTML التي أُنشئت أو تغيّرت', 'ejabh-security' ); ?></label>
					<p class="description"><?php esc_html_e( 'يلتقط ما يصل دون المرور بووردبريس: عبر شِل آخر، أو FTP، أو حساب استضافة مخترق. يعتمد على تاريخ تغيير الملف الذي يضبطه نظام التشغيل، فلا يخدعه تزوير تاريخ التعديل. الملفات المطابقة حرفياً للنسخ الرسمية لا تُمسّ أبداً.', 'ejabh-security' ); ?></p>
					<fieldset style="margin-top:10px;">
						<legend class="screen-reader-text"><?php esc_html_e( 'الإجراء عند اكتشاف ملف خبيث', 'ejabh-security' ); ?></legend>
						<p><strong><?php esc_html_e( 'عند اكتشاف ملف خبيث:', 'ejabh-security' ); ?></strong></p>
						<label style="display:block;margin:4px 0;"><input type="radio" name="watch_action" value="quarantine" <?php checked( $settings['watch_action'], 'quarantine' ); ?> />
							<?php esc_html_e( 'انقله إلى الحجر الصحي (موصى به — يختفي من الموقع ويمكن استعادته)', 'ejabh-security' ); ?></label>
						<label style="display:block;margin:4px 0;"><input type="radio" name="watch_action" value="neutralize" <?php checked( $settings['watch_action'], 'neutralize' ); ?> />
							<?php esc_html_e( 'أفرغ محتواه واترك ملفاً فارغاً مكانه (نسخة في الحجر) — مفيد إذا كان هناك ما يعيد إنشاء الملف كلما حُذف', 'ejabh-security' ); ?></label>
						<label style="display:block;margin:4px 0;"><input type="radio" name="watch_action" value="report" <?php checked( $settings['watch_action'], 'report' ); ?> />
							<?php esc_html_e( 'بلّغ فقط ولا تلمسه', 'ejabh-security' ); ?></label>
					</fieldset>
					<p class="description">
						<?php
						printf(
							/* translators: %d: actions per pass. */
							esc_html__( 'صمّام أمان: إذا وجد المراقب أكثر من %d ملفاً خبيثاً في دورة واحدة يتوقف عن الحجر ويكتفي بالتبليغ حتى يراجعها شخص — فكثرة كهذه أقرب إلى خطأ في قاعدة منها إلى هجوم، وحجر إضافة كاملة يعطّل الموقع.', 'ejabh-security' ),
							(int) Ejabh_Watcher::MAX_ACTIONS_PER_PASS
						);
						?>
					</p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( '١٠. تحديثات الإضافة', 'ejabh-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'التحديث التلقائي', 'ejabh-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="auto_update_self" value="1" <?php checked( $settings['auto_update_self'] ); ?> />
						<?php esc_html_e( 'ثبّت إصدارات Ejabh Security الجديدة تلقائياً فور نشرها', 'ejabh-security' ); ?></label>
					<p class="description">
						<?php
						$latest = Ejabh_Updater::latest();
						printf(
							/* translators: 1: installed version, 2: latest version, 3: repo. */
							esc_html__( 'المثبّت: %1$s · آخر إصدار منشور: %2$s · المصدر: github.com/%3$s', 'ejabh-security' ),
							esc_html( EJABH_SEC_VERSION ),
							esc_html( $latest ? $latest['version'] : '—' ),
							esc_html( Ejabh_Updater::repo() )
						);
						?>
					</p>
					<p class="description"><?php esc_html_e( 'كل إصدار موقّع رقمياً بمفتاح لا يغادر جهاز المطوّر؛ أي حزمة توقيعها غير صحيح تُرفض قبل فكّها — حتى لو اختُرق حساب GitHub نفسه.', 'ejabh-security' ); ?></p>
				</td>
			</tr>
		</table>

		<?php submit_button( __( 'حفظ الإعدادات', 'ejabh-security' ) ); ?>
	</form>

	<hr />
	<h2><?php esc_html_e( 'تجربة التقرير اليومي', 'ejabh-security' ); ?></h2>
	<p class="description"><?php esc_html_e( 'يرسل التقرير الآن إلى كل المستلمين المحفوظين أعلاه (احفظ الإعدادات أولاً إن عدّلت القائمة)، ويعرض نتيجة كل عنوان.', 'ejabh-security' ); ?></p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<?php wp_nonce_field( 'dys_sec_test_report' ); ?>
		<input type="hidden" name="action" value="dys_sec_test_report" />
		<button type="submit" class="button button-secondary">
			<span class="dashicons dashicons-email-alt" style="vertical-align:text-bottom;"></span>
			<?php esc_html_e( 'أرسل التقرير الآن', 'ejabh-security' ); ?>
		</button>
	</form>
</div>
