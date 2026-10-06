<?php
/**
 * Active sessions screen.
 *
 * @package Ejabh_Security
 *
 * @var Ejabh_Admin $admin
 * @var array     $rows
 * @var array     $summary
 */

defined( 'ABSPATH' ) || exit;

$notice = isset( $_GET['dys_notice'] ) ? sanitize_key( wp_unslash( $_GET['dys_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

$messages = array(
	'revoked_one'  => __( 'أُلغيت الجلسة المحددة.', 'ejabh-security' ),
	'revoked_user' => __( 'أُلغيت كل جلسات هذا المستخدم.', 'ejabh-security' ),
	'revoked_all'  => __( 'أُلغيت كل الجلسات على الموقع. سيحتاج الجميع إلى تسجيل الدخول من جديد.', 'ejabh-security' ),
);

// Group by user so an administrator sees "who is logged in", not a flat list.
$by_user = array();
foreach ( $rows as $row ) {
	$by_user[ $row['user_id'] ][] = $row;
}
?>
<div class="wrap ejabh-wrap">
	<h1><span class="dashicons dashicons-groups"></span> <?php esc_html_e( 'الجلسات النشطة', 'ejabh-security' ); ?></h1>

	<?php if ( isset( $messages[ $notice ] ) ) : ?>
		<div class="notice notice-success is-dismissible"><p><?php echo esc_html( $messages[ $notice ] ); ?></p></div>
	<?php endif; ?>

	<p class="description">
		<?php esc_html_e( 'كل صف هو جلسة دخول قائمة فعلياً. ووردبريس يسجّل عنوان IP والمتصفح ووقت الدخول لكل جلسة. إلغاء الجلسة يُخرج صاحبها فوراً دون تغيير كلمة مروره.', 'ejabh-security' ); ?>
	</p>

	<div class="ejabh-grid ejabh-grid--compact">
		<div class="ejabh-card">
			<span class="ejabh-card__label"><?php esc_html_e( 'إجمالي الجلسات', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value"><?php echo esc_html( number_format_i18n( $summary['total'] ) ); ?></span>
		</div>
		<div class="ejabh-card">
			<span class="ejabh-card__label"><?php esc_html_e( 'جلسات مديرين', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value"><?php echo esc_html( number_format_i18n( $summary['admins'] ) ); ?></span>
		</div>
		<div class="ejabh-card">
			<span class="ejabh-card__label"><?php esc_html_e( 'مستخدمون متصلون', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value"><?php echo esc_html( number_format_i18n( $summary['users'] ) ); ?></span>
		</div>
		<div class="ejabh-card">
			<span class="ejabh-card__label"><?php esc_html_e( 'عناوين IP مختلفة', 'ejabh-security' ); ?></span>
			<span class="ejabh-card__value"><?php echo esc_html( number_format_i18n( $summary['unique_ips'] ) ); ?></span>
		</div>
	</div>

	<?php if ( ! $rows ) : ?>
		<p><?php esc_html_e( 'لا توجد جلسات نشطة حالياً.', 'ejabh-security' ); ?></p>
	<?php else : ?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:16px 0;"
			onsubmit="return confirm('<?php echo esc_js( __( 'سيُخرَج كل المستخدمين من الموقع بما فيهم أنت. متابعة؟', 'ejabh-security' ) ); ?>');">
			<?php wp_nonce_field( 'dys_sec_sessions' ); ?>
			<input type="hidden" name="action" value="dys_sec_session_action" />
			<input type="hidden" name="what" value="revoke_all" />
			<button type="submit" class="button button-secondary">
				<?php esc_html_e( '⚠ إلغاء كل الجلسات على الموقع', 'ejabh-security' ); ?>
			</button>
			<span class="description"><?php esc_html_e( 'استخدمه بعد اختراق مؤكد: يقطع أي جلسة يملكها المخترق فوراً.', 'ejabh-security' ); ?></span>
		</form>

		<?php foreach ( $by_user as $user_id => $user_rows ) : ?>
			<?php
			$first    = $user_rows[0];
			$is_admin = $first['is_admin'];
			$ips      = array_unique( array_filter( wp_list_pluck( $user_rows, 'ip' ) ) );
			?>
			<div class="ejabh-user-block<?php echo $is_admin ? ' ejabh-user-block--admin' : ''; ?>">
				<div class="ejabh-user-head">
					<strong><?php echo esc_html( $first['display'] ); ?></strong>
					<code><?php echo esc_html( $first['user_login'] ); ?></code>
					<span class="ejabh-role"><?php echo esc_html( implode( ', ', $first['roles'] ) ); ?></span>
					<?php if ( $is_admin ) : ?>
						<span class="ejabh-badge ejabh-badge--high"><?php esc_html_e( 'مدير', 'ejabh-security' ); ?></span>
					<?php endif; ?>
					<span class="ejabh-muted"><?php echo esc_html( $first['email'] ); ?></span>

					<?php if ( count( $ips ) > 1 ) : ?>
						<span class="ejabh-badge ejabh-badge--medium" title="<?php esc_attr_e( 'الحساب متصل من أكثر من عنوان IP في نفس الوقت — تحقّق من ذلك.', 'ejabh-security' ); ?>">
							<?php
							printf(
								/* translators: %d: number of distinct IPs. */
								esc_html__( '%d عناوين IP', 'ejabh-security' ),
								count( $ips )
							);
							?>
						</span>
					<?php endif; ?>

					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ejabh-inline-form"
						onsubmit="return confirm('<?php echo esc_js( __( 'إلغاء كل جلسات هذا المستخدم؟', 'ejabh-security' ) ); ?>');">
						<?php wp_nonce_field( 'dys_sec_sessions' ); ?>
						<input type="hidden" name="action" value="dys_sec_session_action" />
						<input type="hidden" name="what" value="revoke_user" />
						<input type="hidden" name="user_id" value="<?php echo esc_attr( $user_id ); ?>" />
						<button type="submit" class="button button-small"><?php esc_html_e( 'إخراج هذا المستخدم', 'ejabh-security' ); ?></button>
					</form>

					<a class="button button-small" href="<?php echo esc_url( get_edit_user_link( $user_id ) ); ?>"><?php esc_html_e( 'ملف المستخدم', 'ejabh-security' ); ?></a>
				</div>

				<table class="widefat striped ejabh-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'عنوان IP', 'ejabh-security' ); ?></th>
							<th><?php esc_html_e( 'المتصفح / النظام', 'ejabh-security' ); ?></th>
							<th><?php esc_html_e( 'وقت الدخول', 'ejabh-security' ); ?></th>
							<th><?php esc_html_e( 'تنتهي', 'ejabh-security' ); ?></th>
							<th style="width:110px;"><?php esc_html_e( 'إجراء', 'ejabh-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $user_rows as $row ) : ?>
							<tr<?php echo $row['expired'] ? ' class="ejabh-expired"' : ''; ?>>
								<td>
									<code><?php echo esc_html( $row['ip'] ? $row['ip'] : '—' ); ?></code>
									<?php if ( $row['is_current'] ) : ?>
										<span class="ejabh-badge ejabh-badge--low"><?php esc_html_e( 'جلستك الحالية', 'ejabh-security' ); ?></span>
									<?php endif; ?>
								</td>
								<td>
									<?php echo esc_html( Ejabh_Sessions::pretty_ua( $row['ua'] ) ); ?>
									<br /><span class="ejabh-muted ejabh-ua" dir="ltr"><?php echo esc_html( $row['ua'] ); ?></span>
								</td>
								<td>
									<?php echo $row['login'] ? esc_html( gmdate( 'Y-m-d H:i', $row['login'] ) . ' UTC' ) : '—'; ?>
									<br /><span class="ejabh-muted"><?php echo esc_html( $admin->ago( $row['login'] ) ); ?></span>
								</td>
								<td>
									<?php echo $row['expiration'] ? esc_html( gmdate( 'Y-m-d H:i', $row['expiration'] ) . ' UTC' ) : '—'; ?>
									<?php if ( $row['expired'] ) : ?>
										<br /><span class="ejabh-badge ejabh-badge--medium"><?php esc_html_e( 'منتهية', 'ejabh-security' ); ?></span>
									<?php endif; ?>
								</td>
								<td>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
										<?php wp_nonce_field( 'dys_sec_sessions' ); ?>
										<input type="hidden" name="action" value="dys_sec_session_action" />
										<input type="hidden" name="what" value="revoke_one" />
										<input type="hidden" name="user_id" value="<?php echo esc_attr( $row['user_id'] ); ?>" />
										<input type="hidden" name="verifier" value="<?php echo esc_attr( $row['verifier'] ); ?>" />
										<button type="submit" class="button button-small"><?php esc_html_e( 'إلغاء', 'ejabh-security' ); ?></button>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endforeach; ?>
	<?php endif; ?>
</div>
