<?php
/**
 * SQRLLogin class file
 *
 * This is a plugin that implements the SQRL Login feature for WordPress.
 *
 * @category   SQRLLogin
 * @package    SQRLLogin
 * @author     Daniel Persson
 * @license    https://opensource.org/licenses/MIT MIT
 * @link       http://danielpersson.dev
 * @version    2.1.0
 */

/**
 * SQRLLogin class
 *
 * @wordpress-plugin
 * Plugin Name:       SQRL Login
 * Description:       Login and Register your users using SQRL
 * Version:           2.1.0
 * Author:            Daniel Persson
 * Author URI:        http://danielpersson.dev
 * Text Domain:       sqrl
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * GitHub Plugin URI: http://github.com/kalaspuffar/wordpress-sqrl
 */
class SQRLLogin {

	/**
	 * Script version so scripts are reloaded in case of changes.
	 */
	const SCRIPT_VERSION = '2.1.0';

	/**
	 * SQRL state values
	 */
	const CURRENT_ID_MATCH       = 1;
	const PREVIOUS_ID_MATCH      = 2;
	const IP_MATCHED             = 4;
	const ACCOUNT_DISABLED       = 8;
	const FUNCTION_NOT_SUPPORTED = 16;
	const TRANSIENT_ERROR        = 32;
	const COMMAND_FAILED         = 64;
	const CLIENT_FAILURE         = 128;
	const BAD_ID_ASSOCIATION     = 256;

	/**
	 * Change messages
	 */
	const MESSAGE_DISABLED                 = 1;
	const MESSAGE_REMOVED                  = 2;
	const MESSAGE_SQRLONLY                 = 3;
	const MESSAGE_ERROR                    = 4;
	const MESSAGE_REGISTRATION_NOT_ALLOWED = 5;

	/**
	 * Command flags
	 */
	const COMMAND_LOGIN    = 1;
	const COMMAND_ENABLE   = 2;
	const COMMAND_DISABLE  = 3;
	const COMMAND_REMOVE   = 4;
	const COMMAND_REGISTER = 5;

	/**
	 * Timeout constant
	 */
	const SESSION_TIMEOUT = 15 * 60;

	/**
	 * SQRLLogin constructor.
	 *
	 * Setting up all places we want to show the login form and also all
	 * the get / post request we need to handle.
	 */
	public function __construct() {
		add_action( 'login_form', array( $this, 'add_to_login_form' ) );

		add_action( 'admin_post_sqrl_login', array( $this, 'login_callback' ) );
		add_action( 'admin_post_nopriv_sqrl_login', array( $this, 'login_callback' ) );
		add_action( 'admin_post_sqrl_logout', array( $this, 'logout_callback' ) );
		add_action( 'admin_post_nopriv_sqrl_logout', array( $this, 'logout_callback' ) );
		add_action( 'admin_post_sqrl_auth', array( $this, 'api_callback' ) );
		add_action( 'admin_post_nopriv_sqrl_auth', array( $this, 'api_callback' ) );

		add_action( 'admin_post_sqrl_check_login', array( $this, 'check_if_logged_in_ajax' ) );
		add_action( 'admin_post_nopriv_sqrl_check_login', array( $this, 'check_if_logged_in_ajax' ) );

		add_action( 'edit_user_profile', array( $this, 'associate_sqrl' ) );
		add_action( 'show_user_profile', array( $this, 'associate_sqrl' ) );

		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_scripts' ) );

		add_action( 'wp_login', array( $this, 'user_login' ), 10, 2 );
		add_filter( 'login_message', array( $this, 'user_login_message' ) );

		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_menu', array( $this, 'register_options_page' ) );

		add_action( 'register_form', array( $this, 'add_registration_fields' ) );
		add_action( 'user_register', array( $this, 'registration_save' ), 10, 1 );

		add_filter( 'site_url', array( $this, 'keep_registration_nut' ), 10, 4 );

		add_action( 'admin_post_nopriv_sqrl_registration_selection', array( $this, 'registration_selection' ) );
		add_action( 'admin_post_nopriv_sqrl_anonymous_registration', array( $this, 'anonymous_registration' ) );

	}

	/**
	 * This function handle the logging of the plugin so you may turn it on in your installation if you want
	 * to find the reason something does not work.
	 *
	 * @param string $message Message to log.
	 */
	public function sqrl_logging( $message ) {
		if ( WP_DEBUG === true ) {
			error_log( $message );
		}
	}

	/**
	 * Function to save the association and to create an anonymous account.
	 */
	public function anonymous_registration() {
		if ( empty( $_GET['nut'] ) ) {
			return;
		}

		// Validate session value
		// If the string is not Base64URL encoded, die here and don't process code below.
		$nut = sanitize_text_field( wp_unslash( $_GET['nut'] ) );
		$this->only_allow_base64_url( $nut );

		$session = get_transient( $nut );
		delete_transient( $nut );

		$this->create_user( $session['client'] );
		$session['user'] = $this->get_user_id( $session['client']['idk'] );
		$session['cmd']  = self::COMMAND_LOGIN;

		$nut = $this->generate_random_string();
		set_transient( $nut, $session, self::SESSION_TIMEOUT );
		$login_url = admin_url( 'admin-post.php' );
		$login_url = add_query_arg( 'action', 'sqrl_login', $login_url );
		$login_url = add_query_arg( 'nut', $nut, $login_url );
		wp_safe_redirect( $login_url );
		$this->terminate();
	}

	/**
	 * Show page enabling choice between creating an anonymous account or
	 * a registered user.
	 */
	public function registration_selection() {
		if ( empty( $_GET['nut'] ) ) {
			return;
		}

		wp_enqueue_style( 'buttons', get_site_url() . '/wp-includes/css/buttons.min.css', false, self::SCRIPT_VERSION, 'all' );
		wp_enqueue_style( 'login', get_site_url() . '/wp-admin/css/login.min.css', false, self::SCRIPT_VERSION, 'all' );

		// Validate session value
		// If the string is not Base64URL encoded, die here and don't process code below.
		$nut = sanitize_text_field( wp_unslash( $_GET['nut'] ) );
		$this->only_allow_base64_url( $nut );

		$sqrl_registration_option_title     = esc_html__( 'Registration selection', 'sqrl' );
		$sqrl_registration_option_header    = esc_html__( 'Select registration option', 'sqrl' );
		$sqrl_registration_option_anonymous = esc_html__( 'Anonymous registration', 'sqrl' );
		$sqrl_registration_option_normal    = esc_html__( 'Normal registration', 'sqrl' );

		$register_url = site_url( 'wp-login.php', 'https' );
		$register_url = add_query_arg( 'action', 'register', $register_url );
		$register_url = add_query_arg( 'nut', $nut, $register_url );

		$anonymous_url = admin_url( 'admin-post.php' );
		$anonymous_url = add_query_arg( 'action', 'sqrl_anonymous_registration', $anonymous_url );
		$anonymous_url = add_query_arg( 'nut', $nut, $anonymous_url );
		?>
		<!DOCTYPE html>
		<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<meta http-equiv="X-UA-Compatible" content="ie=edge">
				<meta name='robots' content='noindex,noarchive' />
				<meta name='referrer' content='strict-origin-when-cross-origin' />
				<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
				<title><?php echo $sqrl_registration_option_title; ?></title>

				<?php print_admin_styles(); ?>

				<style>
					.space {
						margin: 20px 0 0 0;
					}
				</style>
			</head>
			<body class="login login-action-register wp-core-ui locale-en-us">
				<div id="login">
					<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
					<p class="message register"><?php echo $sqrl_registration_option_header; ?></p>
					<form>
						<div>
							<a href="<?php echo $anonymous_url; ?>" class="button button-large"><?php echo $sqrl_registration_option_anonymous; ?></a>
						</div>
						<div class="space">
							<a href="<?php echo $register_url; ?>" class="button button-large"><?php echo $sqrl_registration_option_normal; ?></a>
						</div>
					</form>
				</div>
			</body>
		</html>
		<?php
	}

	/**
	 * This function will ensure to keep the nut even if we need to retry
	 * on the registration page if we select a email or username that is in used for instance.
	 *
	 * @param string      $url       The complete URL we want to change in order to keep nut.
	 * @param string      $path      Path relative to the site URL.
	 * @param string|null $scheme    Scheme to give the site URL context. Accepts 'http', 'https', 'login', 'login_post', 'admin', or 'relative'.
	 * @param int|null    $blog_id   Site ID. Default null (current site).
	 * @return string
	 */
	public function keep_registration_nut( $url, $path, $scheme, $blog_id ) {
		if ( 'login_post' === $scheme ) {
			if ( strpos( $url, '?action=register' ) !== false && ! empty( $_GET['nut'] ) ) {
				$url = add_query_arg( 'nut', sanitize_text_field( wp_unslash( $_GET['nut'] ) ), $url );
			}
		}
		return $url;
	}

	/**
	 * Add the nut to the registration page in order to create a user
	 * that we later can associate with the identity saved under the current nut.
	 */
	public function add_registration_fields() {
		if ( empty( $_GET['nut'] ) ) {
			return;
		}

		// Validate session value
		// If the string is not Base64URL encoded, die here and don't process code below.
		$nut = sanitize_text_field( wp_unslash( $_GET['nut'] ) );
		$this->only_allow_base64_url( $nut );

		?>
		<input type="hidden" name="nut" value="<?php echo $nut; ?>" />
		<?php
	}

	/**
	 * The last function in the chain to register a user and saving the identity
	 * association on the user.
	 *
	 * @see https://developer.wordpress.org/reference/hooks/user_register/
	 *
	 * @param int $user_id       User ID to associate identity with.
	 */
	public function registration_save( $user_id ) {
		if ( empty( $_POST['nut'] ) ) {
			return;
		}

		// Validate session value
		// If the string is not Base64URL encoded, die here and don't process code below.
		$nut = sanitize_text_field( wp_unslash( $_POST['nut'] ) );
		$this->only_allow_base64_url( $nut );

		$session = get_transient( $nut );
		delete_transient( $nut );

		$this->associate_user( $user_id, $session['client'] );

		$session['user'] = $user_id;
		$session['cmd']  = self::COMMAND_LOGIN;

		$nut = $this->generate_random_string();
		set_transient( $nut, $session, self::SESSION_TIMEOUT );
		$login_url = admin_url( 'admin-post.php' );
		$login_url = add_query_arg( 'action', 'sqrl_login', $login_url );
		$login_url = add_query_arg( 'nut', $nut, $login_url );
		wp_safe_redirect( $login_url );
		$this->terminate();
	}

	/**
	 * Function to register the admin group for SQRL settings.
	 */
	public function register_settings() {
		add_option( 'sqrl_redirect_url', get_site_url() );
		register_setting( 'sqrl_general', 'sqrl_redirect_url' );
	}

	/**
	 * Function to register the settings page for admin options.
	 */
	public function register_options_page() {
		add_options_page( 'Settings', 'SQRL Login', 'manage_options', 'sqrl_login', array( $this, 'options_page' ) );
	}

	/**
	 * Function to show options in the admin pages.
	 */
	public function options_page() {
		$settings_title = esc_html__( 'SQRL Login settings', 'sqrl' );
		$redirect_title = esc_html__( 'Redirect URL', 'sqrl' );
		$redirect_desc  = esc_html__( 'This URL is used to redirect the user after login if no redirect_to variable has been set.', 'sqrl' );
		?>
		<div class="wpbody-content">
			<div class="wrap">
				<h1><?php echo $settings_title; ?></h1>
				<form method="post" action="options.php">
					<?php settings_fields( 'sqrl_general' ); ?>
					<table class="form-table">
						<tr>
							<th scope="row">
								<label for="sqrl_redirect_url"><?php echo $redirect_title; ?></label>
							</th>
							<td>
								<input
									type="text"
									id="sqrl_redirect_url"
									name="sqrl_redirect_url"
									value="<?php echo esc_url( get_option( 'sqrl_redirect_url' ) ); ?>"
									class="regular-text ltr"
								/>
								<p class="description" id="sqrl_redirect_url_description">
									<?php echo $redirect_desc; ?>
								</p>
							</td>
						</tr>
					</table>
					<?php submit_button(); ?>
				</form>
			</div>
		</div>
		<?php
	}

	/**
	 * This will add the style script used by the plugin code.
	 */
	public function enqueue_scripts() {
		wp_enqueue_style( 'style', plugin_dir_url( __FILE__ ) . 'style.css', self::SCRIPT_VERSION, true );
	}

	/**
	 * Display screen in profile to associate or disassociate a SQRL login with a user
	 * profile.
	 *
	 * @param WP_User $user       User object of the associated user account.
	 */
	public function associate_sqrl( $user ) {
		$admin_post_path = wp_parse_url( admin_url( 'admin-post.php' ), PHP_URL_PATH );

		$sqrl_settings_title = esc_html__( 'SQRL settings', 'sqrl' );
		$disassociate_button = esc_html__( 'Disassociate', 'sqrl' );
		$hardlock_disclaimer = esc_html__( 'The hardlock option is set on this account but there is no real way to assure that it\'s honored by all WordPress implementations.', 'sqrl' );

		?>
		<h3><?php echo $sqrl_settings_title; ?></h3>
		<?php
		if ( get_user_meta( $user->ID, 'sqrl_idk', true ) ) {
			?>
			<table class="form-table">
				<tr>
					<th>
					</th>
					<td>
						<?php if ( get_user_meta( $user->ID, 'sqrl_hardlock', true ) ) { ?>
							<div class="sqrl-form" style="border-left: 3px solid #dc3232;">
								<div class="sqrl-login-row"><?php echo $hardlock_disclaimer; ?></div>
							</div>
						<?php } ?>
						<div class="sqrl-form">
							<?php $this->add_to_login_form( $user, true ); ?>
						</div>
					</td>
				</tr>
			</table>
			<?php
		} else {
			?>
			<table class="form-table">
				<tr>
					<th>
					</th>
					<td>
						<div class="sqrl-form">
							<?php $this->add_to_login_form( $user ); ?>
						</div>
					</td>
				</tr>
			</table>
			<?php
		}
	}

	/**
	 * Background call that the reload.js calls regularly to check if a login
	 * has been done correctly. Returns true only if a correct validated SQRL
	 * connection has been done.
	 */
	public function check_if_logged_in_ajax() {
		header( 'Access-Control-Allow-Origin: ' . get_site_url() );
		header( 'Access-Control-Allow-Credentials: true' );
		header( 'Access-Control-Max-Age: 1' ); // cache for 1 day.
		header( 'Access-Control-Allow-Methods: GET, OPTIONS' );

		if ( ! isset( $_GET['session'] ) ) {
			echo 'false';
			$this->terminate();
		}

		echo get_transient( sanitize_text_field( wp_unslash( $_GET['session'] ) ) ) === false ? 'false' : 'true';
	}

	/**
	 * Creates random string value of length 32 with characters between 0-9, a-z and A-Z.
	 */
	private function generate_random_string() {
		$x = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		return substr( str_shuffle( str_repeat( $x, ceil( 32 / strlen( $x ) ) ) ), 1, 32 );
	}

	/**
	 * Get the current client IP so we can verify it later to be the same when using CPS.
	 */
	private function get_client_ip() {
		$ip = '';
		if ( isset( $_SERVER['HTTP_CLIENT_IP'] ) && ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			// check ip from share internet.
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) );
		} elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			// to check ip is pass from proxy.
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
		} elseif ( isset( $_SERVER['REMOTE_ADDR'] ) && ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}
		return $ip;
	}

	/**
	 * Function to extract the domain and length of path from a site url.
	 */
	public function get_domain_and_path_length() {
		$site_url    = explode( '://', get_site_url() );
		$domain_name = $site_url[0];
		if ( 2 === count( $site_url ) ) {
			$domain_name = $site_url[1];
		}

		$slash_pos      = strpos( $domain_name, '/' );
		$path_len_param = '';
		if ( false !== $slash_pos ) {
			$path_len_param = '&x=' . ( strlen( $domain_name ) - $slash_pos );
			$domain_name    = substr( $domain_name, 0, $slash_pos );
		}
		return array( $domain_name, $path_len_param );
	}

	/**
	 * Add the SQRL specific code. Used both from the profile screen and the login screen to
	 * login users or associate them with a specific account.
	 *
	 * @param WP_User $user       User object of the logged in user account.
	 * @param bool    $associated True if the user is associated with a SQRL identity.
	 */
	public function add_to_login_form( $user = null, $associated = false ) {
		if ( get_option( 'users_can_register' ) ) {
			$button_label = esc_html__( 'Sign in or Register with SQRL', 'sqrl' );
			$qrcode_label = esc_html__( 'You may also sign in or register with SQRL using any SQRL-equipped smartphone by scanning this QR code.', 'sqrl' );
		} else {
			$button_label = esc_html__( 'Sign in with SQRL', 'sqrl' );
			$qrcode_label = esc_html__( 'You may also sign in with SQRL using any SQRL-equipped smartphone by scanning this QR code.', 'sqrl' );
		}

		if ( $associated ) {
			$button_label = esc_html__( 'Change your account', 'sqrl' );
			$qrcode_label = esc_html__( 'Scan QR code or click button to change account. Using your client you can disable, enable and remove the account.', 'sqrl' );
		} elseif ( $user ) {
			$button_label = esc_html__( 'Associate with account', 'sqrl' );
			$qrcode_label = esc_html__( 'Scan QR code or click button to associate to this account.', 'sqrl' );
		}

		$admin_post_path = wp_parse_url( admin_url( 'admin-post.php' ), PHP_URL_PATH );

		list( $domain_name, $path_len_param ) = $this->get_domain_and_path_length();

		$cancel_addr = '&can=' . $this->base64url_encode( get_site_url() );

		$nut      = $this->generate_random_string();
		$session  = $this->generate_random_string();
		$sqrl_url = 'sqrl://' . $domain_name . $admin_post_path . '?action=sqrl_auth&nut=' . $nut . $path_len_param . $cancel_addr;

		if ( $user ) {
			set_transient(
				$nut,
				array(
					'user'        => $user->ID,
					'ip'          => $this->get_client_ip(),
					'redir'       => isset( $_GET['redirect_to'] ) ? sanitize_text_field( wp_unslash( $_GET['redirect_to'] ) ) : '',
					'session'     => $session,
					'server_hash' => hash( 'sha256', $this->base64url_encode( $sqrl_url ) ),
				),
				self::SESSION_TIMEOUT
			);
		} else {
			set_transient(
				$nut,
				array(
					'user'        => false,
					'ip'          => $this->get_client_ip(),
					'redir'       => isset( $_GET['redirect_to'] ) ? sanitize_text_field( wp_unslash( $_GET['redirect_to'] ) ) : '',
					'session'     => $session,
					'server_hash' => hash( 'sha256', $this->base64url_encode( $sqrl_url ) ),
				),
				self::SESSION_TIMEOUT
			);
		}

		wp_enqueue_script( 'pagesync', plugin_dir_url( __FILE__ ) . 'pagesync.js', array(), self::SCRIPT_VERSION, true );
		wp_enqueue_script( 'qrcode', plugin_dir_url( __FILE__ ) . 'qrcode.min.js', array(), self::SCRIPT_VERSION, true );
		wp_register_script( 'reload', plugin_dir_url( __FILE__ ) . 'reload.js', array(), self::SCRIPT_VERSION, true );
		wp_localize_script(
			'reload',
			'sqrlReload',
			array(
				'adminURL'          => admin_url( 'admin-post.php' ),
				'session'           => $session,
				'existingUserParam' => $user ? '&existingUser=1' : '',
				'sqrlLoginURL'      => $sqrl_url,
				'countDownDesc'     => esc_html__( 'Will look for QR Login in' ),
			)
		);
		wp_enqueue_script( 'reload' );

		?>

<div class="sqrl-login-row">
	<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8Xw8AAoMBgDTD2qgAAAAASUVORK5CYII=" height="6">
</div>

<div class="sqrl-login-wrapper">
	<div class="sqrl-login-row">
		<img src="<?php echo plugins_url( 'images/SQRL_icon_normal_32.png', __FILE__ ); ?>" alt="SQRL"/> 
	</div>

	<div class="sqrl-login-row">
		<h3>Scan</h3>	
	</div>
	<div class="sqrl-login-row">
		<div id="sqrl-qrcode">
	</div>
	<div><?php echo $qrcode_label; ?></div>
</div>
<div class="sqrl-login-row">
	<span id="reloadDisplay"></span>
</div>
	<div class="sqrl-login-row">
		<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8Xw8AAoMBgDTD2qgAAAAASUVORK5CYII=" height="20">
	</div>
	<div class="sqrl-login-row">
		<hr class="dotted1" width="100%">
	</div>
	<div class="sqrl-login-row">
		<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8Xw8AAoMBgDTD2qgAAAAASUVORK5CYII=" height="15">
	</div>
	<div class="sqrl-login-row">
		<h3>-- or Click --</h3>	
	</div>
	<div class="sqrl-login-row">
		<a id="sqrl"
			href="<?php echo $sqrl_url; ?>" onclick="sqrlLinkClick( this );return true;"
			encoded-sqrl-url="<?php echo $this->base64url_encode( $sqrl_url ); ?>"
			tabindex="-1">
			Sign in with SQRL
		</a>
	</div>
	<div class="sqrl-login-row">
		<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8Xw8AAoMBgDTD2qgAAAAASUVORK5CYII=" height="10">
	</div>

	<div class="sqrl-login-row">
		<a href="https://play.google.com/store/apps/details?id=org.ea.sqrl">
			<img src="<?php echo plugins_url( 'images/en_badge_web_generic.png', __FILE__ ); ?>" alt="Get it on Google Play" height="60" />
		</a>
		<a href="https://www.grc.com/files/sqrl.exe">
			<img src="<?php echo plugins_url( 'images/microsoft.png', __FILE__ ); ?>" alt="Get it for Windows" height="42" />
		</a>
	</div>
</div>

<div class="sqrl-login-row">
	<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8Xw8AAoMBgDTD2qgAAAAASUVORK5CYII=" height="24">
</div>
		<?php
	}

	/**
	 * Base64 is an encoding to encode any set of bytes using only 64 characters. Usually this entails
	 * the characters a-z, A-Z, 0-9, /, + and =. The characters /, + and = are not valid characters to be
	 * used in URLs so Base64URL uses the _ instead of / and - instead of +. We also don't use any padding with
	 * = because that character does not work in URLs.
	 *
	 * The function below checks that the string is Base64URL encoded and if not it will report the string to
	 * the error log and die. This means that if any incorrect data is sent the execution will halt here and not
	 * continue.
	 *
	 * @param string $s    String to validate as an base64 url string.
	 */
	private function only_allow_base64_url( $s ) {
		if ( ! preg_match( '/^[a-zA-Z0-9_-]*$/', $s ) ) {
			$this->sqrl_logging( 'Incorrect input ' . $s );
			$this->exit_with_error_code( self::TRANSIENT_ERROR );
		}
	}

	/**
	 * This callback is called when ever the API requires the user to be logged out.
	 * The supplied message in the query parameter will display the reason for this action.
	 */
	public function logout_callback() {
		if ( ! empty( $_GET['message'] ) ) {
			return;
		}

		$message_key = sanitize_text_field( wp_unslash( $_GET['message'] ) );
		$this->logout_with_message( $message_key );
	}

	/**
	 * This function will add the message key to the login page when logging out
	 * from WordPress so the message with the specific message key can be displayed.
	 *
	 * @param int $message_key  Message number for the specific message to be shown.
	 */
	public function logout_with_message( $message_key ) {
		// Clear cookies, a.k.a log user out.
		wp_clear_auth_cookie();
		// Build login URL and then redirect.

		$login_url = site_url( 'wp-login.php', 'https' );
		$login_url = add_query_arg( 'message', $message_key, $login_url );

		wp_safe_redirect( $login_url );
		exit;
	}

	/**
	 * This function is called by the client in order to initiate an action, logging in,
	 * removing the association, locking or unlocking the account.
	 */
	public function login_callback() {
		// Validate session value.
		// If the string is not Base64URL encoded, die here and don't process code below.
		if ( isset( $_GET['session'] ) ) {
			$session_key = sanitize_text_field( wp_unslash( $_GET['session'] ) );
			$this->only_allow_base64_url( $session_key );
		}

		$session_nut = null;

		// Validate nut value.
		// If the string is not Base64URL encoded, die here and don't process code below.
		if ( isset( $_GET['nut'] ) ) {
			$session_nut = sanitize_text_field( wp_unslash( $_GET['nut'] ) );
			$this->only_allow_base64_url( $session_nut );
		}

		if ( empty( $session_key ) ) {
			$session_key = $session_nut;
		}
		$session = get_transient( $session_key );
		delete_transient( $session_key );

		if ( self::COMMAND_REMOVE === $session['cmd'] ) {
			if ( ! empty( $_GET['existingUser'] ) ) {
				wp_safe_redirect( admin_url( 'profile.php' ) );
			} else {
				$this->logout_with_message( self::MESSAGE_REMOVED );
			}
		}
		if ( self::MESSAGE_REGISTRATION_NOT_ALLOWED === $session['err'] ) {
			$this->logout_with_message( self::MESSAGE_REGISTRATION_NOT_ALLOWED );
		}
		if ( self::MESSAGE_ERROR === $session['err'] ) {
			$this->logout_with_message( self::MESSAGE_ERROR );
		}

		if ( self::COMMAND_REGISTER === $session['cmd'] ) {
			$nut = $this->generate_random_string();
			set_transient( $nut, $session, self::SESSION_TIMEOUT );
			$register_url = admin_url( 'admin-post.php' );
			$register_url = add_query_arg( 'action', 'sqrl_registration_selection', $register_url );
			$register_url = add_query_arg( 'nut', $nut, $register_url );
			wp_safe_redirect( $register_url );
			$this->terminate();
		}

		if ( self::COMMAND_LOGIN === $session['cmd'] || self::COMMAND_ENABLE === $session['cmd'] ) {
			wp_set_auth_cookie( $session['user'] );
		}

		$disabled = get_user_meta( $session['user'], 'sqrl_disable_user', true );
		if ( $disabled ) {
			$this->logout_with_message( self::MESSAGE_DISABLED );
		} elseif ( ! empty( $session['redir'] ) ) {
			wp_safe_redirect( $session['redir'] );
		} elseif ( ! empty( $_GET['existingUser'] ) ) {
			wp_safe_redirect( admin_url( 'profile.php' ) );
		} else {
			wp_safe_redirect( esc_url( get_option( 'sqrl_redirect_url' ) ) );
		}
	}

	/**
	 * This function is used to respond to the user with an message on API calls.
	 *
	 * @param string $content  String with the text to display to the client contacting the API endpoint.
	 */
	public function respond_with_message( $content ) {
		header( 'Content-Type: application/x-www-form-urlencoded' );
		header( 'Content-Length: ' . strlen( $content ) );
		echo $content;
		exit();
	}

	/**
	 * This function is terminating the execution and mostly for mocking purposes.
	 */
	public function terminate() {
		exit();
	}

	/**
	 * Return with information to the server about the error that occured.
	 *
	 * @param int          $ret_val                 State of the session to display for the end user of the client.
	 * @param bool         $client_provided_session If true the session have CPS enabled and could be redirected.
	 * @param object|false $transient_session       Current session with information about user, nut and command.
	 */
	public function exit_with_error_code( $ret_val, $client_provided_session = false, $transient_session = false ) {
		$response   = array();
		$response[] = 'ver=1';
		$response[] = 'tif=' . dechex( $ret_val );
		$response[] = 'sin=0';

		$nut = $this->generate_random_string();

		$admin_post_path = wp_parse_url( admin_url( 'admin-post.php' ), PHP_URL_PATH );

		if ( $transient_session ) {
			list( , $path_len_param ) = $this->get_domain_and_path_length();

			/*
			 * If we have a session we will prepare some extra return values to enable retries.
			 */
			$response[] = 'nut=' . $nut;
			$response[] = 'qry=' . $admin_post_path . '?action=sqrl_auth&nut=' . $nut . $path_len_param;
		}

		if ( $client_provided_session ) {
			$response[] = 'url=' . $this->get_server_url_without_path() . $admin_post_path . '?action=sqrl_logout&message=' . self::MESSAGE_ERROR;
		}

		$this->sqrl_logging( 'Failed response: ' . print_r( $response, true ) );

		$content = $this->base64url_encode( implode( "\r\n", $response ) . "\r\n" );

		if ( $transient_session ) {
			/*
			 * Setting server_hash to ensure possibility of retries for failed connections.
			 */
			$transient_session['server_hash'] = hash( 'sha256', $content );
			set_transient( $nut, $transient_session, self::SESSION_TIMEOUT );
		}
		$this->respond_with_message( $content );
	}

	/**
	 * This API callback will be called form the client to query for server status, login user,
	 * register new users, disable the account, enable the account and remove the account.
	 */
	public function api_callback() {

		// Fix to handle google bot trying to connect to the callback URL.
		// Looking for required post parameters and exit if missing.
		if ( ! isset( $_POST['client'] ) || ! isset( $_POST['server'] ) || ! isset( $_POST['ids'] ) ) {
			$this->sqrl_logging( 'Missing required parameter' );
			$this->exit_with_error_code( self::CLIENT_FAILURE );
		}

		// Validate Client data
		// If the string is not Base64URL encoded, die here and don't process code below.
		$client_input = sanitize_text_field( wp_unslash( $_POST['client'] ) );
		$this->only_allow_base64_url( $client_input );

		// Validate Server data
		// If the string is not Base64URL encoded, die here and don't process code below.
		$server_input = sanitize_text_field( wp_unslash( $_POST['server'] ) );
		$this->only_allow_base64_url( $server_input );

		// Validate Identity Signature
		// If the string is not Base64URL encoded, die here and don't process code below.
		$ids_input = sanitize_text_field( wp_unslash( $_POST['ids'] ) );
		$this->only_allow_base64_url( $ids_input );

		// Validate Previous Identity Signature
		// If the string is not Base64URL encoded, die here and don't process code below.
		if ( isset( $_POST['pids'] ) ) {
			$pids_input = sanitize_text_field( wp_unslash( $_POST['pids'] ) );
			$this->only_allow_base64_url( $pids_input );
		}

		// Validate Unlock Request Signature
		// If the string is not Base64URL encoded, die here and don't process code below.
		if ( isset( $_POST['urs'] ) ) {
			$urs_input = sanitize_text_field( wp_unslash( $_POST['urs'] ) );
			$this->only_allow_base64_url( $urs_input );
		}

		/**
		 * Reset return value used as the tif (Transaction Information Flags)
		 */
		$ret_val = 0;

		/**
		 * Split the client variables into an array so we can use them later.
		 */
		$client_str = explode( "\r\n", $this->base64url_decode( sanitize_text_field( wp_unslash( $_POST['client'] ) ) ) );
		$client     = array();
		foreach ( $client_str as $k => $v ) {
			list( $key, $val ) = $this->value_pair( $v );
			$client[ $key ]    = $val;
		}

		/**
		 * Prepare the admin post array that we will use multiple times to refeer the client back to
		 * the server.
		 */
		$admin_post_path = wp_parse_url( admin_url( 'admin-post.php' ), PHP_URL_PATH );

		$result = false;

		/**
		 * Check the user call that we have a valid signature for the current authentication.
		 */
		try {
			$result = sodium_crypto_sign_verify_detached(
				$this->base64url_decode( sanitize_text_field( wp_unslash( $_POST['ids'] ) ) ),
				sanitize_text_field( wp_unslash( $_POST['client'] ) ) . sanitize_text_field( wp_unslash( $_POST['server'] ) ),
				$this->base64url_decode( $client['idk'] )
			);
		} catch ( SodiumException $e ) {
			$this->sqrl_logging( $e->getMessage() );
			$this->exit_with_error_code( self::CLIENT_FAILURE );
		}

		if ( ! $result ) {
			$this->sqrl_logging( 'Incorrect signature' );
			$this->exit_with_error_code( self::CLIENT_FAILURE );
		}

		/**
		 * Check the user call that we have a valid previous if available signature for
		 * the current authentication.
		 */
		if ( ! empty( $client['pidk'] ) ) {
			try {
				$result = sodium_crypto_sign_verify_detached(
					$this->base64url_decode( sanitize_text_field( wp_unslash( $_POST['pids'] ) ) ),
					sanitize_text_field( wp_unslash( $_POST['client'] ) ) . sanitize_text_field( wp_unslash( $_POST['server'] ) ),
					$this->base64url_decode( sanitize_text_field( wp_unslash( $client['pidk'] ) ) )
				);
			} catch ( SodiumException $e ) {
				$this->sqrl_logging( $e->getMessage() );
				$this->exit_with_error_code( self::CLIENT_FAILURE );
			}

			if ( ! $result ) {
				$this->sqrl_logging( 'Incorrect previous signature' );
				$this->exit_with_error_code( self::CLIENT_FAILURE );
			}
		}

		/**
		 * Prepare the server values. If the previous value from the client is only a single value that means
		 * the client only have seen the URL from the server and we should fetch the query values from the call.
		 *
		 * Otherwise we handle the server string with properties that are line separated.
		 */
		$server_hash = sanitize_text_field( wp_unslash( $_POST['server'] ) );
		$server_str  = explode( "\r\n", $this->base64url_decode( $server_hash ) );
		$server      = array();
		if ( count( $server_str ) === 1 ) {
			$server_str = substr( $server_str[0], strpos( $server_str[0], '?' ) + 1 );
			foreach ( explode( '&', $server_str ) as $k => $v ) {
				list( $key, $val ) = $this->value_pair( $v );
				$server[ $key ]    = $val;
			}
		} else {
			foreach ( $server_str as $k => $v ) {
				list( $key, $val ) = $this->value_pair( $v );
				$server[ $key ]    = $val;
			}
		}

		/**
		 * Explode the option array with all the SQRL options. Valid values are
		 *
		 * Value: suk = Request for Server unlock key
		 * Value: cps = Client Provided Session is available
		 * Value: noiptest = Server don't need to check the IP address of the client (remote device login)
		 * Value: sqrlonly = Client requests the server to only allow SQRL logins, all other authentication should be
		 *        disabled.
		 * Value: hardlock = Client request all "out of band" changes to the account. Like security questions to
		 *        retrieve the account when password is lost.
		 */
		$options                 = array();
		$client_provided_session = false;
		if ( isset( $client['opt'] ) ) {
			foreach ( explode( '~', $client['opt'] ) as $v ) {
				$options[ $v ] = true;
			}
			$client_provided_session = strpos( $client['opt'], 'cps' ) !== false;
		}

		/**
		 * Fetch the current transient session where we keep all session information.
		 */
		$transient_session = false;
		if ( isset( $server['nut'] ) ) {
			$transient_session = get_transient( $server['nut'] );
			delete_transient( $server['nut'] );
		}
		if ( false === $transient_session ) {
			$this->sqrl_logging( 'Missing transient session' );
			$this->exit_with_error_code( self::TRANSIENT_ERROR, $client_provided_session );
		}

		/**
		 * Check if the users IP have changed since last time we logged in. Only required when CPS is used.
		 */
		if ( ! isset( $options['noiptest'] ) ) {
			if ( ! empty( $transient_session['ip'] ) && $transient_session['ip'] === $this->get_client_ip() ) {
				$ret_val += self::IP_MATCHED;
			}
		}

		/**
		 * Check that the server information sent back from the client haven't been tampered with.
		 */
		if ( ! isset( $transient_session['server_hash'] ) || hash( 'sha256', $server_hash ) !== $transient_session['server_hash'] ) {
			$this->sqrl_logging( 'Incorrect server hash' );
			$this->exit_with_error_code( self::CLIENT_FAILURE, $client_provided_session );
		}

		/**
		 * Get the a new random nut
		 */
		$nut = $this->generate_random_string();

		/**
		 * Prepare response.
		 *
		 * Set version number for the call, new nut for the session and a path with query that the next client
		 * call should use in order to contact the server.
		 */
		list( , $path_len_param ) = $this->get_domain_and_path_length();

		$associated_existing_user = false;
		$response                 = array();
		$response[]               = 'ver=1';

		if ( ! isset( $client['cmd'] ) ) {
			/**
			 * If command isn't supplied, Not implemented yet we should print the client request and die.
			 */
			$this->sqrl_logging( print_r( $client, true ) );
			$this->exit_with_error_code( self::FUNCTION_NOT_SUPPORTED, $client_provided_session, $transient_session );
		}

		if ( 'query' === $client['cmd'] ) {
			/**
			 * Query the system for the current user status.
			 */
			if ( $this->account_present( $client['idk'] ) ) {
				$ret_val += self::CURRENT_ID_MATCH;

				/**
				 * If the client requests a Server Unlock Key then add that to the response.
				 */
				if ( isset( $options['suk'] ) ) {
					$response[] = 'suk=' . $this->get_server_unlock_key( $client );
				}
			}

			if ( isset( $client['pidk'] ) && $this->account_present( $client['pidk'] ) ) {
				$ret_val += self::PREVIOUS_ID_MATCH;
			}
			if ( $this->account_disabled( $client ) ) {
				$ret_val += self::ACCOUNT_DISABLED;
			}
		} elseif ( 'ident' === $client['cmd'] ) {
			/**
			 * Identify with the system either creating a new user or authorizing login with a user
			 * already in the system.
			 */
			if ( ! $this->account_present( $client['idk'] ) ) {
				/*
				 * Fetch the current user from the transient session store and remove it as we only keep
				 * it for the current session.
				 */
				$user = false;
				if ( isset( $transient_session['user'] ) ) {
					$user = $transient_session['user'];
				}

				/*
				 * We need to check if the user is in the transient session before we lookup the user from
				 * a previous identity. This association is only on already logged in users on the profile page.
				 */
				if ( $user ) {
					$associated_existing_user = true;
				}

				/*
				 * Check if we have a hit on a previous account so we need to update the current identity
				 * to our new identity identifier.
				 */
				if ( isset( $client['pidk'] ) && ! $user && $this->account_present( $client['pidk'] ) ) {
					$user = $this->get_user_id( $client['pidk'] );
				}

				/*
				 * Check if we should associate an old user or create a new one. Checking if registering users
				 * are allowed on the current installation.
				 */
				if ( $user ) {
					$this->associate_user( $user, $client );
				} else {
					if ( ! get_option( 'users_can_register' ) ) {
						$transient_session['err'] = self::MESSAGE_REGISTRATION_NOT_ALLOWED;
					} else {
						$transient_session['client'] = $client;
						$transient_session['cmd']    = self::COMMAND_REGISTER;
					}
				}
			}

			/**
			 * Check if user is present in the system after eventual creation of the user.
			 */
			if ( $this->account_present( $client['idk'] ) ) {
				$ret_val += self::CURRENT_ID_MATCH;

				$transient_session['cmd']  = self::COMMAND_LOGIN;
				$transient_session['user'] = $this->get_user_id( $client['idk'] );
			}

			/**
			 * If Client Provided Session is enabled we need to respond with links for the client to follow in order
			 * to securely login.
			 */
			if ( $client_provided_session ) {
				$response[] = 'url=' . $this->get_server_url_without_path() . $admin_post_path .
					'?action=sqrl_login&nut=' . $nut .
					( $associated_existing_user ? '&existingUser=1' : '' );
			} else {
				/**
				 * Add session data signaling to the reload.js script that a login has been successfully transacted.
				 */
				if ( ! isset( $transient_session['session'] ) ) {
					$this->sqrl_logging( 'Missing transient session' );
					$this->exit_with_error_code( self::TRANSIENT_ERROR, $client_provided_session );
				}
				set_transient( $transient_session['session'], $transient_session, self::SESSION_TIMEOUT );
			}
		} elseif ( 'disable' === $client['cmd'] ) {
			/*
			 * Fetch user to disable.
			 */
			$user = $this->get_user_id( $client['idk'] );
			if ( ! $user ) {
				$user = $this->get_user_id( $client['pidk'] );
			}

			if ( ! $user ) {
				$this->sqrl_logging( 'User is missing, can\'t disable' );
				$this->exit_with_error_code( self::COMMAND_FAILED, $client_provided_session, $transient_session );
			}

			update_user_meta( $user, 'sqrl_disable_user', true );

			$ret_val += self::CURRENT_ID_MATCH + self::ACCOUNT_DISABLED;

			$transient_session['cmd']  = self::COMMAND_DISABLE;
			$transient_session['user'] = $user;

			$response[] = 'suk=' . $this->get_server_unlock_key( $client );

			/**
			 * If Client Provided Session is enabled we need to respond with links for the client to follow in order
			 * to securely login.
			 */
			if ( $client_provided_session ) {
				$response[] = 'url=' . $this->get_server_url_without_path() . $admin_post_path . '?action=sqrl_logout&message=' . self::MESSAGE_DISABLED;
			} else {
				/**
				 * Add session data signaling to the reload.js script that a login has been successfully transacted.
				 */
				if ( ! isset( $transient_session['session'] ) ) {
					$this->sqrl_logging( 'Missing transient session' );
					$this->exit_with_error_code( self::TRANSIENT_ERROR, $client_provided_session );
				}
				set_transient( $transient_session['session'], $transient_session, self::SESSION_TIMEOUT );
			}
		} elseif ( 'enable' === $client['cmd'] ) {
			/*
			 * Fetch user to be enabled.
			 */
			$user = $this->get_user_id( $client['idk'] );
			if ( ! $user ) {
				$user = $this->get_user_id( $client['pidk'] );
			}
			if ( empty( $user ) ) {
				$this->sqrl_logging( 'User is missing, can\'t be enable' );
				$this->exit_with_error_code( self::COMMAND_FAILED, $client_provided_session, $transient_session );
			}
			if ( ! $this->account_disabled( $client ) ) {
				$this->sqrl_logging( 'User is not disabled, can\'t be enable' );
				$this->exit_with_error_code( self::COMMAND_FAILED, $client_provided_session, $transient_session );
			}

			$result = sodium_crypto_sign_verify_detached(
				$this->base64url_decode( sanitize_text_field( wp_unslash( $_POST['urs'] ) ) ),
				sanitize_text_field( wp_unslash( $_POST['client'] ) ) . sanitize_text_field( wp_unslash( $_POST['server'] ) ),
				$this->base64url_decode( $this->get_verify_unlock_key( $client ) )
			);
			if ( ! $result ) {
				$this->sqrl_logging( 'Incorrect Unlock Request signature' );
				$this->exit_with_error_code( self::COMMAND_FAILED, $client_provided_session, $transient_session );
			}

			delete_user_meta( $user, 'sqrl_disable_user' );

			$ret_val += self::CURRENT_ID_MATCH;

			$transient_session['cmd']  = self::COMMAND_ENABLE;
			$transient_session['user'] = $user;

			/**
			 * If Client Provided Session is enabled we need to respond with links for the client to follow in order
			 * to securely login.
			 */
			if ( $client_provided_session ) {
				$response[] = 'url=' . $this->get_server_url_without_path() . $admin_post_path .
					'?action=sqrl_login&nut=' . $nut;
			} else {
				/**
				 * Add session data signaling to the reload.js script that a login has been successfully transacted.
				 */
				if ( ! isset( $transient_session['session'] ) ) {
					$this->sqrl_logging( 'Missing transient session' );
					$this->exit_with_error_code( self::TRANSIENT_ERROR, $client_provided_session );
				}
				set_transient( $transient_session['session'], $transient_session, self::SESSION_TIMEOUT );
			}
		} elseif ( 'remove' === $client['cmd'] ) {
			/*
			 * Fetch user to be removed.
			 */
			$user = $this->get_user_id( $client['idk'] );
			if ( ! $user ) {
				$user = $this->get_user_id( $client['pidk'] );
			}
			if ( empty( $user ) ) {
				$this->sqrl_logging( 'User is missing, can\'t be removed' );
				$this->exit_with_error_code( self::COMMAND_FAILED, $client_provided_session, $transient_session );
			}

			$result = sodium_crypto_sign_verify_detached(
				$this->base64url_decode( sanitize_text_field( wp_unslash( $_POST['urs'] ) ) ),
				sanitize_text_field( wp_unslash( $_POST['client'] ) ) . sanitize_text_field( wp_unslash( $_POST['server'] ) ),
				$this->base64url_decode( $this->get_verify_unlock_key( $client ) )
			);
			if ( ! $result ) {
				$this->sqrl_logging( 'Incorrect Unlock Request signature' );
				$this->exit_with_error_code( self::COMMAND_FAILED, $client_provided_session, $transient_session );
			}

			$transient_session['cmd'] = self::COMMAND_REMOVE;

			$this->dis_associate_user( $user );
			/**
			 * If Client Provided Session is enabled we need to respond with links for the client to follow in order
			 * to securely login.
			 */
			if ( $client_provided_session ) {
				$profile_path = wp_parse_url( admin_url( 'profile.php' ), PHP_URL_PATH );
				if ( ! empty( $transient_session['user'] ) ) {
					$response[] = 'url=' . $this->get_server_url_without_path() . $profile_path;
				} else {
					$response[] = 'url=' . $this->get_server_url_without_path() . $admin_post_path . '?action=sqrl_logout&message=' . self::MESSAGE_REMOVED;
				}
			} else {
				if ( ! isset( $transient_session['session'] ) ) {
					$this->sqrl_logging( 'Missing transient session' );
					$this->exit_with_error_code( self::TRANSIENT_ERROR, $client_provided_session );
				}
				set_transient( $transient_session['session'], $transient_session, self::SESSION_TIMEOUT );
			}
		} else {
			/**
			 * If we have an unknown command, Not implemented yet we should print the client request and die.
			 */
			$this->sqrl_logging( print_r( $client, true ) );
			$this->exit_with_error_code( self::FUNCTION_NOT_SUPPORTED, $client_provided_session, $transient_session );
		}

		/**
		 * Set the extra options for users preferences.
		 */
		$this->update_options( $client, $options );

		/**
		 * Set the status condition code for this call.
		 */
		$response[] = 'tif=' . dechex( $ret_val );
		$response[] = 'sin=0';

		/*
		 * Prepare the return values.
		 */
		$response[] = 'nut=' . $nut;
		$response[] = 'qry=' . $admin_post_path . '?action=sqrl_auth&nut=' . $nut . $path_len_param;
		$content    = $this->base64url_encode( implode( "\r\n", $response ) . "\r\n" );

		/*
		 * Set the transient session where we keep all the session information.
		 */
		$transient_session['server_hash'] = hash( 'sha256', $content );
		set_transient( $nut, $transient_session, self::SESSION_TIMEOUT );

		/**
		 * Display the result as an base64url encoded string.
		 */
		$this->respond_with_message( $content );
	}

	/**
	 * Update user preferences.
	 *
	 * SQRLOnly = Don't allow login using username and password.
	 * Hardlock = Don't allow the user to request a password reset.
	 *
	 * @param array  $client    Current client parameter sent from the client.
	 * @param object $options   Options sent from the client, the options handled here are preferences for login.
	 */
	private function update_options( $client, $options ) {
		$user = $this->get_user_id( $client['idk'] );

		$sqrlonly = isset( $options['sqrlonly'] ) ? 1 : 0;
		$hardlock = isset( $options['hardlock'] ) ? 1 : 0;

		update_user_meta( $user, 'sqrl_sqrlonly', $sqrlonly );
		update_user_meta( $user, 'sqrl_hardlock', $hardlock );
	}

	/**
	 * Check if a user account is disabled.
	 *
	 * @param object $client   Current client parameter sent from the client.
	 *
	 * @return bool|mixed
	 */
	private function account_disabled( $client ) {
		/*
		 * Fetch user to check.
		 */
		$user = $this->get_user_id( $client['idk'] );
		if ( ! $user && isset( $client['pidk'] ) ) {
			$user = $this->get_user_id( $client['pidk'] );
		}
		if ( ! $user ) {
			return false;
		}
		return get_user_meta( $user, 'sqrl_disable_user', true );
	}

	/**
	 * This will disable login for disabled users.
	 *
	 * Code inspired by https://github.com/jaredatch/Disable-Users
	 *
	 * @param object $user_login   Login parameter to find user by.
	 * @param object $user         User object of the currently logged in user.
	 */
	public function user_login( $user_login, $user = null ) {
		if ( ! $user ) {
			$user = get_user_by( 'login', $user_login );
		}
		if ( ! $user ) {
			// not logged in - definitely not disabled.
			return;
		}
		// Get user meta.
		$disabled = get_user_meta( $user->ID, 'sqrl_disable_user', true );
		$sqrlonly = get_user_meta( $user->ID, 'sqrl_sqrlonly', true );

		$login_url = site_url( 'wp-login.php', 'login' );

		if ( '1' === $disabled && '1' === $sqrlonly ) {
			wp_clear_auth_cookie();
			$login_url = add_query_arg( 'message', self::MESSAGE_DISABLED, $login_url );
			wp_safe_redirect( $login_url );
			exit;
		}
		if ( '1' === $sqrlonly ) {
			wp_clear_auth_cookie();
			$login_url = add_query_arg( 'message', self::MESSAGE_SQRLONLY, $login_url );
			wp_safe_redirect( $login_url );
			exit;
		}
	}

	/**
	 * This will show a message that the user account is disabled.
	 *
	 * Code inspired by https://github.com/jaredatch/Disable-Users
	 *
	 * @param string $message  Original message.
	 *
	 * @return string
	 */
	public function user_login_message( $message = '' ) {
		if ( isset( $_GET['message'] ) && self::MESSAGE_DISABLED === (int) $_GET['message'] ) {
			$message .= '<div id="login_error">' . esc_html__( 'Account disabled', 'sqrl' ) . '</div>';
		}
		if ( isset( $_GET['message'] ) && self::MESSAGE_REMOVED === (int) $_GET['message'] ) {
			$message .= '<div id="login_error">' . esc_html__( 'Identity disassociated from account', 'sqrl' ) . '</div>';
		}
		if ( isset( $_GET['message'] ) && self::MESSAGE_SQRLONLY === (int) $_GET['message'] ) {
			$message .= '<div id="login_error">' . esc_html__( 'The only allowed login method is SQRL for this account', 'sqrl' ) . '</div>';
		}
		if ( isset( $_GET['message'] ) && self::MESSAGE_ERROR === (int) $_GET['message'] ) {
			$message .= '<div id="login_error">' . esc_html__( 'An error occurred with the last SQRL command, please try again.', 'sqrl' ) . '</div>';
		}
		if ( isset( $_GET['message'] ) && self::MESSAGE_REGISTRATION_NOT_ALLOWED === (int) $_GET['message'] ) {
			$message .= '<div id="login_error">' . esc_html__( 'The site is not allowing new registrations and your SQRL identity is not associated with any account.', 'sqrl' ) . '</div>';
		}

		if ( ! is_ssl() ) {
			$message .= '<div id="login_error">' . esc_html__( 'SQRL Login is only available for sites utilizing SSL connections. Please activate SSL before using SQRL Login.', 'sqrl' ) . '</div>';
		}

		return $message;
	}

	/**
	 * This function returns the server url without path
	 */
	private function get_server_url_without_path() {
		$parsed_url = wp_parse_url( get_site_url() );

		$url  = $parsed_url['scheme'];
		$url .= '://';
		$url .= $parsed_url['host'];
		if ( ! empty( $parsed_url['port'] ) ) {
			$url .= ':';
			$url .= $parsed_url['port'];
		}
		return $url;
	}

	/**
	 * This function will create a new user and associate it with an SQRL identity
	 *
	 * @param object $client    Current client parameter sent from the client.
	 */
	private function create_user( $client ) {
		$random_user_string = $this->get_random_unique_username( 'user_' );

		$new_user = wp_create_user(
			$random_user_string,
			wp_generate_password(),
			$random_user_string . '@localhost'
		);

		$this->associate_user( $new_user, $client );
	}

	/**
	 * This function associates a user with a SQRL identity.
	 *
	 * Identity key (idk) used to check the validity of the current user and also
	 * associate the current login with the account.
	 *
	 * Server unlock key (suk) is returned on request from the client when the client
	 * requires it for more advanced features.
	 *
	 * Verify Unlock Key (vuk) used to verify the unlock request signature sent from the client
	 * when an disabled account should be enabled again.
	 *
	 * @param int    $user_id   User ID to update login keys for.
	 * @param object $client    Current client parameter sent from the client.
	 */
	private function associate_user( $user_id, $client ) {
		if ( ! isset( $client['idk'] ) || ! isset( $client['suk'] ) || ! isset( $client['vuk'] ) ) {
			$this->sqrl_logging( 'Missing required parameter' );
			$this->exit_with_error_code( self::CLIENT_FAILURE );
		}

		update_user_meta( $user_id, 'sqrl_idk', sanitize_text_field( $client['idk'] ) );
		update_user_meta( $user_id, 'sqrl_suk', sanitize_text_field( $client['suk'] ) );
		update_user_meta( $user_id, 'sqrl_vuk', sanitize_text_field( $client['vuk'] ) );
	}

	/**
	 * This function removes the SQRL identifying data from the user account.
	 *
	 * Identity key (idk) used to check the validity of the current user and also
	 * associate the current login with the account.
	 *
	 * Server unlock key (suk) is returned on request from the client when the client
	 * requires it for more advanced features.
	 *
	 * Verify Unlock Key (vuk) used to verify the unlock request signature sent from the client
	 * when an disabled account should be enabled again.
	 *
	 * @param object $user   User to remove login keys for.
	 */
	public function dis_associate_user( $user ) {
		delete_user_meta( $user, 'sqrl_idk' );
		delete_user_meta( $user, 'sqrl_suk' );
		delete_user_meta( $user, 'sqrl_vuk' );
	}

	/**
	 * Gets the server unlock code, saved for the user so the user can ask for
	 * it when doing special operations like enabling or removing the SQRL identity
	 * from the system.
	 *
	 * @param string $idk_val    Identity key value used to lookup user id.
	 *
	 * @return false|mixed
	 */
	private function get_user_id( $idk_val ) {
		if ( empty( $idk_val ) ) {
			return false;
		}

		$wp_users = get_users(
			array(
				'meta_key'    => 'sqrl_idk',
				'meta_value'  => sanitize_text_field( $idk_val ),
				'number'      => 1,
				'count_total' => false,
				'fields'      => 'id',
			)
		);

		if ( ! isset( $wp_users[0] ) ) {
			return false;
		}

		return (int) $wp_users[0];
	}

	/**
	 * Gets the server unlock code, saved for the user so the user can ask for
	 * it when doing special operations like enabling or removing the SQRL identity
	 * from the system.
	 *
	 * @param object $client    Current client parameter sent from the client.
	 *
	 * @return false|mixed
	 */
	private function get_server_unlock_key( $client ) {
		if ( empty( $client['idk'] ) ) {
			return false;
		}

		$wp_users = get_users(
			array(
				'meta_key'    => 'sqrl_idk',
				'meta_value'  => sanitize_text_field( $client['idk'] ),
				'number'      => 1,
				'count_total' => false,
				'fields'      => 'id',
			)
		);

		if ( ! isset( $wp_users[0] ) ) {
			return false;
		}

		return get_user_meta( $wp_users[0], 'sqrl_suk', true );
	}

	/**
	 * Gets the verify unlock code, saved for the user we can verify special
	 * operations like enabling and removing accounts.
	 *
	 * @param object $client   Current client parameter sent from the client.
	 *
	 * @return false|mixed
	 */
	private function get_verify_unlock_key( $client ) {
		if ( empty( $client['idk'] ) ) {
			return false;
		}

		$wp_users = get_users(
			array(
				'meta_key'    => 'sqrl_idk',
				'meta_value'  => sanitize_text_field( $client['idk'] ),
				'number'      => 1,
				'count_total' => false,
				'fields'      => 'id',
			)
		);

		if ( ! isset( $wp_users[0] ) ) {
			return false;
		}

		return get_user_meta( $wp_users[0], 'sqrl_vuk', true );
	}


	/**
	 * Checks if the current client requests identity is already associated with a user
	 * in the system.
	 *
	 * @param string $idk_val    Identity key value used see if the account is associated with a user.
	 *
	 * @return bool
	 */
	private function account_present( $idk_val ) {
		if ( empty( $idk_val ) ) {
			return false;
		}

		$wp_users = get_users(
			array(
				'meta_key'    => 'sqrl_idk',
				'meta_value'  => sanitize_text_field( $idk_val ),
				'number'      => 1,
				'count_total' => false,
				'fields'      => 'id',
			)
		);

		if ( empty( $wp_users[0] ) ) {
			return false;
		}
		return true;
	}

	/**
	 * This function will create a random username. This will be used to create anonymous logins
	 * when registering a new user.
	 *
	 * @param string $prefix    String appended before the random number of this anonymous user.
	 *
	 * @return string
	 */
	private function get_random_unique_username( $prefix = '' ) {
		$user_exists = 1;

		do {
			$rnd_str     = sprintf( '%0d', wp_rand( 1, 99999999999999 ) );
			$user_exists = username_exists( $prefix . $rnd_str );
		} while ( $user_exists > 0 );

		return $prefix . $rnd_str;
	}

	/**
	 * Base64 is an encoding to encode any set of bytes using only 64 characters. Usually this entails
	 * the characters a-z, A-Z, 0-9, /, + and =. The characters /, + and = are not valid characters to be
	 * used in URLs so Base64URL uses the _ instead of / and - instead of +. We also don't use any padding with
	 * = because that character does not work in URLs.
	 *
	 * The functions below encodes and decodes strings to and from Base64URL encoding. Simply replacing the
	 * not allowed characters before doing a regular base64 decoding and removing any padding.
	 *
	 * @param string $data   Data to encode into base64 url.
	 *
	 * @return string
	 */
	private function base64url_encode( $data ) {
		$data = str_replace( array( '+', '/' ), array( '-', '_' ), base64_encode( $data ) );
		$data = rtrim( $data, '=' );
		return $data;
	}

	/**
	 * Base64 is an encoding to encode any set of bytes using only 64 characters. Usually this entails
	 * the characters a-z, A-Z, 0-9, /, + and =. The characters /, + and = are not valid characters to be
	 * used in URLs so Base64URL uses the _ instead of / and - instead of +. We also don't use any padding with
	 * = because that character does not work in URLs.
	 *
	 * The functions below encodes and decodes strings to and from Base64URL encoding. Simply replacing the
	 * not allowed characters before doing a regular base64 decoding and removing any padding.
	 *
	 * @param string $data   Data to decode from base64 url.
	 *
	 * @return string
	 */
	private function base64url_decode( $data ) {
		return base64_decode( str_replace( array( '-', '_' ), array( '+', '/' ), $data ) );
	}

	/**
	 * This function will find a equal character and divide a string into two parts, one before this
	 * character and one after. Notice that this function is similar but different than explode because
	 * it can have multiple equal characters present but will only split on the first one.
	 *
	 * @param string $str   String to split into a pair.
	 *
	 * @return array
	 */
	private function value_pair( $str ) {
		$eq_pos = strpos( $str, '=' );
		return array( substr( $str, 0, $eq_pos ), substr( $str, $eq_pos + 1 ) );
	}
}

new SQRLLogin();
