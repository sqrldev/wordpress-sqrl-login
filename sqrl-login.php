<?php
/**
 * Plugin Name:       SQRL Login
 * Description:       Login and Register your users using SQRL
 * Version:           0.2.2
 * Author:            Daniel Persson
 * Author URI:        http://danielpersson.dev
 * Text Domain:       sqrl
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * GitHub Plugin URI: http://github.com/kalaspuffar/wordpress-sqrl
 */

class SQRLLogin{

    /**
     * SQRLLogin constructor.
	 * 
	 * Setting up all places we want to show the login form and also all
	 * the get / post request we need to handle.
     */
    public function __construct() {
		add_action('login_form', array($this, 'addToLoginForm'));

		add_action( 'admin_post_sqrl_login', array($this, 'loginCallback'));
        add_action( 'admin_post_nopriv_sqrl_login', array($this, 'loginCallback'));
        add_action( 'admin_post_sqrl_auth', array($this, 'apiCallback'));
        add_action( 'admin_post_nopriv_sqrl_auth', array($this, 'apiCallback'));

		add_action( 'admin_post_sqrl_check_login', array($this, 'checkIfLoggedInAjax'));
		add_action( 'admin_post_nopriv_sqrl_check_login', array($this, 'checkIfLoggedInAjax'));

		add_action( 'edit_user_profile', array($this, 'associateSQRL') );
		add_action( 'show_user_profile', array($this, 'associateSQRL') );

		add_action( 'admin_post_sqrl_disassociate', array($this, 'disAssociateUser') );
	}

	/**
	 * Display screen in profile to associate or disassociate a SQRL login with a user
	 * profile.
	 */
	function associateSQRL($user) {
		$adminPostPath = parse_url(admin_url('admin-post.php'), PHP_URL_PATH);

		?>
		<h3>Associate SQRL to profile</h3>
		<?php
		if(get_user_meta($user->id, 'idk', true)) {
			?>
			<table class="form-table">
				<tr>
					<th>
					</th>
					<td>
						<div class="sqrl-form">
							<a href="<?php echo $adminPostPath ?>?action=sqrl_disassociate">Disassociate SQRL identity</a>
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
							<?php $this->addToLoginForm($user); ?>
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
	function checkIfLoggedInAjax() {
		$siteURL = "https://uhash.com";
		header("Access-Control-Allow-Origin: {$siteURL}");
		header('Access-Control-Allow-Credentials: true');
		header('Access-Control-Max-Age: 1');    // cache for 1 day
		header("Access-Control-Allow-Methods: GET, OPTIONS");

		$wp_users = get_users(array(
			'meta_key'     => 'sqrl_session',
			'meta_value'   => sanitize_text_field($_GET['session']),
			'number'       => 1,
			'count_total'  => false,
			'fields'       => 'id',
		));

		if($wp_users[0]) {
			echo "true";
		} else {
			echo "false";
		}
	}

	/**
	 * Creates random string value of any length (default 16) with characters between 0-9, a-z and A-Z.
	 */
	function generateRandomString($length = 16) {
		return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
	}

	/**
	 * Add the SQRL specific code. Used both from the profile screen and the login screen to
	 * login users or associate them with a specific account.
	 */
    public function addToLoginForm($user = false) {
        if (get_option( 'users_can_register' )) {
            $button_label = __('Login or Register with SQRL', 'sqrl');
        } else {
            $button_label = __('Login with SQRL', 'sqrl');
        }

		$adminPostPath = parse_url(admin_url('admin-post.php'), PHP_URL_PATH);

		$siteUrl = explode("://", get_site_url());
		$domainName = $siteUrl[0];
		if(count($siteUrl) == 2) {
			$domainName = $siteUrl[1];
		}

		$session = $this->generateRandomString();
		$nut = $this->generateRandomString();
		$sqrlURL = 'sqrl://' . $domainName . $adminPostPath . '?action=sqrl_auth&nut=' . $nut . '-' . $session;

		if($user) {
			set_transient($session, $user->id, 15 * 60);
		}

		$html .= '<div class="sqrl-login-wrapper">';
		$html .= '	<div class="sqrl-login-row">';
		$html .= '		<a id="sqrl" href="' . $sqrlURL . '" onclick="sqrlLinkClick(this);return true;" encoded-sqrl-url="' . $this->base64url_encode($sqrlURL) . '" tabindex="-1">';
		$html .= '			<img src="' . plugins_url( 'images/sqrl-button.png', __FILE__ ) . '"/>';
		$html .= '		</a>';
		$html .= '	</div>';
		$html .= '	<div class="sqrl-login-row">';
		$html .= '		<img src="https://chart.googleapis.com/chart?chs=150x150&cht=qr&chld=M|0&chl=' . urlencode($sqrlURL) . '"/>';
		$html .= '		<div>';
		$html .= '			You may also login with SQRL using';
		$html .= '			any SQRL-equipped smartphone by';
		$html .= '			scanning this QR code.';
		$html .= '		</div>';
		$html .= '	</div>';
		$html .= '	<div class="sqrl-login-row">';
		$html .= '		<span id="reloadDisplay"></span>';
		$html .= '	</div>';
		$html .= '	<div class="sqrl-login-row">';
		$html .= '	    <a href="https://play.google.com/store/apps/details?id=org.ea.sqrl">';
		$html .= '		   <img src="' . plugins_url( 'images/en_badge_web_generic.png', __FILE__ ) . '" alt="Get it on Google Play" height="60" />';
		$html .= '	    </a>';
		$html .= '	    <a href="https://www.grc.com/files/sqrl.exe">';
		$html .= '		   <img src="' . plugins_url( 'images/microsoft.png', __FILE__ ) . '" alt="Get it for Windows" height="42" />';
		$html .= '	    </a>';
		$html .= '	</div>';
		$html .= '</div>';

		wp_enqueue_script('pagesync', plugin_dir_url(__FILE__).'pagesync.js');
		wp_register_script('reload', plugin_dir_url(__FILE__).'reload.js');
		wp_localize_script('reload', 'sqrlReload', array(
			'adminURL' => admin_url('admin-post.php'),
			'session' => $session,
		));
		wp_enqueue_script('reload');

		wp_enqueue_style('style', plugin_dir_url(__FILE__).'style.css');

		echo $html;
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
	 */
	function onlyAllowBase64URL($s) {
		if(!preg_match('/^[a-zA-Z0-9_-]*$/', $s)) {
			error_log("Incorrect input " . $s);
			die();
		}
	}

	public function loginCallback() {

		// Validate session value
		// If the string is not Base64URL encoded, die here and don't process code below.
		$this->onlyAllowBase64URL($_GET['session']);

		// Validate nut value
		// If the string is not Base64URL encoded, die here and don't process code below.
		$this->onlyAllowBase64URL($_GET['nut']);

		// These lines of code will only run on a get variables are Base64URL encoded, due to the lines above.
		$session = sanitize_text_field($_GET['session']);
		if(empty($session)) {
			$nutSession = explode('-', sanitize_text_field($_GET["nut"]));
			$session = $nutSession[1];
		}

		$wp_users = get_users(array(
			'meta_key'     => 'sqrl_session',
			'meta_value'   => sanitize_text_field($session),
			'number'       => 1,
			'count_total'  => false,
			'fields'       => 'id',
		));

		delete_user_meta( $wp_users[0], 'sqrl_session');
		wp_set_auth_cookie( $wp_users[0] );

		header("Location: " . get_site_url(), true);
	}

	/**
	 * This API callback will be called form the client to query for server status, login user,
	 * register new users, disable the account, enable the account and remove the account.
	 */
	public function apiCallback() {

		// Validate Client data
		// If the string is not Base64URL encoded, die here and don't process code below.
		$this->onlyAllowBase64URL($_POST['client']); 

		// Validate Server data
		// If the string is not Base64URL encoded, die here and don't process code below.
		$this->onlyAllowBase64URL($_POST['server']); 

		// Validate Identity Signature
		// If the string is not Base64URL encoded, die here and don't process code below.
		$this->onlyAllowBase64URL($_POST['ids']);

		// Validate Previous Identity Signature
		// If the string is not Base64URL encoded, die here and don't process code below.
		$this->onlyAllowBase64URL($_POST['pids']);

		// Validate Unlock Request Signature
		// If the string is not Base64URL encoded, die here and don't process code below.
		$this->onlyAllowBase64URL($_POST['urs']);

		/**
		 * Split the client variables into an array so we can use them later.
		 */
		$clientStr = explode("\r\n", $this->base64url_decode(sanitize_text_field($_POST["client"])));
		$client = array();
		foreach ($clientStr as $k => $v) {
			$p = explode("=", $v);
			$client[$p[0]] = $p[1];
		}

		/**
		 * Prepare the admin post array that we will use multiple times to refeer the client back to
		 * the server.
		 */
		$adminPostPath = parse_url(admin_url('admin-post.php'), PHP_URL_PATH);
		
		/**
		 * Check the user call that we have a valid signature for the current authentication.
		 */
		$result = sodium_crypto_sign_verify_detached (
			$this->base64url_decode(sanitize_text_field($_POST["ids"])),
			sanitize_text_field($_POST["client"]) . sanitize_text_field($_POST["server"]),
			$this->base64url_decode($client["idk"])
		);
		if(!$result) {
			error_log("Incorrect signature");
			die();
		}

		/**
		 * Prepare the server values. If the previous value from the client is only a single value that means
		 * the client only have seen the URL from the server and we should fetch the query values from the call.
		 * 
		 * Otherwise we handle the server string with properties that are line separated.
		 */
		$serverStr = explode("\r\n", $this->base64url_decode(sanitize_text_field($_POST["server"])));
		if(count($serverStr) == 1) {
			foreach (explode("&", $serverStr[0]) as $k => $v) {
				$p = explode("=", $v);
				$server[$p[0]] = $p[1];
			}
		} else {
			$server = array();
			foreach ($serverStr as $k => $v) {
				$p = explode("=", $v);
				$server[$p[0]] = $p[1];
			}
		}

		/**
		 * Get the current nut + session value and replace the nut in order to have a 
		 * unique random value for each call in order to secure against replay attacks.
		 */
		$nutSession = explode('-', $server["nut"]);
		$nutSession[0] = $this->generateRandomString();

		/**
		 * Explode the option array with all the SQRL options. Valid values are
		 * 
		 * suk = Request for Server unlock key
		 * cps = Client Provided Session is available
		 * noiptest = Server don't need to check the IP address of the client (remote device login)
		 * sqrlonly = Client requests the server to only allow SQRL logins, all other authentication should be
		 * 			  disabled.
		 * hardlock = Client request all "out of band" changes to the account. Like security questions to 
		 * 			  retrieve the account when password is lost.
		 */
		$options = array();
		foreach (explode("~", $client["opt"]) as $v) {
			$options[$v] = true;
		}

		/**
		 * TODO: More correct check should be implemented later, now we only return the correct code for
		 * the ip check if needed.
		 */
		$retVal = $options["noiptest"] ? 0 : 4;

		/**
		 * Prepare response.
		 * 
		 * Set version number for the call, new nut for the session and a path with query that the next client
		 * call should use in order to contact the server.
		 */
		$response = array();
		$response[] = "ver=1";
		$response[] = "nut=" . $nutSession[0] . '-' . $nutSession[1];
		$response[] = "qry=" . $adminPostPath . "?action=sqrl_auth&nut=" . $nutSession[0] . '-' . $nutSession[1];
		if($client['cmd'] == 'query') {
			/**
			 * Query the system for the current user status.
			 */
			if($this->accountPresent($client)) {
				$retVal += 1;

				/**
				 * If the client requests a Server Unlock Key then add that to the response.
				 */
				if($options["suk"]) {
					$response[] = "suk=" . $this->getServerUnlockKey($client);
				}
			}
		} else if($client['cmd'] == 'ident') {
			/**
			 * Identify with the system either creating a new user or authorizing login with a user
			 * already in the system.
			 */
			if(!$this->accountPresent($client)) {
				$retVal += 1;

				/**
				 * Fetch the current user from the transient session store and remove it as we only keep
				 * it for the current session.
				 */
				$user = get_transient($nutSession[1]);
				delete_transient($nutSession[1]);

				if($user) {
					$this->associateUser($user, $client, $nutSession[1]);
				} else {
					$this->createUser($client, $nutSession[1]);
				}
			}

			/**
			 * Add session data signaling to the reload.js script that a login has been successfully transacted.
			 */
			$this->addUserSession($client, $server);

			/**
			 * If Client Provided Session is enabled we need to respond with links for the client to follow in order
			 * to securely login.
			 */
			if(strpos($client['opt'], 'cps') !== false) {
				$response[] = "url=" . get_site_url() . $adminPostPath . "?action=sqrl_login&nut=" . $nutSession[0] . '-' . $nutSession[1];
				$response[] = "can=" . get_site_url() . "?q=canceled";
			}
		} else {
			/**
			 * If we have an unknown command, Not implemented yet we should print the client request and die.
			 */
			error_log(print_r($client, true));
			die();
		}

		/**
		 * Set the status condition code for this call.
		 */
		$response[] = "tif=" . $retVal;

		/**
		 * Display the result as an base64url encoded string.
		 */
		header('Content-Type: application/x-www-form-urlencoded');
        echo $this->base64url_encode(implode("\r\n", $response));
    }

	/**
	 * This function will create a new user and associate it with an SQRL identity
	 */
	private function createUser($client) {
		$randomUserString = $this->get_random_unique_username('user_');
		$new_user = wp_create_user(
			$randomUserString,
			wp_generate_password(),
			$randomUserString . '@localhost'
		);
		$this->associateUser($new_user, $client, $session);
	}

	/**
	 * This function associates a user with a SQRL identity.
	 * 
	 * idk = Identity key, used to check the validity of the current user and also
	 * 		 associate the current login with the account.
	 * suk = Server unlock key is returned on request from the client when the client
	 * 		 requires it for more advanced features.
	 * vuk = Verify Unlock Key, used to verify the unlock request signature sent from the client
	 * 		 when an disabled account should be enabled again.
	 */
	private function associateUser($user, $client) {
		update_user_meta( $user, 'idk', sanitize_text_field($client['idk']));
		update_user_meta( $user, 'suk', sanitize_text_field($client['suk']));
		update_user_meta( $user, 'vuk', sanitize_text_field($client['vuk']));
	}

	/**
	 * This function removes the SQRL identifying data from the user account.
	 * 
	 * idk = Identity key, used to check the validity of the current user and also
	 * 		 associate the current login with the account.
	 * suk = Server unlock key is returned on request from the client when the client
	 * 		 requires it for more advanced features.
	 * vuk = Verify Unlock Key, used to verify the unlock request signature sent from the client
	 * 		 when an disabled account should be enabled again.
	 * sqrl_session = temporary value used during login to signal a correct authentication.
	 */	
	public function disAssociateUser() {
		$user = wp_get_current_user();

		delete_user_meta( $user->id, 'idk');
		delete_user_meta( $user->id, 'suk');
		delete_user_meta( $user->id, 'vuk');
		delete_user_meta( $user->id, 'sqrl_session');

		header("Location: " . admin_url('profile.php'), true);
	}

	/**
	 * Used to add the temporary sqrl_session value indicate a correct authentication so reload.js
	 * could reload the client and login the user.
	 */
	private function addUserSession($client, $server) {
		$wp_users = get_users(array(
			'meta_key'     => 'idk',
			'meta_value'   => sanitize_text_field($client['idk']),
			'number'       => 1,
			'count_total'  => false,
			'fields'       => 'id',
		));

		$nutSession = explode('-', $server["nut"]);

		update_user_meta( $wp_users[0], 'sqrl_session', $nutSession[1] );
	}

	/**
	 * Gets the server unlock code, saved for the user so the user can ask for
	 * it when doing special operations like enabling or removing the SQRL identity
	 * from the system.
	 */
	private function getServerUnlockKey($client) {
		$wp_users = get_users(array(
			'meta_key'     => 'idk',
			'meta_value'   => sanitize_text_field($client['idk']),
			'number'       => 1,
			'count_total'  => false,
			'fields'       => 'id',
		));

		return get_user_meta($wp_users[0], "suk", true);
	}

	/**
	 * Checks if the current client requests identity is already associated with a user
	 * in the system.
	 */
	private function accountPresent($client) {
		$wp_users = get_users(array(
			'meta_key'     => 'idk',
			'meta_value'   => sanitize_text_field($client['idk']),
			'number'       => 1,
			'count_total'  => false,
			'fields'       => 'id',
		));

		if(empty($wp_users[0])) {
			return false;
		}
		return true;
	}

	/**
	 * This function will create a random username. This will be used to create anonymous logins
	 * when registring a new user.
	 */
	function get_random_unique_username( $prefix = '' ){
		$user_exists = 1;
		do {
		   $rnd_str = sprintf("%0d", mt_rand(1, 99999999999999));
		   $user_exists = username_exists( $prefix . $rnd_str );
	   } while( $user_exists > 0 );
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
	 */
	function base64url_encode($data, $pad = null) {
		$data = str_replace(array('+', '/'), array('-', '_'), base64_encode($data));
		if (!$pad) {
			$data = rtrim($data, '=');
		}
		return $data;
	}
	function base64url_decode($data) {
		return base64_decode(str_replace(array('-', '_'), array('+', '/'), $data));
	}

}

new SQRLLogin();
