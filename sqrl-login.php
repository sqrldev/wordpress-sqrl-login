<?php
/**
 * Plugin Name:       SQRL Login
 * Description:       Login and Register your users using SQRL
 * Version:           1.1.2
 * Author:            Daniel Persson
 * Author URI:        http://danielpersson.dev
 * Text Domain:       sqrl
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * GitHub Plugin URI: http://github.com/kalaspuffar/wordpress-sqrl
 */

class SQRLLogin {

    const CURRENT_ID_MATCH = 1;
    const PREVIOUS_ID_MATCH = 2;
    const IP_MATCHED = 4;
    const ACCOUNT_DISABLED = 8;
    const FUNCTION_NOT_SUPPORTED = 16;
    const TRANSIENT_ERROR = 32;
    const COMMAND_FAILED = 64;
    const CLIENT_FAILURE = 128;
    const BAD_ID_ASSOCIATION = 256;

    /**
     * Change messages
     */
    const MESSAGE_DISABLED = '1';
    const MESSAGE_REMOVED = '2';
    const MESSAGE_SQRLONLY = '3';
    const MESSAGE_ERROR = '4';
    const MESSAGE_REGISTRATION_NOT_ALLOWED = '5';

    const COMMAND_LOGIN = 1;
    const COMMAND_ENABLE = 2;
    const COMMAND_DISABLE = 3;
    const COMMAND_REMOVE = 4;

    const SESSION_TIMEOUT = 15 * 60;

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
        add_action( 'admin_post_sqrl_logout', array($this, 'logoutCallback'));
        add_action( 'admin_post_nopriv_sqrl_logout', array($this, 'logoutCallback'));
        add_action( 'admin_post_sqrl_auth', array($this, 'apiCallback'));
        add_action( 'admin_post_nopriv_sqrl_auth', array($this, 'apiCallback'));

        add_action( 'admin_post_sqrl_check_login', array($this, 'checkIfLoggedInAjax'));
        add_action( 'admin_post_nopriv_sqrl_check_login', array($this, 'checkIfLoggedInAjax'));

        add_action( 'edit_user_profile', array($this, 'associateSQRL') );
        add_action( 'show_user_profile', array($this, 'associateSQRL') );

        add_action( 'login_enqueue_scripts', array($this, 'enqueueScripts') );
        add_action( 'admin_enqueue_scripts', array($this, 'enqueueScripts') );

        add_action( 'wp_login', array($this, 'userLogin'), 10, 2 );
        add_filter( 'login_message', array($this, 'userLoginMessage') );

        add_action( 'admin_init', array($this, 'registerSettings') );
        add_action( 'admin_menu', array($this, 'registerOptionsPage') );
    }

    function registerSettings() {
        add_option( 'sqrl_redirect_url', get_site_url() );
        register_setting( 'sqrl_general', 'sqrl_redirect_url' );
    }

    function registerOptionsPage() {
        add_options_page( 'Settings', 'SQRL Login', 'manage_options', 'sqrl_login', array($this, 'optionsPage') );
    }

    function optionsPage() {
        $settings_title = __('SQRL Login settings', 'sqrl');
        $redirect_title = __('Redirect URL', 'sqrl');
        $redirect_desc = __('This URL is used to redirect the user after login if no redirect_to variable has been set.', 'sqrl');
        ?>
        <div class="wpbody-content">
            <div class="wrap">
                <?php screen_icon(); ?>
                <h1><?php echo $settings_title ?></h1>
                <form method="post" action="options.php">
                    <?php settings_fields( 'sqrl_general' ); ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="sqrl_redirect_url"><?php echo $redirect_title ?></label>
                            </th>
                            <td>
                                <input
                                    type="text"
                                    id="sqrl_redirect_url"
                                    name="sqrl_redirect_url"
                                    value="<?php echo get_option('sqrl_redirect_url'); ?>"
                                    class="regular-text ltr"
                                />
                                <p class="description" id="sqrl_redirect_url_description">
                                    <?php echo $redirect_desc ?>
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

    public function enqueueScripts() {
        wp_enqueue_style('style', plugin_dir_url(__FILE__).'style.css');
    }

    /**
     * Display screen in profile to associate or disassociate a SQRL login with a user
     * profile.
     */
    function associateSQRL($user) {
        $adminPostPath = parse_url(admin_url('admin-post.php'), PHP_URL_PATH);

        $sqrl_settings_title = __('SQRL settings', 'sqrl');
        $disassociate_button = __('Disassociate', 'sqrl');
        $hardlock_disclaimer = __('The hardlock option is set on this account but there is no real way to assure that it\'s honored by all WordPress implementations.', 'sqrl');

        ?>
        <h3><?php echo $sqrl_settings_title ?></h3>
        <?php
        if(get_user_meta($user->id, 'sqrl_idk', true)) {
            ?>
            <table class="form-table">
                <tr>
                    <th>
                    </th>
                    <td>
                        <?php if (get_user_meta($user->id, 'sqrl_hardlock', true)) { ?>
                            <div class="sqrl-form" style="border-left: 3px solid #dc3232;">
                                <div class="sqrl-login-row"><?php echo $hardlock_disclaimer ?></div>
                            </div>
                        <?php } ?>
                        <div class="sqrl-form">
                            <?php $this->addToLoginForm($user, true); ?>
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
        header("Access-Control-Allow-Origin: " . get_site_url());
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Max-Age: 1');    // cache for 1 day
        header("Access-Control-Allow-Methods: GET, OPTIONS");

        echo get_transient(sanitize_text_field($_GET['session'])) === false ? "false" : "true";
    }

    /**
     * Creates random string value of any length (default 16) with characters between 0-9, a-z and A-Z.
     */
    function generateRandomString($length = 32) {
        return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
    }

    /**
     * Get the current client IP so we can verify it later to be the same when using CPS.
     */
    function getClientIP() {
        if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
            //check ip from share internet
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            //to check ip is pass from proxy
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return $ip;
    }

    public function getDomainAndPathLength() {
        $siteUrl = explode("://", get_site_url());
        $domainName = $siteUrl[0];
        if(count($siteUrl) == 2) {
            $domainName = $siteUrl[1];
        }

        $slashPos = strpos($domainName, '/');
        $pathLenParam = "";
        if ($slashPos !== false) {
            $pathLenParam = '&x=' . (strlen($domainName) - $slashPos);
            $domainName = substr($domainName, 0, $slashPos);
        }
        return array($domainName, $pathLenParam);
    }

    /**
     * Add the SQRL specific code. Used both from the profile screen and the login screen to
     * login users or associate them with a specific account.
     */
    public function addToLoginForm($user = false, $associated = false) {
        if (get_option( 'users_can_register' )) {
            $button_label = __('Sign in or Register with SQRL', 'sqrl');
            $qrcode_label = __('You may also sign in or register with SQRL using any SQRL-equipped smartphone by scanning this QR code.', 'sqrl');
        } else {
            $button_label = __('Sign in with SQRL', 'sqrl');
            $qrcode_label = __('You may also sign in with SQRL using any SQRL-equipped smartphone by scanning this QR code.', 'sqrl');
        }

        if ($associated) {
            $button_label = __('Change your account', 'sqrl');
            $qrcode_label = __('Scan QR code or click button to change account. Using your client you can disable, enable and remove the account.', 'sqrl');
        } else if ($user) {
            $button_label = __('Associate with account', 'sqrl');
            $qrcode_label = __('Scan QR code or click button to associate to this account.', 'sqrl');
        }

        $adminPostPath = parse_url(admin_url('admin-post.php'), PHP_URL_PATH);

        list($domainName, $pathLenParam) = $this->getDomainAndPathLength();

        $cancelAddr = "&can=" . $this->base64url_encode(get_site_url());

        $nut = $this->generateRandomString();
        $session = $this->generateRandomString();
        $sqrlURL = 'sqrl://' . $domainName . $adminPostPath . '?action=sqrl_auth&nut=' . $nut . $pathLenParam . $cancelAddr;

        if($user) {
            set_transient($nut, array(
                'user'     => $user->id,
                'ip'  => $this->getClientIP(),
                'redir' => isset( $_GET['redirect_to'] ) ? sanitize_text_field( $_GET['redirect_to'] ) : '',
                'session'     => $session
            ), self::SESSION_TIMEOUT);
        } else {
            set_transient($nut, array(
                'user'     => false,
                'ip'  => $this->getClientIP(),
                'redir' => isset( $_GET['redirect_to'] ) ? sanitize_text_field( $_GET['redirect_to'] ) : '',
                'session'     => $session
            ), self::SESSION_TIMEOUT);
        }

        wp_enqueue_script('pagesync', plugin_dir_url(__FILE__).'pagesync.js');
        wp_enqueue_script('qrcode', plugin_dir_url(__FILE__).'qrcode.min.js');
        wp_register_script('reload', plugin_dir_url(__FILE__).'reload.js');
        wp_localize_script('reload', 'sqrlReload', array(
            'adminURL' => admin_url('admin-post.php'),
            'session' => $session,
            'existingUserParam' => $user ? "&existingUser=1" : "",
            'sqrlLoginURL' => $sqrlURL,
            'countDownDesc' => __('Will look for QR Login in')
        ));
        wp_enqueue_script('reload');

        ?>
        <div class="sqrl-login-wrapper">
            <div class="sqrl-login-row">
                <a id="sqrl"
                   class="sqrl-button"
                   href="<?php echo $sqrlURL ?>" onclick="sqrlLinkClick(this);return true;"
                   encoded-sqrl-url="<?php echo $this->base64url_encode($sqrlURL) ?>"
                   tabindex="-1"
                >
                  <img src="<?php echo plugins_url( 'images/sqrl_outline.svg', __FILE__ ) ?>"/>
                  <div><?php echo $button_label ?></div>
                </a>
            </div>
            <div class="sqrl-login-row">
                <div id="sqrl-qrcode"></div>
                <div><?php echo $qrcode_label ?></div>
            </div>
            <div class="sqrl-login-row">
                <span id="reloadDisplay"></span>
            </div>
            <div class="sqrl-login-row">
                <a href="https://play.google.com/store/apps/details?id=org.ea.sqrl">
                   <img src="<?php echo plugins_url( 'images/en_badge_web_generic.png', __FILE__ ) ?>" alt="Get it on Google Play" height="60" />
                </a>
                <a href="https://www.grc.com/files/sqrl.exe">
                   <img src="<?php echo plugins_url( 'images/microsoft.png', __FILE__ ) ?>" alt="Get it for Windows" height="42" />
                </a>
            </div>
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
     */
    function onlyAllowBase64URL($s) {
        if(!preg_match('/^[a-zA-Z0-9_-]*$/', $s)) {
            error_log("Incorrect input " . $s);
            $this->exitWithErrorCode(self::TRANSIENT_ERROR);
        }
    }

    public function logoutCallback() {
        $messageKey = sanitize_text_field($_GET['message']);
        $this->logoutWithMessage($messageKey);
    }

    public function logoutWithMessage($messageKey) {
        // Clear cookies, a.k.a log user out
        wp_clear_auth_cookie();
        // Build login URL and then redirect
        $login_url = site_url( 'wp-login.php', 'login' );

        $login_url = add_query_arg( 'message', $messageKey, $login_url );
        wp_redirect( $login_url );
        exit;
    }

    public function loginCallback() {

        // Validate session value
        // If the string is not Base64URL encoded, die here and don't process code below.
        $this->onlyAllowBase64URL($_GET['session']);

        // Validate nut value
        // If the string is not Base64URL encoded, die here and don't process code below.
        $this->onlyAllowBase64URL($_GET['nut']);


        $sessionKey = sanitize_text_field($_GET['session']);
        if(empty($sessionKey)) {
            $sessionKey = sanitize_text_field($_GET['nut']);
        }
        $session = get_transient($sessionKey);
        delete_transient($sessionKey);

        error_log("Session data: " . print_r($session, true));

        if ($session['cmd'] === self::COMMAND_REMOVE) {
            if (!empty($_GET['existingUser'])) {
                header("Location: " . admin_url('profile.php'), true);
            } else {
                $this->logoutWithMessage(self::MESSAGE_REMOVED);
            }
        }
        if ($session['err'] === self::MESSAGE_REGISTRATION_NOT_ALLOWED) {
            $this->logoutWithMessage(self::MESSAGE_REGISTRATION_NOT_ALLOWED);
        }
        if ($session['err'] === self::MESSAGE_ERROR) {
            $this->logoutWithMessage(self::MESSAGE_ERROR);
        }
        if ($session['cmd'] === self::COMMAND_LOGIN || $session['cmd'] === self::COMMAND_ENABLE) {
            wp_set_auth_cookie( $session['user'] );
        }

        $disabled = get_user_meta( $wp_users[0], 'sqrl_disable_user', true);
        if ($disabled) {
            $this->logoutWithMessage(self::MESSAGE_DISABLED);
        } else if (!empty($session['redir'])) {
            header("Location: " . $session['redir'], true);
        } else if (!empty($_GET['existingUser'])) {
            header("Location: " . admin_url('profile.php'), true);
        } else {
            header("Location: " . get_option('sqrl_redirect_url'), true);
        }
    }

    /**
     * Return with information to the server about the error that occured.
     */
    public function exitWithErrorCode($retVal, $clientProvidedSession = false, $transientSession = false) {
        $response = array();
        $response[] = "ver=1";
        $response[] = "tif=" . dechex($retVal);
        $response[] = "sin=0";

        if($transientSession) {
            list(, $pathLenParam) = $this->getDomainAndPathLength();

            $nut = $this->generateRandomString();
            set_transient($nut, $transientSession, self::SESSION_TIMEOUT);

            $adminPostPath = parse_url(admin_url('admin-post.php'), PHP_URL_PATH);
            $response[] = "nut=" . $nut;
            $response[] = "qry=" . $adminPostPath . "?action=sqrl_auth&nut=" . $nut . $pathLenParam;
        }

        if($clientProvidedSession) {
            $response[] = "url=" . $this->getServerUrlWithoutPath() . $adminPostPath . '?action=sqrl_logout&message=' . self::MESSAGE_ERROR;
        }

        error_log("Failed response: " . print_r($response, true));

        $content = $this->base64url_encode(implode("\r\n", $response) . "\r\n");
        header('Content-Type: application/x-www-form-urlencoded');
        header('Content-Length: ' . strlen($content));
        echo $content;
        exit();
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
         * Reset return value used as the tif (Transaction Information Flags)
         */
        $retVal = 0;

        /**
         * Split the client variables into an array so we can use them later.
         */
        $clientStr = explode("\r\n", $this->base64url_decode(sanitize_text_field($_POST["client"])));
        $client = array();
        foreach ($clientStr as $k => $v) {
            list($key, $val) = $this->valuePair($v);
            $client[$key] = $val;
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
            $this->exitWithErrorCode(self::CLIENT_FAILURE);
        }

        /**
         * Check the user call that we have a valid pewvious if available signature for
         * the current authentication.
         */
        if(!empty($client["pidk"])) {
            $result = sodium_crypto_sign_verify_detached (
                $this->base64url_decode(sanitize_text_field($_POST["pids"])),
                sanitize_text_field($_POST["client"]) . sanitize_text_field($_POST["server"]),
                $this->base64url_decode(sanitize_text_field($client["pidk"]))
            );
            if(!$result) {
                error_log("Incorrect previous signature");
                $this->exitWithErrorCode(self::CLIENT_FAILURE);
            }
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
                list($key, $val) = $this->valuePair($v);
                $server[$key] = $val;
            }
        } else {
            $server = array();
            foreach ($serverStr as $k => $v) {
                list($key, $val) = $this->valuePair($v);
                $server[$key] = $val;
            }
        }

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

        $clientProvidedSession = strpos($client['opt'], 'cps') !== false;

        /**
         * Fetch the current transient session where we keep all session information.
         */
        $transientSession = get_transient($server["nut"]);
        delete_transient($server["nut"]);

        /**
         * Check if the users IP have changed since last time we logged in. Only required when CPS is used.
         */
        if (empty($transientSession)) {
            error_log("Missing transient session");
            $this->exitWithErrorCode(self::TRANSIENT_ERROR, $clientProvidedSession);
        }

        if (!$options["noiptest"]) {
            if (!empty($transientSession["ip"]) && $transientSession["ip"] == $this->getClientIP()) {
                $retVal += self::IP_MATCHED;
            }
        }

        /**
         * Get the a new random nut
         */
        $nut = $this->generateRandomString();

        /**
         * Prepare response.
         *
         * Set version number for the call, new nut for the session and a path with query that the next client
         * call should use in order to contact the server.
         */
        list(, $pathLenParam) = $this->getDomainAndPathLength();

        $associatedExistingUser = false;
        $response = array();
        $response[] = "ver=1";

        if($client['cmd'] == 'query') {
            /**
             * Query the system for the current user status.
             */
            if($this->accountPresent($client['idk'])) {
                $retVal += self::CURRENT_ID_MATCH;

                /**
                 * If the client requests a Server Unlock Key then add that to the response.
                 */
                if($options["suk"]) {
                    $response[] = "suk=" . $this->getServerUnlockKey($client);
                }
            }

            if($this->accountPresent($client['pidk'])) {
                $retVal += self::PREVIOUS_ID_MATCH;
            }
            if ($this->accountDisabled($client)) {
                $retVal += self::ACCOUNT_DISABLED;
            }

        } else if($client['cmd'] == 'ident') {
            /**
             * Identify with the system either creating a new user or authorizing login with a user
             * already in the system.
             */
            if(!$this->accountPresent($client['idk'])) {
                /*
                 * Fetch the current user from the transient session store and remove it as we only keep
                 * it for the current session.
                 */
                $user = $transientSession["user"];

                /*
                 * We need to check if the user is in the transient session before we lookup the user from
                 * a previous identity. This association is only on already logged in users on the profile page.
                 */
                if($user) {
                    $associatedExistingUser = true;
                }

                /*
                 * Check if we have a hit on a previous account so we need to update the current identity
                 * to our new identity identifier.
                 */
                if(!$user && $this->accountPresent($client['pidk'])) {
                    $user = $this->getUserId($client['pidk']);
                }

                /*
                 * Check if we should associate an old user or create a new one. Checking if registring users
                 * are allowed on the current installation.
                 */
                if($user) {
                    $this->associateUser($user, $client);
                } else {
                    if (!get_option( 'users_can_register' )) {
                        $transientSession["err"] = self::MESSAGE_REGISTRATION_NOT_ALLOWED;
                    } else {
                        $this->createUser($client);
                    }
                }
            }

            /**
             * Check if user is present in the system after eventual creation of the user.
             */
            if($this->accountPresent($client['idk'])) {
                $retVal += self::CURRENT_ID_MATCH;

                $transientSession["cmd"] = self::COMMAND_LOGIN;
                $transientSession["user"] = $this->getUserId($client['idk']);
            }

            /**
             * If Client Provided Session is enabled we need to respond with links for the client to follow in order
             * to securely login.
             */
            if($clientProvidedSession) {
                $response[] = "url=" . $this->getServerUrlWithoutPath() . $adminPostPath .
                    "?action=sqrl_login&nut=" . $nut .
                    ($associatedExistingUser ? "&existingUser=1" : "");
            } else {
                /**
                 * Add session data signaling to the reload.js script that a login has been successfully transacted.
                 */
                set_transient($transientSession["session"], $transientSession, self::SESSION_TIMEOUT);
            }

        } else if($client['cmd'] == 'disable') {
            /*
             * Fetch user to disable.
             */
            $user = $this->getUserId($client['idk']);
            if (!$user) {
                $user = $this->getUserId($client['pidk']);
            }

            if (!$user) {
                error_log("User is missing, can't disable");
                $this->exitWithErrorCode(self::COMMAND_FAILED, $clientProvidedSession, $transientSession);
            }

            update_user_meta( $user, 'sqrl_disable_user', true);

            $retVal += self::CURRENT_ID_MATCH + self::ACCOUNT_DISABLED;

            $transientSession["cmd"] = self::COMMAND_DISABLE;
            $transientSession["user"] = $user;

            $response[] = "suk=" . $this->getServerUnlockKey($client);

            /**
             * If Client Provided Session is enabled we need to respond with links for the client to follow in order
             * to securely login.
             */
            if($clientProvidedSession) {
                $response[] = "url=" . $this->getServerUrlWithoutPath() . $adminPostPath . '?action=sqrl_logout&message=' . self::MESSAGE_DISABLED;
            } else {
                /**
                 * Add session data signaling to the reload.js script that a login has been successfully transacted.
                 */
                set_transient($transientSession["session"], $transientSession, self::SESSION_TIMEOUT);
            }
        } else if($client['cmd'] == 'enable') {
            /*
             * Fetch user to be enabled.
             */
            $user = $this->getUserId($client['idk']);
            if (!$user) {
                $user = $this->getUserId($client['pidk']);
            }
            if (empty($user)) {
                error_log("User is missing, can't be enable");
                $this->exitWithErrorCode(self::COMMAND_FAILED, $clientProvidedSession, $transientSession);
            }
            if (!$this->accountDisabled($client)) {
                error_log("User is not disabled, can't be enable");
                $this->exitWithErrorCode(self::COMMAND_FAILED, $clientProvidedSession, $transientSession);
            }

            $result = sodium_crypto_sign_verify_detached (
                $this->base64url_decode(sanitize_text_field($_POST["urs"])),
                sanitize_text_field($_POST["client"]) . sanitize_text_field($_POST["server"]),
                $this->base64url_decode($this->getVerifyUnlockKey($client))
            );
            if(!$result) {
                error_log("Incorrect Unlock Request signature");
                $this->exitWithErrorCode(self::COMMAND_FAILED, $clientProvidedSession, $transientSession);
            }

            delete_user_meta( $user, 'sqrl_disable_user' );

            $retVal += self::CURRENT_ID_MATCH;

            $transientSession["cmd"] = self::COMMAND_ENABLE;
            $transientSession["user"] = $user;

            /**
             * If Client Provided Session is enabled we need to respond with links for the client to follow in order
             * to securely login.
             */
            if($clientProvidedSession) {
                $response[] = "url=" . $this->getServerUrlWithoutPath() . $adminPostPath .
                    "?action=sqrl_login&nut=" . $nut;
            } else {
                /**
                 * Add session data signaling to the reload.js script that a login has been successfully transacted.
                 */
                set_transient($transientSession["session"], $transientSession, self::SESSION_TIMEOUT);
            }
        } else if($client['cmd'] == 'remove') {
            /*
             * Fetch user to be removed.
             */
            $user = $this->getUserId($client['idk']);
            if (!$user) {
                $user = $this->getUserId($client['pidk']);
            }
            if (empty($user)) {
                error_log("User is missing, can't be removed");
                $this->exitWithErrorCode(self::COMMAND_FAILED, $clientProvidedSession, $transientSession);
            }

            $result = sodium_crypto_sign_verify_detached (
                $this->base64url_decode(sanitize_text_field($_POST["urs"])),
                sanitize_text_field($_POST["client"]) . sanitize_text_field($_POST["server"]),
                $this->base64url_decode($this->getVerifyUnlockKey($client))
            );
            if(!$result) {
                error_log("Incorrect Unlock Request signature");
                $this->exitWithErrorCode(self::COMMAND_FAILED, $clientProvidedSession, $transientSession);
            }

            $transientSession["cmd"] = self::COMMAND_REMOVE;

            $this->disAssociateUser($user);
            /**
             * If Client Provided Session is enabled we need to respond with links for the client to follow in order
             * to securely login.
             */
            if($clientProvidedSession) {
                $profilePath = parse_url(admin_url('profile.php'), PHP_URL_PATH);
                if(!empty($transientSession["user"])) {
                    $response[] = "url=" . $this->getServerUrlWithoutPath() . $profilePath;
                } else {
                    $response[] = "url=" . $this->getServerUrlWithoutPath() . $adminPostPath . '?action=sqrl_logout&message=' . self::MESSAGE_REMOVED;
                }
            } else {
                set_transient($transientSession["session"], $transientSession, self::SESSION_TIMEOUT);
            }
        } else {
            /**
             * If we have an unknown command, Not implemented yet we should print the client request and die.
             */
            error_log(print_r($client, true));
            $this->exitWithErrorCode(self::FUNCTION_NOT_SUPPORTED, $clientProvidedSession, $transientSession);
        }

        /**
         * Set the extra options for users preferences.
         */
        $this->updateOptions($client, $options);

        /**
         * Set the status condition code for this call.
         */
        $response[] = "tif=" . dechex($retVal);
        $response[] = "sin=0";

        /*
         * Prepare the return values and set the transient session
         * where we keep all the session information.
         */
        $response[] = "nut=" . $nut;
        $response[] = "qry=" . $adminPostPath . "?action=sqrl_auth&nut=" . $nut . $pathLenParam;
        set_transient($nut, $transientSession, self::SESSION_TIMEOUT);

        /**
         * Display the result as an base64url encoded string.
         */
        $content = $this->base64url_encode(implode("\r\n", $response) . "\r\n");
        header('Content-Type: application/x-www-form-urlencoded');
        header('Content-Length: ' . strlen($content));
        echo $content;
    }

    /**
     * Update user preferences.
     */
    private function updateOptions($client, $options) {
        $user = $this->getUserId($client['idk']);

        update_user_meta( $user, 'sqrl_sqrlonly', $options['sqrlonly']);
        update_user_meta( $user, 'sqrl_hardlock', $options['hardlock']);
    }

    /**
     * Check if a user account is disabled.
     */
    private function accountDisabled($client) {
        /*
         * Fetch user to check.
         */
        $user = $this->getUserId($client['idk']);
        if (!$user) {
            $user = $this->getUserId($client['pidk']);
        }
        if(!$user) {
            return false;
        }
        return get_user_meta( $user, 'sqrl_disable_user', true);
    }

    /**
     * This will disable login for disabled users.
     *
     * Code inspired by https://github.com/jaredatch/Disable-Users
     */
    public function userLogin( $user_login, $user = null ) {
        if ( !$user ) {
            $user = get_user_by('login', $user_login);
        }
        if ( !$user ) {
            // not logged in - definitely not disabled
            return;
        }
        // Get user meta
        $disabled = get_user_meta( $user->ID, 'sqrl_disable_user', true );
        $sqrlonly = get_user_meta( $user->ID, 'sqrl_sqrlonly', true );

        if( $disabled == '1' && $sqrlonly == '1') {
            wp_clear_auth_cookie();
            $login_url = add_query_arg( 'message', self::MESSAGE_DISABLED, $login_url );
            wp_redirect( $login_url );
            exit;
        }
        if( $sqrlonly == '1' ) {
            wp_clear_auth_cookie();
            $login_url = add_query_arg( 'message', self::MESSAGE_SQRLONLY, $login_url );
            wp_redirect( $login_url );
            exit;
        }
    }

    /**
     * This will show a message that the user account is disabled.
     *
     * Code inspired by https://github.com/jaredatch/Disable-Users
     */
    public function userLoginMessage( $message ) {
        if ( isset( $_GET['message'] ) && $_GET['message'] == self::MESSAGE_DISABLED ) {
            $message =  '<div id="login_error">' . __( 'Account disabled', 'sqrl' ) . '</div>';
        }
        if ( isset( $_GET['message'] ) && $_GET['message'] == self::MESSAGE_REMOVED ) {
            $message =  '<div id="login_error">' . __( 'Identity disassociated from account', 'sqrl' ) . '</div>';
        }
        if ( isset( $_GET['message'] ) && $_GET['message'] == self::MESSAGE_SQRLONLY ) {
            $message =  '<div id="login_error">' . __( 'The only allowed login method is SQRL for this account', 'sqrl' ) . '</div>';
        }
        if ( isset( $_GET['message'] ) && $_GET['message'] == self::MESSAGE_ERROR ) {
            $message =  '<div id="login_error">' . __( 'An error occured with the last SQRL command, please try again.', 'sqrl' ) . '</div>';
        }
        if ( isset( $_GET['message'] ) && $_GET['message'] == self::MESSAGE_REGISTRATION_NOT_ALLOWED ) {
            $message =  '<div id="login_error">' . __( 'The site is not allowing new registrations and your SQRL identity is not associated with any account.', 'sqrl' ) . '</div>';
        }

        if (!is_ssl()) {
            $message .=  '<div id="login_error">' . __( 'SQRL Login is only available for sites utilizing SSL connections. Please activate SSL before using SQRL Login.', 'sqrl' ) . '</div>';
        }

        return $message;
    }

    /**
     * This function returns the server url without path
     */
    private function getServerUrlWithoutPath() {
        $parsedURL = parse_url(get_site_url());

        $url = $parsedURL['scheme'];
        $url .= '://';
        $url .= $parsedURL['host'];
        if (!empty($parsedURL['port'])) {
            $url .= ':';
            $url .= $parsedURL['port'];
        }
        return $url;
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
        $this->associateUser($new_user, $client);
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
        update_user_meta( $user, 'sqrl_idk', sanitize_text_field($client['idk']));
        update_user_meta( $user, 'sqrl_suk', sanitize_text_field($client['suk']));
        update_user_meta( $user, 'sqrl_vuk', sanitize_text_field($client['vuk']));
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
    public function disAssociateUser($user) {
        delete_user_meta( $user, 'sqrl_idk');
        delete_user_meta( $user, 'sqrl_suk');
        delete_user_meta( $user, 'sqrl_vuk');
    }

    /**
     * Gets the server unlock code, saved for the user so the user can ask for
     * it when doing special operations like enabling or removing the SQRL identity
     * from the system.
     */
    private function getUserId($idkVal) {
        if(empty($idkVal)) return false;

        $wp_users = get_users(array(
            'meta_key'     => 'sqrl_idk',
            'meta_value'   => sanitize_text_field($idkVal),
            'number'       => 1,
            'count_total'  => false,
            'fields'       => 'id',
        ));

        return $wp_users[0];
    }

    /**
     * Gets the server unlock code, saved for the user so the user can ask for
     * it when doing special operations like enabling or removing the SQRL identity
     * from the system.
     */
    private function getServerUnlockKey($client) {
        if(empty($client['idk'])) return false;

        $wp_users = get_users(array(
            'meta_key'     => 'sqrl_idk',
            'meta_value'   => sanitize_text_field($client['idk']),
            'number'       => 1,
            'count_total'  => false,
            'fields'       => 'id',
        ));

        return get_user_meta($wp_users[0], "sqrl_suk", true);
    }

    /**
     * Gets the verify unlock code, saved for the user we can verify special
     * operations like enabling and removing accounts.
     */
    private function getVerifyUnlockKey($client) {
        if(empty($client['idk'])) return false;

        $wp_users = get_users(array(
            'meta_key'     => 'sqrl_idk',
            'meta_value'   => sanitize_text_field($client['idk']),
            'number'       => 1,
            'count_total'  => false,
            'fields'       => 'id',
        ));

        return get_user_meta($wp_users[0], "sqrl_vuk", true);
    }


    /**
     * Checks if the current client requests identity is already associated with a user
     * in the system.
     */
    private function accountPresent($idkVal) {
        if(empty($idkVal)) return false;

        $wp_users = get_users(array(
            'meta_key'     => 'sqrl_idk',
            'meta_value'   => sanitize_text_field($idkVal),
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

    function valuePair($str) {
        $eqPos = strpos($str, "=");
        return array(substr($str, 0, $eqPos), substr($str, $eqPos + 1));
    }
}

new SQRLLogin();
