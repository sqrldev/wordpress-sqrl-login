<?php

class PluginTest extends WP_UnitTestCase {
  private $idk_secret;
  private $idk_public;
  
  
  private $rescueIdentityUnlockKey;
  private $identityLockKey;
  private $serverUnlock;
  private $verifyUnlock;

  public function setUp() {
    $idk = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);

    $idk_pair = sodium_crypto_sign_seed_keypair($idk);
    $this->idk_secret = sodium_crypto_sign_secretkey($idk_pair);
    $this->idk_public = sodium_crypto_sign_publickey($idk_pair);

    $this->rescueIdentityUnlockKey = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
    $randomLock = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);

    $this->identityLockKey = sodium_crypto_scalarmult_base($this->rescueIdentityUnlockKey);
    $this->serverUnlock = sodium_crypto_scalarmult_base($randomLock);
    $bytesToSign = sodium_crypto_scalarmult($randomLock, $this->identityLockKey);
    $vuk_pair = sodium_crypto_sign_seed_keypair($bytesToSign);
    $this->verifyUnlock = sodium_crypto_sign_publickey($vuk_pair);

    unset($_POST["client"]);
    unset($_POST["server"]);

    unset($_POST["ids"]);
    unset($_POST["pids"]);
    unset($_POST["urs"]);
  }

  private function base64url_encode( $data ) {
		$data = str_replace( array( '+', '/' ), array( '-', '_' ), base64_encode( $data ) );
		$data = rtrim( $data, '=' );
		return $data;
	}
	private function base64url_decode( $data ) {
		return base64_decode( str_replace( array( '-', '_' ), array( '+', '/' ), $data ) );
	}

  // Check that that activation doesn't break
  function test_plugin_activated() {
    $this->assertTrue( is_plugin_active( PLUGIN_PATH ) );
  }

  function test_user_login_message() {
    $sqrlLogin = new SQRLLogin();

    $_SERVER['HTTPS'] = 0;
    $message = $sqrlLogin->user_login_message("");
    $this->assertEquals( '<div id="login_error">SQRL Login is only available for sites utilizing SSL connections. Please activate SSL before using SQRL Login.</div>', $message );

    $_SERVER['HTTPS'] = 1;
    $message = $sqrlLogin->user_login_message("test");
    $this->assertEquals( "test", $message );

    $_GET['message'] = SQRLLogin::MESSAGE_DISABLED;
    $message = $sqrlLogin->user_login_message("");
    $this->assertEquals( '<div id="login_error">Account disabled</div>', $message );

    $_GET['message'] = SQRLLogin::MESSAGE_REMOVED;
    $message = $sqrlLogin->user_login_message("");
    $this->assertEquals( '<div id="login_error">Identity disassociated from account</div>', $message );

    $_GET['message'] = SQRLLogin::MESSAGE_SQRLONLY;
    $message = $sqrlLogin->user_login_message("");
    $this->assertEquals( '<div id="login_error">The only allowed login method is SQRL for this account</div>', $message );

    $_GET['message'] = SQRLLogin::MESSAGE_ERROR;
    $message = $sqrlLogin->user_login_message("");
    $this->assertEquals( '<div id="login_error">An error occured with the last SQRL command, please try again.</div>', $message );

    $_GET['message'] = SQRLLogin::MESSAGE_REGISTRATION_NOT_ALLOWED;
    $message = $sqrlLogin->user_login_message("");
    $this->assertEquals( '<div id="login_error">The site is not allowing new registrations and your SQRL identity is not associated with any account.</div>', $message );
  }

  function createMockForResult($expected) {
    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) use ($expected) {
        $strOutput = $this->base64url_decode( $strOutput );

        if (isset($expected["debug"])) {
          var_dump($strOutput);
        }

        $expected["response"] = $strOutput;

        $containsAnswer = strstr($strOutput, $expected["message"]) !== false;
        $this->assertTrue($containsAnswer);

        if (isset($expected["throw"])) {
          throw new InvalidArgumentException();
        }
      }));
    if (isset($expected["throw"])) {
      $this->expectException(InvalidArgumentException::class);
    }

    return $sqrlLogin;
  }

  function test_exit_with_error_code() {

    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=0\r\n"
    ));

    $sqrlLogin->exit_with_error_code( 0 );
  }


  function test_exit_with_error_code_with_cps() {

    $sqrlLogin = $this->createMockForResult(array(
      "message" => "url=https://example.org/wp-admin/admin-post.php?action=sqrl_logout&message=4"
    ));

    $sqrlLogin->exit_with_error_code( 0, true );
  }

  function test_exit_with_error_code_with_transient_session() {

    $sqrlLogin = $this->createMockForResult(array(
      "message" => "qry=/wp-admin/admin-post.php?action=sqrl_auth&nut="
    ));

    $sqrlLogin->exit_with_error_code( 0, false, array('nut' => 'abcd') );
  }

  function test_api_callback_without_params() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=80\r\n",
      "throw" => true
    ));

    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_client() {

    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=20\r\n",
      "throw" => true
    ));

    $_POST["client"] = "*&%¤";
    $_POST["server"] = "1234";
    $_POST["ids"] = "1234";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_server() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=20\r\n",
      "throw" => true
    ));

    $_POST["client"] = "1234";
    $_POST["server"] = "*&%¤";
    $_POST["ids"] = "1234";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_ids() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=20\r\n",
      "throw" => true
    ));

    $_POST["client"] = "1234";
    $_POST["server"] = "1234";
    $_POST["ids"] = "*&%¤";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_pids() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=20\r\n",
      "throw" => true
    ));

    $_POST["client"] = "1234";
    $_POST["server"] = "1234";
    $_POST["ids"] = "1234";
    $_POST["pids"] = "*&%¤";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_urs() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=20\r\n",
      "throw" => true
    ));

    $_POST["client"] = "1234";
    $_POST["server"] = "1234";
    $_POST["ids"] = "1234";
    $_POST["urs"] = "*&%¤";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_faulty_key() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=80\r\n",
      "throw" => true
    ));

    $_POST["client"] = $this->base64url_encode("idk=1234");
    $_POST["server"] = "1234";
    $_POST["ids"] = "1234";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_faulty_idk_signature() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=80\r\n",
      "throw" => true
    ));

    $secret = random_bytes(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES);

    $_POST["client"] = $this->base64url_encode("idk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = "1234";
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $secret);

    $_POST["ids"] = $this->base64url_encode($signature);
    $sqrlLogin->api_callback();
  }

  function test_api_callback_without_transient_session() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=20\r\n",
      "throw" => true
    ));


    $_POST["client"] = $this->base64url_encode("idk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = "1234";
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    $_POST["ids"] = $this->base64url_encode($signature);
    $sqrlLogin->api_callback();
  }

  function test_api_callback_without_command() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=10\r\n",
      "throw" => true
    ));

    $_POST["client"] = $this->base64url_encode("idk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $this->base64url_encode("https://example.org/wp-admin/admin-post.php?nut=1234");
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] )
    ), 60);

    $_POST["ids"] = $this->base64url_encode($signature);
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_invalid_command() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=10\r\n",
      "throw" => true
    ));

    $_POST["client"] = $this->base64url_encode("cmd=dsajki\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $this->base64url_encode("https://example.org/wp-admin/admin-post.php?nut=1234");
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] )
    ), 60);

    $_POST["ids"] = $this->base64url_encode($signature);
    $sqrlLogin->api_callback();
  }

  function test_api_callback_check_for_ip_match() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=4\r\n",
      "throw" => true
    ));

    $_POST["client"] = $this->base64url_encode("cmd=query\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $this->base64url_encode("https://example.org/wp-admin/admin-post.php?nut=1234");
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    $_POST["ids"] = $this->base64url_encode($signature);

    $_SERVER['REMOTE_ADDR'] = "1.1.1.1";
    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] ),
      "ip" => "1.1.1.1"
    ), 60);
    $sqrlLogin->api_callback();

    $_SERVER['HTTP_X_FORWARDED_FOR'] = "2.2.2.2";
    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] ),
      "ip" => "2.2.2.2"
    ), 60);
    $sqrlLogin->api_callback();

    $_SERVER['HTTP_CLIENT_IP'] = "3.3.3.3";
    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] ),
      "ip" => "3.3.3.3"
    ), 60);
    $sqrlLogin->api_callback();
  }

  function test_api_callback_missing_session_variable() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=20\r\n",
      "throw" => true
    ));

    $_POST["client"] = $this->base64url_encode("cmd=ident\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $this->base64url_encode("https://example.org/wp-admin/admin-post.php?nut=1234");
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);
    $_POST["ids"] = $this->base64url_encode($signature);

    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] ),
    ), 60);

    $sqrlLogin->api_callback();

    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] ),
    ), 60);
    $_POST["client"] = $this->base64url_encode("cmd=query\r\nidk=" . $this->base64url_encode($this->idk_public));
    $sqrlLogin->api_callback();
  }

  function test_api_callback_missing_suk_or_vuk() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=80\r\n",
      "throw" => true
    ));

    $_POST["client"] = $this->base64url_encode("cmd=ident\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $this->base64url_encode("https://example.org/wp-admin/admin-post.php?nut=1234");
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);
    $_POST["ids"] = $this->base64url_encode($signature);

    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] ),
      "user" => 1,
      "session" => "dasasd"
    ), 60);

    $sqrlLogin->api_callback();
  }

  function test_api_callback_create_new_association() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=1\r\n",
      "throw" => true
    ));

    $_POST["client"] = $this->base64url_encode("cmd=ident\r\nsuk=dasasd\r\nvuk=dasasd\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $this->base64url_encode("https://example.org/wp-admin/admin-post.php?nut=1234");
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);
    $_POST["ids"] = $this->base64url_encode($signature);

    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] ),
      "user" => 1,
      "session" => "dasasd"
    ), 60);

    $sqrlLogin->api_callback();

    set_transient("1234", array(
      "server_hash" => hash( "sha256", $_POST["server"] ),
    ), 60);
    $_POST["client"] = $this->base64url_encode("cmd=query\r\nidk=" . $this->base64url_encode($this->idk_public));
    $sqrlLogin->api_callback();
  }


  function test_api_callback_with_incorrect_server_hash() {
    $sqrlLogin = $this->createMockForResult(array(
      "message" => "tif=80\r\n",
      "throw" => true
    ));

    set_transient("1234", array(
      "server_hash" => "incorrect"
    ), 60);

    $_POST["client"] = $this->base64url_encode("idk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $this->base64url_encode("https://example.org/wp-admin/admin-post.php?nut=1234");
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    $_POST["ids"] = $this->base64url_encode($signature);
    $sqrlLogin->api_callback();
  }


  function createMockJustPrint() {
    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        echo $strOutput;
      }));

    return $sqrlLogin;
  }

  function runAndReturn($func) {
    ob_start();
    $func();
    $strOutput = $this->base64url_decode( ob_get_clean() );

    $response = [];
    $array = explode("\r\n", $strOutput);
    foreach ($array as $str) {
      $eq_pos = strpos( $str, '=' );
      if ($eq_pos === false) continue;
      $response[substr( $str, 0, $eq_pos )] = substr( $str, $eq_pos + 1 );
    }
    return $response;
  }

  function parseString($strOutput) {

  }

  function test_api_callback_after_login_form_without_user() {
    $sqrlLogin = $this->createMockJustPrint();

    update_option('users_can_register', true);

    ob_start();
    $sqrlLogin->add_to_login_form();
    $response = ob_get_clean();

    $re = '/encoded-sqrl-url="([A-Za-z0-9_-]+)"/m';
    preg_match_all($re, $response, $matches, PREG_SET_ORDER, 0);

    $_POST["client"] = $this->base64url_encode("cmd=ident\r\nsuk=dasasd\r\nvuk=dasasd\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $matches[0][1];
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    $_POST["ids"] = $this->base64url_encode($signature);

    $response = $this->runAndReturn(function() use ($sqrlLogin) {
      $sqrlLogin->api_callback();
    });

    $session = get_transient($response["nut"]);

    $this->assertEquals( 5, $session['cmd'] );
  }

  function test_api_callback_registration_not_allowed() {
    $sqrlLogin = $this->createMockJustPrint();

    update_option('users_can_register', false);

    ob_start();
    $sqrlLogin->add_to_login_form();
    $response = ob_get_clean();

    $re = '/encoded-sqrl-url="([A-Za-z0-9_-]+)"/m';
    preg_match_all($re, $response, $matches, PREG_SET_ORDER, 0);

    $_POST["client"] = $this->base64url_encode("cmd=ident\r\nsuk=dasasd\r\nvuk=dasasd\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $matches[0][1];
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    $_POST["ids"] = $this->base64url_encode($signature);

    $response = $this->runAndReturn(function() use ($sqrlLogin) {
      $sqrlLogin->api_callback();
    });

    $session = get_transient($response["nut"]);

    $this->assertEquals( SQRLLogin::MESSAGE_REGISTRATION_NOT_ALLOWED, $session['err'] );
  }  

  function test_api_callback_after_login_form_with_user() {
    $sqrlLogin = $this->createMockJustPrint();

    $user = new stdClass();
    $user->id = 1;

    ob_start();
    $sqrlLogin->add_to_login_form( $user );
    $response = ob_get_clean();

    $re = '/encoded-sqrl-url="([A-Za-z0-9_-]+)"/m';
    preg_match_all($re, $response, $matches, PREG_SET_ORDER, 0);

    $_POST["client"] = $this->base64url_encode("cmd=ident\r\nsuk=dasasd\r\nvuk=dasasd\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $matches[0][1];
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    $_POST["ids"] = $this->base64url_encode($signature);

    $response = $this->runAndReturn(function() use ($sqrlLogin) {
      $sqrlLogin->api_callback();
    });

    $this->assertEquals( SQRLLogin::COMMAND_REGISTER, $response['tif'] );
  }

  function test_api_callback_login_and_disable() {
    $sqrlLogin = $this->createMockJustPrint();

    $user = new stdClass();
    $user->id = 1;

    ob_start();
    $sqrlLogin->add_to_login_form( $user );
    $response = ob_get_clean();

    $re = '/encoded-sqrl-url="([A-Za-z0-9_-]+)"/m';
    preg_match_all($re, $response, $matches, PREG_SET_ORDER, 0);

    $_POST["client"] = $this->base64url_encode("cmd=ident\r\nsuk=dasasd\r\nvuk=dasasd\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $matches[0][1];
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    $_POST["ids"] = $this->base64url_encode($signature);

    ob_start();
    $sqrlLogin->api_callback();
    $response = ob_get_clean();

    $_POST["client"] = $this->base64url_encode("cmd=disable\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $response;
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    $_POST["ids"] = $this->base64url_encode($signature);

    $response = $this->runAndReturn(function() use ($sqrlLogin) {
      $sqrlLogin->api_callback();
    });

    $this->assertEquals( 'd', $response['tif'] );
  }

  function test_api_callback_login_and_remove() {
    $sqrlLogin = $this->createMockJustPrint();

    $user = new stdClass();
    $user->id = 1;

    ob_start();
    $sqrlLogin->add_to_login_form( $user );
    $response = ob_get_clean();

    $re = '/encoded-sqrl-url="([A-Za-z0-9_-]+)"/m';
    preg_match_all($re, $response, $matches, PREG_SET_ORDER, 0);

    $enc_idk = $this->base64url_encode($this->idk_public);
    $enc_suk = $this->base64url_encode($this->serverUnlock);
    $enc_vuk = $this->base64url_encode($this->verifyUnlock);

    $_POST["client"] = $this->base64url_encode("cmd=ident\r\nsuk=" . $enc_suk . "\r\nvuk=" . $enc_vuk . "\r\nidk=" . $enc_idk);
    $_POST["server"] = $matches[0][1];
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);

    $_POST["ids"] = $this->base64url_encode($signature);

    ob_start();
    $sqrlLogin->api_callback();
    $response = ob_get_clean();

    var_dump($this->base64url_decode($response));

    $_POST["client"] = $this->base64url_encode("cmd=remove\r\nidk=" . $this->base64url_encode($this->idk_public));
    $_POST["server"] = $response;
    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $this->idk_secret);
    $_POST["ids"] = $this->base64url_encode($signature);

    $bytesToSign = sodium_crypto_scalarmult($this->rescueIdentityUnlockKey, $this->serverUnlock);
    $unlock_pair = sodium_crypto_sign_seed_keypair($bytesToSign);
    $unlock_secret = sodium_crypto_sign_secretkey($unlock_pair);

    $signature = sodium_crypto_sign_detached($_POST["client"] . $_POST["server"], $unlock_secret);
    $_POST["urs"] = $this->base64url_encode($signature);

    $response = $this->runAndReturn(function() use ($sqrlLogin) {
      $sqrlLogin->api_callback();
    });

    $this->assertEquals( '4', $response['tif'] );
  }

}