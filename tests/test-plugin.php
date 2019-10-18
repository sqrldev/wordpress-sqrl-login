<?php

class PluginTest extends WP_UnitTestCase {

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

  function test_exit_with_error_code() {

    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "tif=0") !== false;
        $this->assertTrue($containsAnswer);
      }));

    $sqrlLogin->exit_with_error_code( 0 );
  }


  function test_exit_with_error_code_with_cps() {

    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "url=https://example.org/wp-admin/admin-post.php?action=sqrl_logout&message=4") !== false;
        $this->assertTrue($containsAnswer);
      }));

    $sqrlLogin->exit_with_error_code( 0, true );
  }

  function test_exit_with_error_code_with_transient_session() {

    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "qry=/wp-admin/admin-post.php?action=sqrl_auth&nut=") !== false;
        $this->assertTrue($containsAnswer);
      }));

    $sqrlLogin->exit_with_error_code( 0, false, array('nut' => 'abcd') );
  }

  function test_api_callback_without_params() {

    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "tif=80") !== false;
        $this->assertTrue($containsAnswer);
        throw new InvalidArgumentException();
      }));
    $this->expectException(InvalidArgumentException::class);

    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_client() {

    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "tif=20") !== false;
        $this->assertTrue($containsAnswer);
        throw new InvalidArgumentException();
      }));
    $this->expectException(InvalidArgumentException::class);
    $_POST["client"] = "*&%¤";
    $_POST["server"] = "1234";
    $_POST["ids"] = "1234";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_server() {

    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "tif=20") !== false;
        $this->assertTrue($containsAnswer);
        throw new InvalidArgumentException();
      }));
    $this->expectException(InvalidArgumentException::class);
    $_POST["client"] = "1234";
    $_POST["server"] = "*&%¤";
    $_POST["ids"] = "1234";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_ids() {

    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "tif=20") !== false;
        $this->assertTrue($containsAnswer);
        throw new InvalidArgumentException();
      }));
    $this->expectException(InvalidArgumentException::class);
    $_POST["client"] = "1234";
    $_POST["server"] = "1234";
    $_POST["ids"] = "*&%¤";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_pids() {

    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "tif=20") !== false;
        $this->assertTrue($containsAnswer);
        throw new InvalidArgumentException();
      }));
    $this->expectException(InvalidArgumentException::class);
    $_POST["client"] = "1234";
    $_POST["server"] = "1234";
    $_POST["ids"] = "1234";
    $_POST["pids"] = "*&%¤";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_incorrect_urs() {

    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "tif=20") !== false;
        $this->assertTrue($containsAnswer);
        throw new InvalidArgumentException();
      }));
    $this->expectException(InvalidArgumentException::class);
    $_POST["client"] = "1234";
    $_POST["server"] = "1234";
    $_POST["ids"] = "1234";
    $_POST["urs"] = "*&%¤";
    $sqrlLogin->api_callback();
  }

  function test_api_callback_with_faulty_key() {
    $sqrlLogin = $this->getMockBuilder( SQRLLogin::class )->setMethods( [ 'respond_with_message' ] )->getMock();
    $sqrlLogin
      ->expects($this->once())
      ->method('respond_with_message')
      ->will($this->returnCallback(function($strOutput) {
        $strOutput = $this->base64url_decode( $strOutput );
        $containsAnswer = strstr($strOutput, "tif=80") !== false;
        $this->assertTrue($containsAnswer);
        throw new InvalidArgumentException();
      }));
    $this->expectException(InvalidArgumentException::class);
    $_POST["client"] = $this->base64url_encode("idk=1234");
    $_POST["server"] = "1234";
    $_POST["ids"] = "1234";
    $sqrlLogin->api_callback();
  }
}

