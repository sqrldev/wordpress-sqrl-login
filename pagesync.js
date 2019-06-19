'use strict';
//******************************************************************************
//           This is reference/sample JavaScript support for SQRL
//------------------------------------------------------------------------------
// This script begins running when it is invoked, typically at the top of the
// page through a script declaration in the page's head. There is no need for,
// nor benefit in, deliberately placing this at the bottom of the page, though
// that can be done if it's preferable for any reason.
//
// The script defines two SQRL-enhancing functions and onload/onerror handlers
// for a memory-resident 'probe' GIF image.
//
// The first function produces a periodic (every 500ms) host server probe which
// checks to see whether anything has changed (the user has authenticated) and
// the page should be refreshed to show the updated status. This queries SQRL's
// webserver for a 'sync.txt' page. When the returned data differs from the data 
// it first obtained, a refresh/reload of the page is triggered.
//
// The second function converts a user click or touch action on the SQRL QR code
// into two actions: the URL's sqrl:// URL is immediately invoked to launch or
// awaken the platform's SQRL client. Immediately after that the script begins
// probing for the presence of SQRL's localhost server listening on port 25519
// by repeatedly attempting to load a randomly-named GIF image from the server.
// If the attempt fails for any reason, the script waits 200msec and retries.
// Once the image is successfully loaded, the localhost server is confirmed to
// be running and listening, so the script initiates an HREF jump to a page on
// the localhost:25519 server. The browser then waits to receive a response in
// the form of an "HTTP 301 Found" redirect to the URL provided by the
// authenticating website... and the user is securely logged on.
//
//------------------------------------------------------------------------------
// LICENSE AND COPYRIGHT:  LIKE ALL OF SQRL, THIS CODE IS HEREBY RELEASED INTO
// THE PUBLIC DOMAIN. Gibson Research Corporation releases and disclaims ALL
// RIGHTS AND TITLE IN THIS CODE OR ANY DERIVATIVES. It may be used and/or
// modified and used by anyone for any purpose.
//******************************************************************************
var newSync, lastSync, encodedSqrlUrl = false;
var syncQuery = window.XMLHttpRequest ? new window.XMLHttpRequest() : new ActiveXObject('MSXML2.XMLHTTP.3.0');
var gifProbe = new Image(); 					// create an instance of a memory-based probe image
var localhostRoot = 'http://localhost:25519/';	// the SQRL client listener
Date.now = Date.now || function() { return (+new Date()) };	// add old browser Date.now() support

// Linux/WINE desktop environments lack the uniform means for registering scheme handlers.
// So when we detect that we're running under Linux we disable the invocation of SQRL with
// the "sqrl://" scheme and rely upon upon the localhost server --- UNLESS we detect 'sqrl'
// present in the user-agent header which gives us permission to invoke with the sqrl:// scheme.
window.onload = function() {
	if ((navigator.userAgent.match(/linux/i)) && !(navigator.userAgent.match(/sqrl/i)) && !(navigator.userAgent.match(/android/i)))
	{		// if we're on Linux, suppress the sqrl:// href completely
		document.getElementById("sqrl").onclick = function() { sqrlLinkClick(this); return false; };
	}
 }

// =============================================================================
// this defines the "onload" (load success) function for our in-memory test GIF
// image. IF, and only if, it succeeds, we know the localhost server is up and
// listening and that it's safe to execute an HREF jump to the localhost for CPS.
gifProbe.onload = function() {  // define our load-success function
	document.location.href = localhostRoot + encodedSqrlUrl;
};

// =============================================================================
// this defines the "onerror" (GIF probe failure) function for our in-memory
// test GIF. If no SQRL localhost:25519 server replies to and returns a
// GIF, this function queues a retry of the load after a 200msec delay.
gifProbe.onerror = function() { // define our load-failure function
	setTimeout( function(){ gifProbe.src = localhostRoot + Date.now() + '.gif';	}, 250 );
}

// =============================================================================
// sqrlLinkClick is invoked by the SQRL URL's href upon the user's mouse-click
// or touch. The function verifies that the current page's SQRL HREF link has
// defined a custom property named "encoded-sqrl-url" which is a base64-encoded
// version of the SQRL URL, provided by the server.  When this function is
// triggered by the user's SQRL authentication action with the "encoded-sqrl-url"
// link property present, it initiates a one-second delay before initiating a
// page-change to http://localhost:25519/{encoded-sqrl-url}. When authentication
// succeeds, the authenticating SQRL client will return an "HTTP 302 Found" to
// redirect the user's browser to a logged-in page.
//
// Note that the page could use JavaScript to generate this base64url-encoded
// URL locally from the link's HREF value. But that would require guaranteed
// JavaScript execution on the page, which no webserver can force. Therefore,
// having the webserver explicitly provide the base64url-encoded link allows
// CPS login to be used successfully without any requirement for JavaScript.
function sqrlLinkClick(e) {
	encodedSqrlUrl = e.getAttribute('encoded-sqrl-url');
	// if we have an encoded URL to jump to, initiate our GIF probing before jumping
	if ( encodedSqrlUrl ) { gifProbe.onerror(); };	// trigger the initial image probe query
}
