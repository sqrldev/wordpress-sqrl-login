setInterval(function() {
}, 5000);

var countDown = 5;

setInterval(function() {
	document.getElementById('reloadDisplay').innerHTML = 'Will look for QR Login in ' + countDown;
	if(countDown <= 0) {
		fetch(window.location.origin + '/wp-admin/admin-post.php?action=sqrl_check_login&session=' + window.sqrlSession)
			.then((res) => {	
				return res.text();
			})
	    	.then((body) => {
				if(body == 'true') {
					window.location.href = window.location.origin + '/wp-admin/admin-post.php?action=sqrl_login&session=' + window.sqrlSession;
				}		
	    	});		
		countDown = 6;
	}
	countDown--;
}, 1000);