setInterval(function() {
}, 5000);

var countDown = 5;

setInterval(function() {
	var sqrlSession = document.getElementById('sqrl').dataset.session;
	document.getElementById('reloadDisplay').innerHTML = 'Will look for QR Login in ' + countDown;
	if(countDown <= 0) {
		fetch(window.location.origin + '/wp-admin/admin-post.php?action=sqrl_check_login&session=' + sqrlSession)
			.then((res) => {	
				return res.text();
			})
	    	.then((body) => {
				if(body == 'true') {
					window.location.href = window.location.origin + '/wp-admin/admin-post.php?action=sqrl_login&session=' + sqrlSession;
				}		
	    	});		
		countDown = 6;
	}
	countDown--;
}, 1000);