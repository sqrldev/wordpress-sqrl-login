setInterval(function() {
}, 5000);

var countDown = 5;

setInterval(function() {
	document.getElementById('reloadDisplay').innerHTML = 'Will look for QR Login in ' + countDown;
	if(countDown <= 0) {
		fetch(sqrlReload.adminURL + '?action=sqrl_check_login&session=' + sqrlReload.session)
			.then((res) => {
				return res.text();
			})
	    	.then((body) => {
				if(body == 'true') {
					window.location.href = sqrlReload.adminURL + '?action=sqrl_login&session=' + sqrlReload.session;
				}
	    	});
		countDown = 6;
	}
	countDown--;
}, 1000);