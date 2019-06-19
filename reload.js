setInterval(function() {
	fetch('https://uhash.com/wp-content/plugins/sqrl-login/ajax-check.php?session=' + window.sqrlSession)
		.then((res) => {	
			return res.text();
		})
	    .then((body) => {
			if(body == 'true') {
				window.location.href = 'https://uhash.com/wp-content/plugins/sqrl-login/login.php?session=' + window.sqrlSession;
			}		
	    });
}, 5000);