    chrome.identity.getAuthToken({ 'interactive': false }, function(token) {
        // Use the token.
        var x = new XMLHttpRequest();
        
        x.open('GET','http://100.115.92.199:8000/',true)
        x.setRequestHeader('Authentication',token)
        x.onload = function() {
            alert(x.response);
        };
        x.send();
    });
