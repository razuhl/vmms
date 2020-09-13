/*
MIT License

Copyright (c) 2020 razuhl

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// ==UserScript==
// @name           VMProps
// @namespace      http://vmms.org/
// @description    Pagebuilder for settings dialogs in violentmonkey.
// ==/UserScript==

function VMProps() {
	var dialogOrigin;
	var prohibitedHosts;
	var dialogSrc;
	
    var props, values, validators, storageKey, title, dialogWindow, dialogWindowOrigin, dlgSize, 
	dialogPublicKey, rsaKey, aesKey;
    
    /**
     * Initialize configuration 
     * 
     * @param newData New data object
     */
    function init(newData) {
		var data;
		if (newData)
			data = newData;
		else data = {};
		
		if ( data.props === undefined || data.props === null )
			props = {};
		else
			props = data.props;
		
		if ( data.validators === undefined || data.validators === null )
			validators = {};
		else
			validators = data.validators;
		
		dialogOrigin = data.dialogOrigin ? data.dialogOrigin : 'https://raw.githack.com/';
		prohibitedHosts = data.prohibitedHosts ? data.prohibitedHosts : [/http[s]?:\/\/(.+[.])?githack.[^/]+/];
		dialogSrc = data.dialogSrc ? data.dialogSrc : 'https://raw.githack.com/razuhl/vmms/master/vmprops.html';
		
		values = {};
        
		title = data.title ? data.title : typeof GM_getMetadata == 'function' ? GM_getMetadata('name') : 'Unknown';
		dlgSize = data.dlgSize;
		
        /* Make a safe version of title to be used as stored value identifier */ 
        var safeTitle = title.replace(/[^a-zA-Z0-9]/g, '_');

        storageKey = '_VMProps_storage_' + safeTitle;
        
        var storedValues;
        
        if (GM_getValue(storageKey))
            storedValues = JSON.parse(GM_getValue(storageKey));

        for (var name in props) {
            if (storedValues && storedValues[name] !== undefined)
                set(name, storedValues[name]);            
            else if (props[name]['default'] !== undefined) 
				set(name, props[name]['default']);
            else set(name, null);
        }
	
        if ( data.menuCommand ) {
            GM_registerMenuCommand(title, function () { open(); });
        }
    }
    
    function get(name) {
        return values[name];
    }
    
    function set(name, value) {
        values[name] = value;
    }
    
    function resetValue(name) {
		if ( typeof name !== 'undefined' ) {
			if ( typeof props[name] !== 'undefined' ) {
				if ( typeof props[name]['default'] !== 'undefined' ) {
					set(name, props[name]['default']);
				}
			}
		} else {
			for (var name in props) {
				if (typeof props[name]['default'] !== 'undefined') {
					set(name, props[name]['default']);
				}
			}
		}
    }
	
	function sendMessage(data) {
		if ( dialogWindow !== null && dialogWindowOrigin !== null && data !== null && typeof data === 'object' ) {
			var iv = window.crypto.getRandomValues(new Uint8Array(12));
			window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, dialogPublicKey, iv).then(ivEncrypted => {
				window.crypto.subtle.encrypt({name: "AES-GCM",iv: iv},aesKey,new TextEncoder().encode(JSON.stringify(data))).then(encrypted => {
					if ( dialogWindow !== null && dialogWindowOrigin !== null )
						dialogWindow.postMessage({data: encrypted, token: ivEncrypted},dialogWindowOrigin);
				}).catch(err => {
					console.log(err);
				});
			}).catch(err => {
				console.log(err);
			});
		}
	}
	
	function reportSuccess(originalLifecycle, validations) {
		sendMessage({lifecycle: originalLifecycle+'Success', validations: validations});
	}
	
	function reportFailure(originalLifecycle, validations) {
		sendMessage({lifecycle: originalLifecycle+'Failure', validations: validations});
	}
    
    function receivedMessage(data) {
        try{
			if ( data.lifecycle === 'Save' ) {
				try {
					var isValid = true;
					if ( typeof validators !== 'undefined' ) {
						var validations = {};
						for ( var name in validators ) {
							var messages = [];
							if ( !validators[name](data.values[name],messages) ) {
								isValid = false;
								validations[name] = { isValid: false, messages: messages };
							} else {
								validations[name] = { isValid: true, messages: messages };
							}
						}
					}
					if ( isValid ) {
						GM_setValue(storageKey, JSON.stringify(data.values));
						values = JSON.parse(GM_getValue(storageKey));
						reportSuccess(data.lifecycle,validations);
					} else {
						reportFailure(data.lifecycle,validations);
					}
				} catch (err) {
					reportFailure(data.lifecycle);
				}
			} else if ( data.lifecycle === 'Close' ) {
				closeDlg();
			} else if ( data.lifecycle === 'ConfigureSuccess' ) {
				document.querySelector('#VMPropsModal').style.display = null;
			} else if ( data.lifecycle === 'ConfigureFailure' ) {
				closeDlg();
			}
		} catch (err) {
			console.log(err);
		}
    }
	
	function closeDlg() {
		var e = document.querySelector('#VMPropsModal');
		e.parentElement.removeChild(e);
		window.removeEventListener('message', listener);
		dialogWindow = null;
	}
	
	function listener(msg) {
		if ( msg.type === 'message' && msg.origin === dialogOrigin && typeof msg.data === 'object' && typeof msg.data.token !== 'undefined' ) {
			window.crypto.subtle.decrypt({ name: rsaKey.privateKey.algorithm.name }, rsaKey.privateKey, msg.data.token).then(iv => {
				window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, msg.data.data).then(data => {
					data = new TextDecoder().decode(data);
					if ( typeof data !== 'string' ) {
						console.log('invalid data detected!');
						return;
					}
					data = JSON.parse(data);
					if ( typeof data !== 'object' ) {
						console.log('invalid data detected!');
						return;
					}
					console.log(data);
					if ( typeof data.lifecycle !== 'undefined' && data.lifecycle !== null ) {
						receivedMessage(data);
					}
				}).catch(err => {
					console.log(err);
				});
			}).catch(err => {
				console.log(err);
			});
		}
	}
	
	function handshakeListener(e) {
		if ( e.type === 'message' && e.origin === dialogOrigin ) {
			if ( typeof e.data !== 'undefined' ) {
				if ( typeof e.data === 'object' && typeof e.data.publicKey !== 'undefined' ) {
					if ( dialogPublicKey === null ) {
						try {
							dialogPublicKey = e.data.publicKey;
							dialogWindow = e.source;
							dialogWindowOrigin = e.origin;
							window.crypto.subtle.generateKey(
								{
									name: "RSA-OAEP",
									modulusLength: 2048,
									publicExponent: new Uint8Array([1, 0, 1]),
									hash: "SHA-256",
								},
								true,
								["encrypt", "decrypt", "wrapKey", "unwrapKey"]
							).then((keyPair) => {
								rsaKey = keyPair;
								window.crypto.subtle.generateKey({name: "AES-GCM",length: 256,},true,["encrypt", "decrypt"]).then(aesKeyLocal=>{
									aesKey = aesKeyLocal;
									crypto.subtle.wrapKey('jwk',aesKey,dialogPublicKey,dialogPublicKey.algorithm.name).then(aesKeyWrapped => {
										e.source.postMessage({publicKey: rsaKey.publicKey, passphrase: aesKeyWrapped},e.origin);
									}).catch(err => {
										console.log(err);
										dialogPublicKey = rsaKey = aesKey = null;
									});
								}).catch(err => {
									console.log(err);
									dialogPublicKey = rsaKey = aesKey = null;
								});
							}).catch(err => {
								console.log(err);
								dialogPublicKey = rsaKey = null;
							});
						} catch (err) {
							console.log('failed to generate key after receiving public key from dialog: '+err);
							dialogPublicKey = null;
						}
					}
				} else if ( dialogPublicKey !== null && typeof e.data === 'object' && typeof e.data.lifecycle !== 'undefined' ) {
					try {
						decrypt(rsaKey.privateKey, e.data.lifecycle).then((decrypted) => {
							if ( decrypted === 'GetConfiguration' ) {
								window.addEventListener('message', listener);
								window.removeEventListener('message', handshakeListener);
								//update in case the values got changed on another page
								var storedValues;
								if (GM_getValue(storageKey)) storedValues = JSON.parse(GM_getValue(storageKey));
								if ( storedValues ) values = storedValues;
								sendMessage({props: props, values: values, lifecycle: 'Configure', title: title, dlgSize: dlgSize});
							}
						}).catch(err => {
							console.log(err);
						});
					} catch (err) {
						console.log('invalid encryption data: '+err);
					}
				}
			}
		}
	}
	
	async function decrypt(key, data) {
		return new TextDecoder().decode(await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, data));
	}
	
	async function encrypt(key, data) {
		//new TextEncoder().encode(JSON.stringify(data))
		return await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, new TextEncoder().encode(JSON.stringify(data)));
	}
	
	function listen() {
		dialogPublicKey = privateKey = publicKey = passphrase = dialogPassphrase = null;
		window.addEventListener('message', handshakeListener);
	}

    function open() {
		try {
			if ( document.domain !== null ) {
				for ( var reg in prohibitedHosts ) {
					if ( prohibitedHosts[reg].test(document.domain) ) {
						alert('Accessing the settings dialog from this host is prohibited.');
						return;
					}
				}
			}
			if ( document.querySelector('#VMPropsModal') === null ) {
				listen();
				var body = document.querySelector('body');
				var iframe = document.createElement('iframe');
				
				iframe.id = 'VMPropsModal';
				iframe.style.display = 'none';
				iframe.style.position = 'fixed';
				iframe.style.left = 0;
				iframe.style.top = 0;
				iframe.style.width = '100%';
				iframe.style.height = '100%';
				iframe.style.zIndex = 9999;
				iframe.frameBorder = '0';
				iframe.scrolling = 'no';
				iframe.seamless = true;
				
				body.appendChild(iframe);
				iframe.src = dialogSrc;
			} else {
				document.querySelector('#VMPropsModal').style.display = 'none';;
			}
		} catch (err) {
			console.log(err);
		}
    }
	
    init(arguments[0]);
}