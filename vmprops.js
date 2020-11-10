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

function VMProps() {
    var dialogOrigin;
    var prohibitedHosts;
    var dialogSrc;

    var props, values, callbacks, storageKey, title, dialogWindow, dialogWindowOrigin, dlgSize,
            dialogPublicKey, rsaKey, aesKey, onSave;

    /**
     * Initialize configuration 
     * 
     * @param newData New data object
     */
    function init(newData) {
        var data;
        if (newData)
            data = newData;
        else
            data = {};

        if (data.props === undefined || data.props === null)
            props = {};
        else
            props = data.props;

        callbacks = data.callbacks;

        dialogOrigin = data.dialogOrigin ? data.dialogOrigin : 'https://razuhl.github.io';
        prohibitedHosts = data.prohibitedHosts ? data.prohibitedHosts : [/http[s]?:\/\/(.+[.])?github([.][^/]+)?/];
        dialogSrc = data.dialogSrc ? data.dialogSrc : 'https://razuhl.github.io/vmms/vmprops.html';

        values = {};

        title = data.title ? data.title : 'Configure';

        storageKey = data.storageKey ? data.storageKey :
                typeof GM_getMetadata === 'function' ? '_VMProps_storage_' + GM_getMetadata('name').replace(/[^a-zA-Z0-9]/g, '_') :
                '_VMProps_storage_Unknown';

        dlgSize = data.dlgSize;

        onSave = typeof data.onSave === 'function' ? data.onSave : null;

        var storedValues;

        if (GM_getValue(storageKey))
            storedValues = JSON.parse(GM_getValue(storageKey));

        for (var name in props) {
            if (storedValues && storedValues[name] !== undefined)
                _set(name, storedValues[name]);
            else
                _set(name, props[name]['default']);
        }

        processCallbacks(values, {}, false, true);
        
        if (data.menuCommand) {
            GM_registerMenuCommand(title, function () {
                _open();
            });
        }
    }

    function _get(name) {
        return values[name];
    }
    
    function addImpliedDefaultValues(defaultValue, cfg) {
        if ( defaultValue === undefined || defaultValue === null || typeof cfg.props === 'undefined' ) return;
        for ( const p in cfg.props ) {
            if ( typeof cfg.props[p].default !== 'undefined' ) {
                if ( Array.isArray(defaultValue) ) {
                    for ( const entry of defaultValue ) {
                        if ( entry !== null ) {
                            if ( typeof entry[p] === 'undefined' ) {
                                entry[p] = cfg.props[p].default;
                            }
                            addImpliedDefaultValues(entry[p],cfg.props[p]);
                        }
                    }
                } else {
                    if ( typeof defaultValue[p] === 'undefined' ) {
                        defaultValue[p] = cfg.props[p].default;
                    }
                    addImpliedDefaultValues(defaultValue[p],cfg.props[p]);
                }
            }
        }
    }

    function _set(name, value) {
        if ( typeof value === 'undefined' ) {
            value = props[name].default;
        }
        addImpliedDefaultValues(value, props[name]);
        
        values[name] = value;
    }

    function _resetValue(name) {
        if (typeof name !== 'undefined') {
            if (typeof props[name] !== 'undefined') {
                if (typeof props[name]['default'] !== 'undefined') {
                    _set(name, props[name]['default']);
                }
            }
        } else {
            for (var name in props) {
                if (typeof props[name]['default'] !== 'undefined') {
                    _set(name, props[name]['default']);
                }
            }
        }
    }

    function sendMessage(data) {
        if (dialogWindow !== null && dialogWindowOrigin !== null && data !== null && typeof data === 'object') {
            var iv = window.crypto.getRandomValues(new Uint8Array(12));
            window.crypto.subtle.encrypt({name: "RSA-OAEP"}, dialogPublicKey, iv).then(ivEncrypted => {
                window.crypto.subtle.encrypt({name: "AES-GCM", iv: iv}, aesKey, new TextEncoder().encode(JSON.stringify(data))).then(encrypted => {
                    if (dialogWindow !== null && dialogWindowOrigin !== null)
                        dialogWindow.postMessage({data: encrypted, token: ivEncrypted}, dialogWindowOrigin);
                }).catch(err => {
                    console.log(err);
                });
            }).catch(err => {
                console.log(err);
            });
        }
    }

    function reportSuccess(originalLifecycle, validations) {
        sendMessage({lifecycle: originalLifecycle + 'Success', validations: validations});
    }

    function reportFailure(originalLifecycle, validations) {
        sendMessage({lifecycle: originalLifecycle + 'Failure', validations: validations});
    }
    
    function removeIrrelevantMessages(messages, propertyName) {
        //the validation of true is implicit so we remove all entries that are either empty or true and have no messages.
        const childLength = Object.keys(messages[propertyName]).length;
        if ( childLength === 0 || (childLength === 2 && messages[propertyName].__isValid && messages[propertyName].__messages.length === 0) ) {
            delete messages[propertyName];
        } else if ( childLength > 2 && messages[propertyName].__isValid && messages[propertyName].__messages.length === 0 ) {
            delete messages[propertyName].__isValid;
            delete messages[propertyName].__messages;
        }
    }
    
    function processCallbacksLoop(currentValue, currentCallbacks, messages, doValidators, doConverters, allValues, isArrayEntry) {
        var isValidSubtree = true;
        if ( Array.isArray(currentValue) ) {
            //if only the entries validator exists we do not need to traverse further down the tree.
            if ( currentCallbacks.entries === undefined || Object.keys(currentCallbacks).length > 1 ) {
                var index = 0;
                for ( const entry of currentValue ) {
                    var nextMessages = {};
                    messages[index] = nextMessages;
                    isValidSubtree = processCallbacksLoop(entry, currentCallbacks, nextMessages, doValidators, doConverters, allValues, true) && isValidSubtree;
                    removeIrrelevantMessages(messages, index);
                    index++;
                }
            }
        } else if ( currentValue && Object.keys(currentValue).length > 0 ) {
            for ( const property in currentValue ) {
                const nextCallback = currentCallbacks[property];
                if ( nextCallback !== undefined ) {
                    var nextMessages = {};
                    messages[property] = nextMessages;
                    isValidSubtree = processCallbacksLoop(currentValue[property], nextCallback, nextMessages, doValidators, doConverters, allValues, false) && isValidSubtree;
                    removeIrrelevantMessages(messages, property);
                }
            }
        }
        //on the way up we perform validation and conversion
        if ( Array.isArray(currentValue) && currentCallbacks.entries !== undefined ) {
            const validator = doValidators ? currentCallbacks.entries.validator : false;
            const converter = doConverters ? currentCallbacks.entries.converter : false;
            var isValidProperty = true;
            var indx = 0;
            for ( const entry of currentValue ) {
                if ( converter ) {
                    const messagesForEntries = messages[indx] !== undefined ? messages[indx].__messages : [];
                    converter(entry, messagesForEntries, allValues);
                    if ( messagesForEntries.length > 0 ) {
                        messages[indx] = {__messages: messagesForEntries, __isValid: true};
                    }
                    
                }
                if ( validator ) {
                    var isValidEntry = true;
                    const messagesForEntries = messages[indx] !== undefined ? messages[indx].__messages : [];
                    isValidEntry = validator(entry, messagesForEntries, allValues);
                    if ( !isValidEntry || messagesForEntries.length > 0 ) {
                        messages[indx] = {__messages: messagesForEntries, __isValid:isValidEntry};
                    }
                    isValidProperty = isValidEntry && isValidProperty;
                }
                indx++;
            }
            messages.__isValid = isValidProperty;
            isValidSubtree = isValidProperty && isValidSubtree; 
        }
        if ( !isArrayEntry ) {
            if ( doConverters && currentCallbacks.converter !== undefined ) {
                const isValid = messages.__isValid !== undefined ? messages.__isValid : true;
                const messagesForProperties = messages.__messages !== undefined ? messages.__messages : [];
                currentCallbacks.converter(currentValue, messagesForProperties, allValues);
                messages.__isValid = isValid;
                messages.__messages = messagesForProperties;
            }
            if ( doValidators && currentCallbacks.validator !== undefined ) {
                var isValid = messages.__isValid !== undefined ? messages.__isValid : true;
                const messagesForProperties = messages.__messages !== undefined ? messages.__messages : [];
                isValid = currentCallbacks.validator(currentValue, messagesForProperties, allValues) && isValid;
                messages.__isValid = isValid;
                messages.__messages = messagesForProperties;
                isValidSubtree = isValid && isValidSubtree;
            }
        }
        return isValidSubtree;
    }
    
    function processCallbacks(valuesToProcess, messages, doValidators, doConverters) {
        if ( callbacks === undefined || callbacks === null ) return true;
        if ( !doValidators && !doConverters ) return true;
        return processCallbacksLoop(valuesToProcess,callbacks,messages,doValidators,doConverters,valuesToProcess,false);
    }

    function saveValues(newValues, validations) {
        var isValid = true;

        try {
            isValid = processCallbacks(newValues, validations, true, true);
        } catch (ex) {
            console.log(ex);
            isValid = false;
        }
        
        if (isValid) {
            GM_setValue(storageKey, JSON.stringify(newValues));
            values = JSON.parse(GM_getValue(storageKey));
            try {
                if (onSave !== null)
                    onSave(newValues);
            } catch (errOnCallback) {
                console.log('Error was thrown during user defined onSave callback!');
                console.log(errOnCallback);
            }
        }

        return isValid;
    }

    function receivedMessage(data) {
        try {
            if (data.lifecycle === 'Save') {
                try {
                    var validations = {};
                    if (saveValues(data.values, validations)) {
                        reportSuccess(data.lifecycle, validations);
                    } else {
                        reportFailure(data.lifecycle, validations);
                    }
                } catch (err) {
                    reportFailure(data.lifecycle);
                }
            } else if (data.lifecycle === 'Close') {
                closeDlg();
            } else if (data.lifecycle === 'ConfigureSuccess') {
                document.querySelector('#VMPropsModal').style.display = null;
            } else if (data.lifecycle === 'ConfigureFailure') {
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
        if (msg.type === 'message' && msg.origin === dialogOrigin && typeof msg.data === 'object' && typeof msg.data.token !== 'undefined') {
            window.crypto.subtle.decrypt({name: rsaKey.privateKey.algorithm.name}, rsaKey.privateKey, msg.data.token).then(iv => {
                window.crypto.subtle.decrypt({name: "AES-GCM", iv: iv}, aesKey, msg.data.data).then(data => {
                    data = new TextDecoder().decode(data);
                    if (typeof data !== 'string') {
                        console.log('invalid data detected!');
                        return;
                    }
                    data = JSON.parse(data);
                    if (typeof data !== 'object') {
                        console.log('invalid data detected!');
                        return;
                    }
                    if (typeof data.lifecycle !== 'undefined' && data.lifecycle !== null) {
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
        if (e.type === 'message' && e.origin === dialogOrigin) {
            if (typeof e.data !== 'undefined') {
                if (typeof e.data === 'object' && typeof e.data.publicKey !== 'undefined') {
                    if (dialogPublicKey === null) {
                        try {
                            dialogPublicKey = e.data.publicKey;
                            dialogWindow = e.source;
                            dialogWindowOrigin = e.origin;
                            window.crypto.subtle.generateKey(
                                    {
                                        name: "RSA-OAEP",
                                        modulusLength: 2048,
                                        publicExponent: new Uint8Array([1, 0, 1]),
                                        hash: "SHA-256"
                                    },
                                    true,
                                    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
                                    ).then((keyPair) => {
                                rsaKey = keyPair;
                                window.crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"]).then(aesKeyLocal => {
                                    aesKey = aesKeyLocal;
                                    crypto.subtle.wrapKey('jwk', aesKey, dialogPublicKey, dialogPublicKey.algorithm.name).then(aesKeyWrapped => {
                                        e.source.postMessage({publicKey: rsaKey.publicKey, passphrase: aesKeyWrapped}, e.origin);
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
                            console.log('failed to generate key after receiving public key from dialog: ' + err);
                            dialogPublicKey = null;
                        }
                    }
                } else if (dialogPublicKey !== null && typeof e.data === 'object' && typeof e.data.lifecycle !== 'undefined') {
                    try {
                        decrypt(rsaKey.privateKey, e.data.lifecycle).then((decrypted) => {
                            if (decrypted === 'GetConfiguration') {
                                window.addEventListener('message', listener);
                                window.removeEventListener('message', handshakeListener);
                                sendConfiguration();
                            }
                        }).catch(err => {
                            console.log(err);
                        });
                    } catch (err) {
                        console.log('invalid encryption data: ' + err);
                    }
                }
            }
        }
    }
    
    function sendConfiguration() {
        //update in case the values got changed on another page
        var storedValues;
        if (GM_getValue(storageKey))
            storedValues = JSON.parse(GM_getValue(storageKey));
        if (storedValues)
            values = storedValues;
        sendMessage({props: props, values: values, lifecycle: 'Configure', title: title, dlgSize: dlgSize});
    }

    async function decrypt(key, data) {
        return new TextDecoder().decode(await window.crypto.subtle.decrypt({name: "RSA-OAEP"}, key, data));
    }

    async function encrypt(key, data) {
        //new TextEncoder().encode(JSON.stringify(data))
        return await window.crypto.subtle.encrypt({name: "RSA-OAEP"}, key, new TextEncoder().encode(JSON.stringify(data)));
    }

    function listen() {
        dialogPublicKey = privateKey = publicKey = passphrase = dialogPassphrase = null;
        window.addEventListener('message', handshakeListener);
    }

    function _open() {
        try {
            if (document.domain !== null) {
                for (var reg in prohibitedHosts) {
                    if (prohibitedHosts[reg].test(document.domain)) {
                        alert('Accessing the settings dialog from this host is prohibited.');
                        return;
                    }
                }
            }
            if (document.querySelector('#VMPropsModal') === null) {
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
                document.querySelector('#VMPropsModal').style.display = 'none';
                sendConfiguration();
            }
        } catch (err) {
            console.log(err);
        }
    }

    init(arguments[0]);

    //exposing method for menu command
    this.open = _open;
    //exposing methods for value cache
    this.get = _get;
    this.set = _set;
    this.resetValue = _resetValue;
    this.save = function (validations) {
        if (typeof validations === 'undefined' || validations === null)
            validations = {};
        return saveValues(values, validations);
    }
}