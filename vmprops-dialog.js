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

class Communicator {
    pairedWindow = null;
    pairedDomain = null;
    rsaKey = null;
    callerPublicKey = null;
    callerAesKey = null;
    handler = null;
    
    constructor(handler, targetWindow) {
        this.handler = handler;
        
        window.addEventListener('message', this.listenerHandshake.bind(this));
        try {
            window.crypto.subtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: "SHA-256"
                    },
                    true,
                    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
                    ).then((rsaKeyLocal) => {
                this.rsaKey = rsaKeyLocal;
                targetWindow.postMessage({publicKey: this.rsaKey.publicKey}, '*');
            }).catch(err => {console.log(err);});
        } catch (err) {
            console.log('failed to generate key when creating dialog: ' + err);
            this.rsaKey = null;
        }
    }
    
    sendMessage(data) {
        if (this.pairedWindow !== null && this.pairedDomain !== null && data !== null && typeof data === 'object') {
            var iv = window.crypto.getRandomValues(new Uint8Array(12));
            window.crypto.subtle.encrypt({name: "RSA-OAEP"}, this.callerPublicKey, iv).then(ivEncrypted => {
                window.crypto.subtle.encrypt({name: "AES-GCM", iv: iv}, this.callerAesKey, new TextEncoder().encode(JSON.stringify(data))).then(encrypted => {
                    if (this.pairedWindow !== null && this.pairedDomain !== null)
                        this.pairedWindow.postMessage({data: encrypted, token: ivEncrypted}, this.pairedDomain);
                }).catch(err => {
                    console.log(err);
                });
            }).catch(err => {
                console.log(err);
            });
        }
    }
    
    reportSuccess(originalLifecycle) {
        this.sendMessage({lifecycle: originalLifecycle + 'Success'});
    }

    reportFailure(originalLifecycle) {
        this.sendMessage({lifecycle: originalLifecycle + 'Failure'});
    }

    listenerHandshake(msg) {
        if (typeof msg.data === 'object' && typeof msg.data.publicKey !== 'undefined' && typeof msg.data.passphrase !== 'undefined') {
            try {
                crypto.subtle.unwrapKey('jwk', msg.data.passphrase, this.rsaKey.privateKey, this.rsaKey.privateKey.algorithm.name, 'AES-GCM', true, ["encrypt", "decrypt"])
                        .then(aesKeyUnwrapped => {
                            try {
                                this.pairedWindow = msg.source;
                                this.pairedDomain = msg.origin;
                                this.callerAesKey = aesKeyUnwrapped;
                                this.callerPublicKey = msg.data.publicKey;
                                window.crypto.subtle.encrypt({name: "RSA-OAEP"}, this.callerPublicKey, new TextEncoder().encode('GetConfiguration')).then(lifecycleEncrypted => {
                                    window.removeEventListener('message', this.listenerHandshake);
                                    window.addEventListener('message', this.listener.bind(this));
                                    this.pairedWindow.postMessage({lifecycle: lifecycleEncrypted}, this.pairedDomain);
                                });
                            } catch (err) {
                                console.log('failed to encrypt aes key: ' + err);
                                this.pairedWindow = this.pairedDomain = this.callerPublicKey = this.callerAesKey = null;
                            }
                        });
            } catch (err) {
                console.log('failed to decrypt passphrase: ' + err);
                this.pairedWindow = this.pairedDomain = this.callerPublicKey = this.callerAesKey = null;
            }
        }
    }
    
    listener(msg) {
        if (msg.source === this.pairedWindow && msg.origin === this.pairedDomain && typeof msg.data !== 'undefined') {
            this.handler.clearStatus();
            window.crypto.subtle.decrypt({name: this.rsaKey.privateKey.algorithm.name}, this.rsaKey.privateKey, msg.data.token).then(iv => {
                window.crypto.subtle.decrypt({name: "AES-GCM", iv: iv}, this.callerAesKey, msg.data.data).then(data => {
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
                    if (data.lifecycle === 'Configure') {
                        try {
                            var dlg = document.querySelector('#VMPropsModal');
                            $('#modalLabel').text(data.title);
                            $('head>title').text(data.title);
                            this.handler.props = data.props;
                            this.handler.currentValue = data.values;
                            this.handler.rootValue = data.values;
                            this.handler.rootProps = data.props;

                            var dlgClass = $('div.modal-dialog');
                            dlgClass.removeClass(['modal-sm', 'modal-lg', 'modal-xl']);
                            if (data.dlgSize !== undefined && data.dlgSize !== null) {
                                if (data.dlgSize === 'xl') {
                                    dlgClass.addClass('modal-xl');
                                } else if (data.dlgSize === 'l') {
                                    dlgClass.addClass('modal-lg');
                                } else if (data.dlgSize === 's') {
                                    dlgClass.addClass('modal-sm');
                                } else
                                    dlgClass.addClass(data.dlgSize);
                            }

                            this.handler.buildBody();

                            $(dlg).modal({backdrop: 'static'});
                            this.reportSuccess(data.lifecycle);
                        } catch (err) {
                            console.log(err);
                            this.reportFailure(data.lifecycle);
                        }
                    } else if (data.lifecycle === 'UpdateValues') {
                        for (var name in data.values) {
                            this.handler.setPropertyValue(name, data.values[name]);
                        }
                    } else if (data.lifecycle === 'UpdateValue') {
                        this.handler.setPropertyValue(data.propertyName, data.propertyValue);
                    } else if (data.lifecycle === 'SaveSuccess') {
                        $('.modal-body').append('<div class="alert alert-success alert-dismissible">' +
                                '<button type="button" class="close" data-dismiss="alert">&times;</button>Saved</div>');
                    } else if (data.lifecycle === 'SaveFailure') {
                        $('.modal-body').append('<div class="alert alert-danger alert-dismissible">' +
                                '<button type="button" class="close" data-dismiss="alert">&times;</button>Failed to Save</div>');
                    }

                    if (data.lifecycle === 'SaveSuccess' || data.lifecycle === 'SaveFailure') {
                        var closed = false;
                        if (data.lifecycle === 'SaveSuccess') {
                            if ( !this.forAny(data.validations,n=>n.__messages !== undefined && n.__messages.length > 0) ) {
                                $('#btn_close').click();
                                closed = true;
                            }
                        }
                        if ( !closed ) this.processValidationResult(data.validations);
                    }
                });
            });
        }
    }
    
    forAny(obj,predicate) {
        if ( predicate(obj) ) return true;
        if (typeof obj === 'object' || Array.isArray(obj)) {
            for (const propName in obj) {
                const prop = obj[propName];
                if ( this.forAny(prop, predicate) ) return true;
            }
        }
        return false;
    }
    
    buildHTMLMessagePreamble(pathForMessage, pathRootIndex) {
        var htmlMessagePreamble = null;
        for ( var i = Math.max(0,pathRootIndex); i < pathForMessage.length; i++ ) {
            if ( pathForMessage[i].index !== undefined ) {
                if ( htmlMessagePreamble === null ) {
                    if ( pathRootIndex >= 0 ) {
                        htmlMessagePreamble = '<span class="badge badge-pill badge-dark">'+
                            pathForMessage[i].index+'</span>';
                    } else {
                        htmlMessagePreamble = '<span class="badge badge-pill badge-info"><span class="badge badge-pill badge-dark">'+
                            pathForMessage[i].index+'</span>'+
                            pathForMessage[i].label+'</span>';
                    }
                } else {
                    htmlMessagePreamble += '<span class="badge badge-pill badge-info"><span class="badge badge-pill badge-dark">'+
                            pathForMessage[i].index+'</span>'+
                            pathForMessage[i].label+'</span>';
                }
            } else {
                if ( htmlMessagePreamble === null ) {
                    if ( pathRootIndex >= 0 ) 
                        htmlMessagePreamble = '';
                    else htmlMessagePreamble = '<span class="badge badge-pill badge-info">'+pathForMessage[i].label+'</span>';
                } else {
                    htmlMessagePreamble += '<span class="badge badge-pill badge-info">'+pathForMessage[i].label+'</span>';
                }
            }
        }
        return htmlMessagePreamble !== null ? htmlMessagePreamble : '';
    }
    
    processValidationResult(validationResult) {
        if (validationResult) {
            /*
             * Validations are displayed in one of 4 positions.
             *  1. Global, because the relevant property or any of its ancestors are not visible in the dialog. A path from the root of the tree is displayed before the message.
             *  2. Global, because the relevant property is the object currently opened in the dialog. No path is displayed before the message.
             *  3. On a property, because it is the relevant property. No path is displayed(in case of lists an index is displayed if the message belongs to an entry instead of the entire list.
             *  4. On a property, because it is a visible ancestor of the relevant property. A path from the display to the relevant property is displayed before the message.
             */
            var propertyIterator = function* (obj) {
                for (const propertyName in obj) {
                    if ( !propertyName.startsWith('__') )
                        yield {propertyName, propertyValue: obj[propertyName]};
                }
            };
            var pathForMessage = [];
            var messagesForProperty = [];
            var propertyStack = [];
            var valueStack = [];
            var validatorStack = [];
            var currentProperty = this.handler.rootProps;
            var currentValue = this.handler.rootValue;
            var currentValidatorPosition = propertyIterator(validationResult);
            var lockout = 1000000;
            var pathRootIndex = this.handler.props === this.handler.rootProps ? 0 : -1;
            var subtreeIsValid = true;
            var globalUnprivileged = $('#validationMessagesGlobal');
            var globalPrivileged = $('#validationMessagesCurrent');
            
            //special case for displaying messages on the root object
            if ( validationResult.__messages ) {
                if ( this.handler.props === this.handler.rootProps ) {
                    for ( const msg of validationResult.__messages ) {
                        globalPrivileged.append('<div class="' + (validationResult.__isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + this.handler.escapeHTML(msg) + '</div>');
                    }
                } else {
                    for ( const msg of validationResult.__messages ) {
                        globalUnprivileged.append('<div class="' + (validationResult.__isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + this.handler.escapeHTML(msg) + '</div>');
                    }
                }
            }
            
            while (lockout > 0) {
                lockout--;
                var pos = currentValidatorPosition.next();
                if (!pos.done) {
                    validatorStack.push(currentValidatorPosition);
                    //stepping into either a new property or an array entry
                    if ((currentProperty.props === undefined && currentProperty[pos.value.propertyName] !== undefined) || (currentProperty.props !== undefined && currentProperty.props[pos.value.propertyName] !== undefined)) {
                        propertyStack.push(currentProperty);
                        //The marker makes it so that message below this point display themself with the shortened path but messages before or beside this point must be able 
                        //to display themselfs with the full path from root.
                        if ( currentProperty.props !== undefined )
                            currentProperty = currentProperty.props[pos.value.propertyName];
                        else currentProperty = currentProperty[pos.value.propertyName];
                        if ( currentValue !== undefined ) {
                            valueStack.push(currentValue);
                            currentValue = currentValue[pos.value.propertyName];
                        }
                        pathForMessage.push({label:currentProperty.label,name:pos.value.propertyName});
                        if ( currentValue === this.handler.currentValue ) {
                            pathRootIndex = pathForMessage.length;
                            subtreeIsValid = true;
                        }
                    } else {
                        pathForMessage[pathForMessage.length - 1].index = pos.value.propertyName;
                        valueStack.push(currentValue);
                        currentValue = currentValue[pos.value.propertyName];
                        if ( currentValue === this.handler.currentValue ) {
                            pathRootIndex = pathForMessage.length;
                            subtreeIsValid = true;
                        }
                        propertyStack.push(null);
                    }
                    //if a validation result exists at this position we create a message
                    if ( pos.value.propertyValue.__isValid !== undefined ) {
                        var msgs = pos.value.propertyValue.__messages;
                        //If messages are empty but the valid flag is set to false we want to still mark the property/list entry but won't display a message.
                        //In case of global messages we can simply skip but property messages must call through to the displayValidations.
                        if ( msgs !== undefined ) {
                            if ( pathRootIndex === -1 ) {
                                if ( msgs.length > 0 ) {
                                    //global message
                                    var htmlMessagePreamble = this.buildHTMLMessagePreamble(pathForMessage,pathRootIndex);
                                    for ( const msg of msgs ) {
                                        globalUnprivileged.append('<div class="' + (pos.value.propertyValue.__isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + 
                                            htmlMessagePreamble + this.handler.escapeHTML(msg) + '</div>');
                                    }
                                }
                            } else {
                                if ( currentValue === this.handler.currentValue ) {
                                    if ( msgs.length > 0 ) {
                                        //These messages are for the currently edited object and must be displayed in the same place as global messages but before them.
                                        var htmlMessagePreamble = this.buildHTMLMessagePreamble(pathForMessage,pathRootIndex);
                                        for ( const msg of msgs ) {
                                            globalPrivileged.append('<div class="' + (pos.value.propertyValue.__isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + 
                                                htmlMessagePreamble + this.handler.escapeHTML(msg) + '</div>');
                                        }
                                    }
                                } else {
                                    //collect message for displaying on property
                                    if ( msgs.length > 0 ) {
                                        var htmlMessagePreamble = this.buildHTMLMessagePreamble(pathForMessage,pathRootIndex);
                                        for ( const msg of msgs ) {
                                            messagesForProperty.push({message: htmlMessagePreamble + this.handler.escapeHTML(msg),
                                                isValid:pos.value.propertyValue.__isValid,listEntry:pathForMessage[Math.max(0,pathRootIndex)].index});
                                        }
                                    } else {
                                        messagesForProperty.push({message: 'No Message', isValid: pos.value.propertyValue.__isValid, listEntry:pathForMessage[Math.max(0,pathRootIndex)].index});
                                    }
                                    subtreeIsValid = subtreeIsValid && pos.value.propertyValue.__isValid;
                                }
                            }
                        }
                    }
                    currentValidatorPosition = propertyIterator(pos.value.propertyValue);
                } else {
                    currentValidatorPosition = validatorStack.pop();
                    //stepping out
                    if (currentValidatorPosition === undefined)
                        break;
                    var previousProperty = propertyStack.pop();
                    if ( previousProperty !== null && pathRootIndex === pathForMessage.length - 1 ) {
                        this.handler.propertyHandlers[currentProperty.type].displayValidation($('#' + pathForMessage[pathForMessage.length - 1].name), {isValid: subtreeIsValid, messages: messagesForProperty});
                        messagesForProperty.splice(0,messagesForProperty.length);
                        subtreeIsValid = true;
                    }
                    if ( currentValue === this.handler.currentValue ) {
                        pathRootIndex = -1;
                    }
                    currentValue = valueStack.pop();
                    if (previousProperty !== null) {
                        currentProperty = previousProperty;
                        pathForMessage.pop();
                    } else
                        delete pathForMessage[pathForMessage.length - 1].index;
                }
            }
        }
        $('div.modal-body .dataHolder').not('.is-invalid').addClass('is-valid');
    }
}

class Handler {
    props = null;
    currentValue = null;
    rootValue = null;
    rootProps = null;
    
    constructor(targetWindow) {
        var communicator = new Communicator(this,targetWindow);
        
        $('#btn_save').on('click', ()=>{
            this.copyValuesIntoModel();

            communicator.sendMessage({lifecycle: 'Save', values: this.rootValue});
        });

        $('#btn_close, button.close').on('click', ()=>{
            communicator.sendMessage({lifecycle: 'Close'});
        });
        
        $('#btn_defaults').on('click', ()=>this.defaults());
        
        window.vmPropsHandler = this;
    }
    
    escapeHTML(str) {
        return str.replace(/[&<>]/g, function (m) {
            switch (m) {
                case '&':
                    return '&amp;';
                case '<':
                    return '&lt;';
                case '>':
                    return '&gt;';
            }
            return 'error';
        });
    }
    
    clearStatus() {
        $('.modal-body .alert').each(function (indx, e) {
            $(e).alert('close');
        });
        $('div.modal-body .is-invalid').removeClass('is-invalid');
        $('div.modal-body .is-valid').removeClass('is-valid');
        $('div.modal-body .invalid-feedback').remove();
        $('div.modal-body .valid-feedback').remove();
    }
    
    defaults() {
        var _self = this;
        $('div.modal-body .dataHolder').each(function (indx, e) {
            e = $(e);
            if (e.data('default') !== undefined) {
                _self.propertyHandlers[e.data('type')].setPropertyValue(e, JSON.parse(JSON.stringify(e.data('default'))));
            }
        });
        this.clearStatus();
    }
    
    addImpliedDefaultValues(defaultValue, cfg) {
        if (  defaultValue === undefined || defaultValue === null || typeof cfg.props === 'undefined' ) return;
        for ( const p in cfg.props ) {
            if ( typeof cfg.props[p].default !== 'undefined' ) {
                if ( Array.isArray(defaultValue) ) {
                    for ( const entry of defaultValue ) {
                        if ( entry !== null ) {
                            if ( typeof entry[p] === 'undefined' ) {
                                entry[p] = cfg.props[p].default;
                            }
                            this.addImpliedDefaultValues(entry[p],cfg.props[p]);
                        }
                    }
                } else {
                    if ( typeof defaultValue[p] === 'undefined' ) {
                        defaultValue[p] = cfg.props[p].default;
                    }
                    this.addImpliedDefaultValues(defaultValue[p],cfg.props[p]);
                }
            }
        }
    }
    
    buildProperty(container, name, cfg) {
        this.propertyHandlers[cfg.type].buildProperty(container, name, cfg);
        var e = $('#' + name);
        e.data('type', cfg.type);
        if (typeof cfg.default !== 'undefined') {
            //in case objects or lists of object appear we have to add implied default values that were defined in child properties but not in the default value itself.
            this.addImpliedDefaultValues(cfg.default, cfg);
            e.data('default', cfg.default);
        }
    }
    
    setPropertyValue(name, value) {
        var e = $('#VMPropsModal #' + name);
        this.propertyHandlers[e.data('type')].setPropertyValue(e, value);
    }
    
    shiftElementUp(e) {
        var prev = e.prev();
        if ( prev.length > 0 ) {
            prev.insertAfter(e);
            var btn = prev.find('button.btn-dark');
            btn.text(parseInt(btn.text()) + 1);
            btn = e.find('button.btn-dark');
            btn.text(parseInt(btn.text()) - 1);
        }
    }
    
    shiftElementDown(e) {
        var next = e.next();
        if ( next.length > 0 ) {
            next.insertBefore(e);
            var btn = next.find('button.btn-dark');
            btn.text(parseInt(btn.text()) - 1);
            btn = e.find('button.btn-dark');
            btn.text(parseInt(btn.text()) + 1);
        }
    }
    
    gotoCrumb(e, storedValue, storedProps, storedTitle) {
        this.prePageChange();

        $('#modalLabel').text(storedTitle);
        this.currentValue = storedValue;
        this.props = storedProps;
        e.parent().nextAll().remove();
        e.parent().remove();

        if ( $('#modalBreadcrumb a').length === 0 ) {
            $('#modalBreadcrumb').parent().parent().css('display', 'none');
        }

        this.buildBody();
    }
    
    copyValuesIntoModel() {
        var inst = this;
        $('div.modal-body .dataHolder').each(function (indx, e) {
            e = $(e);
            inst.currentValue[e.attr('id')] = inst.propertyHandlers[e.data('type')].getPropertyValue(e);
        });
    }
    
    prePageChange() {
        this.copyValuesIntoModel();
    }
    
    buildBody() {
        try {
            var dlg = document.querySelector('#VMPropsModal');
            var dlgBody = dlg.querySelector('div.modal-body');
            $(dlgBody).empty();

            var hasDefaults = false;
            for (var name in this.props) {
                this.buildProperty(dlgBody, name, this.props[name]);
                hasDefaults = hasDefaults || typeof this.props[name].default !== 'undefined';
            }
            for (var name in this.currentValue) {
                if ( typeof this.props[name] !== 'undefined'  ) 
                    this.setPropertyValue(name, this.currentValue[name]);
            }
            
            $(dlgBody).append('<div id="validationMessagesCurrent" class="form-group"></div>')
                    .append('<div id="validationMessagesGlobal" class="form-group"></div>');

            if (!hasDefaults) {
                dlg.querySelector('#btn_defaults').style.display = 'none';
            } else {
                dlg.querySelector('#btn_defaults').style.display = null;
            }
        } catch (err) {
            console.log(err);
        }
    }
    
    gotoProperty(propertyName, listElement) {
        this.prePageChange();

        const jumpback = this.currentValue;
        const currentTitle = $('#modalLabel').text();
        const jumpbackProps = this.props;
        $('#modalBreadcrumb').append('<li class="breadcrumb-item"><a href="#">'+currentTitle+'</a></li>');
        $('#modalBreadcrumb'+' a').last().on('click.vmprops', function() {
            window.vmPropsHandler.gotoCrumb($(this), jumpback, jumpbackProps, currentTitle);
        });
        $('#modalBreadcrumb').parent().parent().css('display', '');

        //if its a list entry we add the index to the title
        if ( listElement !== undefined && listElement !== null ) {
            var childIndex; var e = $(listElement).closest('.input-group')[0];
            for ( childIndex = 0; (e = e.previousSibling); childIndex++ );
            $('#modalLabel').text(this.props[propertyName].label).append('<span class="badge badge-pill badge-dark">'+childIndex+'</span>');
        } else $('#modalLabel').text(this.props[propertyName].label);

        var e = $('#'+propertyName);
        if ( listElement === undefined || listElement === null )
            this.currentValue = this.propertyHandlers[e.data('type')].getPropertyValue(e);
        else this.currentValue = $(listElement).data('value');
        this.props = this.props[propertyName].props;

        this.buildBody();
    }
    
    listButtonsPrepend(e) {
        return '<div class="input-group-prepend mr-1">' +
            '<button type="button" class="btn btn-dark">' + e[0].childElementCount + '</button>' +
        '</div>';
    }
    
    listButtonsAppend(e) {
        return '<div class="input-group-append ml-1">' +
            '<button type="button" onclick="window.vmPropsHandler.shiftElementDown($(this).parent().parent());" class="btn btn-info">V</button>' +
            '<button type="button" onclick="window.vmPropsHandler.shiftElementUp($(this).parent().parent());" class="btn btn-info">A</button>' +
            (e.data('removable')?'<button type="button" onclick="$(this).parent().parent().remove();" class="btn btn-danger remover">-</button>':'') +
        '</div>';
    }
    
    parseLabel(template, value) {
        return template.replace(/\${([^}]*)}/g, (s,g)=> {
            var parts = g.split('.');
            var o = value;
            for( var part of parts ) {
              o = o[part];
            }
            return o;
        });
    }
    
    propertyHandlers = {
        text: {
            setPropertyValue: function (e, value) {
                e.val(value);
            },
            buildProperty: function (container, name, cfg) {
                $(container).append(
                        '<div class="form-group">' +
                        '<label for="' + name + '">' + window.vmPropsHandler.escapeHTML(cfg.label) + '</label>' +
                        '<input type="text" class="form-control dataHolder" id="' + name + '">' +
                        (typeof cfg.tooltip !== 'undefined' ? '<small class="form-text text-muted">' + window.vmPropsHandler.escapeHTML(cfg.tooltip) + '</small>' : '') +
                        '</div>');
            },
            getPropertyValue: function (e) {
                return e.val();
            },
            displayValidation: function (e, validation) {
                var insertAfter = e;
                for (const msg of validation.messages) {
                    insertAfter.after('<div class="' + (msg.isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + msg.message + '</div>');
                    insertAfter = insertAfter.next();
                }
                if (!validation.isValid)
                    e.addClass('is-invalid');
            }
        },
        number: {
            setPropertyValue: function (e, value) {
                e.val(window.vmPropsHandler.propertyHandlers.number.format(value));
            },
            buildProperty: function (container, name, cfg) {
                $(container).append(
                        '<div class="form-group">' +
                        '<label for="' + name + '">' + window.vmPropsHandler.escapeHTML(cfg.label) + '</label>' +
                        '<input type="number" class="form-control dataHolder" id="' + name + '">' +
                        (typeof cfg.tooltip !== 'undefined' ? '<small class="form-text text-muted">' + window.vmPropsHandler.escapeHTML(cfg.tooltip) + '</small>' : '') +
                        '</div>');
            },
            getPropertyValue: function (e) {
                return window.vmPropsHandler.propertyHandlers.number.parse(e.val());
            },
            displayValidation: function (e, validation) {
                var insertAfter = e;
                for (const msg of validation.messages) {
                    insertAfter.after('<div class="' + (msg.isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + msg.message + '</div>');
                    insertAfter = insertAfter.next();
                }
                if (!validation.isValid)
                    e.addClass('is-invalid');
            },
            format: function(value) {
                switch ( typeof value ) {
                    case 'number': return JSON.stringify(value);
                    case 'string': return value;
                }
                return '';
            },
            parse: function(value) {
                switch ( typeof value ) {
                    case 'number': return value;
                    case 'string': 
                        try {
                            var numberCandidate = JSON.parse(value);
                            if ( typeof numberCandidate === 'number' ) return numberCandidate;
                            else return null;
                        } catch (ex) {
                            return null;
                        }
                }
                return null;
            }
        },
        textarea: {
            setPropertyValue: function (e, value) {
                e.val(value);
            },
            buildProperty: function (container, name, cfg) {
                $(container).append(
                        '<div class="form-group">' +
                        '<label for="' + name + '">' + window.vmPropsHandler.escapeHTML(cfg.label) + '</label>' +
                        '<textarea class="form-control dataHolder" id="' + name + '"></textarea>' +
                        (typeof cfg.tooltip !== 'undefined' ? '<small class="form-text text-muted">' + window.vmPropsHandler.escapeHTML(cfg.tooltip) + '</small>' : '') +
                        '</div>');
            },
            getPropertyValue: function (e) {
                return e.val();
            },
            displayValidation: function (e, validation) {
                var insertAfter = e;
                for (const msg of validation.messages) {
                    insertAfter.after('<div class="' + (msg.isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + msg.message + '</div>');
                    insertAfter = insertAfter.next();
                }
                if (!validation.isValid)
                    e.addClass('is-invalid');
            }
        },
        select: {
            setPropertyValue: function (e, value) {
                e.val(value);
            },
            buildProperty: function (container, name, cfg) {
                $(container).append(
                        '<div class="form-group">' +
                        '<label for="' + name + '">' + window.vmPropsHandler.escapeHTML(cfg.label) + '</label>' +
                        '<select class="form-control dataHolder" id="' + name + '"></select>' +
                        (typeof cfg.tooltip !== 'undefined' ? '<small class="form-text text-muted">' + window.vmPropsHandler.escapeHTML(cfg.tooltip) + '</small>' : '') +
                        '</div>');
                var select = $(container).find('select');
                for (var indx in cfg.options) {
                    var option = cfg.options[indx];
                    $('<option></option>').text(option.label).val(option.value).data('value',option.value).appendTo(select);
                }
            },
            getPropertyValue: function (e) {
                return e.find('option:selected').data('value');
            },
            displayValidation: function (e, validation) {
                var insertAfter = e;
                for (const msg of validation.messages) {
                    insertAfter.after('<div class="' + (msg.isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + msg.message + '</div>');
                    insertAfter = insertAfter.next();
                }
                if (!validation.isValid)
                    e.addClass('is-invalid');
            }
        },
        checkbox: {
            setPropertyValue: function (e, value) {
                e.prop('checked', value === true);
            },
            buildProperty: function (container, name, cfg) {
                $(container).append(
                        '<div class="form-check">' +
                        '<input type="checkbox" class="form-check-input dataHolder" id="' + name + '">' +
                        '<label for="' + name + '" class="form-check-label">' + window.vmPropsHandler.escapeHTML(cfg.label) + '</label>' +
                        (typeof cfg.tooltip !== 'undefined' ? '<small class="form-text text-muted">' + window.vmPropsHandler.escapeHTML(cfg.tooltip) + '</small>' : '') +
                        '</div>');
            },
            getPropertyValue: function (e) {
                return e.is(':checked');
            },
            displayValidation: function (e, validation) {
                var insertAfter = e.next();
                for (const msg of validation.messages) {
                    insertAfter.after('<div class="' + (msg.isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + msg.message + '</div>');
                    insertAfter = insertAfter.next();
                }
                if (!validation.isValid)
                    e.addClass('is-invalid');
            }
        },
        list_text: {
            setPropertyValue: function (e, items) {
                e.find('div.input-group').remove();
                for (var indx in items) {
                    var item = items[indx];
                    window.vmPropsHandler.propertyHandlers.list_text.addNewItem(e, item);
                }
            },
            addNewItem: function (e, value) {
                if ( value === undefined ) {
                    var newEntry = e.data('newEntry');
                    if ( newEntry !== undefined ) {
                        if ( newEntry === null ) {
                            value = null;
                        } else {
                            value = JSON.parse(JSON.stringify(newEntry));
                        }
                    }
                }
                $('<div class="input-group">' + window.vmPropsHandler.listButtonsPrepend(e) +
                        '<input type="text" class="form-control">' + window.vmPropsHandler.listButtonsAppend(e) +
                        '</div>').appendTo(e).find('input').val(value);
            },
            buildProperty: function (container, name, cfg) {
                $(container).append(
                        '<div class="form-group">' +
                        '<label for="' + name + '">' + window.vmPropsHandler.escapeHTML(cfg.label) + '</label>' +
                        '<div class="dataHolder" id="' + name + '"></div>' +
                        (cfg.addable ? 
                            '<div class="input-group mt-1"><button type="button" class="form-control btn btn-info" onclick="window.vmPropsHandler.propertyHandlers.list_text.addNewItem($(\'#' + name + '\'));">+</button></div>'
                            : '' ) +
                        (typeof cfg.tooltip !== 'undefined' ? '<small class="form-text text-muted">' + window.vmPropsHandler.escapeHTML(cfg.tooltip) + '</small>' : '') +
                        '</div>');
                var dataHolder = $(container).find('#'+name);
                if ( cfg.addable ) {
                    dataHolder.data('addable',true);
                    dataHolder.data('newEntry',cfg.newEntry);
                }
                if ( cfg.removable ) {
                    dataHolder.data('removable',true);
                }
            },
            getPropertyValue: function (e) {
                var list = [];
                e.find('input.form-control').each(function (indx, e) {
                    list.push($(e).val());
                });
                return list;
            },
            displayValidation: function (e, validation) {
                if (!validation.isValid) {
                    e.addClass('is-invalid');

                    const entries = e.find('input.form-control');
                    for ( const msg of validation.messages ) {
                        if ( !msg.isValid ) {
                            if ( msg.listEntry !== undefined ) {
                                entries.eq(msg.listEntry).addClass('is-invalid');
                            } else {
                                entries.addClass('is-invalid');
                                break;
                            }
                        }
                    }
                    entries.filter(':not(.is-invalid)').addClass('is-valid');

                    e.parent().children('div.input-group').children('button').addClass('is-invalid');
                }
                var container = e.parent();
                for (const msg of validation.messages) {
                    container.append('<div class="' + (msg.isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + msg.message + '</div>');
                }
                container.append(container.children('small.form-text'));
            }
        },
        list_number: {
            setPropertyValue: function (e, items) {
                window.vmPropsHandler.propertyHandlers.list_text.setPropertyValue(e, items);
            },
            addNewItem: function (e, value) {
                if ( value === undefined ) {
                    var newEntry = e.data('newEntry');
                    if ( newEntry !== undefined ) {
                        if ( newEntry === null ) {
                            value = null;
                        } else {
                            value = JSON.parse(JSON.stringify(newEntry));
                        }
                    }
                }
                $('<div class="input-group">' + window.vmPropsHandler.listButtonsPrepend(e) +
                        '<input type="number" class="form-control">' + window.vmPropsHandler.listButtonsAppend(e) +
                        '</div>').appendTo(e).find('input').val(window.vmPropsHandler.propertyHandlers.number.format(value));
            },
            buildProperty: function (container, name, cfg) {
                $(container).append(
                        '<div class="form-group">' +
                        '<label for="' + name + '">' + window.vmPropsHandler.escapeHTML(cfg.label) + '</label>' +
                        '<div class="dataHolder" id="' + name + '"></div>' +
                        (cfg.addable ? 
                            '<div class="input-group mt-1"><button type="button" class="form-control btn btn-info" onclick="window.vmPropsHandler.propertyHandlers.list_number.addNewItem($(\'#' + name + '\'));">+</button></div>'
                            : '' ) +
                        (typeof cfg.tooltip !== 'undefined' ? '<small class="form-text text-muted">' + window.vmPropsHandler.escapeHTML(cfg.tooltip) + '</small>' : '') +
                        '</div>');
                var dataHolder = $(container).find('#'+name);
                if ( cfg.addable ) {
                    dataHolder.data('addable',true);
                    dataHolder.data('newEntry',cfg.newEntry);
                }
                if ( cfg.removable ) {
                    dataHolder.data('removable',true);
                }
            },
            getPropertyValue: function (e) {
                var list = [];
                e.find('input.form-control').each(function (indx, e) {
                    list.push(window.vmPropsHandler.propertyHandlers.number.parse($(e).val()));
                });
                return list;
            },
            displayValidation: function (e, validation) {
                window.vmPropsHandler.propertyHandlers.list_text.displayValidation(e, validation);
            }
        },
        object: {
            setPropertyValue: function (e, value) {
                if ( value === undefined ) value = null;
                e.data('value',value);
                if ( value === null ) {
                    e.off('click.vmprops');
                    var newEntry = e.data('newEntry');
                    if ( e.data('addable') && newEntry !== undefined && newEntry !== null ) {
                        e.text('New');
                        e.on('click.vmprops',function() {
                            var newEntry = e.data('newEntry');
                            if ( newEntry !== undefined && newEntry !== null ) {
                                window.vmPropsHandler.propertyHandlers.object.setPropertyValue(e,JSON.parse(JSON.stringify(e.data('newEntry'))));
                                window.vmPropsHandler.gotoProperty(e.attr('id'));
                            }
                        });
                    } else {
                        e.text('No Value');
                    }
                } else {
                    e.text('Edit');
                }
            },
            buildProperty: function (container, name, cfg) {
                //ability to spawn a copy of the new entry and to remove the current value
                $(container).append(
                    '<div class="form-group">' +
                    '<label for="' + name + '">' + window.vmPropsHandler.escapeHTML(cfg.label) + '</label>' +
                    '<div class="input-group">' +
                    '<button type="button" class="form-control dataHolder btn btn-secondary" id="' + name + '">Edit</button>' +
                    (cfg.removable?
                        '<div class="input-group-append ml-1"><button type="button" class="btn btn-danger" onclick="window.vmPropsHandler.propertyHandlers.object.setPropertyValue($(this).parent().prev(),null)">-</button></div>'
                        :'') +
                    '</div>' +
                    (typeof cfg.tooltip !== 'undefined' ? '<small class="form-text text-muted">' + window.vmPropsHandler.escapeHTML(cfg.tooltip) + '</small>' : '') +
                    '</div>').find('#'+name).data('addable',cfg.addable).data('removable',cfg.removable).data('newEntry',cfg.newEntry).on('click.vmprops',function() { window.vmPropsHandler.gotoProperty(name); });
            },
            getPropertyValue: function (e) {
                return e.data('value');
            },
            displayValidation: function (e, validation) {
                var insertAfter = e.closest('.form-group').children().last();
                for (const msg of validation.messages) {
                    insertAfter.after('<div class="' + (msg.isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + msg.message + '</div>');
                    insertAfter = insertAfter.next();
                }
                if (!validation.isValid)
                    e.addClass('is-invalid');
            }
        },
        list_object: {
            setPropertyValue: function (e, items) {
                e.find('div.input-group').remove();
                for (var indx in items) {
                    var item = items[indx];
                    window.vmPropsHandler.propertyHandlers.list_object.addNewItem(e, item);
                }
            },
            addNewItem: function (e, value) {
                if ( value === undefined ) {
                    var newEntry = e.data('newEntry');
                    if ( newEntry !== undefined ) {
                        if ( newEntry === null ) {
                            value = null;
                        } else {
                            value = JSON.parse(JSON.stringify(newEntry));
                        }
                    }
                }
                $('<div class="input-group">' + window.vmPropsHandler.listButtonsPrepend(e) +
                        '<button type="button" class="form-control btn btn-secondary">' + window.vmPropsHandler.parseLabel(e.data('labelEntry'),value) + '</button>' + window.vmPropsHandler.listButtonsAppend(e) +
                        '</div>').appendTo(e).find('button.form-control').first().data('value',value).on('click.vmprops',function() { window.vmPropsHandler.gotoProperty(e.attr('id'),this); });
            },
            buildProperty: function (container, name, cfg) {
                $(container).append(
                        '<div class="form-group">' +
                        '<label for="' + name + '">' + window.vmPropsHandler.escapeHTML(cfg.label) + '</label>' +
                        '<div class="dataHolder" id="' + name + '"></div>' +
                        (cfg.addable ? 
                            '<div class="input-group mt-1"><button type="button" class="form-control btn btn-info" onclick="window.vmPropsHandler.propertyHandlers.list_object.addNewItem($(\'#' + name + '\'));">+</button></div>' 
                            : '' )+
                        (typeof cfg.tooltip !== 'undefined' ? '<small class="form-text text-muted">' + window.vmPropsHandler.escapeHTML(cfg.tooltip) + '</small>' : '') +
                        '</div>');
                var dataHolder = $(container).find('#'+name);
                if ( cfg.addable ) {
                    dataHolder.data('addable',true);
                    window.vmPropsHandler.addImpliedDefaultValues(cfg.newEntry, cfg);
                    dataHolder.data('newEntry',cfg.newEntry);
                }
                if ( cfg.labelEntry !== undefined && cfg.labelEntry !== null ) {
                    dataHolder.data('labelEntry',cfg.labelEntry);
                } else dataHolder.data('labelEntry','Edit');
                if ( cfg.removable ) {
                    dataHolder.data('removable',true);
                }
            },
            getPropertyValue: function (e) {
                var list = [];
                e.find('button.form-control').each(function (indx, e) {
                    list.push($(e).data('value'));
                });
                return list;
            },
            displayValidation: function (e, validation) {
                if (!validation.isValid) {
                    e.addClass('is-invalid');

                    const entries = e.find('button.form-control');
                    for ( const msg of validation.messages ) {
                        if ( !msg.isValid ) {
                            if ( msg.listEntry !== undefined ) {
                                entries.eq(msg.listEntry).addClass('is-invalid');
                            } else {
                                entries.addClass('is-invalid');
                                break;
                            }
                        }
                    }
                    entries.filter(':not(.is-invalid)').addClass('is-valid');

                    e.parent().children('div.input-group').children('button').addClass('is-invalid');
                }
                var container = e.parent();
                for (const msg of validation.messages) {
                    container.append('<div class="' + (msg.isValid ? 'valid-feedback' : 'invalid-feedback') + '">' + msg.message + '</div>');
                }
                container.append(container.children('small.form-text'));
            }
        }
    }
}

//export to html script entry.
window.onload = function () {
    var targetWindow = null;
    if (window.opener !== null)
        targetWindow = window.opener;
    else if (window.parent !== null)
        targetWindow = window.parent;

    if (targetWindow !== null) {
        new Handler(targetWindow);
    }
};
