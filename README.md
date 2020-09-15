# vmms

## VM Props

A configuration dialog that displays itself in an iframe to isolate itself from the calling pages scope. It encrypts communcation between the window and the iframe to further safeguard the user. The configuration dialog can present simple data structures with tooltips, default values and validation. For its look and feel it uses Bootstrap 4.x.

It uses GM_\* instructions to automatically save the values. The required grants are GM_setValue, GM_getValue and GM_registerMenuCommand. GM_getMetadata is optional, if no storageKey is specified it will be used to resolve the user scripts name to compute a storageKey.

To gurantee the safety of the script it must be *injected-into* the *content* scope. By creating a VMProps object the dialog can be registered and no further interaction with the instance is required.

### Value Cache

The VMProps object can be used to manage the values through get, set and save methods. Getting and setting a value is done through a cache and changes are only persistet if explicitly saved. All values are saved as a single cleartext JSON object in the monkey database.

- get(propertyName) : Returns the cached value for the given property name. If the property has not been saved before it is initialized with it's default value and if no default is defined it's null.
- set(propertyName, value) : Assigns a value to the cache. The change is not persisted.
- resetValue() : Does set all properties to their default value if one is defined. The change is not persisted.
- resetValue(propertyName) : Does set the value for the given property name to it's default if defined. The change is not persisted.
- save(values, validations) : Persist the currently cached values as a JSON object into the monkey database. The validations parameter should be an empty object `{}` that on return will contain all validation results in the form of `{ isValid: [true/false], messages: ['msg1','msg2',...] }` for each registered validator. The return value is true if all validations were valid. Only if the message returns true has the data been persisted. The onSave callback will be invoked if the data was persisted.

### Example script

```
// ==UserScript==
// @name Configuration Demo
// @namespace Violentmonkey Scripts
// @require https://razuhl.github.io/vmms/vmprops.js
// @match http*://*/*
// @grant GM_setValue
// @grant GM_getValue
// @grant GM_registerMenuCommand
// @grant GM_getMetadata
// @inject-into content
// ==/UserScript==

var cfg = new VMProps({
	//default title is Configure
	title: 'My Settings',
	//default storageKey is "_VMProps_storage_" plus all ASCII letters and numbers from the script name. If GM_getMetadata is not allowed its "_VMProps_storage_Unknown".
	storageKey: 'ConfigurationDemo',
	//xl, l, s => bootstrap styles: modal-xl, modal-lg, modal-sm
	dlgSize: 'l',
	//registers the menu action for monkey calling "[VMProps].open();"
	menuCommand: true,
	//a map of available settings
	props: {
		//variable name
		textAreaVariable: {
			//type can be 'textarea', 'text', 'checkbox', 'select', 'list_text'
			type: 'textarea',
			label: 'Multiline Text',
			//default values that the user can reset to.
			default: 'Some kind dof drawn out inconclusive rambling with fairly underwhelming impact on anything in the realm of existince or for that matter beyond it.',
			tooltip: 'You can type multiline content here.'
		},
		textVariable: {
			type: 'text',
			label: 'Text',
			default: '',
			tooltip: 'Single line'
		},
		booleanVariable: {
			type: 'checkbox',
			label: 'A Checkbox',
			default: true,
			tooltip: 'True or False flag.'
		},
		selectVariable: {
			type: 'select',
			label: 'Pick one',
			default: 3,
			options: [{label:'One',value:1},{label:'Two',value:2},{label:'Three',value:3}],
			tooltip: 'A label/value list that the user can choose from.'
		},
		listTextVariable: {
			type: 'list_text',
			label: 'Text List',
			default: ['first line','second line','third line'],
			tooltip: 'Variable length list of single independant lines.'
		}
	},
	//validation references the properties by their variable name and must conclude by returning true before values can be saved.
	validators: {
		//The validation function gets the new value as first argument and a list of string messages to display for the variable as second argument. It must return a boolean result.
		//Messages can be displayed whether the validation is true or false.
		textAreaVariable: function(value, messages) { if ( value === 'ok' ) return true; messages.push('must  be ok'); return false; },
		booleanVariable: function(value, messages) { if ( value ) return true; messages.push('must be true'); return false; },
		listTextVariable: function(value, messages) { if ( value.length == 2 ) return true; messages.push('must be two'); return false; }
	},
	//callback that can be used to react to value changes
	onSave: function(values) { console.log(JSON.stringify(values)); }
});

//access to values can be done through the VMProps object.
console.log(cfg.get('text'));
cfg.set('text','override');
console.log(cfg.save({}));
```

### NoScript

If NoScript is in use an exemption for "razuhl.github.io" must be made. All dependencies are hosted through GitHub Pages which allows users to whitelist exactly one users content and won't grant libraries like jQuery to other pages by using a common cdn link.

### Hosting

Installing the files on a host requires changing the css and js dependencies in the file "vmprops.html". The script can either be configured when initialized or the default values for dialogOrigin, prohibitedHosts and dialogSrc can be edited to accommodate the new host.

- **dialogOrigin** The exact spelling of the origin reported by messages from "vmprops.html". The origin can be inspected by registering a listener before trying to open the dialog "window.addEventListener('message', function(e){console.log(e);});".

- **prohibitedHosts**: This is an array of regular expressions that if any matches the calling pages "document.domain" property will prohibit opening of the dialog. This is done to prevent the invalidation of cross site access safeguards which protect the dialogs scripting data. At least one of the reg expressions should match the dialogs host. By default anything on github is prohibited.

- **dialogSrc**: This is the URL for the file "vmprops.html".
