/**
   schemaManager.js:

   (C) 2009 Rackspace Hosting, All Rights Reserved

   This file defines a single object in global scope:

   trc.schema.sampleManager

   The object is responsible for loading, formatting, and displaying
   samples in schema files. It expects trc.util to be defined which is
   provided in trc/util.js.

   Code highlighting is provided by SHJS
   (http://shjs.sourceforge.net/). It should also be loaded before
   this code is initialized.

   All methods/properties prepended with an underscore (_) are meant
   for internal use.
 **/

//
// Initialization code...
//
(function()
 {
     //
     // Make sure dependecies are defined in the global scope, throw
     // an error if they are not.
     //
     if ((!window.trc) ||
         (!trc.util))
     {
         throw new Error("Require trc/util.js to be loaded.");
     }

     //
     // Make sure syntax highlighter scripts are loaded, if not then
     // load them.
     //
     if (!window.sh_highlightDocument)
     {
         trc.util.dom.addStyle  ("../style/shjs/sh_darkblue.css");

         trc.util.dom.addScript ("../js/shjs/sh_main.js");
         trc.util.dom.addScript ("../js/shjs/sh_xml.js");
         trc.util.dom.addScript ("../js/shjs/sh_javascript.js");
         trc.util.dom.addScript ("../js/shjs/sh_java.js");
     }

     function InitSchemaSampleManager()
     {
         trc.schema.sampleManager._init();
     }

     trc.util.browser.addInitFunction(InitSchemaSampleManager);
 })();

//
//  Define trc.schema.sampleManager...
//
if (!trc.schema)
{
    trc.schema = new Object();
}
trc.schema.sampleManager = {
    //
    // All sample data in an associative array:
    //
    // Select Element ID -> Array of sample ids.
    //
    samples : new Object(),

    //
    // An array of code data..
    //
    // Code data is defined as an object with the following
    // properties:
    //
    // type: The mimetype of the code...href: The location of the code
    // or null if it's inline
    //
    // id: The id of the pre that contains the code.
    //
    // The initial object is the source code for the current document.
    //
    codes : new Array({
        id   : "SrcContentCode",
        type : "application/xml",
        href : (function() {
            var ret = location.href;
            if (location.hash && (location.hash.length != 0))
            {
                ret = ret.replace (location.hash, "");
            }
            return ret;
        })()
    }),

    //
    // Sets up the manager, begins the loading process...
    //
    _init : function() {
        //
        // Setup an array to hold data items to load, this is used by
        // the loadSample method.
        //
        this._toLoad = new Array();

        for (var i=0;i<this.codes.length;i++)
        {
            if ((this.codes[i] != null) &&
                (this.codes[i].href != null))
            {
                this._toLoad.push (this.codes[i]);
            }
        }

        //
        //  Loads the code text
        //
        this._loadCode();
    },

    //
    //  Loads the next sample in the toLoad array.
    //
    _loadCode : function() {
        if (this._toLoad.length == 0)
        {
            //
            //  All samples have been loaded, fire the loadComplete
            //  method.
            //
            this._loadComplete();
            return;
        }

        var codeData = this._toLoad.pop();
        var request = trc.util.net.getHTTPRequest();
        var manager = this;

        request.onreadystatechange = function() {
            if (request.readyState == 4 /* Ready */) {
                if (request.status == 200 /* OKAY */) {
                    manager._setCodeText (codeData, request.responseText);
                }
                else
                {
                    manager._setCodeText (codeData, "Could not load sample ("+request.status+") "+request.responseText);
                }
                manager._loadCode();
            }
        };

        request.open ("GET", codeData.href);
        request.send(null);
    },

    //
    // Called after all samples are loaded into the DOM.
    //
    _loadComplete : function()
    {
        //
        //  Normalize all code samples..
        //
        this._normalizeCodeText(1, 1, 5);

        //
        //  Perform syntax highlighting...
        //
        sh_highlightDocument();

        //
        //  All samples are initially hidden, show the selected
        //  samples...
        //
        for (var optionID in this.samples)
        {
            this.showSample(optionID);
        }

        //
        //  We've adjusted the document, we need to setup the view so
        //  that we're still pointing to the hash target.
        //
        if (window.location.hash &&
            (window.location.hash.length != 0))
        {
            window.location.href = window.location.hash;
        }
    },

    //
    //  Sets code text replacing any text already existing there.
    //
    _setCodeText : function ( codeData /* Info of the code to set (code object) */,
                              code     /* Code text to set (string) */)
    {
        //
        // Preprocess the txt if nessesary...
        //
        var ieVersion = trc.util.browser.detectIEVersion();
        if ((ieVersion > -1) &&
            (ieVersion < 8))
        {
            code = trc.util.text.unix2dos (code);
        }

        var pre      = document.getElementById(codeData.id);
        var preNodes = pre.childNodes;
        //
        // Remove placeholder data...
        //
        while (preNodes.length != 0)
        {
            pre.removeChild (preNodes[0]);
        }

        //
        // Set the correct class type...
        //
        switch (codeData.type)
        {
        /*
           Javascript mimetypes
         */
        case 'application/json':
        case 'application/javascript':
        case 'application/x-javascript':
        case 'application/ecmascript':
        case 'text/ecmascript':
        case 'text/javascript':
            trc.util.dom.setClassName (pre, "sh_javascript");
            break;
        /*
          Not real mimetypes but this is what we'll use for Java.
        */
        case 'application/java':
        case 'text/java':
            trc.util.dom.setClassName (pre, "sh_java");
            break;
        default:
            trc.util.dom.setClassName (pre, "sh_xml");
            break;
        }

        //
        // Add new code...
        //
        pre.appendChild (document.createTextNode (code));
    },

    //
    // Retrives source code text
    //
    _getCodeText : function (codeData /* Info for the code to get*/)
    {
        var pre = document.getElementById(codeData.id);
        pre.normalize();
        //
        //  Should be a single text node after pre...
        //
        return pre.firstChild.nodeValue;
    },


    //
    // Normalizes text by ensuring that top, bottom, right indent
    // levels are equal for all samples.
    //
    _normalizeCodeText : function (top,    /* integer, top indent in lines */
                                   bottom, /* integer, bottom indent in lines */
                                   right   /* integer, right indent in spaces */
                                  )
    {
        for (var i=0;i<this.codes.length;i++)
        {
            if (this.codes[i] != null)
            {
                var code  = this._getCodeText (this.codes[i]);
                code = trc.util.text.setIndent (code, top, bottom, right);
                this._setCodeText (this.codes[i], code);
            }
        }
    },

    //
    // This event handler shows the appropriate sample given an ID
    // to the select element.
    //
    showSample : function (selectID)  /* ID of the Select element */
    {
        //
        // Get the selected value
        //
        var selected = document.getElementById(selectID);
        var selectedValue = selected.options[selected.selectedIndex].value;
        var samples = this.samples[selectID];

        //
        // Undisplay old samples, display selected ones.
        //
        for (var i=0;i<samples.length;i++)
        {
            if (samples[i] != null)
            {
                var sample = document.getElementById (samples[i]);
                if (samples[i] == selectedValue)
                {
                    sample.style.display = "block";
                }
                else
                {
                    sample.style.display = "none";
                }
            }
        }
    },

    //
    // Toggles the current source view. If the source is displayed it
    // undisplays it and vice versa.
    //
    toggleSrcView : function()
    {
        var content = document.getElementById ("Content");
        var src     = document.getElementById ("SrcContent");

        if (content.style.display != "none")
        {
            content.style.display = "none";
            src.style.display = "block";
        }
        else
        {
            content.style.display = "block";
            src.style.display = "none";
        }
    }
};
