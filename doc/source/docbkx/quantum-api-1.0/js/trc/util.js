/**
  util.js:

  (C) 2009 Rackspace Hosting, All Rights Reserved

  This file defines a single object in global scope:

  trc.util

  The util object contains internal objects which contain useful
  utility properties and methods.

  trc.util.browser: contains methods for browser detection.

  trc.util.dom: contains methods for manipulating the DOM.

  trc.util.text: contains methods and properties useful when working
  with plain text.

  trc.util.net: contains methods for creating HTTP requests.

  trc.util.yui : contains methods for working with the YUI toolkit.

  All methods/properties prepended with an underscore (_) are meant
  for internal use.
**/

//
// Define TRC
//
if (!window.trc)
{
    trc= new Object();
}
trc.util = new Object();
trc.util.browser = {
    //
    // Returns the current version of IE, or -1 if it's not an IE
    // browser. This is one of the recommended ways of detecting IE
    // see:
    //
    // http://msdn.microsoft.com/en-us/library/ms537509%28VS.85%29.aspx
    //
    detectIEVersion : function() {
        var rv = -1; // Return value assumes failure.
        if (navigator.appName == 'Microsoft Internet Explorer')
        {
            var ua = navigator.userAgent;
            var re  = new RegExp("MSIE ([0-9]{1,}[\.0-9]{0,})");
            if (re.exec(ua) != null)
                rv = parseFloat( RegExp.$1 );
        }
        return rv;
    },

    //
    //  A list of functions to execute on init.
    //
    _initFuns  : new Array(),

    //
    //  Has the init function event been set?
    //
    _initFunSet: false,

    //
    //  Function called when the DOM has loaded. It launches all init
    //  functions.
    //
    _onInit : function()
    {
        //
        // Sort by order...
        //
        this._initFuns.sort(function(a, b){ return a.order - b.order; });
        for (var i=0;i<this._initFuns.length;i++)
            {
                this._initFuns[i]();
            }
    },

    //
    // Adds a function that should be executed when the dom is
    // loaded.
    //
    addInitFunction : function(init, /*Function to call after dom
                                         * is loaded*/

                               order /* An optional it specifing
                                      * order.  The bigger the int the
                                      * later it will run. Default is
                                      * 1.*/
                              ) {
        if (arguments.length < 2)
        {
            init.order = 1;
        }
        else
        {
            init.order = order;
        }
        this._initFuns.push (init);

        if (!this._initFunSet)
        {
            var butil = this;
            function initFun()
            {
                return (function(){ butil._onInit(); });
            }

            //
            // Try event listeners, attachEvent and if that fails use
            // window.onload...
            //
            if (window.addEventListener)
            {
                window.addEventListener("load", initFun(), false);
            } else if (window.attachEvent)
            {
                window.attachEvent ("onload", initFun());
            } else
            {
                window.onload = initFun();
            }

            this._initFunSet = true;
        }
    }
};

trc.util.dom = {
    //
    //  Adds a new script tag to the current DOM.
    //
    addScript : function (src /* Script href */)
    {
        var scriptElement = document.createElement ("script");
        scriptElement.setAttribute ("type", "text/javascript");
        scriptElement.setAttribute ("src", src);

        this.addToHead (scriptElement);
    },

    //
    //  Adds a new stylesheet to the current DOM.
    //
    addStyle : function (src /* Stylesheet href */)
    {
        var linkElement = document.createElement ("link");
        linkElement.setAttribute ("rel", "stylesheet");
        linkElement.setAttribute ("type", "text/css");
        linkElement.setAttribute ("href", src);

        this.addToHead (linkElement);
    },

    //
    //  Adds a DOM node to the HTTP head element. The element is
    //  always added as the last child an error is thrown if the
    //  head element can't be found.
    //
    addToHead : function (node /* A DOM node */)
    {
        var headArray = document.getElementsByTagName("head");
        if (headArray.length == 0)
        {
            throw new Error("Couldn't find head element, bad DOM?");
        }
        else
        {
            headArray[0].appendChild (node);
        }
    },

    //
    // Dumb utility function for setting the class name of an
    // element.  Eventually we'll move completely to XHTML, but
    // this will never work in IE 6, so for now we need this
    // method for setting the class name.
    //
    setClassName : function (element, /* DOM Element*/
                             name /* Class name to use */
                            )
    {
        var ieVersion = trc.util.browser.detectIEVersion();

        if ((ieVersion > -1) &&
            (ieVersion < 7))
        {
            element.className = name;
        }
        else
        {
            element.setAttribute ("class",name);
        }
    }
};

trc.util.text = {
    //
    // Useful RegExps
    //
    blank     : new RegExp ("^\\s*$"), /* A blank string */
    indent    : new RegExp ("^\\s+"),  /* Line indent */
    lines     : new RegExp ("$","m"),  /* All lines */
    linechars : new RegExp ("(\n|\r)"), /* EOL line characters */
    tabs      : new RegExp ("\t","g"),  /* All tabs */

    //
    // We need this because microsoft browsers before IE 7, connot
    // display pre-formatted text correctly win unix style line
    // endings.
    //
    unix2dos : function(txt /* String */) {
        //if already DOS...
        if (txt.search(/\r\n/) != -1)
        {
            return txt;
        }
        return txt.replace (/\n/g, "\r\n");
    },

    //
    // Useful to normalize text.
    //
    dos2unix : function(txt /* String */) {
        //if already unix...
        if (txt.search(/\r\n/) == -1)
        {
            return txt;
        }

        return txt.replace(/\r/g, "");
    },

    //
    //  Create a string with a character repeated x times.
    //
    repString : function (length,  /* integer, size of the string to create */
                          ch       /* string, The character to set the string to */
                         )
    {
        var ret = new String();
        for (var i=0;i<length;i++) {ret=ret.concat(ch);}

        return ret;
    },

    //
    //  Replace tabs in a text with strings.
    //
    replaceTabs : function (txt, /* String to modify */
                            length /* integer, tab length in spaces */
                           )
    {
        var tabs = this.repString(length, " ");
        return txt.replace (this.tabs, tabs);
    },

    //
    //  Given multi-line text returns Adjust top and bottom indent
    //  (in lines) and right indent (in spaces)
    //
    setIndent : function (txt,    /* String */
                          top,    /* integer, top indent in lines */
                          bottom, /* integer, bottom indent in lines */
                          right   /* integer, right indent in spaces */
                         )
    {
        //
        //  Can't indent an empty string..
        //
        if (txt.length == 0)
        {
            return txt;
        }

        //
        // If not 0, bottom will be off by one...
        //
        if (bottom != 0)
        {
            bottom++;
        }

        var head=this.repString (top, "\n");
        var tail=this.repString (bottom, "\n");
        var marg=this.repString (right, " ");
        var ntxt  = this.dos2unix(txt);
        var ntxt  = this.replaceTabs (ntxt, 8);
        var lines = ntxt.split (this.lines);
        var origIndent=Number.MAX_VALUE;
        var origIndentStr;

        //
        // Look up indent.
        //
        for (var i=0;i<lines.length;i++)
        {
            //
            //  Remove EOL characters...
            //
            lines[i] = lines[i].replace (this.linechars, "");

            //
            // Ignore blank lines
            //
            if (lines[i].match(this.blank) != null)
            {
                continue;
            }

            //
            // Detect the indent if any...
            //
            var result = lines[i].match(this.indent);
            if (result == null)
            {
                origIndent = 0;
                origIndentStr = "";
            }
            else if (result[0].length < origIndent)
            {
                origIndent = result[0].length;
                origIndentStr = result[0];
            }
        }

        //
        //  This implys all line are blank...can't indent.
        //
        if (origIndent == Number.MAX_VALUE)
        {
            return txt;
        }

        if (origIndent != 0)
        {
            var regExStr = "^";
            for (var i=0;i<origIndent;i++)
            {
                regExStr=regExStr.concat("\\s");
            }
            var indent = new RegExp(regExStr);
            for (var i=0;i<lines.length;i++)
            {
                lines[i] = lines[i].replace(indent,marg);
            }
        }
        else
        {
            for (var i=0;i<lines.length;i++)
            {
                lines[i] = marg.concat (lines[i]);
            }
        }

        //
        //  Remove top...
        //
        while (lines.length != 0)
        {
            if (lines[0].match(this.blank))
            {
                lines.shift();
            }
            else
            {
                break;
            }
        }

        //
        //  Remove bottom...
        //
        while (lines.length != 0)
        {
            if (lines[lines.length-1].match(this.blank))
            {
                lines.pop();
            }
            else
            {
                break;
            }
        }

        var indented = lines.join("\n");
        indented=head.concat(indented, tail);

        return indented;
    }
};

trc.util.net = {
    //
    // A list of possible factories for creating an XMLHTTPRequest
    //
    _HTTPReqFactories :
    [
        function() { return new XMLHttpRequest(); },
        function() { return new ActiveXObject("Msxml2.XMLHTTP"); },
        function() { return new ActiveXObject("Microsoft.XMLHTTP"); }
    ],

    //
    // A cached XMLHTTPRequest factory that we know works in this
    // browser
    //
    _HTTPReqFactory : null,

    //
    // Provides a way of getting an HTTPRequest object in a
    // platform independent manner
    //
    getHTTPRequest : function()
    {
        //
        //  Use cache if available..
        //
        if (this._HTTPReqFactory != null) return this._HTTPReqFactory();

        //
        //  Search for a factory..
        //
        for (var i=0; i< this._HTTPReqFactories.length; i++)
        {
            try {
                var factory = this._HTTPReqFactories[i];
                var request = factory();
                if (request != null)
                {
                    this._HTTPReqFactory = factory;
                    return request;
                }
            } catch (e) {
                continue;
            }
        }

        //
        //  Looks like we don't have support for XMLHttpRequest...
        //
        this._HTTPReqFactory = function() {throw new Error("XMLHttpRequest not supported");}
        this._HTTPReqFactory();
        return;
    }
};


//
// Init code for trc.util.yui...
//
(function()
 {
     //
     //  Menu make sure we have the YUI loader as it's used by our
     //  init function to load YUI components.
     //
     if (!window.YAHOO)
     {
         //
         //  We are currently using YUI on YAHOO!'s servers we may
         //  want to change this.
         //
         var YUI_BASE="http://yui.yahooapis.com/2.7.0/";

         trc.util.dom.addScript (YUI_BASE+"build/yuiloader/yuiloader-min.js");
     }

     function InitYUIUtil()
     {
         trc.util.yui._init();
     }
     trc.util.browser.addInitFunction (InitYUIUtil);
 })();

trc.util.yui = {
    //
    // A list of dependecies to be passed to the YUI loader.  This is
    // essentially a hash set: dep->dep.
    //
    _deps : new Object(),

    //
    // An array of callback functions, these should be called when all
    // dependecies are loaded.
    //
    _callbacks : new Array(),

    //
    // The init function simply calls the YUI loader...
    //
    _init : function() {
        var yuiUtil = this;

        //
        // It takes safari a while to load the YUI Loader if it hasn't
        // loaded yet keep trying at 1/4 second intervals
        //
        if (!window.YAHOO)
        {
            window.setTimeout (function() {
                yuiUtil._init();
            }, 250);
            return;
        }

        //
        // Collect requirements...
        //
        var required = new Array();
        for (var req in this._deps)
        {
            required.push (req);
        }

        //
        // Load YUI dependecies...
        //
	var loader = new YAHOO.util.YUILoader({
	    require: required,
	    loadOptional: true,
            filter: "RAW",
	    onSuccess: function() {
                yuiUtil._depsLoaded();
	    },
	    timeout: 10000,
	    combine: true
	});
	loader.insert();
    },

    //
    // Called after all dependecies have been loaded
    //
    _depsLoaded : function() {
        //
        //  Dependecies are loaded let everyone know.
        //
        for (var i=0;i<this._callbacks.length;i++)
        {
            this._callbacks[i]();
        }
    },

    //
    //  Request that one or more YUI dependecies are loaded.
    //
    loadYUIDeps : function (deps,     /*An array of dep strings */
                            callback  /*A function to call when deps are loaded*/
                           )
    {
        for (var i=0;i<deps.length;i++)
        {
            this._deps[deps[i]] = deps[i];
        }
        if (callback != null)
        {
            this._callbacks.push (callback);
        }
    }
};
