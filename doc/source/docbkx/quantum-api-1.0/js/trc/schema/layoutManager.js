/**
   layoutManager.js

   (C) 2009 Rackspace Hosting, All Rights Reserved

   This file contains code that adjusts the layout of a schema
   document after a dom has been loaded.  It does not modify the
   global scope.
**/

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
     //  This function should be called when the DOM is loaded so we
     //  can get to work adjusting things.
     //
     function InitLayoutManager()
     {
         layoutManager._init();
     }
     trc.util.browser.addInitFunction (InitLayoutManager);

     var layoutManager={
         //
         //  Initialization function...
         //
         _init : function()
         {
             this._adjustMain();
             this._adjustSubElements();
         },

         //
         //  Applies appropriate styles to body and other main content
         //  tags.
         //
         _adjustMain : function()
         {
             //
             //  Change the class name for the correct YUI skin name.
             //
             var bodyTags = document.getElementsByTagName("body");
             if (bodyTags.length == 0)
             {
                 throw new Error ("Couldn't find body element, bad DOM?");
             }
             else
             {
                 trc.util.dom.setClassName(bodyTags[0], "yui-skin-sam");
             }

             //
             //  Setout the layout...
             //
             var docDiv  = document.getElementById("doc");
             var mainDiv = document.getElementById("Main");

             trc.util.dom.setClassName (docDiv, "yui-t1");
             docDiv.setAttribute ("id", "doc3");
             mainDiv.setAttribute ("id", "yui-main");

             //
             //  Old IE browser hacks...
             //
             switch (trc.util.browser.detectIEVersion())
             {
                 //
                 // IE 6 does not support fixed positioning.  The
                 // following is a little hack to get it to work.
                 //
                 //
                case 6:
                 var controllerDiv = document.getElementById("Controller");
                 controllerDiv.style.position="absolute";
                 window.setInterval((function(){
                     /* avoid leak by constantly querying for the
                      * controller. */
                     var ctrlDiv = document.getElementById("Controller");
                     ctrlDiv.style.top = document.documentElement.scrollTop+10;
                 }), 1000);
                 break;

                 //
                 // The controler doesn't work **at all** in IE 7
                 // don't even show it.
                 //
                case 7:
                 var controllerDiv = document.getElementById("Controller");
                 controllerDiv.style.display = "none";
                 break;
             }
         },

         //
         //  Adds appropriate classes for subElements...
         //
         _adjustSubElements : function()
         {
             var divs = document.getElementsByTagName("div");
             for (var i=0;i<divs.length;i++)
             {
                 var currentClass = divs[i].getAttribute ("class");
                 var newClassName = currentClass;
                 switch (currentClass)
                 {
                 case "SubItem" :
                     newClassName += " yui-gd";
                     break;
                 case "SubItemProps" :
                     newClassName += " yui-gd first";
                     break;
                 case "SubName" :
                     newClassName += " yui-u first";
                     break;
                 case "SubAttributes" :
                 case "SubDocumentation" :
                     newClassName += " yui-u";
                     break;
                 }
                 if (currentClass != newClassName)
                 {
                     trc.util.dom.setClassName (divs[i], newClassName);
                 }
             }
         }
     };
 })();
