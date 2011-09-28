/**
   controller.js

   (C) 2009 Rackspace Hosting, All Rights Reserved

   This file definas a single object in global scope:

   trc.schema.controller

   The controller object is responsible for displaying a menu that
   allows users to view schema source and jump to various definitions
   in the schema.
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
     //  We use YUI to build our controller menu make sure we have the
     //  proper dependecies loaded, call init when we do...
     //

     function InitController()
     {
         trc.schema.controller._init();
     }

     trc.util.yui.loadYUIDeps (["menu"], InitController);
 })();


if (!trc.schema)
{
    trc.schema = new Object();
}

trc.schema.controller = {
    //
    // Internal and external links by type:
    //
    // type --> array of links
    //
    // possible types include: import, include, element,
    //                         attribute, complextype, simpleType
    //
    // each link contains the following properties:
    //            name  : the name of the link
    //            href  : the link itself
    //            title : a description of the link
    links : new Object(),

    //
    //  A single link that points to the schema index document.
    //
    index : null,

    //
    // Our initialization function
    //
    _init : function() {
        //
        // Load the menu...
        //
        var controllerDiv = document.getElementById("Controller");
        var mainMenu = this._menuMarkup("mainmenu");

        for (var linkType in this.links)
        {
            var subItem = this._menuItemMarkup(mainMenu, linkType, "#", null);
            var subMenu = this._menuMarkup (linkType+"_subMenu");

            var items = this.links[linkType];
            for (var i=0;i<items.length;i++)
            {
                this._menuItemMarkup (subMenu,
                                      items[i].name,
                                      items[i].href,
                                      items[i].title);
            }
            subItem.item.appendChild (subMenu.main);
        }

        //
        //  Toggle view source menu
        //
        this._menuItemMarkup (mainMenu, "toggle src view",
                              "javascript:trc.schema.sampleManager.toggleSrcView()", null);

        //
        //  Index schema document
        //
        if (this.index != null)
        {
            this._menuItemMarkup (mainMenu, this.index.name,
                                  this.index.href, this.index.title);
        }

        controllerDiv.appendChild (mainMenu.main);
        var oMenu = new YAHOO.widget.Menu("mainmenu", {position: "static"});
        oMenu.render();
        oMenu.show();
    },

    //
    //  Builds menu markup returns the associated divs in the
    //  properties main, body, header, footer, and list
    //
    _menuMarkup : function(id /*Id for main part*/)
    {
        //
        //  Build our menu div...
        //
        var mainDiv   = document.createElement("div");
        var headerDiv = document.createElement("div");
        var bodyDiv   = document.createElement("div");
        var footerDiv = document.createElement("div");
        var listDiv   = document.createElement("ul");

        mainDiv.setAttribute ("id", id);
        trc.util.dom.setClassName (mainDiv, "yuimenu");
        trc.util.dom.setClassName (headerDiv, "hd");
        trc.util.dom.setClassName (bodyDiv, "bd");
        trc.util.dom.setClassName (footerDiv, "ft");

        mainDiv.appendChild (headerDiv);
        mainDiv.appendChild (bodyDiv);
        mainDiv.appendChild (footerDiv);
        bodyDiv.appendChild (listDiv);

        return {
            main : mainDiv,
            body : bodyDiv,
            header : headerDiv,
            footer : footerDiv,
            list : listDiv
        };
    },

    //
    //  Adds a menu item to existing markup.
    //
    _menuItemMarkup : function (menu, /*Markup returned from _menuMarkup*/
                                name, /* String, menu item name */
                                href, /* String, menu item href */
                                title /* String, title (tool tip)*/
                               )
    {
        var listItem = document.createElement ("li");
        var link     = document.createElement ("a");

        trc.util.dom.setClassName (listItem, "yuimenuitem");
        trc.util.dom.setClassName (link, "yuimenuitemlabel");

        link.setAttribute ("href", href);

        if (title != null)
        {
            link.setAttribute ("title", title);
        }

        link.appendChild (document.createTextNode(name));

        listItem.appendChild (link);
        menu.list.appendChild(listItem);

        return {
            item : listItem,
            anchor : link
        };
    }
};
