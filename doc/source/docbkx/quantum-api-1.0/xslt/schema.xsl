<?xml version="1.0" encoding="UTF-8"?>

<!-- (C) 2009 Rackspace Hosting, All Rights Reserved -->


<xslt:stylesheet version="1.0"
            xmlns:xslt="http://www.w3.org/1999/XSL/Transform"
            xmlns:html="http://www.w3.org/1999/xhtml"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema"
            xmlns:xsdxt="http://docs.openstack.org/xsd-ext/v1.0"
            xmlns="http://www.w3.org/1999/xhtml"
            >

  <xslt:output method="html"
               encoding="UTF-8"
               media-type="text/html"
               doctype-public = "-//W3C//DTD HTML 4.01//EN"
               doctype-system = "http://www.w3.org/TR/html4/strict.dtd" />

  <!-- Params -->
  <xslt:param name="base">
      <xslt:choose>
          <xslt:when test="/xsd:schema/@xsdxt:base">
              <xslt:value-of select="/xsd:schema/@xsdxt:base"/>
          </xslt:when>
          <xslt:otherwise>
              <xslt:text>..</xslt:text>
          </xslt:otherwise>
      </xslt:choose>
  </xslt:param>

  <!-- Global Variables -->
  <xslt:variable name="defaultTitle">XML Schema Documentation</xslt:variable>
  <xslt:variable name="templateType">application/xhtml+xml</xslt:variable>
  <xslt:variable name="schemaNamespace">http://www.w3.org/2001/XMLSchema</xslt:variable>
  <xslt:variable name="schemaDatatypeURI">http://web4.w3.org/TR/2001/REC-xmlschema-2-20010502/#</xslt:variable>

  <xslt:variable name="dQuote">"</xslt:variable>
  <xslt:variable name="sQuote">'</xslt:variable>

  <!-- The namespace prefixes -->
  <xslt:variable name="targetPrefix">
      <xslt:for-each select="/xsd:schema/namespace::node()">
        <xslt:if test=".=/xsd:schema/@targetNamespace">
          <xslt:value-of select="name(.)"/>
        </xslt:if>
      </xslt:for-each>
  </xslt:variable>

  <xslt:variable name="schemaPrefix">
      <xslt:for-each select="/xsd:schema/namespace::node()">
        <xslt:if test="(.=$schemaNamespace) and (string-length(.) > 0)">
          <xslt:value-of select="name(.)"/>
        </xslt:if>
      </xslt:for-each>
  </xslt:variable>

  <!-- Anchor prefixes -->
  <xslt:variable name="elementPrefix">element_</xslt:variable>
  <xslt:variable name="attributePrefix">attrib_</xslt:variable>
  <xslt:variable name="attributeGroupPrefix">attgrp_</xslt:variable>
  <xslt:variable name="groupPrefix">grp_</xslt:variable>
  <xslt:variable name="typePrefix">type_</xslt:variable>

  <!-- YUI BASE:  -->
  <!--
      We only load YUI style sheets here. We bring js stuff
      dynamically. Stylesheet's can't really be brought dynamically.
      They need to be loaded before anything else.
  -->
  <xslt:variable name="YUI_BASE">http://yui.yahooapis.com/2.7.0/build/</xslt:variable>
  <xslt:variable name="YUI_RESET_STYLESHEET">
    <xslt:value-of select="concat($YUI_BASE,'reset/reset-min.css')" />
  </xslt:variable>
  <xslt:variable name="YUI_BASE_STYLESHEET">
    <xslt:value-of select="concat($YUI_BASE,'base/base-min.css')" />
  </xslt:variable>
  <xslt:variable name="YUI_FONTS_STYLESHEET">
    <xslt:value-of select="concat($YUI_BASE,'fonts/fonts-min.css')" />
  </xslt:variable>
  <xslt:variable name="YUI_GRIDS_STYLESHEET">
    <xslt:value-of select="concat($YUI_BASE,'grids/grids-min.css')" />
  </xslt:variable>

  <xslt:template name="addStylesheet">
    <xslt:param name="sheet" />
    <xslt:element name="link">
      <xslt:attribute name="rel">stylesheet</xslt:attribute>
      <xslt:attribute name="type">text/css</xslt:attribute>
      <xslt:attribute name="href">
        <xslt:value-of select="$sheet"/>
      </xslt:attribute>
    </xslt:element>
  </xslt:template>

  <!-- Templates -->
  <xslt:template name="SchemaHandler" match="xsd:schema">
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <xslt:call-template name="addStylesheet">
          <xslt:with-param name="sheet" select="$YUI_RESET_STYLESHEET"/>
        </xslt:call-template>
        <xslt:call-template name="addStylesheet">
          <xslt:with-param name="sheet" select="$YUI_BASE_STYLESHEET"/>
        </xslt:call-template>
        <xslt:call-template name="addStylesheet">
          <xslt:with-param name="sheet" select="$YUI_FONTS_STYLESHEET"/>
        </xslt:call-template>
        <xslt:call-template name="addStylesheet">
          <xslt:with-param name="sheet" select="$YUI_GRIDS_STYLESHEET"/>
        </xslt:call-template>
        <xslt:call-template name="addStylesheet">
          <xslt:with-param name="sheet" select="concat($base,'/style/schema.css')"/>
        </xslt:call-template>

        <!--
            Add custom links...
        -->
        <xslt:for-each select="//xsdxt:link">
          <xslt:if test="not(@qname)">
            <xslt:element name="link">
              <xslt:if test="@rev">
                <xslt:attribute name="rev"><xslt:value-of select="@rev"/></xslt:attribute>
              </xslt:if>
              <xslt:if test="@rel">
                <xslt:attribute name="rel"><xslt:value-of select="@rel"/></xslt:attribute>
              </xslt:if>
              <xslt:if test="@href">
                <xslt:attribute name="href"><xslt:value-of select="@href"/></xslt:attribute>
              </xslt:if>
              <xslt:if test="@type">
                <xslt:attribute name="type"><xslt:value-of select="@type"/></xslt:attribute>
              </xslt:if>
            </xslt:element>
          </xslt:if>
        </xslt:for-each>

        <!--
            Set the title if it's available, default title if not.
        -->
        <xslt:choose>
          <xslt:when test="xsd:annotation/xsd:appinfo/xsdxt:title">
            <title><xslt:value-of select="xsd:annotation/xsd:appinfo/xsdxt:title"/></title>
          </xslt:when>
          <xslt:otherwise>
            <title><xslt:value-of select="$defaultTitle"/></title>
          </xslt:otherwise>
        </xslt:choose>

        <!-- Schema scripts -->
        <script type="text/javascript" src="{$base}/js/trc/util.js"> </script>
        <script type="text/javascript" src="{$base}/js/trc/schema/layoutManager.js"> </script>
        <script type="text/javascript" src="{$base}/js/trc/schema/sampleManager.js"> </script>
        <script type="text/javascript" src="{$base}/js/trc/schema/controller.js"> </script>

        <xslt:if test="//xsdxt:samples | //xsdxt:code">
          <script type="text/javascript">
            <xslt:for-each select="//xsdxt:samples">
              <xslt:variable name="elmId"><xslt:value-of select="generate-id(.)"/></xslt:variable>
              <xslt:if test="xsdxt:sample">
                <xslt:text>trc.schema.sampleManager.samples["</xslt:text>
                <xslt:value-of select="$elmId"/>
                <xslt:text>"]=[</xslt:text>
                <xslt:for-each select="xsdxt:sample">
                  <xslt:call-template name="StringToJavascript">
                    <xslt:with-param name="inString" select="generate-id(.)"/>
                  </xslt:call-template>
                  <xslt:if test="generate-id(../xsdxt:sample[count(../xsdxt:sample)]) !=
                                 generate-id(.)
                                 ">
                    <xslt:text>,</xslt:text>
                  </xslt:if>
                </xslt:for-each>
                <xslt:text>];</xslt:text>
              </xslt:if>
            </xslt:for-each>
            <xslt:if test="//xsdxt:code">
              <xslt:text>trc.schema.sampleManager.codes.push(</xslt:text>
              <xslt:for-each select="//xsdxt:code">
                <xslt:text>{ id : </xslt:text>
                <xslt:value-of select="concat($dQuote,generate-id(.),$dQuote)" />
                <xslt:text>, type : "</xslt:text>
                <xslt:choose>
                  <xslt:when test="@type">
                    <xslt:value-of select="@type"/>
                  </xslt:when>
                  <xslt:otherwise>
                    <xslt:text>application/xml</xslt:text>
                  </xslt:otherwise>
                </xslt:choose>
                <xslt:text>", href : </xslt:text>
                <xslt:choose>
                  <xslt:when test="@href">
                    <xslt:value-of select="concat($dQuote,@href,$dQuote)"/>
                  </xslt:when>
                  <xslt:otherwise>
                    <xslt:text>null</xslt:text>
                  </xslt:otherwise>
                </xslt:choose>
                <xslt:text>}</xslt:text>
                  <xslt:text>,</xslt:text>
              </xslt:for-each>
              <xslt:text>null);</xslt:text>
            </xslt:if>
          </script>
        </xslt:if>

        <xslt:call-template name="ControllerJSHandler" />

        <!--
            Copy any HTML header tags here
        -->
        <xslt:for-each select="//xsdxt:head">
          <xslt:choose>
            <xslt:when test="not(@type)">
              <xslt:copy-of select="./*" />
            </xslt:when>
            <xslt:when test="@type = $templateType">
              <xslt:copy-of select="./*" />
            </xslt:when>
          </xslt:choose>
        </xslt:for-each>
      </head>
      <body>
        <div id="Controller">
        </div>
        <div id="doc">
          <div id="Main">
            <div id="SrcContent">
              <div class="SampleCode">
                <pre id="SrcContentCode">Loading...</pre>
              </div>
            </div>
            <div id="Content">
              <!--
                  If there is a title use it as a first heading, otherwise,
                  use default title.
              -->
              <xslt:choose>
                <xslt:when test="xsd:annotation/xsd:appinfo/xsdxt:title">
                  <h1><xslt:value-of select="xsd:annotation/xsd:appinfo/xsdxt:title"/></h1>
                </xslt:when>
                <xslt:otherwise>
                  <h1><xslt:value-of select="$defaultTitle"/></h1>
                </xslt:otherwise>
              </xslt:choose>

              <!--
                  Schema attributes
              -->
              <table summary="Schema-level attributes">
                <tbody>
                  <xslt:for-each select="@*">
                    <tr>
                      <td><xslt:value-of select="local-name(.)"/></td>
                      <td><xslt:value-of select="."/></td>
                    </tr>
                  </xslt:for-each>
                </tbody>
              </table>

              <!--
                  Copy schema-level documentation if there's anything to
                  copy. This also processes any internal documentation
                  annotations:  currently just xsdxt:code.
              -->
              <xslt:apply-templates select="xsd:annotation/xsd:documentation/*" mode="Docs"/>
            
              <!--
                  Next comes custom header...
              -->
              <div id="Header">
                <xslt:for-each select="//xsdxt:header">
                  <xslt:choose>
                    <xslt:when test="not(@type)">
                      <xslt:copy-of select="./*" />
                    </xslt:when>
                    <xslt:when test="@type = $templateType">
                      <xslt:copy-of select="./*" />
                    </xslt:when>
                  </xslt:choose>
                </xslt:for-each>
              </div>


              <!--
                  Namespace info, not all borowsers have namespace node
                  support.  Specifically Firefox currently lacks it.

               See:
               https://bugzilla.mozilla.org/show_bug.cgi?id=94270

               In this case we ask the user to try a different
               browser:  Opera, Safari, or even IE.
              -->
              <h2>Namespaces</h2>
              <xslt:choose>
                <xslt:when test="count(namespace::*) = 0">
                  <!--Namespaces are not available...-->
                  <div class="Warning">
                    <p>
                      Your browser does not seem to have support for
                      namespace nodes in XPath. If you're a Firefox
                      user, please consider voting to get this issue
                      resolved:
                      <a href="https://bugzilla.mozilla.org/show_bug.cgi?id=94270"
                         title="FireFox Bug 94270">
                        https://bugzilla.mozilla.org/show_bug.cgi?id=94270
                      </a>
                    </p>
                  </div>
                </xslt:when>
                <xslt:otherwise>
                  <table summary="Namespace details">
                    <tbody>
                      <xslt:for-each select="namespace::*">
                        <xslt:sort />
                        <tr>
                          <td><xslt:value-of select="name(.)"/></td>
                          <td><xslt:value-of select="."/></td>
                        </tr>
                      </xslt:for-each>
                    </tbody>
                  </table>
                </xslt:otherwise>
              </xslt:choose>

              <!--
                  Next, call the handlers for the top schema elements.
              -->
              <xslt:if test="xsd:import">
                <xslt:call-template name="ImportHandler" />
              </xslt:if>
              <xslt:if test="xsd:include">
                <xslt:call-template name="IncludeHandler" />
              </xslt:if>

              <xslt:if test="xsd:element">
                <xslt:call-template name="ElementHandler" />
              </xslt:if>

              <xslt:if test="xsd:complexType">
                <xslt:call-template name="ComplexTypeHandler" />
              </xslt:if>

              <xslt:if test="xsd:simpleType">
                <xslt:call-template name="SimpleTypeHandler" />
              </xslt:if>

              <!-- Finally, custom footers -->
              <div id="Footer">
                <xslt:for-each select="//xsdxt:footer">
                  <xslt:choose>
                    <xslt:when test="not(@type)">
                      <xslt:copy-of select="./*" />
                    </xslt:when>
                    <xslt:when test="@type = $templateType">
                      <xslt:copy-of select="./*" />
                    </xslt:when>
                  </xslt:choose>
                </xslt:for-each>
              </div>
            </div>
          </div>
        </div>
      </body>
    </html>
  </xslt:template>

  <xslt:template name="ControllerExternJSLinks">
    <xslt:param name="nodes" />

    <xslt:text>trc.schema.controller.links['</xslt:text>
    <xslt:value-of select="local-name($nodes[1])"/>
    <xslt:text>']=[</xslt:text>
    <xslt:for-each select="$nodes">
      <xslt:call-template name="ControllerJSLink">
        <xslt:with-param name="href" select="@schemaLocation"/>
        <xslt:with-param name="name">
          <xslt:choose>
            <xslt:when test="@namespace">
              <xslt:value-of select="@namespace" />
            </xslt:when>
            <xslt:otherwise>
              <xslt:value-of select="@schemaLocation" />
            </xslt:otherwise>
          </xslt:choose>
        </xslt:with-param>
        <xslt:with-param name="title">
          <xslt:choose>
            <xslt:when test="@namespace">
              <xslt:value-of select="concat('View schema for namespace ',@namespace)"/>
            </xslt:when>
            <xslt:otherwise>
              <xslt:value-of select="concat('Visit schema ',@schemaLocation)"/>
            </xslt:otherwise>
          </xslt:choose>
        </xslt:with-param>
      </xslt:call-template>
      <xslt:if test="$nodes[count($nodes)]/@schemaLocation !=
                     @schemaLocation">
        <xslt:text>,</xslt:text>
      </xslt:if>
    </xslt:for-each>
    <xslt:text>];</xslt:text>
  </xslt:template>

  <xslt:template name="ControllerIndexJSLink">
    <xslt:param name="node" select="//xsdxt:link[@rel = 'index']" />

    <xslt:text>trc.schema.controller.index = </xslt:text>
    <xslt:call-template name="ControllerJSLink">
      <xslt:with-param name="href">
        <xslt:value-of select="$node/@href"/>
      </xslt:with-param>
      <xslt:with-param name="name">
        <xslt:text>index</xslt:text>
      </xslt:with-param>
      <xslt:with-param name="title">
        <xslt:text>Index Schema Document</xslt:text>
      </xslt:with-param>
    </xslt:call-template>
    <xslt:text>;</xslt:text>
  </xslt:template>

  <xslt:template name="ControllerNamedElementJSLink">
    <xslt:param name="nodes" />
    <xslt:param name="anchorPrefix" />

    <xslt:text>trc.schema.controller.links['</xslt:text>
    <xslt:value-of select="local-name($nodes[1])"/>
    <xslt:text>']=[</xslt:text>
    <xslt:for-each select="$nodes">
      <xslt:call-template name="ControllerJSLink">
        <xslt:with-param name="href">
          <xslt:text>#</xslt:text>
          <xslt:value-of select="$anchorPrefix" />
          <xslt:value-of select="@name" />
        </xslt:with-param>
        <xslt:with-param name="name">
          <xslt:call-template name="StringToName"/>
        </xslt:with-param>
        <xslt:with-param name="title">
          <xslt:text>See definition of </xslt:text>
          <xslt:call-template name="StringToName"/>
        </xslt:with-param>
      </xslt:call-template>
      <xslt:if test="generate-id($nodes[count($nodes)]) !=
                     generate-id(.)">
        <xslt:text>,</xslt:text>
      </xslt:if>
    </xslt:for-each>
    <xslt:text>];</xslt:text>
  </xslt:template>

  <xslt:template name="ControllerJSLink">
    <xslt:param name="name"  />
    <xslt:param name="href"  />
    <xslt:param name="title" />

    <xslt:text>{ href : </xslt:text>
    <xslt:call-template name="StringToJavascript">
      <xslt:with-param name="inString">
        <xslt:value-of select="$href"/>
      </xslt:with-param>
    </xslt:call-template>
    <xslt:text>, name : </xslt:text>
    <xslt:call-template name="StringToJavascript">
      <xslt:with-param name="inString">
        <xslt:value-of select="$name"/>
      </xslt:with-param>
    </xslt:call-template>
    <xslt:text>, title : </xslt:text>
    <xslt:call-template name="StringToJavascript">
      <xslt:with-param name="inString">
        <xslt:value-of select="$title"/>
      </xslt:with-param>
    </xslt:call-template>
    <xslt:text>}</xslt:text>
  </xslt:template>

  <!--
      Adds javascript for controller data..
  -->
  <xslt:template name="ControllerJSHandler">
    <script type="text/javascript">
      <xslt:if test="xsd:import">
        <xslt:call-template name="ControllerExternJSLinks">
          <xslt:with-param name="nodes" select="xsd:import" />
        </xslt:call-template>
      </xslt:if>
      <xslt:if test="xsd:include">
        <xslt:call-template name="ControllerExternJSLinks">
          <xslt:with-param name="nodes" select="xsd:include" />
        </xslt:call-template>
      </xslt:if>
      <xslt:if test="xsd:element">
        <xslt:call-template name="ControllerNamedElementJSLink">
          <xslt:with-param name="nodes" select="xsd:element"/>
          <xslt:with-param name="anchorPrefix" select="$elementPrefix"/>
        </xslt:call-template>
      </xslt:if>
      <xslt:if test="xsd:attribute">
        <xslt:call-template name="ControllerNamedElementJSLink">
          <xslt:with-param name="nodes" select="xsd:attribute"/>
          <xslt:with-param name="anchorPrefix" select="$attributePrefix"/>
        </xslt:call-template>
      </xslt:if>
      <xslt:if test="xsd:complexType">
        <xslt:call-template name="ControllerNamedElementJSLink">
          <xslt:with-param name="nodes" select="xsd:complexType"/>
          <xslt:with-param name="anchorPrefix" select="$typePrefix"/>
        </xslt:call-template>
      </xslt:if>
      <xslt:if test="xsd:simpleType">
        <xslt:call-template name="ControllerNamedElementJSLink">
          <xslt:with-param name="nodes" select="xsd:simpleType"/>
          <xslt:with-param name="anchorPrefix" select="$typePrefix"/>
        </xslt:call-template>
      </xslt:if>
      <xslt:if test="//xsdxt:link[@rel = 'index']">
        <xslt:call-template name="ControllerIndexJSLink" />
      </xslt:if>
    </script>
  </xslt:template>

  <xslt:template name="ImportHandler">
    <h2>Imports</h2>
    <table summary="A list of imported XML Schema" class="ImportTable">
      <tbody>
        <xslt:for-each select="xsd:import">
          <tr>
            <td>
              <xslt:value-of select="@namespace"/>
            </td>
            <td>
              <div class="Extern">
                <div class="ExternHref">
                  <xslt:element name="a">
                    <xslt:attribute name="href"><xslt:value-of select="@schemaLocation"/></xslt:attribute>
                    <xslt:attribute name="title">Visit <xslt:value-of select="@schemaLocation"/></xslt:attribute>
                    <xslt:value-of select="@schemaLocation"/>
                  </xslt:element>
                </div>
                <div class="ExternDoc">
                  <xslt:apply-templates select="xsd:annotation/xsd:documentation/*" mode="Docs"/>
                </div>
              </div>
            </td>
          </tr>
        </xslt:for-each>
      </tbody>
    </table>
  </xslt:template>

  <xslt:template name="IncludeHandler">
    <h2>Includes</h2>
    <table summary="A list of included XML Schema">
      <tbody>
        <xslt:for-each select="xsd:include">
          <tr>
            <td>
              <div class="Extern">
                <div class="ExternHref">
                  <xslt:element name="a">
                    <xslt:attribute name="href"><xslt:value-of select="@schemaLocation"/></xslt:attribute>
                    <xslt:attribute name="title">Visit <xslt:value-of select="@schemaLocation"/></xslt:attribute>
                    <xslt:value-of select="@schemaLocation"/>
                  </xslt:element>
                </div>
                <div class="ExternDoc">
                  <xslt:apply-templates select="xsd:annotation/xsd:documentation/*" mode="Docs"/>
                </div>
              </div>
            </td>
          </tr>
        </xslt:for-each>
      </tbody>
    </table>
  </xslt:template>

  <xslt:template name="ElementHandler">
    <h2>Elements</h2>
    <xslt:for-each select="xsd:element">
      <xslt:call-template name="NamedElement">
        <xslt:with-param name="anchorPrefix" select="$elementPrefix" />
      </xslt:call-template>
      <xslt:if test="xsd:annotation/xsd:appinfo/xsdxt:samples">
        <xslt:apply-templates select="xsd:annotation/xsd:appinfo/xsdxt:samples" mode="Docs" />
      </xslt:if>
    </xslt:for-each>
  </xslt:template>

  <xslt:template name="SampleHandler" match="xsdxt:samples" mode="Docs">
    <xslt:variable name="sampleID" select="generate-id(.)"/>
    <xslt:if test="xsdxt:description">
      <xslt:apply-templates select="xsdxt:description/*" mode="Docs" />
    </xslt:if>
    <form action="">
      <div class="SampleControl">
        <xslt:element name="select">
          <xslt:attribute name="onchange">
            <xslt:text>trc.schema.sampleManager.showSample(</xslt:text>
            <xslt:call-template name="StringToJavascript">
              <xslt:with-param name="inString" select="$sampleID"/>
            </xslt:call-template>
            <xslt:text>);</xslt:text>
          </xslt:attribute>
          <xslt:attribute name="id">
            <xslt:value-of select="$sampleID"/>
          </xslt:attribute>
          <xslt:for-each select="xsdxt:sample">
            <xslt:element name="option">
              <xslt:attribute name="value">
                <xslt:value-of select="generate-id(.)"/>
              </xslt:attribute>
              <xslt:choose>
                <xslt:when test="@title">
                  <xslt:value-of select="@title"/>
                </xslt:when>
                <xslt:otherwise>
                  <xslt:value-of select="./xsdxt:code/@type"/>
                </xslt:otherwise>
              </xslt:choose>
            </xslt:element>
          </xslt:for-each>
        </xslt:element>
      </div>
    </form>
    <xslt:for-each select="xsdxt:sample">
      <xslt:element name="div">
        <xslt:attribute name="id"><xslt:value-of select="generate-id(.)"/></xslt:attribute>
        <xslt:attribute name="class">Sample</xslt:attribute>
        <div class="SampleDesc">
          <xslt:apply-templates select="xsdxt:description/*" mode="Docs"/>
        </div>
        <xslt:apply-templates select="xsdxt:code" mode="Docs"/>
      </xslt:element>
    </xslt:for-each>
  </xslt:template>

  <!--
      Documentation templates, copy everything but process the
      xsdxt:code tag.
  -->
  <xslt:template match="xsdxt:code" mode="Docs">
    <div class="SampleCode">
      <xslt:element name="pre">
        <xslt:attribute name="id">
          <xslt:value-of select="generate-id(.)"/>
        </xslt:attribute>
        <xslt:choose>
          <xslt:when test="@href">
            <xslt:text>Loading...</xslt:text>
          </xslt:when>
          <xslt:otherwise>
            <xslt:value-of select="."/>
          </xslt:otherwise>
        </xslt:choose>
      </xslt:element>
    </div>
  </xslt:template>

  <xslt:template match="*" mode="Docs">
    <xslt:copy-of select="." />
  </xslt:template>

  <xslt:template name="ComplexTypeHandler">
    <h2>Complex Types</h2>
    <xslt:for-each select="xsd:complexType">
      <xslt:call-template name="NamedElement">
        <xslt:with-param name="anchorPrefix" select="$typePrefix" />
      </xslt:call-template>
      <xslt:apply-templates />
    </xslt:for-each>
  </xslt:template>

  <xslt:template name="SimpleTypeHandler">
    <h2>Simple Types</h2>
    <xslt:for-each select="xsd:simpleType">
      <xslt:call-template name="NamedElement">
        <xslt:with-param name="anchorPrefix" select="$typePrefix" />
      </xslt:call-template>
      <xslt:apply-templates />
    </xslt:for-each>
  </xslt:template>

  <xslt:template name="NamedElementLink">
    <xslt:param name="anchorPrefix" />
    <xslt:call-template name="Anchor">
      <xslt:with-param name="href">
        <xslt:text>#</xslt:text>
        <xslt:value-of select="$anchorPrefix"/>
        <xslt:value-of select="@name"/>
      </xslt:with-param>
      <xslt:with-param name="content">
        <xslt:call-template name="StringToName" />
      </xslt:with-param>
    </xslt:call-template>
  </xslt:template>

  <xslt:template name="NamedElement">
    <xslt:param name="anchorPrefix" />
    <xslt:element name="a">
      <xslt:attribute name="id"><xslt:value-of select="$anchorPrefix"/><xslt:value-of select="@name"/></xslt:attribute>
      <!--
          Placing a comment here causes the anchor tag to be closed
          correctly in IE 8.
      -->
      <xslt:comment>
        <xslt:value-of select="@name"/>
      </xslt:comment>
    </xslt:element>
    <h3>
      <xslt:call-template name="StringToName" />
    </h3>

    <xslt:choose>
      <!-- look for extensions and restrictions in type names -->
        <xslt:when test="$anchorPrefix = $typePrefix">
          <xslt:if test=".//xsd:extension">
            <div class="NameAddl">
              <xslt:text> extends: </xslt:text>
              <xslt:for-each select=".//xsd:extension">
                <xslt:apply-templates select="@base" mode="QNameToLink" />
                <xslt:if test=".//xsd:extension[count(.//xsd:extension)]/@base != @base">
                  <xslt:text>,</xslt:text>
                </xslt:if>
              </xslt:for-each>
            </div>
          </xslt:if>
          <xslt:if test=".//xsd:restriction">
            <div class="NameAddl">
              <xslt:text> restricts: </xslt:text>
              <xslt:for-each select=".//xsd:restriction">
                <xslt:apply-templates select="@base" mode="QNameToLink" />
                <xslt:if test=".//xsd:restriction[count(.//xsd:restriction)]/@base != @base">
                  <xslt:text>,</xslt:text>
                </xslt:if>
              </xslt:for-each>
            </div>
          </xslt:if>
        </xslt:when>
    </xslt:choose>

    <xslt:call-template name="AttribsAndDocs" />

  </xslt:template>

  <!-- Display all attributes besides @name -->
  <xslt:template name="Attribs">
    <xslt:param name="isSubItem" select="false()"/>
    <xslt:if test="(count(@*) > 1) or ((count(@*) = 1) and not(@name))">
      <xslt:element name="div">
        <xslt:attribute name="class">
          <xslt:choose>
            <xslt:when test="$isSubItem = true()">
              <xslt:text>SubAttributes</xslt:text>
            </xslt:when>
            <xslt:otherwise>
              <xslt:text>Attributes</xslt:text>
            </xslt:otherwise>
          </xslt:choose>
        </xslt:attribute>
        <table summary="Attributes">
          <tbody>
            <xslt:for-each select="@*">
              <xslt:sort select="local-name(.)"/>
              <xslt:if test="local-name(.) != 'name'">
                <tr>
                  <td><xslt:value-of select="local-name(.)"/></td>
                  <td><xslt:call-template name="QNameToLink"/></td>
                </tr>
              </xslt:if>
            </xslt:for-each>
          </tbody>
        </table>
      </xslt:element>
    </xslt:if>
  </xslt:template>

  <xslt:template name="Docs">
    <xslt:param name="isSubItem" select="false()"/>
    <!--
        Copy element-level documentation
    -->
    <xslt:if test="xsd:annotation/xsd:documentation">
      <xslt:element name="div">
        <xslt:attribute name="class">
          <xslt:choose>
            <xslt:when test="$isSubItem = true()">
              <xslt:text>SubDocumentation</xslt:text>
            </xslt:when>
            <xslt:otherwise>
              <xslt:text>Documentation</xslt:text>
            </xslt:otherwise>
          </xslt:choose>
        </xslt:attribute>
        <xslt:apply-templates select="xsd:annotation/xsd:documentation/*" mode="Docs"/>
      </xslt:element>
    </xslt:if>
  </xslt:template>

  <xslt:template name="AttribsAndDocs">
    <xslt:param name="isSubItem" select="false()"/>
    <xslt:call-template name="Attribs">
      <xslt:with-param name="isSubItem" select="$isSubItem"/>
    </xslt:call-template>
    <xslt:call-template name="Docs">
      <xslt:with-param name="isSubItem" select="$isSubItem"/>
    </xslt:call-template>
  </xslt:template>

  <!--
      Convert a qname to a link.
  -->
  <xslt:template name="QNameToLink" match="@*" mode="QNameToLink">
    <xslt:param name="qname" select="normalize-space(.)"/>
    <xslt:choose>
      <xslt:when test="contains($qname,':')">
        <xslt:variable name="prefix" select="substring-before($qname,':')"/>
        <xslt:variable name="localName" select="substring-after($qname,':')"/>
        <xslt:choose>
          <xslt:when test="//xsdxt:link[(@qname = $qname) and (@rel = 'schema')]">
            <xslt:call-template name="Anchor">
              <xslt:with-param name="href"  select="//xsdxt:link[(@qname = $qname) and (@rel = 'schema')]/@href"/>
              <xslt:with-param name="title" select="concat('See ',$localName)"/>
            </xslt:call-template>
          </xslt:when>
          <xslt:when test="$prefix = $targetPrefix">
            <xslt:call-template name="Anchor">
              <xslt:with-param name="href"><xslt:call-template name="QNameToLocalAnchor"/></xslt:with-param>
              <xslt:with-param name="title" select="concat('See ',$localName)"/>
            </xslt:call-template>
          </xslt:when>
          <xslt:when test="$prefix = $schemaPrefix">
            <xslt:call-template name="Anchor">
              <xslt:with-param name="href"><xslt:call-template name="QNameToXSDAnchor"/></xslt:with-param>
              <xslt:with-param name="title" select="concat('See ',$localName)"/>
            </xslt:call-template>
          </xslt:when>
           <xslt:otherwise>
             <xslt:call-template name="Anchor">
               <xslt:with-param name="href"><xslt:call-template name="QNameToForeignAnchor"/></xslt:with-param>
               <xslt:with-param name="title" select="concat('See ',$localName)"/>
             </xslt:call-template>
           </xslt:otherwise>
        </xslt:choose>
      </xslt:when>
      <xslt:otherwise>
        <xslt:value-of select="."/>
      </xslt:otherwise>
    </xslt:choose>
  </xslt:template>

  <!-- Write an anchor if it's defined for the current node -->
  <xslt:template name="Anchor">
    <xslt:param name="href" /> <!-- if empty don't make an anchor -->
    <xslt:param name="title">
      <xslt:if test="@name">
        <xslt:value-of select="concat('See ',@name)"/>
      </xslt:if>
    </xslt:param>
    <xslt:param name="content" select="."/>
    <xslt:choose>
      <xslt:when test="string-length($href) != 0">
        <xslt:element name="a">
          <xslt:attribute name="href"><xslt:value-of select="$href"/></xslt:attribute>
          <xslt:attribute name="title"><xslt:value-of select="$title"/></xslt:attribute>
          <xslt:value-of select="$content"/>
        </xslt:element>
      </xslt:when>
      <xslt:otherwise><xslt:value-of select="."/></xslt:otherwise>
    </xslt:choose>
  </xslt:template>

  <!--
      Given a quname attribute pointing to a forign XSD type return a
      link if a single import statement exists with a schemaLocation
      attribute
  -->
  <xslt:template name="QNameToForeignAnchor">
    <xslt:param name="qname" select="normalize-space(.)"/>
    <xslt:param name="localName" select="substring-after($qname, ':')"/>
    <xslt:param name="prefix" select="substring-before($qname, ':')"/>
    <xslt:if test="namespace-uri(..) = $schemaNamespace">
      <xslt:variable name="namespace">
        <xslt:for-each select="/xsd:schema/namespace::node()">
          <xslt:if test="name(.)=$prefix">
            <xslt:value-of select="."/>
          </xslt:if>
        </xslt:for-each>
      </xslt:variable>
      <xslt:if test="(string-length($namespace) > 0) and
                     (count(/xsd:schema/xsd:import[@namespace = $namespace]) = 1) and
                     /xsd:schema/xsd:import[@namespace = $namespace]/@schemaLocation
                     ">
        <xslt:value-of select="/xsd:schema/xsd:import[@namespace = $namespace]/@schemaLocation"/>
      </xslt:if>
    </xslt:if>
  </xslt:template>

  <!--
      Given a qname attribute pointing to an XSD type, returns an anchor
      to the XSD definition.  This only works for type references.
  -->
  <xslt:template name="QNameToXSDAnchor">
    <xslt:param name="qname" select="normalize-space(.)"/>
    <xslt:param name="localName" select="substring-after($qname, ':')"/>
    <xslt:if test="namespace-uri(..) = $schemaNamespace">
      <xslt:if test="(local-name(.) = 'type') or (local-name(.) = 'base')">
        <xslt:value-of select="concat($schemaDatatypeURI,$localName)" />
      </xslt:if>
    </xslt:if>
  </xslt:template>

  <!--
     Given a qname attribute, returns an anchor target for that qname,
     or an empty string if an anchor cannot be generated for whatever
     reason.
  -->
  <xslt:template name="QNameToLocalAnchor">
    <xslt:param name="qname" select="normalize-space(.)"/>
    <xslt:param name="localName" select="substring-after($qname, ':')"/>
    <xslt:if test="namespace-uri(..) = $schemaNamespace">
      <xslt:choose>
        <xslt:when test="(local-name(.) = 'type') or
                         (local-name(.) = 'base') or
                         (local-name(.) = 'itemType')"><xslt:call-template name="LocalTypeAnchor"><xslt:with-param name="localName" select="$localName"/>
        </xslt:call-template></xslt:when>
        <xslt:when test="local-name(.) = 'ref'"><xslt:call-template name="LocalRefAnchor"><xslt:with-param name="localName" select="$localName"/>
        </xslt:call-template></xslt:when>
      </xslt:choose>
    </xslt:if>
  </xslt:template>

  <xslt:template name="LocalRefAnchor">
    <xslt:param name="localName" />
    <xslt:choose>
      <!-- Element Reference -->
      <xslt:when test="local-name(..) = 'element'">
        <xslt:call-template name="LocalRefAnchorBuilder">
          <xslt:with-param name="localName" select="$localName"/>
          <xslt:with-param name="search" select="/xsd:schema/xsd:element[@name= $localName]"/>
          <xslt:with-param name="refPrefix" select="$elementPrefix"/>
        </xslt:call-template>
      </xslt:when>
      <!-- Attribute Reference -->
      <xslt:when test="local-name(..) = 'attribute'">
        <xslt:call-template name="LocalRefAnchorBuilder">
          <xslt:with-param name="localName" select="$localName"/>
          <xslt:with-param name="search" select="/xsd:schema/xsd:attribute[@name= $localName]"/>
          <xslt:with-param name="refPrefix" select="$attributePrefix"/>
        </xslt:call-template>
      </xslt:when>
      <!-- Attribute Group Reference -->
      <xslt:when test="local-name(..) = 'attributeGroup'">
        <xslt:call-template name="LocalRefAnchorBuilder">
          <xslt:with-param name="localName" select="$localName"/>
          <xslt:with-param name="search" select="/xsd:schema/xsd:attributeGroup[@name= $localName]"/>
          <xslt:with-param name="refPrefix" select="$attributeGroupPrefix"/>
        </xslt:call-template>
      </xslt:when>
      <!-- Group Reference -->
      <xslt:when test="local-name(..) = 'group'">
        <xslt:call-template name="LocalRefAnchorBuilder">
          <xslt:with-param name="localName" select="$localName"/>
          <xslt:with-param name="search" select="/xsd:schema/xsd:group[@name= $localName]"/>
          <xslt:with-param name="refPrefix" select="$groupPrefix"/>
        </xslt:call-template>
      </xslt:when>
    </xslt:choose>
  </xslt:template>

  <xslt:template  name="LocalRefAnchorBuilder">
    <xslt:param name="localName" />
    <xslt:param name="search" />
    <xslt:param name="refPrefix" />
    <xslt:choose>
      <xslt:when test="$search">
        <xslt:value-of select="concat('#',$refPrefix,$localName)"/>
      </xslt:when>
      <!--
          If we have a single incude then we assume it's
          included...
      -->
      <xslt:when test="count(/xsd:schema/xsd:include) = 1"><xslt:value-of
      select="concat(/xsd:schema/xsd:include/@schemaLocation,'#',$refPrefix,$localName)"/></xslt:when>
    </xslt:choose>
  </xslt:template>

  <!--
     Given a local name as a pram, returns a local "type" anchor or an
     empty string if one cannot be generated.
  -->
  <xslt:template name="LocalTypeAnchor">
    <xslt:param name="localName" />
    <xslt:choose>
      <!-- Search the types -->
      <xslt:when
          test="/xsd:schema/xsd:complexType[@name = $localName] or
                /xsd:schema/xsd:simpleType[@name = $localName]"
          ><xslt:value-of select="concat('#',$typePrefix,$localName)"/></xslt:when>
      <!--
           If we haven't hit yet see if we have an include.
           Currently this only works with a single include.
      -->
      <xslt:when
          test="count(/xsd:schema/xsd:include) = 1"><xslt:value-of
          select="concat(/xsd:schema/xsd:include/@schemaLocation,'#',$typePrefix,$localName)"/></xslt:when>
      <!-- Can't tell so send an empty string... -->
      <xslt:otherwise />
    </xslt:choose>
  </xslt:template>

  <!-- Internal sequences -->
  <xslt:template match="xsd:sequence">
    <div class="Sequence">
       <span class="h4">Sequence</span>
       <xslt:call-template name="AttribsAndDocs" />
       <xslt:apply-templates />
    </div>
  </xslt:template>

  <xslt:template name="SubItem">
    <xslt:param name="name" />
    <div class="SubItem">
      <div class="SubItemProps">
        <div class="SubName">
          <xslt:value-of select="$name"/>
        </div>
        <xslt:call-template name="Attribs">
          <xslt:with-param name="isSubItem" select="true()"/>
        </xslt:call-template>
      </div>
      <xslt:call-template name="Docs">
        <xslt:with-param name="isSubItem" select="true()"/>
      </xslt:call-template>
    </div>
  </xslt:template>

  <xslt:template match="xsd:element">
    <xslt:call-template name="SubItem">
      <xslt:with-param name="name">
        <xslt:choose>
          <xslt:when test="@name">
            <xslt:call-template name="StringToElementName">
              <xslt:with-param name="inString" select="@name"/>
            </xslt:call-template>
          </xslt:when>
          <xslt:when test="@ref">
            <xslt:variable name="elementName" select="substring-after(@ref,':')"/>
            <xslt:call-template name="StringToElementName">
              <xslt:with-param name="inString" select="$elementName"/>
            </xslt:call-template>
          </xslt:when>
        </xslt:choose>
      </xslt:with-param>
    </xslt:call-template>
  </xslt:template>

  <xslt:template match="xsd:any">
    <xslt:call-template name="SubItem">
      <xslt:with-param name="name">
        <xslt:text>&lt;?&gt; (Any Element)</xslt:text>
      </xslt:with-param>
    </xslt:call-template>
  </xslt:template>

  <xslt:template match="xsd:anyAttribute">
    <xslt:call-template name="SubItem">
      <xslt:with-param name="name">
        <xslt:text>@? (Any Attribute)</xslt:text>
      </xslt:with-param>
    </xslt:call-template>
  </xslt:template>

  <xslt:template match="xsd:restriction">
    <div class="SubName">
      <xslt:text>restriction</xslt:text>
    </div>
    <table summary="Restriction Props and Attributes">
      <tbody>
        <xslt:for-each select="@*">
          <xslt:sort select="local-name(.)"/>
          <xslt:if test="local-name(.) != 'name'">
            <tr>
              <td><xslt:value-of select="local-name(.)"/></td>
              <td><xslt:call-template name="QNameToLink"/></td>
            </tr>
          </xslt:if>
        </xslt:for-each>

        <!-- simple restrictions -->
        <xslt:for-each select="xsd:minExclusive | xsd:minInclusive   |
                               xsd:maxExclusive | xsd:maxInclusive   |
                               xsd:totalDigits  | xsd:fractionDigits |
                               xsd:length       | xsd:minLength      |
                               xsd:maxLength    | xsd:minLength      |
                               xsd:whitespace   | xsd:pattern
                               ">
          <tr>
            <td><xslt:value-of select="local-name(.)"/></td>
            <xslt:call-template name="DisplaySimpleRestriction"/>
          </tr>
        </xslt:for-each>

        <xslt:if test="xsd:enumeration">
          <tr>
            <td>enum values</td>
            <xslt:call-template name="DisplayEnumeration">
              <xslt:with-param name="enum" select="xsd:enumeration[1]"/>
            </xslt:call-template>
          </tr>
          <xslt:for-each select="xsd:enumeration">
            <xslt:if test="@value != ../xsd:enumeration[1]/@value">
              <tr>
                <td></td>
                <xslt:call-template name="DisplayEnumeration"/>
              </tr>
            </xslt:if>
          </xslt:for-each>
        </xslt:if>
      </tbody>
    </table>

    <!--
        Copy restriction docs documentation...
    -->
    <xslt:if test="xsd:annotation/xsd:documentation">
      <xslt:apply-templates select="xsd:annotation/xsd:documentation/*" mode="Docs"/>
    </xslt:if>

    <!--
        Apply templates for unhandled children
    -->
    <xslt:apply-templates select="xsd:simpleType     | xsd:group     |
                                  xsd:all            | xsd:choice    |
                                  xsd:sequence       | xsd:attribute |
                                  xsd:attributeGroup | xsd:anyAttribute" />
  </xslt:template>

  <!--
      Displays an enumeration in a table...
  -->
  <xslt:template name="DisplayEnumeration">
    <xslt:param name="enum" select="." />
    <td>
      <div class="Enum">
        <div class="EnumValue">
          <xslt:value-of select="$enum/@value"/>
          <xslt:if test="$enum/@id">
            <xslt:text> (id = </xslt:text>
            <xslt:value-of select="$enum/@id"/>
            <xslt:text>)</xslt:text>
          </xslt:if>
        </div>
        <xslt:if test="$enum/xsd:annotation/xsd:documentation">
          <div class="EnumDoc">
            <xslt:apply-templates select="$enum/xsd:annotation/xsd:documentation/*" mode="Docs"/>
          </div>
        </xslt:if>
      </div>
    </td>
  </xslt:template>

  <!--
      A Simple restriction in a table fragment.
  -->
  <xslt:template name="DisplaySimpleRestriction">
    <xslt:param name="restriction" select="." />
    <td>
      <xslt:value-of select="$restriction/@value"/>
      <xslt:if test="$restriction/@id">
        <xslt:text> (id = </xslt:text>
        <xslt:value-of select="$restriction/@id"/>
        <xslt:text>)</xslt:text>
      </xslt:if>
      <xslt:if test="$restriction/@fixed = 'true'">
        <xslt:text> (fixed)</xslt:text>
      </xslt:if>
    </td>
    <xslt:if test="$restriction/xsd:annotation/xsd:documentation">
      <td>
        <xslt:apply-templates select="$restriction/xsd:annotation/xsd:documentation/*" mode="Docs"/>
      </td>
    </xslt:if>
  </xslt:template>

  <!-- Catch all for the missed elements -->
  <xslt:template match="xsd:*">
    <xslt:if test="local-name(.) != 'annotation'">
      <div class="SubElementName">
        <xslt:value-of select="local-name(.)"/>
      </div>
      <xslt:call-template name="AttribsAndDocs" />
      <div class="SubElementContent">
        <xslt:apply-templates />
      </div>
    </xslt:if>
  </xslt:template>

  <xslt:template match="xsd:attribute">
    <xslt:call-template name="SubItem">
      <xslt:with-param name="name">
        <xslt:choose>
          <xslt:when test="@name">
            <xslt:call-template name="StringToAttributeName">
              <xslt:with-param name="inString" select="@name"/>
            </xslt:call-template>
          </xslt:when>
          <xslt:when test="@ref">
            <xslt:variable name="attribName" select="substring-after(@ref,':')"/>
            <xslt:call-template name="StringToAttributeName">
              <xslt:with-param name="inString" select="$attribName"/>
            </xslt:call-template>
          </xslt:when>
        </xslt:choose>
      </xslt:with-param>
    </xslt:call-template>
  </xslt:template>

  <!-- ignore other text -->
  <xslt:template match="text()" />

  <!-- Convert a string to a name -->
  <xslt:template name="StringToName">
    <xslt:param name="inString" select="@name" />
    <xslt:param name="inNode" select="." />

    <xslt:choose>
      <!-- element names handled with StringToElementName -->
      <xslt:when test="(local-name($inNode) = 'element') and
                       (namespace-uri($inNode) = $schemaNamespace)
                       ">
        <xslt:call-template name="StringToElementName">
          <xslt:with-param name="inString" select="$inString"/>
        </xslt:call-template>
      </xslt:when>

      <!-- attribute names handled with StringToAttributeName -->
      <xslt:when test="(local-name($inNode) = 'attribute') and
                       (namespace-uri($inNode) = $schemaNamespace)
                       ">
        <xslt:call-template name="StringToAttributeName">
          <xslt:with-param name="inString" select="$inString"/>
        </xslt:call-template>
      </xslt:when>

      <xslt:otherwise>
        <xslt:value-of select="@name"/>
      </xslt:otherwise>
    </xslt:choose>
  </xslt:template>

  <!-- Convert a string to an element name -->
  <xslt:template name="StringToElementName">
    <xslt:param name="inString" />
    <xslt:text>&lt;</xslt:text>
    <xslt:value-of select="$inString" />
    <xslt:text>&gt;</xslt:text>
  </xslt:template>

  <!-- Convert a string to an attribute name -->
  <xslt:template name="StringToAttributeName">
    <xslt:param name="inString" />
    <xslt:text>@</xslt:text>
    <xslt:value-of select="$inString" />
  </xslt:template>

  <!--
    Convert a string parameter to an escapted Javascript string in
    quotes.
  -->
  <xslt:template name="StringToJavascript">
    <xslt:param name="inString" />
    <!-- quote the string -->
    <xslt:variable name="quotedString"
                   select="concat($dQuote,translate($inString,$dQuote,$sQuote),$dQuote)"/>
    <!-- replace linefeeds with \n -->
    <xslt:variable name="lfString">
      <xslt:call-template name="ReplaceText">
        <xslt:with-param name="inString" select="$quotedString"/>
        <xslt:with-param name="searchString" select="'&#x0a;'"/>
        <xslt:with-param name="replaceString" select="'\n'"/>
      </xslt:call-template>
    </xslt:variable>
    <!-- replace tabs with 5 spaces -->
    <xslt:variable name="tabString">
      <xslt:call-template name="ReplaceText">
        <xslt:with-param name="inString" select="$lfString"/>
        <xslt:with-param name="searchString" select="'&#x09;'"/>
        <xslt:with-param name="replaceString" select="'     '"/>
      </xslt:call-template>
    </xslt:variable>
    <!-- remove carrige returns -->
    <xslt:variable name="crString" select="translate($tabString,'&#x0d;','')"/>
    <!-- replace < with unicode sequence -->
    <xslt:variable name="ltString">
      <xslt:call-template name="ReplaceText">
        <xslt:with-param name="inString" select="$crString"/>
        <xslt:with-param name="searchString" select="'&#x3c;'"/>
        <xslt:with-param name="replaceString" select="'\u003c'"/>
      </xslt:call-template>
    </xslt:variable>
    <!-- replace > with unicode sequence -->
    <xslt:variable name="gtString">
      <xslt:call-template name="ReplaceText">
        <xslt:with-param name="inString" select="$ltString"/>
        <xslt:with-param name="searchString" select="'&#x3e;'"/>
        <xslt:with-param name="replaceString" select="'\u003e'"/>
      </xslt:call-template>
    </xslt:variable>
    <xslt:value-of select="$gtString"/>
  </xslt:template>

  <!--
     Simple search and replace
  -->
  <xslt:template name="ReplaceText">
    <xslt:param name="inString" />
    <xslt:param name="searchString"/>
    <xslt:param name="replaceString"/>

    <xslt:choose>
      <xslt:when test="$searchString and
                       contains($inString, $searchString)">
        <xslt:value-of select="substring-before($inString, $searchString)"/>
        <xslt:value-of select="$replaceString"/>
        <xslt:call-template name="ReplaceText">
          <xslt:with-param name="inString" select="substring-after($inString, $searchString)"/>
          <xslt:with-param name="searchString" select="$searchString"/>
          <xslt:with-param name="replaceString" select="$replaceString"/>
        </xslt:call-template>
      </xslt:when>
      <xslt:otherwise>
        <xslt:value-of select="$inString"/>
      </xslt:otherwise>
    </xslt:choose>
  </xslt:template>
</xslt:stylesheet>
