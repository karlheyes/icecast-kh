<xsl:stylesheet xmlns:xsl = "http://www.w3.org/1999/XSL/Transform" version = "1.0" >
<xsl:output method="xml" media-type="text/html" indent="yes" encoding="UTF-8"
    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
    doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN" />

<xsl:template match = "/icestats" >
<html>
<head>
<title>Icecast Streaming Media Server</title>
<link rel="stylesheet" type="text/css" href="/style.css" />
</head>
<body bgcolor="#000" topmargin="0" leftmargin="0" rightmargin="0" bottommargin="0">

<div class="main">

<br />

<!--global server stats-->
<div class="roundcont">
<div class="roundtop">

</div>
<div class="newscontent">
<h3>Global Server Stats</h3>
<table border="0" cellpadding="4">
<xsl:for-each select="/icestats">
<xsl:for-each select="*">
<xsl:if test = "name()!='source'"> 
<tr>
	<td width="130"><xsl:value-of select="name()" /></td>
	<td class="streamdata"><xsl:value-of select="." /></td>
</tr>
</xsl:if>
</xsl:for-each>
</xsl:for-each>
</table>
</div>
<div class="roundbottom">

</div>
</div>
<br />
<br />
<!--end global server stats-->

<!--mount point stats-->
<xsl:for-each select="source">
<div class="roundcont">
<div class="roundtop">

</div>
<div class="newscontent">
<div class="streamheader">
    <table cellspacing="0" cellpadding="0">
        <colgroup align="left" />
        <colgroup align="right" width="300" />
        <tr>
            <td><h3>Mount Point <xsl:value-of select="@mount" /></h3></td>
            <xsl:choose>
                <xsl:when test="authenticator">
                    <td align="right"><a class="auth" href="/auth.xsl">Login</a></td>
                </xsl:when>
                <xsl:otherwise>
                    <td align="right"> <a href="{@mount}.m3u">M3U</a> <a href="{@mount}.xspf">XSPF</a></td>
                </xsl:otherwise>
            </xsl:choose>
    </tr></table>
</div>

	<table border="0" cellpadding="1" cellspacing="5" bgcolor="444444">
	<tr>        
	    <td align="center">
		    <a class="nav2" href="listclients.xsl?mount={@mount}">List Clients</a>
        	<a class="nav2" href="moveclients.xsl?mount={@mount}">Move Listeners</a>
        	<a class="nav2" href="updatemetadata.xsl?mount={@mount}">Update Metadata</a>
        	<a class="nav2" href="killsource.xsl?mount={@mount}">Kill Source</a>
                <xsl:if test="authenticator"><a class="nav2" href="manageauth.xsl?mount={@mount}">Manage Authentication</a></xsl:if>
	    </td></tr>
	</table>
<br />
<table cellpadding="5" cellspacing="0" border="0">
	<xsl:for-each select="*">
    <xsl:choose>
    <xsl:when test="name()='listener'"></xsl:when>
    <xsl:otherwise>
	<tr>
		<td width="130"><xsl:value-of select="name()" /></td>
		<td class="streamdata"><xsl:value-of select="." /></td>
	</tr>
    </xsl:otherwise>
    </xsl:choose>
	</xsl:for-each>
</table>
</div>
<div class="roundbottom">

</div>
</div>
<br />
<br />
</xsl:for-each>
<xsl:text disable-output-escaping="yes">&amp;</xsl:text>nbsp;

<!--end mount point stats-->
<div class="poster">Support icecast development at <a class="nav" href="http://www.icecast.org">www.icecast.org</a></div>
</div>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
