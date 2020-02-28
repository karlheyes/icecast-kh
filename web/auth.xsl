<xsl:stylesheet xmlns:xsl = "http://www.w3.org/1999/XSL/Transform" version = "1.0" >
<xsl:output method="xml" media-type="text/html" indent="yes" encoding="UTF-8"
    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
    doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN" />

<xsl:template match = "/icestats" >
<html>
<head>
<title>Icecast Streaming Media Server</title>
<link rel="stylesheet" type="text/css" href="style.css" />
</head>

<body>

<div class="main">

<table border="0" width="100%">
<tr>
<td>
<div class="roundcont">
<div class="roundtop">

</div>

<div class="newscontent">
<xsl:for-each select="source">
<xsl:if test="authenticator">
<h3><xsl:if test="server_name"><xsl:value-of select="server_name" /> </xsl:if>
(<xsl:value-of select="@mount" />)</h3>
<form method="GET" action="/admin/buildm3u">
<table border="0" cellpadding="4">
<tr><td>Username :</td> <td> <input type="text" name="username"/></td></tr>
<tr><td>Password :</td> <td> <input type="password" name="password"/></td></tr>
<tr><td></td></tr>
<tr><td><input type="Submit" value="Login"/></td></tr>
</table>
<input type="hidden" name="mount" value="{@mount}"/>
</form>
</xsl:if>
<br></br>
<br></br>
</xsl:for-each>
<xsl:text disable-output-escaping="yes">&amp;</xsl:text>nbsp;
</div>
<div class="roundbottom">

</div>
</div>
<br></br><br></br>
</td>
</tr>
</table>
<div class="poster">
Support Icecast development at <a target="_blank" href="http://www.icecast.org">www.icecast.org</a>
</div>
</div>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
