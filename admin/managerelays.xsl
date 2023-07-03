<xsl:stylesheet xmlns:xsl = "http://www.w3.org/1999/XSL/Transform" version = "1.0" >
<xsl:output method="xml" media-type="text/html" indent="yes" encoding="UTF-8"
    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
    doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN" />

<xsl:template match = "/icerelaystats" >
<html>
<head>
<title>Icecast Streaming Media Server</title>
<link rel="stylesheet" type="text/css" href="../style.css" />
</head>
<body>

<div class="main">

<div class="roundcont">
<div class="roundtop">

</div>
<div class="newscontent">
<xsl:for-each select="relay">
<h3>Mount
<xsl:value-of select="localmount" />
<xsl:choose>
<xsl:when test = "enable!='0'">
    (<a href="managerelays.xsl?relay={localmount}&amp;enable=0">disable</a>)
</xsl:when>
<xsl:otherwise>
    (<a href="managerelays.xsl?relay={localmount}&amp;enable=1">enable</a>)
</xsl:otherwise>
</xsl:choose>
</h3>
    <p>
    <xsl:choose>
        <xsl:when test="enable">Enabled</xsl:when>
        <xsl:otherwise>Disabled</xsl:otherwise>
    </xsl:choose>
    <xsl:if test="on_demand=1" >, On Demand</xsl:if>
    <xsl:if test="from_master=1" >, Slave Relay</xsl:if>
    <xsl:if test="run_on > 0" >
        <td class="streamdata">, run on for <xsl:value-of select="run_on" />s</td>
    </xsl:if>
</p>
<br />
<table border="0" cellpadding="4">
    <xsl:for-each select="master">
    <tr><td></td></tr>
    <tr>
        <xsl:if test="active" >
        <xsl:attribute name="style">background-color: green</xsl:attribute>
        </xsl:if>
        <th>Host (priority <xsl:value-of select="priority" />) </th>
        <td class="streamdata"> <xsl:value-of select="server" />,</td>
        <td class="streamdata"> Port <xsl:value-of select="port" />,</td>
        <td class="streamdata"> <xsl:value-of select="mount" /></td>
        </tr>
    </xsl:for-each>
</table>
<br />
<br></br>
</xsl:for-each>
<xsl:text disable-output-escaping="yes">&amp;</xsl:text>nbsp;
</div>
<div class="roundbottom">

</div>
</div>
<div class="poster">Support icecast development at <a class="nav" href="http://www.icecast.org">www.icecast.org</a></div>
</div>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
