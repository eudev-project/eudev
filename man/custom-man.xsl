<?xml version='1.0'?> <!--*-nxml-*-->

<!--
  SPDX-License-Identifier: LGPL-2.1-or-later
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:exsl="http://exslt.org/common"
                extension-element-prefixes="exsl"
                version="1.0">

<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl"/>

<xsl:template name="top.comment" />

<!-- The admonitions (note, warning ...) and the titles of tables "pinch together" the line after the title
     with the input trap of the man macros of groff before 1.23, an-trap. groff 1.23 calls it an-input-trap,
     and warns "macro 'an-trap' not defined" (lintian: groff-message): call it only where it is defined.
     The registers are not used by groff 1.23. -->
<xsl:template name="pinch.together">
  <xsl:text>.if d an-trap .it 1 an-trap&#10;</xsl:text>
  <xsl:text>.nr an-no-space-flag 1&#10;</xsl:text>
  <xsl:text>.nr an-break-flag 1&#10;</xsl:text>
  <xsl:text>.br&#10;</xsl:text>
</xsl:template>

</xsl:stylesheet>
