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
     The registers are not used by groff 1.23. The stylesheet ends it with .br, which is left out: every
     caller breaks the line before it already (.sp, or .RS, which sets the indentation), and mandoc warns
     "skipping paragraph macro: br after sp" for the titles of tables. -->
<xsl:template name="pinch.together">
  <xsl:text>.if d an-trap .it 1 an-trap&#10;</xsl:text>
  <xsl:text>.nr an-no-space-flag 1&#10;</xsl:text>
  <xsl:text>.nr an-break-flag 1&#10;</xsl:text>
</xsl:template>

<!-- The stylesheet starts every paragraph, entry of a variable list and example with .PP, also the first
     thing of a section, right after its .SH or .SS heading, where groff and mandoc ignore it, and mandoc
     warns "skipping paragraph macro: PP after SH" (or SS): leave it out there. first.in.section tells
     whether the node is the first thing of a section, after its title, also inside a variable list without
     a title that is. -->
<xsl:template name="first.in.section">
  <xsl:param name="node" select="."/>
  <xsl:choose>
    <xsl:when test="$node/preceding-sibling::*[not(self::title or self::subtitle or self::titleabbrev or
                                                   self::info or self::refsect1info or self::refsect2info or
                                                   self::refsect3info or self::refsectioninfo or
                                                   self::refsynopsisdivinfo)]"/>
    <xsl:when test="$node/parent::refsect1 or $node/parent::refsect2 or $node/parent::refsect3 or
                    $node/parent::refsection or $node/parent::refsynopsisdiv">1</xsl:when>
    <xsl:when test="$node/parent::variablelist[not(title)]">
      <xsl:call-template name="first.in.section">
        <xsl:with-param name="node" select="$node/.."/>
      </xsl:call-template>
    </xsl:when>
  </xsl:choose>
</xsl:template>

<xsl:template match="para">
  <xsl:variable name="first">
    <xsl:call-template name="first.in.section"/>
  </xsl:variable>
  <xsl:choose>
    <xsl:when test="$first = '1'">
      <xsl:call-template name="mixed-block"/>
      <xsl:text>&#10;</xsl:text>
    </xsl:when>
    <xsl:otherwise>
      <xsl:apply-imports/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template match="varlistentry|example|figure">
  <xsl:variable name="first">
    <xsl:call-template name="first.in.section"/>
  </xsl:variable>
  <xsl:choose>
    <xsl:when test="$first = '1'">
      <xsl:variable name="output">
        <xsl:apply-imports/>
      </xsl:variable>
      <xsl:value-of select="substring-after($output, '.PP&#10;')"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:apply-imports/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<!-- troff takes a period at the end of an input line for the end of a sentence, and puts two spaces after
     it. The stylesheet ends a line before markup, so that "e.g." and "i.e." end one whenever markup follows
     them, and render with two spaces, e.g. "a time span with a unit, e.g.  500ms". After the other
     substitutions, put \& after their last period where they end a line, which troff then does not take
     for the end of a sentence. -->
<xsl:param name="man.string.subst.map.local.post">
  <substitution oldstring="e\&amp;.g\&amp;.&#10;" newstring="e\&amp;.g\&amp;.\&amp;&#10;"/>
  <substitution oldstring="i\&amp;.e\&amp;.&#10;" newstring="i\&amp;.e\&amp;.\&amp;&#10;"/>
</xsl:param>

<!-- The same for code-like inline elements whose text ends with a period, a question mark or an exclamation
     mark, e.g. the path component <literal>..</literal>, the prefix <literal>rd.</literal> or the glob
     <literal>?</literal>: followed by more text, they end an input line, and troff would take that character,
     which is part of them, for the end of a sentence. Put \& after them; a period after them that does end a
     sentence still does. -->
<xsl:template match="*[self::literal or self::varname or self::filename or self::option or self::constant or
                       self::command or self::replaceable or self::code or self::envar or self::systemitem or
                       self::uri or self::userinput or self::computeroutput or self::parameter or
                       self::function or self::type or self::property]
                      [contains('.?!', substring(., string-length(.)))][string-length(.) &gt; 0]">
  <xsl:apply-imports/>
  <xsl:text>\&amp;</xsl:text>
</xsl:template>

<!-- The stylesheet writes a page with ".so man<section>/<page>" for every further name of a page, e.g.
     udev.conf.d(5) of udev.conf(5), which works only below a man<section> directory, and which mandoc calls
     fragile. Write none: man/Makefile.am installs the further names as symbolic links instead. -->
<xsl:template name="write.stubs"/>

</xsl:stylesheet>
