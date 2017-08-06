function loginbox(anchor) {
    document.domain = "csdn.net";
    var $logpop = $("#pop_win");
    var iframeUrlParm ="";
    if (anchor != null && anchor != undefined && anchor != "")
    {
        iframeUrlParm = "?anchor=" + anchor;
    }
    $logpop.html('<iframe src="https://passport.csdn.net/account/loginbox?service=http://static.blog.csdn.net/callback.htm' + iframeUrlParm + '" frameborder="0" height="600" width="400" scrolling="no"></iframe>');

    $('#popup_mask').css({
        opacity: 0.5,
        width: $(document).width() + 'px',
        height: $(document).height() + 'px'
    });
    $('#popup_mask').css("display", "block");

    $logpop.css({
        top: ($(window).height() - $logpop.height()) / 2 + $(window
   ).scrollTop() + 'px',
        left: ($(window).width() - $logpop.width()) / 2
    });

    setTimeout(function () {
        $logpop.show();
        $logpop.css({
            opacity: 1
        });
    }, 200);

    $('#popup_mask').unbind("click");
    $('#popup_mask').bind("click", function () {
        $('#popup_mask').hide();
        var $clopop = $("#pop_win");
        $("#common_ask_div_sc").css("display", "none");
        $clopop.css({
            opacity: 0
        });
        setTimeout(function () {
            $clopop.hide();
        }, 350);
        return false;
    });
}

function getUN() {
    var m = document.cookie.match(new RegExp("(^| )UserName=([^;]*)(;|$)"));
    if (m)
        return m[2];
    else
        return '';
}

function getQueryString(name) {
    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i");
    var r = window.location.search.substr(1).match(reg);
    if (r != null) return unescape(r[2]); return null;
}

function setCopyBtn() {
    $('.CopyToClipboard').each(function () {
        var clip = new ZeroClipboard.Client();
        clip.setHandCursor(true);
        clip.addEventListener('load', function (client) {
        });
        clip.addEventListener('mouseOver', function (client) {
            //var _c_ode = client.movie.parentNode.parentNode.parentNode.parentNode.nextSibling.innerHTML;
            var _c_ode = client.movie.parentNode.parentNode.parentNode.parentNode.parentNode.nextSibling.innerHTML;
            _c_ode = _c_ode.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
            client.setText(_c_ode);
        });
        clip.addEventListener('complete', function (client, text) {
            alert("代码已经复制到你的剪贴板。");
        });
        clip.glue(this, this.parentNode);
    });
}

/*SyntaxHighlighter/shCore-src.js*/
var a, dp = { sh: { Toolbar: {}, Utils: {}, RegexLib: {}, Brushes: {}, Strings: { AboutDialog: '<html><head><title>About...</title></head><body class="dp-about"><table cellspacing="0"><tr><td class="copy"><p class="title">dp.SyntaxHighlighter</div><div class="para">Version: {V}</p><p><a href="http://www.dreamprojections.com/syntaxhighlighter/?ref=about" target="_blank">http://www.dreamprojections.com/syntaxhighlighter</a></p>&copy;2004-2007 Alex Gorbatchev.</td></tr><tr><td class="footer"><input type="button" class="close" value="OK" onClick="window.close()"/></td></tr></table></body></html>' }, ClipboardSwf: 'http://static.blog.csdn.net/scripts/ZeroClipboard/ZeroClipboard.swf', Version: "1.5.1" } };
dp.SyntaxHighlighter = dp.sh;
dp.sh.Toolbar.Commands = {
    ExpandSource: {
        label: "+ expand source", check: function (b) {
            return b.collapse
        }, func: function (b, c) {
            b.parentNode.removeChild(b);
            c.div.className = c.div.className.replace("collapsed", "");
        }
    }, ViewSource: {
        label: "view plain", func: function (b, c) {
            b = dp.sh.Utils.FixForBlogger(c.originalCode).replace(/</g, "&lt;");
            c = window.open("", "_blank", "width=750, height=400, location=0, resizable=1, menubar=0, scrollbars=0");
            c.document.write('<textarea style="width:99%;height:99%">' + b + "</textarea>");
            c.document.close();
        }
    }, CopyToClipboard: {
        label: "copy", check: function () {
            return window.clipboardData != null || dp.sh.ClipboardSwf != null
        }, func: function (b, c) {
            b = dp.sh.Utils.FixForBlogger(c.originalCode).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
            if (window.clipboardData)
                window.clipboardData.setData("text", b);
            else if (dp.sh.ClipboardSwf != null) {
                var d = c.flashCopier;
                if (d == null) {
                    d = document.createElement("div");
                    c.flashCopier = d;
                    c.div.appendChild(d);
                }
                d.innerHTML = '<embed src="' + dp.sh.ClipboardSwf + '" FlashVars="clipboard=' + encodeURIComponent(b) + '" width="0" height="0" type="application/x-shockwave-flash"></embed>';
            }
            alert("The code is in your clipboard now");
        }
    }, PrintSource: {
        label: "print", func: function (b, c) {
            b = document.createElement("IFRAME");
            var d = null;
            b.style.cssText = "position:absolute;width:0px;height:0px;left:-500px;top:-500px;";
            document.body.appendChild(b);
            d = b.contentWindow.document;
            dp.sh.Utils.CopyStyles(d, window.document);
            d.write('<div class="' + c.div.className.replace("collapsed", "") + ' printing">' + c.div.innerHTML + "</div>");
            d.close();
            b.contentWindow.focus();
            b.contentWindow.print();
            alert("Printing...");
            document.body.removeChild(b);
        }
    }, About: {
        label: "?", func: function () {
            var b = window.open("", "_blank", "dialog,width=300,height=150,scrollbars=0"), c = b.document;
            dp.sh.Utils.CopyStyles(c, window.document);
            c.write(dp.sh.Strings.AboutDialog.replace("{V}", dp.sh.Version));
            c.close();
            b.focus()
        }
    }
};
dp.sh.Toolbar.Create = function (b) {
    var _code = b.source.className;
    var c = document.createElement("DIV");
    c.className = "tools";
    c.innerHTML = '<b>[' + _code + ']</b> ';
    for (var d in dp.sh.Toolbar.Commands) {
        var f = dp.sh.Toolbar.Commands[d];
        //   f.check != null && !f.check(b) || (c.innerHTML += '<a href="#" class="' + d + '" title="' + f.label + '" onclick="dp.sh.Toolbar.Command(\'' + d + "',this);return false;\">" + f.label + "</a>")
        if (f.label == "print") {
            f.check != null && !f.check(b) || (c.innerHTML += '<span class="tracking-ad" data-mod="popu_169"> <a href="#" class="' + d + '" title="' + f.label + '" onclick="dp.sh.Toolbar.Command(\'' + d + "',this);return false;\">" + f.label + "</a></span>")
        }
        else if (f.label == "copy") {
            f.check != null && !f.check(b) || (c.innerHTML += '<span class="tracking-ad" data-mod="popu_168"> <a href="#" class="' + d + '" title="' + f.label + '" onclick="dp.sh.Toolbar.Command(\'' + d + "',this);return false;\">" + f.label + "</a></span>")
        }
        else {
            f.check != null && !f.check(b) || (c.innerHTML += '<a href="#" class="' + d + '" title="' + f.label + '" onclick="dp.sh.Toolbar.Command(\'' + d + "',this);return false;\">" + f.label + "</a>")
        }
    }
    return c;
};
dp.sh.Toolbar.Command = function (b, c) {
    for (var d = c; d != null && d.className.indexOf("dp-highlighter") == -1;)
        d = d.parentNode;
    d != null && dp.sh.Toolbar.Commands[b].func(c, d.highlighter)
};
dp.sh.Utils.CopyStyles = function (b, c) {
    c = c.getElementsByTagName("link");
    for (var d = 0; d < c.length; d++)
        c[d].rel.toLowerCase() == "stylesheet" && b.write('<link type="text/css" rel="stylesheet" href="' + c[d].href + '"></link>')
};
dp.sh.Utils.FixForBlogger = function (b) {
    return dp.sh.isBloggerMode == true ? b.replace(/<br\s*\/?>|&lt;br\s*\/?&gt;/gi, "\n") : b
};
dp.sh.RegexLib = { MultiLineCComments: new RegExp("/\\*[\\s\\S]*?\\*/", "gm"), SingleLineCComments: new RegExp("//.*$", "gm"), SingleLinePerlComments: new RegExp("#.*$", "gm"), DoubleQuotedString: new RegExp('"(?:\\.|(\\\\\\")|[^\\""\\n])*"', "g"), SingleQuotedString: new RegExp("'(?:\\.|(\\\\\\')|[^\\''\\n])*'", "g") };
dp.sh.Match = function (b, c, d) {
    this.value = b;
    this.index = c;
    this.length = b.length;
    this.css = d
};
dp.sh.Highlighter = function () {
    this.noGutter = false;
    this.addControls = true;
    this.collapse = false;
    this.tabsToSpaces = true;
    this.wrapColumn = 80;
    this.showColumns = true
};
dp.sh.Highlighter.SortCallback = function (b, c) {
    if (b.index < c.index)
        return -1;
    else if (b.index > c.index)
        return 1;
    else if (b.length < c.length)
        return -1;
    else if (b.length > c.length)
        return 1;
    return 0
};
a = dp.sh.Highlighter.prototype;
a.CreateElement = function (b) {
    b = document.createElement(b);
    b.highlighter = this;
    return b
};
a.GetMatches = function (b, c) {
    for (var d = null; (d = b.exec(this.code)) != null;)
        this.matches[this.matches.length] = new dp.sh.Match(d[0], d.index, c)
};
a.AddBit = function (b, c) {
    if (!(b == null || b.length == 0)) {
        var d = this.CreateElement("SPAN");
        b = b.replace(/ /g, "&nbsp;");
        b = b.replace(/</g, "&lt;");
        b = b.replace(/(\r?\n)|(\[BR\])/gm, "&nbsp;<br>");
        if (c != null)
            if (/br/gi.test(b)) {
                b = b.split("&nbsp;<br>");
                for (var f = 0; f < b.length; f++) {
                    d = this.CreateElement("SPAN");
                    d.className = c;
                    d.innerHTML = b[f];
                    this.div.appendChild(d);
                    f + 1 < b.length && this.div.appendChild(this.CreateElement("BR"))
                }
            } else {
                d.className = c;
                d.innerHTML = b;
                this.div.appendChild(d)
            }
        else {
            d.innerHTML = b;
            this.div.appendChild(d)
        }
    }
};
a.IsInside = function (b) {
    if (b == null || b.length == 0)
        return false;
    for (var c = 0; c < this.matches.length; c++) {
        var d = this.matches[c];
        if (d != null)
            if (b.index > d.index && b.index < d.index + d.length)
                return true
    }
    return false
};
a.ProcessRegexList = function () {
    for (var b = 0; b < this.regexList.length; b++)
        this.GetMatches(this.regexList[b].regex, this.regexList[b].css)
};
a.ProcessSmartTabs = function (b) {
    function c(h, e, l) {
        var m = h.substr(0, e);
        h = h.substr(e + 1, h.length);
        e = "";
        for (var i = 0; i < l; i++)
            e += " ";
        return m + e + h
    }
    function d(h, e) {
        if (h.indexOf(p) == -1)
            return h;
        for (var l = 0; (l = h.indexOf(p)) != -1;)
            h = c(h, l, e - l % e);
        return h
    }
    b = b.split("\n");
    for (var f = "", p = "\t", q = 0; q < b.length; q++)
        f += d(b[q], 4) + "\n";
    return f
};
a.SwitchToList = function () {
    var b = this.div.innerHTML.replace(/<(br)\/?>/gi, "\n").split("\n");
    this.addControls == true && this.bar.appendChild(dp.sh.Toolbar.Create(this));
    if (this.showColumns) {
        for (var c = this.CreateElement("div"), d = this.CreateElement("div"), f = 1; f <= 150;)
            if (f % 10 == 0) {
                c.innerHTML += f;
                f += (f + "").length
            } else {
                c.innerHTML += "&middot;";
                f++
            }
        d.className = "columns";
        d.appendChild(c);
        this.bar.appendChild(d)
    }
    f = 0;
    for (c = this.firstLine; f < b.length - 1; f++, c++) {
        d = this.CreateElement("LI");
        var p = this.CreateElement("SPAN");
        d.className = f % 2 == 0 ? "alt" : "";
        p.innerHTML = b[f] + "&nbsp;";
        d.appendChild(p);
        this.ol.appendChild(d)
    }
    this.div.innerHTML = "";
};
a.Highlight = function (b) {
    function c(e) {
        return e.replace(/^\s*(.*?)[\s\n]*$/g, "$1")
    }
    function d(e) {
        return e.replace(/\n*$/, "").replace(/^\n*/, "")
    }
    function f(e) {
        e = dp.sh.Utils.FixForBlogger(e).split("\n");
        for (var l = new RegExp("^\\s*", "g"), m = 1E3, i = 0; i < e.length && m > 0; i++)
            if (c(e[i]).length != 0) {
                var g = l.exec(e[i]);
                if (g != null && g.length > 0)
                    m = Math.min(g[0].length, m)
            }
        if (m > 0)
            for (i = 0; i < e.length; i++)
                e[i] = e[i].substr(m);
        return e.join("\n");
    }
    function p(e, l, m) {
        return e.substr(l, m - l)
    }
    var q = 0;
    if (b == null)
        b = "";
    this.originalCode = b;
    this.code = d(f(b));
    this.div = this.CreateElement("DIV");
    this.bar = this.CreateElement("DIV");
    this.ol = this.CreateElement("OL");
    this.matches = [];
    this.div.className = "dp-highlighter";
    this.div.highlighter = this;
    this.bar.className = "bar";
    this.ol.start = this.firstLine;
    if (this.CssClass != null)
        this.ol.className = this.CssClass;
    if (this.collapse)
        this.div.className += " collapsed";
    if (this.noGutter)
        this.div.className += " nogutter";
    if (this.tabsToSpaces == true)
        this.code = this.ProcessSmartTabs(this.code);
    this.ProcessRegexList();
    if (this.matches.length == 0)
        this.AddBit(this.code, null);
    else {
        this.matches = this.matches.sort(dp.sh.Highlighter.SortCallback);
        for (b = 0; b < this.matches.length; b++)
            if (this.IsInside(this.matches[b]))
                this.matches[b] = null;
        for (b = 0; b < this.matches.length; b++) {
            var h = this.matches[b];
            if (!(h == null || h.length == 0)) {
                this.AddBit(p(this.code, q, h.index), null);
                this.AddBit(h.value, h.css);
                q = h.index + h.length
            }
        }
        this.AddBit(this.code.substr(q), null)
    }
    this.SwitchToList();
    this.div.appendChild(this.bar);
    this.div.appendChild(this.ol)
};
a.GetKeywords = function (b) {
    return "\\b" + b.replace(/ /g, "\\b|\\b") + "\\b"
};
dp.sh.BloggerMode = function () {
    dp.sh.isBloggerMode = true
};
dp.sh.HighlightAll = function (b, c, d, f, p, q) {
    function h() {
        for (var k = arguments, j = 0; j < k.length; j++)
            if (k[j] != null) {
                if (typeof k[j] == "string" && k[j] != "")
                    return k[j] + "";
                if (typeof k[j] == "object" && k[j].value != "")
                    return k[j].value + ""
            }
        return null
    }
    function e(k, j) {
        for (var o = 0; o < j.length; o++)
            if (j[o] == k)
                return true;
        return false
    }
    function l(k, j, o) {
        k = new RegExp("^" + k + "\\[(\\w+)\\]$", "gi");
        for (var s = null, u = 0; u < j.length; u++)
            if ((s = k.exec(j[u])) != null)
                return s[1];
        return o
    }
    function m(k, j, o) {
        o = document.getElementsByTagName(o);
        for (var s = 0; s < o.length; s++) {
            o[s].getAttribute("name") == j && k.push(o[s]);
        }
    }
    var i = [], g = null, v = {};
    m(i, b, "pre");
    m(i, b, "textarea");
    if (i.length != 0) {
        for (var n in dp.sh.Brushes) {
            g = dp.sh.Brushes[n].Aliases;
            if (g != null)
                for (b = 0; b < g.length; b++)
                    v[g[b]] = n
        }
        for (b = 0; b < i.length; b++) {
            n = i[b];
            var r = h(n.attributes["class"], n.className, n.attributes.language, n.language);
            g = "";
            if (r != null) {
                r = r.split(":");
                g = r[0].toLowerCase();
                if (v[g] != null) {
                    g = new dp.sh.Brushes[v[g]];
                    n.style.display = "none";
                    g.noGutter = c == null ? e("nogutter", r) : !c;
                    g.addControls = d == null ? !e("nocontrols", r) : d;
                    g.collapse = f == null ? e("collapse", r) : f;
                    g.showColumns = q == null ? e("showcolumns", r) : q;
                    var w = document.getElementsByTagName("head")[0];
                    if (g.Style && w) {
                        var t = document.createElement("style");
                        t.setAttribute("type", "text/css");
                        if (t.styleSheet)
                            t.styleSheet.cssText = g.Style;
                        else {
                            var x = document.createTextNode(g.Style);
                            t.appendChild(x)
                        }
                        w.appendChild(t);
                    }
                    g.firstLine = p == null ? parseInt(l("firstline", r, 1)) : p;
                    g.source = n;
                    g.Highlight(n.innerHTML);
                    g.div.className += " bg_" + n.className;
                    n.parentNode.insertBefore(g.div, n);
                }
            }
        }
    }
};
dp.sh.Brushes.Xml = function () {
    this.CssClass = "dp-xml";
    this.Style = ""
};
dp.sh.Brushes.Xml.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Xml.Aliases = ["xml", "xhtml", "xslt", "html", "xhtml"];
dp.sh.Brushes.Xml.prototype.ProcessRegexList = function () {
    function c(d, e) {
        d[d.length] = e
    }
    var a = null, b = null;
    this.GetMatches(new RegExp("(&lt;|<)\\!\\[[\\w\\s]*?\\[(.|\\s)*?\\]\\](&gt;|>)", "gm"), "cdata");
    this.GetMatches(new RegExp("(&lt;|<)!--\\s*.*?\\s*--(&gt;|>)", "gm"), "comments");
    for (b = new RegExp("([:\\w-.]+)\\s*=\\s*(\".*?\"|'.*?'|\\w+)*|(\\w+)", "gm") ; (a = b.exec(this.code)) != null;)
        if (a[1] != null) {
            c(this.matches, new dp.sh.Match(a[1], a.index, "attribute"));
            a[2] != undefined && c(this.matches, new dp.sh.Match(a[2], a.index + a[1].length + a[0].substr(a[1].length).indexOf(a[2]), "attribute-value"))
        }
    this.GetMatches(new RegExp("(&lt;|<)/*\\?*(?!\\!)|/*\\?*(&gt;|>)", "gm"), "tag");
    for (b = new RegExp("(?:&lt;|<)/*\\?*\\s*([:\\w-.]+)", "gm") ; (a = b.exec(this.code)) != null;)
        c(this.matches, new dp.sh.Match(a[1], a.index + a[0].indexOf(a[1]), "tag-name"))
};
dp.sh.Brushes.Vb = function () {
    this.regexList = [{ regex: new RegExp("'.*$", "gm"), css: "comment" }, { regex: dp.sh.RegexLib.DoubleQuotedString, css: "string" }, { regex: new RegExp("^\\s*#.*", "gm"), css: "preprocessor" }, { regex: new RegExp(this.GetKeywords("AddHandler AddressOf AndAlso Alias And Ansi As Assembly Auto Boolean ByRef Byte ByVal Call Case Catch CBool CByte CChar CDate CDec CDbl Char CInt Class CLng CObj Const CShort CSng CStr CType Date Decimal Declare Default Delegate Dim DirectCast Do Double Each Else ElseIf End Enum Erase Error Event Exit False Finally For Friend Function Get GetType GoSub GoTo Handles If Implements Imports In Inherits Integer Interface Is Let Lib Like Long Loop Me Mod Module MustInherit MustOverride MyBase MyClass Namespace New Next Not Nothing NotInheritable NotOverridable Object On Option Optional Or OrElse Overloads Overridable Overrides ParamArray Preserve Private Property Protected Public RaiseEvent ReadOnly ReDim REM RemoveHandler Resume Return Select Set Shadows Shared Short Single Static Step Stop String Structure Sub SyncLock Then Throw To True Try TypeOf Unicode Until Variant When While With WithEvents WriteOnly Xor"), "gm"), css: "keyword" }];
    this.CssClass = "dp-vb"
};
dp.sh.Brushes.Vb.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Vb.Aliases = ["vb", "vb.net"];
dp.sh.Brushes.Sql = function () {
    this.regexList = [{ regex: new RegExp("--(.*)$", "gm"), css: "comment" }, { regex: dp.sh.RegexLib.DoubleQuotedString, css: "string" }, { regex: dp.sh.RegexLib.SingleQuotedString, css: "string" }, { regex: new RegExp(this.GetKeywords("abs avg case cast coalesce convert count current_timestamp current_user day isnull left lower month nullif replace right session_user space substring sum system_user upper user year"), "gmi"), css: "func" }, { regex: new RegExp(this.GetKeywords("all and any between cross in join like not null or outer some"), "gmi"), css: "op" }, { regex: new RegExp(this.GetKeywords("absolute action add after alter as asc at authorization begin bigint binary bit by cascade char character check checkpoint close collate column commit committed connect connection constraint contains continue create cube current current_date current_time cursor database date deallocate dec decimal declare default delete desc distinct double drop dynamic else end end-exec escape except exec execute false fetch first float for force foreign forward free from full function global goto grant group grouping having hour ignore index inner insensitive insert instead int integer intersect into is isolation key last level load local max min minute modify move name national nchar next no numeric of off on only open option order out output partial password precision prepare primary prior privileges procedure public read real references relative repeatable restrict return returns revoke rollback rollup rows rule schema scroll second section select sequence serializable set size smallint static statistics table temp temporary then time timestamp to top transaction translation trigger true truncate uncommitted union unique update values varchar varying view when where with work"), "gmi"), css: "keyword" }];
    this.CssClass = "dp-sql";
    this.Style = ""
};
dp.sh.Brushes.Sql.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Sql.Aliases = ["sql"];
dp.sh.Brushes.Ruby = function () {
    this.regexList = [{ regex: dp.sh.RegexLib.SingleLinePerlComments, css: "comment" }, { regex: dp.sh.RegexLib.DoubleQuotedString, css: "string" }, { regex: dp.sh.RegexLib.SingleQuotedString, css: "string" }, { regex: new RegExp(":[a-z][A-Za-z0-9_]*", "g"), css: "symbol" }, { regex: new RegExp("(\\$|@@|@)\\w+", "g"), css: "variable" }, { regex: new RegExp(this.GetKeywords("alias and BEGIN begin break case class def define_method defined do each else elsif END end ensure false for if in module new next nil not or raise redo rescue retry return self super then throw true undef unless until when while yield"), "gm"), css: "keyword" }, { regex: new RegExp(this.GetKeywords("Array Bignum Binding Class Continuation Dir Exception FalseClass File::Stat File Fixnum Fload Hash Integer IO MatchData Method Module NilClass Numeric Object Proc Range Regexp String Struct::TMS Symbol ThreadGroup Thread Time TrueClass"), "gm"), css: "builtin" }];
    this.CssClass = "dp-rb";
    this.Style = ""
};
dp.sh.Brushes.Ruby.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Ruby.Aliases = ["ruby", "rails", "ror"];
dp.sh.Brushes.Python = function () {
    this.regexList = [{ regex: dp.sh.RegexLib.SingleLinePerlComments, css: "comment" }, { regex: new RegExp("^\\s*@\\w+", "gm"), css: "decorator" }, { regex: new RegExp("(['\"]{3})([^\\1])*?\\1", "gm"), css: "comment" }, { regex: new RegExp('"(?!")(?:\\.|\\\\\\"|[^\\""\\n\\r])*"', "gm"), css: "string" }, { regex: new RegExp("'(?!')*(?:\\.|(\\\\\\')|[^\\''\\n\\r])*'", "gm"), css: "string" }, { regex: new RegExp("\\b\\d+\\.?\\w*", "g"), css: "number" }, { regex: new RegExp(this.GetKeywords("and assert break class continue def del elif else except exec finally for from global if import in is lambda not or pass print raise return try yield while"), "gm"), css: "keyword" }, { regex: new RegExp(this.GetKeywords("None True False self cls class_"), "gm"), css: "special" }];
    this.CssClass = "dp-py";
    this.Style = ""
};
dp.sh.Brushes.Python.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Python.Aliases = ["py", "python"];
dp.sh.Brushes.Plain = function () {
    this.regexList = []
};
dp.sh.Brushes.Plain.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Plain.Aliases = ["plain", "text", "txt"];
dp.sh.Brushes.Php = function () {
    this.regexList = [{ regex: dp.sh.RegexLib.SingleLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.MultiLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.DoubleQuotedString, css: "string" }, { regex: dp.sh.RegexLib.SingleQuotedString, css: "string" }, { regex: new RegExp("\\$\\w+", "g"), css: "vars" }, { regex: new RegExp(this.GetKeywords("abs acos acosh addcslashes addslashes array_change_key_case array_chunk array_combine array_count_values array_diff array_diff_assoc array_diff_key array_diff_uassoc array_diff_ukey array_fill array_filter array_flip array_intersect array_intersect_assoc array_intersect_key array_intersect_uassoc array_intersect_ukey array_key_exists array_keys array_map array_merge array_merge_recursive array_multisort array_pad array_pop array_product array_push array_rand array_reduce array_reverse array_search array_shift array_slice array_splice array_sum array_udiff array_udiff_assoc array_udiff_uassoc array_uintersect array_uintersect_assoc array_uintersect_uassoc array_unique array_unshift array_values array_walk array_walk_recursive atan atan2 atanh base64_decode base64_encode base_convert basename bcadd bccomp bcdiv bcmod bcmul bindec bindtextdomain bzclose bzcompress bzdecompress bzerrno bzerror bzerrstr bzflush bzopen bzread bzwrite ceil chdir checkdate checkdnsrr chgrp chmod chop chown chr chroot chunk_split class_exists closedir closelog copy cos cosh count count_chars date decbin dechex decoct deg2rad delete ebcdic2ascii echo empty end ereg ereg_replace eregi eregi_replace error_log error_reporting escapeshellarg escapeshellcmd eval exec exit exp explode extension_loaded feof fflush fgetc fgetcsv fgets fgetss file_exists file_get_contents file_put_contents fileatime filectime filegroup fileinode filemtime fileowner fileperms filesize filetype floatval flock floor flush fmod fnmatch fopen fpassthru fprintf fputcsv fputs fread fscanf fseek fsockopen fstat ftell ftok getallheaders getcwd getdate getenv gethostbyaddr gethostbyname gethostbynamel getimagesize getlastmod getmxrr getmygid getmyinode getmypid getmyuid getopt getprotobyname getprotobynumber getrandmax getrusage getservbyname getservbyport gettext gettimeofday gettype glob gmdate gmmktime ini_alter ini_get ini_get_all ini_restore ini_set interface_exists intval ip2long is_a is_array is_bool is_callable is_dir is_double is_executable is_file is_finite is_float is_infinite is_int is_integer is_link is_long is_nan is_null is_numeric is_object is_readable is_real is_resource is_scalar is_soap_fault is_string is_subclass_of is_uploaded_file is_writable is_writeable mkdir mktime nl2br parse_ini_file parse_str parse_url passthru pathinfo readlink realpath rewind rewinddir rmdir round str_ireplace str_pad str_repeat str_replace str_rot13 str_shuffle str_split str_word_count strcasecmp strchr strcmp strcoll strcspn strftime strip_tags stripcslashes stripos stripslashes stristr strlen strnatcasecmp strnatcmp strncasecmp strncmp strpbrk strpos strptime strrchr strrev strripos strrpos strspn strstr strtok strtolower strtotime strtoupper strtr strval substr substr_compare"), "gmi"), css: "func" }, { regex: new RegExp(this.GetKeywords("and or xor __FILE__ __LINE__ array as break case cfunction class const continue declare default die do else elseif enddeclare endfor endforeach endif endswitch endwhile extends for foreach function include include_once global if new old_function return static switch use require require_once var while __FUNCTION__ __CLASS__ __METHOD__ abstract interface public implements extends private protected throw"), "gm"), css: "keyword" }];
    this.CssClass = "dp-c"
};
dp.sh.Brushes.Php.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Php.Aliases = ["php"];
dp.sh.Brushes.JScript = function () {
    this.regexList = [{ regex: dp.sh.RegexLib.SingleLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.MultiLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.DoubleQuotedString, css: "string" }, { regex: dp.sh.RegexLib.SingleQuotedString, css: "string" }, { regex: new RegExp("^\\s*#.*", "gm"), css: "preprocessor" }, { regex: new RegExp(this.GetKeywords("abstract boolean break byte case catch char class const continue debugger default delete do double else enum export extends false final finally float for function goto if implements import in instanceof int interface long native new null package private protected public return short static super switch synchronized this throw throws transient true try typeof var void volatile while with"), "gm"), css: "keyword" }];
    this.CssClass = "dp-c"
};
dp.sh.Brushes.JScript.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.JScript.Aliases = ["js", "jscript", "javascript"];
dp.sh.Brushes.Java = function () {
    this.regexList = [{ regex: dp.sh.RegexLib.SingleLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.MultiLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.DoubleQuotedString, css: "string" }, { regex: dp.sh.RegexLib.SingleQuotedString, css: "string" }, { regex: new RegExp("\\b([\\d]+(\\.[\\d]+)?|0x[a-f0-9]+)\\b", "gi"), css: "number" }, { regex: new RegExp("(?!\\@interface\\b)\\@[\\$\\w]+\\b", "g"), css: "annotation" }, { regex: new RegExp("\\@interface\\b", "g"), css: "keyword" }, { regex: new RegExp(this.GetKeywords("abstract assert boolean break byte case catch char class const continue default do double else enum extends false final finally float for goto if implements import instanceof int interface long native new null package private protected public return short static strictfp super switch synchronized this throw throws true transient try void volatile while"), "gm"), css: "keyword" }];
    this.CssClass = "dp-j";
    this.Style = ""
};
dp.sh.Brushes.Java.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Java.Aliases = ["java"];
dp.sh.Brushes.Delphi = function () {
    this.regexList = [{ regex: new RegExp("\\(\\*[\\s\\S]*?\\*\\)", "gm"), css: "comment" }, { regex: new RegExp("{(?!\\$)[\\s\\S]*?}", "gm"), css: "comment" }, { regex: dp.sh.RegexLib.SingleLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.SingleQuotedString, css: "string" }, { regex: new RegExp("\\{\\$[a-zA-Z]+ .+\\}", "g"), css: "directive" }, { regex: new RegExp("\\b[\\d\\.]+\\b", "g"), css: "number" }, { regex: new RegExp("\\$[a-zA-Z0-9]+\\b", "g"), css: "number" }, { regex: new RegExp(this.GetKeywords("abs addr and ansichar ansistring array as asm begin boolean byte cardinal case char class comp const constructor currency destructor div do double downto else end except exports extended false file finalization finally for function goto if implementation in inherited int64 initialization integer interface is label library longint longword mod nil not object of on or packed pansichar pansistring pchar pcurrency pdatetime pextended pint64 pointer private procedure program property pshortstring pstring pvariant pwidechar pwidestring protected public published raise real real48 record repeat set shl shortint shortstring shr single smallint string then threadvar to true try type unit until uses val var varirnt while widechar widestring with word write writeln xor"), "gm"), css: "keyword" }];
    this.CssClass = "dp-delphi";
    this.Style = ""
};
dp.sh.Brushes.Delphi.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Delphi.Aliases = ["delphi", "pascal"];
dp.sh.Brushes.CSS = function () {
    this.regexList = [{ regex: dp.sh.RegexLib.MultiLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.DoubleQuotedString, css: "string" }, { regex: dp.sh.RegexLib.SingleQuotedString, css: "string" }, { regex: new RegExp("\\#[a-zA-Z0-9]{3,6}", "g"), css: "value" }, { regex: new RegExp("(-?\\d+)(.\\d+)?(px|em|pt|:|%|)", "g"), css: "value" }, { regex: new RegExp("!important", "g"), css: "important" }, { regex: new RegExp(this.GetKeywordsCSS("ascent azimuth background-attachment background-color background-image background-position background-repeat background baseline bbox border-collapse border-color border-spacing border-style border-top border-right border-bottom border-left border-top-color border-right-color border-bottom-color border-left-color border-top-style border-right-style border-bottom-style border-left-style border-top-width border-right-width border-bottom-width border-left-width border-width border cap-height caption-side centerline clear clip color content counter-increment counter-reset cue-after cue-before cue cursor definition-src descent direction display elevation empty-cells float font-size-adjust font-family font-size font-stretch font-style font-variant font-weight font height letter-spacing line-height list-style-image list-style-position list-style-type list-style margin-top margin-right margin-bottom margin-left margin marker-offset marks mathline max-height max-width min-height min-width orphans outline-color outline-style outline-width outline overflow padding-top padding-right padding-bottom padding-left padding page page-break-after page-break-before page-break-inside pause pause-after pause-before pitch pitch-range play-during position quotes richness size slope src speak-header speak-numeral speak-punctuation speak speech-rate stemh stemv stress table-layout text-align text-decoration text-indent text-shadow text-transform unicode-bidi unicode-range units-per-em vertical-align visibility voice-family volume white-space widows width widths word-spacing x-height z-index"), "gm"), css: "keyword" }, { regex: new RegExp(this.GetValuesCSS("above absolute all always aqua armenian attr aural auto avoid baseline behind below bidi-override black blink block blue bold bolder both bottom braille capitalize caption center center-left center-right circle close-quote code collapse compact condensed continuous counter counters crop cross crosshair cursive dashed decimal decimal-leading-zero default digits disc dotted double embed embossed e-resize expanded extra-condensed extra-expanded fantasy far-left far-right fast faster fixed format fuchsia gray green groove handheld hebrew help hidden hide high higher icon inline-table inline inset inside invert italic justify landscape large larger left-side left leftwards level lighter lime line-through list-item local loud lower-alpha lowercase lower-greek lower-latin lower-roman lower low ltr marker maroon medium message-box middle mix move narrower navy ne-resize no-close-quote none no-open-quote no-repeat normal nowrap n-resize nw-resize oblique olive once open-quote outset outside overline pointer portrait pre print projection purple red relative repeat repeat-x repeat-y rgb ridge right right-side rightwards rtl run-in screen scroll semi-condensed semi-expanded separate se-resize show silent silver slower slow small small-caps small-caption smaller soft solid speech spell-out square s-resize static status-bar sub super sw-resize table-caption table-cell table-column table-column-group table-footer-group table-header-group table-row table-row-group teal text-bottom text-top thick thin top transparent tty tv ultra-condensed ultra-expanded underline upper-alpha uppercase upper-latin upper-roman url visible wait white wider w-resize x-fast x-high x-large x-loud x-low x-slow x-small x-soft xx-large xx-small yellow"), "g"), css: "value" }, { regex: new RegExp(this.GetValuesCSS("[mM]onospace [tT]ahoma [vV]erdana [aA]rial [hH]elvetica [sS]ans-serif [sS]erif"), "g"), css: "value" }];
    this.CssClass = "dp-css";
    this.Style = ""
};
dp.sh.Highlighter.prototype.GetKeywordsCSS = function (a) {
    return "\\b([a-z_]|)" + a.replace(/ /g, "(?=:)\\b|\\b([a-z_\\*]|\\*|)") + "(?=:)\\b"
};
dp.sh.Highlighter.prototype.GetValuesCSS = function (a) {
    return "\\b" + a.replace(/ /g, "(?!-)(?!:)\\b|\\b()") + ":\\b"
};
dp.sh.Brushes.CSS.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.CSS.Aliases = ["css"];
dp.sh.Brushes.CSharp = function () {
    this.regexList = [{ regex: dp.sh.RegexLib.SingleLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.MultiLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.DoubleQuotedString, css: "string" }, { regex: dp.sh.RegexLib.SingleQuotedString, css: "string" }, { regex: new RegExp("^\\s*#.*", "gm"), css: "preprocessor" }, { regex: new RegExp(this.GetKeywords("abstract as base bool break byte case catch char checked class const continue decimal default delegate do double else enum event explicit extern false finally fixed float for foreach get goto if implicit in int interface internal is lock long namespace new null object operator out override params private protected public readonly ref return sbyte sealed set short sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked unsafe ushort using virtual void while"), "gm"), css: "keyword" }];
    this.CssClass = "dp-c";
    this.Style = ""
};
dp.sh.Brushes.CSharp.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.CSharp.Aliases = ["c#", "c-sharp", "csharp"];
dp.sh.Brushes.Cpp = function () {
    this.regexList = [{ regex: dp.sh.RegexLib.SingleLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.MultiLineCComments, css: "comment" }, { regex: dp.sh.RegexLib.DoubleQuotedString, css: "string" }, { regex: dp.sh.RegexLib.SingleQuotedString, css: "string" }, { regex: new RegExp("^ *#.*", "gm"), css: "preprocessor" }, { regex: new RegExp(this.GetKeywords("ATOM BOOL BOOLEAN BYTE CHAR COLORREF DWORD DWORDLONG DWORD_PTR DWORD32 DWORD64 FLOAT HACCEL HALF_PTR HANDLE HBITMAP HBRUSH HCOLORSPACE HCONV HCONVLIST HCURSOR HDC HDDEDATA HDESK HDROP HDWP HENHMETAFILE HFILE HFONT HGDIOBJ HGLOBAL HHOOK HICON HINSTANCE HKEY HKL HLOCAL HMENU HMETAFILE HMODULE HMONITOR HPALETTE HPEN HRESULT HRGN HRSRC HSZ HWINSTA HWND INT INT_PTR INT32 INT64 LANGID LCID LCTYPE LGRPID LONG LONGLONG LONG_PTR LONG32 LONG64 LPARAM LPBOOL LPBYTE LPCOLORREF LPCSTR LPCTSTR LPCVOID LPCWSTR LPDWORD LPHANDLE LPINT LPLONG LPSTR LPTSTR LPVOID LPWORD LPWSTR LRESULT PBOOL PBOOLEAN PBYTE PCHAR PCSTR PCTSTR PCWSTR PDWORDLONG PDWORD_PTR PDWORD32 PDWORD64 PFLOAT PHALF_PTR PHANDLE PHKEY PINT PINT_PTR PINT32 PINT64 PLCID PLONG PLONGLONG PLONG_PTR PLONG32 PLONG64 POINTER_32 POINTER_64 PSHORT PSIZE_T PSSIZE_T PSTR PTBYTE PTCHAR PTSTR PUCHAR PUHALF_PTR PUINT PUINT_PTR PUINT32 PUINT64 PULONG PULONGLONG PULONG_PTR PULONG32 PULONG64 PUSHORT PVOID PWCHAR PWORD PWSTR SC_HANDLE SC_LOCK SERVICE_STATUS_HANDLE SHORT SIZE_T SSIZE_T TBYTE TCHAR UCHAR UHALF_PTR UINT UINT_PTR UINT32 UINT64 ULONG ULONGLONG ULONG_PTR ULONG32 ULONG64 USHORT USN VOID WCHAR WORD WPARAM WPARAM WPARAM char bool short int __int32 __int64 __int8 __int16 long float double __wchar_t clock_t _complex _dev_t _diskfree_t div_t ldiv_t _exception _EXCEPTION_POINTERS FILE _finddata_t _finddatai64_t _wfinddata_t _wfinddatai64_t __finddata64_t __wfinddata64_t _FPIEEE_RECORD fpos_t _HEAPINFO _HFILE lconv intptr_t jmp_buf mbstate_t _off_t _onexit_t _PNH ptrdiff_t _purecall_handler sig_atomic_t size_t _stat __stat64 _stati64 terminate_function time_t __time64_t _timeb __timeb64 tm uintptr_t _utimbuf va_list wchar_t wctrans_t wctype_t wint_t signed"), "gm"), css: "datatypes" }, { regex: new RegExp(this.GetKeywords("break case catch class const __finally __exception __try const_cast continue private public protected __declspec default delete deprecated dllexport dllimport do dynamic_cast else enum explicit extern if for friend goto inline mutable naked namespace new noinline noreturn nothrow register reinterpret_cast return selectany sizeof static static_cast struct switch template this thread throw true false try typedef typeid typename union using uuid virtual void volatile whcar_t while"), "gm"), css: "keyword" }];
    this.CssClass = "dp-cpp";
    this.Style = ""
};
dp.sh.Brushes.Cpp.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Cpp.Aliases = ["cpp", "c", "c++"];
dp.sh.Brushes.Objc = function () {
    var datatypes = 'ATOM BOOL BOOLEAN BYTE CHAR COLORREF DWORD DWORDLONG DWORD_PTR ' +
        'DWORD32 DWORD64 FLOAT HACCEL HALF_PTR HANDLE HBITMAP HBRUSH ' +
        'HCOLORSPACE HCONV HCONVLIST HCURSOR HDC HDDEDATA HDESK HDROP HDWP ' +
        'HENHMETAFILE HFILE HFONT HGDIOBJ HGLOBAL HHOOK HICON HINSTANCE HKEY ' +
        'HKL HLOCAL HMENU HMETAFILE HMODULE HMONITOR HPALETTE HPEN HRESULT ' +
        'HRGN HRSRC HSZ HWINSTA HWND INT INT_PTR INT32 INT64 LANGID LCID LCTYPE ' +
        'LGRPID LONG LONGLONG LONG_PTR LONG32 LONG64 LPARAM LPBOOL LPBYTE LPCOLORREF ' +
        'LPCSTR LPCTSTR LPCVOID LPCWSTR LPDWORD LPHANDLE LPINT LPLONG LPSTR LPTSTR ' +
        'LPVOID LPWORD LPWSTR LRESULT PBOOL PBOOLEAN PBYTE PCHAR PCSTR PCTSTR PCWSTR ' +
        'PDWORDLONG PDWORD_PTR PDWORD32 PDWORD64 PFLOAT PHALF_PTR PHANDLE PHKEY PINT ' +
        'PINT_PTR PINT32 PINT64 PLCID PLONG PLONGLONG PLONG_PTR PLONG32 PLONG64 POINTER_32 ' +
        'POINTER_64 PSHORT PSIZE_T PSSIZE_T PSTR PTBYTE PTCHAR PTSTR PUCHAR PUHALF_PTR ' +
        'PUINT PUINT_PTR PUINT32 PUINT64 PULONG PULONGLONG PULONG_PTR PULONG32 PULONG64 ' +
        'PUSHORT PVOID PWCHAR PWORD PWSTR SC_HANDLE SC_LOCK SERVICE_STATUS_HANDLE SHORT ' +
        'SIZE_T SSIZE_T TBYTE TCHAR UCHAR UHALF_PTR UINT UINT_PTR UINT32 UINT64 ULONG ' +
        'ULONGLONG ULONG_PTR ULONG32 ULONG64 USHORT USN VOID WCHAR WORD WPARAM WPARAM WPARAM ' +
        'char bool short int __int32 __int64 __int8 __int16 long float double __wchar_t ' +
        'clock_t _complex _dev_t _diskfree_t div_t ldiv_t _exception _EXCEPTION_POINTERS ' +
        'FILE _finddata_t _finddatai64_t _wfinddata_t _wfinddatai64_t __finddata64_t ' +
        '__wfinddata64_t _FPIEEE_RECORD fpos_t _HEAPINFO _HFILE lconv intptr_t id ' +
        'jmp_buf mbstate_t _off_t _onexit_t _PNH ptrdiff_t _purecall_handler ' +
        'sig_atomic_t size_t _stat __stat64 _stati64 terminate_function ' +
        'time_t __time64_t _timeb __timeb64 tm uintptr_t _utimbuf ' +
        'va_list wchar_t wctrans_t wctype_t wint_t signed';
    var keywords = 'break case catch class copy const __finally __exception __try ' +
        'const_cast continue private public protected __declspec ' +
        'default delete deprecated dllexport dllimport do dynamic_cast ' +
        'else enum explicit extern if for friend getter goto inline ' +
        'mutable naked namespace new nil NO noinline nonatomic noreturn nothrow NULL ' +
        'readonly readwrite register reinterpret_cast retain strong return SEL selectany self ' +
        'setter sizeof static static_cast struct super switch template ' +
        'thread throw true false try typedef typeid typename union ' +
        'using uuid virtual void volatile whcar_t while YES';
    //顺序很重要
    this.regexList = [
        { regex: new RegExp(this.GetKeywords(datatypes), 'gm'), css: 'keyword' },  // primitive data types
        { regex: new RegExp(this.GetKeywords(keywords), 'gm'), css: 'keyword' },  // keywords
        { regex: new RegExp('@\\w+\\b', 'g'), css: 'keyword' },  // @-keywords
        { regex: new RegExp('[: ]nil', 'g'), css: 'keyword' },  // nil-workaround
        { regex: new RegExp('\\.\\w+', 'g'), css: 'xcodeconstants' },  // accessors
        { regex: new RegExp(' \\w+(?=[:\\]])', 'g'), css: 'vars' },  // messages
        { regex: dp.sh.RegexLib.SingleLineCComments, css: 'comment' },  // comments
        { regex: dp.sh.RegexLib.MultiLineCComments, css: 'comment' },  // comments
        { regex: dp.sh.RegexLib.DoubleQuotedString, css: 'string' },  // strings
        { regex: dp.sh.RegexLib.SingleQuotedString, css: 'string' },  // strings
        { regex: new RegExp('@"[^"]*"', 'gm'), css: 'string' },  // strings
        { regex: new RegExp('\\d', 'gm'), css: 'xcodenumber' },  // numeric values
        { regex: new RegExp('^ *#.*', 'gm'), css: 'xcodepreprocessor' },  // preprocessor
        { regex: new RegExp('\\w+(?= \\*)', 'g'), css: 'keyword' } // object types - variable declaration
        /*{ regex: new RegExp('\\b[A-Z]\\w+\\b(?=[ ,;])', 'gm'),  css: 'xcodekeyword' },*/ // object types - protocol
    ];
    this.CssClass = 'dp-objc';
    this.Style = '.dp-objc .vars { color: #d00; }';
}
dp.sh.Brushes.Objc.prototype = new dp.sh.Highlighter;
dp.sh.Brushes.Objc.Aliases = ['objc'];

/*ZeroClipboard/ZeroClipboard.js*/
var ZeroClipboard = {
    version: "1.0.7", clients: {}, moviePath: 'http://static.blog.csdn.net/scripts/ZeroClipboard/ZeroClipboard.swf', nextId: 1, $: function (thingy) {
        if (typeof (thingy) == 'string')
            thingy = document.getElementById(thingy);
        if (true || !thingy.addClass) {
            thingy.hide = function () {
                this.style.display = 'none';
            };
            thingy.show = function () {
                this.style.display = 'block';
            };
            thingy.addClass = function (name) {
                this.removeClass(name);
                this.className += ' ' + name;
            };
            thingy.removeClass = function (name) {
                var classes = this.className.split(/\s+/);
                var idx = -1;
                for (var k = 0; k < classes.length; k++) {
                    if (classes[k] == name) {
                        idx = k;
                        k = classes.length;
                    }
                }
                if (idx > -1) {
                    classes.splice(idx, 1);
                    this.className = classes.join(' ');
                }
                return this;
            };
            thingy.hasClass = function (name) {
                return !!this.className.match(new RegExp("\\s*" + name + "\\s*"));
            };
        }
        return thingy;
    }, setMoviePath: function (path) {
        this.moviePath = path;
    }, dispatch: function (id, eventName, args) {
        var client = this.clients[id];
        if (client) {
            client.receiveEvent(eventName, args);
        }
    }, register: function (id, client) {
        this.clients[id] = client;
    }, getDOMObjectPosition: function (obj, stopObj) {
        var info = { left: 0, top: 0, width: obj.width ? obj.width : obj.offsetWidth, height: obj.height ? obj.height : obj.offsetHeight };
        while (obj && (obj != stopObj)) {
            info.left += obj.offsetLeft;
            info.top += obj.offsetTop;
            obj = obj.offsetParent;
        }
        return info;
    }, Client: function (elem) {
        this.handlers = {};
        this.id = ZeroClipboard.nextId++;
        this.movieId = 'ZeroClipboardMovie_' + this.id;
        ZeroClipboard.register(this.id, this);
        if (elem)
            this.glue(elem);
    }
};
ZeroClipboard.Client.prototype = {
    id: 0, ready: false, movie: null, clipText: '', handCursorEnabled: true, cssEffects: true, handlers: null, glue: function (elem, appendElem, stylesToAdd) {
        this.domElement = ZeroClipboard.$(elem);
        var zIndex = 99;
        if (this.domElement.style.zIndex) {
            zIndex = parseInt(this.domElement.style.zIndex, 10) + 1;
        }
        if (typeof (appendElem) == 'string') {
            appendElem = ZeroClipboard.$(appendElem);
        }
        else if (typeof (appendElem) == 'undefined') {
            appendElem = document.getElementsByTagName('body')[0];
        }
        var box = ZeroClipboard.getDOMObjectPosition(this.domElement, appendElem);
        this.div = document.createElement('div');
        var style = this.div.style;
        style.position = 'absolute';
        style.left = '' + box.left + 'px';
        style.top = '' + box.top + 'px';
        style.width = '' + box.width + 'px';
        style.height = '' + box.height + 'px';
        style.zIndex = zIndex;
        if (typeof (stylesToAdd) == 'object') {
            for (addedStyle in stylesToAdd) {
                style[addedStyle] = stylesToAdd[addedStyle];
            }
        }
        appendElem.appendChild(this.div);
        this.div.innerHTML = this.getHTML(box.width, box.height);
    }, getHTML: function (width, height) {
        var html = '';
        var flashvars = 'id=' + this.id + '&width=' + width + '&height=' + height;
        if (navigator.userAgent.match(/MSIE/)) {
            var protocol = location.href.match(/^https/i) ? 'https://' : 'http://';
            html += '<object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" codebase="' + protocol + 'download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=9,0,0,0" width="' + width + '" height="' + height + '" id="' + this.movieId + '" align="middle"><param name="allowScriptAccess" value="always" /><param name="allowFullScreen" value="false" /><param name="movie" value="' + ZeroClipboard.moviePath + '" /><param name="loop" value="false" /><param name="menu" value="false" /><param name="quality" value="best" /><param name="bgcolor" value="#ffffff" /><param name="flashvars" value="' + flashvars + '"/><param name="wmode" value="transparent"/></object>';
        }
        else {
            html += '<embed id="' + this.movieId + '" src="' + ZeroClipboard.moviePath + '" loop="false" menu="false" quality="best" bgcolor="#ffffff" width="' + width + '" height="' + height + '" name="' + this.movieId + '" align="middle" allowScriptAccess="always" allowFullScreen="false" type="application/x-shockwave-flash" pluginspage="http://www.macromedia.com/go/getflashplayer" flashvars="' + flashvars + '" wmode="transparent" />';
        }
        return html;
    }, hide: function () {
        if (this.div) {
            this.div.style.left = '-2000px';
        }
    }, show: function () {
        this.reposition();
    }, destroy: function () {
        if (this.domElement && this.div) {
            this.hide();
            this.div.innerHTML = '';
            var body = document.getElementsByTagName('body')[0];
            try {
                body.removeChild(this.div);
            } catch (e) {
                ;
            }
            this.domElement = null;
            this.div = null;
        }
    }, reposition: function (elem) {
        if (elem) {
            this.domElement = ZeroClipboard.$(elem);
            if (!this.domElement)
                this.hide();
        }
        if (this.domElement && this.div) {
            var box = ZeroClipboard.getDOMObjectPosition(this.domElement);
            var style = this.div.style;
            style.left = '' + box.left + 'px';
            style.top = '' + box.top + 'px';
        }
    }, setText: function (newText) {
        this.clipText = newText;
        if (this.ready)
            this.movie.setText(newText);
    }, addEventListener: function (eventName, func) {
        eventName = eventName.toString().toLowerCase().replace(/^on/, '');
        if (!this.handlers[eventName])
            this.handlers[eventName] = [];
        this.handlers[eventName].push(func);
    }, setHandCursor: function (enabled) {
        this.handCursorEnabled = enabled;
        if (this.ready)
            this.movie.setHandCursor(enabled);
    }, setCSSEffects: function (enabled) {
        this.cssEffects = !!enabled;
    }, receiveEvent: function (eventName, args) {
        eventName = eventName.toString().toLowerCase().replace(/^on/, '');
        switch (eventName) {
            case 'load':
                this.movie = document.getElementById(this.movieId);
                if (!this.movie) {
                    var self = this;
                    setTimeout(function () {
                        self.receiveEvent('load', null);
                    }, 1);
                    return;
                }
                if (!this.ready && navigator.userAgent.match(/Firefox/) && navigator.userAgent.match(/Windows/)) {
                    var self = this;
                    setTimeout(function () {
                        self.receiveEvent('load', null);
                    }, 100);
                    this.ready = true;
                    return;
                }
                this.ready = true;
                this.movie.setText(this.clipText);
                this.movie.setHandCursor(this.handCursorEnabled);
                break;
            case 'mouseover':
                if (this.domElement && this.cssEffects) {
                    this.domElement.addClass('hover');
                    if (this.recoverActive)
                        this.domElement.addClass('active');
                }
                break;
            case 'mouseout':
                if (this.domElement && this.cssEffects) {
                    this.recoverActive = false;
                    if (this.domElement.hasClass('active')) {
                        this.domElement.removeClass('active');
                        this.recoverActive = true;
                    }
                    this.domElement.removeClass('hover');
                }
                break;
            case 'mousedown':
                if (this.domElement && this.cssEffects) {
                    this.domElement.addClass('active');
                }
                break;
            case 'mouseup':
                if (this.domElement && this.cssEffects) {
                    this.domElement.removeClass('active');
                    this.recoverActive = false;
                }
                break;
        }
        if (this.handlers[eventName]) {
            for (var idx = 0, len = this.handlers[eventName].length; idx < len; idx++) {
                var func = this.handlers[eventName][idx];
                if (typeof (func) == 'function') {
                    func(this, args);
                }
                else if ((typeof (func) == 'object') && (func.length == 2)) {
                    func[0][func[1]](this, args);
                }
                else if (typeof (func) == 'string') {
                    window[func](this, args);
                }
            }
        }
    }
};


function report(id, t, e) {
    $.createMask();
    var url = blog_address + "/common/report?id=" + id + "&t=" + t;
    if (location.href.indexOf("dev") > -1)
    {
        var u = blog_address.split('/')[3];
        url = "http://dev.blog.csdn.net:5391/"+u+"/common/report?id=" + id + "&t=" + t;
    }
    
    if (t == 3) {
        var floor = e.attr('floor');
        url += "&floor=" + floor;
    }
    var top = (document.documentElement.clientHeight - 400) / 2 + (document.documentElement.scrollTop || document.body.scrollTop);
    var left = (document.documentElement.clientWidth - 400) / 2;
    $("#report_dialog").load(url).css({ "top": top + "px", "left": left }).show();
}


jQuery.createMask = function () {
    var height = document.documentElement.clientHeight;
    var width = document.documentElement.clientWidth;
    var bodyHeight = $("body").height();
    if (bodyHeight > height) {
        height = bodyHeight;
    }
    var mask = {};
    if ($("#mask_div").length == 0) {
        $("body").append('<div id="mask_div" style="position:absolute;top:0;left:0;filter:alpha(opacity=20);-moz-opacity:0.2;opacity:.2;"></div>')
    }
    mask = $("#mask_div");
    mask.css({ "width": width, "height": height, "background": "#000" });
};
jQuery.removeMask = function () {
    $("#mask_div").remove();
};
Array.prototype.contain = function (val) {
    for (var i = 0; i < this.length; i++) {
        if (this[i] === val) {
            return true;
        }
    }
    return false;
}

function collectArticle(title, fileName) {
    openWindow("http://wz.csdn.net/storeit.aspx?t=" + encodeURIComponent(title) + "&u=" + blog_address + "/article/details/" + fileName, title);
}

function deleteArticle(articleId) {
    if (!confirm("你确定要删除这篇文章吗？"))
        return;
    $.get(blog_address + "/article/delete?articleId=" + articleId, function (txt) {
        var data = eval("(" + txt + ")");
        if (data.result) {
            alert("文章已删除！");
            location.reload();
        } else {
            if (data.content)
                alert(data.content);
            else
                alert("无法删除，请到后台删除！");
        }
    });
}
function openWindow(url, title) {
    var _t = title || encodeURI(document.title);
    var _u = url || encodeURIComponent(document.location);
    var f = function () {
        var left = (screen.width - 600) / 2;
        var top = (screen.height - 450) / 2;
        if (!window.open(url, '', 'toolbar=0,resizable=1,scrollbars=yes,status=1,width=600,height=400'))
            location.href = url;
    }
    if (/Firefox/.test(navigator.userAgent))
        setTimeout(f, 0);
    else
        f();
}

function GetCategoryArticles(id, username, type, aid) {
    var topid = "top_" + id;
    
    if (type == "top") {
        var objtop = $("#" + topid + " li");
        if (objtop.length > 0) {
            return;
        }
    }

   

    var url = "/" + username + "/svc/GetCategoryArticleList?id=" + id + "&type=" + type;
    //url="http://dev.blog.csdn.net:5391"+url;
    $.get(url, function (res) {

        if (type == "top") {
            var objtop = $("#" + topid);
            objtop.html("");
            $(res).each(function (i) {
                var obj = res[i];
                if (aid != obj.articleid) {
                    var articleurl = "http://blog.csdn.net/" + username + "/article/details/" + obj.articleid;
                    var aritcleid = "top_aritcle_" + obj.articleid + Math.random().toString().replace("0.");
                    objtop.append("<li class=\"tracking-ad\" data-mod=\"popu_140\"><em>•</em><a href='" + articleurl + "'  id='" + aritcleid + "' target=\"_blank\"></a></li> ");
                    $("#" + aritcleid).text(obj.title);
                    $("#" + aritcleid).attr("title", obj.title);
                }
            });

            var count = $(objtop.parent().parent().find("em")[0]).text().replace("（", "").replace("）", "");
            if (parseInt(count) > 5) {
                var moreurl = objtop.parent().find(".subItem_t a").attr("href");
                objtop.append("<li style=\"padding-left: 300px;\"><a href='" + moreurl + "' target=\"_blank\">更多</a></li>");
            }

        }
        else if (type == "foot") {

            $(".my_article_t_cur").removeClass("my_article_t_cur");   
            $("#samecate"+id).addClass("my_article_t_cur");

            var objfootleft = $(".my_list.fl");
            var objfootright = $(".my_list.fr");

            objfootleft.html("");
            objfootright.html("");

            var j = 0;

            $.each(res, function (i) {
                var obj = res[i];
                if (j < 11) {
                    if (aid != obj.articleid) {
                        var articleurl = "http://blog.csdn.net/" + username + "/article/details/" + obj.articleid;
                        var aritcleid = "foot_aritcle_" + obj.articleid + Math.random().toString().replace("0.");

                        var html = "<li><a href='" + articleurl + "'  id='" + aritcleid + "' target=\"_blank\"></a><label><span>" + obj.posttime + "</span><i class=\"fa fa-eye\"></i><em>" + obj.viewcount + "</em></label></li> ";
                        if (j % 2 == 1) {
                            objfootright.append(html);
                        }
                        else {
                            objfootleft.append(html);
                        }

                        j++;

                        $("#" + aritcleid).text(obj.title);
                        $("#" + aritcleid).attr("title", obj.title);


                        $(".my_article").show();
                    }
                }
            });

            var count = $(".my_article_t_l.my_article_t_cur em").text().replace("（", "").replace("）", "");
            if (parseInt(count) > 10) {                
                var moreurl=$(".my_article_t_l.my_article_t_cur").attr("moreurl");               
                if (moreurl != "") {
                    //objfootright.append("<li style=\"padding-left: 200px;\"><a href='" + moreurl + "' target=\"_blank\">更多</a></li>");
                    $(".my_more").remove();
                    $(".my_article_c_c").append('<a href=' + moreurl + ' class="my_more">更多文章</a>');
                }
            }
        }
    });
}