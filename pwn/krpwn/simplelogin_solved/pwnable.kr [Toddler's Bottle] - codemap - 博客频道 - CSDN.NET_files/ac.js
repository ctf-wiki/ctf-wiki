(function () {
	function u(a, c) {
		var b = [],
		f;
		for (f in c)
			Object.prototype.hasOwnProperty.call(c, f) && b.push(encodeURIComponent(f) + "=" + encodeURIComponent(c[f] || ""));
		b.push("_=" + +new Date);
		a += b.join("&");
		"Microsoft Internet Explorer" === window.navigator.appName && (b = (window.navigator.userAgent || "").match(/msie (\d+\.\d)/i)) && 8 > parseInt(b[1], 10) && (a = a.slice(0, 2048));
		b = e.createElement("div");
		b.id = "any_log";
		f = e.body;
		f.insertBefore(b, f.firstChild);
		f = ['<iframe width="1" height="1" ', 'src="' + a + '" ', 'align="center" marginwidth="0" marginheight="0" scrolling="no" frameborder="0" allowtransparency="true" </iframe>'].join("");
		b.innerHTML = f
	}
	function v(a) {
		var c = e.createElement("script");
		c.src = a;
		a = e.body;
		a.insertBefore(c, a.firstChild)
	}
	var i = !1,
	w = !1,
	x = !1,
	e = window.document,
	l = -1 !== window.location.href.indexOf("cf=u");
	try {
		var m = window.localStorage
	} catch (E) {}

	window.isJsReady = function () {
		return "anyFlashReady"
	};
	var y = function (a, c) {
		var b = RegExp("(^| )" + a + "=([^;]*)(;|$)").exec(e.cookie);
		return b ? c ? decodeURIComponent(b[2]) : b[2] : ""
	},
	z = function (a, c, b, f) {
		var d = b.expires;
		"number" === typeof d && (d = new Date, d.setTime(+d + b.expires));
		e.cookie =
			a + "=" + (f ? encodeURIComponent(c) : c) + (b.path ? "; path=" + b.path : "") + (d ? "; expires=" + d.toGMTString() : "") + (b.domain ? "; domain=" + b.domain : "")
	},
	j = function (a, c) {
		c && 0 > c.indexOf(":FG=1") && (c += ":FG=1");
		if (y(a) !== c) {
			var b = new Date;
			b.setTime(b.getTime() + 864E8);
			z(a, c, {
				path : "/",
				expires : b
			})
		}
	},
	n = function (a, c) {
		if (void 0 !== c)
			z(a, c, {});
		else
			return y(a)
	},
	A = function (a, c) {
		var b = -1 !== navigator.appName.indexOf("Microsoft") ? e.getElementById("BAIDU_CLB_ac_o_flash") : e.getElementById("BAIDU_CLB_ac_o_flash_embed");
		if (!b)
			return "";
		if (void 0 !== c)
			b.anySetSO(a, c);
		else
			return b.anyGetSO(a)
	},
	B = function (a, c) {
		try {
			var b;
			b = e.getElementById("cPersistDiv") ? e.getElementById("cPersistDiv") : e.createElement("div");
			b.style.visibility = "hidden";
			b.style.position = "absolute";
			b.setAttribute("id", "cPersistDiv");
			e.body.appendChild(b);
			b.style.behavior = "url(#default#userData)";
			if (void 0 !== c)
				b.setAttribute(a, c), b.save(a);
			else
				return b.load(a), b.getAttribute(a)
		} catch (d) {}

	},
	C = function (a, c) {
		try {
			if (m)
				if (void 0 !== c)
					m.setItem(a, c);
				else
					return m.getItem(a) ||
					void 0
		} catch (b) {}

	},
	o = "",
	p = n("CPROID") || n("BAIDUID") || "",
	d = B("CPROID") || "",
	g = C("CPROID") || "",
	k = "",
	h = p || d || g;
	d && j("UDID", d);
	g && j("LDID", g);
	window.anyFlashReady = function () {
		x = !0;
		var a = k = A("CPROID");
		a || (A("CPROID", h), k = a = h);
		j("FCID", a);
		!i && x && w && (u("//eclick.baidu.com/fp.htm?", {
				ci : h,
				cn : p,
				cu : d,
				cl : g,
				cf : k,
				ce : o,
				ff : q,
				cuid : r,
				cuid2 : s,
				de : t,
				bp : D,
				nip : ""
			}), i = !0)
	};
	d || B("CPROID", h);
	g || C("CPROID", h);
	var q = "c";
	!0 === l && (q = "u");
	window.setEtag = window.getEtag = function (a) {
		w = !0;
		a && (o = a, j("ETID", a))
	};
	var r = "",
	t = "",
	s = "",
	D = n("BDUSS") || "";
	window.getCuid = function (a) {
		0 === a.error && a.cuid && (r = a.cuid)
	};
	window.getCuid2 = function (a) {
		0 === a.error && a.cuid && (s = a.cuid)
	};
	l = "//127.0.0.1:40310/getcuid?callback=getCuid&mcmdf=inapp_test";
	0 <= navigator.userAgent.toLowerCase().indexOf("android") && (t = "an", v(l), v("//127.0.0.1:6259/getcuid?callback=getCuid2&mcmdf=inapp_test"));
	setTimeout(function () {
		i || (u("//eclick.baidu.com/fp.htm?", {
				ci : h,
				cn : p,
				cu : d,
				cl : g,
				cf : k,
				ce : o,
				ff : q,
				cuid : r,
				cuid2 : s,
				de : t,
				bp : D,
				nip : ""
			}), i = !0)
	}, 800)
})();
