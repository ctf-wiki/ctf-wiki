/*
* CSDN 登录框
* Copyright 2012, zhuhz@csdn.net
* Date: 2012-6-6
* 
* 调用：csdn.showLogin(callback);
*
* 获取当前登录用户名（可用于判断用户是否处于登录状态）：csdn.getCookie('UserName')
*/
var csdn = window.csdn || function () { };

csdn.domain = "passport.csdn.net";
csdn.doing = false;
csdn.$ = function (id) {
    return document.getElementById(id);
};
csdn.loginBack = null;
csdn.showLogin = function (callback) {
    var div = csdn.$('csdn_divh');
    if(!div){
        div = document.createElement("DIV");
        div.id = "csdn_divh";
        div.style.marginTop = -75 + (document.documentElement.scrollTop || document.body.scrollTop) + "px";
    }

    // var title = '登录<a class="close" href="javascript:void(0);" onclick="javascript:csdn.closeLogin();return false;" title="关闭窗口">[X]</a>';
    var title = '';
    var body = csdn.loginForm();
    var bottom = '';
    var s = csdn.openBox().replace('#title#', title).replace('#body#', body);
    div.innerHTML = s;

    csdn.shieldBody();
    document.body.appendChild(div);

    var un = csdn.getCookie("UN");
    if (un) {
        csdn.$('u').value = un;
        csdn.$('p').focus();
    }
    else {
        csdn.$('u').focus();
    }
    csdn.$('u').onkeypress =
    csdn.$('p').onkeypress = function (ev) {
        if (csdn.isEnter(ev)) {
            csdn.login();
        }
    };
    csdn.loginBack = callback;
    
    new WxLogin({
    	id:"wxqr", 
    	appid: "wx0ae11b6a28b4b9fc", 
    	scope: "snsapi_login",
    	redirect_uri: "https://passport.csdn.net/account/weixin?" + encodeURIComponent("qr=true&from=" + window.location.href),
    	state: "csdn",
    	style: "white",
    	href: 'https://' + csdn.domain + "/content/loginbox/replace-wx-style2.css"
    });
};

csdn.showLoginByMobile = function (callback) {

    var div = csdn.$('csdn_divh');
    if(!div){
        div = document.createElement("DIV");
        div.id = "csdn_divh";
        div.style.marginTop = -75 + (document.documentElement.scrollTop || document.body.scrollTop) + "px";
    }
    // var title = '登录<a class="close" href="javascript:void(0);" onclick="javascript:csdn.closeLogin();return false;" title="关闭窗口">[X]</a>';
    var title = '';
    var body = csdn.loginFormByMobile();
    var bottom = '';
    var s = csdn.openBox().replace('#title#', title).replace('#body#', body);
    div.innerHTML = s;

    csdn.shieldBody();
    document.body.appendChild(div);

    csdn.loginBack = callback;
};

csdn.closeLogin = function () {
    document.body.removeChild(csdn.$('csdn_divh'));
    document.body.removeChild(csdn.$('csdn_shield'));
};
csdn.shieldBody = function () {
    if(csdn.$("csdn_shield")){
        return;
    }
    var shield = document.createElement("DIV");
    shield.id = "csdn_shield";
    var h1 = document.documentElement.clientHeight;
    var h2 = document.documentElement.scrollHeight;
    shield.style.height = Math.max(h1, h2) + "px";
    shield.style.filter = "alpha(opacity=0)";
    shield.style.opacity = 0;
    document.body.appendChild(shield);

    csdn.setOpacity = function (obj, opacity) {
        if (opacity >= 1) opacity = opacity / 100;
        try { obj.style.opacity = opacity; } catch (err) { }
        try {
            if (obj.filters.length > 0 && obj.filters("alpha")) {
                obj.filters("alpha").opacity = opacity * 150;
            } else {
                obj.style.filter = "alpha(opacity=\"" + (opacity * 150) + "\")";
            }
        } catch (err) { }
    };
    var c = 0;
    csdn.doAlpha = function () {
        c += 2;
        if (c > 20) { clearInterval(ad); return 0; }
        csdn.setOpacity(shield, c);
    };
    var ad = setInterval("csdn.doAlpha()", 1);
};
csdn.setStyle = function () {
    var lk = document.createElement("LINK");
    lk.type = "text/css";
    lk.rel = "stylesheet";
    lk.href = location.protocol + "//" + csdn.domain + "/content/loginbox/style.css?r=" + (new Date().getTime());
    var head = document.getElementsByTagName("head")[0];
    head.appendChild(lk);
};
csdn.isEnter = function (ev) {
    ev = ev || window.event;
    var code = (ev.keyCode || ev.which);
    return (code == 10 || code == 13);
};
csdn.getCookie = function (name) {
    var ck = document.cookie.match(new RegExp("(^| )" + name + "=([^;]*)(;|$)"));
    if (ck) return ck[2];
    else return null;
};
csdn.setCookie = function (name, value, expires) {
    if (expires) expires = '; expires=' + new Date(expires).toUTCString();
    else expires = '';
    var path = '; path=/';
    var domain = '; domain=' + document.domain.replace('www.', '');

    document.cookie = [name, '=', encodeURIComponent(value), expires, path, domain].join('');
}

csdn.openBox = function () {
    var text =
         "<div class='boxbody'>#body#</div>"

    return text;
};
csdn.loginForm = function () {
    var fromurl = encodeURIComponent(location.href);
    var text = 
    "<div class='csdn_loginbox' style='z-index: 100'>"
    	+ "<div class='login_content' style='float:left;'>"
    	  + "<div class='login_content_inner'>"
    		+ "<div style='font-size: 12px;'>帐号登录 </div>"
    		+ "<input name='close' type='button' class='close'  onclick='javascript:csdn.closeLogin();return false;'  />"
    		+ "<p class='point' id='sperr'></p>"
    		+ "<input name='user_id'  id='u'  type='text' class='user_id' placeholder='用户ID/注册邮箱' />"
    		+ "<input name='password' id='p' type='password' class='password' placeholder='密码'/ >"
    		+ "<label><p class='remember clearfix'><input name='checkbox'  id='chkre' type='checkbox' value='checkbox' />记住我一周</p></label>"
    		+ "<div class='pw_lg'>"
    			+ "<a href='https://" + csdn.domain + "/account/forgotpassword' target='_blank' >忘记密码</a>|<a href='https://" + csdn.domain + "/account/register' target='_blank' class='pw_a'>注册</a>"
    		+ "</div>"
    		+ "<input name='button' type='button' onclick='javascript:csdn.login();return false;' value='登  录' class='login_bt'/>"
    		+ "<div class='lg_3 clearfix'>"
				+ "<a href='javascript:void(0)' class='wechat' onclick='csdn.showWechatQr()'></a>"
				+ "<a href='https://" + csdn.domain + "/auth/baidu?from=" + fromurl + "' target='_blank' class='baidu'></a>"
				+ "<a href='https://" + csdn.domain + "/auth/Github?from=" + fromurl + "' target='_blank' class='github'></a>"
				+ "<a href='https://" + csdn.domain + "/auth/qq?from=" + fromurl + "' target='_blank' class='qq'></a>"
				+ "<a href='https://" + csdn.domain + "/auth/sinat?from=" + fromurl + "' target='_blank' class='weibo'></a>"
				+ "第三方登录："
			+ "</div>" 
		  + "</div>"
		+ "</div>"
		+ "<div id='wxqr' class='wxqr' style='float:left;display:none;position:relative;'></div>"
		+ "<div style='clear: both;'></div>"
	+ "</div>";
    
    return text;
};

csdn.send_code_callback = function(data){
    if(data.err == 0){
        csdn.$("send-code").innerHTML = "重新发送(60s)";
        setTimeout("csdn.countdown(60)", 1000);
    }else{
        csdn.$('sperr').innerHTML = data.msg;
        csdn.$("send-code").innerHTML = "发送验证码";
        csdn.is_countdown = false;
    }
}

csdn.send_code = function(){
    if(csdn.is_countdown){
        return;
    }
    csdn.$('sperr').innerHTML = "";
    csdn.is_countdown = true;
    csdn.$("send-code").innerHTML = "发送中...";

    csdn.post(location.protocol + '//' + csdn.domain + "/account/fpwd?action=sendLoginMobileCode&mobile=" + csdn.$("mobile").value + "&callback=csdn.send_code_callback");
}

csdn.is_countdown = false;

csdn.countdown = function(i){
    if(i<=0){
        csdn.$("send-code").innerHTML = "发送验证码";
        csdn.is_countdown = false;
    }else{
        csdn.$("send-code").innerHTML = "重新发送(" + (i-1) + "s)";
        setTimeout("csdn.countdown(" + (i-1) + ")", 1000);
    }
}

csdn.loginFormByMobile = function () {
    var fromurl = encodeURIComponent(location.href);
    var text = 
    "<div class='csdn_loginbox' style='z-index: 100'>"
        + "<div class='login_content'>"
          + "<div class='login_content_inner'>"
        	+ "<div style='font-size: 12px;'>手机快捷登录 | <a href='javascript:csdn.showLogin(csdn.loginBack);' style='text-decoration: none;color: #428bca;'>帐号登录</a></div>"
        	+ "<input name='close' type='button' class='close'  onclick='javascript:csdn.closeLogin();return false;'  />"
        	+ "<p class='point' id='sperr'></p>"
        	+ "<input name='mobile'  id='mobile'  type='text' class='user_id' placeholder='手机号码' />"
        	+ "<input name='verificationCode' id='verificationCode' type='text' class='password' placeholder='验证码' style='width: 120px;'/>"
        	+ "<a id='send-code' href='javascript:csdn.send_code();' style='display: inline-block;background: #ddd;margin-left: 8px;width: 80px;height: 28px;line-height: 28px;font-size: 12px;white-space: nowrap;color: #333;text-align: center;text-decoration: none;'>发送验证码</a>"
        	+ "<div class='pw_lg'>"
        		+ "<a href='https://" + csdn.domain + "/account/forgotpassword' target='_blank' >忘记密码</a>|<a href='https://" + csdn.domain + "/account/register' target='_blank' class='pw_a'>注册</a>"
        	+ "</div>"
        	+ "<input name='button' type='button' onclick='javascript:csdn.login_by_mobile();return false;' value='登  录' class='login_bt'/>"
          + "</div>"
        + "</div>"
      + "</div>";

    return text;
};

csdn.login = function () {
    if (csdn.doing) return;
    var u = csdn.$('u');
    var p = csdn.$('p');
    var er = csdn.$('sperr');
    if (!u.value) {
        er.innerHTML = '* 请输入用户名/邮箱。';
        return;
    }
    if (!p.value) {
        er.innerHTML = '* 请输入密码。';
        return;
    }
    csdn.doing = true;
    er.innerHTML = '正在登录...';
    var url = location.protocol + '//' + csdn.domain + '/ajax/accounthandler.ashx';
    var data = 't=log&u=' + encodeURIComponent(u.value)
        + '&p=' + encodeURIComponent(p.value)
        + '&remember=' + (csdn.$('chkre').checked ? 1 : 0)
        + '&callback=csdn.login_back'
        + '&r=' + (new Date().getTime());

    csdn.post(url + '?' + data);
};



csdn.login_by_mobile = function () {

    if (csdn.doing) return;
    var m = csdn.$('mobile');
    var v = csdn.$('verificationCode');
    var er = csdn.$('sperr');
    if (!m.value) {
        er.innerHTML = '* 请输入手机号码。';
        return;
    }
    if (!v.value) {
        er.innerHTML = '* 请输入验证码。';
        return;
    }
    csdn.doing = true;
    er.innerHTML = '正在登录...';
    var url = location.protocol + '//' + csdn.domain + '/ajax/accounthandler.ashx';
    var data = 't=logmobile&m=' + encodeURIComponent(m.value)
        + '&v=' + encodeURIComponent(v.value)
        + '&callback=csdn.login_back'
        + '&r=' + (new Date().getTime());

    csdn.post(url + '?' + data);

};


csdn.login_back = function (data) {
    if (data.status) {
        var userName = data.data.userName;
        var userInfo = data.data.encryptUserInfo;
        var exp = csdn.$('chkre') ? (csdn.$('chkre').checked ? 7 : 0) : 0;
        var url = location.protocol + '//' + csdn.domain + '/home/ssoindex'
            + '?userName=' + encodeURIComponent(userName)
            + '&userInfo=' + encodeURIComponent(userInfo)
            + '&exp=' + exp;

        csdn.load_frm(url, csdn.login_ok(data));
    } else {
        if (data.error.indexOf("激活") > -1) {
            csdn.$('sperr').innerHTML = '* 账户未激活，请先<a href="https://' + csdn.domain + '/account/active?from=' + encodeURIComponent(location + '') + '" target=_blank>激活</a>。';
        } else {
            csdn.$('sperr').innerHTML = '* ' + data.error;
        }
        csdn.doing = false;
    }
};
csdn.login_ok = function (data) {
    csdn.doing = false;
    csdn.$('sperr').innerHTML = '<span style="color:green;">登录成功！</span>';
    if (csdn.loginBack) csdn.loginBack(data);
    csdn.closeLogin();
};
csdn.post = function (url, callback) {
    var sc = document.createElement("script");
    sc.type = 'text/javascript';
    sc.async = true;
    sc.src = url;
    if (callback) {
        if (sc.onload) sc.onload = callback;
        else sc.onreadystatechange = callback;
    }
    document.body.appendChild(sc);
};
csdn.arr_isloaded = [];
csdn.load_frm = function (url, loaded) {
    var idx = csdn.arr_isloaded.length;
    csdn.arr_isloaded[idx] = false;
    var frm = document.createElement("iframe");
    frm.style.width = '1px';
    frm.style.height = '1px';
    frm.style.visibility = 'hidden';
    frm.src = url;
    if (loaded) {
        var call = function () {
            if (!csdn.arr_isloaded[idx]) {
                csdn.arr_isloaded[idx] = true;
                loaded();
            }
        };
        if (frm.onreadystatechange) {
            frm.onreadystatechange = call;
        } else {
            frm.onload = call;
        }
        setTimeout(call, 5000);
    }
    document.body.appendChild(frm);
};

csdn.showWechatQr = function(){
	csdn.$("wxqr").style.display="block";
};

/*加载样式表单*/
(function () {
    if (typeof jQuery != 'undefined') {
        jQuery(csdn.setStyle);
    } else {
        var ld = window.onload;
        window.onload = function () {
            if (ld) ld();
            csdn.setStyle();
        };
    }
    var script = document.createElement("script");
    script.src = "https://res.wx.qq.com/connect/zh_CN/htmledition/js/wxLogin.js";
    document.head.appendChild(script);
    // document.write("<script src='https://res.wx.qq.com/connect/zh_CN/htmledition/js/wxLogin.js'></script>");
})();


