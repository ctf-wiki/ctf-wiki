var list = []; //评论列表
var editorId = "#comment_content";
var verifycodeId = "#img_verifycode";
var listId = "#comment_list";

$(document).ready(init_comment);

(function ($) {
    $.fn.extend({
        selection: function () {
            var selectedValue = '';
            var me = this[0];
            if (document.selection) {
                var range = document.selection.createRange();
                selectedValue = range.text;
            }
            else if (typeof (me.selectionStart) == 'number') {
                var start = me.selectionStart;
                var end = me.selectionEnd;
                if (start != end) {
                    selectedValue = me.value.substring(start, end);
                }
            }
            return $.trim(selectedValue);
        }, parseHtml: function (val) {
            var me = this[0];
            var value = $(this).val();
            if (document.selection) {
                var range = document.selection.createRange();
                if (range.text) {
                    range.text = val;
                } else {
                    $(this).val(value + val);
                }
            } else if (typeof (me.selectionStart) == 'number') {
                var start = me.selectionStart;
                var end = me.selectionEnd;
                var startVal = value.substring(0, start);
                var endVal = value.substring(end);
                $(this).val(startVal + val + endVal);
            }
            else
                $(this).val(value + val);
            me.selectionStart = me.selectionEnd = $(this).val().length;
            me.focus();
        }
    });
})(jQuery);



function init_comment() {
    load_comment_form();

    editor = $(editorId);

    var editor_inter = null;
    if (editor.length > 0) {    
        //$("#lang_list").append('<a class="long_name" href="#html">HTML/XML</a><a class="long_name" href="#objc">objective-c</a><a class="zhong_name" href="#delphi">Delphi</a><a  class="zhong_name" href="#ruby">Ruby</a><a href="#php">PHP</a><a class="duan_name" href="#csharp">C#</a><a style=" border-right: none;"  class="duan_name" href="#cpp">C++</a><a style=" border-bottom:none;"class="long_name" href="#javascript">JavaScript</a><a style=" border-bottom:none;" class="long_name" href="#vb">Visual Basic</a><a style=" border-bottom:none;" class="zhong_name" href="#python">Python</a><a style=" border-bottom:none;" class="zhong_name" href="#java">Java</a><a style="border-bottom:none;" class="duan_name" href="#css">CSS</a><a style="border-bottom:none;" class="duan_name" href="#sql">SQL</a><a style="border:none;"  class="duan_name" href="#plain">其它</a>');
        editor.focus(function () {
            editor_inter = setInterval(function () {
                commentTip("还能输入" + (1000 - editor.val().length) + "个字符");
            }, 200);
        }).blur(function () {
            if (editor_inter) clearInterval(editor_inter);
        });
    }

    //加载列表
    loadList(1);

}
function noComments() {
    $(listId).html('<br />&nbsp;&nbsp;暂无评论<br /><br /><div class="clear"></div>');
}
function loadList(pageIndex, isSub) {
    if (commentscount == 0) {
        noComments();
        return;
    }
    pageIndex = parseInt(pageIndex) || 1;

    $("#comments_bar").html("正在加载评论...");
    //var cmtUrl = "../../comment/list/" + fileName + "?page=" + (pageIndex || 1);
    var url = location.href.toString().split('/');
    var cmtUrl = "http://"+url[2]+"/"+url[3]+"/comment/list/" + fileName + "?page=" + (pageIndex || 1);
    if (isSub) cmtUrl += "&_" + Math.random();
    $.get(cmtUrl, function (json) {

        if (!json) {
            noComments();
            return;
        }
        var data = (typeof json == 'object') ? json : eval("(" + json + ")");
        if (isSub) list = data.list;
        else list = list.concat(data.list);

        var listHtml = '';
        //listHtml+=' <h3 class="com_list_t">共有4条评论</h3>';

        //构造主题
        var topics = getTopics(list);

        var total = data.total > 0 ? data.total : topics.length;
        //组装HTM
        for (var i = 0; i < topics.length; i++) {
            var comment = topics[i];
            var layer = total - i;

            listHtml += getItemHtml(comment, layer);
        }
        listHtml += '<div class="clear"></div>';
        //输出列表
        $(listId).html(listHtml);
        //高亮评论中的代码段
        dp.SyntaxHighlighter.HighlightAll('code2');
        //展示昵称
        new CNick(listId + ' a.username').showNickname();

        //分页处理
        if (data.page.PageIndex >= data.page.PageCount) {
            $("#comment_bar").hide();
        } else {
            $("#comment_bar").html('<div id="load_comments" page="' + (pageIndex + 1) + '">查看更多评论</div>');
        }
        //添加按钮事件
        setBtnEvent();

        //scrollInit();
    });
};

//获取评论主题
function getTopics(list) {
    var topics = [];
    for (var i = 0; i < list.length; i++) {
        var t = list[i];
        if (t.ParentId == 0) {
            t.Replies = getReplies(t, list);
            topics.push(t);
        }
    }
    return topics;
}
//获取评论回复
function getReplies(item, list) {
    var replies = [];
    for (var i = 0; i < list.length; i++) {
        var r = list[i];
        if (r.ParentId == item.CommentId) {
            r.Replies = getReplies(r, list);
            replies.push(r);
        }
    }
    return replies;
}
//获取评论的HTML
function getItemHtml(comment, index, floor, deep) {        
    var html = ' <dl class="bole_comment clearfix" id="comment_item_' + comment.CommentId + '">';
    html += '           <dt>';
    html += '               <a href="/' + comment.UserName + '"><img src="' + comment.Userface + '" alt="' + comment.UserName + '"></a></dt>';
    html += '           <dd>';
    html += '             <h3 class="username J_userNT">' + comment.UserName + '</h3>';
    html += '             <div class="comment_p">' + replaceUBBToHTML(comment) + '</div>';
    html += '             <div class="comment_b clearfix"><span>' + comment.PostTime + '</span>';

    html += '               <label>';
    html += '                 <a href="#reply" class="com_reply" title="回复" commentid="' + comment.CommentId + '" floor="' + index + '"> <i class="fa fa-mail-forward"></i><a>';
    html += '                 <a href="#quote" class="com_reply" title="引用" commentid="' + comment.CommentId + '" floor="' + index + '"> <i class="fa fa-quote-left"></i><a>';
    html += '                 <a href="#report" class="com_reply" title="举报" commentid="' + comment.CommentId + '" floor="' + index + '"> <i class="fa fa-exclamation-triangle"></i><a>';
    if (currentUserName != "" && comment.UserName != "" && comment.UserName.toLowerCase() == currentUserName.toLowerCase()) {
        html += '                 <a href="#delete" class="com_reply" commentid="' + comment.CommentId + '" floor="' + floor + '"> <i class="fa fa-close"></i><a>';
    } else if (currentUserName != "" && currentUserName.toLowerCase() == username.toLowerCase()) {
        html += '                 <a href="#delete" class="com_reply" commentid="' + comment.CommentId + '" floor="' + floor + '"> <i class="fa fa-close"></i><a>';
    }
    html += '               </label>';

    html += '             </div>';

    if (comment.Replies != null) {
        for (var j = 0; j < comment.Replies.length; j++) {
            html += getChildItemHtml(comment.Replies[j], j + 1, index, deep + 1);
        }
    }

    html += '            </dd>';
    html += '          </dl>';

    return html;
}

function getChildItemHtml(comment, index, floor, deep) {

    var html = ' <dl class="bole_comment clearfix" id="comment_item_' + comment.CommentId + '">';
    html += '    <dt><a href="/' + comment.UserName + '"><img src="' + comment.Userface + '" alt="' + comment.UserName + '"></a></dt>';
    html += '    <dd>';
    html += '      <h3 class="username J_userNT">' + comment.UserName + '</h3>';
    html += '       <div class="comment_p">' + replaceUBBToHTML(comment) + '</div>';
    html += '       <div class="comment_b"><span>' + comment.PostTime + '</span>';
    
    html += '               <label>';
    html += '                 <a href="#reply" class="com_reply" commentid="' + comment.CommentId + '" floor="' + floor + '"> <i class="fa fa-mail-forward"></i><a>';
    html += '                 <a href="#quote" class="com_reply" commentid="' + comment.CommentId + '" floor="' + floor + '"> <i class="fa fa-quote-left"></i><a>';
    html += '                 <a href="#report" class="com_reply" commentid="' + comment.CommentId + '" floor="' + floor + '"> <i class="fa fa-exclamation-triangle"></i><a>';
    if (currentUserName != "" && comment.UserName != "" && comment.UserName.toLowerCase() == currentUserName.toLowerCase()) {
        html += '                 <a href="#delete" class="com_reply" commentid="' + comment.CommentId + '" floor="' + floor + '"> <i class="fa fa-close"></i><a>';
    }
    else if (currentUserName != "" && currentUserName.toLowerCase() == username.toLowerCase()) {
        html += '                 <a href="#delete" class="com_reply" commentid="' + comment.CommentId + '" floor="' + floor + '"> <i class="fa fa-close"></i><a>';
    }
    html += '               </label>';

    html += '                  </div>';
    html += '                </dd>';
    html += '              </dl>';
  
    return html;
}

//获取评论对象
function getComment(commentId, list) {
    for (var i = 0; i < list.length; i++) {
        var comment = list[i];
        if (comment.CommentId == commentId)
            return comment;
    }
    return null;
}
function setBtnEvent() {

    $("#load_comments").click(function () {
        var page = $(this).attr("page");
        loadList(page);
    });

    //评论按钮点击
    $(".com_reply").click(function () {
        var action = $(this).attr("href");

        action = action.substring(action.lastIndexOf('#'));

        var commentId = $(this).attr("commentid");
        switch (action) {
            case "#reply":
                if (currentUserName) {                   
                    replyComment(commentId, list);
                    setEditorFocus();
                }
                return true;
            case "#quote":
                if (currentUserName) {                   
                    quoteComment(commentId, list);
                    setEditorFocus();
                }
                return true;
            case "#report":             
                reportComment(commentId, $(this));
                break;
            case "#delete":
                deleteComment(commentId);
                break;
            default:
                return true;
        }
        return false;
    });    
}
/*使评论框获得焦点*/
function setEditorFocus() {
    var val = editor.val();
    editor.val('');
    editor.focus();
    editor.val(val);
}
//引用评论
function quoteComment(commentId, list) {
    var comment = getComment(commentId, list);
    var content = comment.Content;
    if (comment.Content.length > 50) {
        content = comment.Content.substring(0, 50) + "...";
    }
    editor.val("[quote=" + (comment.UserName == null ? "游客" : comment.UserName) + "]" + content + "[/quote]\r\n");
}
//回复评论
function replyComment(commentId, list) {
    var comment = getComment(commentId, list);
    editor.val('[reply]' + comment.UserName + "[/reply]\r\n");
    $("#comment_replyId").val(commentId);
}
//举报评论
function reportComment(commentId, e) {
    report(commentId, 3, e);
}
//删除评论
function deleteComment(commentId) {
    if (!confirm("你确定要删除这篇评论吗？")) return;

    var delUrl = blog_address + "/comment/delete?commentid=" + commentId + "&filename=" + fileName;
    $.get(delUrl, function (data) {
        if (data.result == 1) {
            $("#comment_item_" + commentId).hide().remove();
        } else {
            alert("你没有删除该评论的权限！");
        }
    });
}
//替换评论的UBB代码
function replaceUBBToHTML(comment) {
    var content = $.trim(comment.Content);

    var re = /\[code=([\w#\.]+)\]([\s\S]*?)\[\/code\]/ig;

    var codelist = [];
    while ((mc = re.exec(content)) != null) {
        codelist.push(mc[0]);
        content = content.replace(mc[0], "--code--");
    }
    content = replaceQuote(content);
    //content = content.replace(/\[e(\d+)\]/g, "<img src=\"" + static_host + "/images/emotions/e$1.gif\"\/>");
    content = content.replace(/\[reply]([\s\S]*?)\[\/reply\][\r\n]{0,2}/gi, "回复$1：");
    content = content.replace(/\[url=([^\]]+)]([\s\S]*?)\[\/url\]/gi, '<a href="$1" target="_blank">$2</a>');
    content = content.replace(/\[img(=([^\]]+))?]([\s\S]*?)\[\/img\]/gi, '<img src="$3" style="max-width:400px;max-height:200px;" border="0" title="$2" />');
    //content = content.replace(/\[(\/?)(b|i|u|p)\]/ig, "<$1$2>");
    content = content.replace(/\r?\n/ig, "<br />");

    if (codelist.length > 0) {
        var re1 = /--code--/ig;
        var i = 0;
        while ((mc = re1.exec(content)) != null) {
            content = content.replace(mc[0], codelist[i]);
            i++;
        }
    }
    content = content.replace(/\[code=([\w#\.]+)\]([\s\S]*?)\[\/code\]/ig, function (m0, m1, m2) {
        if ($.trim(m2) == "") return '';
        return '<pre name="code2" class="' + m1 + '">' + m2 + '</pre>';
    });
    return content;
}
//替换评论的引用
function replaceQuote(str) {
    var m = /\[quote=([^\]]+)]([\s\S]*)\[\/quote\]/gi.exec(str);
    if (m) {
        return str.replace(m[0], '<fieldset><legend>引用“' + m[1] + '”的评论：</legend>' + replaceQuote(m[2]) + '</fieldset>');
    } else {
        return str;
    }
}



function load_comment_form() {
    $("#commentbox").hide();
    var un = getcookie("UserName").toLowerCase();
    if (islock) {
        $("#commentsbmitarear").html("<div class='notice'>该文章已被禁止评论！</div>");
    } else if (currentUserName || (un != null&&un!=""&&un!=undefined)) {
        $("#commentbox").show()             
             
        $(".publish_btn").click(function () {
            $("#commentform").submit();
        });       
    } else {
        var curl = encodeURIComponent(location.href);
        $("#commentsbmitarear").html('<div class="guest_link">您还没有登录,请' +
		//'<a href="javascript:void(0);" onclick="javascript:csdn.showLogin(function (dat) {js_logined(dat.data.userName);});">[登录]</a>或' +
        '<a href="javascript:void(0);" onclick="javascript:loginbox();">[登录]</a>或' +
		'<a href="http://passport.csdn.net/account/register?from=' + curl + '">[注册]</a></div>');
    }
    ubb_event(); 
}

function getcookie(name) {
    var cookie_start = document.cookie.indexOf(name);
    var cookie_end = document.cookie.indexOf(";", cookie_start);
    return cookie_start == -1 ? '' : unescape(document.cookie.substring(cookie_start + name.length + 1, (cookie_end > cookie_start ? cookie_end : document.cookie.length)));
}

var c_doing = false;
function subform(e) {
    if (c_doing) return false;
    var content = $.trim($(editorId).val());
    if (content == "") {
        commentTip("评论内容没有填写!");
        return false;
    } else if (content.length > 1000) {
        commentTip("评论内容太长了，不能超过1000个字符！");
        return false;
    }
    var commentId = $("#commentId").val();
    commentTip("正在发表评论...");
    var beginTime = new Date();
    $(editorId).attr("disabled", true);
    $("button[type=submit]", e).attr("disabled", true);
    c_doing = true;
    $.ajax({
        type: "POST",
        url: $(e).attr("action"),
        data: {
            "commentid": commentId,
            "content": content,
            "replyId": $("#comment_replyId").val(),
            "boleattohome": $("#boleattohome").val()
        },
        success: function (data) {
            c_doing = false;
            commentTip(data.content);
            if (data.result) {
                var rcommentid=$("#comment_replyId").val()
                $(editorId).val('');
                $("#comment_replyId,#comment_verifycode").val('');

                commentscount++;
                loadList(1, true);
                $(editorId).attr("disabled", false);
                $("button[type=submit]", e).attr("disabled", false);

                commentTip("发表成功！评论耗时:" + (new Date() - beginTime) + "毫秒")

                if (rcommentid!=undefined && rcommentid != "")
                {
                    $("html,body").animate({ scrollTop: $("#comment_item_" + rcommentid).offset().top }, 1000);
                }
                
            }
        }
    });
    return false;
}

//操作提示
var _c_t;
function commentTip(message) {
    $("#tip_comment").html(message).show();
    clearTimeout(_c_t);
    _c_t = setTimeout(function () {
        $("#tip_comment").hide();
    }, 10000);
}


function ubb_event() {
    //ubb按钮事件
    $("#lang_list").children().click(function () {
        editor = $(editorId);
        var selectedValue = editor.selection();
        editor.focus();
        var code = $(this).parent().attr("code");
        switch (code) {
            case "code":
                var lang_list = $("#lang_list");
                lang_list.show();
                lang_list.children().each(function () {
                    $(this).unbind("click").click(function () {
                        editor.val("[code=" + $.trim(this.href.split('#')[1]) + "]\n" + selectedValue + "\n[/code]");                        
                        setTimeout(function () { lang_list.hide();; }, 200);
                    });
                });
                editor.click(function (e) {
                    lang_list.hide();
                });
                break;
            default:
                editor.val("[" + code + "]" + selectedValue + "[/" + code + "]");
                break;
        }
        return false;
    });

   
    editor = $(editorId);
    $("#lang_list").children().each(function () {       
        var selectedValue = editor.selection();
        //editor.focus();

        $(this).unbind("click").click(function () {
            editor.val("[code=" + $.trim(this.href.split('#')[1]) + "]\n" + selectedValue + "\n[/code]");
            setTimeout(function () { $("#lang_list").hide(); }, 200);
        });
    });
}

