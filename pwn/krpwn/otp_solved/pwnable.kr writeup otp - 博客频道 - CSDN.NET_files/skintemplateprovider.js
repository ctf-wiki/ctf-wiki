$(function () {
    copyrightInit();
    guanzhuInit();
    rightcolumInit();
    bolecommentInit();
    diggInit();
    searchInit();
    //buildCTable();
    $(".js_column_wrap").click(function () {
        //setTimeout(function () {
        //    scrollInit();
        //}, 3000);        
    });
    //setTimeout(function () {
    //    scrollInit();
    //}, 1000);
});

function copyrightInit()
{
    var copyright = $("#copyright");
    var copyrightcontent = copyright.html();
    if (copyrightcontent != "") {
        copyright.show();
    }
}

function guanzhuInit()
{
    var un = getUN().toLowerCase();
    if (un == _blogger.toLowerCase()) {
        $('.attention').hide();
    } else if (un) {
        set_guanzhu_status(un);
    } else {
        if (un != "") {
            $('#span_add_follow')[0].onclick = (function () {
                loginto(0);
            });
        }
        else {
            $('#span_add_follow')[0].onclick = (function () {
                loginbox();
            });
        }
    }
}

function set_guanzhu_status(un) {
    var url = "http://my.csdn.net/index.php/follow/check_is_followed/" + encodeURIComponent(un) + "/" + encodeURIComponent(_blogger) + "?jsonpcallback=?";
    $.getJSON(url, {}, function (data) {
        if (data.succ == 1 && data.info == 1) {
            $("#span_add_follow span").text('已关注');
            $('#span_add_follow').attr('class', 'alreadyAdd')[0].onclick = (function () {
                return false;
            });
        } else {
            $('#span_add_follow')[0].onclick = guanzhu;
        }
    }, 'json');
}

function guanzhu() {
    var url = "http://my.csdn.net/index.php/follow/do_follow?jsonpcallback=?";
    $.getJSON(url, { "username": _blogger }, function (data) {
        if (data.succ == 1) {
            $("#span_add_follow span").text('已关注');
            alert('关注成功！');
            $('#span_add_follow').attr('class', 'alreadyAdd')[0].onclick = (function () {
                return false;
            });
        } else {
            alert(data.msg);
        }
    });
    return false;
}

function getUN() {
    var m = document.cookie.match(new RegExp("(^| )UserName=([^;]*)(;|$)"));
    if (m)
        return m[2];
    else
        return '';
}

function rightcolumInit()
{
    for (var i = 0; i < 2; i++)
    {
        var obj = $("#article_list" + i);
        if (obj.find("li").length > 0)
        {
            obj.parent().parent().show();
        }
    }
}

function bolecommentInit()
{
    if ($(".bole").find("dl").length > 0)
    {
        $(".bole").show();
    }
}

function diggInit() {
    var un = getUN().toLowerCase();
    if (un != "") {
        var diggdiv = $("#digg");
        var articleId = diggdiv.attr("ArticleId");
        $("#btnDigg,#btnBury").click(function () {
            var id = $(this).attr("id");
            var action = id == "btnDigg" ? "digg" : "bury";
            //blog_address = "http://dev.blog.csdn.net:5391/csdntest01";
            $.get(blog_address + "/article/" + action + "?ArticleId=" + articleId, function (data) {
                $("#digg em").html(data.digg);
                $("#bury em").html(data.bury);
            });
        });
    }
    else {
        $("#btnDigg,#btnBury").click(function () {
            loginbox("digg");
        });        
    }
}

function searchInit()
{
    $("#btnSubmit").click(function () {
        search();
    });

    $("#frmSearch").submit(function () {
        search();
        return false;
    });
}

function search() {
    var url = "http://so.csdn.net/so/search/s.do?q=" + encodeURIComponent($("#inputSearch").val()) + "&u=" + username + "&t=blog";
    window.location.href = url;
}


function buildCTable() {
    var hs = $('#article_content').find('h1,h2,h3,h4,h5,h6');
    if (hs.length < 2)
        return;
    var s = '';
    s += '<div style="clear:both"></div>';
    s += '<div style="border:solid 1px #ccc; background:#eee; float:left; min-width:200px;padding:4px 10px;">';
    s += '<p style="text-align:right;margin:0;"><span style="float:left;">目录<a href="#" title="系统根据文章中H1到H6标签自动生成文章目录">(?)</a></span><a href="#" onclick="javascript:return openct(this);" title="展开">[+]</a></p>';
    s += '<ol style="display:none;margin-left:14px;padding-left:14px;line-height:160%;">';
    var old_h = 0, ol_cnt = 0;
    for (var i = 0; i < hs.length; i++) {
        var h = parseInt(hs[i].tagName.substr(1), 10);
        if (!old_h)
            old_h = h;
        if (h > old_h) {
            s += '<ol>';
            ol_cnt++;
        }
        else if (h < old_h && ol_cnt > 0) {
            s += '</ol>';
            ol_cnt--;
        }
        if (h == 1) {
            while (ol_cnt > 0) {
                s += '</ol>';
                ol_cnt--;
            }
        }
        old_h = h;
        var tit = hs.eq(i).text().replace(/^\d+[.、\s]+/g, '');
        tit = tit.replace(/[^a-zA-Z0-9_\-\s\u4e00-\u9fa5]+/g, '');

        if (tit.length < 100) {
            s += '<li><a href="#t' + i + '">' + tit + '</a></li>';
            hs.eq(i).html('<a name="t' + i + '"></a>' + hs.eq(i).html());
        }
    }
    while (ol_cnt > 0) {
        s += '</ol>';
        ol_cnt--;
    }
    s += '</ol></div>';
    s += '<div style="clear:both"></div>';
    $(s).insertBefore($('#article_content'));
}
function openct(e) {
    if (e.innerHTML == '[+]') {
        $(e).attr('title', '收起').html('[-]').parent().next().show();
    } else {
        $(e).attr('title', '展开').html('[+]').parent().next().hide();
    }
    e.blur();
    return false;
}