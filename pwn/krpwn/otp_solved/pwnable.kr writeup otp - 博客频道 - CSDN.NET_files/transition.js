/*
*create by liwz 2015-9-15
*1、动画效果
*2、评论选code
*3、评论回复、引用
*/
$(function()
{
    var transition = (function()
    {
            var navicon = $("#faNavicon");
            var skin_r_small = $("#skin_right_small");
            var skin_r = $(".skin_right");
            var arrow_r = $("#arrow_r");
            var smallArticle = $(".js_smallArticle");
            var aColumn = $(".js_list");
            var oClientH = document.documentElement.clientHeight
            navicon.on("click",function()
            {
                rUnfold();
            });
            smallArticle.each(function()
            {
                $(this).click(function()
                {
                    rUnfold();
                    var index = smallArticle.index(this);
                    var aColumnList = aColumn.eq(index).find(".article_list");
                    if(aColumnList.is(":hidden"))
                    {
                        aColumnList.show();
                        //creatScroll('skin_r_wrap', 'skin_r', oClientH);
                    }
                    else
                    {
                        aColumnList.hide();
                        //creatScroll('skin_r_wrap', 'skin_r', oClientH);
                    }
                    return false;
                })
            });
            arrow_r.on("click",function()
            {
                rFold();
                //window.location.reload();
                return false;
            });
            if($(window).width()<1400)
            {
                    arrow_r.on("click",function()
                    {
                        rFold();
                        return false;
                    })
            };
            //点击mask时收缩
            $("#mask").on("click",function()
            {
                if($(window).width()<1400)
                {
                    rFold();
                }
                else
                {
                    rUnfold();
                    $(this).hide();
                }
                return false;
            })

            //右侧展开
            function rUnfold()
            {
                $("#mask").show();
                /*skin_r.addClass("skin_r_show").removeClass('skin_r_hide');
                skin_r_small.addClass('skin_r_small_hide').removeClass('skin_r_small_show');*/
                skin_r.css({
                    "right":"0",
                    "transition":"all 0.6s ease"
                });
                skin_r_small.css({
                    "right":"-250px",
                    "transition":"all 0.6s ease"
                });
            }
            //右侧收缩
            function rFold()
            {
                $("#mask").hide();
                /*skin_r.addClass("skin_r_hide").removeClass('skin_r_show');
                skin_r_small.addClass('skin_r_small_show').removeClass('skin_r_small_hide');*/
                skin_r.css({
                    "right":"-250px",
                    "transition":"all 0.6s ease"
                });
                skin_r_small.css({
                    "right":"0",
                    "transition":"all 0.6s ease"
                });
            }
    })();

    //评论点击切换代码语言(code)
    var code = (function()
    {
        $(".J_code").on("click",show);
        $(".J_lang_list").on("click",show);
        function show(ev)
        {
            ev.stopPropagation();
            $(this).closest(".publish").find(".J_lang_list").show();
        }
        $(document).on("click",function()
        {
            $(".J_lang_list").hide();
        })
    })();

    //评论代码
    var comment = (function ()
    {
        var aComBtn = $(".fa-mail-forward");
        var aUser = $(".comment_list .J_userNT").text();
        aComBtn.on("click",function()
        {
            var parent = $(this).parents(".bole_comment");
            var User_t = $(this).closest(".comment_b").siblings(".J_userNT").text();
            var publish_box = parent.find(".publish_comment");
            publish_box.show();          //评论框显示
            publish_box.find(".J_usern em").text(User_t);    //显示回复一级评论还是二级评论
            publish_box.find(".publish_txt").focus();      //评论框获取焦点
        })
    })();

    //点击引用按钮，评论框中可以引用之前评论的内容
    var quote = (function()
    {
        var aQuote = $(".fa-quote-left");
        aQuote.on("click",function()
        {
            var quote_txt = $(this).closest(".comment_b").prev().text();
            $(this).parents(".bole_comment").find(".publish_txt").text('[quote]' + quote_txt + '[quote]');
        })
    })();

    //评论点击切换代码语言
    $("#J_code").on("click",show);
    $("#lang_list").on("click",show);
    function show(ev)
    {
        $("#lang_list").show();
        ev.stopPropagation();
    }
    $(document).on("click",function(ev)
      {
          var ev = ev || event;
          $("#lang_list").hide();
      });

});










