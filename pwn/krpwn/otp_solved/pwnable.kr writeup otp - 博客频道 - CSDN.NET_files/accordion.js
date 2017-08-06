/*
*create by liwz 2015-9-14
*文章分类折叠展开
*加关注及取消关注
*列表页面鼠标移上去显示编辑和删除按钮
*/
$(function()
{
    var oBlog = {
        oClientHeight: document.documentElement.clientHeight,
        slideFn:function()
        {
                var that = this;
                var aColumn = $(".js_column_wrap");
                aColumn.on("click",function()
                {
                    //var index = aColumn.index(this);
                    var _this = $(this);
                    if(_this.next().is(":hidden"))
                    {
                        _this.next().slideDown(200);
                    }
                    else
                    {
                        _this.next().slideUp(200);
                    }
                    return false;
                });
        },
        addAttention:function()
        {
            var oAdd = $("#add_attention");
            var strCon = oAdd.find("span");
            oAdd.on('click',function()
            {
                if(strCon.text() == '加关注')
                {
                    //$(this).addClass("alreadyAdd");
                    $("#add_attention span").text('已关注');
                }
                /*else if(strCon.text() == '取消关注')
                {
                    $(this).find(".fa").show();
                    $(this).removeClass("alreadyAdd");
                    strCon.text('加关注');
                }*/
            });
            /*oAdd.hover(function()
            {
                if(strCon.text() == '已关注')
                {
                    $(this).find(".fa").hide();
                    strCon.addClass("whiteColor").text("取消关注");
                }
            },function()
            {
                if(strCon.text() == '取消关注')
                {
                    $(this).find(".fa").show();
                    strCon.removeClass("whiteColor").text("已关注");
                }

            })*/
        },
        //列表页面鼠标移到相应的博文显示编辑和删除按钮
        showBtnFn:function()
        {
            var aList = $(".list_c");
            aList.hover(function()
            {
                $(this).children(".btn_right").show();
            },function()
            {
                $(this).children(".btn_right").hide();
            });
        },
        //点击详情页面的评论跳转到发表评论处，滚动条也相应移到相应的位置
        reCountScroll:function()
        {
            var that = this;
            //$("#skin_m").css({"height":that.oClientHeight})
            //var oSkin_centerH = $(".skin_center_t").outerHeight();
            var scrollH = $("#skin_center").outerHeight();
            var barH,scrollbottom,scrollBarTop;
            $("#comments_btn").on("click",function()
            {
                var oCenterH = $("#comments").offset().top;
                console.log(oCenterH);
                if(scrollH > that.oClientHeight)
                {
                    $(".scrollbar").show();
                    barH = parseInt((that.oClientHeight / scrollH) * that.oClientHeight);
                    scrollbottom = that.oClientHeight - barH;
                    scrollBarTop = oCenterH/(scrollH - that.oClientHeight)*scrollbottom + 'px';
                    console.log(scrollBarTop);
                    $(".scrollbar").animate({'top':scrollBarTop},200);
                    creatScroll('skin_m', 'skin_center', that.oClientHeight);
                }

                /*$("#skin_center").animate({'top':-oSkin_centerH},200);
                if(scrollH > that.oClientHeight)
                {
                    barH = parseInt((that.oClientHeight / scrollH) * that.oClientHeight);
                    scrollbottom = that.oClientHeight - barH;
                    scrollBarTop = oSkin_centerH/(scrollH - that.oClientHeight)*scrollbottom + 'px';
                    $(".scrollbar").animate({'top':scrollBarTop},200);
                }*/
            });
        },
        //鼠标移到排名上显示积分
        showIntergral:function()
        {
            var oGrage = $(".grade p:first-child");
            var oHtml = '<div id="intergral_pop">积分：<em>154893</em><div class="triangle_tip"></div></div>';
            oGrage.on('mouseenter',function()
            {
                $(this).append(oHtml);
            });
            oGrage.on('mouseleave',function()
            {
                $("#intergral_pop").remove();
            });
        },
        //滚动条插件
        scrollBar:function()
        {
            $('#skin_m, #skin_r_wrap').rollbar({zIndex:80});
        }
    }

    //右侧各分类折叠展开
    oBlog.slideFn();
    oBlog.addAttention();
    oBlog.showBtnFn();
    oBlog.reCountScroll();
    oBlog.showIntergral();
    oBlog.scrollBar();
});










