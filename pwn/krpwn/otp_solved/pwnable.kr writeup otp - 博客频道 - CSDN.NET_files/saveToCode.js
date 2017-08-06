/*
* @file 博客的代码片段保存到code的代码片
* @author liwz
* @create Time 2016-5-19
* */

$(function()
{
    (function(){
        var oBlog_code = {},
            $target,
            i = 0,b = false,
            title = $.trim($(".list_c_t a").text() || $(".link_title a").text()),
            code,lang,username,description,tags,
            newVal ='';
        username = currentUserName;
        //获取页面中默认的tag
        oBlog_code.getTag = function (){
            var pageTags = $('.link_categories a');
            var len = pageTags.length,oPageTag='';
            len = len <= 5 ? len : 5;
            pageTags.each(function(){
                oPageTag += '<span class=\"label blog_tag\"><span>' + $(this).text() +
                        '</span><a title=\"Removing tag\" href=\"javascript:;\">x</a></span>';
                newVal +=  $(this).text() + ',';
            });
            i=len;
            return oPageTag;
        };
        /**
         * 页面开始加载时把收藏代码片的按钮和弹层预先加载到页面中,上报
         * */

        oBlog_code.preLoad = function(){
            var _this = this;
            var oWrap = $(".dp-highlighter,.prettyprint"),
                    oSnippetsBtn = '<div class="save_code tracking-ad" data-mod="popu_249"><a href="javascript:;"><img src="http://static.blog.csdn.net/images/save_snippets.png"/></a></div>',
                    winHref= window.location.href,
                    oTagHtml;
            oWrap.each(function(){
                $(this).append(oSnippetsBtn);
            });
            oTagHtml = _this.getTag();
            $('body').append("<div id='mask_code'></div>");
            var oHtml = '<div class="gist_edit" ><div class="save_snippets clearfix">'+
                    '<div class="tit"><h3>保存代码片</h3><span>整理和分享保存的代码片，请访问<a href="https://code.csdn.net/snippets_manage" target="_blank">代码笔记</a></span></div>'+
                    '<div class="con_form"><ul class="gist_edit_list clearfix"><li><span class="red">*</span><span class="txt">标题</span>'+
                    '<input id="form_title" class="form-input" placeholder="" type="text"></li><li><span class="red">*</span><span class="txt">描述</span><textarea id="form-textarea" class="form-textarea" placeholder=""></textarea></li><li><span class="red">&nbsp;</span><span class="txt">标签</span>'+
                    '<div id="divSearchTags">';
            oHtml += oTagHtml;
            oHtml +='<input id="insertTag" class="insertTag" placeholder="请输入标签，按Enter生成(最多5项)" type="text" value="" name="insertTag"  maxlength="21" style="color: rgb(51, 51, 51);">'+
                    '<input id="OrganTag" class="OrganTag" type="hidden" name="OrganTag" value='+newVal+'>'+
                    '<input id="OldOrganTag" class="OldOrganTag" type="hidden" name="OldOrganTag" value=""><input type="hidden" name="txtSearchTags"></div>'+

                    '</li></ul></div><div class="bottom-bar"><a href="javascript:;" class="btn-submit btn-cancel">取消</a><span class="tracking-ad"  data-mod="popu_250"><a class="btn-submit btn-confirm"  href="javascript:;">确定</a></span></div></div></div>';

            $('body').append(oHtml);
            $("#form_title").attr("placeholder",decodeURIComponent(title));
            $("#form-textarea").attr("placeholder",decodeURIComponent(title) + '： ' + winHref );
        }
        oBlog_code.preLoad();


         //鼠标移上去显示保存到我的代码片按钮
        (function()
        {
            $(document).delegate('.dp-highlighter,.prettyprint','mouseenter',function()
            {
                if($(this).height() < 80){
                    //$(this).addClass("pad_bot");
                    $(this).find(".save_code img").attr("src",'http://static.blog.csdn.net/images/save_snippets_01.png');
                }
                $(this).find('.save_code').show();
                return false;
            });
            $(document).delegate('.dp-highlighter,.prettyprint','mouseleave',function()
            {
                $(this).find('.save_code').hide();
                //$(this).removeClass("pad_bot");
                return false;
            });
        })();
        oBlog_code.getLang = function (str,htmlEdit){
            var _this = this;
            if(str != undefined){
                str = str.split(' ')[0];
                str = str.substring(9,str.length);
                //lang = preLan;
                _this.handle(str);
            }else{
                htmlEdit = encodeURIComponent(htmlEdit.substring(1,htmlEdit.length-1));
                _this.handle(htmlEdit);
            }
        };
        //处理字符串成code可识别的语言类型
        oBlog_code.handle = function (str){
            var langArr = {
                'cpp':'c++',
                'csharp':'c#',
                'obj-c':'objective-c',
                'objc':'objective-c'
            };
            for(var key in langArr){
                if(str.toLowerCase() == key ){
                    if(str != langArr[str]){
                        str = langArr[str];
                    }
                }
            }
            lang = encodeURIComponent(str);
        };
        //点击保存按钮弹出弹层
        oBlog_code.showPop = function()
        {
            var _this = this;

            $(document).delegate('.save_code','click',function(ev)
            {
                var event = ev || event;
                title = $.trim($(".list_c_t a").text() || $(".link_title a").text());
                $target = $(event.target || event.srcElement);
                code = $(this).parents('.prettyprint').find('code').text() || $(this).parents('.dp-highlighter').next('pre').text() || $(this).parents('.dp-highlighter').siblings('textarea[name="code"]').text();
                code = encodeURIComponent(code);
                if(code == ''){
                    alert("无法获取到code代码！");
                    return;
                }
                var preLan = $(this).parents('.prettyprint').find('code').attr('class');
                var htmlEdit = $(this).parents('.dp-highlighter').find('.bar').find('strong').text() || $(this).parents('.dp-highlighter').find('.bar').find('b').text();
                //获取语言类型
                _this.getLang(preLan,htmlEdit);

                if(currentUserName)
                {
                    $('#mask_code').show();
                    $('.gist_edit').show();

                    var offsetTop = $(window).scrollTop() + $(window).height()/2;
                    $(".gist_edit").css({
                        "top":offsetTop
                    });
                }
                else
                {
                    window.location.href = "https://passport.csdn.net/";
                }
            })
        };
        oBlog_code.showPop();

        oBlog_code.hidePop = function(obj)
        {
            var _this = this;
            $(document).delegate('.btn-cancel','click',function()
            {
                $("#form-textarea").val('');
                $("#form_title").val('');
                _this.resetTag(obj);
            });

            //点击确定保存到code的代码段
            $(document).delegate('.btn-confirm','click',function()
            {
                description = encodeURIComponent($("#form-textarea").val() || $("#form-textarea").attr('placeholder'));
                title = encodeURIComponent($("#form_title").val() || title);
                tags = encodeURIComponent($("#OrganTag").val());

                $.ajax({
                    type: "post",
                    /*dataType:"jsonp",
                    jsonp:'callback',*/
                    url: "http://blog.csdn.net/"+currentUserName+"/svc/addpostcode",
                    data: 'code='+code+'&lang='+lang + '&username='+username + '&title='+title + '&description='+description + '&tags='+tags,
                    success: function(msg){
                        if(msg)
                        {
                            alert("保存成功！");
                            _this.resetTag(obj);
                        }
                    },
                    error:function()
                    {
                        alert("保存失败");
                    }
                });
            });
        };
        oBlog_code.hidePop('#divSearchTags');

        //把弹层隐藏
        oBlog_code.resetTag = function ()
        {
            $('#mask_code').hide();
            $('.gist_edit').hide();
        };

        oBlog_code.enterTag = function (Wrap,insert){
            var _this = this;
            var event = arguments.callee.caller.arguments[0] || window.event; //消除浏览器差异
            if (event.keyCode == 13 || event.keyCode == 188) {
                _this.addTag(Wrap,insert);
            }
        };
        oBlog_code.addTag = function (Wrap,insert)
        {
            var insertval = $.trim($(insert).val());
            if (insertval != "")
            {
                //排重
                $(''+Wrap+'>span>span').each(
                        function ()
                        {
                            var spanval =$.trim($(this).html());
                            if (insertval == spanval)
                            {
                                b = true;
                                //值相同，把flg的值设为true，再调用test()方法时弹出“此项已被选择”
                                $(insert).off('keydown');   //先把keydown事件关闭了，再按空格的时候让test()方法生效
                                if(i < 5)    //只有在i<5的时候才让“此项已选择弹出”,如果i>5时也输入一个和前面重复的标签的话，这句话就不再弹出
                                {
                                    test(true);
                                }
                                return;
                            }
                        }
                );
                //如果标签个数大于5，就把b置为true,即不让再添加
                if(i>=5)
                {
                    b = true;
                    test(false);
                }
                if(b==false)    //只有b=false的时候才添加标签
                {

                    $(insert).before('<span class=\"label blog_tag\"><span>' + insertval +
                            '</span><a title=\"Removing tag\" href=\"javascript:;\">x</a></span>');
                    newVal +=  insertval + ',';
                    i++;
                }
                if(b == true)
                {
                    b = false;      //b=true有两种情况，（1）是和前面标签重复了  （2）已经大于5项，如果是第一种情况，把b置，那后面就要再把b置为false，让后面的还可以再添加
                    $(insert).val('');
                }
            }
            $(insert).val('');   //添加成为标签了，再把输入框中的值给清空
            $('#OrganTag').val(newVal);

            //输入框的时候，如果有相同的就延时300ms弹出警告
            function test(flg)
            {
                if(flg)
                {
                    setTimeout(function(){
                        alert("此项已被选择");
                    },300);
                }
                else{
                    setTimeout(function(){
                        alert("已选择5项");
                    },300);
                }
            }
        };
        /**
         * 删除标签
         * */
        oBlog_code.DelTag = function(obj) {
            $(obj).parent("span").remove();
            var delVal = $(obj).siblings("span").text();
            newVal = newVal.substring(0,newVal.length-1);
            if(newVal.indexOf(delVal) != -1){
                var newValArr = newVal.split(',');
                for(var j =0;j<newValArr.length; j++){
                    if(delVal == newValArr[j]){
                        newValArr.splice(j,1);
                    }
                }
                newVal = newValArr.join(',') + ',';
                $('#OrganTag').val(newVal);
            }
            i--;
        };

        oBlog_code.Tag = function(Wrap,insert){
            var _this = this;
            $(document).delegate($(insert),'keydown',function()
            {
                _this.enterTag(Wrap,insert);
            });
            $(document).delegate(''+Wrap+' span a','click',function()
            {
                _this.DelTag(this);
            });
        };
        oBlog_code.Tag('#divSearchTags','#insertTag');

    }).call(this);
});
