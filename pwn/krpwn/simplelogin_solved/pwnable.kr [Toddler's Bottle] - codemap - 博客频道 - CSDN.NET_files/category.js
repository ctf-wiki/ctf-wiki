
$(function()
{
   
        var aCategory = $(".category_r label"),
            aClose = $(".category_r").find(".J_close");
        aCategory.click(function () {
            if ($(this).find(".subItem").is(":hidden")) {
                //close all
                var thisClickText = $(this).attr("onclick");

                $.each(aCategory, function (i) {
                    var thisCategory = $(aCategory[i]);
                    var thisCategoryText = thisCategory.attr("onclick");
                   
                    if (thisCategoryText != thisClickText)
                    {
                        if (!thisCategory.find(".subItem").is(":hidden")) {
                            thisCategory.find(".arrow-up").hide().end()
                                .find(".arrow-down").show();
                            thisCategory.find(".subItem").hide();
                        }
                    }
                });

                $(this).find(".arrow-up").show().end()
                        .find(".arrow-down").hide();
                $(this).find(".subItem").show();

                //$("#body").css("overflow", "visible");
                //$("#main").css("overflow", "visible");               
            }
            else {
                $(this).find(".arrow-up").hide().end()
                       .find(".arrow-down").show();
                $(this).find(".subItem").hide();

               // $("#body").css("overflow", "hidden");
               // $("#main").css("overflow", "hidden");
            }
        });
        aClose.click(function () {
            $(this).parents(".subItem").hide()
                    .siblings(".arrow-up").hide()
                    .siblings(".arrow-down").show();

            //$("#body").css("overflow", "hidden");
            //$("#main").css("overflow", "hidden");

            return false;
        });

     $(".similar_c_t label span").click(function () {         
         $(".similar_cur").removeClass("similar_cur");
         $(this).parent().addClass("similar_cur");
     });
})

function GetCategoryArticles(id,username,type,aid)
{
    var topid = "top_" + id;

    if (type == "top") {
        var objtop = $("#" + topid +" li");
        if (objtop.length > 0)
        {
            return;
        }
    }
    var url = "/" + username + "/svc/GetCategoryArticleList?id=" + id + "&type="+ type;
	//url="http://dev.blog.csdn.net:5391"+url;
	$.get(url, function (res) {	  

	    if (type == "top")
	    {
	        var objtop = $("#" + topid);
	        objtop.html("");	       
	        $(res).each(function (i) {
	            var obj = res[i];
	            if (aid != obj.articleid) {	             
	                var articleurl = "http://blog.csdn.net/" + username + "/article/details/" + obj.articleid;
	                var aritcleid = "top_aritcle_" + obj.articleid + Math.random().toString().replace("0.");
	                objtop.append("<li class=\"tracking-ad\" data-mod=\"popu_140\"><em>•</em><a href='" + articleurl + "'  id='" + aritcleid + "' target=\"_blank\"></a></li> ");
	                $("#" + aritcleid).text(obj.title);
	                $("#" + aritcleid).attr("title",obj.title);
	            }
	        });

	        var count = $(objtop.parent().parent().find("em")[0]).text().replace("（", "").replace("）", "");
	        if (parseInt(count) > 5)
	        {
	            var moreurl = objtop.parent().find(".subItem_t a").attr("href");
	            objtop.append("<li style=\"padding-left: 300px;\"><a href='" + moreurl + "' target=\"_blank\">更多</a></li>");
	        }

	    }
	    else if (type == "foot")
	    {	       	       
	        var objfootleft = $(".similar_list.fl");
	        var objfootright = $(".similar_list.fr");

	        objfootleft.html("");
	        objfootright.html("");

	        var j = 0;

	        $.each(res, function (i) {	            
	            var obj = res[i];
	            if (aid != obj.articleid) {
	                var articleurl = "http://blog.csdn.net/" + username + "/article/details/" + obj.articleid;
	                var aritcleid = "foot_aritcle_" + obj.articleid + Math.random().toString().replace("0.");

	                var html = "<li><em>•</em><a href='" + articleurl + "'  id='" + aritcleid + "' target=\"_blank\"></a><span>" + obj.posttime + "</span><label><i>阅读</i><b>" + obj.viewcount + "</b></label></li> ";
	                if (j % 2 == 1) {
	                    objfootright.append(html);
	                }
	                else {
	                    objfootleft.append(html);
	                }
	                $("#" + aritcleid).text(obj.title);
	                $("#" + aritcleid).attr("title",obj.title);
	                j++;

	                $(".similar_article").show();
	            }
	        });

	        var count = $(".similar_cur span em").text().replace("（", "").replace("）", "");
	        if (parseInt(count) > 10) {
	            var moreurl ="";
	            $.each($(".subItem_t a"), function (i) {
	                if($(this).attr("href").toString().indexOf(id)>-1)
	                {
	                    moreurl = $(this).attr("href");	                    
	                }
	            });
	            if (moreurl != "") {
	                //objfootright.append("<li style=\"padding-left: 200px;\"><a href='" + moreurl + "' target=\"_blank\">更多</a></li>");
	                $(".MoreArticle").remove();
	                $(".similar_wrap").append('<a href=' + moreurl + ' class="MoreArticle">更多文章</a>');
	            }
	        }
	    }
	});
}