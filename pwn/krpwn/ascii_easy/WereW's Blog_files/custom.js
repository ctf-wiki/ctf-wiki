
/* Bind everything to the onload event */
$('document').ready(function(){


	/****************** werew animation ********************/

	function show_navbar(){
		/* Third: show the navbar and remove the svg werew*/
		$('nav').css({opacity: 0, visibility: "visible"})
			.animate({opacity: 1},100);
		$("#svg").remove();

		/* Fourth: show the content of the home page and the footer */
		$('#hidden-content, footer').css({opacity: 0, display: 'block'})
			    .animate({opacity: 1},200);

		/* Fifth: replace url */
		window.history.replaceState({},'','./blog');
	};

	function move_to_navbar(){
		var icon = $("#icon"); var werew = $("#svg");
		var offset = icon.offset();

		/* Second: merge with the icon */
		werew.animate({
			top:  offset.top  + werew.height()/2,
			left: offset.left + werew.width()/2,
			width:  icon.width(),
			height: icon.height(),
			opacity: 0.5
		}, 600, show_navbar);

	};

	function werew_animation(){

			/* First: show nose and eyes */
			$('polygon').css({opacity: 0, visibility: "visible"})
				    .animate({opacity: 1},200, move_to_navbar);
	};

	
	
	$("path").bind('oanimationend animationend webkitAnimationEnd', werew_animation);



	/****************** Dynamic style  ***********************/	

    function adjust_page(){

        $("img").addClass("img-responsive img-rounded center-block");  
        $(".post-content > h2, .post-content > h3").addClass("text-center");  

        $("#navbar-collapse a, #navbar-collapse button").click(
            function (){
                $("#navbar-collapse").collapse('hide');
        });
    }

    adjust_page();

    
	

	/****************** Navigation *************************/	


	/* Activate autohiding bar */		
	$(".navbar-fixed-top").autoHidingNavbar();


	/* Update the content with a fadeIn effect. If url is specified push it
	   into the history */
	function update_page_content(newContent, url){

		var container = $("#page-content");

		container.fadeOut(function(){
			container.html(newContent).hide().fadeIn();
            adjust_page();
            window.scrollTo(0,0);
		});
			
		if (url != undefined ) {
			window.history.pushState({},'',url);
		}

		
	}

	
	/* Ajax navigation to the given url, if pushInHistory is true
	   the url is pushed into the history using pushState */
	function navigate_to(url, pushInHistory){
		$.ajax({
		   // Url to fetch
		   url:  url, 					

		   // Add a param to the query
		   data: { "content-only" : true }, 		
		
		   // Insert the response into the page
		   success: function(res){ 
				if(pushInHistory) update_page_content(res,url);
				else 		  update_page_content(res);
			   },
		
		   // Worst case, use the old way
		   error: function(){window.location = url;}  	
		});
	}


	function activate_navigation(){	

		// Test for legacy browsers
		if (typeof history.pushState != "function"){
			console.log("No ajax navigation");
			return;
		}

		// Handle history backward-forward navigation
		window.onpopstate = function(event){	
			/* Only previous ajax navigations (state=={}) */
			if (event.state != null) navigate_to(location.href, false);
		}

		// Enable ajax navigation for every anchor
		var selector = "a:not([href^='#'], [href^='http'],[class~='noajax'])";
		$('body').on('click', selector, function (event){
			event.preventDefault();
			navigate_to(this.href,true);
		});


		// Enable search 
		function search(event){
			event.preventDefault();
			var url = "/search/"+escape($('input[name="search"]').val())+"/";
			navigate_to(url,true);
		}

		$('#search-button').click(search);
		$('input[name="search"]').keypress(function(event){
			if (event.keyCode == 13) {search(event);}
		});
			
	}
	


	activate_navigation();

});
