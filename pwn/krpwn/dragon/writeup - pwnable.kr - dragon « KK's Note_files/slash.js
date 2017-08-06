(function($){
	// Open external links in new window
	var externalLinks = function(){
		var host = location.host;

		$('body').on('click', 'a', function(e){
			var href = this.href,
				link = href.replace(/https?:\/\/([^\/]+)(.*)/, '$1');

			if (link != '' && link != host && !$(this).hasClass('fancybox')){
				window.open(href);
				e.preventDefault();
			}
		});
	};

	// Append caption after pictures
	var appendCaption = function(){
		$('.entry-content').each(function(i){
			var _i = i;
			$(this).find('img').each(function(){
				var alt = this.alt;

				if (alt != ''){
					$(this).after('<span class="caption">'+alt+'</span>');
				}

				$(this).wrap('<a href="'+this.src+'" title="'+alt+'" class="fancybox" rel="gallery'+_i+'" />');
			});
		});
	};

	externalLinks(); // Delete or comment this line to disable opening external links in new window
	appendCaption(); // Delete or comment this line to disable caption

	var mobilenav = $('#mobile-nav');

	$('html').click(function(){
		mobilenav.find('.on').each(function(){
			$(this).removeClass('on').next().hide();
		});
	});

	mobilenav.on('click', '.menu .button', function(){
		if (!$(this).hasClass('on')){
			var width = $(this).width() + 42;
			$(this).addClass('on').next().show().css({width: width});
		} else {
			$(this).removeClass('on').next().hide();
		}
	}).on('click', '.search .button', function(){
		if (!$(this).hasClass('on')){
			var width = mobilenav.width() - 51;
			mobilenav.children('.menu').children().eq(0).removeClass('on').next().hide();
			$(this).addClass('on').next().show().css({width: width}).children().children().eq(0).focus();
		} else {
			$(this).removeClass('on').next().hide().children().children().eq(0).val('');
		}
	}).click(function(e){
		e.stopPropagation();
	});
})(jQuery);