function path()
{
	var args = arguments,
		result = []
		;
		
	for(var i = 0; i < args.length; i++)
		result.push(args[i].replace('@', '/static/js/'));
		
	return result
};

SyntaxHighlighter.autoloader.apply(null, path(
	'applescript			@shBrushAppleScript.js',
	'actionscript actionscript3 as3		@shBrushAS3.js',
	'apache batchfile bash shell makefile yaml lighttpd haml emacslisp svn 	@shBrushBash.js',
	'coldfusion cf			@shBrushColdFusion.js',
	'cpp objectivec c iphone arduino swift		@shBrushCpp.js',
	'c# c-sharp csharp		@shBrushCSharp.js',
	'css					@shBrushCss.js',
	'delphi pascal			@shBrushDelphi.js',
	'diff patch pas			@shBrushDiff.js',
	'erl erlang				@shBrushErlang.js',
	'groovy					@shBrushGroovy.js',
	'java go clojure r		@shBrushJava.js',
	'jfx javafx				@shBrushJavaFX.js',
	'js jscript javascript jquery json	@shBrushJScript.js',
	'perl pl				@shBrushPerl.js',
	'php symfony			@shBrushPhp.js',
	'prolog other assembler text plain typo3	@shBrushPlain.js',
	'lua py python django elixir			@shBrushPython.js',
	'powershell ps posh windowspowershell dosbatch		@shBrushPowerShell.js',
	'ruby rails ror rb		@shBrushRuby.js',
	'sass scss				@shBrushSass.js',
	'scala					@shBrushScala.js',
	'sql mysql				@shBrushSql.js',
	'vb vbnet visualbasic asp				@shBrushVb.js',
	'xml xhtml xslt html mxml	@shBrushXml.js'
));
SyntaxHighlighter.all();

$(document).ready(function()
{
	$('.email').html(email());
	$('table')
		.attr('cellSpacing', 0)
		.find('tr')
		 	.find('td:first').addClass('first').end()
			.find('td:last').addClass('last').end()
			
		.filter(':first').addClass('first').end()
		.filter(':last').addClass('last').end()
		;
		
	$('.autoinclude').each(function()
	{
		var $this = $(this),
			path = $this.find('a:first').attr('href'),
			brushes = { js: 'JScript', css: 'CSS' }
			;
		
		$.ajax({
			url: path,
			type: 'GET',
			dataType: 'text',
			success: function(code)
			{
				var ext = path.match(/\w+$/)[0],
					name = brushes[ext],
					brush = new SyntaxHighlighter.brushes[name]()
					;
				brush.init({ toolbar: false });
				$this.append(brush.getHtml(code));
			}
		});
	});
	
	$('a[href^="http://"]').addClass('external');
	
	$('#whatsnew').appendTo('#title h1');
});
