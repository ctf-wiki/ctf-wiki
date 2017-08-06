try{(function(){function init(){var flashEl=document.getElementById('cFlashDiv');var isFlash=checkFlash();if(isFlash){var addHtml=flashHTML();flashEl.innerHTML=addHtml;};}
function flashHTML(){var isIE=checkIE();var result='';if(isIE){result=''
+'<object '
+'classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" '
+'width="1" height="1" id="BAIDU_CLB_ac_o_flash" title="BAIDU_CLB_ac_o_flash" align="middle"> '
+'<param name="allowScriptAccess" value="samedomain" />'
+'<param name="movie" value="c.swf?v=3">'
+'<param name="quality" value="high">'
+'<param name="wmode" value="transparent" >'
+'</object>';}
else{result=''
+'<embed wmode="transparent" src="c.swf?v=3" '
+'" quality="high" name="BAIDU_CLB_ac_o_flash_embed" '
+'id="BAIDU_CLB_ac_o_flash" '
+'swliveconnect="true" quality="high" '
+'width="1" height="1" '
+'align="middle" '
+'allowScriptAccess="samedomain" '
+'hasPriority="false" '
+'type="application/x-shockwave-flash" >';}
return result;}
function checkIE(){var ua=navigator.userAgent;var reg=window['RegExp'];if(/msie (\d+\.\d)/i.test(ua)){return true;}
return false;}
function checkFlash(){var isIE=checkIE();if(isIE){var swf=new ActiveXObject('ShockwaveFlash.ShockwaveFlash');if(swf){return true;}}else{if(navigator.plugins&&navigator.plugins.length>0&&navigator.plugins["Shockwave Flash"]){return true;}}
return false;}
init();})();}catch(e){}