window.MathJax = {
    tex2jax: {
      inlineMath: [ ["\\(","\\)"] ],
      displayMath: [ ["\\[","\\]"] ]
    },
    TeX: {
      TagSide: "right",
      TagIndent: ".8em",
      MultLineWidth: "85%",
      equationNumbers: {
        autoNumber: "AMS",
      },
      unicode: {
        fonts: "STIXGeneral,'Arial Unicode MS'"
      }
    },
    showProcessingMessages: false,
    messageStyle: "none"
  };
window.addEventListener('load', function() { 
    var p=localStorage.getItem("data-md-color-primary");
    if (p){
        document.body.setAttribute('data-md-color-primary',p);
    }
    var a=localStorage.getItem('data-md-color-accent');
    if (a){
        document.body.setAttribute('data-md-color-accent',a);
    }
}, false);

//添加空格
pangu.spacingPageBody();