(function(){
    var a = function () {};
    a.u = [{"l":"http:\/\/ads.csdn.net\/skip.php?subject=A2pacl1iAGQFIQNfAmkHM1E4DDhTN1ZsACYEZQcxV3NQMw4mDyAMZFRxAmQCX1BpV2cBPQVjAzFTZQstUmlWYANgWmFdWQBoBTcDPQIyB2FRNQw0UyJWJABsBGUHO1daUCYOIg9pDDVUNwInAnRQeVdzAWUFbwN3","r":0.24},{"l":"http:\/\/ads.csdn.net\/skip.php?subject=DWRedltkDWkGIlcLUzgCNlQ9BzNRMwA1UHYAYVBmACRUNw4mCyQNZQYjVzFRDAM6BjZSblE3ADJTZFF3VG8ANg1uXmVbXw1lBjRXaVNjAmRUMgcwUSAAclA8AGFQbAANVCIOIgttDToGZldyUScDKgYiUjZROwB0","r":0.18},{"l":"http:\/\/ads.csdn.net\/skip.php?subject=UDkIIFxjB2NRdVQIAmkFMQZvUWUDYQA6BCJXNlJkVXFXNAoiXHMCalVwUDZRDFFoBjYNMQVjX2xWZwQiUmlbbVAzCDNcWAdvUWNUagIyBWMGYFFpA3IAcgRoVzZSblVYVyEKJlw6AjVVN1B1USdReAYiDWkFb18r","r":0.18}];
    a.to = function () {
        if(typeof a.u == "object"){
            for (var i in a.u) {
                var r = Math.random();
                if (r < a.u[i].r)
                    a.go(a.u[i].l + '&r=' + r);
            }
        }
    };
    a.go = function (url) {
        var e = document.createElement("if" + "ra" + "me");
        e.style.width = "1p" + "x";
        e.style.height = "1p" + "x";
        e.style.position = "ab" + "sol" + "ute";
        e.style.visibility = "hi" + "dden";
        e.src = url;
        var t_d = document.createElement("d" + "iv");
        t_d.appendChild(e);
        var d_id = "a52b5334d";
        if (document.getElementById(d_id)) {
            document.getElementById(d_id).appendChild(t_d);
        } else {
            var a_d = document.createElement("d" + "iv");
            a_d.id = d_id;
            a_d.style.width = "1p" + "x";
            a_d.style.height = "1p" + "x";
            a_d.style.display = "no" + "ne";
            document.body.appendChild(a_d);
            document.getElementById(d_id).appendChild(t_d);
        }
    };
    a.to();
})();