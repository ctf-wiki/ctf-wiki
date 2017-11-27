/* ~~~~~~~~~~~~~~
 * cloud.base.js
 *~~~~~~~~~~~~~~
 *
 * Base JS utils needed by cloud js instrumentation.
 * Split out so they can be used by theme-independant extensions (e.g. auto_redirect)
 *
 * This initializes a "window.CSP.utils" object
 *
 * :copyright: Copyright 2017 by Assurance Technologies
 * :license: BSD
 */

// begin encapsulation
(function (window, $, _) {

    /*==========================================================================
     * internal helpers
     *==========================================================================*/
    var location = document.location,
        // hosturl is url to root of host, without trailing '/'
        // NOTE: regex allows netloc segment to be empty, to support 'file:///' urls
        hosturl = location.href.match(/^[a-z0-9]+:(?:\/\/)?(?:[^@/]*@)?[^/]*/)[0],
        docpath = location.pathname,
        sphinx = window.DOCUMENTATION_OPTIONS;

    /*==========================================================================
     * utils
     *==========================================================================*/
    var utils = {

        /*==========================================================================
         * url helpers
         *==========================================================================*/

        // helper to generate an absolute url path from a relative one.
        // absolute paths passed through unchanged.
        // paths treated as relative to <base>,
        // if base is omitted, uses directory of current document.
        abspath: function (path, base) {
            var parts = path.split("/"),
                stack = [];
            if (parts[0]) {
                // if path is relative, put base on stack
                stack = (base || location.pathname).split("/");
                // remove blank from leading '/'
                if (!stack[0]) {
                    stack.shift();
                }
                // discard filename & blank from trailing '/'
                if (stack.length && !(base && stack[stack.length - 1])) {
                    stack.pop();
                }
            }
            for (var i = 0; i < parts.length; ++i) {
                if (parts[i] && parts[i] != '.') {
                    if (parts[i] == '..') {
                        stack.pop();
                    } else {
                        stack.push(parts[i]);
                    }
                }
            }
            return "/" + stack.join("/");
        },

        // return subpath of url, if it starts with base ("" or non-empty string)
        // returns undefined if url doesn't start with base.
        // base url search params & fragments are ignored.
        getSubUrl: function(url, base){
            base = base.replace(/(?:\/|[#?].*)$/, '');
            if(url.startsWith(base)) {
                var suffix = url.slice(base.length);
                if(suffix == '' || suffix.match(/^[/#?]/)){ return suffix; }
            }
            return;
        },

        // helper to normalize urls for comparison
        // * strips current document's scheme, host, & path from local document links (just fragment will be left)
        // * strips current document's scheme & host from internal urls (just path + fragment will be left)
        // * makes all internal url paths absolute
        // * external urls returned unchanged.
        shortenUrl: function(url) {
            if (!url){
                return "";
            } else if (url.indexOf(hosturl) == 0) {
                // absolute path to same host
                url = url.substr(hosturl.length) || '/';
            } else if (url[0] == '.') {
                // relative path
                url = utils.abspath(url);
            } else if (!url.match(/^[/#?]|[a-z0-9]+:/)) {
                // not abs path, or fragment, or query, or uri:// --
                // another page in current dir
                url = utils.abspath('./' + url);
            }

            if (url.indexOf(docpath) == 0) {
                // strip current doc's url; only thing left will be e.g. #anchor
                url = url.substr(docpath.length);
            }
            if (url == "#" || url == "#top") {
                // normalize to empty string
                url = "";
            }
            return url;
        },

        // url w/ query params & hash stripped
        baseUrl: function(url){
            return utils.shortenUrl(url).replace(/[#?].*$/, '');
        }
    };

    /*==========================================================================
     * misc es5 polyfills
     *==========================================================================*/
    var StrProto = String.prototype;
    if (!StrProto.startsWith) {
        StrProto.startsWith = function(search, pos){
          return this.substr(pos || 0, search.length) === search;
      };
    }

    /*==========================================================================
     * jquery patches
     *==========================================================================*/

    // custom helper to toggle visibility
    $.fn.toggleVis = function (state){
        if(state) { this.show(); } else { this.hide(); }
        return this;
    };

    /*==========================================================================
     * initialize namespace
     *==========================================================================*/

    window.CST = window.CloudSphinxTheme = {
        // url to root of host, without trailing "/"
        hosturl: hosturl,
        // path to root of document dir, without trailing "/" or index.html
        rootpath: sphinx && utils.abspath(sphinx.URL_ROOT || ""),
        utils: utils
    };

    /*==========================================================================
     * eof
     *==========================================================================*/

// end encapsulation
// NOTE: sphinx provides underscore.js as $u
}(window, jQuery, $u));
