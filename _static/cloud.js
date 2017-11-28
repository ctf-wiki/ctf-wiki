/* ~~~~~~~~~~~~~~
 * cloud.js_t
 *~~~~~~~~~~~~~~
 *
 * Various bits of javascript driving the moving parts behind various
 * parts of the cloud theme. Handles things such as toggleable sections,
 * collapsing the sidebar, etc.
 *
 * :copyright: Copyright 2011-2012 by Assurance Technologies
 * :license: BSD
 */



    
    


// begin encapsulation
(function (window, $, _, CST) {

    /*==========================================================================
     * common helpers
     *==========================================================================*/
    var isUndef = _.isUndefined,
        TEXT_NODE = 3, // could use Node.TEXT_NODE, but IE doesn't define it :(
        $window = $(window),
        utils = CST.utils,
        shorten_url = utils.shortenUrl,
        baseUrl = utils.baseUrl;

    // helper that retrieves css property in pixels
    function csspx(elem, prop) {
        return parseInt($(elem).css(prop).replace("px", ""), 10);
    }

    // NOTE: would use $().offset(), but it's document-relative,
    //       and we need viewport-relative... which means getBoundingClientRect().
    // NOTE: 'window.frameElement' will only work we're embedded in an iframe on same domain.
    var parentFrame = window.frameElement;
    if (window.parent && window.parent !== window) {
        $(window.parent).scroll(function () {
            $window.scroll();
        });
    }

    function leftFrameOffset() {
        return parentFrame ? parentFrame.getBoundingClientRect().left : 0;
    }

    function topFrameOffset() {
        return parentFrame ? parentFrame.getBoundingClientRect().top : 0;
    }

    function leftViewOffset($node) {
        return ($node && $node.length > 0) ? $node[0].getBoundingClientRect().left + leftFrameOffset() : 0;
    }

    function topViewOffset($node) {
        return ($node && $node.length > 0) ? $node[0].getBoundingClientRect().top + topFrameOffset() : 0;
    }

    function bottomViewOffset($node) {
        return ($node && $node.length > 0) ? $node[0].getBoundingClientRect().bottom + topFrameOffset() : 0;
    }

    
    function topOffset($target, $parent) {
        if (!($target && $target[0])) {
            return 0;
        }
        var offset = $target[0].getBoundingClientRect().top;
        if ($parent && $parent[0]) {
            offset -= $parent[0].getBoundingClientRect().top;
        }
        else {
            offset += topFrameOffset();
        }
        return offset;
    }

    // return normalized nodename, takes in node or jquery selector
    // (can't trust nodeName, per http://ejohn.org/blog/nodename-case-sensitivity/)
    function nodeName(elem) {
        if (elem && elem.length) {
            elem = elem[0];
        }
        return elem && elem.nodeName.toUpperCase();
    }

    /*==========================================================================
     * Sythesize 'cloud-breakpoint' event
     *==========================================================================
     * Event emitted when crossing small <-> medium media breakpoint
     *==========================================================================*/
    var smallScreen;

    $(function (){
        var $smallDiv = $('<div class="hide-for-small" />').appendTo("body"),
            $html = $("html");
        function update(){
            var test = $smallDiv.css("display") == "none";
            if(test !== smallScreen){
                smallScreen = test;
                $html.toggleClass("small-screen", test)
                     .toggleClass("medium-up-screen", !test);
                $window.trigger("cloud-breakpoint");
            }
        }
        $window.on("DOMContentLoaded load resize", update);
        update();
    });

    /*==========================================================================
     * Highlighter Assist
     *==========================================================================
     * Sphinx's highlighter marks some objects when user follows link,
     * but doesn't include section names, etc. This catches those.
     *==========================================================================*/
    $(function () {
        // helper to locate highlight target based on #fragment
        function locate_target() {
            // find id referenced by #fragment
            var hash = document.location.hash;
            if (!hash) return null;
            var section = document.getElementById(hash.substr(1));
            if (!section) return null;

            // could be div.section, or hidden span at top of div.section
            var name = nodeName(section);
            if (name != "DIV") {
                if (name == "SPAN" && section.innerHTML == "" &&
                    nodeName(section.parentNode) == "DIV") {
                    section = section.parentNode;
                }
                else if (name == "DT" && section.children.length &&
                    $(section).children("tt.descname, code.descname").length > 0) {
                    // not a section, but an object definition, e.g. a class, func, or attr
                    return $(section);
                }
            }
            // now at section div and either way we have to find title element - h2, h3, etc.
            var header = $(section).children("h2, h3, h4, h5, h6").first();
            return header.length ? header : null;
        }

        // init highlight
        var target = locate_target();
        if (target) target.addClass("highlighted");

        // update highlight if hash changes
        $window.on("hashchange", function () {
            if (target) target.removeClass("highlighted");
            target = locate_target();
            if (target) target.addClass("highlighted");
        });
    });

    /*==========================================================================
     * Toggleable Sections
     *==========================================================================
     * Added expand/collapse button to any collapsible RST sections.
     * Looks for sections with CSS class "html-toggle",
     * along with the optional classes "expanded" or "collapsed".
     * Button toggles "html-toggle.expanded/collapsed" classes,
     * and relies on CSS to do the rest of the job displaying them as appropriate.
     *==========================================================================*/

    // given "#hash-name-with.periods", escape so it's usable as CSS selector
    // (e.g. "#hash-name-with\\.periods")
    // XXX: replace this with proper CSS.escape polyfill?
    function escapeHash(hash) {
        return hash.replace(/\./g, "\\.");
    }

    $(function () {
        function init() {
            // get header & section, and add static classes
            var header = $(this);
            var section = header.parent();
            header.addClass("html-toggle-button");

            // helper to test if url hash is within this section
            function contains_hash() {
                var hash = document.location.hash;
                return hash && (section[0].id == hash.substr(1) ||
                    section.find(escapeHash(hash)).length > 0);
            }

            // helper to control toggle state
            function set_state(expanded) {
                expanded = !!expanded; // toggleClass et al need actual boolean
                section.toggleClass("expanded", expanded);
                section.toggleClass("collapsed", !expanded);
                section.children().toggle(expanded);
                if (!expanded) {
                    section.children("span:first-child:empty").show();
                    /* for :ref: span tag */
                    header.show();
                }
            }

            // initialize state
            set_state(section.hasClass("expanded") || contains_hash());

            // bind toggle callback
            header.click(function (evt) {
                var state = section.hasClass("expanded")
                if (state && $(evt.target).is(".headerlink")) {
                    return;
                }
                set_state(!state);
                $window.trigger('cloud-section-toggled', section[0]);
            });

            // open section if user jumps to it from w/in page
            $window.on("hashchange", function () {
                if (contains_hash()) set_state(true);
            });
        }

        $(".html-toggle.section > h2, .html-toggle.section > h3, .html-toggle.section > h4, .html-toggle.section > h5, .html-toggle.section > h6").each(init);
    });

    /*==========================================================================
     * mobile menu / collapsible sidebar
     *==========================================================================
     * Instruments sidebar toggle buttons.  Relies on applying classes
     * to div.document in order to trigger css rules that show/hide sidebar.
     * Persists sidebar state via session cookie.
     * Sidebar state for small screens is tracked separately,
     * and is NOT persisted.
     *==========================================================================*/
    $(function () {
        // get nodes
        if (!$(".sphinxsidebar").length) { return; }

        var $doc = $('div.document'),
            $hide = $('button#sidebar-hide'),
            $show = $('button#sidebar-show'),
            copts = {
                // expires: 7,
                path: utils.rootpath
            };

        // set sidebar state for current media size
        var lastSmall = false,
            smallState = false,
            largeState = false;
        function setState(visible){
            $doc.toggleClass("sidebar-hidden", !smallScreen && !visible)
                .toggleClass("document-hidden", smallScreen && visible);
            $hide.toggleVis(visible);
            $show.toggleVis(!visible);
            lastSmall = smallScreen;
            if(smallScreen) {
                smallState = visible;
                if(visible) { largeState = true; }
            } else {
                largeState = visible;
                if(!visible) { smallState = false; }
                $.cookie("sidebar", visible ? "expanded" : "collapsed", copts);
            }
            $window.trigger("cloud-sidebar-toggled", visible);
        }

        // change when buttons clicked
        $show.click(function () { setState(true); });
        $hide.click(function () { setState(false); });

        // refresh sidebar state when crossing breakpoints
        $window.on("cloud-breakpoint", function (){
            setState(smallScreen ? smallState : largeState);
        });

        // load initial state
        if(smallScreen){
            setState(false);
        } else {
            var value = $.cookie("sidebar");
            
            setState(value != "collapsed");
        }

        // make buttons visible now that they're instrumented
        $(".sidebar-toggle-group").removeClass("no-js");
    });
        /*==========================================================================
         * sticky sidebar
         *==========================================================================
         * Instrument sidebar so that it sticks in place as page is scrolled.
         *==========================================================================*/

        function resetStickyState($target){
            $target.css({
                position: "",
                marginLeft: "",
                top: "",
                left: "",
                bottom: ""
            });
        }

        // helper to update 'sticky' state of target --
        // tried to make this generic, but some bits are specific to sidebar
        function setStickyState($target, top, start, end, $container){
            if (top >= start) {
                // top of sidebar is above stickyStart -- scroll with document
                resetStickyState($target);
            } else if (top > end) {
                $target.css({
                    position: "fixed",
                    marginLeft: 0,
                    top: start - topFrameOffset(),
                    left: leftViewOffset($container),
                    bottom: ""
                });
            } else {
                // bottom of sidebar is below stickyEnd -- scroll with document,
                // but place at bottom of container
                $target.css({
                    position: "absolute",
                    marginLeft: 0,
                    top: "",
                    left: 0,
                    bottom: 0
                });
            }
        }

        $(function () {
            // initialize references to relevant elements,
            // and internal state
            var $bodywrapper = $(".bodywrapper"), // element that contains content
                $bodytoc = $('.sphinxglobaltoc a[href="#"]').parent(), // element containing toc for page
                $container = $('.document'), // element to stick within
                $target = $('.sphinxsidebar'), // element to sticky
                $toggle = $(".sidebar-toggle-group"), // extra element to sticky
                targetMargin = 0, // $target top margin
                windowHeight = 0, // cache of window height
                disable = false, // whether sticky is disabled for given window size
                start = 0, // start sticking when top of target goes above this point
                lastTop = null, // tracks last offset for scroll+hover handling
                containerOffset = 0, // top margin of target (included)
                offset = 0, // offset within target
                offsetMin = Math.max(0, start); // min offset

            // func to update sidebar position based on scrollbar & container positions
            function update_sticky(evt) {
                if (disable) { return; }

                // calc stats
                // HACK: using $container for offset so we don't have to reset_sticky() for calc.
                //       then add cached container-relative offset to get topViewOffset($target).
                var top = topViewOffset($container),
                    targetHeight = $target.outerHeight(true),
                    end = targetHeight - $container.height();

                // adjust offset if users scrolls while hovering over sidebar
                if (evt && evt.type == "scroll" && ($target.first().is(":hover") ||
                    // make sure local toc scrolls into view
                    // XXX: will this still work right if window height < bodytoc height?
                    ($bodytoc.length && bottomViewOffset($bodytoc) + 16 >= windowHeight))) {
                    offset -= top - lastTop;
                }
                lastTop = top;

                // see note in top init (above), but doing this here
                // so it doesn't affect offset adjustment
                top += containerOffset;

                // limit offset to container bounds
                if (offset < offsetMin) {
                    offset = offsetMin;
                } else {
                    var offsetMax = targetHeight - windowHeight - start;
                    offset = Math.max(offsetMin, Math.min(offset, -top, offsetMax));
                }

                // offset = 0;
                // console.debug("sticky sidebar: top=%o offset=%o start=%o end=%o",
                //               top, offset, start, end);

                // set sticky state
                setStickyState($target, top, start - offset, end - offset, $container);

                // set button sticky state -- has to stay at top of screen
                setStickyState($toggle, top, start - Math.min(offset, targetMargin), -1e9, $container);
            }

            // func to update sidebar measurements, and then call update_sticky()
            function update_measurements() {
                // if body shorter than sidebar,  setting sidebar to 'fixed' would cause doc
                // to shrink below sidebar height, so have to disable sticky mode in this case.
                resetStickyState($target);
                resetStickyState($toggle);
                disable = (smallScreen || $bodywrapper.height() < $target.height());
                if (disable) {
                    return;
                }

                // calc stats
                windowHeight = $window.height();
                targetMargin = csspx($target, "margin-top");
                if($target.css("display") == "none"){
                    // so toggle positioned correctly on collapsed sidebar
                    containerOffset = 0;
                } else {
                    // NOTE: this includes margin-top since it's not removed by sticky code above
                    containerOffset = topOffset($target, $container) - targetMargin;
                }

                // update state
                update_sticky();
            }

            // run function now, and every time window scrolls
            // XXX: would it help to throttle/raf() scroll & resize calls?
            $window.scroll(update_sticky)
                   .on("resize hashchange cloud-section-toggled cloud-sidebar-toggled", update_measurements);
            update_measurements();

            // hack to fix errant initial-layout issue
            $window.on("load", update_sticky);
        });
    

    // flag set by smooth scroller to temporarily disable toc sliding.
    var scrollingActive = false;
        /*==========================================================================
         * sidebar toc highlighter
         *==========================================================================
         * highlights toc entry for current section being viewed;
         * as well as expands & collapses entries for sections that aren't onscreen.
         *==========================================================================*/
        $(function () {
            // scan all links, gathering info about their relationships
            var $sbody = $("div.body"),
                localDB = [], // entries that are part of local page OR child page
                toggleDB = []; // subset of localDB which has $ul defined

            // scan all links w/o TOCs
            $(".sphinxlocaltoc ul a, .sphinxglobaltoc ul a").each(function (idx, link) {
                // grab basic info about link
                var $link = $(link),
                    // NOTE: reading link.attr() so highlight parameter
                    //       from current location isn't included...
                    href = shorten_url($link.attr("href")) || "#",
                    isLocal = (href[0] == "#"),
                    isTop = (href == "#"),
                    $li = $link.parent("li"),
                    parent = $li.parent("ul").prev("a").data("toc"),
                    $target;

                // determine type of link & target element for visibility calc
                if (isLocal) {
                    // css code relies on all local links starting with "#"
                    // so make sure links use right representation
                    $link.attr("href", href);

                    // needing for styling
                    $li.addClass("local");

                    // link points to section in current document.
                    // use that section as visibility target
                    if(isTop){
                        $target = $sbody;

                        // don't bother traversing to parent entry if outside page
                        parent = null;
                    } else {
                        $target = $(document.getElementById(href.slice(1)));

                        // XXX: what about rare border case where there's
                        //      multiple toplevel entries? not sure *how* to handle that.
                        //      (parent will be null in this case)
                    }

                } else if (parent) {
                    // needing for styling
                    $li.addClass("child");

                    // parent (or some ancestor) is part of page,
                    // so this is link for child page.
                    // prefer to use actual link in document as visibility target
                    $target = parent.$target.find("a").filter(function () {
                        return shorten_url(this.href) == href;
                    });
                    if (!$target.length) {
                        // target link not actually visible in document
                        // XXX: what if target has multiple links, but to subfragments
                        //      e.g. (passlib.hash manpage's link to passlib.hash.ldap_std)?
                        return;
                    }
                    if (($target.parent("li").attr("class") || '').search(/(^|\w)toctree-/) == 0) {
                        // it's part of embedded toc tree, use whole LI as target.
                        $target = $target.parent("li");
                    }
                    // XXX: what if target link is w/in subsection,
                    //      even though it belongs at this level in TOC?
                    //      *think* active_child code below will prevent spurious highlighting.
                } else {
                    // this link isn't local, nor is any ancestor, so ignore this one.
                    return;
                }

                // add to update list
                var entry = {
                    //
                    // static vars
                    //
                    $target: $target, // section/object controlling link's visibility
                    $li: $li, // list item we're instrumenting
                    parent: parent, // reference to parent entry
                    children: [], // list of child nodes
                    href: href, // normalized copy of li > a[href]
                    isLocal: isLocal, // whether href points to local page

                    // filled by $ul pass, below
                    $ul: null, // list of child items if we're doing collapse checking, else null
                    openSize: 0, // avg # of child items expecting to be visible at a time.

                    //
                    // state vars modified by updateTOC()
                    //
                    rect: null, // cache of client bounding rect
                    visible: false, // whether target is onscreen
                    active: false, // whether this entry (or child) is marked active
                    justOpened: false // whether toc-toggle was opened during this updateTOC() pass
                };
                localDB.push(entry);
                if(parent) { parent.children.push(entry); }
                $link.data("toc", entry); // used to get parent entry (above), and for debugging
            });

            // if no local links found, don't bother w/ update hook
            //console.debug("localDB: %o", localDB);
            if (!localDB.length) return;

            // figure out which nodes should be collapsible.
            // go in reverse order, so we have count available for parent elements.
            // fills in $ul & viewCount in entries
            for(var i=localDB.length - 1; i>=0; --i){
                // don't fill in $ul for toplevel, or ones w/ no entries.
                var entry = localDB[i],
                    $ul = entry.$li.children("ul");
                if(!i || !$ul.length){ continue; }

                // calculate how many children will be visible at a time
                // when $ul is open.  this is # of children, plus number
                // of descendants always visible in non-collapsing children,
                // plus the largest visibility count of all collapsing children.
                var weight = entry.children.length,
                    dynamic = 0;
                entry.children.forEach(function (child){
                    if(!child.$ul) {
                        // always open
                        weight += child.openSize;
                    } else if(child.openSize > dynamic){
                        // largest collapsible child seen so far
                        dynamic = child.openSize;
                    }
                });
                entry.openSize = (weight += dynamic);

                // determine if this one should actually be collapsible
                // TODO: this max weight should really depend on how much
                //       room is available; and/or be decided when parent
                //       is comparing all the children.
                // NOTE: 'toc-always-open' and 'toc-always-toggle' are control
                //       flags that can be applied via rst-class to section header.
                if((weight > 3 && !entry.$target.hasClass("toc-always-open") ||
                    entry.$target.hasClass("toc-always-toggle")))
                {
                    entry.$ul = $ul;
                    entry.$li.addClass("toc-toggle");
                    toggleDB.push(entry);
                }
            }

            // debugging helper
//            var cutoffPrefix = 'pointer-events: none; position: fixed; left: 0; right: 0; background: ',
//                $cutoff = $('<div/>', {style: cutoffPrefix + 'rgba(0,0,255,0.3)'}).appendTo("body"),
//                $cutoff2 = $('<div/>', {style: cutoffPrefix + 'rgba(0,255,0,0.3)'}).appendTo("body");

            // function to update cutoff settings
            var winHeight, // window height
                lineHeight, // sbody's line height (px)
                minCutoff, // minimum viewport offset where we assume user is reading
                curHash; // hash of current highlighted section

            function updateConfig(_evt, first_run){
                // determine viewable range
                lineHeight = csspx($sbody, "line-height");
                winHeight = $window.height();
                minCutoff = Math.floor(Math.min(winHeight * 0.2, 7 * lineHeight));
                curHash = shorten_url(document.location.hash) || "#";

                // update TOC markers
                updateTOC(_evt, first_run);
            }

            // function to update toc markers
            function updateTOC(_evt, first_run) {
                // recalc readline -- attempt to estimate where user who's
                // scanning through docs is "reading".  We start w/ minCutoff,
                // but when at bottom of screen, may have a bunch of sections visible,
                // and want to have them expand as last bit of document scrolls into view,
                // so the readline moves down page when document gets to the end.
                var readline = minCutoff,
                    bodyBottom = $sbody[0].getBoundingClientRect().bottom,
                    useMaxRatio = (2 * winHeight - bodyBottom - minCutoff) / (winHeight - minCutoff);
                if (useMaxRatio > 0) {
                    var maxCutoff = Math.min(bodyBottom - 3 * lineHeight, winHeight);
                    readline = minCutoff + (maxCutoff - minCutoff) * Math.min(useMaxRatio, 1);
                }
                if (winHeight > $sbody.height()) {
                    readline = 0;
                }

                // debug stats
//                console.debug("useMaxRatio=%o", useMaxRatio);
//                $cutoff.css({height: readline, top: 0});
//                $cutoff2.css({height: minCutoff, top: 0});

                // reset entries -- recalc .rect & .visible; clear .active flag;
                // clear active/focus styling classes
                localDB.forEach(function (entry){
                    var rect = entry.rect = entry.$target[0].getBoundingClientRect();
                    entry.visible = (rect.top <= winHeight && rect.bottom >= 0 &&
                                     (rect.width || rect.height));
                    entry.active = false;
                    entry.$li.removeClass("active focus");
                });

                // pick focus at top TOC level, then check if one of it's
                // children would be better choice, and so on until
                // there are no children that could hold focus.
                // NOTE: assumes children are listed in reading order.
                var focus = localDB[0];
                while (true) {
                    var best = null,
                        children = focus.children,
                        cutoff = readline;
                    for(var i = 0, e = children.length; i < e; ++i){
                        var child = children[i];
                        // skip hidden children
                        if(!child.visible) { continue; }

                        // pick bottom-most child which starts above readline.
                        else if (child.rect.top <= cutoff) {
                            best = child;

                            // if child is highlighted, keep it open longer,
                            // by raising the readline up to minCutoff.
                            if(child.href == curHash){
                                cutoff = minCutoff;
                            }
                        }
                    }
                    var $li = focus.$li;
                    focus.active = true;
                    $li.addClass("active");
                    if (best) {
                        if(!best.isLocal && focus.isLocal){
                            // set focus on final local section
                            // as well as child link
                            $li.addClass("focus");
                        }
                        focus = best;
                    } else {
                        $li.addClass("focus");
                        break;
                    }
                }

                // update open/closed status of nested ULs
                // TODO: would like to do cleaner job tracking
                //       which sections are being animated open/close,
                //       and sync it w/ smooth-scrolling code (below).
                //       for now, only have '.justOpened' hack to detect
                //       if we're currently animating a parent element.
                toggleDB.forEach(function (entry){
                    var $li = entry.$li,
                        $ul = entry.$ul,
                        closed = (!entry.visible || !entry.active ||
                                  entry.$target.hasClass("collapsed"));
                    if(smallScreen) { closed = false; first_run = true; }
                    entry.justOpened = false;
                    if ($li.hasClass("closed") == closed) { return; }
                    if (closed) {
                        if (first_run) {
                            $ul.hide(); // don't animate things on first run
                        } else {
                            $ul.slideUp();
                        }
                    } else {
                        var parent = entry.parent;
                        if (first_run || (parent && parent.justOpened)) {
                            $ul.show(); // don't animate if parent is animated.
                        } else {
                            $ul.slideDown();
                        }
                        entry.justOpened = true;
                    }
                    $li.toggleClass("closed", closed);
                });
            }

            // run function now, and every time window is resized
            // TODO: disable when sidebar isn't sticky (including when window is too small)
            //       and when sidebar is collapsed / invisible
            function scrollWrapper(evt){
                if(scrollingActive) { return; }
                return updateTOC(evt);
            }
            $window.on("scroll", scrollWrapper)
                   .on('resize hashchange cloud-section-toggled cloud-sidebar-toggled',
                       updateConfig);
            updateConfig(null, true);
        });
    

    /* ==========================================================================
     * header breaker
     * ==========================================================================
     * attempts to intelligently insert linebreaks into page titles, where possible.
     * currently only handles titles such as "module - description",
     * adding a break after the "-".
     * ==========================================================================*/
    $(function () {
        // get header's content, insert linebreaks
        var header = $("h1");
        var orig = header[0].innerHTML;
        var shorter = orig;
        if ($("h1 > a:first > tt > span.pre").length > 0) {
            shorter = orig.replace(/(<\/tt><\/a>\s*[-\u2013\u2014:]\s+)/im, "$1<br> ");
        }
        else if ($("h1 > tt.literal:first").length > 0) {
            shorter = orig.replace(/(<\/tt>\s*[-\u2013\u2014:]\s+)/im, "$1<br> ");
        }
        if (shorter == orig) {
            return;
        }

        // hack to determine full width of header
        header.css({whiteSpace: "nowrap", position: "absolute"});
        var header_width = header.width();
        header.css({whiteSpace: "", position: ""});

        // func to insert linebreaks when needed
        function layout_header() {
            header[0].innerHTML = (header_width > header.parent().width()) ? shorter : orig;
        }

        // run function now, and every time window is resized
        layout_header();
        $window.on('resize cloud-sidebar-toggled', layout_header);
    });

    

    
        /*==========================================================================
         * smooth scrolling
         * instrument toc links w/in same page to use smooth scrolling
         *==========================================================================*/
        var scrollSpeed = 500;
        $(function () {
            $('.sphinxsidebar a[href^="#"]').click(function (event) {
                var hash = this.hash;
                event.preventDefault();
                scrollingActive = true; // disable toc focus calc
                $('html,body').animate({
                    // NOTE: hash == "" for top of document
                    scrollTop: hash ? $(escapeHash(hash)).offset().top : 0
                }, scrollSpeed).promise().always(function (){
                    // enable & redraw toc focus
                    // xxx: would really like to update *before* animation starts,
                    //      so it's animation happened in parallel to scrolling animation
                    scrollingActive = false;
                    $window.trigger("cloud-sidebar-toggled");
                });
                if (window.history.pushState) {
                    window.history.pushState(null, "", hash || "#");
                }
                $window.trigger("hashchange"); // for toggle section code
            });
        });
    

    
        /*==========================================================================
         * auto determine when admonition should have inline / block title
         * under this mode, the css will default to styling everything like a block,
         * so we just mark everything that shouldn't be blocked out.
         *==========================================================================*/
        $(function () {
            $("div.body div.admonition:not(.inline-title):not(.block-title)" +
                ":not(.danger):not(.error)" +
                ":has(p.first + p.last)").addClass("inline-title");
        });
    

    /*==========================================================================
     * patch sphinx search code to try to and prevent rest markup from showing up
     * in search results
     *==========================================================================*/
    var Search = window.Search;
    if (Search && Search.makeSearchSummary) {
        var sphinxSummary = Search.makeSearchSummary;
        Search.makeSearchSummary = function (text, keywords, hlwords) {
            /* very primitive regex hack to turn headers into dots */
            text = text.replace(/^(\s|\n)*([-#=.])\2{6,}\s*\n/, '');
            text = text.replace(/^([-#=.])\1{6,}\s*$/mg, '\u26AB');
            text = text.replace(/^\s*#\.\s*/mg, '\u2022 ');
            //console.debug("makeSearchSummary: text=%o keywords=%o hlwords=%o", text, keywords, hlwords);
            return sphinxSummary.call(this, text, keywords, hlwords);
        }
    }

    /*==========================================================================
     * toc page styling
     *==========================================================================
     * adds some classes to TOC page so items can be styled.
     * sets li.page and div.highlight-pages markers
     *==========================================================================*/
    $(function () {
        $("div.body div.toctree-wrapper").each(function (){
            var $div = $(this),
                highlight = false;
            $div.find("li").each(function (){
                var $li = $(this),
                    url = baseUrl($li.children("a").attr("href")),
                    $parent = $li.parent("ul").prev("a"),
                    parentUrl = baseUrl($parent.attr("href"));
                if(!$parent.length || parentUrl != url){
                    $li.addClass("page");
                } else {
                    highlight = true;
                }
            });
            if(highlight) { $div.addClass("highlight-pages"); }
        });

        var $toc = $("#table-of-contents div.toctree-wrapper.highlight-pages");
        if($toc.length){
            $('<label id="hide-page-sections"><input type="checkbox" /> Hide page sections</label>')
                .insertBefore($toc).find("input")
                .change(function (evt){
                    $toc.toggleClass("hide-sections", evt.target.checked);
                }).change();
            $(".sphinxglobaltoc > h3").css("margin-top", "4px").wrap('<ul><li class="current active"></li></ul>');
        }
    });

    /* ==========================================================================
     * codeblock lineno aligner
     * if document contains multiple codeblocks, and some have different counts
     * (e.g. 10 lines vs 300 lines), the alignment will look off, since the
     * 300 line block will be indented 1 extra space to account for the hundreds.
     * this unifies the widths of all such blocks (issue 19)
     *==========================================================================*/
    $(function () {
        var $lines = $(".linenodiv pre");
        if (!$lines.length) {
            return;
        }
        // NOTE: using ems so this holds under font size changes
        var largest = Math.max.apply(null, $lines.map(function () {
                return $(this).innerWidth();
            })),
            em_to_px = csspx($lines, "font-size");
        $lines.css("width", (largest / em_to_px) + "em").css("text-align", "right");
    });

    /*==========================================================================
     * codeblock copy helper button
     *==========================================================================
     *
     * Add a [>>>] button on the top-right corner of code samples to hide
     * the '>>>' and '...' prompts and the output and thus make the code
     * copyable. Also hides linenumbers.
     *
     * Adapted from copybutton.js,
     * Copyright 2014 PSF. Licensed under the PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
     * File originates from the cpython source found in Doc/tools/sphinxext/static/copybutton.js
     *==========================================================================*/
    $(function () {
        // TODO: enhance this to hide linenos for ALL highlighted code blocks,
        //       and only perform python-specific hiding as-needed.

        // static text
        var hide_text = 'Hide the prompts and output',
            show_text = 'Show the prompts and output';

        // helper which sets button & codeblock state
        function setButtonState($button, active) {
            $button.parent().find('.go, .gp, .gt').toggle(!active);
            $button.next('pre').find('.gt').nextUntil('.gp, .go').css('visibility', active ? 'hidden' : 'visible');
            $button.closest(".highlighttable").find(".linenos pre").css('visibility', active ? 'hidden' : 'visible');
            $button.attr('title', active ? show_text : hide_text);
            $button.toggleClass("active", active);
        }

        // create and add the button to all the code blocks containing a python prompt
        var $blocks = $('.highlight-python, .highlight-python3');
        $blocks.find(".highlight:has(pre .gp)").each(function () {
            var $block = $(this);

            // tracebacks (.gt) contain bare text elements that need to be
            // wrapped in a span to work with .nextUntil() call in setButtonState()
            $block.find('pre:has(.gt)').contents().filter(function () {
                return ((this.nodeType == TEXT_NODE) && (this.data.trim().length > 0));
            }).wrap('<span>');

            // insert button into block
            var $button = $('<button class="copybutton">&gt;&gt;&gt;</button>');
            $block.css("position", "relative").prepend($button);
            setButtonState($button, false);
        });

        // toggle button state when clicked
        $('.copybutton').click(
            function () {
                var $button = $(this);
                setButtonState($button, !$button.hasClass("active"));
            });
    });

    /*==========================================================================
     * nested section helper
     *==========================================================================
     * fills out 'data-nested-label' for nested sections (e.g. those w/in a class def)
     * based on name of containing class.  this is used to generate a "return to top"
     * link w/in nested section header.
     *==========================================================================*/
    
        $(function () {
            var template = _.template(('<%- name %> \\2014\\0020').replace(
                /\\(\d{4})/g, function (m, char) { return String.fromCharCode(parseInt(char,16)); }
            ));
            $(".desc-section > .section-header").each(function (idx, header) {
                var $header = $(header),
                    $parent = $header.closest("dd").prev("dt"),
                    name = $parent.find(".descname").text();
                if (!name) {
                    return;
                }
                $header.attr("data-nested-label", template({name: name, parent: $parent}));
            });
        });
    

    /*==========================================================================
     * eof
     *==========================================================================*/

// end encapsulation
// NOTE: sphinx provides underscore.js as $u
}(window, jQuery, $u, CST));