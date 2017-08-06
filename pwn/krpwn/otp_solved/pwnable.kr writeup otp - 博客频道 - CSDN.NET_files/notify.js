(function(window, undefined) {
  var protocol = window.location.protocol;
  var localUreadData=[],hasNewMsg=false,hasGetData=false;
  try {
    var aaInput = document.createElement('input');
    aaInput.type = "hidden";
    aaInput.id = "aa_g_data_ids";
    document.getElementsByTagName('body')[0].appendChild(aaInput);
  } catch(e) {};
  var defaults = {
    realtime: protocol+'//s{0}-im-notify.csdn.net'
    , api: protocol+'//svc-notify.csdn.net'
    , app:'http://msg.csdn.net'
    , space: protocol+'//my.csdn.net/'
    , count: 5
    , subCount: 5
    , staticUrl: protocol+'//csdnimg.cn/rabbit/notev2/'
    , cssUrl: 'css/style.css'
    , 'realtime.js': 'js/realtime.js' // base staticUrl
    // , 'channel': 'message'
    , 'socket.io.js': 'js/socket.io.js'
    // , 'socket.io options': { transports: ["xhr-polling", "jsonp-polling"]}
  }
  //
  , csdn = window.csdn || (window.csdn = {})
  , isShowMsg = true
    // && location.search === '?smsg=1' // DEV
  , friendlyErrors = {
    'timeout': '请求超时，请检查网络后重试！'
    , 'abort': '请求被中止！'
    , 'parsererror': '解析错误，请检查网络后重试！'
    , 'No id supplied': '未登录或登录超时，请重新登录！'
    , 'locked': ''
  }
  ;
var getCookie =function (objName){//获取指定名称的cookie的值
      var arrStr = document.cookie.split("; ");
      for(var i = 0;i < arrStr.length;i ++){
      var temp = arrStr[i].split("="); 
      if(temp[0] == objName) return decodeURI(temp[1]);
      } 
  }
//

  if (Function.prototype.bind === undefined) {
    Function.prototype.bind = function (ctx) {
      var self = this;
      return function () {
        self.apply(ctx, [].slice(arguments, 0));
      };
    };
  }

  function log() {
    if (typeof console !== 'undefined') {
      Function.prototype.apply.call(console.log, console, Array.prototype.slice.call(arguments));
    }
  }

  var $
    , currUser = { username: '' } //登录用户对象
    ;

  csdn.note = function(conf) {
    $ = jQuery;

    //配置项
    this.conf = conf;

    //Dom节点
    this.Dom = {};

    //初始化
    this.init();
  };

  csdn.note.prototype = {
    /*
     * 【初始化入口】
     */
    init: function() {
      var self = this, opts = self.conf;
      opts.wrap = $('#' + opts.wrapId);
      if(typeof opts.count === 'string') {
        opts.count = parseInt(opts.count, 10) || undefined;
      }
      if(typeof opts.subCount === 'string') {
        opts.subCount = parseInt(opts.subCount, 10) || undefined;
      }
      
      self.conf = $.extend({}, defaults,
        //
        opts);

      //初始化消息列表
      self.getDoms();

      //检查用户登录
      self.checkLogin(function(data) {
        //
        if(isShowMsg) {
          //加载样式与事件
          self.loadCss(self.staticUrl(self.conf.cssUrl));
          self.addEvent();
        }
        // 初始化实时系统
        self.initRealtime();
      });
    },
    loadCss : function(src, callback){
      $('<link rel="stylesheet" type="text/css"/>').appendTo('head:first').load(function(){
        callback && callback();
      }).attr('href', src);
    },
    /**
     * 显示指定范围的.loading元素，返回一个函数，执行后将隐藏loading
     * @param  {String} [selector=''] css选择器，配合ctx决定使用哪个.loading
     * @param  {jQuery Object} ctx=wrap .loading所在的上下文
     * @return {Function(Function(Boolean loading) doneCallback)}
     * 隐藏已显示的.loading元素，并在隐藏完毕后调用doneCallback
     * loading参数用于指示.loading当前还在显示中（共享loading时会有这种状况）
     */
    loading: function (selector, ctx) {
      var self = this
        , ctx = typeof selector === 'object' ? selector : self.Dom.wrap
        , selector = typeof selector === 'string' ? selector : ''
        , el = $(selector + ' .loading', ctx)
        , num = (el.data('loadingCount') || 0) + 1
        , completed = false
        ;
      el.show().data('loadingCount', num);
      return function (callback) {
        if(completed) return;
        num = el.data('loadingCount') - 1;
        if(num <= 0) {
          num = 0;
          el.fadeOut('fast', function(){
            el.hide(); // jQuery 1.4.3存在的bug，当fadeOut元素的父元素不可视时，fadeOut不会改变元素display
            callback && callback(false);
          });
        } else {
          callback && callback(true);
        }
        el.data('loadingCount', num);
        completed = true;
      }
    },
    emptyCb: function () {},
    wrapCb: function () {
      var args = [].slice.call(arguments, 0);
      return function (callback) {
        callback && callback.apply(args);
      };
    },
    toggleEmpty: function (toggle, ctx, list) {
      ctx = typeof ctx === 'string' ? $(ctx, this.Dom.wrap) : ctx;
      $('.empty', ctx).toggle(toggle && !$(list, ctx)[0]);
    },
    staticUrl: function (url) {
      // TODO 可配置不同url使用不同时间戳
      return this.conf.staticUrl + url + '?4d63d1f';
    },

    on: function (type, data, handler) {
      this.Dom.wrap.bind(type, data, handler);
      return this;
    },
    emit: function (type, params) {
      this.Dom.wrap.triggerHandler(type, params)
      return this;
    },
    lock: function (id, callback) {
      var self = this;
      if(self.lockers === undefined) {
        self.lockers = {};
      }
      if(!id || !self.lockers[id]) { // id为null 空白字符串等表示不使用lock
        self.lockers[id || ''] = true;
        callback(null, function () {
          self.lockers[id || ''] = false;
        });
      } else {
        callback('locked', self.emptyCb);
      }
    },
    /**
     * 填充this.Dom，建立必要的背景iframe
     * 注意：此时css尚未加载，所以样式都没生效
     */
    getDoms: function() {
      var wrap = this.Dom.wrap = this.conf.wrap
        , tip = wrap.next()
        ;
      if(!tip.is('.csdn_notice_tip')) {
        tip = $('.csdn_notice_tip');
      }
      this.Dom.tip = tip;
      this.Dom.btn = this.conf.btn;
      wrap.append('<iframe src="about:block" frameborder="0" allowTransparency="true" style="z-index:-1;position:absolute;top:0;left:0;width:100%;height:100%;background:transparent"></iframe>');
      return this;
    },
    resetPosition: function () {
      var self = this
        , offset = self.Dom.btn.offset()
        ;
      self.Dom.wrap.css({
        left: offset.left - 212 + 'px',
        top: offset.top + 25 + 'px'
      });
      self.Dom.tip.css({
        left: offset.left - 72 + 'px',
        top: offset.top + 18 + 'px'
      });
    },
    changeToNickname: function (ctx) {
      var self = this;
      ctx = ctx || self.Dom.wrap;
      var users = $('.user_name', ctx).filter(function(){
        return !$(this).data('nickname');
      });
      if(users[0]) {
        $.getJSON('//api.csdn.net/service/open/nick?callback=?', {
          users: users.map(function(){ return this.innerHTML; }).get().join()
        }, function(data){
          //
          users.each(function (i) {
            this.innerHTML = data[i].n;
            $(this).data('nickname', true);
          });
        });
      }
    },
    addEvent: function() {
      var self = this
        , unreads = -1
        , hasReadedItems = false
        , keepUnread = false
        , notifications
        ;
      self.unreads = unreads;
      self.initPanel();
      notifications = $('.notifications', self.Dom.wrap);

      self.Dom.btn.click(function(e, params) {
        self.emit('panel_showed', params);
        if(self.Dom.wrap.toggle().is(':visible')) {
          self.Dom.tip.hide();
        } else {
          self.emit('tip_showing');
        }
        return false;
      });
      $(window).resize(function(e){
        self.resetPosition();
      });
      $(document).click(function(e) {
        var t = e.target;
        try {
          if(!$.contains(self.Dom.wrap[0], t) && !$.contains(self.Dom.tip[0], t)) {
            $(document).trigger('notify-hide');
          }
        } catch(e) {
          log(e);
        }
      });

      $('.notice_list_con .notice_content', self.Dom.wrap).bind('click', function (e) {
        var target = e.target
           , item = $(target).parents(".list")
           , index = item.index()
           , detail = $('.detail_con .notice_content > *:eq(' + index + ')', self.Dom.wrap)
           ;


        item.hasClass("unread")&&self.setReaded([{containIds:item.attr("data-ids").split(",")}],function(data){
          keepUnread = true;
          item.removeClass('unread');
          //去除已读id
          var _strReadedIds = item.attr("data-ids");
          var _unread = [],_item={};
          for(var i=0;i<localUreadData.length;i++){
            _item = localUreadData[i];
            if(_item.containIds.join() === _strReadedIds){
              localUreadData.splice(i,1);
            }
          }
          self.emit('tip_showing');
        });

        detail.addClass('curr').show().siblings().removeClass('curr').hide();
        if(!item.hasClass("noslide")){
          self.goSlide(notifications.eq(0), notifications.eq(1), 'right').emit('detail_showed', [detail, index]);
        }
        if(item.hasClass("action")&&target.tagName=="A"){
          self.doaction({
            id:$(item).attr("data-ids").split(",")[0]*1,
            dataApi:$(".callback",item).attr("data-api"),
            args:$(target).attr("data-api")
          },function(err, data){
            $(".callback",item).html(data.msg);
            $(".callback",detail).html(data.msg);
          });
        }
      });

      $('.detail_con .notice_content', self.Dom.wrap).delegate('.item_title', 'click', function (e) {
        var target = e.target
          , item = $(target).parents(".detail_list")
          , index = item.index()
          , list = $('.notice_list_con .notice_content > *:eq(' + index + ')', self.Dom.wrap);
        
        if(item.hasClass("action")&&target.tagName=="A"){
          self.doaction({
            id:$(item).attr("data-ids").split(",")[0]*1,
            dataApi:$(".callback",item).attr("data-api"),
            args:$(target).attr("data-api")
          },function(err, data){
            $(".callback",item).html(data.msg);
            $(".callback",list).html(data.msg);
          });
        }
      });

      //当trigger click时，会将事件源对象变成这个close节点，扰乱了其它js的判断逻辑。
      function hidecb(){
        self.Dom.wrap.hide();
        self.emit('tip_showing');
      }

      $(document).bind("notify-hide",function(){
        hidecb();
      });

      $('.csdn_note .close1', self.Dom.wrap).click(function () {
        hidecb();
      });

      $('.go_back', self.Dom.wrap).click(function () {
        self.goSlide(notifications.eq(1), notifications.eq(0), 'left');
        self.emit('panel_showed');
      });
      //$('.read_all', self.Dom.wrap).click(function () {
      //  self.setAllReaded();
      //  return false;
      //});
      $('.prvnote, .nextnote', self.Dom.wrap).click(function () {
        var el = $(this);
        if(el.hasClass('disabled')) return;
        var form = $('.detail_con .notice_content .curr', self.Dom.wrap)
          , to = form[el.hasClass('prvnote') ? 'prev' : 'next']()
          , index = to.index()
          ;
        if (~index) {
          $('.notice_list_con .notice_content > *:eq(' + index + ')', self.Dom.wrap).removeClass('unread');
          $([form[0], to[0]]).toggleClass('curr');
          self.goSlide(form, to, el.hasClass('prvnote') ? 'left' : 'right').emit('detail_showed', [to, index]);
        }
      });

      self.on('panel_showed', function (e, showDetail) {
        self.resetPosition();

        if (!hasReadedItems) {
          $('.notice_content', self.Dom.wrap).empty();
          self.getAllReaded(self.showListCbWrap(function (err, data, loading) {
            hasReadedItems = true;
          }));
        }
        if(showDetail&&showDetail.data){
          self.fillList("prepend",showDetail);
          self.slideReset();
          hasGetData = true;
          hasNewMsg = false;
        }
        // 显示面板内容
        else if (localUreadData.length > 0&&hasNewMsg) {
          hasNewMsg = false;
          self.getUnreads(self.showListCbWrap(function (err, data, loading) {
              localUreadData = data.data;
              hasNewMsg = false;
              self.emit('tip_showing');
          }));
        }
        
        if (hasGetData) {
          self.Dom.wrap.one('list_showed', function (e, err) {
            if (err) {
              self.error(err);
            } else {
              if(showDetail) {
                var unreadsItem = $('.notice_list_con .unread', self.Dom.wrap);
                if(unreadsItem.length === 1) {
                  unreadsItem.trigger('click');
                }
              }
            }
          });
        }
      }).on('detail_showed', function (e, detail, index) {
        // 显示通知详情
        $('.detail_con .prvnote', self.Dom.wrap).toggleClass('disabled', !(index > 0));
        $('.detail_con .nextnote', self.Dom.wrap).toggleClass('disabled', !detail.next()[0]);
        if (!detail.data('loaded') && !$('dd', detail)[0] && !$('.empty:visible', detail)[0] && !$('.loading:visible', detail)[0]) {
          self.getDetail(detail);
        }
      }).on('tip_showing', function () {
        keepUnread = true;
        // if ($('.notice_list_con', self.Dom.wrap).css('display') !== 'none') {
        //   $('.notice_list_con .notice_content .unread', self.Dom.wrap).removeClass('unread');
        // }
        self.initBtn();
        if (localUreadData.length > 0) {
          self.resetPosition();
          $('strong', self.Dom.tip.show()).html(localUreadData.length);
          $('.icon-hasnotes',self.Dom.btn).show();
          //派发给toolbar
        }else{
          $('.icon-hasnotes',self.Dom.btn).hide();
        }
        $(document).trigger("toolbar-setNotesNum",localUreadData.length);
      }).on('receive_unreads', function (e, data) {
        
        data.initUnreadIds&&(localUreadData = data.initUnreadIds);
        // 收到未读消息实时通知 typeof data === number123123

        //data.realtimeMsg&&localUreadData = data.realtimeMsg;
        //self.unreads = unreads = (unreads === -1 ? 0 : unreads) + data;

        if (self.Dom.wrap.is(':visible')) {
          if($('.notice_list_con', self.Dom.wrap).is(':visible')){
            if(data.realtimeMsg){
              self.emit('panel_showed',{
                data:data.data
              });
            }else{
              self.emit('panel_showed');
            }
          }
        } else {
          self.emit('tip_showing');
        }
      }).on('receive_setreaded', function (e, data) {
        var _len = localUreadData.length;
        // 收到设置为已读实时通知 typeof data === array or number
        if (keepUnread) {
        } else { // TODO 如果焦点在当前浏览器窗口，什么都不做
          // 非查看窗口收到已读通知时需要重置状态，以便再次打开时能正确显示通知
          self.unreads = _len;
          hasReadedItems = false;
        }
        
        if (_len <= 0) {
          self.Dom.tip.hide();
          $(".icon-hasnotes",self.Dom.btn).hide();
        }
        $('strong', self.Dom.tip).html(_len);
      });

      $('.close2', self.Dom.tip).click(function () {
        self.Dom.tip.hide();
        self.setReaded([], function(){
        });
      });

      $('.tip_text', self.Dom.tip).click(function () {
        self.Dom.btn.trigger('click'
          // , ['Show one and only unread detail'] // 点击未读消息提示框后，如果未读条目只有一条，则自动进入哪一条未读
        );
      });


      return self;
    },
    initBtn: function(){
      if(this.conf.btn.find(".icon-hasnotes").length<=0){
        this.conf.btn.html('<div class="icon-hasnotes" style="display:none"></div>');
      }
    },
    //<span class="title"><a href="' + this.conf.app + '/" target="_blank" class="read_all">全部设为已读</a><a href="' + this.conf.app + '/" target="_blank" class="go_all">查看所有通知</a></span>\
    initPanel: function () {
      $('.box', this.Dom.wrap).append('\
<div class="notifications notice_list_con curr">\
  <div class="menu_title">\
    <span class="title"><a href="http://msg.csdn.net/letters" target="_blank" class="read_all">查看所有私信</a><a href="http://msg.csdn.net" target="_blank" class="go_all">查看所有通知</a></span>\
  </div>\
  <div class="loading"></div>\
  <div class="empty">暂没有新通知</div>\
  <div class="notice_content"></div>\
</div>\
<div class="notifications detail_con" style="display: none">\
  <div class="menu_title">\
    <span class="title">\
      <a class="go_back" href="javascript:void 0;">返回通知列表</a>\
      <a class="notifications_page_none nextnote" href="javascript:void 0;">下一条</a>\
      <a class="notifications_page prvnote" href="javascript:void 0;">上一条</a>\
    </span>\
  </div>\
  <div class="notice_content" style="overflow-y: scroll; height: 250px;"></div>\
</div>\
<div class="error"></div>');
    },
    fillList: function(insert, data) {
      if(!data || !data.data || !data.data.length) return;
      data = data.data;
      var self = this
        , wrap = self.Dom.wrap
        , list = new Array(data.length)
        , details = new Array(data.length)
        ;
      $.each(data, function (i, v) {
        var action = v.isaction?" action ":"";
        var isslide = !v.isslide?" noslide ":"";
        var dataIds=(function(){
          var _ids = [];
          for(var i=0,len=v.containIds.length,item=v.containIds;i<len;i++){
            _ids.push(item[i]*1);
          }
          return _ids.join(",");
        })();
        try
        {
          var aaaInput = document.getElementById("aa_g_data_ids");
          var cv = aaaInput.value;
          if (cv.indexOf(dataIds + "|") >= 0) {
            return;
          }
          aaaInput.value += dataIds + "|";
        } catch(e) {}
        list[i] = '\
<dl data-ids="'+dataIds+'" class="list rev_type'+v.type + (insert === 'append' ? '' : ' unread')+isslide+action+'" style="/*display: none*/">\
  <dt>\
    <i></i>\
    <span class="item_title">' + v.title + '</span>\
    <span class="count_down">' + v.time + '</span>\
  </dt>\
</dl>';
        var remain = v.containIds.length - self.conf.subCount;
        details[i]='\
<div style="/*display: none*/">\
  <dl class="detail_list rev_type' + v.type +isslide+action+ '" data-ids="' + v.containIds.join() + '">\
    <dt>\
      <i></i>\
      <span class="item_title">' + self.ubbDecode(v.longTitle) + '</span>\
      <span class="count_down"></span>\
    </dt>\
  </dl>\
  <div class="loading"></div>\
  <div class="empty">暂没有新通知</div>\
  <a class="notifications_more" target="_blank">查看其它 0 条</a>\
</div>';
      });
      $('.notice_list_con .notice_content', wrap)[insert](list.join(''));
      $('.detail_con .notice_content', wrap)[insert](details.join(''));
      self.changeToNickname();
    },
    fillDetail: function (detail, data) {
      if(!data || !data.data || !data.data.length) return;
      var bodyTpl = data.bodyTpl
        , self = this
        , dl = $('dl', detail)
        , html
        ;
      data = data.data;

      if (data[0].body) {
        html = $.map(data, function (v) {
          return self.feTemplate(bodyTpl).render({
            userlink:self.conf.space + v.from_user,
            from_user:v.from_user,
            body:self.ubbDecode(v.body),
            time:v.time
          });
        }).join('');
        if (html) {
          dl.append(html);
          var remain = dl.attr('data-ids').split(',').length - data.length
            , url = data[0].url
            ;
          if(remain > 0 && url) {
            $('.notifications_more', detail).html(function (i, v) {
              return v.replace(/\d+/g, remain);
            }).attr('href', url).addClass('block');
          }
        }
      }
      if (!html) {
        $('dt .count_down', detail).html(data[0].time);
        detail.data('loaded', true);
      }
      self.changeToNickname(dl);
    },
    /**
     * 显示列表的回调包装。和getUnreads，getAllReaded配合使用，包含一些通用的操作，以及触发必要的事件
     * @param  {Function} callback 当正常获取到数据时的回调
     * @return {Function} 包装之后的回调函数
     */
    showListCbWrap: function (callback) {
      var self = this;
      return function (err, data, loading) {
        if (err) {
          self.emit('list_showed', [err]);
        } else {
          callback && callback(err, data, loading);
          if (!loading) {
            var list = $('.notice_list_con .notice_content > .list', self.Dom.wrap);
            // 调整可见消息数量
            if (list.filter(':visible').length === 0) {
              var n = list.filter('.unread').length;
              if(n < self.conf.count) {
                n = self.conf.count;
              }
              list.slice(n).remove();
              $('.detail_con .notice_content > *', self.Dom.wrap).slice(n).remove();
            }
            list.show();
            self.slideReset();
            self.emit('list_showed');
          }
        }
      };
    },
    error: function (msg) {
      var self = this, func = arguments.callee;
      if(func.init === undefined) {
        func.ele = $('.error', self.Dom.wrap);
        self.on('panel_showed detail_showed', function () {
          func.ele.hide();
        });
        func.init = true;
      }
      msg = friendlyErrors[msg] !== undefined ? friendlyErrors[msg] : msg;
      func.ele.toggle(!!msg).html(msg);
    },
    invokeAPI: function (url, params, opts, callback) {
      var self = this
        , opts = opts || {}
        , callback = callback || self.emptyCb
        ;
      self.lock(opts.lock === undefined || opts.lock ? url : null, function (err, unlock) {
        if(err) {
          callback(err);
          return;
        }
        var done = opts.loading === undefined || opts.loading ? self.loading(opts.container) : self.wrapCb(false)
          , data
          , completed = false
          , complete = function (xhr, status) {
            if(completed) return;
            done(function (loading) {
              if(status && status !== 'success') {
                callback(status, null, loading);
              } else {
                if(data.status !== 200) {
                  callback(data.error || data.status, data, loading);
                } else {
                  if(opts.list) {
                    // /detail/i.test(url) && (data.data = []); // DEV
                    self.toggleEmpty(!loading && data.data && !data.data.length, opts.container, opts.list);
                  }
                  callback(null, data, loading);
                }
              }
              unlock();
              completed = true;
            });
          }
          ;
        setTimeout(function () {
          complete(null, 'timeout');
        }, 20000);
        $.ajax({
          url: self.conf.api + url,
          data: params,
          dataType: 'jsonp', // TODO jsonp方式调用不能产生正确的timeout错误等，考虑换成支持跨域的xhr(在ff chrome ie8+)
          success: function (json) {
            if(completed) return;
            data = json;
          },
          complete: complete
        });
      });
    },
    getUnreads: function (callback) {
      var self = this;
      self.invokeAPI('/get_unread?jsonpcallback=?', {}, {
        container: '.notice_list_con',
        list: '.notice_content > .list'
      }, function (err, data, loading) {
        self.fillList('prepend', data);
        callback && callback(err, data, loading);
      });
    },
    doaction : function(data,callback){
      var self = this;
      self.invokeAPI('/do_action?jsonpcallback=?', {
          id:data.id,
          dataApi:data.dataApi+"?me="+currUser.username+'&'+data.args,
        }, {
      }, function (err, data, loading) {
        callback && callback(err, data, loading);
      });
    },
    getAllReaded: function (callback) {
      var self = this;
      self.invokeAPI('/get_all?jsonpcallback=?', {
        username: currUser.username,
        status: 1,
        count: self.conf.count || 5,
        subcount: self.conf.subcount || 5
      }, {
        container: '.notice_list_con',
        list: '.notice_content > .list'
      }, function (err, data, loading) {
        self.fillList('append', data);
        callback && callback(err, data, loading);
      });
    },
    setAllReaded: function(){
     if(!localUreadData.length){
        return;
     }
     this.setReaded([],function(){
        $(".csdn_note .unread").each(function(i){
           $(this).removeClass("unread");
           localUreadData=[];
        });
     });
    },
    setReaded: function (data, next) {
      var self = this;
      self.invokeAPI('/set_readed?jsonpcallback=?', {
        ids: $.map(data, function (i) {
          return i.containIds.join();
        }).join()
      }, {
        loading: false
      },function(data){
        next&&next(data);
      });
    },
    getlocalUnread: function(){
      return localUreadData;
    },
    isGetAll: function(){
      return hasGetData;
    },
    isHasNewMsg: function(){
      return hasNewMsg;
    },
    getDetail: function(detail, start, limit){
      var self = this
        , ids = $('dl', detail).attr('data-ids').split(',')
        ;
      start = start || 0;
      limit = limit || self.conf.subCount;
      if (ids.length > 0) {
        self.invokeAPI('/get_details?jsonpcallback=?', {
          ids: ids.slice(start, start + limit).join()
        }, {
          container: detail,
          list: 'dl > dd',
          lock: false
        }, function (err, data) {
          if (err) {
            self.error(err);
          } else {
            self.fillDetail(detail, data);
          }
        });
      }
    },
    /**
     * 动画切换
     * @param  {jQuery Object} from     动画开始的元素
     * @param  {jQuery Object} to       动画结束的元素
     * @param  {String} direction       to在from的左边还是右边, left right
     */
    goSlide: function(from, to, direction) {
      var self = this
        , speed = 110
          // + 3000 // DEV
        , offsetW = from.width()
        , content = to.parents('.notice_content:first')
        , fromComplete, toComplete
        ;

      self.emit('goSliding');

      if (!to.hasClass('curr')) {
        from.removeClass('curr');
        to.addClass('curr');
      }

      from.css({
        position: 'relative'
      });

      to.css({
        position: 'absolute'
        , top: 0
        , left: (direction === 'left' ? -offsetW : offsetW) + 'px'
        , width: offsetW
      }).show();

      content.height(function (i, v) {
        return v - from.height() + Math.max(from.height(), to.height());
      });

      fromComplete = function () {
        from.css('position', '').hide();
      };
      from.animate({
        left: (direction === 'left' ? offsetW : -offsetW) + 'px'
      }, speed, fromComplete);

      toComplete = function () {
        to.css({
          position: ''
          , top: ''
          , left: ''
        });
        content.css('height', '');
      };
      to.animate({ left: 0 }, speed, toComplete);

      self.Dom.wrap.one('goSliding', function () {
        from.stop();
        fromComplete.call(from[0]);
        to.stop();
        toComplete.call(to[0]);
      });

      return this;
    },
    slideReset: function() {
      var self = this
        , container = $('.notice_list_con .notice_content', self.Dom.wrap)
        , items = container.children().filter(':visible')
        ;
      $('.notifications', this.Dom.wrap).eq(0).addClass('curr').show().end()
        .slice(1).hide();
        ;
      if(items.length > self.conf.count) {
        // container.css({
        //   overflow: 'auto'
        //   , height: '255px'
        // });
        container.addClass("hover-overflow");
      }
    },
    /*
     * 【LOGIC】检查登录
     */
    checkLogin: function(callback) {
        try{
          currUser.username = getCookie("UserName") || currUser.username;
          currUser.userInfo = getCookie("UserInfo") || currUser.userInfo;
          currUser.username && callback && callback(currUser.username);
        }catch(e){
          log(e);
        }
    },
    initRealtime: function () {
      var self = this;
      // 兼容独立和合并的realtime.js
      if(csdn.RealtimeClient === undefined) {
        $.ajax({
          url: self.staticUrl(self.conf['realtime.js'])
          , dataType: 'script'
          , cache: true // 已通过staticUrl对外链文件提供了缓存支持，getScript()可能会始终在url结尾加时间戳
          , success: arguments.callee.bind(self)
        });
        return;
      }
      self.conf['socket.io.js'] = self.staticUrl(self.conf['socket.io.js']);
      self.realtimeClient = new csdn.RealtimeClient($.extend({
        channel: currUser.username
      }, self.conf), function (msg) {
        // 分发收到的实时消息
        if(typeof msg === 'object') {
          if(msg.setReaded) {
            self.emit('receive_setreaded', [msg.setReaded]);
          }
          if(msg.initUnreadIds&&msg.initUnreadIds.length){
            hasNewMsg = true;
            self.emit('receive_unreads', msg);
          }
          if(msg.realtimeMsg){
            hasNewMsg = true;
            localUreadData = localUreadData.concat(msg.data);
            self.emit('receive_unreads', msg);
          }
        }
      });
    },
    /*
    * UBB转义
    */
    ubbDecode : function(content){
      var _this = this;
      content = $.trim(content);
      var re = /\[code=([\w#\.]+)\]([\s\S]*?)\[\/code\]/ig;

      function replaceQuote(str) {
        var m = /\[quote=([^\]]+)]([\s\S]*)\[\/quote\]/gi.exec(str);
        if (m) {
            return str.replace(m[0], '<fieldset><legend>引用“<span class="user_name">' + m[1] + '</span>”的评论：</legend>' + replaceQuote(m[2]) + '</fieldset>');
        } else {
            return str;
        }
      }
      var codelist = [];
      while ((mc = re.exec(content)) != null) {
          codelist.push(mc[0]);
          content = content.replace(mc[0], "--code--");
      }
      content = replaceQuote(content);
      content = content.replace(/\[reply]([\s\S]*?)\[\/reply\][\r\n]{0,2}/gi, "回复<span class='user_name'>$1</span>：");
      content = content.replace(/\[url=([^\]]+)]([\s\S]*?)\[\/url\]/gi, '<a href="$1" target="_blank">$2</a>');
      content = content.replace(/\[img(=([^\]]+))?]([\s\S]*?)\[\/img\]/gi, '<img src="$3" style="max-width:200px;max-height:100px;" border="0" title="$2" />');
      content = content.replace(/\r?\n/ig, "<br />");

      if (codelist.length > 0) {
          var re1 = /--code--/ig;
          var i = 0;
          while ((mc = re1.exec(content)) != null) {
              content = content.replace(mc[0], codelist[i]);
              i++;
          }
      }
      content = content.replace(/\[code=([\w#\.]+)\]([\s\S]*?)\[\/code\]/ig, function (m0, m1, m2) {
          if ($.trim(m2) == "") return '';
          return '<pre name="code2" class="' + m1 + '">' + _this.HTMLEncode(m2) + '</pre>';
      });

      content = content.replace(/(<br\s\S*>|<br>)/ig, function (m0) {
          if ($.trim(m0) == "") return '';
          //return _this.HTMLEncode(m0);
          return "&nbsp;&nbsp;";
      });
      //针对转义的"做处理
      content = content.replace(/(\\&quote\;|\&quote\;)/ig, function (m0) {
          if ($.trim(m0) == "") return '';
          //return _this.HTMLEncode(m0);
          return "";
      });
      return content;
    },
    HTMLEncode : function(str) {
      var s = "";
      if(str.length == 0) return "";
      s = str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\'/g, "&#39;").replace(/\"/g, "&quot;");
      return s;
    },

    /**
    * 简单模板替换
    * @param  {String} tempStr 待替换字符串
    * @return {String}         替换后的html
    */
    feTemplate : function(tempStr){
      // TODO 未处理模板字段重复出现的问题       [fixed]
      //      未处理返回的模板对象复用的问题     [fixed]
      // 测试用例 //jsfiddle.net/SdzfU/2/
      
      return {
          render:function(conf){
            var result=tempStr;
            for(var name in conf){
                if(conf.hasOwnProperty(name)){
                    result=result.replace(new RegExp("{"+"%"+name+"%"+"}","g"),conf[name]);
                }
            }
            return result;
          }
      }
    }
  };

})(window);

(function($, window, undefined) {
  if ($ === undefined) {
    // 按需加载jQuery
    var done = false
      , callback = arguments.callee
      , script = document.createElement('script')
      , head = document.getElementsByTagName('head')[0] || document.documentElement
      ;
    script.src = '//csdnimg.cn/www/js/jquery-1.4.2.min.js';
    script.charset = 'utf-8';
    script.onload = script.onreadystatechange = function () {
      if(!done && (!this.readyState || this.readyState === 'loaded' || this.readyState === 'complete')) {
        done = true;
        try {
          callback(window.jQuery, window);
        } catch(e) {
          window.console && window.console.log(e);
        }

        script.onload = script.onreadystatechange = null;
        if(head && script.parentNode) {
          head.removeChild(script);
        }
      }
    };
    head.insertBefore(script, head.firstChild);
    return;
  }

  // 初始化通知面板
  var script = $("#noticeScript")
    , opts = {
      instance: 'csdn_note'
      , btnId: script.attr('btnId') || 'header_notice_num'
      , wrapId: 'note1'
    }
    ;
  opts.btn = $('#' + opts.btnId);
  if(!opts.btn[0]) {
    return;
  }

  $.map(['instance', 'wrapId'
    , 'realtime', 'api', 'app', 'space', 'count', 'subCount'
    , 'staticUrl', 'cssUrl'
    , 'realtime.js', 'channel', 'socket.io.js', 'socket.io options'], function (v) {
    opts[v] = script.attr(v.replace(/[. ]/g, '-')) || opts[v];
  });

  if(opts.instance === "csdn_note") {
    $('\
<div id="note1" class="csdn_note" style="display:none; position:absolute; z-index:9999; width:440px">\
  <span class="notice_top_arrow"><span class="inner"></span></span>\
  <div class="box"></div>\
</div>').insertBefore(script);
  }
  $('\
<div class="csdn_notice_tip" style="display:none; position:absolute; z-index:9990; width:170px">\
  <iframe src="about:blank" frameborder="0" scrolling="no" style="z-index:-1;position:absolute;top:0;left:0;width:100%;height:100%;background:transparent"></iframe>\
  <div class="tip_text">您有<strong>0</strong>条新通知</div>\
  <a href="javascript:void 0" class="close2"></a>\
</div>').insertBefore(script).hide();

  window[opts.instance] = new csdn.note(opts);

})(window.jQuery, window);
