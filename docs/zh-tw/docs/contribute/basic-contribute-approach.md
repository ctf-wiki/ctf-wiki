# 基本貢獻方式

## 我之前沒怎麼用過 Github

參與 Wiki 的編寫**需要**一個 Github 賬號， **不需要**高超的 Github 技巧。

舉個栗子，假如我想要修改一個頁面內容，應該怎麼操作呢？

1. 在 [CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/) 上找到對應頁面
2. 點擊 正文右上方、目錄左側的 **“編輯此頁”** 按鈕
3. （應該已經跳轉到了 Github 上的對應頁面吧？）這時候右上方還會有一個 **“編輯此頁”** 的按鈕，點擊它就可以在線編輯了
4. 寫好了之後點下方的綠色按鈕，可能會提示沒有權限。不必擔心！Github 會自動幫你 fork 一份項目的文件並創建 Pull Request

（有木有很簡單？）

如果還是不放心，可以參考以下資料：  

https://guides.github.com/activities/hello-world/  
https://guides.github.com/activities/forking/  

## 我之前用過 Github

基本協作方式如下

1. Fork 主倉庫到自己的倉庫中。
2. 當想要貢獻某部分內容時，請務必仔細查看 **[Issue](https://github.com/ctf-wiki/ctf-wiki/issues)** 與 **[Project](https://github.com/ctf-wiki/ctf-wiki/projects)**，以便確定是否有人已經開始了這項工作。當然，我們更希望你可以加入 [Discord](https://discord.gg/ekv7WDa9pq)，以便於溝通與交流。
3. 在決定將內容推送到本倉庫時，**請你首先拉取本倉庫代碼進行合併，自行處理好衝突，同時確保在本地可以正常生成文檔**，然後再 PR 到主倉庫的 master 分支上。其中，PR 需要包含以下基本信息
    * 標題：本次 PR 的目的（做了什麼工作，修復了什麼問題）
    * 內容：如果必要的話，請給出對修復問題的敘述
    * **注意，所有的內容都應該使用英語**
4. 如果發現 PR 中有什麼問題，請在 PR 中直接評論，並儘量給出修正的方式，或者也可以直接進行修改。 
5. 提出該 PR 的人根據評論修正內容，然後將修改後的內容 Merge 到 master 分支中。

目前，在人員較少的前提下，基本上可以忽略 4-5 步。

## 注意

- 每次 Pull Request 應只解決一個主要的事情，這樣方便於進行修改。
- 在每次 Pull Request 時，請確保自己在本地生成時，可以正確顯示，並在 Pull Request 頁面的評論中查看預覽的站點是否爲自己期望的樣子。
- 如果你想要開啓一個新的章節，即編寫目前 CTF Wiki 中沒有的內容，請務必加入 [Discord](https://discord.gg/ekv7WDa9pq) 中交流，並在交流完畢後**將自己想要開啓的新的章節以簡明扼要的方式發起一個新的 issue**，以便於管理人員把這個放到對應 Project 的 In Process 欄中。
- 在你成爲團隊成員後，你可以自由地編寫 Project 中的內容。
- 更多信息，請參見 [F.A.Q](https://github.com/ctf-wiki/ctf-wiki/wiki/F.A.Q)。
