# Android 應用運行機制簡述

本部分主要關注 Android 中 Java 層代碼與 Native 層代碼的基本運行原理。

一般而言，在啓動一個 App 時，Android 會首先執行 Application 類（AndroidManifest.xml 文件中註明）的創建工作，然後再開始執行 Main Activity，繼而根據各種各樣的邏輯執行相關代碼。

注：本部分的內容可能存在以下問題

- 簡略
- 理解不到位

如果發現可以補充的地方，歡迎隨時及時補充。當然，本部分內容也會隨着時間不斷更新。