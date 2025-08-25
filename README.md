# HAR_Replay GUI (封包回放小幫手)

有 GUI 介面的小程式，可以將從 **瀏覽器 DevTools 匯出的 .har** 載入在 localhost，並嘗試還原當時瀏覽網頁的樣子。  
這對於網路偵查、數位取證、案件報告展示都特別有幫助。  

---

## ✨ 為什麼需要它？
- 在 **網路偵查與數位取證** 中，最簡單的蒐證方式之一是利用 **瀏覽器內建的「開發者工具 (DevTools)」**，錄下上網過程並匯出 **HAR (HTTP Archive)**。  
- 但 HAR 檔案本身相當複雜，一般人無法直接看懂。  
- 本工具能把 HAR 檔回放成「當時看到的網頁畫面」，讓案件檢視、教學或法庭展示更直觀。  

---

## 🔍 功能特色
- **最終合成畫面**：以主要網域頁面為基底，自動補齊 HAR 中可用的資源。  
- **時間點回放**：可選擇某一時間點，還原當時的頁面樣貌。  
- **取證流程輔助**：內建簡單教學，提醒錄影、PDF 輸出等保存方式。  
- **快速操作**：提供一鍵複製 DOM 指令  
  ```js
  copy(document.documentElement.outerHTML);
  ```

方便在現場快速保存完整 HTML。

---

## 📦 安裝與使用

1. 從 [Releases](https://github.com/Chiakai-Chang/HAR_Replay/releases) 下載最新的 `HAR_Replay.exe`。
2. 執行後，選擇要載入的 `.har` 檔案。
3. 瀏覽器自動開啟介面，可以選擇「最終合成畫面」或「依時間點預覽」。
4. 可搭配錄影、存 PDF，一併保存證據。

---

## ⚖️ 注意事項

* HAR 本身才是證據，本工具只是 **輔助呈現與理解**。
* 回放屬「靜態合成」：不執行 JavaScript，互動功能與外掛廣告不一定能重播。
* 「外聯補資源」模式會讓瀏覽器上網補齊缺漏的檔案；「純本機」模式則只使用 HAR 內保存的資源。

---

## 📚 學術研究價值

本工具亦作為研究的一部分，探討 **HAR 在數位取證中的應用**，目標是建立更低門檻、可重現的取證流程，未來將以此為基礎發表相關論文。

---

## 🖼️ 預覽

[![](https://chiakai-chang.github.io/CKTools/img/HarReplayPreview.png)](https://github.com/Chiakai-Chang/HAR_Replay/releases)

---

## 👤 作者

由 [Chang, Chia-kai](https://www.linkedin.com/in/chiakai-chang-htciu) 開發，專注於數位鑑識、網路犯罪偵查與 AI 工具實務應用。
