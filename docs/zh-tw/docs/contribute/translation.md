# 翻譯

目前，多語言的支持主要借鑑了 fastapi 的處理方式。需要注意的是，在翻譯的過程中我們只需要確保不同語言在文件級別上保持一致。對於文件中具體的內容，不必過於拘謹，只需意思表達一致即可。

## 完善已有語言

這裏我們以英語爲例進行介紹。

首先，我們需要確定英語對應的 2 個字母的代碼，通過查詢https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes，我們可以知道對應的代碼爲 `en`。

在確定了代碼後，我們就可以知道該語言的文檔所在的目錄，即 `docs/en`。

假設我們想要翻譯的文檔爲 `docs/zh/docs/contribute/translation.md`。那麼，我們可以把該文件拷貝到 `docs/en/docs/contribute/translation.md`。同時，如果該文件依賴了圖片，我們也需要拷貝對應的圖片文件夾到相應的目錄下。

然後，我們可以打開中文對應的 mkdocs.yml，即 `docs/zh/docs/mkdocs.yml`，找到我們想要翻譯的文件所在的位置，比如


```yaml hl_lines="8"
nav:
- Start:
  - index.md
  - discussion.md
  - contribute/before-contributing.md
  - contribute/basic-contribute-approach.md
  - contribute/documentation-requirement.md
  - contribute/translation.md
```

那我們應該在英語的配置文件中相應的層次結構處添加對應的文件。


```yaml hl_lines="8"
nav:
- Start:
  - index.md
  - discussion.md
  - contribute/before-contributing.md
  - contribute/basic-contribute-approach.md
  - contribute/documentation-requirement.md
  - contribute/translation.md
```

然後，我們就可以對其進行翻譯。

最後，我們可以使用 `python3 scripts/doc.py live en` 來預覽修改後的內容。

## 新增全新語言

如果你打算添加一種尚未進行任何翻譯的語言，比如說日語（ `jp`），你可以使用

```python
python3 scripts/doc.py new-lang jp
```

來進行初始化。此後，你就可以按照上一小節的方式來進行貢獻了。