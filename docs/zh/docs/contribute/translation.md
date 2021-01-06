# 翻译

目前，多语言的支持主要借鉴了 fastapi 的处理方式。需要注意的是，在翻译的过程中我们只需要确保不同语言在文件级别上保持一致。对于文件中具体的内容，不必过于拘谨，只需意思表达一致即可。

## 完善已有语言

这里我们以英语为例进行介绍。

首先，我们需要确定英语对应的 2 个字母的代码，通过查询https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes，我们可以知道对应的代码为 `en`。

在确定了代码后，我们就可以知道该语言的文档所在的目录，即 `docs/en`。

假设我们想要翻译的文档为 `docs/zh/docs/contribute/translation.md`。那么，我们可以把该文件拷贝到 `docs/en/docs/contribute/translation.md`。同时，如果该文件依赖了图片，我们也需要拷贝对应的图片文件夹到相应的目录下。

然后，我们可以打开中文对应的 mkdocs.yml，即 `docs/zh/docs/mkdocs.yml`，找到我们想要翻译的文件所在的位置，比如


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

那我们应该在英语的配置文件中相应的层次结构处添加对应的文件。


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

然后，我们就可以对其进行翻译。

最后，我们可以使用 `python3 scripts/doc.py live en` 来预览修改后的内容。

## 新增全新语言

如果你打算添加一种尚未进行任何翻译的语言，比如说日语（ `jp`），你可以使用

```python
python3 scripts/doc.py new-lang jp
```

来进行初始化。此后，你就可以按照上一小节的方式来进行贡献了。