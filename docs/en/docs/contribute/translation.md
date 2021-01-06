# Translation

Currently, multi-language support mainly draws on the processing method of fastapi. It should be noted that during the translation process, we only need to ensure that the different languages ​​are consistent at the file level. Regarding the specific content of the document, you don't need to be too restrictive, just express the same meaning.

## Improve existing language

Here we take English as an example.

First, we need to determine the two-letter code corresponding to English. By querying https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes, we can know that the corresponding code is `en`.

After confirming the code, we can know the directory where the documentation of the language is located, namely `docs/en`.

Suppose the document we want to translate is `docs/zh/docs/contribute/translation.md`. Then, we can copy the file to `docs/en/docs/contribute/translation.md`. At the same time, if the file depends on figures, we also need to copy the corresponding figure folder to the corresponding directory.

Then, we can open the Chinese corresponding mkdocs.yml, namely `docs/zh/docs/mkdocs.yml`, and find the location of the file we want to translate, such as

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
Then we should add the corresponding file at the corresponding hierarchical structure in the English configuration file.

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

Then, we can translate it.

Finally, we can use `python3 scripts/doc.py live en` to preview the modified content.

## Add New language

If you plan to add a language that has not yet undergone any translation, such as Japanese (`jp`), you can use

```python
python3 scripts/doc.py new-lang jp
```

To initialize. After that, you can contribute as in the previous section.