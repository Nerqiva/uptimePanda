# Vendored fonts — JetBrains Mono

JetBrains Mono **v2.304** (latest upstream release, published 2023-01-14,
<https://github.com/JetBrains/JetBrainsMono/releases/tag/v2.304>), licensed
under the **SIL Open Font License 1.1** — see `OFL.txt` in this directory.
Redistribution and embedding are permitted under the OFL.

## Weights / files

| file                    | weight | bytes | sha256                                                           |
|-------------------------|--------|-------|------------------------------------------------------------------|
| `jetbrains-mono-400.woff2` | 400    | 21168 | `14425ba9c695763c1547f48a206b7aa60350a33ae23de09f0407877f3fcd89eb` |
| `jetbrains-mono-500.woff2` | 500    | 21832 | `cb182feeed4d798ff6961d3c79f7026279448fca0676438aaecb21f3fc39553a` |
| `jetbrains-mono-600.woff2` | 600    | 21860 | `400c6bfda18d5d14acad1c15d6dcb9f8e13c015e7286317e0b9a482539bef147` |

## Source (how these exact bytes were obtained)

The upstream release ships **TTF only** (`JetBrainsMono-2.304.zip`); it does
not contain woff2, and no sketchy local conversion was used. Instead the
officially served woff2 files were fetched from the **Google Fonts CDN**
(`fonts.gstatic.com`), the exact latin-subset files Google serves to browsers
for the CSS2 API request

    https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&display=swap
    https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500&display=swap
    https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@600&display=swap

(with a modern browser `User-Agent` so the `woff2` variant is returned; the
multi-weight response serves the shared variable build, so each weight was
requested individually to obtain the same per-weight static instances Google
normally serves). Files are the latin subset (`unicode-range:
U+0000-00FF,…`), matching the primary `latin` glyph coverage the UI needs.
`@font-face` in `public/styles.css` intentionally carries **no**
`unicode-range` descriptor, identical to the previous project's setup.

`OFL.txt` was fetched verbatim from the upstream repository at tag `v2.304`
(`raw.githubusercontent.com/JetBrains/JetBrainsMono/v2.304/OFL.txt`).
