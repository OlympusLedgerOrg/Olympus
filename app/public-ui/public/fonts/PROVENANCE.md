# Vendored web fonts — provenance

The 18-family Olympus type system used to load from the Google Fonts CDN via a
`<link>` in `app/public-ui/index.html`. Every application launch therefore sent
the user's IP address and launch time to `fonts.googleapis.com` and
`fonts.gstatic.com`, and the Tauri CSP had to whitelist both origins. For a tool
whose premise is that nothing about a sensitive document leaves the machine,
that was the wrong default, and it made first paint depend on a network the
application otherwise does not need.

These files are those same fonts, fetched once and committed. Nothing here is
modified: they are byte-for-byte the subsets the CDN serves.

## Source

Fetched 2026-08-10 from the exact stylesheet URL `index.html` previously linked,
requested with a Chrome user agent so the CDN returns `woff2` (an older agent
gets `ttf`):

```text
https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Audiowide&family=Rajdhani:wght@400;500;600;700&family=Oxanium:wght@400;500;600;700&family=Exo+2:wght@300;400;500;600;700&family=Michroma&family=Share+Tech+Mono&family=IBM+Plex+Mono:wght@300;400;500;600&family=JetBrains+Mono:wght@300;400;500;600&family=Space+Mono:wght@400;700&family=Roboto+Mono:wght@300;400;500&family=VT323&family=Press+Start+2P&family=Silkscreen:wght@400;700&family=Pixelify+Sans:wght@400;600&family=DotGothic16&family=Inter:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap
```

Every `@font-face` block in that response whose subset is `latin` or `latin-ext`
was downloaded; the `src` URL of each became the file listed below, and each
`unicode-range` was carried across unchanged into
`app/public-ui/src/styles/fonts.css`.

**Subset scope.** Latin and Latin-Extended only — the shipped UI is English.
The CDN also serves Cyrillic, Greek, Vietnamese, and Devanagari cuts of some of
these families; those are deliberately not vendored, so text in those scripts
now falls back to a system face instead of being fetched on demand. Vendor the
additional subsets here if the UI is ever localised.

## Licence

All 18 families are under the SIL Open Font License. That is not asserted from
memory — it is read out of the `name` table of each binary in this directory
(name ID 14, "License Info URL"), so it is the licence the foundry attached to
the exact bytes being shipped:

| Family | Licence URL embedded in the binary |
|---|---|
| Audiowide | http://scripts.sil.org/OFL |
| DotGothic16 | https://scripts.sil.org/OFL |
| Exo 2 | https://openfontlicense.org |
| IBM Plex Mono | http://scripts.sil.org/OFL |
| IBM Plex Mono Light | http://scripts.sil.org/OFL |
| IBM Plex Mono Medium | http://scripts.sil.org/OFL |
| IBM Plex Mono SemiBold | http://scripts.sil.org/OFL |
| IBM Plex Sans | http://scripts.sil.org/OFL |
| Inter | https://openfontlicense.org |
| JetBrains Mono | https://scripts.sil.org/OFL |
| Michroma | https://scripts.sil.org/OFL |
| Orbitron | http://scripts.sil.org/OFL |
| Oxanium ExtraLight | https://scripts.sil.org/OFL |
| Pixelify Sans | https://scripts.sil.org/OFL |
| Press Start 2P | http://scripts.sil.org/OFL |
| Rajdhani | http://scripts.sil.org/OFL |
| Rajdhani Medium | http://scripts.sil.org/OFL |
| Rajdhani SemiBold | http://scripts.sil.org/OFL |
| Roboto Mono | https://openfontlicense.org |
| Share Tech Mono | http://scripts.sil.org/OFL |
| Silkscreen | https://scripts.sil.org/OFL |
| Space Mono | https://openfontlicense.org |
| VT323 | http://scripts.sil.org/OFL |

(The style-linked names — `Rajdhani Medium`, `IBM Plex Mono SemiBold`,
`Oxanium ExtraLight` — are weight-specific `name` entries of the same families,
not separate typefaces.)

Name ID 13, the long licence description, is stripped from the web subsets to
save bytes, which is why only the URL survives.

**The licence text travels with the fonts.** The OFL requires it, so
[`LICENSES/LICENSE-OFL-1.1`](../../../../LICENSES/LICENSE-OFL-1.1) carries the
full OFL 1.1 text plus the per-family copyright notices, and
`src-tauri/tauri.conf.json` lists `../LICENSES/*` under `bundle.resources` so
the file ships inside every installer alongside the binaries it covers.

The copyright notices there are read from name ID 0 of these same files, so each
notice belongs to the exact bytes being distributed. The licence body is the
standard, invariant OFL 1.1 text.

## Regenerating

Fetch the stylesheet with a modern user agent, keep the `latin` / `latin-ext`
blocks, download each `src` URL, and rewrite `fonts.css` to point at
`/fonts/<family>-<weight>-<style>-<subset>.woff2`. Re-record the digests below,
and re-read the embedded licence URLs rather than copying the table forward.

## Files

`app/public-ui/public/` is copied verbatim into the bundle by Vite, so these
paths are stable at runtime as `/fonts/…`.

### Audiowide

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `audiowide-400-normal-latin-ext.woff2` | 400 | latin-ext | 7176 | `bc0d2b852eb2c7c2048ef8852f0b41a9900a9b6b8b72bfa96efa0a1f4393458f` |
| `audiowide-400-normal-latin.woff2` | 400 | latin | 14132 | `e21fd195dd9dcdafc5a0f162a8fc252703f3683179861afb057cd58f9d27dbe5` |

### DotGothic16

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `dotgothic16-400-normal-latin-ext.woff2` | 400 | latin-ext | 1940 | `1640fece67968044c08bcecbf66c8e04873ba7beac70ea2bb0842a7cb20ecb81` |
| `dotgothic16-400-normal-latin.woff2` | 400 | latin | 10508 | `d29abf817463fdba7e9e87fc954cfa2b60ea6534e8a79c46e858a0dc5aa6a6f6` |

### Exo 2

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `exo-2-300-normal-latin-ext.woff2` | 300 | latin-ext | 30832 | `a3b66800e9aa36bd8f3cc59f29024c9e063a2ac607d955dd27e149c29cac8410` |
| `exo-2-300-normal-latin.woff2` | 300 | latin | 40896 | `4a259dde317e08aa5d37e6eb684e222ae833516b2a0fccba36ee5e36224f16be` |
| `exo-2-400-normal-latin-ext.woff2` | 400 | latin-ext | 30832 | `a3b66800e9aa36bd8f3cc59f29024c9e063a2ac607d955dd27e149c29cac8410` |
| `exo-2-400-normal-latin.woff2` | 400 | latin | 40896 | `4a259dde317e08aa5d37e6eb684e222ae833516b2a0fccba36ee5e36224f16be` |
| `exo-2-500-normal-latin-ext.woff2` | 500 | latin-ext | 30832 | `a3b66800e9aa36bd8f3cc59f29024c9e063a2ac607d955dd27e149c29cac8410` |
| `exo-2-500-normal-latin.woff2` | 500 | latin | 40896 | `4a259dde317e08aa5d37e6eb684e222ae833516b2a0fccba36ee5e36224f16be` |
| `exo-2-600-normal-latin-ext.woff2` | 600 | latin-ext | 30832 | `a3b66800e9aa36bd8f3cc59f29024c9e063a2ac607d955dd27e149c29cac8410` |
| `exo-2-600-normal-latin.woff2` | 600 | latin | 40896 | `4a259dde317e08aa5d37e6eb684e222ae833516b2a0fccba36ee5e36224f16be` |
| `exo-2-700-normal-latin-ext.woff2` | 700 | latin-ext | 30832 | `a3b66800e9aa36bd8f3cc59f29024c9e063a2ac607d955dd27e149c29cac8410` |
| `exo-2-700-normal-latin.woff2` | 700 | latin | 40896 | `4a259dde317e08aa5d37e6eb684e222ae833516b2a0fccba36ee5e36224f16be` |

### IBM Plex Mono

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `ibm-plex-mono-300-normal-latin-ext.woff2` | 300 | latin-ext | 13404 | `40a4c5fb57ace858d7d9f7da764a9104a75976c88fc27f8e957d717e6189938d` |
| `ibm-plex-mono-300-normal-latin.woff2` | 300 | latin | 14748 | `d2ce22595d55a52b0c63f837515729bd97706bfa1b833816509f13d93daa59b5` |
| `ibm-plex-mono-400-normal-latin-ext.woff2` | 400 | latin-ext | 13348 | `6bc0f226a5b7884a8170e3f62c63d7675609d4631bdc5931b5cdab81821f00eb` |
| `ibm-plex-mono-400-normal-latin.woff2` | 400 | latin | 14708 | `08949f728dc52d528e69b1667d15c89a5686a4ee9a296ff90983985f99c380f7` |
| `ibm-plex-mono-500-normal-latin-ext.woff2` | 500 | latin-ext | 13432 | `6bb06407c97584b0867a959e05e8874693bfeb8c317de190811c51598f2d99ea` |
| `ibm-plex-mono-500-normal-latin.woff2` | 500 | latin | 14888 | `01d285447409c8a588692162439a038b8cbd7871309ee20267b0d2d91c6e8e22` |
| `ibm-plex-mono-600-normal-latin-ext.woff2` | 600 | latin-ext | 14328 | `32057cf50dd14bdb21a2c93766c4a2c43e4abe688ea3922df3203cac7751a98b` |
| `ibm-plex-mono-600-normal-latin.woff2` | 600 | latin | 15620 | `0d1f0b8d0722224e32e9f28261bdc86c79115be73444ae5eceb73976a1bcdf83` |

### IBM Plex Sans

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `ibm-plex-sans-300-normal-latin-ext.woff2` | 300 | latin-ext | 30964 | `d160e20920ae4d6556518d352d3af27a74e9b0de3d8fe17b1c1044fc75aa2f81` |
| `ibm-plex-sans-300-normal-latin.woff2` | 300 | latin | 45712 | `e2291e842cf5af167122a22881a740c7f2dda7716f1e8cd76680264f4a859470` |
| `ibm-plex-sans-400-normal-latin-ext.woff2` | 400 | latin-ext | 30964 | `d160e20920ae4d6556518d352d3af27a74e9b0de3d8fe17b1c1044fc75aa2f81` |
| `ibm-plex-sans-400-normal-latin.woff2` | 400 | latin | 45712 | `e2291e842cf5af167122a22881a740c7f2dda7716f1e8cd76680264f4a859470` |
| `ibm-plex-sans-500-normal-latin-ext.woff2` | 500 | latin-ext | 30964 | `d160e20920ae4d6556518d352d3af27a74e9b0de3d8fe17b1c1044fc75aa2f81` |
| `ibm-plex-sans-500-normal-latin.woff2` | 500 | latin | 45712 | `e2291e842cf5af167122a22881a740c7f2dda7716f1e8cd76680264f4a859470` |
| `ibm-plex-sans-600-normal-latin-ext.woff2` | 600 | latin-ext | 30964 | `d160e20920ae4d6556518d352d3af27a74e9b0de3d8fe17b1c1044fc75aa2f81` |
| `ibm-plex-sans-600-normal-latin.woff2` | 600 | latin | 45712 | `e2291e842cf5af167122a22881a740c7f2dda7716f1e8cd76680264f4a859470` |

### Inter

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `inter-300-normal-latin-ext.woff2` | 300 | latin-ext | 85068 | `34b9c504cab7a73e37b746343a449132e56cf7b5481af2cb81dc74dcff25c956` |
| `inter-300-normal-latin.woff2` | 300 | latin | 48256 | `3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62` |
| `inter-400-normal-latin-ext.woff2` | 400 | latin-ext | 85068 | `34b9c504cab7a73e37b746343a449132e56cf7b5481af2cb81dc74dcff25c956` |
| `inter-400-normal-latin.woff2` | 400 | latin | 48256 | `3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62` |
| `inter-500-normal-latin-ext.woff2` | 500 | latin-ext | 85068 | `34b9c504cab7a73e37b746343a449132e56cf7b5481af2cb81dc74dcff25c956` |
| `inter-500-normal-latin.woff2` | 500 | latin | 48256 | `3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62` |
| `inter-600-normal-latin-ext.woff2` | 600 | latin-ext | 85068 | `34b9c504cab7a73e37b746343a449132e56cf7b5481af2cb81dc74dcff25c956` |
| `inter-600-normal-latin.woff2` | 600 | latin | 48256 | `3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62` |
| `inter-700-normal-latin-ext.woff2` | 700 | latin-ext | 85068 | `34b9c504cab7a73e37b746343a449132e56cf7b5481af2cb81dc74dcff25c956` |
| `inter-700-normal-latin.woff2` | 700 | latin | 48256 | `3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62` |

### JetBrains Mono

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `jetbrains-mono-300-normal-latin-ext.woff2` | 300 | latin-ext | 15196 | `79bfdab9ba467e26eea4122e6f2567e188dd8a09a8c730d501fc487c4ab99c6e` |
| `jetbrains-mono-300-normal-latin.woff2` | 300 | latin | 40404 | `18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e` |
| `jetbrains-mono-400-normal-latin-ext.woff2` | 400 | latin-ext | 15196 | `79bfdab9ba467e26eea4122e6f2567e188dd8a09a8c730d501fc487c4ab99c6e` |
| `jetbrains-mono-400-normal-latin.woff2` | 400 | latin | 40404 | `18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e` |
| `jetbrains-mono-500-normal-latin-ext.woff2` | 500 | latin-ext | 15196 | `79bfdab9ba467e26eea4122e6f2567e188dd8a09a8c730d501fc487c4ab99c6e` |
| `jetbrains-mono-500-normal-latin.woff2` | 500 | latin | 40404 | `18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e` |
| `jetbrains-mono-600-normal-latin-ext.woff2` | 600 | latin-ext | 15196 | `79bfdab9ba467e26eea4122e6f2567e188dd8a09a8c730d501fc487c4ab99c6e` |
| `jetbrains-mono-600-normal-latin.woff2` | 600 | latin | 40404 | `18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e` |

### Michroma

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `michroma-400-normal-latin-ext.woff2` | 400 | latin-ext | 14456 | `389fd1a84c8a275eea953ff215a11396982d8091591075733af086b400a9b2c5` |
| `michroma-400-normal-latin.woff2` | 400 | latin | 17908 | `754fdb31c9906e82cf9c0ecb1d0b528073818fc2c418a39932c83a34cca027b6` |

### Orbitron

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `orbitron-500-normal-latin.woff2` | 500 | latin | 11800 | `c25a9f9da5d9f3db1bf2a01474722dc9b377675b7bbab6d0dfda6902794fd1ed` |
| `orbitron-700-normal-latin.woff2` | 700 | latin | 11800 | `c25a9f9da5d9f3db1bf2a01474722dc9b377675b7bbab6d0dfda6902794fd1ed` |
| `orbitron-900-normal-latin.woff2` | 900 | latin | 11800 | `c25a9f9da5d9f3db1bf2a01474722dc9b377675b7bbab6d0dfda6902794fd1ed` |

### Oxanium

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `oxanium-400-normal-latin-ext.woff2` | 400 | latin-ext | 7824 | `75b9254b2437310f3baa788ea6d005d35256cb3e98b2b723fea702f77cd31064` |
| `oxanium-400-normal-latin.woff2` | 400 | latin | 14044 | `3aa555c528430aab19bb2693dc206bab557767d3082dba66400784c9cc90cfbb` |
| `oxanium-500-normal-latin-ext.woff2` | 500 | latin-ext | 7824 | `75b9254b2437310f3baa788ea6d005d35256cb3e98b2b723fea702f77cd31064` |
| `oxanium-500-normal-latin.woff2` | 500 | latin | 14044 | `3aa555c528430aab19bb2693dc206bab557767d3082dba66400784c9cc90cfbb` |
| `oxanium-600-normal-latin-ext.woff2` | 600 | latin-ext | 7824 | `75b9254b2437310f3baa788ea6d005d35256cb3e98b2b723fea702f77cd31064` |
| `oxanium-600-normal-latin.woff2` | 600 | latin | 14044 | `3aa555c528430aab19bb2693dc206bab557767d3082dba66400784c9cc90cfbb` |
| `oxanium-700-normal-latin-ext.woff2` | 700 | latin-ext | 7824 | `75b9254b2437310f3baa788ea6d005d35256cb3e98b2b723fea702f77cd31064` |
| `oxanium-700-normal-latin.woff2` | 700 | latin | 14044 | `3aa555c528430aab19bb2693dc206bab557767d3082dba66400784c9cc90cfbb` |

### Pixelify Sans

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `pixelify-sans-400-normal-latin-ext.woff2` | 400 | latin-ext | 8208 | `0afa0101fd8c5892b1661f7561564c98f0aa13ef2d6609809d477820c4bc6c89` |
| `pixelify-sans-400-normal-latin.woff2` | 400 | latin | 12016 | `4a5633a0c9c1b73abd133a56d3716c2d8df2ed03cb987346f72194aeb224f382` |
| `pixelify-sans-600-normal-latin-ext.woff2` | 600 | latin-ext | 8208 | `0afa0101fd8c5892b1661f7561564c98f0aa13ef2d6609809d477820c4bc6c89` |
| `pixelify-sans-600-normal-latin.woff2` | 600 | latin | 12016 | `4a5633a0c9c1b73abd133a56d3716c2d8df2ed03cb987346f72194aeb224f382` |

### Press Start 2P

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `press-start-2p-400-normal-latin-ext.woff2` | 400 | latin-ext | 9856 | `3c7df3a15e173b8fa04ec9191171e72c314ddbac1b395e2b2e2092bb4f47cc8c` |
| `press-start-2p-400-normal-latin.woff2` | 400 | latin | 12512 | `afec86997fdaf54af1f59358fa2c1e2a0f1d04146edad18e5cd141d0384a7548` |

### Rajdhani

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `rajdhani-400-normal-latin-ext.woff2` | 400 | latin-ext | 12388 | `90721cae01bf677b419b28fec9896e50923c9e956817b85f4b6ab1e5ad028a56` |
| `rajdhani-400-normal-latin.woff2` | 400 | latin | 14976 | `759a9000e47b028799d7a4ca602634a7ac7adf415775df070a335d18d9b66f38` |
| `rajdhani-500-normal-latin-ext.woff2` | 500 | latin-ext | 12380 | `16fd373954f7569ad294444531caa2e7e5ffd1a6798c6df3f56b9faf691190c2` |
| `rajdhani-500-normal-latin.woff2` | 500 | latin | 15084 | `23afdb9b5b89b878fab04d80cc30bf41bb4f3f7e8be88e5f16a7cc7671cdb2dc` |
| `rajdhani-600-normal-latin-ext.woff2` | 600 | latin-ext | 13124 | `f57c2b379ba92460d25730ef1f7b8745afb4eadb401d652900f2059f8ee2f2b6` |
| `rajdhani-600-normal-latin.woff2` | 600 | latin | 15732 | `433a7007e4747a02a790167a6efa2625855f013970ba49b9b739a5d3db8b2601` |
| `rajdhani-700-normal-latin-ext.woff2` | 700 | latin-ext | 12964 | `c6b9df58743ccca1236e9521720b135138309bc4149d5d027a9bd10183cc8ed5` |
| `rajdhani-700-normal-latin.woff2` | 700 | latin | 15688 | `5b7e4a6f97163c2636724d4de90304fc895653dcfe64c67a7a22f26331ca5c5f` |

### Roboto Mono

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `roboto-mono-300-normal-latin-ext.woff2` | 300 | latin-ext | 22916 | `4cc0d52e0fa37c28084e0cbce3589a8ab32dd21e6ea619489c5f7c6e8c43b922` |
| `roboto-mono-300-normal-latin.woff2` | 300 | latin | 32796 | `b81cd55177300649be8f95b3b747d721ce607e8ed2856e25bd0c630cfd631faf` |
| `roboto-mono-400-normal-latin-ext.woff2` | 400 | latin-ext | 22916 | `4cc0d52e0fa37c28084e0cbce3589a8ab32dd21e6ea619489c5f7c6e8c43b922` |
| `roboto-mono-400-normal-latin.woff2` | 400 | latin | 32796 | `b81cd55177300649be8f95b3b747d721ce607e8ed2856e25bd0c630cfd631faf` |
| `roboto-mono-500-normal-latin-ext.woff2` | 500 | latin-ext | 22916 | `4cc0d52e0fa37c28084e0cbce3589a8ab32dd21e6ea619489c5f7c6e8c43b922` |
| `roboto-mono-500-normal-latin.woff2` | 500 | latin | 32796 | `b81cd55177300649be8f95b3b747d721ce607e8ed2856e25bd0c630cfd631faf` |

### Share Tech Mono

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `share-tech-mono-400-normal-latin.woff2` | 400 | latin | 13500 | `41e6b9f297f7d9a2df2aaa274092f76d2f72711a15ca455f7f4f4f92caf16b72` |

### Silkscreen

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `silkscreen-400-normal-latin-ext.woff2` | 400 | latin-ext | 3436 | `1006c6fc608892267eebc2a4d5ab4d3c1f56bc1f86cbe1615b521993bca8c375` |
| `silkscreen-400-normal-latin.woff2` | 400 | latin | 8404 | `e6c72ea4702249202bcdd79d3343057e4e25ef1f04e3fcffd8602ab53b40b4cc` |
| `silkscreen-700-normal-latin-ext.woff2` | 700 | latin-ext | 3320 | `6d5c5a2fd0123c36c6a963e826728bbb49d2a65556c58042671d71d4f8bc567c` |
| `silkscreen-700-normal-latin.woff2` | 700 | latin | 7524 | `5741b7f01a127f40ed70281fa2f686e8fc2cfe241930a120e4d1a1cebe78f995` |

### Space Mono

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `space-mono-400-normal-latin-ext.woff2` | 400 | latin-ext | 15832 | `44ad50c760fa8f5b62da3d489edb40adebabaf97988b9b0adbbc3f0be859050a` |
| `space-mono-400-normal-latin.woff2` | 400 | latin | 16520 | `fb4a81a2d0a893e5c38c394a7e716a1cef0b24610a0af49c96f6d529bd66bf2b` |
| `space-mono-700-normal-latin-ext.woff2` | 700 | latin-ext | 15808 | `52edd9a8959ec3e68d618e2a4757182c0e61bfeea61679850cad8744a68cadf3` |
| `space-mono-700-normal-latin.woff2` | 700 | latin | 16724 | `2d46bd159b53f55c41167a4f1540a074649464194fd1e416f5b4694a6c0f282c` |

### VT323

| File | Weight | Subset | Bytes | SHA-256 |
|---|---|---|---|---|
| `vt323-400-normal-latin-ext.woff2` | 400 | latin-ext | 16372 | `4435f062ebe744d097d0d618ac5ad6b8ea25ee3bd6004c5369c24518e70af1f0` |
| `vt323-400-normal-latin.woff2` | 400 | latin | 17936 | `8ddbebcc1048154132e1d78eb9b1f7850bca1b7d857035ccf1cb4318ebc615b6` |

**Total:** 92 files, 2335496 bytes (2280 KiB).
