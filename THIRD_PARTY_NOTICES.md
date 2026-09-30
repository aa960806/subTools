# toSub2

Source: https://github.com/poxiao33/toSub2

Revision: `8548397e89bf80e508eda64a87e0d556d43abc84` (v1.7.1; checked against remote HEAD on 2026-09-28).

`phone_price_catalog.py` adapts the country/price normalization in `src/smsbower.mjs` to Python. `phone_smsbower.py` uses its read-only `getPrices` + `getCountries` discovery approach, while retaining this tool's V3 allocation, budget checks and order lifecycle.

Other additions are local implementations informed by upstream source: structured input fields (`src/console-server.mjs`), selected-account actions (`web/src/main.jsx`), task history and periodic inspection scheduling (`src/console-server.mjs`). They reuse the existing Tk UI, DPAPI journals and Playwright workflow. Upstream Node servers, automatic account repair, plaintext browser checkpoints and protocol-login implementations are not dependencies of this tool.

MIT License

Copyright (c) 2026 poxiao33

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
