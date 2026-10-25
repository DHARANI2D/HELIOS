`oleform-PR314.docm` is a benign test document from oletools 0.60.2
(`tests/test-data/oleform/`), saved by Microsoft Word, used here as a real
VBA project. oletools is © Philippe Lagadec and contributors, BSD 2-Clause
licence (https://github.com/decalage2/oletools).

`oleform-PR314.olevba.json` is what oletools' `olevba` extracts from it
(`VBA_Parser.extract_macros()`, CRLF normalized to LF) — the reference the
macro reader is checked against.
