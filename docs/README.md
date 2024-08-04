# Introduction
This project is an experiment of different pattern detection methods, serving as a review of a selection of techniques 
to detect patterns such as digital secrets (API Keys, Credentials, Tokens etc.).

## Parsers

| detection method                                   | description                                                                                  |
|-------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| [winnow](https://docs.rs/winnow/latest/winnow/index.html)   | parser combinator library, fork of [nom](https://docs.rs/nom/latest/nom/#)                   |
| [pest](https://docs.rs/pest/latest/pest/)                   | [PEG grammar](https://en.wikipedia.org/wiki/Parsing_expression_grammar) parsing library      |
| [vectorscan](https://docs.rs/vectorscan/latest/vectorscan/) | open source, cross-platform fork of [hyperscan](https://docs.rs/hyperscan/latest/hyperscan/) |