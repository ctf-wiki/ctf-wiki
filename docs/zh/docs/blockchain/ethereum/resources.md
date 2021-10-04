# 学习资源

## Books
- 《以太坊技术详解与实战》-- 以太坊创始人、首席科学家 Vitalik Buterin 倾力推荐
- 待补充

## papers
- 智能合约 [https://github.com/hzysvilla/Academic_Smart_Contract_Papers](https://github.com/hzysvilla/Academic_Smart_Contract_Papers)
- 区块链（包括智能合约）[https://github.com/jianyu-niu/blockchain_conference_paper](https://github.com/jianyu-niu/blockchain_conference_paper)
- 待补充

## Security Tools

> 搬运自 [https://consensys.github.io/smart-contract-best-practices/security_tools/](https://consensys.github.io/smart-contract-best-practices/security_tools/)

### Visualization

- [Solidity Visual Auditor](https://marketplace.visualstudio.com/items?itemName=tintinweb.solidity-visual-auditor) - This extension contributes security centric syntax and semantic highlighting, a detailed class outline and advanced Solidity code insights to Visual Studio Code
- [Sūrya](https://github.com/ConsenSys/surya) - Utility tool for smart contract systems, offering a number of visual outputs and information about the contracts' structure. Also supports querying the function call graph.
- [Solgraph](https://github.com/raineorshine/solgraph) - Generates a DOT graph that visualizes function control flow of a Solidity contract and highlights potential security vulnerabilities.
- [EVM Lab](https://github.com/ethereum/evmlab) - Rich tool package to interact with the EVM. Includes a VM, Etherchain API, and a trace-viewer.
- [ethereum-graph-debugger](https://github.com/fergarrui/ethereum-graph-debugger) - A graphical EVM debugger. Displays the entire program control flow graph.
- [Piet](https://github.com/slockit/piet) - Web application helping understand smart contract architectures. Offers graphical representation and inspection of smart contracts as well as a markdown documentation generator.

### Static and Dynamic Analysis

- [MythX](https://mythx.io) - MythX is a professional-grade cloud service that uses symbolic analysis and input fuzzing to [detect common security bugs](https://medium.com/consensys-diligence/detecting-the-top-4-critical-smart-contract-vulnerabilities-with-mythx-9c568d7db7a6) and [verify the correctness of smart contract code](https://medium.com/coinmonks/advanced-smart-contract-security-verification-in-remix-9630b43695e5). Using MythX requires an API key from [mythx.io](https://mythx.io).
- [Mythril](https://github.com/ConsenSys/mythril) - The Swiss army knife for smart contract security.
- [Slither](https://github.com/trailofbits/slither) - Static analysis framework with detectors for many common Solidity issues. It has taint and value tracking capabilities and is written in Python.
- [Contract-Library](https://contract-library.com) - Decompiler and security analysis tool for all deployed contracts.
- [Echidna](https://github.com/trailofbits/echidna) - The only available fuzzer for Ethereum software. Uses property testing to generate malicious inputs that break smart contracts.
- [Manticore](https://github.com/trailofbits/manticore) - Dynamic binary analysis tool with [EVM support](https://asciinema.org/a/haJU2cl0R0Q3jB9wd733LVosL).
- [Oyente](https://github.com/melonproject/oyente) - Analyze Ethereum code to find common vulnerabilities, based on this [paper](http://www.comp.nus.edu.sg/~loiluu/papers/oyente.pdf).
- [Securify](https://github.com/eth-sri/securify2) - Fully automated online static analyzer for smart contracts, providing a security report based on vulnerability patterns.
- [SmartCheck](https://tool.smartdec.net) - Static analysis of Solidity source code for security vulnerabilities and best practices.
- [Octopus](https://github.com/quoscient/octopus) - Security Analysis tool for Blockchain Smart Contracts with support of EVM and (e)WASM.
- [sFuzz](https://sfuzz.github.io/) - Efficient fuzzer inspired from AFL to find common vulnerabilities.
- [Vertigo](https://github.com/JoranHonig/vertigo) - Mutation Testing for Ethereum Smart Contracts.

### Weakness OSSClassifcation & Test Cases

- [SWC-registry](https://github.com/SmartContractSecurity/SWC-registry/) - SWC definitions and a large repository of crafted and real-world samples of vulnerable smart contracts.
- [SWC Pages](https://smartcontractsecurity.github.io/SWC-registry/) - The SWC-registry repo published on Github Pages

### Test Coverage

- [solidity-coverage](https://github.com/sc-forks/solidity-coverage) - Code coverage for Solidity testing.

### Linters and Formatters

Linters improve code quality by enforcing rules for style and composition, making code easier to read and review.

- [Ethlint](https://github.com/duaraghav8/Ethlint) - Yet another Solidity linting.
- [Solhint](https://github.com/protofire/solhint) - A linter for Solidity that provides both Security and Style Guide validations.
- [Prettier](https://prettier.io/) + [Solidity Plugin](https://github.com/prettier-solidity/prettier-plugin-solidity) - Prettier enforces basic style conventions in your code.