# CHANGELOG

<!-- version list -->

## v1.7.0 (2026-05-31)

### Chores

- Adjusting demo ([#51](https://github.com/flaviomilan/fackel/pull/51),
  [`a55ff86`](https://github.com/flaviomilan/fackel/commit/a55ff865cdb78523306b22cf305a85cf5f3f8338))

### Features

- Add 6 passive OSINT tools + RoE scope + eval harness
  ([#52](https://github.com/flaviomilan/fackel/pull/52),
  [`dd2589c`](https://github.com/flaviomilan/fackel/commit/dd2589c9d194735d70ab823a0ed764e195db86e3))


## v1.6.0 (2026-05-31)

### Chores

- **deps**: Bump aiohttp from 3.13.3 to 3.13.4
  ([#23](https://github.com/flaviomilan/fackel/pull/23),
  [`80008f9`](https://github.com/flaviomilan/fackel/commit/80008f9a672b3a4427afec93b731641beedc9feb))

- **deps**: Bump langchain-core from 1.2.16 to 1.2.22
  ([#21](https://github.com/flaviomilan/fackel/pull/21),
  [`d8feee9`](https://github.com/flaviomilan/fackel/commit/d8feee98860fafa1278a8375dd12ea52dd385ee6))

- **deps**: Bump langchain-core from 1.2.22 to 1.2.28
  ([#24](https://github.com/flaviomilan/fackel/pull/24),
  [`60d0d03`](https://github.com/flaviomilan/fackel/commit/60d0d03ade260ffa1e1adb7c73bddb45f7acf468))

- **deps**: Bump pygments from 2.19.2 to 2.20.0
  ([#22](https://github.com/flaviomilan/fackel/pull/22),
  [`4191add`](https://github.com/flaviomilan/fackel/commit/4191add3a53e00e0e7ed3139e83f0106d9f31a73))

- **deps**: Bump pytest from 9.0.2 to 9.0.3 ([#35](https://github.com/flaviomilan/fackel/pull/35),
  [`527b12c`](https://github.com/flaviomilan/fackel/commit/527b12cb5d5cb231b5e79fa5b06873410305a9ae))

- **deps**: Bump requests from 2.32.5 to 2.33.0
  ([#20](https://github.com/flaviomilan/fackel/pull/20),
  [`b67daf6`](https://github.com/flaviomilan/fackel/commit/b67daf6add42c2fa72251d01c802b56c53b1fe82))

### Features

- Adding improvements on structure, agents and harness
  ([#50](https://github.com/flaviomilan/fackel/pull/50),
  [`73a3650`](https://github.com/flaviomilan/fackel/commit/73a3650741b20793c285ee03807eef7dc397596e))


## v1.5.1 (2026-03-21)

### Bug Fixes

- **scripts**: Escape virtualenv in python clone tool wrappers
  ([`d4ce3e9`](https://github.com/flaviomilan/fackel/commit/d4ce3e930adf99090236f5ca8f7ac61b75a59863))


## v1.5.0 (2026-03-09)

### Chores

- **lint**: Resolve ruff violations across src and tests
  ([`e3e91e7`](https://github.com/flaviomilan/fackel/commit/e3e91e7d739b4f98ffa82ec77add6845dd4953f1))

### Features

- **orchestrator**: Wire new tools into audit pipeline
  ([`3b32d8c`](https://github.com/flaviomilan/fackel/commit/3b32d8c0bc99b417add9c7c5d5d9c6f30542a8b5))

- **recon**: Expand osint collectors and secret scanning
  ([`22f5686`](https://github.com/flaviomilan/fackel/commit/22f56865b3c75ec14276059904e802e9a3dd3ae9))

- **scanning**: Add ffuf support and improve web scanners
  ([`9b50d7a`](https://github.com/flaviomilan/fackel/commit/9b50d7a4f394034da4a66c22dfe42c2d3daf1267))

- **vuln**: Introduce jwt and web vuln analyzers
  ([`2ecddf0`](https://github.com/flaviomilan/fackel/commit/2ecddf0f74d4fb3abf4ad96ef8e0d926561a58f0))

### Refactoring

- **prompts**: Migrate prompt packs and update agent bindings
  ([`f87ead9`](https://github.com/flaviomilan/fackel/commit/f87ead9de04a5978465192fe622065cf5f90c95d))


## v1.4.0 (2026-03-02)

### Bug Fixes

- **tools**: Remove CLI args that create spurious '-' and 'json' files
  ([`3173bbb`](https://github.com/flaviomilan/fackel/commit/3173bbb75a26d34ad5d9f4c9162fbed3c9410de8))

### Chores

- Remove spurious files - and json from repository root
  ([`980cab6`](https://github.com/flaviomilan/fackel/commit/980cab6607aec93a1b002c52505acd0e82635e9c))

### Documentation

- Dockerfile, CONTRIBUTING.md, and configuration reference updates
  ([`a2edeae`](https://github.com/flaviomilan/fackel/commit/a2edeaea267825994bf23bb6472df8b87bd86315))

### Features

- Centralized settings, DNS rebinding protection, secret redaction, graceful shutdown
  ([`c0f3eab`](https://github.com/flaviomilan/fackel/commit/c0f3eab7934601c8fdd2e13299d9e97aa06ff12e))

- Remove comments
  ([`082793d`](https://github.com/flaviomilan/fackel/commit/082793df86c3d390b17bc676eef2da855ef4abb6))

- Security hardening and operational improvements
  ([`726768f`](https://github.com/flaviomilan/fackel/commit/726768fe5fbca338cb53f9e1b18bffb96082c590))

### Refactoring

- Relocate infrastructure modules, reorganize tests, eliminate side effects
  ([`f146c6f`](https://github.com/flaviomilan/fackel/commit/f146c6f4d85cc6417a62c96840ecc132ec969300))

- **tests**: Clean up test_security_improvements
  ([`6f006a0`](https://github.com/flaviomilan/fackel/commit/6f006a0a09f2a45fde50e3e0d6784094a7fbca0d))


## v1.3.1 (2026-02-26)

### Bug Fixes

- Files
  ([`379fa1e`](https://github.com/flaviomilan/fackel/commit/379fa1e6562ad13a30506bcb966681d09c3da0d9))


## v1.3.0 (2026-02-26)

### Bug Fixes

- Files
  ([`d76c92b`](https://github.com/flaviomilan/fackel/commit/d76c92bf75adc4a0b4b784ae95a9d36847c753ef))

### Features

- Adding more tools
  ([`8ff03e8`](https://github.com/flaviomilan/fackel/commit/8ff03e8983d9005e6a0120f7a0a5911f96fdefd4))


## v1.2.0 (2026-02-26)

### Chores

- Remove unused code
  ([`7f51cf2`](https://github.com/flaviomilan/fackel/commit/7f51cf23a8db7c9fbab6ce87089add3553b8f61a))

### Features

- Adding new tools
  ([`d5509f5`](https://github.com/flaviomilan/fackel/commit/d5509f56f660786125be756de586053bb45b76f3))


## v1.1.0 (2026-02-26)

### Bug Fixes

- Pipeline
  ([`d0a1dff`](https://github.com/flaviomilan/fackel/commit/d0a1dff5dd4102c34b4e327643f2e8fbcc6a2f55))

### Features

- Git hooks and fixes
  ([`e8c52e6`](https://github.com/flaviomilan/fackel/commit/e8c52e677e72117af300f011e2841110e64cb43f))


## v1.0.0 (2026-02-25)

- Initial Release
