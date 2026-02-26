# Changelog

## [0.2.1](https://github.com/verana-labs/verre/compare/v0.2.0...v0.2.1) (2026-02-26)


### Bug Fixes

* signature validation ([#77](https://github.com/verana-labs/verre/issues/77)) ([6c97c7a](https://github.com/verana-labs/verre/commit/6c97c7a5648681427079faec24d0a9f46b5e6297))

## [0.2.0](https://github.com/verana-labs/verre/compare/v0.1.1...v0.2.0) (2026-02-25)


### ⚠ BREAKING CHANGES

* replace Credo Suite with singleton cached resolver for improved performance ([#72](https://github.com/verana-labs/verre/issues/72))

### Features

* replace Credo Suite with singleton cached resolver for improved performance ([#72](https://github.com/verana-labs/verre/issues/72)) ([aa6bebf](https://github.com/verana-labs/verre/commit/aa6bebf3398b51dea9b840661657972709cbc6b9))

## [0.1.1](https://github.com/verana-labs/verre/compare/v0.1.0...v0.1.1) (2026-02-24)


### Bug Fixes

* use effectiveFrom and effective_until to verifyPermission ([#70](https://github.com/verana-labs/verre/issues/70)) ([3108c41](https://github.com/verana-labs/verre/commit/3108c4175871d699d31599c7105ecc1dd34827a3))

## [0.1.0](https://github.com/verana-labs/verre/compare/v0.0.16...v0.1.0) (2026-02-20)


### ⚠ BREAKING CHANGES

* digestSRI calculation ([#59](https://github.com/verana-labs/verre/issues/59))
* replace verifyIssuerPermissions by verifyPermissions function ([#66](https://github.com/verana-labs/verre/issues/66))

### Features

* add logger setup ([#65](https://github.com/verana-labs/verre/issues/65)) ([e3558d8](https://github.com/verana-labs/verre/commit/e3558d85eb101ea7df1efcad95ce7fbe84c0b674))
* add skipDigestSRICheck flag to avoid digest validation ([#64](https://github.com/verana-labs/verre/issues/64)) ([4192a1a](https://github.com/verana-labs/verre/commit/4192a1aba625236c0b6e4276c2dd2e9651d10c55))
* optional credential verification reusage via cache ([#54](https://github.com/verana-labs/verre/issues/54)) ([aba8be2](https://github.com/verana-labs/verre/commit/aba8be29188c98bd3c29ef11b7dd123a699809f5))
* replace verifyIssuerPermissions by verifyPermissions function ([#66](https://github.com/verana-labs/verre/issues/66)) ([c3b2fca](https://github.com/verana-labs/verre/commit/c3b2fca2711a3d98ada4c30caaceeb6f507b3d0a))


### Bug Fixes

* digestSRI calculation ([#59](https://github.com/verana-labs/verre/issues/59)) ([a3bc726](https://github.com/verana-labs/verre/commit/a3bc726686f1e8b6bca0d1611f444e51227a8b77))
* remove getWebDid due legacy did support ([#55](https://github.com/verana-labs/verre/issues/55)) ([15c57a1](https://github.com/verana-labs/verre/commit/15c57a1b8519cf6513c4522f00b57dcfeb4b8044))

## [0.1.0](https://github.com/verana-labs/verre/compare/v0.0.16...v0.1.0) (2026-02-19)


### ⚠ BREAKING CHANGES

* digestSRI calculation ([#59](https://github.com/verana-labs/verre/issues/59))
* replace verifyIssuerPermissions by verifyPermissions function ([#66](https://github.com/verana-labs/verre/issues/66))

### Features

* add logger setup ([#65](https://github.com/verana-labs/verre/issues/65)) ([e3558d8](https://github.com/verana-labs/verre/commit/e3558d85eb101ea7df1efcad95ce7fbe84c0b674))
* add skipDigestSRICheck flag to avoid digest validation ([#64](https://github.com/verana-labs/verre/issues/64)) ([4192a1a](https://github.com/verana-labs/verre/commit/4192a1aba625236c0b6e4276c2dd2e9651d10c55))
* optional credential verification reusage via cache ([#54](https://github.com/verana-labs/verre/issues/54)) ([aba8be2](https://github.com/verana-labs/verre/commit/aba8be29188c98bd3c29ef11b7dd123a699809f5))
* replace verifyIssuerPermissions by verifyPermissions function ([#66](https://github.com/verana-labs/verre/issues/66)) ([c3b2fca](https://github.com/verana-labs/verre/commit/c3b2fca2711a3d98ada4c30caaceeb6f507b3d0a))


### Bug Fixes

* digestSRI calculation ([#59](https://github.com/verana-labs/verre/issues/59)) ([a3bc726](https://github.com/verana-labs/verre/commit/a3bc726686f1e8b6bca0d1611f444e51227a8b77))
* remove getWebDid due legacy did support ([#55](https://github.com/verana-labs/verre/issues/55)) ([15c57a1](https://github.com/verana-labs/verre/commit/15c57a1b8519cf6513c4522f00b57dcfeb4b8044))

## [0.0.16](https://github.com/verana-labs/verre/compare/v0.0.15...v0.0.16) (2025-11-24)


### Features

* Enhance trust-chain resolution and add permission checks ([#45](https://github.com/verana-labs/verre/issues/45)) ([fb1e04d](https://github.com/verana-labs/verre/commit/fb1e04df2a512555c4442d2a6d13130debc16194))


### Bug Fixes

* add validation logic for verifiablePublicRegistries and improve error handling in resolveCredential ([#48](https://github.com/verana-labs/verre/issues/48)) ([71b9935](https://github.com/verana-labs/verre/commit/71b9935926ca6b828e8dcb235050e100275bcd41))
* allow vpr-ecs for essential esquemas ([#40](https://github.com/verana-labs/verre/issues/40)) ([48dbe32](https://github.com/verana-labs/verre/commit/48dbe32448a8f7470ed38a365d2859756e828a17))
* Implement check issuer vt service ([#46](https://github.com/verana-labs/verre/issues/46)) ([db59946](https://github.com/verana-labs/verre/commit/db59946b4ae31590569e37f2c9f169be461eaf0a))

## [0.0.15](https://github.com/verana-labs/verre/compare/v0.0.14...v0.0.15) (2025-09-03)


### Bug Fixes

* proof purpose in verifiable presentations ([#37](https://github.com/verana-labs/verre/issues/37)) ([f7cc8c5](https://github.com/verana-labs/verre/commit/f7cc8c56ea134d78998b7bfb724cda1a3ec1c8f5))

## [0.0.14](https://github.com/verana-labs/verre/compare/v0.0.13...v0.0.14) (2025-08-29)


### Bug Fixes

* perform resolution only on relevant linked vp services ([#35](https://github.com/verana-labs/verre/issues/35)) ([dd28ab8](https://github.com/verana-labs/verre/commit/dd28ab8a53c66a44cc79192c27b33c8d5a62d90e))

## [0.0.13](https://github.com/verana-labs/verre/compare/v0.0.12...v0.0.13) (2025-08-14)


### Features

* add verifiable registry support for known networks with trust status outcome ([#30](https://github.com/verana-labs/verre/issues/30)) ([4c83479](https://github.com/verana-labs/verre/commit/4c834798846439718eb816281156a00cc22a9660))
* use credo resolver by default ([#31](https://github.com/verana-labs/verre/issues/31)) ([6f48f30](https://github.com/verana-labs/verre/commit/6f48f3066fb25144cac2941b354febfbc03ba17e))

## [0.0.12](https://github.com/verana-labs/verre/compare/v0.0.11...v0.0.12) (2025-08-04)


### Features

* add verifyDidAuthorization method ([#27](https://github.com/verana-labs/verre/issues/27)) ([4dd6a91](https://github.com/verana-labs/verre/commit/4dd6a91e5a401b293be3542ad337cdc5aaca5400))

## [0.0.11](https://github.com/verana-labs/verre/compare/v0.0.10...v0.0.11) (2025-07-28)


### Features

* add integration tests and improve schema validation & debugging ([#23](https://github.com/verana-labs/verre/issues/23)) ([48c976b](https://github.com/verana-labs/verre/commit/48c976bc0834d5ce90c5a8808239d017d60ccce1))

## [0.0.10](https://github.com/verana-labs/verre/compare/v0.0.9...v0.0.10) (2025-07-03)


### Features

* update interface output structure and testing ([#17](https://github.com/verana-labs/verre/issues/17)) ([70c08d4](https://github.com/verana-labs/verre/commit/70c08d4875bd6f52ada762a022ef663cb392ec90))

## [0.0.9](https://github.com/verana-labs/verre/compare/v0.0.8...v0.0.9) (2025-07-01)


### Bug Fixes

* Make agentContext a mandatory parameter in DID resolver options ([#14](https://github.com/verana-labs/verre/issues/14)) ([ffdcf94](https://github.com/verana-labs/verre/commit/ffdcf94c8fc68b384b42ead393f08532fcb3f928))

## [0.0.8](https://github.com/verana-labs/verre/compare/v0.0.7...v0.0.8) (2025-06-27)


### Bug Fixes

* add suite signature ([#12](https://github.com/verana-labs/verre/issues/12)) ([24b559c](https://github.com/verana-labs/verre/commit/24b559c03c706738cb3b57641b35206beba9a0ca))

## [0.0.7](https://github.com/verana-labs/verre/compare/v0.0.6...v0.0.7) (2025-06-27)


### Bug Fixes

* make hash compatible with react native ([#9](https://github.com/verana-labs/verre/issues/9)) ([08b6494](https://github.com/verana-labs/verre/commit/08b6494024efb2c37debd0941d31f8808f9acabd))

## [0.0.6](https://github.com/verana-labs/verre/compare/v0.0.5...v0.0.6) (2025-06-26)


### Bug Fixes

* improvement according specs and first deploy ([#6](https://github.com/verana-labs/verre/issues/6)) ([bd6e6fc](https://github.com/verana-labs/verre/commit/bd6e6fc4c52e76f6d399bc61093c88b2ca5c1a2c))

## [0.0.5](https://github.com/verana-labs/verre/compare/v0.0.4...v0.0.5) (2025-06-25)


### Bug Fixes

* improvement package for support cjs oon library ([#5](https://github.com/verana-labs/verre/issues/5)) ([c589d84](https://github.com/verana-labs/verre/commit/c589d84f46c3b0d90b28ec8698ce638e2e718a76))

## [0.0.4](https://github.com/verana-labs/verre/compare/v0.0.3...v0.0.4) (2025-06-25)


### Bug Fixes

* setup npm token for pnpm ([7e02701](https://github.com/verana-labs/verre/commit/7e027011a34a080106df24fdf1cda2c4edd2f95d))

## [0.0.3](https://github.com/verana-labs/verre/compare/v0.0.2...v0.0.3) (2025-06-25)


### Bug Fixes

* ci npm token variable name ([7f3a94b](https://github.com/verana-labs/verre/commit/7f3a94b0bf8de58fb200b3644c7a5d21aaf45de7))

## [0.0.2](https://github.com/verana-labs/verre/compare/v0.0.1...v0.0.2) (2025-06-25)


### Features

* initial validation ([#1](https://github.com/verana-labs/verre/issues/1)) ([28c809a](https://github.com/verana-labs/verre/commit/28c809add1d163810f22f20d55606dacea77e340))


### Bug Fixes

* ci permission an test data ([3d32d96](https://github.com/verana-labs/verre/commit/3d32d96471e3dfc44bf14621c95630f365094958))
