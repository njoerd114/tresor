# Changelog

## [0.4.1](https://github.com/njoerd114/tresor/compare/v0.4.0...v0.4.1) (2026-10-15)


### Build

* **packaging:** auto-sync Homebrew formula, scoop and AUR pins ([#41](https://github.com/njoerd114/tresor/issues/41)) ([45374a3](https://github.com/njoerd114/tresor/commit/45374a32fa66b25301d5b125692c12b852fc3781))

## [0.4.0](https://github.com/njoerd114/tresor/compare/v0.3.0...v0.4.0) (2026-10-14)


### Features

* acl policy browsing with external editor handoff ([#27](https://github.com/njoerd114/tresor/issues/27)) ([fe36f9b](https://github.com/njoerd114/tresor/commit/fe36f9b382f8e3568d3ca622ec5b0c396747f8b3))
* add contexts/profiles (:ctx) and fuzzy filter (/) ([#29](https://github.com/njoerd114/tresor/issues/29)) ([f795663](https://github.com/njoerd114/tresor/commit/f79566300cdb2c8a30e6a31bf9e7a6fa49389fd4))
* **token:** add token inspector with renew-self, child tokens, and wrapping ([#28](https://github.com/njoerd114/tresor/issues/28)) ([e2b024c](https://github.com/njoerd114/tresor/commit/e2b024cf6264a63d71244298f887c42ae2c7e805))


### Bug Fixes

* **deps:** update rust crate base64 to 0.23 ([#37](https://github.com/njoerd114/tresor/issues/37)) ([7f81099](https://github.com/njoerd114/tresor/commit/7f81099a5b541f73787d2f30f70924d0517e158a))


### Build

* **deps:** bump actions/checkout from 4 to 7 ([#35](https://github.com/njoerd114/tresor/issues/35)) ([4e8f3ce](https://github.com/njoerd114/tresor/commit/4e8f3cec47a92450cce2e94a3ccf71308f80b259))
* **deps:** bump actions/download-artifact from 4 to 8 ([#32](https://github.com/njoerd114/tresor/issues/32)) ([b2e09a1](https://github.com/njoerd114/tresor/commit/b2e09a10c50e1269a94b8521dfbe2393fddb3cf5))
* **deps:** bump actions/upload-artifact from 4 to 7 ([#33](https://github.com/njoerd114/tresor/issues/33)) ([adb1613](https://github.com/njoerd114/tresor/commit/adb1613d27e45ab0967053b2d55221b4249a497f))
* **deps:** bump amannn/action-semantic-pull-request from 5 to 6 ([#34](https://github.com/njoerd114/tresor/issues/34)) ([27b428e](https://github.com/njoerd114/tresor/commit/27b428e935fc8fe950b062f82ab76942e5920be6))
* **deps:** bump googleapis/release-please-action from 4 to 5 ([#31](https://github.com/njoerd114/tresor/issues/31)) ([3e5ee3f](https://github.com/njoerd114/tresor/commit/3e5ee3f3f98e6f3703afbfc08f741843bcbf8243))
* **deps:** bump toml from 0.9.12+spec-1.1.0 to 1.1.8+spec-1.1.0 ([#26](https://github.com/njoerd114/tresor/issues/26)) ([933b0b8](https://github.com/njoerd114/tresor/commit/933b0b803b88cc77b7cf246842377fe4ed41343e))

## [0.3.0](https://github.com/njoerd114/tresor/compare/v0.2.0...v0.3.0) (2026-10-13)


### Features

* initial release of tresor — k9s-style Vault/OpenBao TUI ([33f1932](https://github.com/njoerd114/tresor/commit/33f1932acb62cb1b00ed2aa658ef5d3da3d7aff9))


### Bug Fixes

* **ci:** build and attach release binaries inside the release-please run ([#19](https://github.com/njoerd114/tresor/issues/19)) ([ed60fcd](https://github.com/njoerd114/tresor/commit/ed60fcde487a0dd9ee64bbb6425e8b6e2e3f8302))
* **ci:** install nfpm via go install; emit plain vX.Y.Z tags ([#21](https://github.com/njoerd114/tresor/issues/21)) ([4677dcc](https://github.com/njoerd114/tresor/commit/4677dcceee152e79bbfeffb0e742271b978e9a42))
* **ci:** replace release-plz with release-please (tag-driven, no crates.io) ([#17](https://github.com/njoerd114/tresor/issues/17)) ([4fc2237](https://github.com/njoerd114/tresor/commit/4fc2237b8a589ccb4e0fdbfd6023aa86dac2e21d))
* **deps:** complete the ratatui 0.30 / crossterm 0.29 upgrade ([#25](https://github.com/njoerd114/tresor/issues/25)) ([17bbcd7](https://github.com/njoerd114/tresor/commit/17bbcd7d72f91e338eae0406f4a374867c2c1edf))
* **deps:** repair main after Renovate bumps; land CLI, CI and packaging fixes ([#16](https://github.com/njoerd114/tresor/issues/16)) ([bfed051](https://github.com/njoerd114/tresor/commit/bfed051e45825e53e2ea8fd9ccc51ffaff6f6797))
* **deps:** update rust crate crossterm to 0.29 ([e0dfc6f](https://github.com/njoerd114/tresor/commit/e0dfc6f7e80a0e39e88cd780bf5b056724b110c0))
* **deps:** update rust crate crossterm to 0.29 ([60908cf](https://github.com/njoerd114/tresor/commit/60908cf9337e4be4b179c167341a7b0a1ce0067e))
* **deps:** update rust crate ratatui to 0.30 ([d75d793](https://github.com/njoerd114/tresor/commit/d75d79395b60a941a001f86ac487e1b0cd296694))
* **deps:** update rust crate ratatui to 0.30 ([85756b5](https://github.com/njoerd114/tresor/commit/85756b59e17fb8bbc25a3295df973b4134320d20))
* **deps:** update rust crate reqwest to 0.13 ([f4c2ef0](https://github.com/njoerd114/tresor/commit/f4c2ef01cb47669dd01e4b383a40c50cecc69096))
* **deps:** update rust crate reqwest to 0.13 ([1634813](https://github.com/njoerd114/tresor/commit/1634813239a0b69da793e5beaa2f192ee45afc7a))
* **deps:** update rust crate toml to 0.9 ([#24](https://github.com/njoerd114/tresor/issues/24)) ([c9e3a45](https://github.com/njoerd114/tresor/commit/c9e3a458241aeaaa1ffefbe21f61262865fb100b))
* **test:** pin the header version in the composed-frame snapshot ([#22](https://github.com/njoerd114/tresor/issues/22)) ([301b6f7](https://github.com/njoerd114/tresor/commit/301b6f799ab30f8f7982674ef451b2f5329e9bf1))


### Documentation

* features deliberately out of scope (and why) ([4e95278](https://github.com/njoerd114/tresor/commit/4e952785784ec53fa5b09c8042e825981273f28e))
* track features deliberately out of scope ([73c7b3b](https://github.com/njoerd114/tresor/commit/73c7b3b12f8a5652851c1e17c59273b2f3d5b6dc)), closes [#8](https://github.com/njoerd114/tresor/issues/8)


### CI

* automated releases from conventional commits + distro packages + install docs ([6c5473a](https://github.com/njoerd114/tresor/commit/6c5473aaa660cac83189489715c6b20f68177272))
* automated releases from conventional commits + distro packages + install docs ([fb07d16](https://github.com/njoerd114/tresor/commit/fb07d163dcf571c3e102ce5a9a943e98f79798f0))

## [0.2.0](https://github.com/njoerd114/tresor/compare/tresor-v0.1.0...tresor-v0.2.0) (2026-10-13)


### Features

* initial release of tresor — k9s-style Vault/OpenBao TUI ([33f1932](https://github.com/njoerd114/tresor/commit/33f1932acb62cb1b00ed2aa658ef5d3da3d7aff9))


### Bug Fixes

* **ci:** replace release-plz with release-please (tag-driven, no crates.io) ([#17](https://github.com/njoerd114/tresor/issues/17)) ([4fc2237](https://github.com/njoerd114/tresor/commit/4fc2237b8a589ccb4e0fdbfd6023aa86dac2e21d))
* **deps:** repair main after Renovate bumps; land CLI, CI and packaging fixes ([#16](https://github.com/njoerd114/tresor/issues/16)) ([bfed051](https://github.com/njoerd114/tresor/commit/bfed051e45825e53e2ea8fd9ccc51ffaff6f6797))
* **deps:** update rust crate crossterm to 0.29 ([e0dfc6f](https://github.com/njoerd114/tresor/commit/e0dfc6f7e80a0e39e88cd780bf5b056724b110c0))
* **deps:** update rust crate crossterm to 0.29 ([60908cf](https://github.com/njoerd114/tresor/commit/60908cf9337e4be4b179c167341a7b0a1ce0067e))
* **deps:** update rust crate ratatui to 0.30 ([d75d793](https://github.com/njoerd114/tresor/commit/d75d79395b60a941a001f86ac487e1b0cd296694))
* **deps:** update rust crate ratatui to 0.30 ([85756b5](https://github.com/njoerd114/tresor/commit/85756b59e17fb8bbc25a3295df973b4134320d20))
* **deps:** update rust crate reqwest to 0.13 ([f4c2ef0](https://github.com/njoerd114/tresor/commit/f4c2ef01cb47669dd01e4b383a40c50cecc69096))
* **deps:** update rust crate reqwest to 0.13 ([1634813](https://github.com/njoerd114/tresor/commit/1634813239a0b69da793e5beaa2f192ee45afc7a))


### Documentation

* features deliberately out of scope (and why) ([4e95278](https://github.com/njoerd114/tresor/commit/4e952785784ec53fa5b09c8042e825981273f28e))
* track features deliberately out of scope ([73c7b3b](https://github.com/njoerd114/tresor/commit/73c7b3b12f8a5652851c1e17c59273b2f3d5b6dc)), closes [#8](https://github.com/njoerd114/tresor/issues/8)


### CI

* automated releases from conventional commits + distro packages + install docs ([6c5473a](https://github.com/njoerd114/tresor/commit/6c5473aaa660cac83189489715c6b20f68177272))
* automated releases from conventional commits + distro packages + install docs ([fb07d16](https://github.com/njoerd114/tresor/commit/fb07d163dcf571c3e102ce5a9a943e98f79798f0))
