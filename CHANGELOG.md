# Changelog

## [0.1.1](https://github.com/unified-systems-com/tenable-tap/compare/v0.1.0...v0.1.1) (2026-11-20)


### Features

* **grift:** declare tenable's dimensions (seed carved out of the collector PR) ([ae37485](https://github.com/unified-systems-com/tenable-tap/commit/ae374852acf004844d4b6ce49a256cf42b3de2ea))
* **grift:** declare tenable's dimensions for tap's declared-dimension storage ([f15fefb](https://github.com/unified-systems-com/tenable-tap/commit/f15fefb09f1cd304a3bd58ad3c8c436c77dbc878))
* **models:** the Tenable-owned node and edge types ([99232f2](https://github.com/unified-systems-com/tenable-tap/commit/99232f28b714b093dc960ec62c264742b7abfbce))
* **models:** the Tenable-owned node and edge types ([59408bb](https://github.com/unified-systems-com/tenable-tap/commit/59408bb8b480accc9c27754308b5414c5598f33a))


### Bug Fixes

* **identity:** refuse URL spellings that could name a console twice ([f895a7a](https://github.com/unified-systems-com/tenable-tap/commit/f895a7a419afdc6590b234e1105bb7fe6ad2b4d1))
* **identity:** tenable.instance is the instance key itself ([78ed0af](https://github.com/unified-systems-com/tenable-tap/commit/78ed0af17fef826d89b066257515e7f91b26b5c2))
* **models:** a result's state and resolution source agree ([b3f9363](https://github.com/unified-systems-com/tenable-tap/commit/b3f936310531890283c2fd04e1fd5a4314d161c6))
* **models:** chain BaseModel.validate; no edge joins two consoles ([be8e5ab](https://github.com/unified-systems-com/tenable-tap/commit/be8e5abc4d649e1820c010b30917ee15c5c28f82))
* **models:** every node checks its instance key and the free-text ceiling ([142af9e](https://github.com/unified-systems-com/tenable-tap/commit/142af9eb13d481fab57cac3587bedc47a90658de))


### Documentation

* **spec:** a recorded 4 MiB ceiling on free text from Tenable ([f8eef06](https://github.com/unified-systems-com/tenable-tap/commit/f8eef064cb59e67c6a689e66e9ade3a692b5d6fc))
* **spec:** add the conditional finding-level CVE narrowing as Backlog ([58ae311](https://github.com/unified-systems-com/tenable-tap/commit/58ae3114f1f93494cb4a9581cc01bffd8f5ef8f9))
* **spec:** always hash the repository into the host key ([ed0761a](https://github.com/unified-systems-com/tenable-tap/commit/ed0761a8dadda454ffc5bd2e958fa02e06064489))
* **spec:** answer review — mitigation precedence, fail-closed host uniqueness, network risk ([2ad94aa](https://github.com/unified-systems-com/tenable-tap/commit/2ad94aae303c93e49282f88a7bd2a6a41105ad6d))
* **spec:** cite Q54a for the same-console rule ([d980db5](https://github.com/unified-systems-com/tenable-tap/commit/d980db5e4965deaa3ecb975bf2fad0ca51cf13f9))
* **spec:** cite rulings and PR comments, not 'review of PR 6' ([df38d40](https://github.com/unified-systems-com/tenable-tap/commit/df38d4089b820b06948bd1cd48e17f378a424a3c))
* **spec:** link CVEs from the plugin, not the finding ([2145e91](https://github.com/unified-systems-com/tenable-tap/commit/2145e91ed6b5184efc118b8de43de63888350183))
* **spec:** link CVEs from the plugin, not the finding ([7d24f6d](https://github.com/unified-systems-com/tenable-tap/commit/7d24f6d94b174b164c7c4a31ed2b5c03a17d49d1))
* **spec:** name the agent uuid field and separate host-key MAC from shared-fact MAC ([498fa19](https://github.com/unified-systems-com/tenable-tap/commit/498fa19d00c7d67b40bc8e89a7fafd6ca4c18822))
* **spec:** refresh plugin CVEs independently of pluginModDate; keep disagreement evidence ([a28a8d7](https://github.com/unified-systems-com/tenable-tap/commit/a28a8d7670236ea4b8ce1c22ca5e461c59ec70c8))
* **spec:** scope address-edge retirement to UUID-keyed observed hosts ([96aacdb](https://github.com/unified-systems-com/tenable-tap/commit/96aacdb4850fefafeb5e556a3c6b635edc236697))
* **spec:** tag the same-console edge rule as a workaround for tap[#1187](https://github.com/unified-systems-com/tenable-tap/issues/1187) ([1cdc6bd](https://github.com/unified-systems-com/tenable-tap/commit/1cdc6bd45089edebbb8e66ea8e46a3625788585d))
* **spec:** v0 network-scan path, Tenable house-format types and shared facts ([f24c619](https://github.com/unified-systems-com/tenable-tap/commit/f24c61914fb3c05c2a364959470a76b2a5e0e032))
* **spec:** v0 network-scan path, Tenable house-format types and shared facts ([8e575e8](https://github.com/unified-systems-com/tenable-tap/commit/8e575e86dbf227cbd0387dabadfe684d502e0ba4))
