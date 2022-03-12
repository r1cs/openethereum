// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

//! Engine deserialization.

use super::{Ethash, InstantSeal, NullEngine};

/// Engine deserialization.
#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub enum Engine {
    /// Null engine.
    Null(NullEngine),
    /// Instantly sealing engine.
    InstantSeal(Option<InstantSeal>),
    /// Ethash engine.
    #[serde(rename = "Ethash")]
    Ethash(Ethash),
}

#[cfg(test)]
mod tests {
    use crate::spec::Engine;
    use serde_json;

    #[test]
    fn engine_deserialization() {
        let s = r#"{
			"null": {
				"params": {
					"blockReward": "0x0d"
				}
			}
		}"#;

        let deserialized: Engine = serde_json::from_str(s).unwrap();
        match deserialized {
            Engine::Null(_) => {} // unit test in its own file.
            _ => panic!(),
        }

        let s = r#"{
			"instantSeal": {"params": {}}
		}"#;

        let deserialized: Engine = serde_json::from_str(s).unwrap();
        match deserialized {
            Engine::InstantSeal(_) => {} // instant seal is unit tested in its own file.
            _ => panic!(),
        };

        let s = r#"{
			"instantSeal": null
		}"#;

        let deserialized: Engine = serde_json::from_str(s).unwrap();
        match deserialized {
            Engine::InstantSeal(_) => {} // instant seal is unit tested in its own file.
            _ => panic!(),
        };

        let s = r#"{
			"Ethash": {
				"params": {
					"minimumDifficulty": "0x020000",
					"difficultyBoundDivisor": "0x0800",
					"durationLimit": "0x0d",
					"homesteadTransition" : "0x",
					"daoHardforkTransition": "0xffffffffffffffff",
					"daoHardforkBeneficiary": "0x0000000000000000000000000000000000000000",
					"daoHardforkAccounts": []
				}
			}
		}"#;

        let deserialized: Engine = serde_json::from_str(s).unwrap();
        match deserialized {
            Engine::Ethash(_) => {} // ethash is unit tested in its own file.
            _ => panic!(),
        };
    }
}
