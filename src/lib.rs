#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use ink_lang as ink;

pub use crate::sample_oracle::*;

#[ink::contract(env = pink_extension::PinkEnvironment)]
mod sample_oracle {
    use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};
    use ink_storage::traits::{PackedLayout, SpreadLayout};
    use phat_offchain_rollup::{
        clients::evm::read::{Action, QueuedRollupSession},
        lock::GLOBAL as GLOBAL_LOCK,
        RollupHandler, RollupResult,
    };
    use pink_extension as pink;
    use pink_web3::ethabi;
    use primitive_types::H160;
    use scale::{Decode, Encode};

    use abi::ABI;
    use pink::http_get;
    use primitive_types::U256;
    use serde_json;

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct SampleOracle {
        owner: AccountId,
        config: Option<Config>,
        apiconfig: Option<ApiConfig>,
    }

    #[derive(Encode, Decode, Debug, PackedLayout, SpreadLayout)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout)
    )]
    struct Config {
        rpc: String,
        anchor: [u8; 20],
    }

    #[derive(Encode, Decode, Debug, PackedLayout, SpreadLayout)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout)
    )]
    struct ApiConfig {
        url: String,
        apikey: Option<String>,
    }

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        NotConfigurated,
        BadAbi,
        FailedToGetStorage,
        FailedToDecodeStorage,
        FailedToEstimateGas,
        FailedToDecodeParams,
        FailedToDecodeResBody,
        MultiplyTimesOverflow,
    }

    type Result<T> = core::result::Result<T, Error>;

    impl SampleOracle {
        #[ink(constructor)]
        pub fn default() -> Self {
            Self {
                owner: Self::env().caller(),
                config: None,
                apiconfig: None,
            }
        }

        /// Configures the rollup target
        #[ink(message)]
        pub fn config(&mut self, rpc: String, anchor: H160) -> Result<()> {
            self.ensure_owner()?;
            self.config = Some(Config {
                rpc,
                anchor: anchor.into(),
            });
            Ok(())
        }

        #[ink(message)]
        pub fn set_apiconfig(&mut self, url: String, apikey: Option<String>) -> Result<()> {
            self.ensure_owner()?;
            self.apiconfig = Some(ApiConfig { url, apikey });
            Ok(())
        }

        fn handle_req(&self) -> Result<Option<RollupResult>> {
            #[cfg(feature = "std")]
            println!("handling req");

            let Config { rpc, anchor } = self.config.as_ref().ok_or(Error::NotConfigurated)?;
            let mut rollup = QueuedRollupSession::new(rpc, anchor.into(), b"q", |_locks| {});

            // Declare write to global lock since it pops an element from the queue
            rollup
                .lock_write(GLOBAL_LOCK)
                .expect("FIXME: failed to fetch lock");

            // Read the first item in the queue (return if the queue is empty)
            let (raw_item, idx) = rollup
                .queue_head()
                .expect("FIXME: failed to read queue head");

            #[cfg(feature = "std")]
            println!("raw_item: {:?}, idx: {:?}", raw_item, idx);

            let raw_item = match raw_item {
                Some(v) => v,
                _ => return Ok(None),
            };

            #[cfg(feature = "std")]
            println!("raw_item {:?}", raw_item);

            // Decode the queue data by ethabi (u256, bytes)
            let decoded = ethabi::decode(
                &[ethabi::ParamType::Uint(32), ethabi::ParamType::Bytes],
                &raw_item,
            )
            .or(Err(Error::FailedToDecodeStorage))?;

            let (rid, parameter_abi_bytes) = match decoded.as_slice() {
                [ethabi::Token::Uint(reqid), ethabi::Token::Bytes(content)] => (reqid, content),
                _ => return Err(Error::FailedToDecodeStorage),
            };

            //
            //let tokens_of_params = ethabi::decode(
            //    &[ethabi::ParamType::Array(Box::new(
            //        ethabi::ParamType::FixedBytes(32),
            //    ))],
            //    &parameter_abi_bytes,
            //);
            //let mut abi256 = Vec::new();
            //for param in tokens_of_params.unwrap().into_iter() {
            //    if let ethabi::Token::FixedBytes(bytes) = param {
            //        //let mut buf = [0u8; 32];
            //        //buf.copy_from_slice(&bytes);
            //        //let v = U256::from_big_endian(&buf);
            //        abi256.push(U256::from_big_endian(&bytes));
            //    }
            //}
            //let decoded_abi = ABI::decode(&abi256, true).or(Err(Error::FailedToDecodeParams))?;
            let decoded_abi = ABI::decode_from_slice(parameter_abi_bytes, true)
                .or(Err(Error::FailedToDecodeParams))?;

            #[cfg(feature = "std")]
            println!("Got decoded params abi {:?}", decoded_abi);

            let url_suffix = decoded_abi
                .params
                .iter()
                .filter(|param| !param.get_name().starts_with("_"))
                .map(|param| param.get_name().to_string() + "=" + &param.get_value().to_string())
                .collect::<Vec<String>>()
                .join("&");

            #[cfg(feature = "std")]
            println!("Got url suffix {:?}", url_suffix);

            let ApiConfig { url, apikey } =
                self.apiconfig.as_ref().ok_or(Error::NotConfigurated)?;

            let resp = http_get!(url.to_owned() + &"?".to_string() + &url_suffix);

            #[cfg(feature = "std")]
            println!("Got response {:?}", resp.body);

            // TODO check resp code
            let body = resp.body;
            // let root = serde_json::from_slice::<serde_json::Value>(&body)
            //.or(Err(Error::FailedToDecodeResBody))?;

            // TODO use macro to generate the code
            // 1. get path field
            // 2. generate the code
            let match_result = U256::from_little_endian(&body);

            // offchain to onchain 1.0 string x 10000
            // onchain to offchain / 10000
            // U256

            // Apply the response to request
            let payload =
                ethabi::encode(&[ethabi::Token::Uint(*rid), ethabi::Token::Uint(match_result)]);

            rollup
                .tx_mut()
                .action(Action::Reply(payload))
                .action(Action::ProcessedTo(idx + 1));

            Ok(Some(rollup.build()))
        }

        /// Returns BadOrigin error if the caller is not the owner
        fn ensure_owner(&self) -> Result<()> {
            if self.env().caller() == self.owner {
                Ok(())
            } else {
                Err(Error::BadOrigin)
            }
        }
    }

    impl RollupHandler for SampleOracle {
        #[ink(message)]
        fn handle_rollup(&self) -> core::result::Result<Option<RollupResult>, Vec<u8>> {
            self.handle_req().map_err(|e| Encode::encode(&e))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        fn consts() -> (String, H160) {
            use std::env;
            dotenvy::dotenv().ok();
            /*
             Deployed {
                anchor: '0xb3083F961C729f1007a6A1265Ae6b97dC2Cc16f2',
                oracle: '0x8Bf50F8d0B62017c9B83341CB936797f6B6235dd'
            }
            */
            // let rpc = env::var("RPC").unwrap();
            let rpc = "https://goerli.infura.io/v3/e5cbadfb7319409f981ee0231c256639".to_string();
            let anchor_addr: [u8; 20] = hex::decode("0071B8CCeEc507ccc58656B50727eCfb46C6E3c5")
                .expect("hex decode failed")
                .try_into()
                .expect("invald length");
            let anchor_addr: H160 = anchor_addr.into();
            (rpc, anchor_addr)
        }

        #[ink::test]
        fn default_works() {
            pink_extension_runtime::mock_ext::mock_all_ext();

            let (rpc, anchor_addr) = consts();

            let mut sample_oracle = SampleOracle::default();
            sample_oracle.config(rpc, anchor_addr).unwrap();
            sample_oracle
                .set_apiconfig(
                    "https://150.109.145.144:3301/saas3/web2/qatar2022/played".to_string(),
                    None,
                )
                .unwrap();

            let res = sample_oracle.handle_req().unwrap();
            println!("res: {:#?}", res);
        }
    }
}
