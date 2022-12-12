#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use ink_lang as ink;

/// Fat contract version SaaS3 decentralized oracle runtime
/// `config`  should be called after the deployment of the contract
/// With phala TEE environment, the oracle data like API token can be safely stored in the contract
#[ink::contract(env = pink_extension::PinkEnvironment)]
mod druntime {
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

    use abi::{encode::str_chunk32_bytes, ABI};
    use pink::http_get;
    use primitive_types::U256;
    use serde_json;

    /// The the storage of druntime
    #[ink(storage)]
    pub struct Oracle {
        owner: AccountId,
        /// oracle config, is none before config
        config: Option<Config>,
    }

    #[derive(Encode, Decode, Debug, PackedLayout, SpreadLayout)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout)
    )]
    struct Config {
        rpc: String,
        anchor: [u8; 20],
        url: String,
        apikey: Option<String>,
    }

    #[derive(Encode, Decode, Debug, PartialEq)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        NotConfigurated,
        BadAbi,
        FailedToGetStorage,
        FailedToDecodeStorage,
        FailedToDecodeOracleRequest,
        FailedToDecodeParams,
        FailedToDecodeResBody,
        FailedToDecodeByPath,
        FailedToGetInternalPath,
        Web2StatusError,
        TimesTooSmall,
        FailedToCreateRollupSession,
        FailedToFetchLock,
        FailedToReadQueueHead,
        FailedToDecodeNumberFromJson,
        TypeNotSet,
        InvalidType,
        InvalidRootValue,
        NumberSignNotMatch,
        EncodeNonDecimalNumberTo256Failed,
        EncodeStringTo32BytesFailed,
        TimesParseFailed,
        NotANumberOrString,
    }

    type Result<T> = core::result::Result<T, Error>;

    impl Oracle {
        #[ink(constructor)]
        pub fn default() -> Self {
            Self {
                owner: Self::env().caller(),
                config: None,
            }
        }

        /// Configures the oracle
        #[ink(message)]
        pub fn config(
            &mut self,
            // saas3 protocol target chain rpc
            target_chain_rpc: Option<String>,
            // phala anchor contract address
            anchor_contract_addr: Option<H160>,
            // web2 api url prefix
            web2_api_url_prefix: Option<String>,
            // web2 api key
            api_key: Option<String>,
        ) -> Result<()> {
            self.ensure_owner()?;
            if self.config.is_none() {
                if target_chain_rpc.is_none() || anchor_contract_addr.is_none() {
                    return Err(Error::NotConfigurated);
                }
                self.config = Some(Config {
                    rpc: target_chain_rpc.unwrap(),
                    anchor: anchor_contract_addr.unwrap().into(),
                    url: web2_api_url_prefix.unwrap_or_default(),
                    apikey: api_key,
                });
            } else {
                if let Some(rpc) = target_chain_rpc {
                    self.config.as_mut().unwrap().rpc = rpc;
                }
                if let Some(anchor) = anchor_contract_addr {
                    self.config.as_mut().unwrap().anchor = anchor.into();
                }
                if let Some(url) = web2_api_url_prefix {
                    self.config.as_mut().unwrap().url = url;
                }
                if let Some(apikey) = api_key {
                    self.config.as_mut().unwrap().apikey = Some(apikey);
                }
            }
            Ok(())
        }

        fn read_by_path(&self, v: serde_json::Value, path: &str) -> Result<serde_json::Value> {
            let v = path.split(".").fold(Ok(v), |v, p| {
                #[cfg(feature = "std")]
                println!("p: {}", p);

                let v = v?.get(p).ok_or(Error::FailedToDecodeByPath).cloned();
                v
            })?;

            #[cfg(feature = "std")]
            println!("path {} value {:#?}", path, v);

            Ok(v)
        }

        fn encode_from_string_to_256(
            &self,
            s: String,
            signed: bool,
            _times: u32,
        ) -> Result<ethabi::Token> {
            let is_signed = s.starts_with("-");
            if is_signed && !signed {
                // eg. try encode "-3" to u256
                return Err(Error::NumberSignNotMatch);
            }
            let pos = s.find(".");
            if pos != None {
                // offset count
                let y = s.len() - pos.unwrap() - 1;

                if 10_u32.pow(y as u32) > _times {
                    return Err(Error::TimesTooSmall);
                }

                // remove decimal point
                let mut s = s.to_owned();
                s.retain(|c| c != '.' && c != '-');

                // alreay multiply by 10^y
                let mut v = s.parse::<u64>().unwrap();

                // times must >= 10^y
                v = v * (_times / 10_u32.pow(y as u32)) as u64;

                // encode to u256
                if is_signed {
                    return Ok(ethabi::Token::Int(U256::from(v)));
                } else {
                    return Ok(ethabi::Token::Uint(U256::from(v)));
                }
            } else {
                // not a decimal number
                let mut s = s.to_owned();
                s.retain(|c| c != '-');

                #[cfg(feature = "std")]
                println!("s: {}", s);

                if signed {
                    s.parse::<i64>()
                        .map(|x| ethabi::Token::Int(U256::from(x)))
                        .map_err(|_| Error::EncodeNonDecimalNumberTo256Failed)
                } else {
                    s.parse::<u64>()
                        .map(|x| ethabi::Token::Uint(U256::from(x)))
                        .map_err(|_| Error::EncodeNonDecimalNumberTo256Failed)
                }
            }
        }

        fn encode_answer(
            &self,
            v: serde_json::Value,
            _type: &str,
            _times: u32,
        ) -> Result<ethabi::Token> {
            match v {
                serde_json::Value::Number(n) => {
                    return match _type {
                        "string" => Ok(ethabi::Token::String(n.to_string())),
                        "string32" => {
                            let chunk = str_chunk32_bytes(&n.to_string())
                                .map_err(|_| Error::EncodeStringTo32BytesFailed)?;
                            Ok(ethabi::Token::FixedBytes(chunk))
                        }
                        "uint256" => {
                            Ok(self.encode_from_string_to_256(n.to_string(), false, _times)?)
                        }
                        "int256" => {
                            Ok(self.encode_from_string_to_256(n.to_string(), true, _times)?)
                        }
                        _ => Err(Error::InvalidType),
                    };
                }
                serde_json::Value::String(s) => {
                    #[cfg(feature = "std")]
                    println!("String: {}", s);

                    return match _type {
                        "string" => Ok(ethabi::Token::String(s)),
                        "string32" => {
                            let chunk = str_chunk32_bytes(&s.to_string())
                                .map_err(|_| Error::EncodeStringTo32BytesFailed)?;
                            Ok(ethabi::Token::FixedBytes(chunk))
                        }
                        "uint256" => Ok(self.encode_from_string_to_256(s, false, _times)?),
                        "int256" => Ok(self.encode_from_string_to_256(s, true, _times)?),
                        _ => Err(Error::InvalidType),
                    };
                }
                _ => {
                    #[cfg(feature = "std")]
                    println!("Not a number or string");

                    return Err(Error::NotANumberOrString);
                }
            }
        }

        fn handle_req(&self) -> Result<Option<RollupResult>> {
            #[cfg(feature = "std")]
            println!("handling req");

            let Config {
                rpc,
                anchor,
                url,
                apikey: _,
            } = self.config.as_ref().ok_or(Error::NotConfigurated)?;
            let mut rollup =
                QueuedRollupSession::new(rpc, anchor.into(), |_locks| {}).map_err(|e| {
                    pink::warn!("Failed to create rollup session: {e:?}");
                    Error::FailedToCreateRollupSession
                })?;

            // Declare write to global lock since it pops an element from the queue
            rollup.lock_read(GLOBAL_LOCK).map_err(|e| {
                pink::warn!("Failed to fetch lock: {e:?}");
                Error::FailedToFetchLock
            })?;

            #[cfg(feature = "std")]
            println!("reading raw data from qeueue ...");
            // Read the first item in the queue (return if the queue is empty)
            let (raw_item, idx) = rollup.queue_head().map_err(|e| {
                pink::warn!("Failed to read queue head: {e:?}");
                Error::FailedToReadQueueHead
            })?;

            let raw_item = match raw_item {
                Some(v) => v,
                _ => {
                    pink::debug!("No items in the queue. Returning.");
                    return Ok(None);
                }
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
                _ => return Err(Error::FailedToDecodeOracleRequest),
            };

            #[cfg(feature = "std")]
            println!("ask_id {:?}", rid);

            let decoded_abi = ABI::decode_from_slice(parameter_abi_bytes, true)
                .or(Err(Error::FailedToDecodeParams))?;

            #[cfg(feature = "std")]
            println!("Got decoded params abi {:?}", decoded_abi);

            // build url suffix
            let url_suffix = decoded_abi
                .params
                .iter()
                .filter(|param| !param.get_name().starts_with("_")) // skip the internal params
                .map(|param| param.get_name().to_string() + "=" + &param.get_value().to_string())
                .collect::<Vec<String>>()
                .join("&");

            // path is optional, if not set, we will use the root path
            let _path = decoded_abi
                .params
                .iter()
                .find(|param| param.get_name() == "_path")
                .get_or_insert(&abi::Param::String {
                    name: "_path".to_string(),
                    value: "".to_string(),
                })
                .get_value();

            // _type is necessary
            let _type = decoded_abi
                .params
                .iter()
                .find(|param| param.get_name() == "_type")
                .ok_or(Error::TypeNotSet)?
                .get_value();

            // _times is only necessary for float number data
            let _times = decoded_abi
                .params
                .iter()
                .find(|param| param.get_name() == "_times")
                .get_or_insert(&abi::Param::String {
                    name: "_times".to_string(),
                    value: "100".to_string(),
                })
                .get_value()
                .parse::<u32>()
                .map_err(|_| Error::TimesParseFailed)?;

            #[cfg(feature = "std")]
            println!("Got url suffix {:?}", url_suffix);

            let uri = url.to_owned() + "?" + &url_suffix;

            #[cfg(feature = "std")]
            println!("Got uri {:?}", uri);

            let resp = http_get!(uri);
            if resp.status_code != 200 {
                return Err(Error::Web2StatusError);
            }

            #[cfg(feature = "std")]
            println!("Got response {:?}", resp.body);

            let root = serde_json::from_slice::<serde_json::Value>(&resp.body)
                .or(Err(Error::FailedToDecodeResBody))?;

            #[cfg(feature = "std")]
            println!("Got response {:#?}", root);

            let mut v = root.clone();
            if _path != "" {
                v = self.read_by_path(root, &_path)?;
            } // no path, use the root path

            if v.is_array() || v.is_null() || v.is_object() {
                // we only support number, string, bool
                return Err(Error::InvalidRootValue);
            }
            let answer = self.encode_answer(v, &_type, _times)?;

            #[cfg(feature = "std")]
            println!("answer {:#?}", answer);

            let answer = ethabi::encode(&[answer]);

            // Apply the response to request
            let payload =
                ethabi::encode(&[ethabi::Token::Uint(*rid), ethabi::Token::Bytes(answer)]);

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

    impl RollupHandler for Oracle {
        /// The anchor contract message handler
        /// It should be called by a scheduled task
        #[ink(message)]
        fn handle_rollup(&self) -> core::result::Result<Option<RollupResult>, Vec<u8>> {
            self.handle_req().map_err(|e| Encode::encode(&e))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        #[ink::test]
        fn read_by_path_should_ok() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let root = serde_json::from_str::<serde_json::Value>(
                r#"
                {
                    "a": {
                        "b": {
                            "c": 1
                        }
                    }
                }
                "#,
            )
            .unwrap();
            let v = oracle.read_by_path(root, "a.b.c").unwrap();
            assert_eq!(v, serde_json::Value::Number(1.into()));
        }

        #[ink::test]
        fn read_by_path_should_fail() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let root = serde_json::from_str::<serde_json::Value>(
                r#"
                {
                    "a": {
                        "b": {
                            "c": 1
                        }
                    }
                }
                "#,
            )
            .unwrap();
            let v = oracle.read_by_path(root.clone(), "a.b.d");
            assert!(v.is_err());
            assert_eq!(v.err().unwrap(), Error::FailedToDecodeByPath);
            let v1 = oracle.read_by_path(root, "a.b");
            assert!(v1.unwrap().is_object());
        }

        #[ink::test]
        fn encode_from_string_to_256_should_ok() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle
                .encode_from_string_to_256("1.23".to_string(), false, 100)
                .unwrap();
            assert_eq!(v, ethabi::Token::Uint(123.into()));
        }

        #[ink::test]
        fn encode_from_string_to_256_should_ok_with_signed_decimal() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle
                .encode_from_string_to_256("-1.23".to_string(), true, 100)
                .unwrap();
            assert_eq!(v, ethabi::Token::Int(123.into()));
        }

        #[ink::test]
        fn encode_from_string_to_256_should_ok_with_signed_non_decimal() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle
                .encode_from_string_to_256("-123".to_string(), true, 100)
                .unwrap();
            assert_eq!(v, ethabi::Token::Int(123.into()));
        }

        #[ink::test]
        fn encode_from_string_to_256_should_fail() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle.encode_from_string_to_256("1.23".to_string(), false, 10);
            assert_eq!(v.err().unwrap(), Error::TimesTooSmall);
        }

        #[ink::test]
        fn encode_from_string_to_256_should_ok_with_non_decimal_str() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = oracle.encode_from_string_to_256("123".to_string(), false, 10);
            assert_eq!(v.unwrap(), ethabi::Token::Uint(123.into()));
        }

        #[ink::test]
        fn encode_answer_should_ok_with_string32() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = serde_json::json!({ "city": "saas3", "street": "10 Downing Street" });
            let v = oracle.read_by_path(v, "city").unwrap();
            let t = oracle.encode_answer(v, "string32", 100).unwrap();
            assert_eq!(
                t.into_bytes(),
                ethabi::Token::String("saas3".to_string()).into_bytes()
            );
        }

        #[ink::test]
        fn encode_answer_should_ok_with_float() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let oracle = Oracle::default();
            let v = serde_json::json!({ "city": 1.32, "street": "10 Downing Street" });
            let v = oracle.read_by_path(v, "city").unwrap();
            let t = oracle.encode_answer(v, "uint256", 1000).unwrap();
            assert_eq!(
                t.into_bytes(),
                ethabi::Token::Uint(U256::from(1320)).into_bytes()
            );
        }

        fn consts() -> (String, H160) {
            dotenvy::dotenv().ok();
            // let rpc = env::var("RPC").unwrap();
            //let rpc = "https://goerli.infura.io/v3/e5cbadfb7319409f981ee0231c256639".to_string();
            // let rpc = "https://moonbase-alpha.public.blastapi.io".to_string();
            // let rpc = "https://rpc.api.moonbase.moonbeam.network".to_string();
            //let rpc = "https://moonbeam-alpha.api.onfinality.io/public".to_string();
            let rpc = "https://polygon-mainnet.public.blastapi.io".to_string();

            let anchor_addr: [u8; 20] = hex::decode("63De844992279204a7132C936EF07c27A770D809")
                .expect("hex decode failed")
                .try_into()
                .expect("invald length");
            let anchor_addr: H160 = anchor_addr.into();
            (rpc, anchor_addr)
        }

        #[ink::test]
        fn default_works() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let (rpc, anchor_addr) = consts();

            let mut oracle = Oracle::default();
            oracle
                .config(
                    Some(rpc),
                    Some(anchor_addr),
                    Some("https://rpc.saas3.io:3301/saas3/web2/qatar2022/played".to_string()),
                    None,
                )
                .unwrap();
            let res = oracle.handle_req().unwrap();
            println!("res: {:#?}", res);
        }
    }
}
