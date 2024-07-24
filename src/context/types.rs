use primitive_types::U256;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct Evmtest {
    pub name: String,
    pub hint: String,
    pub code: Code,
    pub expect: Expect,
    pub tx: Option<TX>,
    pub block: Option<Block>,
    pub state: Option<HashMap<String, State>>,
    pub static_call: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct State {
    pub balance: Option<String>,
    pub code: Option<Code>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Code {
    pub asm: String,
    pub bin: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Expect {
    pub stack: Option<Vec<String>>,
    pub success: bool,
    pub logs: Option<Vec<Log>>,
    pub returndata: Option<String>,
    // #[serde(rename = "return")]
    // ret: Option<String>,
}
#[derive(Debug, Deserialize, Clone)]
pub struct Log {
    pub address: String,
    pub data: String,
    pub topics: Vec<String>,
}
impl Log {
    pub fn new() -> Log {
        return Log {
            address: String::new(),
            data: String::new(),
            topics: Vec::new(),
        };
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TX {
    pub to: Option<String>,
    pub from: Option<String>,
    pub origin: Option<String>,
    pub gasprice: Option<String>,
    pub value: Option<String>,
    pub data: Option<String>,
}
#[derive(Debug, Deserialize, Clone)]
pub struct Block {
    pub basefee: Option<String>,
    pub coinbase: Option<String>,
    pub timestamp: Option<String>,
    pub number: Option<String>,
    pub difficulty: Option<String>,
    pub gaslimit: Option<String>,
    pub chainid: Option<String>,
}

pub struct EvmResult {
    pub stack: Vec<U256>,
    pub success: bool,
    pub logs: Vec<Log>,
    pub returndata: String,
}
