pub mod types;
use crate::context::types::Log;
use crate::memory::Memory;
use primitive_types::U256;
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Debug)]
pub struct WorldState {
    pub accounts: HashMap<[u8; 20], Account>,
}

impl WorldState {
    pub fn get(&mut self, address: &[u8; 20]) -> Option<&mut Account> {
        return self.accounts.get_mut(address);
    }
    pub fn as_ref(&self, address: &[u8; 20]) -> Option<&Account> {
        return self.accounts.get(address);
    }
    pub fn set(&mut self, address: &[u8; 20], account: Account) {
        self.accounts.insert(address.clone(), account);
    }
    pub fn new() -> WorldState {
        WorldState {
            accounts: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]

pub struct Account {
    pub balance: U256,
    pub nonce: U256,
    pub code: Vec<u8>,
    pub storage: Storage,
}
impl Account {
    pub fn new() -> Account {
        Account {
            balance: U256::zero(),
            nonce: U256::zero(),
            code: Vec::new(),
            storage: Storage::new(),
        }
    }
}
#[derive(Debug, Clone)]
pub struct Storage {
    pub data: HashMap<U256, U256>,
}

impl Storage {
    pub fn new() -> Storage {
        Storage {
            data: HashMap::new(),
        }
    }
    pub fn get(&self, key: &U256) -> Option<&U256> {
        self.data.get(key)
    }
    pub fn store(&mut self, key: U256, value: U256) {
        self.data.insert(key, value);
    }
}

pub struct Context<'a> {
    pub stack: Vec<U256>,
    pub pc: U256,
    pub code: &'a [u8],
    pub stopped: bool,
    pub gas: U256,
    pub valid_jumpdests: HashSet<U256>,
    pub memory: Memory,
    pub world_state: &'a mut WorldState,
    pub calldata: Vec<u8>,
    pub logs: Vec<Log>,
    pub returndata: String,
}

impl<'a> Context<'a> {
    pub fn new(
        code: &'a [u8],
        world_state: &'a mut WorldState,
        calldata: Vec<u8>,
        gas: U256,
    ) -> Self {
        let mut valid_jumpdests: HashSet<U256> = HashSet::new();
        let mut pc: usize = 0;
        loop {
            if pc >= code.len() {
                break;
            }
            let op = code[pc];
            if op >= 0x60 && op <= 0x7f {
                pc += (op as usize) - 0x60 + 2;
            }
            if pc < code.len() && code[pc] == 0x5b {
                valid_jumpdests.insert(U256::from(pc as u32));
            }
            pc += 1;
        }
        Context {
            stack: Vec::new(),
            pc: U256::zero(),
            code,
            stopped: false,
            gas,
            valid_jumpdests,
            memory: Memory::new(),
            world_state,
            calldata,
            logs: Vec::new(),
            returndata: String::new(),
        }
    }

    pub fn calldataload(&mut self, offset: U256, size: usize) -> Vec<u8> {
        let len = self.calldata.len();
        if offset.as_u64() as usize + size > len {
            self.calldata.resize(offset.as_u64() as usize + size, 0);
        }

        return self.calldata[(offset.as_u64() as usize)..((offset.as_u64() as usize) + size)]
            .to_vec();
    }
    pub fn calldatasize(&self) -> U256 {
        return U256::from(self.calldata.len());
    }
}
