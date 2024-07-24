/**
 * EVM From Scratch
 * Rust template
 *
 * To work on EVM From Scratch in Rust:
 *
 * - Install Rust: https://www.rust-lang.org/tools/install
 * - Edit `rust/lib.rs`
 * - Run `cd rust && cargo run` to run the tests
 *
 * Hint: most people who were trying to learn Rust and EVM at the same
 * gave up and switched to JavaScript, Python, or Go. If you are new
 * to Rust, implement EVM in another programming language first.
 */
use evm::context::{Account, Storage, WorldState};
use evm::evm;
use primitive_types::U256;

fn main() {
    let text: String = std::fs::read_to_string("./evm.json").unwrap();
    let data: Vec<evm::context::types::Evmtest> = serde_json::from_str(&text).unwrap();

    let total: usize = data.len();

    for (index, test) in data.iter().enumerate() {
        println!("Test {} of {}: {}", index + 1, total, test.name);

        let code: Vec<u8> = hex::decode(&test.code.bin).unwrap();

        let mut state = WorldState::new();

        if let Some(test_state) = &test.state {
            for x in test_state {
                //Address
                let mut address: [u8; 20] = [0u8; 20];
                let address_vec_res = hex::decode(x.0.clone().replace("0x", "")).unwrap();
                address.copy_from_slice(&address_vec_res);

                //Balance
                let mut bal_in_u8 = [0u8; 32];
                if let Some(mut balance_in_hex) = x.1.balance.clone() {
                    if balance_in_hex.len() % 2 == 1 {
                        balance_in_hex.insert(2, '0');
                    }
                    let balance_in_vec = hex::decode(balance_in_hex.replace("0x", "")).unwrap();
                    for x in 0..balance_in_vec.len() {
                        bal_in_u8[32 - 1 - x] = balance_in_vec[balance_in_vec.len() - 1 - x];
                    }
                }
                let mut code: Vec<u8> = Vec::new();
                if let Some(code_detail) = &x.1.code {
                    code = hex::decode(&code_detail.bin).unwrap();
                }

                let account = Account {
                    balance: U256::from(bal_in_u8),
                    code,
                    storage: Storage::new(),
                    nonce: U256::from(0),
                };

                state.accounts.insert(address, account);
            }
        }

        let calldata: Vec<u8>;
        if let Some(tx_) = &test.tx {
            if let Some(data) = &tx_.data {
                calldata = hex::decode(data).unwrap();
            } else {
                calldata = Vec::new();
            }
        } else {
            calldata = Vec::new();
        }

        //Because We don't have gas in test cases we will take uint256 max.
        let gas: U256 = U256::max_value();

        //@note Let's implement Origin, From and to. If nothing is given.

        //@note - Here
        let result = evm(&code, &mut state, test, calldata, gas);

        let mut expected_stack: Vec<U256> = Vec::new();
        if let Some(ref stacks) = test.expect.stack {
            for value in stacks {
                expected_stack.push(U256::from_str_radix(value, 16).unwrap());
            }
        }

        let mut matching = result.stack.len() == expected_stack.len();
        if matching {
            for i in 0..result.stack.len() {
                // We not it's good because our order it right but they are having bad order.
                // if result.stack[i] != expected_stack[i] {
                if result.stack[result.stack.len() - i - 1] != expected_stack[i] {
                    matching = false;
                    break;
                }
            }
        }

        matching = matching && result.success == test.expect.success;

        //Stack
        if !matching {
            println!("Instructions: \n{}\n", test.code.asm);

            println!("Expected success: {:?}", test.expect.success);
            println!("Expected stack: [");
            for v in expected_stack {
                println!("  {:#X},", v);
            }
            println!("]\n");

            println!("Actual success: {:?}", result.success);
            println!("Actual stack: [");
            for v in result.stack {
                println!("  {:#X},", v);
            }
            println!("]\n");

            println!("\nHint: {}\n", test.hint);
            println!("Progress: {}/{}\n\n", index, total);
            panic!("Test failed");
        }

        //Log
        if let Some(logs) = test.expect.logs.as_ref() {
            if logs.len() == result.logs.len() {
                for x in 0..logs.len() {
                    if logs[x].address != result.logs[x].address {
                        println!("Address is not matching for {}th log", x);
                        println!("Expected address is {}", logs[x].address);
                        println!("Actuall address is {}", result.logs[x].address);
                        panic!("Test failed");
                    }
                    if logs[x].data != result.logs[x].data {
                        println!("Data is not matching for {}th log", x);
                        println!("Expected data is {}", logs[x].data);
                        println!("Actuall data is {}", result.logs[x].data);
                        panic!("Test failed");
                    }
                    if logs[x].topics != result.logs[x].topics {
                        println!("Topics are not matching for {}th log", x);
                        println!("Expected topics are {:?}", logs[x].topics);
                        println!("Actuall topics are {:?}", result.logs[x].topics);
                        panic!("Test failed");
                    }
                }
            } else {
                println!("Length not matching for logs");

                panic!("Test failed");
            }
        }

        //Data
        if let Some(returndata_) = &test.expect.returndata {
            if *returndata_ != result.returndata {
                println!("Return data is wrong!");
                println!("Expected return data is {}", returndata_);
                println!("Actuall return data is {}", result.returndata);
                panic!("Test failed");
            }
        }
        println!("PASS");
    }

    println!("Congratulations!");
}
