mod constants;
pub mod context;
mod int256;
mod memory;

use crate::constants::STATICCALL_DISSALOWED_OPCODES;
use crate::context::types::{EvmResult, Evmtest, Log, TX};
use crate::context::{Account, Context, Storage, WorldState};
use crate::int256::Int256;

use keccak_hash::keccak_256;
use primitive_types::U256;
use std::ops::{Div, Neg, Sub};

fn opcode_stop(ctx: &mut Context) -> bool {
    ctx.stopped = true;
    false
}

fn opcode_push(ctx: &mut Context, times: u8) -> bool {
    let mut to_push: U256 = U256::zero();
    for _ in 0..times {
        let val = ctx.code[ctx.pc.as_u32() as usize + 1];
        let val_in_u256: U256 = U256::from(val);
        to_push = to_push << 8 | val_in_u256;
        ctx.pc += U256::one();
    }
    ctx.stack.push(to_push);
    false
}

fn opcode_pop(ctx: &mut Context) -> bool {
    ctx.stack.pop();
    false
}

fn opcode_zero(ctx: &mut Context) -> bool {
    let to_push: U256 = U256::zero();
    ctx.stack.push(to_push);
    false
}

fn opcode_add(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();
    let sumab = a.overflowing_add(b);
    ctx.stack.push(sumab.0);
    false
}

fn opcode_mul(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();
    let mulval = a.overflowing_mul(b);
    ctx.stack.push(mulval.0);
    false
}

fn opcode_sub(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();
    let subval = a.overflowing_sub(b);
    ctx.stack.push(subval.0);
    false
}
fn opcode_div(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();
    if b == U256::from(0) {
        ctx.stack.push(U256::from(0));
    } else {
        let divval = a.div(b);
        ctx.stack.push(divval);
    }
    false
}
fn opcode_mod(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();
    if b == U256::from(0) {
        ctx.stack.push(U256::from(0));
    } else {
        let modval: (U256, U256) = a.div_mod(b);
        ctx.stack.push(modval.1);
    }
    false
}
fn opcode_addmod(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();
    let c = ctx.stack.pop().unwrap();
    if c == U256::from(0) {
        ctx.stack.push(U256::from(0));
    } else {
        let addval = a.overflowing_add(b);
        let modval: (U256, U256) = addval.0.div_mod(c);
        ctx.stack.push(modval.1);
    }
    false
}

fn opcode_mulmod(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();
    let c = ctx.stack.pop().unwrap();
    if c == U256::from(0) {
        ctx.stack.push(U256::from(0));
    } else {
        let mulval = a.overflowing_mul(b);
        let modval: (U256, U256) = mulval.0.div_mod(c);
        ctx.stack.push(modval.1);
    }
    false
}
fn opcode_exp(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();
    ctx.stack.push(a.overflowing_pow(b).0);
    false
}

fn opcode_signextend(ctx: &mut Context) -> bool {
    let a: U256 = ctx.stack.pop().unwrap();
    let mut b = ctx.stack.pop().unwrap();

    b = b & ((U256::from(1) << (a + 1) * 8) - 1);
    if (b >> ((a + 1) * 8 - 1)) != U256::from(0) {
        let mask = U256::max_value() ^ ((U256::from(1) << (a + 1) * 8) - 1);
        b = b | mask;
    }
    ctx.stack.push(b);
    false
}

fn opcode_sdiv(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    if b == U256::zero() {
        ctx.stack.push(U256::zero());
    } else {
        let signed_dividend = Int256::from_u256(a);
        let signed_divisor = Int256::from_u256(b);

        let signed_result = signed_dividend / signed_divisor;
        ctx.stack.push(signed_result.0);
    }
    false
}
fn opcode_smod(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    if b == U256::zero() {
        ctx.stack.push(U256::zero());
    } else {
        let signed_dividend = Int256::from_u256(a);
        let signed_divisor = Int256::from_u256(b);

        let signed_result = signed_dividend % signed_divisor;
        ctx.stack.push(signed_result.0);
    }
    false
}
fn opcode_lt(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    ctx.stack.push(U256::from(if a < b { 1 } else { 0 }));
    false
}
fn opcode_gt(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    ctx.stack.push(U256::from(if a > b { 1 } else { 0 }));
    false
}
fn opcode_slt(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    let (a_sign, b_sign) = (Int256::from_u256(a).sign(), Int256::from_u256(b).sign());

    if a_sign == -1 && b_sign == 1 || b_sign == 0 {
        ctx.stack.push(U256::from(1));
    } else if a_sign == 1 || a_sign == 0 && b_sign == -1 {
        ctx.stack.push(U256::from(0));
    } else if a_sign == -1 && b_sign == -1 {
        ctx.stack.push(U256::from(
            if Int256::from_u256(b).neg().0 < Int256::from_u256(a).neg().0 {
                1
            } else {
                0
            },
        ));
    } else {
        ctx.stack.push(U256::from(
            if Int256::from_u256(a).0 < Int256::from_u256(b).0 {
                1
            } else {
                0
            },
        ));
    }
    false
}
fn opcode_sgt(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    let (a_sign, b_sign) = (Int256::from_u256(a).sign(), Int256::from_u256(b).sign());

    if a_sign == -1 && b_sign == 1 || b_sign == 0 {
        ctx.stack.push(U256::from(0));
    } else if a_sign == 1 || a_sign == 0 && b_sign == -1 {
        ctx.stack.push(U256::from(1));
    } else if a_sign == -1 && b_sign == -1 {
        ctx.stack.push(U256::from(
            if Int256::from_u256(b).neg().0 > Int256::from_u256(a).neg().0 {
                1
            } else {
                0
            },
        ));
    } else {
        ctx.stack.push(U256::from(
            if Int256::from_u256(a).0 > Int256::from_u256(b).0 {
                1
            } else {
                0
            },
        ));
    }

    false
}

fn opcode_eq(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    ctx.stack.push(U256::from(if a == b { 1 } else { 0 }));

    false
}

fn opcode_and(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    ctx.stack.push(a & b);

    false
}

fn opcode_or(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    ctx.stack.push(a | b);

    false
}

fn opcode_xor(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    ctx.stack.push(a ^ b);

    false
}
fn opcode_iszero(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();

    ctx.stack
        .push(U256::from(if a == U256::zero() { 1 } else { 0 }));

    false
}
fn opcode_not(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();

    ctx.stack.push(!a);

    false
}
fn opcode_shl(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    ctx.stack.push(b << a);
    false
}

fn opcode_shr(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    ctx.stack.push(b >> a);
    false
}

fn opcode_sar(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    let b_sign = Int256::from_u256(b).sign();
    if b_sign == -1 {
        let mut mask = U256::max_value();
        if !(a > U256::from(256)) {
            mask = mask << (U256::from(256).sub(a));
        }
        ctx.stack.push(b >> a | mask);
    } else {
        ctx.stack.push(b >> a);
    }
    false
}
fn opcode_byte(ctx: &mut Context) -> bool {
    let a = ctx.stack.pop().unwrap();
    let b = ctx.stack.pop().unwrap();

    if a < U256::from(32) {
        ctx.stack
            .push((b >> ((U256::from(31) - a) * 8)) & U256::from(0xFF));
    } else {
        ctx.stack.push(U256::zero());
    }
    false
}
fn opcode_dup(ctx: &mut Context, top: usize) -> bool {
    ctx.stack.push(ctx.stack[ctx.stack.len() - (top - 1) - 1]);
    false
}
fn opcode_swap(ctx: &mut Context, with: usize) -> bool {
    let len = ctx.stack.len();
    let top = ctx.stack[len - 1];
    ctx.stack[len - 1] = ctx.stack[len - with - 1];
    ctx.stack[len - with - 1] = top;
    false
}
fn opcode_pc(ctx: &mut Context) -> bool {
    ctx.stack.push(U256::from(ctx.pc));
    false
}
fn opcode_gas(ctx: &mut Context) -> bool {
    ctx.stack.push(ctx.gas);
    false
}
fn opcode_jump(ctx: &mut Context) -> bool {
    let to = ctx.stack.pop().unwrap();
    if to >= U256::from(ctx.code.len()) {
        return true;
    } else if !ctx.valid_jumpdests.contains(&to) {
        return true;
    }
    ctx.pc = to;
    false
}
fn opcode_jumpi(ctx: &mut Context) -> bool {
    let to = ctx.stack.pop().unwrap();
    let can_we = ctx.stack.pop().unwrap();
    if can_we > U256::zero() {
        if to >= U256::from(ctx.code.len()) {
            return true;
        } else if !ctx.valid_jumpdests.contains(&to) {
            return true;
        }
        ctx.pc = to;
    } else {
        ctx.pc += U256::one();
    }
    false
}
fn opcode_jumpdest() -> bool {
    false
}
fn opcode_invalid(_: &mut Context) -> bool {
    true
}
fn opcode_mstore(ctx: &mut Context) -> bool {
    let offset = ctx.stack.pop().unwrap();
    let value_in_u256 = ctx.stack.pop().unwrap();
    let mut in_u8 = [0u8; 32];
    value_in_u256.to_big_endian(&mut in_u8);
    ctx.memory.store(offset.as_u32() as usize, &in_u8.to_vec());
    false
}
fn opcode_mstore8(ctx: &mut Context) -> bool {
    let offset = ctx.stack.pop().unwrap();
    let value_in_u256 = ctx.stack.pop().unwrap();
    let mut in_u8 = [0u8; 1];
    in_u8[0] = value_in_u256.as_u32() as u8;
    ctx.memory.store(offset.as_u32() as usize, &in_u8.to_vec());
    false
}
fn opcode_mload(ctx: &mut Context) -> bool {
    let offset = ctx.stack.pop().unwrap();
    let val = ctx.memory.load(offset.as_u32() as usize, 32);
    let mut to_push = U256::zero();
    for i in 0..val.len() {
        to_push = to_push << 8 | U256::from(val[i]);
    }

    ctx.stack.push(to_push);
    false
}
fn opcode_sha3(ctx: &mut Context) -> bool {
    let offset = ctx.stack.pop().unwrap();
    let len = ctx.stack.pop().unwrap();
    let val = ctx
        .memory
        .load(offset.as_u32() as usize, len.as_u32() as usize);
    let mut hash = [0u8; 32];
    keccak_256(&val, &mut hash);
    let ans = U256::from(hash);
    ctx.stack.push(ans);
    false
}
fn opcode_msize(ctx: &mut Context) -> bool {
    ctx.stack.push(U256::from(ctx.memory.msize() as u64));
    false
}
fn opcode_address(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack
        .push(U256::from_str_radix(info.tx.as_ref().unwrap().to.as_ref().unwrap(), 16).unwrap());
    false
}
fn opcode_caller(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack
        .push(U256::from_str_radix(info.tx.as_ref().unwrap().from.as_ref().unwrap(), 16).unwrap());
    false
}
fn opcode_origin(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack.push(
        U256::from_str_radix(info.tx.as_ref().unwrap().origin.as_ref().unwrap(), 16).unwrap(),
    );
    false
}
fn opcode_gasprice(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack.push(
        U256::from_str_radix(info.tx.as_ref().unwrap().gasprice.as_ref().unwrap(), 16).unwrap(),
    );
    false
}
fn opcode_basefee(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack.push(
        U256::from_str_radix(info.block.as_ref().unwrap().basefee.as_ref().unwrap(), 16).unwrap(),
    );
    false
}
fn opcode_coinbase(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack.push(
        U256::from_str_radix(info.block.as_ref().unwrap().coinbase.as_ref().unwrap(), 16).unwrap(),
    );
    false
}
fn opcode_timestamp(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack.push(
        U256::from_str_radix(info.block.as_ref().unwrap().timestamp.as_ref().unwrap(), 16).unwrap(),
    );
    false
}
fn opcode_number(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack.push(
        U256::from_str_radix(info.block.as_ref().unwrap().number.as_ref().unwrap(), 16).unwrap(),
    );
    false
}
fn opcode_difficulty(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack.push(
        U256::from_str_radix(
            info.block.as_ref().unwrap().difficulty.as_ref().unwrap(),
            16,
        )
        .unwrap(),
    );
    false
}
fn opcode_gaslimit(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack.push(
        U256::from_str_radix(info.block.as_ref().unwrap().gaslimit.as_ref().unwrap(), 16).unwrap(),
    );
    false
}
fn opcode_chainid(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack.push(
        U256::from_str_radix(info.block.as_ref().unwrap().chainid.as_ref().unwrap(), 16).unwrap(),
    );
    false
}
fn u256_to_address(value: U256) -> [u8; 20] {
    let val: [u8; 32] = value.into();
    let mut address: [u8; 20] = [0u8; 20];
    for x in 12..32 {
        address[x - 12] = val[x];
    }
    address
}

fn opcode_balance(ctx: &mut Context) -> bool {
    let address = u256_to_address(ctx.stack.pop().unwrap());
    let account = ctx.world_state.get(&address);

    if let Some(account_) = account {
        ctx.stack.push(account_.balance);
    } else {
        ctx.stack.push(U256::from(0));
    }
    false
}
fn opcode_selfbalance(ctx: &mut Context, info: &Evmtest) -> bool {
    let address = u256_to_address(
        U256::from_str_radix(info.tx.as_ref().unwrap().to.as_ref().unwrap(), 16).unwrap(),
    );
    let account = ctx.world_state.get(&address);

    if let Some(account_) = account {
        ctx.stack.push(account_.balance);
    } else {
        ctx.stack.push(U256::from(0));
    }
    false
}
fn opcode_value(ctx: &mut Context, info: &Evmtest) -> bool {
    ctx.stack
        .push(U256::from_str_radix(info.tx.as_ref().unwrap().value.as_ref().unwrap(), 16).unwrap());
    false
}
fn opcode_blockhash() -> bool {
    false
}
fn opcode_calldataload(ctx: &mut Context) -> bool {
    let offset = ctx.stack.pop().unwrap();

    let data = ctx.calldataload(offset, 32);

    ctx.stack.push(U256::from(&data[..]));
    false
}
fn opcode_calldatasize(ctx: &mut Context) -> bool {
    ctx.stack.push(ctx.calldatasize());
    false
}

fn opcode_calldatacopy(ctx: &mut Context) -> bool {
    let destoffset = ctx.stack.pop().unwrap();
    let offset = ctx.stack.pop().unwrap();
    let size = ctx.stack.pop().unwrap();

    let data = ctx.calldataload(offset, size.as_u64() as usize);
    ctx.memory.store(destoffset.as_u64() as usize, &data);
    false
}
fn opcode_codecopy(ctx: &mut Context) -> bool {
    let destoffset = ctx.stack.pop().unwrap();
    let offset = ctx.stack.pop().unwrap();
    let size = ctx.stack.pop().unwrap();

    let mut code = ctx.code.to_vec();

    let len = code.len();
    if (offset + size).as_u64() as usize > len {
        code.resize((offset + size).as_u64() as usize, 0);
    }

    let to_copy = code[(offset.as_u64() as usize)..((offset + size).as_u64() as usize)].to_vec();

    ctx.memory.store(destoffset.as_u64() as usize, &to_copy);
    false
}
fn opcode_extcodecopy(ctx: &mut Context) -> bool {
    let address = ctx.stack.pop().unwrap();
    let destoffset = ctx.stack.pop().unwrap();
    let offset = ctx.stack.pop().unwrap();
    let size = ctx.stack.pop().unwrap();

    let mut code = ctx
        .world_state
        .get(&u256_to_address(address))
        .unwrap()
        .clone()
        .code;

    let len = code.len();
    if (offset + size).as_u64() as usize > len {
        code.resize((offset + size).as_u64() as usize, 0);
    }

    let to_copy = code[(offset.as_u64() as usize)..((offset + size).as_u64() as usize)].to_vec();

    ctx.memory.store(destoffset.as_u64() as usize, &to_copy);
    false
}
fn opcode_extcodehash(ctx: &mut Context) -> bool {
    let address = ctx.stack.pop().unwrap();

    if let Some(account_) = ctx.world_state.get(&u256_to_address(address)) {
        if account_.code.len() == 0 {
            ctx.stack.push(U256::zero());
        } else {
            let mut hash = [0u8; 32];
            keccak_256(&account_.code, &mut hash);
            let ans = U256::from(hash);
            ctx.stack.push(ans);
        }
    } else {
        ctx.stack.push(U256::zero());
    }

    false
}
fn opcode_codesize(ctx: &mut Context) -> bool {
    ctx.stack.push(U256::from(ctx.code.len()));
    false
}
fn opcode_extcodesize(ctx: &mut Context) -> bool {
    let address_in_u256 = ctx.stack.pop().unwrap();
    let address = u256_to_address(address_in_u256);

    if let Some(__) = ctx.world_state.get(&address) {
        ctx.stack.push(U256::from(__.code.len()));
    } else {
        ctx.stack.push(U256::from(0));
    }
    false
}
fn opcode_sstore(ctx: &mut Context, info: &Evmtest) -> bool {
    let key = ctx.stack.pop().unwrap();
    let value = ctx.stack.pop().unwrap();
    let mut address = [0u8; 20];
    if let Some(tx_) = info.tx.as_ref() {
        if let Some(to_) = tx_.to.as_ref() {
            address = u256_to_address(U256::from_str_radix(to_, 16).unwrap());
        }
    }

    let account_ = ctx.world_state.get(&address);

    if let Some(account) = account_ {
        account.storage.store(key, value);
    } else {
        let mut account = Account::new();
        account.storage.store(key, value);
        ctx.world_state.set(&address, account);
    }
    false
}

fn opcode_sload(ctx: &mut Context, info: &Evmtest) -> bool {
    let key = ctx.stack.pop().unwrap();
    let mut address = [0u8; 20];
    if let Some(tx_) = info.tx.as_ref() {
        if let Some(to_) = tx_.to.as_ref() {
            address = u256_to_address(U256::from_str_radix(to_, 16).unwrap());
        }
    }

    let account_ = ctx.world_state.as_ref(&address);

    if let Some(account) = account_ {
        if let Some(value) = account.storage.get(&key) {
            ctx.stack.push(*value);
        } else {
            ctx.stack.push(U256::zero());
        }
    } else {
        ctx.stack.push(U256::zero());
    }
    false
}
fn opcode_log(ctx: &mut Context, info: &Evmtest, n_topics: usize) -> bool {
    let offset = ctx.stack.pop().unwrap();
    let size = ctx.stack.pop().unwrap();
    let data = ctx
        .memory
        .load(offset.as_u64() as usize, size.as_u64() as usize);
    let mut log = Log::new();
    log.data = hex::encode(&data[..]);
    log.address = info.tx.as_ref().unwrap().to.as_ref().unwrap().clone();

    for _ in 0..n_topics {
        let topic = ctx.stack.pop().unwrap();
        log.topics.push(format!("{:#x}", topic));
    }
    ctx.logs.push(log);
    false
}
fn opcode_return(ctx: &mut Context) -> bool {
    let offset = ctx.stack.pop().unwrap();
    let size = ctx.stack.pop().unwrap();
    let data = ctx
        .memory
        .load(offset.as_u64() as usize, size.as_u64() as usize);
    ctx.returndata = hex::encode(&data[..]);
    ctx.stopped = true;
    false
}
fn opcode_returndatasize(ctx: &mut Context) -> bool {
    ctx.stack
        .push(U256::from(hex::decode(&ctx.returndata).unwrap().len()));
    false
}
fn opcode_returndatacopy(ctx: &mut Context) -> bool {
    let dest = ctx.stack.pop().unwrap();
    let offset = ctx.stack.pop().unwrap();
    let size = ctx.stack.pop().unwrap();

    let mut returndata = hex::decode(&ctx.returndata).unwrap();

    if offset + size > U256::from(returndata.len()) {
        returndata.resize((offset - size).as_u64() as usize, 0);
    }
    ctx.memory.store(
        dest.as_u32() as usize,
        &returndata[(offset.as_u64() as usize)..(size.as_u64() as usize)].to_vec(),
    );

    false
}
fn opcode_revert(ctx: &mut Context) -> bool {
    let offset = ctx.stack.pop().unwrap();
    let size = ctx.stack.pop().unwrap();
    let data = ctx
        .memory
        .load(offset.as_u64() as usize, size.as_u64() as usize);
    ctx.returndata = hex::encode(&data[..]);
    true
}

//@note gas as argument and sath mai info implement with setting value in it.
fn opcode_call(ctx: &mut Context, info: &Evmtest) -> bool {
    let gas = ctx.stack.pop().unwrap();
    let address = ctx.stack.pop().unwrap();
    let value = ctx.stack.pop().unwrap();
    let argsoffset = ctx.stack.pop().unwrap();
    let argssize = ctx.stack.pop().unwrap();
    let retoffset = ctx.stack.pop().unwrap();
    let retsize = ctx.stack.pop().unwrap();

    let code = ctx
        .world_state
        .as_ref(&u256_to_address(address))
        .unwrap()
        .code
        .clone();

    let calldata = ctx
        .memory
        .load(argsoffset.as_u64() as usize, argssize.as_u64() as usize);

    let mut test = info.clone();

    let mut address_from = [0u8; 20];
    if let Some(tx_) = info.tx.as_ref() {
        if let Some(to_) = tx_.to.as_ref() {
            address_from = u256_to_address(U256::from_str_radix(to_, 16).unwrap());
        }
    }

    if let Some(tx) = test.tx.as_mut() {
        tx.to = Some(hex::encode(u256_to_address(address)));
        tx.from = Some(hex::encode(&address_from[..]));
        tx.value = Some(value.to_string());
    } else {
        let tx = TX {
            data: None,
            from: Some(hex::encode(&address_from[..])),
            to: Some(hex::encode(u256_to_address(address))),
            gasprice: None,
            origin: None,
            value: Some(value.to_string()),
        };

        test.tx = Some(tx);
    }

    let result = evm(&code, ctx.world_state, &test, calldata, gas);

    let returndata = hex::decode(&result.returndata).unwrap();
    ctx.returndata = result.returndata;
    ctx.memory.store(
        retoffset.as_u32() as usize,
        &returndata[0..(retsize.as_u64() as usize)].to_vec(),
    );

    if !result.success {
        ctx.stack.push(U256::zero());
    } else {
        ctx.stack.push(U256::one());
    }

    false
}
fn opcode_staticall(ctx: &mut Context, info: &Evmtest) -> bool {
    let gas = ctx.stack.pop().unwrap();
    let address = ctx.stack.pop().unwrap();
    let argsoffset = ctx.stack.pop().unwrap();
    let argssize = ctx.stack.pop().unwrap();
    let retoffset = ctx.stack.pop().unwrap();
    let retsize = ctx.stack.pop().unwrap();

    let code = ctx
        .world_state
        .as_ref(&u256_to_address(address))
        .unwrap()
        .code
        .clone();

    let calldata = ctx
        .memory
        .load(argsoffset.as_u64() as usize, argssize.as_u64() as usize);

    let mut test = info.clone();

    let mut address_from = [0u8; 20];
    if let Some(tx_) = info.tx.as_ref() {
        if let Some(to_) = tx_.to.as_ref() {
            address_from = u256_to_address(U256::from_str_radix(to_, 16).unwrap());
        }
    }

    if let Some(tx) = test.tx.as_mut() {
        tx.to = Some(hex::encode(u256_to_address(address)));
        tx.from = Some(hex::encode(&address_from[..]));
    } else {
        let tx = TX {
            data: None,
            from: Some(hex::encode(&address_from[..])),
            to: Some(hex::encode(u256_to_address(address))),
            gasprice: None,
            origin: None,
            value: None,
        };
        test.tx = Some(tx);
    }

    test.static_call = Some(true);

    let result = evm(&code, ctx.world_state, &test, calldata, gas);

    let mut returndata = hex::decode(&result.returndata).unwrap();

    if retsize.as_u64() as usize > returndata.len() {
        returndata.resize(retsize.as_u64() as usize, 0);
    }

    ctx.returndata = result.returndata;

    ctx.memory.store(
        retoffset.as_u32() as usize,
        &returndata[0..(retsize.as_u64() as usize)].to_vec(),
    );

    if !result.success {
        ctx.stack.push(U256::zero());
    } else {
        ctx.stack.push(U256::one());
    }

    false
}
fn opcode_delegatecall(ctx: &mut Context, info: &Evmtest) -> bool {
    let gas = ctx.stack.pop().unwrap();
    let address = ctx.stack.pop().unwrap();
    let argsoffset = ctx.stack.pop().unwrap();
    let argssize = ctx.stack.pop().unwrap();
    let retoffset = ctx.stack.pop().unwrap();
    let retsize = ctx.stack.pop().unwrap();

    let code = ctx
        .world_state
        .as_ref(&u256_to_address(address))
        .unwrap()
        .code
        .clone();

    let calldata = ctx
        .memory
        .load(argsoffset.as_u64() as usize, argssize.as_u64() as usize);

    let result = evm(&code, ctx.world_state, info, calldata, gas);

    let returndata = hex::decode(&result.returndata).unwrap();
    ctx.returndata = result.returndata;
    ctx.memory.store(
        retoffset.as_u32() as usize,
        &returndata[0..(retsize.as_u64() as usize)].to_vec(),
    );

    if !result.success {
        ctx.stack.push(U256::zero());
    } else {
        ctx.stack.push(U256::one());
    }

    false
}

fn opcode_create(ctx: &mut Context, info: &Evmtest) -> bool {
    let value = ctx.stack.pop().unwrap();
    let offset = ctx.stack.pop().unwrap();
    let size = ctx.stack.pop().unwrap();

    let address = u256_to_address(
        U256::from_str_radix(info.tx.as_ref().unwrap().to.as_ref().unwrap(), 16).unwrap(),
    );

    let nonce: U256;

    let account_option = ctx.world_state.get(&address);
    if let Some(account) = account_option {
        nonce = account.nonce;
        account.nonce += U256::one();
    } else {
        nonce = U256::zero();
        let mut account = Account::new();
        account.nonce = U256::one();
        ctx.world_state.set(&address, account);
    }
    let nonce_as_u8 = u256_to_address(nonce);

    let tohash = [address.to_vec(), nonce_as_u8.to_vec()].concat();
    let mut hash = [0u8; 32];
    keccak_256(&tohash, &mut hash);

    let new_address = hash;

    let code = ctx
        .memory
        .load(offset.as_u32() as usize, size.as_u64() as usize);

    let gas: U256 = U256::max_value();

    let result = evm(&code, ctx.world_state, info, Vec::new(), gas);

    let to_deploy = hex::decode(result.returndata).unwrap();

    let mut a = [0; 20];

    a.copy_from_slice(&new_address[0..20]);

    if let Some(state) = ctx.world_state.get(&a) {
        state.code = to_deploy;
        state.balance = value;
    } else {
        ctx.world_state.set(
            &a,
            Account {
                balance: value,
                nonce: U256::zero(),
                code: to_deploy,
                storage: Storage::new(),
            },
        )
    }

    if !result.success {
        ctx.stack.push(U256::zero());
    } else {
        ctx.stack
            .push(U256::from_str_radix(hex::encode(a).as_str().as_ref(), 16).unwrap());
    }
    return false;
}
fn opcode_selfdestruct(ctx: &mut Context, info: &Evmtest) -> bool {
    let to = ctx.stack.pop().unwrap();

    let address = u256_to_address(
        U256::from_str_radix(info.tx.as_ref().unwrap().to.as_ref().unwrap(), 16).unwrap(),
    );

    let mut val = U256::zero();
    if let Some(account) = ctx.world_state.get(&address) {
        val = account.balance;
        ctx.world_state.set(
            &address,
            Account {
                balance: U256::zero(),
                nonce: U256::zero(),
                code: Vec::new(),
                storage: Storage::new(),
            },
        );
    }
    if let Some(to_account) = ctx.world_state.get(&u256_to_address(to)) {
        to_account.balance += val;
    } else {
        ctx.world_state.set(
            &u256_to_address(to),
            Account {
                balance: val,
                nonce: U256::zero(),
                code: Vec::new(),
                storage: Storage::new(),
            },
        )
    }

    return false;
}
fn call_with_opcode(opcode: u8, ctx: &mut Context, info: &Evmtest) -> bool {
    match opcode {
        0x00 => opcode_stop(ctx),
        0x5f => opcode_zero(ctx),
        0x60 => opcode_push(ctx, 1),
        0x61 => opcode_push(ctx, 2),
        0x62 => opcode_push(ctx, 3),
        0x63 => opcode_push(ctx, 4),
        0x64 => opcode_push(ctx, 5),
        0x65 => opcode_push(ctx, 6),
        0x66 => opcode_push(ctx, 7),
        0x67 => opcode_push(ctx, 8),
        0x68 => opcode_push(ctx, 9),
        0x69 => opcode_push(ctx, 10),
        0x6a => opcode_push(ctx, 11),
        0x6b => opcode_push(ctx, 12),
        0x6c => opcode_push(ctx, 13),
        0x6d => opcode_push(ctx, 14),
        0x6e => opcode_push(ctx, 15),
        0x6f => opcode_push(ctx, 16),
        0x70 => opcode_push(ctx, 17),
        0x71 => opcode_push(ctx, 18),
        0x72 => opcode_push(ctx, 19),
        0x73 => opcode_push(ctx, 20),
        0x74 => opcode_push(ctx, 21),
        0x75 => opcode_push(ctx, 22),
        0x76 => opcode_push(ctx, 23),
        0x77 => opcode_push(ctx, 24),
        0x78 => opcode_push(ctx, 25),
        0x79 => opcode_push(ctx, 26),
        0x7a => opcode_push(ctx, 27),
        0x7b => opcode_push(ctx, 28),
        0x7c => opcode_push(ctx, 29),
        0x7d => opcode_push(ctx, 30),
        0x7e => opcode_push(ctx, 31),
        0x7f => opcode_push(ctx, 32),
        0x50 => opcode_pop(ctx),
        0x01 => opcode_add(ctx),
        0x02 => opcode_mul(ctx),
        0x03 => opcode_sub(ctx),
        0x04 => opcode_div(ctx),
        0x06 => opcode_mod(ctx),
        0x08 => opcode_addmod(ctx),
        0x09 => opcode_mulmod(ctx),
        0x0a => opcode_exp(ctx),
        0x0b => opcode_signextend(ctx),
        0x05 => opcode_sdiv(ctx),
        0x07 => opcode_smod(ctx),
        0x10 => opcode_lt(ctx),
        0x11 => opcode_gt(ctx),
        0x12 => opcode_slt(ctx),
        0x13 => opcode_sgt(ctx),
        0x14 => opcode_eq(ctx),
        0x15 => opcode_iszero(ctx),
        0x19 => opcode_not(ctx),
        0x16 => opcode_and(ctx),
        0x17 => opcode_or(ctx),
        0x18 => opcode_xor(ctx),
        0x1b => opcode_shl(ctx),
        0x1c => opcode_shr(ctx),
        0x1d => opcode_sar(ctx),
        0x1a => opcode_byte(ctx),

        0x80 => opcode_dup(ctx, 1),
        0x81 => opcode_dup(ctx, 2),
        0x82 => opcode_dup(ctx, 3),
        0x83 => opcode_dup(ctx, 4),
        0x84 => opcode_dup(ctx, 5),
        0x85 => opcode_dup(ctx, 6),
        0x86 => opcode_dup(ctx, 7),
        0x87 => opcode_dup(ctx, 8),
        0x88 => opcode_dup(ctx, 9),
        0x89 => opcode_dup(ctx, 10),
        0x8a => opcode_dup(ctx, 11),
        0x8b => opcode_dup(ctx, 12),
        0x8c => opcode_dup(ctx, 13),
        0x8d => opcode_dup(ctx, 14),
        0x8e => opcode_dup(ctx, 15),
        0x8f => opcode_dup(ctx, 16),

        0x90 => opcode_swap(ctx, 1),
        0x91 => opcode_swap(ctx, 2),
        0x92 => opcode_swap(ctx, 3),
        0x93 => opcode_swap(ctx, 4),
        0x94 => opcode_swap(ctx, 5),
        0x95 => opcode_swap(ctx, 6),
        0x96 => opcode_swap(ctx, 7),
        0x97 => opcode_swap(ctx, 8),
        0x98 => opcode_swap(ctx, 9),
        0x99 => opcode_swap(ctx, 10),
        0x9a => opcode_swap(ctx, 11),
        0x9b => opcode_swap(ctx, 12),
        0x9c => opcode_swap(ctx, 13),
        0x9d => opcode_swap(ctx, 14),
        0x9e => opcode_swap(ctx, 15),
        0x9f => opcode_swap(ctx, 16),

        0xfe => opcode_invalid(ctx),
        0x58 => opcode_pc(ctx),
        0x5a => opcode_gas(ctx),
        0x56 => opcode_jump(ctx),
        0x5b => opcode_jumpdest(),
        0x57 => opcode_jumpi(ctx),
        0x52 => opcode_mstore(ctx),
        0x51 => opcode_mload(ctx),
        0x53 => opcode_mstore8(ctx),
        0x59 => opcode_msize(ctx),
        0x20 => opcode_sha3(ctx),
        0x30 => opcode_address(ctx, info),
        0x33 => opcode_caller(ctx, info),
        0x32 => opcode_origin(ctx, info),
        0x3a => opcode_gasprice(ctx, info),
        0x48 => opcode_basefee(ctx, info),
        0x41 => opcode_coinbase(ctx, info),
        0x42 => opcode_timestamp(ctx, info),
        0x43 => opcode_number(ctx, info),
        0x44 => opcode_difficulty(ctx, info),
        0x45 => opcode_gaslimit(ctx, info),
        0x46 => opcode_chainid(ctx, info),
        0x40 => opcode_blockhash(),
        0x31 => opcode_balance(ctx),
        0x34 => opcode_value(ctx, info),
        0x35 => opcode_calldataload(ctx),
        0x36 => opcode_calldatasize(ctx),
        0x37 => opcode_calldatacopy(ctx),
        0x38 => opcode_codesize(ctx),
        0x39 => opcode_codecopy(ctx),
        0x3b => opcode_extcodesize(ctx),
        0x3c => opcode_extcodecopy(ctx),
        0x3f => opcode_extcodehash(ctx),
        0x47 => opcode_selfbalance(ctx, info),
        0x55 => opcode_sstore(ctx, info),
        0x54 => opcode_sload(ctx, info),
        0xa0 => opcode_log(ctx, info, 0),
        0xa1 => opcode_log(ctx, info, 1),
        0xa2 => opcode_log(ctx, info, 2),
        0xa3 => opcode_log(ctx, info, 3),
        0xa4 => opcode_log(ctx, info, 4),
        0xf3 => opcode_return(ctx),
        0xfd => opcode_revert(ctx),
        0xf1 => opcode_call(ctx, info),
        0x3d => opcode_returndatasize(ctx),
        0x3e => opcode_returndatacopy(ctx),
        0xf4 => opcode_delegatecall(ctx, info),
        0xfa => opcode_staticall(ctx, info),
        0xf0 => opcode_create(ctx, info),
        0xff => opcode_selfdestruct(ctx, info),
        // We will halt if nothing is matching
        _ => true,
    }
}
pub fn evm(
    _code: impl AsRef<[u8]>,
    world_state: &mut WorldState,
    info: &Evmtest,
    calldata: Vec<u8>,
    gas: U256,
) -> EvmResult {
    let mut ctx = Context::new(_code.as_ref(), world_state, calldata, gas);

    let mut isstaticcall = false;

    if let Some(staticcall) = info.static_call {
        isstaticcall = staticcall;
    }

    while ctx.pc < U256::from(ctx.code.len()) {
        let opcode = ctx.code[ctx.pc.as_u32() as usize];
        if isstaticcall {
            if STATICCALL_DISSALOWED_OPCODES.contains(&opcode) {
                return EvmResult {
                    stack: ctx.stack,
                    success: false,
                    logs: ctx.logs,
                    returndata: ctx.returndata,
                };
            }
        }

        let got_error = call_with_opcode(opcode, &mut ctx, info);
        if !(opcode == 0x56 || opcode == 0x57) {
            ctx.pc += U256::from(1);
        }
        if ctx.stopped {
            break;
        }
        if got_error {
            return EvmResult {
                stack: ctx.stack,
                success: false,
                logs: ctx.logs,
                returndata: ctx.returndata,
            };
        }
    }

    return EvmResult {
        stack: ctx.stack,
        success: true,
        logs: ctx.logs,
        returndata: ctx.returndata,
    };
}
