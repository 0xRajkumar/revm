use primitive_types::U256;
use std::ops::{Div, Neg, Rem};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Int256(pub U256);

impl Int256 {
    pub fn from_u256(value: U256) -> Self {
        Int256(value)
    }

    pub fn sign(&self) -> i32 {
        if self.0.is_zero() {
            0
        } else if self.0 >= U256::from(1) << 255 {
            -1
        } else {
            1
        }
    }
}

impl Neg for Int256 {
    type Output = Int256;

    fn neg(self) -> Int256 {
        if self.0.is_zero() {
            self
        } else {
            Int256(!self.0 + U256::one())
        }
    }
}

impl Div for Int256 {
    type Output = Int256;

    fn div(self, rhs: Int256) -> Int256 {
        let lhs_sign = self.sign();
        let rhs_sign = rhs.sign();

        let lhs_abs = if lhs_sign == -1 { self.neg() } else { self };
        let rhs_abs = if rhs_sign == -1 { rhs.neg() } else { rhs };

        let result = Int256::from_u256(lhs_abs.0 / rhs_abs.0);

        if lhs_sign != rhs_sign {
            result.neg()
        } else {
            result
        }
    }
}

impl Rem for Int256 {
    type Output = Int256;

    fn rem(self, rhs: Int256) -> Int256 {
        let lhs_sign = self.sign();

        let lhs_abs = if lhs_sign == -1 { self.neg() } else { self };
        let rhs_abs = if rhs.sign() == -1 { rhs.neg() } else { rhs };

        let mut result = Int256(lhs_abs.0 % rhs_abs.0);

        if lhs_sign == -1 {
            result = result.neg();
        }

        result
    }
}
