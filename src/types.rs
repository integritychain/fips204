// Note: These types will be reworked; probably struct shells

pub(crate) trait Zero {
    fn zero() -> Self;
}

pub(crate) type Rq = i32;
pub(crate) type R = [Rq; 256];

impl Zero for R {
    fn zero() -> Self { [0i32; 256] }
}


pub(crate) type Tq = i32;
pub(crate) type T = [Tq; 256];


pub(crate) type Zq = i32;
