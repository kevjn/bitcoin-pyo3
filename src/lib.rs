use pyo3::PyNumberProtocol;
use pyo3::prelude::*;

use num::bigint::BigInt;
use num::Integer;
use num::One;
use num::Zero;

#[macro_use]
extern crate lazy_static;
lazy_static! {
    // Constants for bitcoin elliptic curve (secp256k1)
    static ref P: BigInt = 
        BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();

    // Generator point
    static ref G: Point = 
        Point {
            x: BigInt::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
            y: BigInt::parse_bytes(b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16).unwrap()
        };
}

#[pymodule]
fn bitcoin(py: Python, m: &PyModule) -> PyResult<()> {
    m.add("__doc__", "This module is implemented in Rust.")?;
    m.add_class::<Point>()?;

    Ok(())
}

#[pyclass]
#[derive(Clone)]
struct Point {
    #[pyo3(get)]
    x: BigInt,
    #[pyo3(get)]
    y: BigInt
}

#[pymethods]
impl Point {
    #[new]
    fn new(x: BigInt, y: BigInt) -> Self {
        Point { x, y }
    }
}

#[pyproto]
impl PyNumberProtocol for Point {
    fn __add__(p: Point, q: Point) -> Self {
        ecc_add(&p, &q)
    }

    fn __mul__(p: Point, k: BigInt) -> Self {
        ecc_mul(p, k)
    }
}

fn modinv(n: &BigInt, p: &BigInt) -> BigInt {
    // TODO: use binary exponentiation for modinv
    if p.is_one() { return BigInt::one() }

    let (mut a, mut m, mut x, mut inv) = (n.clone(), p.clone(), BigInt::zero(), BigInt::one());

    // handle negative numbers
    while a < BigInt::zero() { a += p }

    while a > BigInt::one() {
        let (div, rem) = a.div_rem(&m);
        inv -= div * &x;
        a = rem;
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x, &mut inv);
    }
 
    if inv < BigInt::zero() { inv += p }
    inv
}

fn ecc_add(p: &Point, q: &Point) -> Point {
    assert!(!(p.x == q.x && p.y != q.y), "Not implemented");

    let m: BigInt = if p.x == q.x {
        3u32 * &p.x * &p.x * modinv(&(2u32 * &p.y), &*P)
    } else {
       (&p.y - &q.y) * modinv(&(&p.x - &q.x), &*P)
    };

    let rx = (&m * &m - &p.x - &q.x).mod_floor(&*P);
    let ry = (&m * (&p.x - &rx) - &p.y).mod_floor(&*P);

    Point {x: rx, y: ry}
}

fn ecc_mul(mut p: Point, mut k: BigInt) -> Point {
    let mut q: Option<Point> = None;

    while !k.is_zero() {
        if k.is_odd() {
            q = match q {
                None => Some(p.clone()),
                _ => Some(ecc_add(&p, &q.unwrap()))
            }
        }

        p = ecc_add(&p, &p);

        k >>= 1;
    }
    q.unwrap()
}
