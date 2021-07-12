extern crate cpython;
use cpython::{PyResult, Python, py_module_initializer, py_fn, PyBytes};

extern crate num;
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
}

py_module_initializer!(lib, |py, m| {
    m.add(py, "__doc__", "This module is implemented in Rust.")?;
    m.add(py, "ecc_mul", py_fn!(py, ecc_mul(x: &[u8], y: &[u8], k: &[u8])))?;

    Ok(())
});

#[derive(Clone)]
struct Point {
    x: BigInt,
    y: BigInt
}

fn modinv(n: &BigInt, p: &BigInt) -> BigInt {
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

fn ecc_mul(_py: Python, x: &[u8], y: &[u8], k: &[u8]) -> PyResult<(PyBytes, PyBytes)> {

    let p: Point = Point {
        x: BigInt::parse_bytes(x, 10).unwrap(),
        y: BigInt::parse_bytes(y, 10).unwrap()
    };

    let mut n: Point = p.clone();
    let mut q: Option<Point> = None;

    let mut k = BigInt::parse_bytes(k, 10).unwrap();

    while !k.is_zero() {
        if k.is_odd() {
            q = match q {
                None => Some(n.clone()),
                _ => Some(ecc_add(&n, &q.unwrap()))
            }
        }

        n = ecc_add(&n, &n);

        k >>= 1;
    }
    let result = q.unwrap();

    Ok( (PyBytes::new(_py, &result.x.to_signed_bytes_le()), 
         PyBytes::new(_py, &result.y.to_signed_bytes_le())) )
}
