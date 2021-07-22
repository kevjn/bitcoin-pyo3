use pyo3::PyNumberProtocol;
use pyo3::PyObjectProtocol;
use pyo3::prelude::*;

use pyo3::types::PyBytes;
use num::ToPrimitive;

// maybe replace with https://docs.rs/crypto-bigint/0.2.2/crypto_bigint/index.html
use num::bigint::BigInt;
use num::Integer;
use num::One;
use num::Zero;

// Hashing
use sha2::{Sha256, Digest};
use ripemd160::{Ripemd160};

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
fn bitcoin(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add("__doc__", "This module is implemented in Rust.")?;
    m.add_class::<Point>()?;
    m.add_class::<Script>()?;

    m.add_function(wrap_pyfunction!(hash160, m)?)?;

    Ok(())
}

#[pyclass]
#[derive(Clone)]
struct Point {
    #[pyo3(get)]
    x: BigInt, // 32 bytes = 256 bits
    #[pyo3(get)]
    y: BigInt
}

#[pymethods]
impl Point {
    #[new]
    fn new(x: BigInt, y: BigInt) -> Self {
        Point { x, y }
    }

    fn encode(&self, py: Python) -> PyObject {
        // return the compressed SEC bytes encoding of the point
        PyBytes::new(py, &encode(self)).into()
    }

    fn address(&self) -> PyResult<String> {
        // encode Point (public key) into bytes with the prepended version (0x6f for test network)
        let mut pkb_hash: Vec<u8> = vec![0x6f];
        pkb_hash.extend(hash160(&encode(self)));

        // checksum is the first 4 bytes
        let checksum = &hash256(&pkb_hash)[..4];

        // append to get the full 25-byte bitcoin address
        pkb_hash.extend(checksum);

        // return the b58 encoded address
        Ok(b58encode(&pkb_hash))
    }
}

#[pyproto]
impl PyObjectProtocol for Point {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("<Point at x={}, y={}>", self.x, self.y))
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

#[derive(Clone, Debug)]
#[derive(FromPyObject)]
enum Command {
    Operation(u8),
    Element(Vec<u8>)
}

#[pyclass]
struct Script {
    commands: Vec<Command>
}

#[pymethods]
impl Script {
    #[new]
    fn new(commands: Vec<Command>) -> Self {
        Script { commands }
    }

    fn encode(&self, py: Python) -> PyObject {
        let mut bytes: Vec<u8> = Vec::new();
        // Operations get encoded as a single byte
        // Elements get encoded as encoding length + element
        for cmd in self.commands.iter() {
            match cmd {
                Command::Operation(x) => bytes.push(*x),
                Command::Element(x) => { 
                    bytes.push(x.len() as u8);
                    bytes.extend(x);
                }
            };
        }

        // prepend the encoded length of the script
        let mut prefix: Vec<u8> = Vec::new();
        prefix.push(bytes.len() as u8);
        prefix.extend(bytes);

        PyBytes::new(py, &prefix).into()
    }
}

#[pyproto]
impl PyObjectProtocol for Script {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("<Script with commands={:?}>", self.commands))
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

fn encode(p: &Point) -> Vec<u8> {
    let mut prefix = if p.y.is_even() {
        b"\x02".to_vec()
    } else {
        b"\x03".to_vec()
    };
    let mut point = p.x.to_signed_bytes_le();
    point.resize(32, 0);
    point.reverse(); // switch to big endian

    prefix.extend(point);
    assert_eq!(prefix.len(), 33);
    prefix
}

const B58ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58encode(bytes: &[u8]) -> String {
    // Base256-to-Base58 conversion
    // version is 1 byte, pkb_hash 20 bytes, checksum 4 bytes
    assert_eq!(bytes.len(), 25);

    // TODO: count leading zero bytes

    let mut string: Vec<char> = Vec::new();
    let mut n = BigInt::from_signed_bytes_be(bytes);
    while n > BigInt::one() {
        let (div, idx) = n.div_rem(&BigInt::from(58));
        n = div;
        string.push(B58ALPHABET.as_bytes()[idx.to_usize().unwrap()] as char);
    }

    string.reverse();
    string.into_iter().collect()
}

#[pyfunction]
fn hash160(bytes: &[u8]) -> [u8; 20] {
    // sha256
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let bytes = hasher.finalize();

    // ripemd160
    let mut hasher = Ripemd160::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hash256(bytes: &[u8]) -> [u8; 32] {
    // sha256 2x
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let bytes = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}