use pyo3::PyNumberProtocol;
use pyo3::PyObjectProtocol;
use pyo3::prelude::*;

use pyo3::types::PyBytes;
use num::ToPrimitive;

// maybe replace with https://docs.rs/crypto-bigint/0.2.2/crypto_bigint/index.html
use num::bigint::BigInt;
use num::bigint::Sign;
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

    static ref N: BigInt = 
        BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();

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
    m.add_class::<Signature>()?;

    m.add_class::<TxIn>()?;
    m.add_class::<TxOut>()?;
    m.add_class::<Tx>()?;

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
        // return the compressed SEC (Standards for Efficient Cryptography) bytes encoding of the point
        PyBytes::new(py, &encode(self)).into()
    }

    #[staticmethod]
    fn decode(sec: &[u8]) -> Self {
        let (prefix, elements) = sec.split_first().unwrap();
        let x = BigInt::from_bytes_be(Sign::Plus, elements);

        // solve y^2 = x^3 + 7 (mod P) for y
        let mut y: BigInt = (x.modpow(&BigInt::from(3u32), &*P) + 7u32) % &*P;
        y = y.modpow(&(&*P + 1u32).div_floor(&BigInt::from(4u32)), &*P);
        if y.is_even() != (prefix == &2u8) {
            y = &*P - y; // flip if needed
        }

        Point { x, y }
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
#[derive(Clone)]
struct Script {
    commands: Vec<Command>
}

#[pyclass]
struct Signature {
    #[pyo3(get)]
    r: BigInt,
    #[pyo3(get)]
    s: BigInt
}

#[pymethods]
impl Signature {
    #[new]
    fn new(r: BigInt, s: BigInt) -> Self {
        Signature { r, s }
    }

    fn encode(&self, py: Python) -> PyObject {
        let mut rbin = self.r.to_bytes_be().1;
        rbin.resize(32, 0);

        if rbin[1] < 0x80 {
            // remove leading zeros
            rbin = rbin.into_iter().skip_while(|x| *x == 0u8).collect();
        }

        let mut sbin = self.s.to_bytes_be().1;
        sbin.resize(32, 0);

        if sbin[1] < 0x80 {
            // remove leading zeros
            sbin = sbin.into_iter().skip_while(|x| *x == 0u8).collect();
        }

        let content: Vec<u8> = [vec![2, rbin.len() as u8], rbin, 
                                vec![2, sbin.len() as u8], sbin].concat();

        let result: Vec<u8> = [vec![0x30, content.len() as u8], content].concat();

        PyBytes::new(py, &result).into()
    }

    #[staticmethod]
    fn decode(der: &[u8]) -> Self {
        let mut idx = 0;
        assert_eq!(0x30, der[idx]);
        idx += 1;
        let length = der[idx];
        idx += 1;
        assert_eq!(length, der.len() as u8 - 2);
        assert_eq!(0x02, der[idx]);
        idx += 1;

        // read r
        let rlen = der[idx] as usize;
        idx += 1;
        let r = BigInt::from_bytes_be(Sign::Plus, &der[idx .. idx + rlen]);
        idx += rlen;

        assert_eq!(0x02, der[idx]);
        idx += 1;

        // read s
        let slen = der[idx] as usize;
        idx += 1;
        let s = BigInt::from_bytes_be(Sign::Plus, &der[idx .. idx + slen]);

        Signature { r, s }
    }

}

fn op_dup(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.is_empty() {
        return false
    }

    let last: Vec<u8> = stack.last().unwrap().to_vec();
    stack.push(last);
    true
}

fn op_equalverify(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 2 {
        return false
    }

    stack.pop() == stack.pop()
}

fn op_checksig(stack: &mut Vec<Vec<u8>>, z: &BigInt) -> bool {
    if stack.len() < 2 {
        return false
    }

    let sec = stack.pop().unwrap();
    let der = stack.pop().unwrap();
    let der = der.split_last().unwrap().1;

    let point = Point::decode(&sec);
    let sig = Signature::decode(&der);

    // verify the signature by using the public key (point), signature hash (z) and signature (r,s)
    let w = modinv(&sig.s, &*N);
    let u = z * &w % &*N;
    let v = &sig.r * &w % &*N;

    let total = ecc_add(&ecc_mul(G.clone(), u), &ecc_mul(point, v));

    let result = total.x == sig.r;
    stack.push(vec![result as u8]);
    result
}

#[pymethods]
impl Script {
    #[new]
    fn new(commands: Vec<Command>) -> Self {
        Script { commands }
    }

    fn encode<'a>(&self, py: Python<'a>) -> PyResult<&'a PyBytes>  {
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

        Ok(PyBytes::new(py, &prefix))
    }

    fn evaluate(&self, z: BigInt) -> bool {
        let mut stack: Vec<Vec<u8>> = Vec::new();

        self.commands.iter().all(|cmd| {
            match cmd {
                Command::Operation(x) => {
                    match x {
                        69 => op_dup(&mut stack),
                        136 => op_equalverify(&mut stack),
                        172 => op_checksig(&mut stack, &z),
                        _ => panic!("unrecognized op: {}", x)
                    }
                }
                Command::Element(x) => { stack.push(x.to_vec()); true }
            }
        })
    }
}

#[pyproto]
impl PyObjectProtocol for Script {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("<Script with commands={:?}>", self.commands))
    }
}

#[pyproto]
impl PyNumberProtocol for Script {
    fn __add__(this: Script, other: Script) -> Self {
        let commands: Vec<Command> = [this.commands, other.commands].concat();
        Script { commands }
    }
}

#[pyclass]
#[derive(FromPyObject)]
struct TxIn {
    #[pyo3(get)]
    prev_tx: Vec<u8>, // hash256 of UTXO as big endian (32-byte)
    #[pyo3(get)]
    prev_idx: u32, // the index number of the UTXO to be spent (4-byte)
    #[pyo3(get)]
    script_sig: Script // UTXO unlocking script (var size)
}

#[pymethods]
impl TxIn {
    #[new]
    fn new(prev_tx: Vec<u8>, prev_idx: u32, script_sig: Script) -> Self {
        TxIn { prev_tx, prev_idx, script_sig }
    }

    fn encode<'a>(&self, py: Python<'a>) -> PyResult<&'a PyBytes>  {
        let result = [
            &self.prev_tx[..],
            &self.prev_idx.to_le_bytes(),
            self.script_sig.encode(py).unwrap().as_bytes(),
            &0xffffffffu32.to_le_bytes() // sequence (4-byte)
        ].concat();

        Ok(PyBytes::new(py, &result))
    }
}

#[pyclass]
#[derive(FromPyObject)]
struct TxOut {
    #[pyo3(get)]
    amount: u64, // in 1e-8 units (8 bytes)
    #[pyo3(get)]
    script_pubkey: Script
}

#[pymethods]
impl TxOut {
    #[new]
    fn new(amount: u64, script_pubkey: Script) -> Self {
        TxOut { amount, script_pubkey}
    }

    fn encode<'a>(&self, py: Python<'a>) -> PyResult<&'a PyBytes>  {
        let result = [
            &self.amount.to_le_bytes()[..],
            self.script_pubkey.encode(py).unwrap().as_bytes()
        ].concat();

        Ok(PyBytes::new(py, &result))
    }
}

#[pyclass]
struct Tx {
    version: u32, // version (4 bytes)
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>
}

#[pymethods]
impl Tx {
    #[new]
    fn new(version: u32, tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> Self {
        Tx { version, tx_ins, tx_outs}
    }

    fn encode(&self, py: Python) -> PyObject {

        let result = [
            &self.version.to_le_bytes()[..],

            &self.tx_ins.len().to_le_bytes()[..1], // assume there are less than 256 input txs!
            &self.tx_ins.iter().flat_map(|tx_in| tx_in.encode(py).unwrap().as_bytes())
                .copied().collect::<Vec<u8>>(),

            &self.tx_outs.len().to_le_bytes()[..1], // assume there are less than 256 output txs!
            &self.tx_outs.iter().flat_map(|tx_out| tx_out.encode(py).unwrap().as_bytes())
                .copied().collect::<Vec<u8>>(),

            &0u32.to_le_bytes(), // locktime (not used)
        ].concat();

        PyBytes::new(py, &result).into()
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