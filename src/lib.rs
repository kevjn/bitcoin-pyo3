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
use num::Num;

// Used for parsing byte streams
// use std::io::BufReader;
// use std::io::Read;

// encoding/decoding structs
use serde::{Serialize, Deserialize};
use serde::ser::{Serializer, SerializeSeq, SerializeTuple};
use serde::de::{Deserializer, Visitor, SeqAccess};
use bincode::{DefaultOptions, Options};

// convert Vec<T> to an array
use std::convert::TryInto;

// formatting
use std::fmt;

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
    m.add_function(wrap_pyfunction!(hash256, m)?)?;

    Ok(())
}

#[pyclass]
#[derive(Debug, Clone, bitcoin_macros::Repr)]
struct Point {
    #[pyo3(get)]
    x: BigInt, // 32 bytes = 256 bits
    #[pyo3(get)]
    y: BigInt
}

impl Serialize for Point {
    // According to Standards of Efficient Cryptography a compressed coordinate is encoded as:
    // 1. 0x02/0x03 byte header to indicate a compressed ECDSA point, 0x02 for even y, 0x03 for odd y
    // 2. the x coordinate as a 32-byte big-endian integer
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer,
    {
        let mut tup = serializer.serialize_tuple(2)?;
        tup.serialize_element::<u8>(&[0x02, 0x03][self.y.is_odd() as usize])?;
        let mut x = self.x.to_signed_bytes_le();
        x.resize(32, 0);
        x.reverse(); // switch to big endian
        tup.serialize_element::<[u8; 32]>(&x.try_into().unwrap())?;
        tup.end()
    }
}

struct PointVisitor;
impl<'de> Visitor<'de> for PointVisitor {
    type Value = Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Point")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error> where V: SeqAccess<'de>,
    {
        assert_eq!(Some(2), seq.size_hint());
        let prefix = seq.next_element::<u8>()?.unwrap();
        let elements = seq.next_element::<[u8; 32]>()?.unwrap();
        let x = BigInt::from_bytes_be(Sign::Plus, &elements);

        // solve y^2 = x^3 + 7 (mod P) for y
        let mut y: BigInt = (x.modpow(&BigInt::from(3u32), &*P) + 7u32) % &*P;
        y = y.modpow(&(&*P + 1u32).div_floor(&BigInt::from(4u32)), &*P);
        if y.is_even() != (prefix == 2u8) {
            y = &*P - y; // flip if needed
        }

        Ok(Point { x, y })
    }
}

impl<'de> Deserialize<'de> for Point {
    fn deserialize<D>(deserializer: D) -> Result<Point, D::Error> where D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(2, PointVisitor)
    }
}

#[bitcoin_macros::serdes]
#[pymethods]
impl Point {
    #[new]
    fn new(x: BigInt, y: BigInt) -> Self {
        Point { x, y }
    }

    fn address(&self, py: Python) -> PyResult<String> {
        // encode Point (public key) into bytes with the prepended version (0x6f for test network)
        let mut pkb_hash: Vec<u8> = vec![0x6f];
        pkb_hash.extend(hash160(&self.encode(py).unwrap().as_bytes()));

        // checksum is the first 4 bytes
        let checksum = &hash256(&pkb_hash)[..4];

        // append to get the full 25-byte bitcoin address
        pkb_hash.extend(checksum);

        // return the b58 encoded address
        Ok(b58encode(&pkb_hash))
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

#[derive(Clone, FromPyObject, Serialize)]
#[serde(untagged)]
enum Command {
    Operation(u8),
    Element(Vec<u8>)
}

impl ::core::fmt::Debug for Command {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match self {
            Command::Operation(x) => write!(f, "Operation({:?})", x),
            Command::Element(x) => write!(f, "Element(0x{})", x.iter().map(|b| format!("{:02X}", b)).collect::<String>() )
        }
    }
}

impl IntoPy<PyObject> for Command {
    fn into_py(self, py: Python) -> PyObject {
        let bytes = match self {
            Command::Operation(x) => x.to_le_bytes().to_vec(),
            Command::Element(x) => x
        };

        PyBytes::new(py, &bytes).into()
    }
}

#[pyclass]
#[derive(Debug, Clone, bitcoin_macros::Repr)]
struct Script {
    #[pyo3(get)]
    commands: Vec<Command>
}

impl Serialize for Script {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer,
    {
        let len = self.commands.iter().fold(0, |sum, val| match val {
            Command::Element(x) => sum + x.len() + 1,
            _ => sum + 1,
        });

        let mut seq = serializer.serialize_seq(Some(len))?;
        for cmd in &self.commands {
            seq.serialize_element(cmd)?
        };
        seq.end()
    }
}

struct ScriptVisitor;
impl<'de> Visitor<'de> for ScriptVisitor {
    type Value = Script;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("A script where values < 75 are Elements and values between 78 and 2^8 are considered Commands")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error> where V: SeqAccess<'de>,
    {
        let mut commands: Vec<Command> = Vec::with_capacity(seq.size_hint().unwrap_or(0));

        while let Some(current) = seq.next_element::<u8>()? {
            match current {
                1..=75 => {
                    let mut v = vec![0; current.into()];
                    v.fill_with(|| seq.next_element().unwrap().unwrap());
                    commands.push(Command::Element(v));
                }
                76..=77 => unimplemented!("{}", current),
                _ => {
                    commands.push(Command::Operation(current))
                }
            }
        }
        Ok(Script { commands })
    }
}

impl<'de> Deserialize<'de> for Script {
    fn deserialize<D>(deserializer: D) -> Result<Script, D::Error> where D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ScriptVisitor)
    }
}

#[bitcoin_macros::serdes]
#[pymethods]
impl Script {
    #[new]
    fn new(commands: Vec<Command>) -> Self {
        Script { commands }
    }

    // #[staticmethod]
    // fn p2pkh_script(h160: Command) {
    //     // OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY, OP_CHECKSIG
    // }

    fn evaluate(&self, z: BigInt) -> bool {
        let mut stack: Vec<Vec<u8>> = Vec::new();

        self.commands.iter().all(|cmd| {
            match cmd {
                Command::Operation(x) => {
                    match x {
                        118 => op_dup(&mut stack),
                        136 => op_equalverify(&mut stack),
                        169 => op_hash160(&mut stack),
                        172 => op_checksig(&mut stack, &z),
                        _ => panic!("unrecognized op: {}", x)
                    }
                }
                Command::Element(x) => { stack.push(x.to_vec()); true }
            }
        })
    }
}

#[pyclass]
#[derive(Debug, bitcoin_macros::Repr)]
struct Signature {
    #[pyo3(get)]
    r: BigInt,
    #[pyo3(get)]
    s: BigInt
}

impl Serialize for Signature {
    // According to https://en.bitcoin.it/wiki/BIP_0062#DER_encoding DER has the following format:
    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash-type]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer,
    {
        let der = |x: &BigInt| -> Vec<u8> {
            let mut v = x.to_signed_bytes_le();
            // resize to 32 bytes
            v.resize(32, 0);
            v.reverse(); // switch endianness
            // remove leading zeros
            v = v.into_iter().skip_while(|&x| x == 0u8).collect();
            // prepend a single 0x00 byte if first byte >= 0x80
            if v[0] >= 0x80 {
                v.insert(0, 0x00);
            }
            v
        };

        let content: Vec<Vec<u8>> = [&self.r, &self.s].iter().map(|x| der(x)).collect();
        let total_length = content.iter().flatten().collect::<Vec<_>>().len() as u8 + 2*2;

        let mut tup = serializer.serialize_tuple(8)?;
        tup.serialize_element::<u8>(&0x30)?;
        tup.serialize_element::<u8>(&total_length)?;
        for elem in content {
            tup.serialize_element::<u8>(&0x02)?;
            tup.serialize_element(&elem)?;
        }
        tup.end()
    }
}

struct SignatureVisitor;
impl<'de> Visitor<'de> for SignatureVisitor {
    type Value = Signature;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Signature")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error> where V: SeqAccess<'de>,
    {
        assert_eq!(Some(8), seq.size_hint());
        assert_eq!(Some(0x30), seq.next_element::<u8>()?);
        let _total_length = seq.next_element::<u8>()?.unwrap();
        assert_eq!(Some(0x02), seq.next_element::<u8>()?);
        let r: Vec<u8> = seq.next_element()?.unwrap();
        let r = BigInt::from_bytes_be(Sign::Plus, &r);
        assert_eq!(Some(0x02), seq.next_element::<u8>()?);
        let s: Vec<u8> = seq.next_element()?.unwrap();
        let s = BigInt::from_signed_bytes_be(&s);

        Ok(Signature { r, s })
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error> where D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(8, SignatureVisitor)
    }
}

#[bitcoin_macros::serdes]
#[pymethods]
impl Signature {
    #[new]
    fn new(r: BigInt, s: BigInt) -> Self {
        Signature { r, s }
    }

    #[staticmethod]
    fn sign(secret_key: BigInt, mut message: Vec<u8>) -> Self {
        message.extend(1u32.to_le_bytes()); // 1 = SIGHASH_ALL

        let z = BigInt::from_bytes_be(Sign::Plus, &hash256(&message));

        // TODO: generate a 'random' secret key here
        let secret = BigInt::from_str_radix("22642164261113154316413445432723627165870392276002866272158059571956911456350", 10).unwrap();

        let r = ecc_mul(G.clone(), secret.clone()).x;
        let mut s = modinv(&secret, &N) * (&z + &secret_key * &r) % &*N;
        if s > &*N/2 {
            s = &*N - s;
        }

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

fn op_hash160(stack: &mut Vec<Vec<u8>>) -> bool {
    if stack.len() < 1 {
        return false
    }
    let element = stack.pop().unwrap();
    stack.push(hash160(&element).to_vec());
    true
}

fn op_checksig(stack: &mut Vec<Vec<u8>>, z: &BigInt) -> bool {
    if stack.len() < 2 {
        return false
    }

    let sec = stack.pop().unwrap();
    let der = stack.pop().unwrap();
    let der = der.split_last().unwrap().1;

    let point = Point::decode(&sec).unwrap();
    let sig = Signature::decode(&der).unwrap();

    // verify the signature by using the public key (point), signature hash (z) and signature (r,s)
    let w = modinv(&sig.s, &*N);
    let u = z * &w % &*N;
    let v = &sig.r * &w % &*N;

    let total = ecc_add(&ecc_mul(G.clone(), u), &ecc_mul(point, v));

    let result = total.x == sig.r;
    stack.push(vec![result as u8]);
    result
}

#[pyproto]
impl PyNumberProtocol for Script {
    fn __add__(lhs: Script, rhs: Script) -> Script {
        let commands: Vec<Command> = [lhs.commands, rhs.commands].concat();
        Script { commands }
    }
}

#[pyclass]
#[derive(Debug, bitcoin_macros::Repr, Clone, Serialize, Deserialize)]
struct TxIn {
    prev_tx: [u8; 32], // hash256 of UTXO as big endian (32-byte)
    #[pyo3(get)]
    #[serde(with = "fix_u32")]
    prev_idx: u32, // the index number of the UTXO to be spent (4-byte)
    #[pyo3(get, set)]
    script_sig: Script, // UTXO unlocking script (var size)
    #[pyo3(get)]
    #[serde(with = "fix_u32")]
    sequence: u32 // not used
}

pub mod fix_u32 {
    // simulate a fixed size integer by representing it as an array of bytes
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error> where D: Deserializer<'de>
    {
        Ok(u32::from_le_bytes(<[u8; 4]>::deserialize(deserializer)?))
    }

    pub fn serialize<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer
    {
        value.to_le_bytes().serialize(serializer)
    }
}

#[bitcoin_macros::serdes]
#[pymethods]
impl TxIn {
    #[new]
    #[args(sequence=0xffffffffu32)]
    fn new(prev_tx: [u8; 32], prev_idx: u32, script_sig: Script, sequence: u32) -> Self {
        TxIn { prev_tx, prev_idx: prev_idx, script_sig, sequence: sequence }
    }

    #[getter]
    fn prev_tx<'a>(&self, py: Python<'a>) -> PyResult<&'a PyBytes> {
        Ok(PyBytes::new(py, &self.prev_tx))
    }
}

#[pyclass]
#[derive(Debug, bitcoin_macros::Repr, Clone, Serialize, Deserialize)]
struct TxOut {
    #[pyo3(get)]
    #[serde(with = "fix_u64")]
    amount: u64, // in 1e-8 units (8 bytes)
    #[pyo3(get, set)]
    script_pubkey: Script
}

pub mod fix_u64 {
    // simulate a fixed size integer by representing it as an array of bytes
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error> where D: Deserializer<'de>
    {
        Ok(u64::from_le_bytes(<[u8; 8]>::deserialize(deserializer)?))
    }

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer
    {
        value.to_le_bytes().serialize(serializer)
    }
}

#[bitcoin_macros::serdes]
#[pymethods]
impl TxOut {
    #[new]
    fn new(amount: u64, script_pubkey: Script) -> Self {
        TxOut { amount, script_pubkey}
    }
}

#[pyclass]
#[derive(Debug, bitcoin_macros::Repr, Serialize, Deserialize)]
struct Tx {
    #[pyo3(get)]
    #[serde(with = "fix_u32")]
    version: u32, // version (4 bytes)
    #[pyo3(get, set)]
    tx_ins: Vec<TxIn>,
    #[pyo3(get)]
    tx_outs: Vec<TxOut>,
    #[pyo3(get)]
    #[serde(with = "fix_u32")]
    locktime: u32
}

#[bitcoin_macros::serdes]
#[pymethods]
impl Tx {
    #[new]
    #[args(locktime=0u32)]
    fn new(version: u32, tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>, locktime: u32) -> Self {
        Tx { version, tx_ins, tx_outs, locktime}
    }

    fn id<'a>(&self, py: Python<'a>) -> PyResult<&'a PyBytes> {
        let mut result = hash256(self.encode(py).unwrap().as_bytes());
        result.reverse();
        Ok(PyBytes::new(py, &result))
    }

    fn validate(&mut self, prev_script_pubkey: &[u8]) -> bool {
        // Bitcoin’s inputs are spending outputs of a previous transaction (UTXO).
        // The UTXO is valid for spending if the scriptsig successfully unlocks 
        // the previous scriptpubkey

        let prev_script_pubkey = Script::decode(&prev_script_pubkey).unwrap();

        for i in 0..self.tx_ins.len() {
            let script_sig = &self.tx_ins[i].script_sig.clone();

            self.tx_ins[i].script_sig = prev_script_pubkey.clone();

            // get the signature hash and append 1 (SIGHASH_ALL)
            let mut sighash = DefaultOptions::new()
                    .with_varint_encoding()
                    .serialize(&self).unwrap();

            sighash.extend(1u32.to_le_bytes());
            
            // integer representation of the signature hash
            let z = BigInt::from_bytes_be(Sign::Plus, &hash256(&sighash));

            self.tx_ins[i].script_sig = script_sig.clone(); // revert back

            let commands = [script_sig.commands.clone(), prev_script_pubkey.commands.clone()].concat();
            let combined = Script { commands };
            if !combined.evaluate(z) {
                return false;
            }
        }
        true
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

#[pyfunction]
fn hash256(bytes: &[u8]) -> [u8; 32] {
    // sha256 2x
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let bytes = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}