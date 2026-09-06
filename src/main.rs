use std::fmt::Debug;

use elliptic_curve::array::typenum::Unsigned;
use elliptic_curve::ecdh::SharedSecret;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{
    Curve, CurveArithmetic, PublicKey as GroupPublicKey, ScalarValue, SecretKey as GroupPrivateKey,
};
use kem::Ciphertext;
use kem::Decapsulator;
use kem::Encapsulate;
use kem::EncapsulationKey;
use kem::Generate;
use kem::InvalidKey;
use kem::Kem;
use kem::Key;
use kem::KeyExport;
use kem::KeySizeUser;
use kem::SharedKey;
use kem::TryKeyInit;
use kem::common::typenum::Sum;
use kem::consts::{U1, U128};
use kem::{Decapsulate, KeyInit};
use ml_kem::ArraySize;
use ml_kem::MlKem768;
use ml_kem::MlKem1024;
use ml_kem::array::sizes::{U32, U1153};
use ml_kem::array::{Array, ArrayN};
use p256::NistP256;
use p384::{NistP384, U48};
use rand_core::CryptoRng;
use rand_core::TryCryptoRng;
use sha3::{Digest, Sha3_256};
use shake::Shake256;
use shake::digest::{ExtendableOutput, XofReader};

const SEED_SIZE: usize = 32;

/// MlKem768P256 ciphertext
struct MlKem768P256Ciphertext {
    kem_ciphertext: ArrayN<u8, { <MlKem768 as Kem>::CiphertextSize::USIZE }>,
    group_ciphertext: GroupPublicKey<NistP256>,
}

impl From<MlKem768P256Ciphertext> for Ciphertext<MlKem768P256> {
    fn from(value: MlKem768P256Ciphertext) -> Self {
        let mut buffer = Ciphertext::<MlKem768P256>::default();
        buffer[..<MlKem768 as Kem>::CiphertextSize::USIZE].copy_from_slice(&value.kem_ciphertext);
        buffer[<MlKem768 as Kem>::CiphertextSize::USIZE..]
            .copy_from_slice(&value.group_ciphertext.to_sec1_bytes());
        buffer
    }
}

/// MlKem768P256
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
struct MlKem768P256 {}

impl Kem for MlKem768P256 {
    type DecapsulationKey = HybridKemDecapsulationKey<MlKem768, NistP256>;
    type EncapsulationKey = HybridKemEncapsulationKey<MlKem768, NistP256>;
    type SharedKeySize = U32;
    type CiphertextSize = U1153;
}

impl Encapsulate for HybridKemEncapsulationKey<MlKem768, NistP256> {
    type Kem = MlKem768P256;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: CryptoRng + ?Sized,
    {
        // <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.5>
        // def Encaps(ek):
        //     (ek_PQ, ek_T) = split(KEM_PQ.Nek, Group_T.Nelem, ek)
        //     (ss_PQ, ss_T, ct_PQ, ct_T) = prepareEncapsG(ek_PQ, ek_T)
        //     ss_H = C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, Label)
        //     ct_H = concat(ct_PQ, ct_T)
        //     return (ss_H, ct_H)
        let (kem_shared_key, group_shared_secret, kem_ciphertext, group_ciphertext) =
            prepare_encaps_g(self, rng);
        let secret_key = c2pri_combiner::<MlKem768, NistP256, Sha3_256>(
            &kem_shared_key,
            &group_shared_secret,
            &group_ciphertext,
            &self.group_public_key,
            br"MLKEM768-P256",
        );
        let ciphertext = MlKem768P256Ciphertext {
            kem_ciphertext,
            group_ciphertext,
        };
        (ciphertext.into(), secret_key)
    }
}

impl Decapsulator for HybridKemDecapsulationKey<MlKem768, NistP256> {
    type Kem = MlKem768P256;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}

impl Decapsulate for HybridKemDecapsulationKey<MlKem768, NistP256> {
    fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
        todo!()
    }
}

/// MlKem1024P384
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
struct MlKem1024P384 {}

impl Kem for MlKem1024P384 {
    type DecapsulationKey = HybridKemDecapsulationKey<MlKem1024, NistP384>;
    type EncapsulationKey = HybridKemEncapsulationKey<MlKem1024, NistP384>;
    type SharedKeySize = U32;
    type CiphertextSize = U1153;
}

impl Encapsulate for HybridKemEncapsulationKey<MlKem1024, NistP384> {
    type Kem = MlKem1024P384;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: CryptoRng + ?Sized,
    {
        todo!()
    }
}

impl Decapsulator for HybridKemDecapsulationKey<MlKem1024, NistP384> {
    type Kem = MlKem1024P384;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}

impl Decapsulate for HybridKemDecapsulationKey<MlKem1024, NistP384> {
    fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
        todo!()
    }
}

/// EncapsulationKey
#[derive(Clone, Debug, PartialEq, Eq)]
struct HybridKemEncapsulationKey<K: Kem, C: CurveArithmetic> {
    kem_encapsulation_key: K::EncapsulationKey,
    group_public_key: GroupPublicKey<C>,
}

impl<K: Kem, C: CurveArithmetic + PointCompression> KeyExport for HybridKemEncapsulationKey<K, C>
where
    <C as Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
{
    fn to_bytes(&self) -> Key<Self> {
        let mut key = Key::<Self>::default();
        let (kem_bytes, group_bytes) = key.split_at_mut(K::EncapsulationKey::key_size());
        kem_bytes.copy_from_slice(&self.kem_encapsulation_key.to_bytes());
        group_bytes.copy_from_slice(&self.group_public_key.to_sec1_bytes());
        key
    }
}

impl<K: Kem, C: CurveArithmetic> TryKeyInit for HybridKemEncapsulationKey<K, C>
where
    <C as Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
{
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        let kem_bytes = key
            .get(..K::EncapsulationKey::key_size())
            .ok_or(InvalidKey)?;
        let group_bytes = key
            .get(K::EncapsulationKey::key_size()..)
            .ok_or(InvalidKey)?;
        let kem_encapsulation_key = K::EncapsulationKey::new_from_slice(kem_bytes)?;
        let group_public_key =
            GroupPublicKey::<C>::from_sec1_bytes(group_bytes).map_err(|_| InvalidKey)?;
        Ok(HybridKemEncapsulationKey {
            kem_encapsulation_key,
            group_public_key,
        })
    }
}

impl<K: Kem, C: CurveArithmetic> KeySizeUser for HybridKemEncapsulationKey<K, C> {
    type KeySize = Sum<Sum<<C as Curve>::FieldBytesSize, <C as Curve>::FieldBytesSize>, U1>;
}

/// DecapsulationKey
struct HybridKemDecapsulationKey<K: Kem, C: CurveArithmetic> {
    seed: [u8; SEED_SIZE],
    kem_decapsulation_key: K::DecapsulationKey,
    group_private_key: GroupPrivateKey<C>,
    encapsulation_key: HybridKemEncapsulationKey<K, C>,
}

impl<K: Kem, C: CurveArithmetic + RandomScalar> Generate for HybridKemDecapsulationKey<K, C>
where
    K::DecapsulationKey: KeyInit,
{
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let seed = Array::try_generate_from_rng(rng)?;
        Ok(HybridKemDecapsulationKey::new(&seed))
    }
}

impl<K: Kem, C: CurveArithmetic> KeyExport for HybridKemDecapsulationKey<K, C> {
    fn to_bytes(&self) -> Key<Self> {
        Array::from(self.seed)
    }
}

impl<K: Kem, C: CurveArithmetic + RandomScalar> KeyInit for HybridKemDecapsulationKey<K, C>
where
    K::DecapsulationKey: KeyInit,
{
    fn new(seed: &Key<Self>) -> Self {
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_g::<Shake256, K, C>(seed);

        HybridKemDecapsulationKey {
            seed: seed.0,
            kem_decapsulation_key: dk_pq,
            group_private_key: dk_t,
            encapsulation_key: HybridKemEncapsulationKey {
                kem_encapsulation_key: ek_pq,
                group_public_key: ek_t,
            },
        }
    }
}

impl<K: Kem, C: CurveArithmetic> KeySizeUser for HybridKemDecapsulationKey<K, C> {
    type KeySize = U32;
}

/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-12.html#section-5.1.1>
fn expand_decaps_key_g<PRG: Default + ExtendableOutput, K: Kem, C: CurveArithmetic + RandomScalar>(
    seed: &Array<u8, <HybridKemDecapsulationKey<K, C> as KeySizeUser>::KeySize>,
) -> (
    K::DecapsulationKey,
    GroupPrivateKey<C>,
    K::EncapsulationKey,
    GroupPublicKey<C>,
)
where
    K::DecapsulationKey: KeyInit,
{
    // seed_full = PRG(seed)
    // (seed_PQ, seed_T) = split(KEM_PQ.Nseed, Group_T.Nseed, seed_full)
    let mut prg = PRG::default();
    prg.update(&seed.0);
    let mut seed_full = prg.finalize_xof();
    let mut seed_pq = Array::default();
    let mut seed_t = Array::default();

    // (dk_PQ, ek_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)
    seed_full.read(&mut seed_pq);
    let dk_pq = K::DecapsulationKey::new(&seed_pq);
    let ek_pq = dk_pq.encapsulation_key().clone();

    // dk_T = Group_T.RandomScalar(seed_T)
    // ek_T = Group_T.Exp(Group_T.g, dk_T)
    seed_full.read(&mut seed_t);
    let dk_t = C::random_scalar(&seed_t)
        .expect("RandomScalar fails with cryptographically negligible probability");
    let ek_t = dk_t.public_key();

    (dk_pq, dk_t, ek_pq, ek_t)
}

/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.html#section-3.1.1>
trait RandomScalar: Curve {
    type SeedSize: ArraySize;

    fn random_scalar(seed: &Array<u8, Self::SeedSize>) -> Option<GroupPrivateKey<Self>> {
        #[expect(clippy::chunks_exact_to_as_chunks)]
        for chunk in seed.chunks_exact(Self::FieldBytesSize::USIZE) {
            if let Some(private_key) = Array::try_from(chunk)
                .ok()
                .and_then(|bytes| ScalarValue::from_bytes(&bytes).into_option())
                .and_then(|scalar| GroupPrivateKey::from_scalar(scalar).into_option())
            {
                return Some(private_key);
            }
        }
        None
    }
}

impl RandomScalar for NistP256 {
    type SeedSize = U128;
}

impl RandomScalar for NistP384 {
    type SeedSize = U48;
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.1.3>
fn c2pri_combiner<K: Kem, C: CurveArithmetic + PointCompression, KDF: Default + Digest>(
    kem_shared_key: &SharedKey<K>,
    group_shared_secret: &SharedSecret<C>,
    group_ciphertext: &GroupPublicKey<C>,
    group_public_key: &GroupPublicKey<C>,
    label: &[u8],
) -> Array<u8, KDF::OutputSize>
where
    <C as Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
{
    let mut hasher = KDF::default();
    hasher.update(kem_shared_key);
    hasher.update(group_shared_secret.raw_secret_bytes());
    hasher.update(group_ciphertext.to_sec1_bytes());
    hasher.update(group_public_key.to_sec1_bytes());
    hasher.update(label);
    hasher.finalize()
}

// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.1.1>
#[expect(clippy::type_complexity)]
fn prepare_encaps_g<K: Kem, C: CurveArithmetic, R: CryptoRng + ?Sized>(
    encpasulation_key: &HybridKemEncapsulationKey<K, C>,
    rng: &mut R,
) -> (
    Array<u8, <K as Kem>::SharedKeySize>,
    SharedSecret<C>,
    Array<u8, <K as Kem>::CiphertextSize>,
    GroupPublicKey<C>,
) {
    // (ss_PQ, ct_PQ) = KEM_PQ.Encaps(ek_PQ)
    let (kem_ciphertext, kem_shared_key) = encpasulation_key
        .kem_encapsulation_key
        .encapsulate_with_rng(rng);

    // sk_E = Group_T.RandomScalar(random(Group_T.Nseed))
    let group_private_key = GroupPrivateKey::<C>::generate_from_rng(rng);

    // ct_T = Group_T.Exp(Group_T.g, sk_E)
    let group_ciphertext = group_private_key.public_key();

    // ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ek_T, sk_E))
    let group_shared_secret = group_private_key.diffie_hellman(&encpasulation_key.group_public_key);

    // return (ss_PQ, ss_T, ct_PQ, ct_T)
    (
        kem_shared_key,
        group_shared_secret,
        kem_ciphertext,
        group_ciphertext,
    )
}

fn main() {}
