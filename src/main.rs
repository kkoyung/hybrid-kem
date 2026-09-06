use std::fmt::Debug;

use elliptic_curve::array::typenum::Unsigned;
use elliptic_curve::bigint::CtOption;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{
    Curve, CurveArithmetic, PublicKey as GroupPublicKey, ScalarValue, SecretKey as GroupPrivateKey,
    scalar,
};
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
use kem::{Ciphertext, DecapsulationKey};
use kem::{Decapsulate, KeyInit};
use ml_kem::DecapsulationKey1024 as MlKem1024DecapsulationKey;
use ml_kem::EncapsulationKey768 as MlKem768EncapsulationKey;
use ml_kem::EncapsulationKey1024 as MlKem1024EncapsulationKey;
use ml_kem::array::Array;
use ml_kem::array::sizes::{U32, U1153};
use ml_kem::{ArraySize, DecapsulationKey768 as MlKem768DecapsulationKey};
use p256::NistP256;
use p384::{NistP384, U48};
use rand_core::CryptoRng;
use rand_core::TryCryptoRng;
use shake::Shake256;
use shake::digest::{ExtendableOutput, XofReader};

const SEED_SIZE: usize = 32;

// MlKem768P256

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
struct MlKem768P256 {}

impl Kem for MlKem768P256 {
    type DecapsulationKey = HybridKemDecapsulationKey<MlKem768DecapsulationKey, NistP256>;
    type EncapsulationKey = HybridKemEncapsulationKey<MlKem768EncapsulationKey, NistP256>;
    type SharedKeySize = U32;
    type CiphertextSize = U1153;
}

impl Encapsulate for HybridKemEncapsulationKey<MlKem768EncapsulationKey, NistP256> {
    type Kem = MlKem768P256;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: CryptoRng + ?Sized,
    {
        todo!()
    }
}

impl Decapsulator for HybridKemDecapsulationKey<MlKem768DecapsulationKey, NistP256> {
    type Kem = MlKem768P256;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}

impl Decapsulate for HybridKemDecapsulationKey<MlKem768DecapsulationKey, NistP256> {
    fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
        todo!()
    }
}

// MlKem1024P384

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
struct MlKem1024P384 {}

impl Kem for MlKem1024P384 {
    type DecapsulationKey = HybridKemDecapsulationKey<MlKem1024DecapsulationKey, NistP384>;
    type EncapsulationKey = HybridKemEncapsulationKey<MlKem1024EncapsulationKey, NistP384>;
    type SharedKeySize = U32;
    type CiphertextSize = U1153;
}

impl Encapsulate for HybridKemEncapsulationKey<MlKem1024EncapsulationKey, NistP384> {
    type Kem = MlKem1024P384;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: CryptoRng + ?Sized,
    {
        todo!()
    }
}

impl Decapsulator for HybridKemDecapsulationKey<MlKem1024DecapsulationKey, NistP384> {
    type Kem = MlKem1024P384;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.encapsulation_key
    }
}

impl Decapsulate for HybridKemDecapsulationKey<MlKem1024DecapsulationKey, NistP384> {
    fn decapsulate(&self, ct: &Ciphertext<Self::Kem>) -> SharedKey<Self::Kem> {
        todo!()
    }
}

// EncapsulationKey

#[derive(Clone, Debug, PartialEq, Eq)]
struct HybridKemEncapsulationKey<MlKemEncap, C: Curve + CurveArithmetic> {
    kem_encapsulation_key: MlKemEncap,
    group_public_key: GroupPublicKey<C>,
}

impl<MlKemEncap, C: Curve + CurveArithmetic> KeyExport for HybridKemEncapsulationKey<MlKemEncap, C>
where
    MlKemEncap: KeySizeUser,
    MlKemEncap: KeyExport,
    C: PointCompression,
    <C as Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
{
    fn to_bytes(&self) -> Key<Self> {
        let mut key = Key::<Self>::default();
        let (kem_bytes, group_bytes) = key.split_at_mut(MlKemEncap::key_size());
        kem_bytes.copy_from_slice(&self.kem_encapsulation_key.to_bytes());
        group_bytes.copy_from_slice(&self.group_public_key.to_sec1_bytes());
        key
    }
}

impl<MlKemEncap, C: Curve + CurveArithmetic> TryKeyInit for HybridKemEncapsulationKey<MlKemEncap, C>
where
    MlKemEncap: KeySizeUser,
    MlKemEncap: TryKeyInit,
    <C as Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
{
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        let kem_bytes = key.get(..MlKemEncap::key_size()).ok_or(InvalidKey)?;
        let group_bytes = key.get(MlKemEncap::key_size()..).ok_or(InvalidKey)?;
        let kem_encapsulation_key = MlKemEncap::new_from_slice(kem_bytes)?;
        let group_public_key =
            GroupPublicKey::<C>::from_sec1_bytes(group_bytes).map_err(|_| InvalidKey)?;
        Ok(HybridKemEncapsulationKey::<MlKemEncap, C> {
            kem_encapsulation_key,
            group_public_key,
        })
    }
}

impl<MlKemEncap, C: Curve + CurveArithmetic> KeySizeUser
    for HybridKemEncapsulationKey<MlKemEncap, C>
{
    type KeySize = Sum<Sum<<C as Curve>::FieldBytesSize, <C as Curve>::FieldBytesSize>, U1>;
}

// DecapsulationKey

struct HybridKemDecapsulationKey<MlKemDecap: Decapsulator, C: Curve + CurveArithmetic> {
    seed: [u8; SEED_SIZE],
    kem_decapsulation_key: MlKemDecap,
    group_private_key: GroupPrivateKey<C>,
    encapsulation_key:
        HybridKemEncapsulationKey<<<MlKemDecap as Decapsulator>::Kem as Kem>::EncapsulationKey, C>,
}

impl<MlKemDecap: Decapsulator + KeyInit, C: Curve + CurveArithmetic + RandomScalar> Generate
    for HybridKemDecapsulationKey<MlKemDecap, C>
where
    MlKemDecap: Generate,
{
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let seed = Array::try_generate_from_rng(rng)?;
        Ok(HybridKemDecapsulationKey::<MlKemDecap, C>::new(&seed))
    }
}

impl<MlKemDecap: Decapsulator + KeyInit, C: Curve + CurveArithmetic + RandomScalar> KeyInit
    for HybridKemDecapsulationKey<MlKemDecap, C>
{
    fn new(seed: &Key<Self>) -> Self {
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_g::<Shake256, _, _>(seed);

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

impl<MlKemDecap: Decapsulator, C: Curve + CurveArithmetic> KeySizeUser
    for HybridKemDecapsulationKey<MlKemDecap, C>
{
    type KeySize = U32;
}

/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-12.html#section-5.1.1>
fn expand_decaps_key_g<
    PRG: Default + ExtendableOutput,
    MlKemDecap: Decapsulator + KeyInit,
    C: Curve + CurveArithmetic + RandomScalar,
>(
    seed: &Array<u8, <HybridKemDecapsulationKey<MlKemDecap, C> as KeySizeUser>::KeySize>,
) -> (
    MlKemDecap,
    GroupPrivateKey<C>,
    <<MlKemDecap as Decapsulator>::Kem as Kem>::EncapsulationKey,
    GroupPublicKey<C>,
) {
    // seed_full = PRG(seed)
    // (seed_PQ, seed_T) = split(KEM_PQ.Nseed, Group_T.Nseed, seed_full)
    let mut prg = PRG::default();
    prg.update(&seed.0);
    let mut seed_full = prg.finalize_xof();
    let mut seed_pq = Array::default();
    let mut seed_t = Array::default();

    // (dk_PQ, ek_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)
    seed_full.read(&mut seed_pq);
    let dk_pq = MlKemDecap::new(&seed_pq);
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
        #[allow(clippy::chunks_exact_to_as_chunks)]
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

fn main() {}
