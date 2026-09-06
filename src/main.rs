use std::fmt::Debug;

use elliptic_curve::{
    Curve, CurveArithmetic, PublicKey as GroupPublicKey, SecretKey as GroupPrivateKey,
};
use kem::Ciphertext;
use kem::Decapsulate;
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
use kem::consts::U1;
use ml_kem::DecapsulationKey768 as MlKem768DecapsulationKey;
use ml_kem::DecapsulationKey1024 as MlKem1024DecapsulationKey;
use ml_kem::EncapsulationKey768 as MlKem768EncapsulationKey;
use ml_kem::EncapsulationKey1024 as MlKem1024EncapsulationKey;
use ml_kem::array::sizes::{U32, U1153};
use p256::NistP256;
use p384::NistP384;
use rand_core::CryptoRng;
use rand_core::TryCryptoRng;

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
        todo!()
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
        todo!()
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

impl<MlKemEncap, C: Curve + CurveArithmetic> KeyExport
    for HybridKemEncapsulationKey<MlKemEncap, C>
{
    fn to_bytes(&self) -> Key<Self> {
        todo!()
    }
}

impl<MlKemEncap, C: Curve + CurveArithmetic> TryKeyInit
    for HybridKemEncapsulationKey<MlKemEncap, C>
{
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        todo!()
    }
}

impl<MlKemEncap, C: Curve + CurveArithmetic> KeySizeUser
    for HybridKemEncapsulationKey<MlKemEncap, C>
{
    type KeySize = Sum<Sum<<C as Curve>::FieldBytesSize, <C as Curve>::FieldBytesSize>, U1>;
}

// DecapsulationKey

struct HybridKemDecapsulationKey<MlKemDecap, C: Curve + CurveArithmetic> {
    kem_decapsulation_key: MlKemDecap,
    group_private_key: GroupPrivateKey<C>,
}

impl<MlKemDecap, C: Curve + CurveArithmetic> Generate for HybridKemDecapsulationKey<MlKemDecap, C> {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        todo!()
    }
}

fn main() {}
