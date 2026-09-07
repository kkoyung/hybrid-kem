use std::fmt::Debug;

use elliptic_curve::array::typenum::Unsigned;
use elliptic_curve::ecdh::SharedSecret;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{
    Curve, CurveArithmetic, PublicKey as GroupPublicKey, ScalarValue, SecretKey as GroupPrivateKey,
};
use kem::Decapsulator;
use kem::Encapsulate;
use kem::EncapsulationKey;
use kem::Generate;
use kem::InvalidKey;
use kem::Kem;
use kem::Key;
use kem::KeyExport;
use kem::KeyInit;
use kem::KeySizeUser;
use kem::SharedKey;
use kem::TryKeyInit;
use kem::common::OutputSizeUser;
use kem::common::typenum::Sum;
use kem::consts::{U1, U128};
use kem::{Ciphertext, TryDecapsulate};
use ml_kem::ArraySize;
use ml_kem::MlKem768;
use ml_kem::MlKem1024;
use ml_kem::array::Array;
use ml_kem::array::sizes::{U32, U1153, U1249, U1665};
use p256::NistP256;
use p384::{NistP384, U48};
use rand_core::CryptoRng;
use rand_core::TryCryptoRng;
use sha3::{Digest, Sha3_256};
use shake::digest::{ExtendableOutput, XofReader};
use shake::{Shake256, Update};

#[cfg(test)]
mod tests;

const SEED_SIZE: usize = 32;
const ML_KEM768_P256_LABEL: &[u8] = br"MLKEM768-P256";
const ML_KEM1024_P384_LABEL: &[u8] = br"MLKEM1024-P384";

#[derive(Debug)]
struct DecapsulationError;

impl core::fmt::Display for DecapsulationError {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.write_str("DecapsulationError")
    }
}

impl core::error::Error for DecapsulationError {}

// /// MlKem768P256
// #[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
// struct MlKem768P256 {}
//
// impl Kem for MlKem768P256 {
//     type DecapsulationKey = HybridKemDecapsulationKey<MlKem768, NistP256>;
//     type EncapsulationKey = HybridKemEncapsulationKey<MlKem768, NistP256>;
//     type SharedKeySize = U32;
//     type CiphertextSize = U1153;
// }
//
// impl Encapsulate for HybridKemEncapsulationKey<MlKem768, NistP256> {
//     type Kem = MlKem768P256;
//
//     /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.5>
//     ///
//     /// def Encaps(ek):
//     fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
//     where
//         R: CryptoRng + ?Sized,
//     {
//         // (ek_PQ, ek_T) = split(KEM_PQ.Nek, Group_T.Nelem, ek)
//         // (ss_PQ, ss_T, ct_PQ, ct_T) = prepareEncapsG(ek_PQ, ek_T)
//         let (kem_shared_key, group_shared_secret, kem_ciphertext, group_ciphertext) =
//             prepare_encaps_g(self, rng);
//
//         // ss_H = C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, Label)
//         let secret_key = c2pri_combiner::<MlKem768, NistP256, Sha3_256>(
//             &kem_shared_key,
//             &group_shared_secret,
//             &group_ciphertext,
//             &self.group_public_key,
//             ML_KEM768_P256_LABEL,
//         );
//
//         // ct_H = concat(ct_PQ, ct_T)
//         let mut ciphertext = Ciphertext::<MlKem768P256>::default();
//         ciphertext[..<MlKem768 as Kem>::CiphertextSize::USIZE].copy_from_slice(&kem_ciphertext);
//         ciphertext[<MlKem768 as Kem>::CiphertextSize::USIZE..]
//             .copy_from_slice(&group_ciphertext.to_sec1_bytes());
//
//         // return (ss_H, ct_H)
//         (ciphertext, secret_key)
//     }
// }
//
// impl Decapsulator for HybridKemDecapsulationKey<MlKem768, NistP256> {
//     type Kem = MlKem768P256;
//
//     fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
//         &self.encapsulation_key
//     }
// }
//
// impl TryDecapsulate for HybridKemDecapsulationKey<MlKem768, NistP256> {
//     type Error = DecapsulationError;
//
//     /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.5>
//     ///
//     /// def Decaps(dk, ct):
//     fn try_decapsulate(
//         &self,
//         ciphertext: &Ciphertext<Self::Kem>,
//     ) -> Result<SharedKey<Self::Kem>, Self::Error> {
//         // (ct_PQ, ct_T) = split(KEM_PQ.Nct, Group_T.Nelem, ct)
//         let kem_ciphertext =
//             Array::slice_as_array(&ciphertext[..<MlKem768 as Kem>::CiphertextSize::USIZE])
//                 .ok_or(DecapsulationError)?;
//         let group_ciphertext = &GroupPublicKey::from_sec1_bytes(
//             &ciphertext[<MlKem768 as Kem>::CiphertextSize::USIZE..],
//         )
//         .map_err(|_| DecapsulationError)?;
//
//         // (ek_PQ, ek_T, dk_PQ, dk_T) = expandDecapsKeyG(dk)
//         let (_kem_encapsulation_key, group_public_key, kem_decapsulation_key, group_private_key) =
//             expand_decaps_key_g::<MlKem768, NistP256, Shake256>(&Array::from(self.seed));
//
//         // (ss_PQ, ss_T) = prepareDecapsG(ct_PQ, ct_T, dk_PQ, dk_T)
//         let (kem_shared_key, group_shared_secret) = prepare_decaps_g::<MlKem768, NistP256>(
//             kem_ciphertext,
//             group_ciphertext,
//             &kem_decapsulation_key,
//             &group_private_key,
//         )
//         .map_err(|_| DecapsulationError)?;
//
//         // ss_H = C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, Label)
//         let secret_key = c2pri_combiner::<MlKem768, NistP256, Sha3_256>(
//             &kem_shared_key,
//             &group_shared_secret,
//             group_ciphertext,
//             &group_public_key,
//             ML_KEM768_P256_LABEL,
//         );
//
//         // return ss_H
//         Ok(secret_key)
//     }
// }
//
// /// MlKem1024P384
// #[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
// struct MlKem1024P384 {}
//
// impl Kem for MlKem1024P384 {
//     type DecapsulationKey = HybridKemDecapsulationKey<MlKem1024, NistP384>;
//     type EncapsulationKey = HybridKemEncapsulationKey<MlKem1024, NistP384>;
//     type SharedKeySize = U32;
//     type CiphertextSize = U1153;
// }
//
// impl Encapsulate for HybridKemEncapsulationKey<MlKem1024, NistP384> {
//     type Kem = MlKem1024P384;
//
//     /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.5>
//     ///
//     /// def Encaps(ek):
//     fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
//     where
//         R: CryptoRng + ?Sized,
//     {
//         // (ek_PQ, ek_T) = split(KEM_PQ.Nek, Group_T.Nelem, ek)
//         // (ss_PQ, ss_T, ct_PQ, ct_T) = prepareEncapsG(ek_PQ, ek_T)
//         let (kem_shared_key, group_shared_secret, kem_ciphertext, group_ciphertext) =
//             prepare_encaps_g(self, rng);
//
//         // ss_H = C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, Label)
//         let secret_key = c2pri_combiner::<MlKem1024, NistP384, Sha3_256>(
//             &kem_shared_key,
//             &group_shared_secret,
//             &group_ciphertext,
//             &self.group_public_key,
//             ML_KEM1024_P384_LABEL,
//         );
//
//         // ct_H = concat(ct_PQ, ct_T)
//         let mut ciphertext = Ciphertext::<MlKem1024P384>::default();
//         ciphertext[..<MlKem1024 as Kem>::CiphertextSize::USIZE].copy_from_slice(&kem_ciphertext);
//         ciphertext[<MlKem1024 as Kem>::CiphertextSize::USIZE..]
//             .copy_from_slice(&group_ciphertext.to_sec1_bytes());
//
//         // return (ss_H, ct_H)
//         (ciphertext, secret_key)
//     }
// }
//
// impl Decapsulator for HybridKemDecapsulationKey<MlKem1024, NistP384> {
//     type Kem = MlKem1024P384;
//
//     fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
//         &self.encapsulation_key
//     }
// }
//
// impl TryDecapsulate for HybridKemDecapsulationKey<MlKem1024, NistP384> {
//     type Error = DecapsulationError;
//
//     /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.5>
//     ///
//     /// def Decaps(dk, ct):
//     fn try_decapsulate(
//         &self,
//         ciphertext: &Ciphertext<Self::Kem>,
//     ) -> Result<SharedKey<Self::Kem>, Self::Error> {
//         // (ct_PQ, ct_T) = split(KEM_PQ.Nct, Group_T.Nelem, ct)
//         let kem_ciphertext =
//             Array::slice_as_array(&ciphertext[..<MlKem1024 as Kem>::CiphertextSize::USIZE])
//                 .ok_or(DecapsulationError)?;
//         let group_ciphertext = &GroupPublicKey::from_sec1_bytes(
//             &ciphertext[<MlKem1024 as Kem>::CiphertextSize::USIZE..],
//         )
//         .map_err(|_| DecapsulationError)?;
//
//         // (ek_PQ, ek_T, dk_PQ, dk_T) = expandDecapsKeyG(dk)
//         let (_kem_encapsulation_key, group_public_key, kem_decapsulation_key, group_private_key) =
//             expand_decaps_key_g::<MlKem1024, NistP384, Shake256>(&Array::from(self.seed));
//
//         // (ss_PQ, ss_T) = prepareDecapsG(ct_PQ, ct_T, dk_PQ, dk_T)
//         let (kem_shared_key, group_shared_secret) = prepare_decaps_g::<MlKem1024, NistP384>(
//             kem_ciphertext,
//             group_ciphertext,
//             &kem_decapsulation_key,
//             &group_private_key,
//         )
//         .map_err(|_| DecapsulationError)?;
//
//         // ss_H = C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, Label)
//         let secret_key = c2pri_combiner::<MlKem1024, NistP384, Sha3_256>(
//             &kem_shared_key,
//             &group_shared_secret,
//             group_ciphertext,
//             &group_public_key,
//             ML_KEM1024_P384_LABEL,
//         );
//
//         // return ss_H
//         Ok(secret_key)
//     }
// }

trait HybridKemParameter {
    type GroupT: Curve + CurveArithmetic + PointCompression + RandomScalar;
    type KemPQ: Kem;
    type PRG: Default + Update + ExtendableOutput;
    type KDF: Default + Digest;

    type SeedSize: ArraySize;
    type EncapsulationKeySize: ArraySize;
    type DecapsulationKeySize: ArraySize;
    type CiphertextSize: ArraySize;
    type SharedSecretSize: ArraySize;
}

struct MlKem768P256 {}

impl HybridKemParameter for MlKem768P256 {
    type GroupT = NistP256;
    type KemPQ = MlKem768;
    type PRG = Shake256;
    type KDF = Sha3_256;

    type SeedSize = U32;
    type EncapsulationKeySize = U1249;
    type DecapsulationKeySize = U32;
    type CiphertextSize = U1153;
    type SharedSecretSize = U32;
}

struct MlKem1024P384 {}

impl HybridKemParameter for MlKem1024P384 {
    type GroupT = NistP384;
    type KemPQ = MlKem1024;
    type PRG = Shake256;
    type KDF = Sha3_256;

    type SeedSize = U32;
    type EncapsulationKeySize = U1665;
    type DecapsulationKeySize = U32;
    type CiphertextSize = U1665;
    type SharedSecretSize = U32;
}

/// EncapsulationKey
#[derive(Clone, Debug, PartialEq, Eq)]
struct HybridKemEncapsulationKey<H: HybridKemParameter> {
    encapsulation_key_pq: <H::KemPQ as Kem>::EncapsulationKey,
    encapsulation_key_t: GroupPublicKey<H::GroupT>,
}

impl<H: HybridKemParameter> KeyExport for HybridKemEncapsulationKey<H>
where
    <H::GroupT as Curve>::FieldBytesSize: ModulusSize,
    <H::GroupT as CurveArithmetic>::AffinePoint: FromSec1Point<H::GroupT> + ToSec1Point<H::GroupT>,
{
    fn to_bytes(&self) -> Key<Self> {
        let mut bytes = Key::<Self>::default();
        let (bytes_pq, bytes_t) =
            bytes.split_at_mut(<H::KemPQ as Kem>::EncapsulationKey::key_size());
        bytes_pq.copy_from_slice(&self.encapsulation_key_pq.to_bytes());
        bytes_t.copy_from_slice(&self.encapsulation_key_t.to_sec1_bytes());
        bytes
    }
}

impl<H: HybridKemParameter> TryKeyInit for HybridKemEncapsulationKey<H>
where
    <H::GroupT as Curve>::FieldBytesSize: ModulusSize,
    <H::GroupT as CurveArithmetic>::AffinePoint: FromSec1Point<H::GroupT> + ToSec1Point<H::GroupT>,
{
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        let bytes_pq = key
            .get(..<H::KemPQ as Kem>::EncapsulationKey::key_size())
            .ok_or(InvalidKey)?;
        let bytes_t = key
            .get(<H::KemPQ as Kem>::EncapsulationKey::key_size()..)
            .ok_or(InvalidKey)?;
        let encapsulation_key_pq = <H::KemPQ as Kem>::EncapsulationKey::new_from_slice(bytes_pq)?;
        let encapsulation_key_t =
            GroupPublicKey::<H::GroupT>::from_sec1_bytes(bytes_t).map_err(|_| InvalidKey)?;
        Ok(HybridKemEncapsulationKey {
            encapsulation_key_pq,
            encapsulation_key_t,
        })
    }
}

impl<H: HybridKemParameter> KeySizeUser for HybridKemEncapsulationKey<H> {
    type KeySize = H::EncapsulationKeySize;
}

/// DecapsulationKey
struct HybridKemDecapsulationKey<H: HybridKemParameter> {
    seed: Array<u8, H::DecapsulationKeySize>,
    decapsulation_key_pq: <H::KemPQ as Kem>::DecapsulationKey,
    decapsulation_key_t: GroupPrivateKey<H::GroupT>,
    encapsulation_key: HybridKemEncapsulationKey<H>,
}

impl<H: HybridKemParameter> HybridKemDecapsulationKey<H>
where
    <H::KemPQ as Kem>::DecapsulationKey: KeyInit,
{
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.5>
    ///
    /// def DeriveKeyPair(seed):
    #[expect(clippy::type_complexity)]
    fn derive_key_pair(
        seed: &Array<u8, H::DecapsulationKeySize>,
    ) -> (
        &Array<u8, H::DecapsulationKeySize>,
        (
            <H::KemPQ as Kem>::EncapsulationKey,
            GroupPublicKey<H::GroupT>,
        ),
    ) {
        // (ek_PQ, ek_T, dk_PQ, dk_T) = expandDecapsKeyG(seed)
        let (
            encapsulation_key_pq,
            encapsulation_key_t,
            _decapsulation_key_pq,
            _decapsulation_key_t,
        ) = expand_decaps_key_g::<H>(seed);

        // return (seed, concat(ek_PQ, ek_T))
        (seed, (encapsulation_key_pq, encapsulation_key_t))
    }
}

impl<H: HybridKemParameter> Generate for HybridKemDecapsulationKey<H>
where
    <H::KemPQ as Kem>::DecapsulationKey: KeyInit,
{
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let seed = Array::try_generate_from_rng(rng)?;
        Ok(HybridKemDecapsulationKey::new(&seed))
    }
}

impl<H: HybridKemParameter> KeyExport for HybridKemDecapsulationKey<H> {
    fn to_bytes(&self) -> Key<Self> {
        self.seed.clone()
    }
}

impl<H: HybridKemParameter> KeyInit for HybridKemDecapsulationKey<H>
where
    <H::KemPQ as Kem>::DecapsulationKey: KeyInit,
{
    fn new(seed: &Key<Self>) -> Self {
        let (encapsulation_key_pq, encapsulation_key_t, decapsulation_key_pq, decapsulation_key_t) =
            expand_decaps_key_g::<H>(seed);

        HybridKemDecapsulationKey {
            seed: seed.clone(),
            decapsulation_key_pq,
            decapsulation_key_t,
            encapsulation_key: HybridKemEncapsulationKey {
                encapsulation_key_pq,
                encapsulation_key_t,
            },
        }
    }
}

impl<H: HybridKemParameter> KeySizeUser for HybridKemDecapsulationKey<H> {
    type KeySize = H::DecapsulationKeySize;
}

trait RandomScalar: Curve {
    type SeedSize: ArraySize;

    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.html#section-3.1.1>
    ///
    /// def RandomScalar(seed):
    fn random_scalar(seed: &Array<u8, Self::SeedSize>) -> Option<GroupPrivateKey<Self>> {
        // start = 0
        // end = Nscalar
        // sk = OS2IP(seed[start : end])
        //
        // while sk == 0 || sk >= order:
        //   start = end
        //   end = end + Nscalar
        //   if end > len(seed):
        //       raise Exception("Rejection sampling failed")
        //   sk = OS2IP(seed[start : end])
        // return sk
        #[expect(clippy::chunks_exact_to_as_chunks)]
        for chunk in seed.chunks_exact(Self::FieldBytesSize::USIZE) {
            if let Some(secret_key) = Array::try_from(chunk)
                .ok()
                .and_then(|bytes| ScalarValue::from_bytes(&bytes).into_option())
                .and_then(|scalar| GroupPrivateKey::from_scalar(scalar).into_option())
            {
                return Some(secret_key);
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

/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-12.html#section-5.1.1>
///
/// def expandDecapsKeyG(seed):
fn expand_decaps_key_g<H: HybridKemParameter>(
    seed: &Array<u8, H::DecapsulationKeySize>,
) -> (
    <H::KemPQ as Kem>::EncapsulationKey,
    GroupPublicKey<H::GroupT>,
    <H::KemPQ as Kem>::DecapsulationKey,
    GroupPrivateKey<H::GroupT>,
)
where
    <H::KemPQ as Kem>::DecapsulationKey: KeyInit,
{
    // seed_full = PRG(seed)
    let mut prg = H::PRG::default();
    prg.update(&seed);
    let mut seed_full = prg.finalize_xof();

    // (seed_PQ, seed_T) = split(KEM_PQ.Nseed, Group_T.Nseed, seed_full)
    let mut seed_pq = Array::default();
    let mut seed_t = Array::default();
    seed_full.read(&mut seed_pq);
    seed_full.read(&mut seed_t);

    // (dk_PQ, ek_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)
    let decapsulation_key_pq = <H::KemPQ as Kem>::DecapsulationKey::new(&seed_pq);
    let encapsulation_key_pq = decapsulation_key_pq.encapsulation_key().clone();

    // dk_T = Group_T.RandomScalar(seed_T)
    let decapsulation_key_t = H::GroupT::random_scalar(&seed_t)
        .expect("RandomScalar fails with cryptographically negligible probability");

    // ek_T = Group_T.Exp(Group_T.g, dk_T)
    let encapsulation_key_t = decapsulation_key_t.public_key();

    // return (ek_PQ, ek_T, dk_PQ, dk_T)
    (
        encapsulation_key_pq,
        encapsulation_key_t,
        decapsulation_key_pq,
        decapsulation_key_t,
    )
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.1.1>
///
/// def prepareEncapsG(ek_PQ, ek_T):
#[expect(clippy::type_complexity)]
fn prepare_encaps_g<H: HybridKemParameter, R: CryptoRng + ?Sized>(
    encapsulation_key_pq: &<H::KemPQ as Kem>::EncapsulationKey,
    encapsulation_key_t: &GroupPublicKey<H::GroupT>,
    rng: &mut R,
) -> (
    Array<u8, <H::KemPQ as Kem>::SharedKeySize>,
    Array<u8, <H::GroupT as Curve>::FieldBytesSize>,
    Array<u8, <H::KemPQ as Kem>::CiphertextSize>,
    GroupPublicKey<H::GroupT>,
) {
    // (ss_PQ, ct_PQ) = KEM_PQ.Encaps(ek_PQ)
    let (ciphertext_pq, shared_secret_pq) = encapsulation_key_pq.encapsulate_with_rng(rng);

    // sk_E = Group_T.RandomScalar(random(Group_T.Nseed))
    let secret_key_e = GroupPrivateKey::<H::GroupT>::generate_from_rng(rng);

    // ct_T = Group_T.Exp(Group_T.g, sk_E)
    let ciphertext_t = secret_key_e.public_key();

    // ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ek_T, sk_E))
    let shared_secret_t =
        element_to_shared_secret::<H>(secret_key_e.diffie_hellman(encapsulation_key_t));

    // return (ss_PQ, ss_T, ct_PQ, ct_T)
    (
        shared_secret_pq,
        shared_secret_t,
        ciphertext_pq,
        ciphertext_t,
    )
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.1.1>
///
/// def prepareDecapsG(ct_PQ, ct_T, dk_PQ, dk_T):
#[expect(clippy::type_complexity)]
fn prepare_decaps_g<H: HybridKemParameter>(
    ciphertext_pq: &Array<u8, <H::KemPQ as Kem>::CiphertextSize>,
    ciphertext_t: &GroupPublicKey<H::GroupT>,
    decapsulation_key_pq: &<H::KemPQ as Kem>::DecapsulationKey,
    decapsulation_key_t: &GroupPrivateKey<H::GroupT>,
) -> Result<
    (
        Array<u8, <H::KemPQ as Kem>::SharedKeySize>,
        Array<u8, <H::GroupT as Curve>::FieldBytesSize>,
    ),
    <<H::KemPQ as Kem>::DecapsulationKey as TryDecapsulate>::Error,
> {
    // ss_PQ = KEM_PQ.Decaps(dk_PQ, ct_PQ)
    let shared_secret_pq = decapsulation_key_pq.try_decapsulate(ciphertext_pq)?;

    // ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ct_T, dk_T))
    let shared_secret_t =
        element_to_shared_secret::<H>(decapsulation_key_t.diffie_hellman(ciphertext_t));

    // return (ss_PQ, ss_T)
    Ok((shared_secret_pq, shared_secret_t))
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-5.1.3>
///
/// def C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, label):
fn c2pri_combiner<H: HybridKemParameter>(
    shared_secret_pq: &SharedKey<H::KemPQ>,
    shared_secret_t: &SharedSecret<H::GroupT>,
    ciphertext_t: &GroupPublicKey<H::GroupT>,
    encapsulation_t: &GroupPublicKey<H::GroupT>,
    label: &[u8],
) -> Array<u8, <H::KDF as OutputSizeUser>::OutputSize>
where
    <H::GroupT as Curve>::FieldBytesSize: ModulusSize,
    <H::GroupT as CurveArithmetic>::AffinePoint: FromSec1Point<H::GroupT> + ToSec1Point<H::GroupT>,
{
    // return KDF(concat(ss_PQ, ss_T, ct_T, ek_T, label))
    let mut hasher = H::KDF::default();
    hasher.update(shared_secret_pq);
    hasher.update(shared_secret_t.raw_secret_bytes());
    hasher.update(ciphertext_t.to_sec1_bytes());
    hasher.update(encapsulation_t.to_sec1_bytes());
    hasher.update(label);
    hasher.finalize()
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12#section-4.2>
///
/// ElementToSharedSecret(P) -> ss: Extract a shared secret from an element of the group (e.g., by
/// taking the X coordinate of an elliptic curve point).
fn element_to_shared_secret<H: HybridKemParameter>(
    p: SharedSecret<H::GroupT>,
) -> Array<u8, <H::GroupT as Curve>::FieldBytesSize> {
    *p.raw_secret_bytes()
}

// seed: seed
// ss  : shared secret
// ct  : ciphertext
// ek  : encapsulation key (encapsulation key for KEMs, public key for Nominal Groups)
// dk  : decapsulation key (decapsulation key for KEMs, secret key for Nominal Groups)
// sk  : secret key for Nominal Groups
//
// _PQ : Post-quantum
// _T  : Traditional
