use kem::{Decapsulator, KeyExport, KeyInit};
use ml_kem::array::Array;

use crate::{HybridKemDecapsulationKey, MlKem768P256, expand_decaps_key_g};

#[expect(clippy::complexity)]
fn mlkem768p256_test_case_1() -> (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
) {
    let seed = hex::decode(concat!(
        "000000000000000000000000000000000000000000000000000000000",
        "0000000",
    ))
    .unwrap();
    let randomness = hex::decode(concat!(
        "646464646464646464646464646464646464646464646464646",
        "464646464646464646464646464646464646464646464646464",
        "646464646464646464646464646464646464646464646464646",
        "464646464646464646464646464646464646464646464646464",
        "646464646464646464646464646464646464646464646464646",
        "464646464646464646464646464646464646464646464646464",
        "64646464646464",
    ))
    .unwrap();
    let encapsulation_key = hex::decode(concat!(
        "3d209f716752f6408e7f89bceef97ac3885300453779",
        "27644ef046c0a7cae978c8841a0133aac4f1e1a70272",
        "77f671219cf58b85d29c8fec08edd432e787a3cf9936",
        "fe0026a113cb9efb1d7214049527bfe2141ea170b029",
        "4a59403ab0ce16760a8baa95b823cbb8aacdcc17ef32",
        "775223c791e3740163941f9bb3f63346bef1c050c31f",
        "932c62719429aff14c2bd438ab135bed692d56c77c04",
        "cbbffd6335b578318b513771e84b14ea821262141ca0",
        "06ccb8bf2500aa1008970f216fe7f1ae34125aa29049",
        "2c069a189222adc322f97649c762c7d3128ad3bb2667",
        "971d0744014bc3b67445cbcd0b3e7ea69fb1cb9f9c33",
        "1f97487920187292926d04a25a2650abbd44982bb0c3",
        "c6301fe6a61330d24d8a3c7021dc3e3392c79a139b37",
        "613bba67a2984298507b84a4d61eef18acfb979af2d3",
        "9caa4c0db4513815359d76fc378c63a7f4f3053b1716",
        "8d0221cf0c2eec5514ba235f81d04d67c3b5c5180949",
        "17671c26a7c046457533cc32844581277a03eb065c45",
        "29a779a9a5878f2aac3f81db9ed3d8c9345697058cbb",
        "99d379bca16d8fdb61d129960390524791b9d3e501b9",
        "00bd1e5002e095be06c23f1fb212f5801f24b6b28c0c",
        "5493d246d02aa29fa3acfbe15ac4e212eb0b6f69ebbe",
        "a259a2703aa4c308224bdb741c65c7a5d4bff7882795",
        "07bbfe513d7aa5694e7b3cdf62ab36432742d4a0ca9b",
        "3570ba742fa803b46989c8526ea586cc4fc32866143b",
        "79601725fa545fd280b404530318bbc3371194710b6d",
        "74beaa629eb18a36a953b75915ae96999ba5c88cdc56",
        "a46861c50032c9b630bcc1445a30878979bc55a2c095",
        "5bf399b231203b90c651b6afe0e242b5a543250b142f",
        "7291ed753d816098f7913302a8ce91641716623d4fc2",
        "ac6772aa5f3674042b7c4a18a2186289a4ac4e200774",
        "596ca03e6798c7506b984999db6ac142586bae0799f1",
        "e776f9f5247dc574d8556ddf9bbbc4ca3643263457f7",
        "4248010d62d4311268360aecb4902b450bf2050ecb8b",
        "a7a92820d233f5a14ed31225a1d17ca6f19e825894cf",
        "b1807d922cbd60761134be419144bcf72006366a4460",
        "137ad9136c113f05eb54c409520edc72e4150cc3a24b",
        "0f819eec11bbd19ca9645b0810a60b4a8a9e9c395539",
        "6a1653955b047bcf4f98433c27236c570d75f809e44a",
        "af2dc33665826351872c293350ab324518c8c0c80b52",
        "1c80c81a56bdc968a5650315a830c8bb17532c62ccc2",
        "3b1d46412c256b224fd4674491803501d0143125c757",
        "7239689965b6989ca561793c0f85c62a9e13487da176",
        "62a7188c70b1040a67ed4c3f85e74e3691822fb96314",
        "d6134fe6a626b3cbe1461d62a7b573b2cc75579ffa22",
        "967e36ceb2a1aa0b71875a22751d706b72ca9ecd0c81",
        "00ad0aa58009a5c83fffe91759e6baa0a9345af99fe3",
        "b69509dbc84032868844ab3f65bb1df8beadf36442e4",
        "8e339c967023a525411544c789a2f04dacd06ffef783",
        "02210450b931f6b4c32aab34a3f5260b810f4c9a946f",
        "c22d3baabaa80ba8d9955d6dc35e8609b4256b482cdc",
        "9d8977c1a47a354e7c527fdb1672e166917b95cd6351",
        "820261daab361f8a2dcbb240c55abd6a8105e5291b42",
        "7b566d731e6b7047189cff20d8b120e0b3e72472d1b0",
        "086812200fd3698e23f06e4f4e08bbb54cc2049c039c",
        "845be659999c8fa48d7f62327c146cf1bc0b0bb1b91b",
        "30174b7bc220d422023bff6b0dee263532c503f3982e",
        "4d3e27071b855578a9a9aa63b8a8c339bf",
    ))
    .unwrap();
    let decapsulation_key = hex::decode(concat!(
        "00000000000000000000000000000000000000000000",
        "00000000000000000000",
    ))
    .unwrap();
    let decapsulation_key_pq = hex::decode(concat!(
        "f5977c8283546a63723bc31d2619124f11db46586",
        "43336741df81757d5ad3062221e124311ec7f7181",
        "568de7938df805d894f5fded465001a04e260a494",
        "82cf5",
    ))
    .unwrap();
    let decapsulation_key_t = hex::decode(concat!(
        "e00b3f9d338de90488973787b0916a4a9ae8bebf4e",
        "2bc07a7bc18f1a62215182",
    ))
    .unwrap();
    let ciphertext = hex::decode(concat!(
        "d81018a94f8078e02105beaa814e003390befa4589bb614f773",
        "97af42d8e8150796f2c88a4efca81b8cf93c0ae3716c54ec1b0",
        "45e3875f38c2dd12d7f717bd7fb701a9fecda5ed8b764c9a35d",
        "4a5c1d8930f6071f653eebb2d1afa77debb8302d16f17e0f5f3",
        "920a71a4d49beafa0e1c7e443f8abca64a65a9e81a97e7357bf",
        "902573363c0e1a12e5228036828e3f759121fada92441fe334e",
        "85d79347e470d2fed945541d832c54baaa3cb7526c3853954db",
        "4f73547cc7c27fd38398bfa7704952cb841e38b270e4db7435f",
        "0ee22f57d7ad3270bd0c88e71b4b864cf2277c65daa10a6dad4",
        "c7abecd95cc4ebec39c08404b522e4ecc1545713f76bebd3b5a",
        "0f2feb3461936065dbd13f6a1f61e1b142a2af2e5a482ba2c50",
        "cf0317049c0b3bfd6d5e9240eba9111d2030fdea17e33b65240",
        "20d30b0c4f8069285f3a6ca267d287d01e827d8422bf5426e11",
        "688bfc73756af1841b1c87e126cb50c914b5b2b8673488ad3b0",
        "74cad77a3840eb12dd688f313ee1e9ff8c479a678f276356fc9",
        "d65e1d5b4c1e9855b4175db144f7767c12061769190fe6b5e51",
        "563b91f94d131a2b796bd2980ed0dab4ae7a7110e920007a757",
        "158a5eb8662cbf89ddffe9d8196821313cdc00108853fc4746b",
        "111d5b56da638d8ed2973918960f5dfe93ead3ae521e957cec3",
        "c8d843e8fce234c70ad055177f235439d6098bdd771b1cfcfad",
        "aab4f50a7378185c62409f383c8ff658c2a2af66498cfd81e96",
        "2766ac6b774e88424fb4f331837d0a28502708477caf8780a15",
        "6d723f68fca791e1cd2397bfc2b24c77c765d9b2af36f732d52",
        "107517efd8157b283b440a613f756c364ca108971a8878199a9",
        "3f260baec3e850033cc032c2e53f823576affb4d3b116e2d160",
        "49152c35aaa263ab376f0ad5ede6a749607a283e3016e62191c",
        "0e8fde33e718cd989591c9a205d608d99fcb8a7471603d716cb",
        "01b56328d7d880aec2851f4e6d8b5016c25647e9026ebb44154",
        "3e8012dbfcf078d4012b8c39184dd64f3821b4774ae4e36365f",
        "8baf2bd1f6667c017a1e65ff8a1554458fb3f367c02721752bf",
        "a56fc7fd566ae95ffb208f919ef12f4cf8a2fdd141a8df559bd",
        "db7b8d1f04ee6d4cf7805d142989caf216dfae985faaab9974f",
        "6d9f8aa1129084db8db912b1655f595ffbaa66491ab4655fd73",
        "4cfd4bb0c0289d4bcc8fc5e9943b351cb147c8db059a24004d1",
        "c3e3bb4c14a881e5101acb736c65c5d579acb67ee85a560277b",
        "43338fe79d34b772c5da001da3b5a3383dd81319a0b4542e6d7",
        "e46eed5314cc70eb231de27b6e760db598ba19995cf69be0e44",
        "58e35f3f274aca2455d43fe3344e183c6dc47c857dbe9907b41",
        "e41006d91b25adcafc098fe66f7554be8dad493c4f4b1dbf7a5",
        "1464139db474afab5572f92a2232b59be56a72c0505149dae5c",
        "de1e602877037de7802b5f6fa47a4c9a3e52d6ca15339920254",
        "e9ffb53c7b834cc0288ed9905a1841e9390ea94a8898bd4c6b6",
        "d6027e4d43c7867242515bbeefe12340fc04428a824ea7cf56a",
        "d2a64ed368b71315d80cee846007cff1d2eea2c3f0f92153730",
        "4ae598f98dd10d1f102811a4e2d161c3fd8bbb193d4b25bee95",
        "0ac839c0f9d",
    ))
    .unwrap();
    let shared_secret = hex::decode(concat!(
        "9bd018e869bb01b63fb8f5da374a73d347ea14cb2bc570b1",
        "3d0908e2288ec456",
    ))
    .unwrap();

    (
        seed,
        randomness,
        encapsulation_key,
        decapsulation_key,
        decapsulation_key_pq,
        decapsulation_key_t,
        ciphertext,
        shared_secret,
    )
}

#[test]
fn test_expand_decaps_key_g() {
    let (
        seed_bytes,
        _randomness_bytes,
        encapsulation_key_bytes,
        decapsulation_key_bytes,
        decapsulation_key_pq_bytes,
        decapsulation_key_t_bytes,
        _ciphertext_bytes,
        _shared_secret_bytes,
    ) = mlkem768p256_test_case_1();

    // let (encapsulation_key, ) = expand_decaps_key_g::<MlKem768,NistP256,Shake256>(&Array::try_from(&seed_bytes).unwrap());

    let seed = Array::slice_as_array(&seed_bytes).expect("Invalid seed length");
    let decapsulation_key = HybridKemDecapsulationKey::<MlKem768P256>::new(seed);
    let encapsulation_key = decapsulation_key.encapsulation_key();
    assert_eq!(
        encapsulation_key.to_bytes().as_slice(),
        &encapsulation_key_bytes
    );
    assert_eq!(
        decapsulation_key.to_bytes().as_slice(),
        &decapsulation_key_bytes
    );
    let (_, _, decapsulation_key_pq, decapsulation_key_t) =
        expand_decaps_key_g::<MlKem768P256>(seed);
    assert_eq!(
        decapsulation_key_pq.to_bytes().as_slice(),
        &decapsulation_key_pq_bytes
    );
    assert_eq!(
        decapsulation_key_t.to_bytes().as_slice(),
        &decapsulation_key_t_bytes
    );
}
