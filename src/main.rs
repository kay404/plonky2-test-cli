#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use hex;
use clap::Parser;
use num::BigUint;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
// use sha3::{Digest, Keccak256};
use plonky2::util::timing::TimingTree;
use log::{info, Level, LevelFilter};

use plonky2_ecdsa::gadgets::biguint::{CircuitBuilderBiguint, BigUintTarget};
use plonky2_keccak256::keccak256::{CircuitBuilderHashKeccak, WitnessHashKeccak, KECCAK256_R};
use plonky2_keccak256::CircuitBuilderHash;

use plonky2::field::types::Sample;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;

use plonky2_ecdsa::gadgets::recursive_proof::recursive_proof;
use plonky2_ecdsa::gadgets::ecdsa::prove_ecdsa;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::curve::curve_types::{CurveScalar, Curve};
use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature};

use plonky2::field::types::Field;
use plonky2_u32::gadgets::arithmetic_u32::CircuitBuilderU32;
use sha3::{Digest, Keccak256};

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value_t = false)]
    keccak: bool,
    #[arg(short, long, default_value_t = false)]
    ecdsa: bool,
    #[arg(short, long, default_value_t = false)]
    all: bool,
    #[arg(short, long, default_value_t = false)]
    merge: bool,
    #[arg(short, long)]
    msg: Option<String>,
    #[arg(short, long)]
    pk: Option<String>,
    #[arg(short, long)]
    sig: Option<String>,
}

fn main() {
    let mut log_builder = env_logger::Builder::from_default_env();
    log_builder.format_timestamp(None);
    log_builder.filter_level(LevelFilter::Info);
    log_builder.try_init().unwrap();

    let args = Cli::parse();

    if args.keccak {
        test_keccak();
    } else if args.ecdsa {
        test_ecdsa();
    } else if args.all {
        test_all();
    } else if args.merge {
        merge();
    }
}

fn test_keccak() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let tests = [
        [
            // empty string
            "",
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        ],
        [
            // empty trie
            "80",
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        ],
        [
            // short hash, e.g. last step of storage proof
            "e19f37a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee301",
            "19225e4ee19eb5a11e5260392e6d5154d4bc6a35d89c9d18bf6a63104e9bbcc2",
        ],
        [
            // storage proof
            "f90211a0dc6ab9a606e3ef2e125ebd792c502cb6500aa1d1a80fa6e706482175742f4744a0bcb03c1a82cc80a677c98fe35c8ff953d1de3b1322a33f2c8d10132eac5639bfa02d81761f56b3bcd9137ef6823f879ba41c32c925c95f4658a7b1418d14424175a0c1c4d0f264475235249547fdfe63cf4aed82ef8cfc3019ed217fcf5f25620067a0f6d7a23257b2c155b5c4ffb37d76d4e6e8fae6bdab5d3cf2d868d4741b80d214a0f7bb2681b64939b292248bd66c21c40d54fca9460abda45da28a50b746b1b2a1a037bfc201846115d4d0e85eb6b3f0920817a7e0081bcb8bdaeb9c7dcf726b0885a0a238a31e3c6a36f24afa650058eabbf3682cc83a576d58453b7b74a3ffac8d1aa03315cb55fbc6bc9d9987cd0e2001f39305961856126d0ef7280d01d45c0b27d5a03cfc7bd374410e92dba88a3a8ce380a6ceed3ea977ee64f904e3723ce4afed01a0e5d3350effa6d755100afa3e4560d39ddc2dd35988f65bc0931f924134c4a2aba07609fdcdd38bf9e2f7b35b022a30e564877323f4d38381b3c792ac21f7617e28a0cd43ad06bbdd7d4dcf450e5212325ae2b177e80701c64f492b6e095e0cd43bbba0652063acc150fc0a729761d4fd80f230329e2eef41cb0dda1df74a4002ba6c4ca0ee0c0661fec773e14f94d8977e69cb22b41cc15fe9c682160488c0a2aa7daf4ba0d4cb2d1c9f1ff574d4854301a6ea891143e123d4dd04db1432509c2307f10a2180",
            "578d0063e7f59c51a1b609f98ab8447cfb69422e3e92cc3cafdc3499735d98a8",
        ],
        [
            // account proof
            "f90211a0160c36cc6e1f0499f82e964ad41216e3222f9e439c2c8ecebb9f6d8e8682fbd3a0c9288b274cda35ac8ea4ecc51a40b6291d965f66f8dbd029e9419e583d7f0d6aa08a768a530c839cd9ba26f39f381a4e6d1c75bdbaccfd0e08773275460bebb392a0e8b3c8ca435de4f3614f65507f2ffdf77f446f66dfe295fa57287d838505d85ca0d073345bee411e9ee68097c6797025bdbae114c2847821fb12e8d5876cc74fd5a07471033f73ed2b5f1de920765c8d8c895016833aea875cbedfac28eeaf78b38ca073ef613ea081010ff0c3e685dcdd7599e2724121629d736ae206a779524619cca0062fee86b0c595607a46b39da1db0b8d6950f7ceb15a4240b26502bd28f71266a037433cfba971c3f88dd48a9ba77f00af7b916c813ef05e1621439ce39c06f676a081a896e219d44b627d81c27d6af8deacedf503aac7a709325f244add2ad4320da086fd39396891a30937f64e299a7d2fb85814a910c477cee64b0db109d92206aaa023ed91b155f896a409658f30d87f3f16d5bc6193b4ac2e3d5524a980e57149d4a09885e8e7165d55d4a32b0f8b226c382c6aa6d632ca68bdd79a17fd65c31c7fc0a08a04011c30e2fa3121663b88a08732017130f702a24dfe6107ca5757a8caf92aa0ac8239f39a106972436c768499afcc787d257c3d7928bfa524e90752500f4334a0e68fba45dceffc99e87785a850a7fefa813a803f2eb13359e5602d98fce7845080",
            "f530311917cff532bf25f103e7a0c092be92ace7e919f7a4f644e5b011e677f3",
        ],
        [
            // med hash
            "f9015180a060f3bdb593359882a705ff924581eb99537f2428a007a0006f459182f07dba16a06776a7e6abd64250488ed106c0fbd66ee338b7ce59ae967714ce43ecd5a3de97a0f8d6740520928d0e540bf439f1c214ce434f349e4c9b71bb9fcce14144a48914a0f31b2b9570033a103b8a4c0db8debbff2cf8dc4eb2ed31fa292d41c7adf13dc980808080a016a530127910d9d4a89450f0c9dc075545441126b222396eb28e30c73c01c8a9a05d9eb59dae800d3f8cfe8efdfa86776fc7f3b09dfc5b2f537b2c2abda9787755a0bcdc8744035201f5d8d9bd0f440887a40d8cafc3f986f20ce276b1b1e37c01fda0f56f6a7cbf29f15d0923780608ffbb5671fcb518b482812bb8a02b46bae016f0a0cc20fa696765f56b03c14de2b16ab042f191dafb61df0dab8e1101cc08e78f3980a0e1328f040062749d53d278300e0e9857744279645fbc7a3ae11fcb87a6e000e680",
            "d4cb2d1c9f1ff574d4854301a6ea891143e123d4dd04db1432509c2307f10a21",
        ],
    ];

    for t in tests {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input = hex::decode(t[0]).unwrap();
        let block_size_in_bytes = 136; // in bytes
        let block_num = input.len() / block_size_in_bytes + 1;
    
        let hash_target = builder.add_virtual_hash_input_target(block_num, KECCAK256_R);
        let hash_output = builder.hash_keccak256(&hash_target);
        let num_gates = builder.num_gates();
        // let copy_constraints = builder.copy_constraints.len();
        let copy_constraints = "<private>";
        let data = builder.build::<C>();
        println!(
            "keccak256 num_gates={}, copy_constraints={}, quotient_degree_factor={}",
            num_gates, copy_constraints, data.common.quotient_degree_factor
        );
    
        // for t in tests {
        let input = hex::decode(t[0]).unwrap();
        let output = hex::decode(t[1]).unwrap();
    
        // test program
        let mut hasher = Keccak256::new();
        hasher.update(input.as_slice());
        let result = hasher.finalize();
        assert_eq!(result[..], output[..]);
    
        let timing = TimingTree::new("prove keccak", Level::Info);
        // test circuit
        let mut pw = PartialWitness::new();
        pw.set_keccak256_input_target(&hash_target, &input);
        pw.set_keccak256_output_target(&hash_output, &output);
    
        let proof = data.prove(pw).unwrap();
        timing.print();
        assert!(data.verify(proof).is_ok());
    }
}

fn test_ecdsa(){    
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Curve = Secp256K1;

    fn sample_ecdsa() -> (Secp256K1Scalar, ECDSAPublicKey<Curve>, ECDSASignature<Curve>) {
        let msg = Secp256K1Scalar::rand();
        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let sig = sign_message(msg, sk);

        (msg, pk, sig)
    }

    let config = CircuitConfig::standard_recursion_config();

    let ecdsa_1 = sample_ecdsa();
    let ecdsa_2 = sample_ecdsa();
    let ecdsa_3 = sample_ecdsa();

    // The performance bottleneck is due to the proving of a single `ecdsa` verification, and there needs to be a multithread version of the below proving
    info!("Prove single ecdsa starting...");
    let timing = TimingTree::new("prove ecdsa 1, 2, and 3", Level::Info);
    let mut proofs = std::vec::Vec::new();
    proofs.push(prove_ecdsa::<F, C, D>(ecdsa_1.0, ecdsa_1.2, ecdsa_1.1).expect("prove error 1"));
    proofs.push(prove_ecdsa::<F, C, D>(ecdsa_2.0, ecdsa_2.2, ecdsa_2.1).expect("prove error 2"));
    proofs.push(prove_ecdsa::<F, C, D>(ecdsa_3.0, ecdsa_3.2, ecdsa_3.1).expect("prove error 3"));
    timing.print();
    info!("Prove single ecdsa ended and start recursive proving...");

    // Recursively verify the proof
    let timing = TimingTree::new("Recursively verify the proof", Level::Info);
    let middle = recursive_proof::<F, C, C, D>(&proofs, &config, None).expect("prove recursive error!");
    let (_, _, cd) = &middle;
    info!(
        "Single recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );
    timing.print();

    // Add a second layer of recursion to shrink the proof size further
    let timing = TimingTree::new("final prove and verify", Level::Info);
    let final_proof_vec = std::vec![middle];
    let outer = recursive_proof::<F, C, C, D>(&final_proof_vec, &config, None).expect("prove final error!");
    let (_, _, cd) = &outer;
    info!(
        "Double recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );
    timing.print();
}

fn test_all() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Curve = Secp256K1;

    // msg "Hello omniverse"
    let msg = "48656c6c6f206f6d6e697665727365";
    let msg_hash = "ad80a0940685275182f26b9e99270f3792d43fb797781b69db37cea2413f89a4";
    
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let input = hex::decode(msg).unwrap();
    let output = hex::decode(msg_hash).unwrap();

    let msg =
    Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_radix_be(&input, 256).unwrap());
    let block_size_in_bytes = 136; // in bytes
    let block_num = input.len() / block_size_in_bytes + 1;
    let hash_target = builder.add_virtual_hash_input_target(block_num, KECCAK256_R);
    let hash_output = builder.hash_keccak256(&hash_target);
    let data = builder.build::<C>();

    let timing = TimingTree::new("prove keccak", Level::Info);
    // test circuit
    let mut pw = PartialWitness::new();
    pw.set_keccak256_input_target(&hash_target, &input);
    pw.set_keccak256_output_target(&hash_output, &output);

    let proof = data.prove(pw).unwrap();
    timing.print();
    assert!(data.verify(proof).is_ok());

    // let msg = Secp256K1Scalar::rand();
    let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let sig = sign_message(msg, sk);

    let _ = prove_ecdsa::<F, C, D>(msg, sig, pk);
}

fn merge() {
    use plonky2_ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
    use plonky2_ecdsa::gadgets::ecdsa::{verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget, RegisterNonNativePublicTarget, SetNonNativeTarget};
    use plonky2_ecdsa::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
    use core::marker::PhantomData;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Curve = Secp256K1; 
    
    // msg "Hello omniverse"
    let msg = "48656c6c6f206f6d6e697665727365";
    let msg_hash = "ad80a0940685275182f26b9e99270f3792d43fb797781b69db37cea2413f89a4";
    
    let config = CircuitConfig::wide_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let input = hex::decode(msg).unwrap();
    let output = hex::decode(msg_hash).unwrap();

    let msg =
        Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_radix_be(&input, 256).unwrap());
    let block_size_in_bytes = 136; // in bytes
    let block_num = input.len() / block_size_in_bytes + 1;
    let hash_target = builder.add_virtual_hash_input_target(block_num, KECCAK256_R);
    let hash_output = builder.hash_keccak256(&hash_target);
    let msg_target: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();
    let pk_target: ECDSAPublicKeyTarget<Secp256K1> = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());

    let r_target = builder.add_virtual_nonnative_target();
    let s_target = builder.add_virtual_nonnative_target();
    let sig_target = ECDSASignatureTarget::<Curve> {
        r: r_target,
        s: s_target,
    };

    let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    let sig = sign_message(msg, sk);
    pk_target.register_public_input(&mut builder);
    sig_target.register_public_input(&mut builder);

    verify_message_circuit(&mut builder, msg_target.clone(), sig_target.clone(), pk_target.clone());

    let mut pw = PartialWitness::new();
    msg_target.set_nonative_target(&mut pw, &msg);
    pk_target.set_ecdsa_pk_target(&mut pw, &pk);
    sig_target.set_ecdsa_signature_target(&mut pw, &sig);
    pw.set_keccak256_input_target(&hash_target, &input);
    pw.set_keccak256_output_target(&hash_output, &output);

    info!(
        "Constructing inner proof of `prove_ecdsa` with {} gates",
        builder.num_gates()
    );

    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Info);
    data.verify(proof.clone()).expect("verify error");
    timing.print();

    // test_serialization(&proof, &data.verifier_only, &data.common)?;
    // Ok((proof, data.verifier_only, data.common))

}