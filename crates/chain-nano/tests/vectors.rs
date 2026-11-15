#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Known-answer tests from the public Nano protocol documentation and the live network genesis block, plus
//! behavioural checks. The key-derivation vector is additionally reproduced by an independent pure-Python
//! implementation in `scripts/nano_reference.py` (outside this crate).

use shadowallet_chain_nano::*;

fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).unwrap();
    out
}

#[test]
fn zero_seed_index_zero_matches_documentation() {
    let seed = Seed::from_hex(&"0".repeat(64)).unwrap();
    let private = derive_private_key(&seed, 0);
    assert_eq!(
        hex::encode_upper(private),
        "9F0E444C69F77A49BD0BE89DB92C38FE713E0963165CCA12FAF5712D7657120F"
    );
    let public = public_key(&private);
    assert_eq!(
        hex::encode_upper(public),
        "C008B814A7D269A1FA3C6528B19201A24D797912DB9996FF02A1FF356E45552B"
    );
    assert_eq!(
        encode_address(&public),
        "nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7"
    );
    assert_eq!(
        decode_address("nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7")
            .unwrap(),
        public
    );
    assert_eq!(
        decode_address("xrb_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7").unwrap(),
        public
    );
}

#[test]
fn live_genesis_block_hash_signature_and_work() {
    let genesis = h32("E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA");
    assert_eq!(
        encode_address(&genesis),
        "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
    );
    // The genesis block is a *legacy open* block: hash = Blake2b-256(source || representative || account).
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(genesis);
    hasher.update(genesis);
    hasher.update(genesis);
    let hash: [u8; 32] = hasher.finalize().into();
    assert_eq!(
        hex::encode_upper(hash),
        "991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948"
    );
    let mut sig = [0u8; 64];
    hex::decode_to_slice("9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02", &mut sig).unwrap();
    verify_hash(&genesis, &hash, &sig).expect("genesis signature must verify with Blake2b-Ed25519");
    let mut bad = sig;
    bad[10] ^= 1;
    assert!(verify_hash(&genesis, &hash, &bad).is_err());
    assert!(Difficulty(0xffff_ffc0_0000_0000).is_met(0x62f0_5417_dd3f_b691, &genesis));
}

#[test]
fn sign_verify_round_trip_and_wrong_key_refused() {
    let seed = Seed::from_hex(&"11".repeat(32)).unwrap();
    let private = derive_private_key(&seed, 3);
    let account = public_key(&private);
    let block = StateBlock {
        account,
        previous: [7; 32],
        representative: account,
        balance: 5,
        link: [9; 32],
    };
    let signed = SignedBlock::sign(block.clone(), &private).unwrap();
    signed.verify().unwrap();
    let other = derive_private_key(&seed, 4);
    assert!(SignedBlock::sign(block, &other).is_err());
}

#[test]
fn address_rejects_corruption() {
    let good = "nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7";
    assert!(decode_address(&good.replace("3b7", "3b8")).is_err());
    assert!(decode_address("nano_1").is_err());
    assert!(
        decode_address("btc_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7").is_err()
    );
    assert!(decode_address(&good.replace('3', "l")).is_err());
}

#[test]
fn work_generation_meets_a_low_threshold_and_fails_closed() {
    let root = [5u8; 32];
    let d = Difficulty(0xfff0_0000_0000_0000);
    let w = generate_work(&root, d, 2, 1 << 28).unwrap();
    assert!(d.is_met(w, &root));
    assert!(generate_work(&root, Difficulty(u64::MAX), 1, 1000).is_err());
}

#[test]
fn network_registry_separates_live_test_and_beta() {
    // Mainnet is recognisable (read-only) but can never sign.
    let live = NanoNet::identify("live", LIVE_NETWORK_ID).unwrap();
    assert_eq!(live.kind, NetworkKind::Live);
    assert!(!live.can_sign());
    assert!(NanoNet::verify("live", LIVE_NETWORK_ID).is_err());
    // A node claiming a test name with the live genesis (or the reverse) is refused for signing and identification.
    assert!(NanoNet::verify("test", LIVE_NETWORK_ID).is_err());
    assert!(NanoNet::verify("beta", LIVE_NETWORK_ID).is_err());
    assert!(NanoNet::identify("live", TEST_NETWORK_ID).is_err());
    assert!(NanoNet::identify("test", BETA_NETWORK_ID).is_err());
    assert!(NanoNet::verify("test", &"AB".repeat(32)).is_err());
    // Test and beta are separate, signing-capable identities (case-insensitive hex).
    let test = NanoNet::verify("test", &TEST_NETWORK_ID.to_lowercase()).unwrap();
    assert_eq!((test.kind, test.can_sign()), (NetworkKind::Test, true));
    let beta = NanoNet::verify("beta", BETA_NETWORK_ID).unwrap();
    assert_eq!((beta.kind, beta.can_sign()), (NetworkKind::Beta, true));
    assert_ne!(TEST_NETWORK_ID, BETA_NETWORK_ID);
}

#[test]
fn test_network_genesis_account_is_the_one_a_real_test_node_reports() {
    // Observed from a real nano-node V28.2 built with NANO_NETWORK=test: `Genesis account:` in its log and `version`.
    let account =
        decode_address("nano_1jg8zygjg3pp5w644emqcbmjqpnzmubfni3kfe1s8pooeuxsw49fdq1mco9j")
            .unwrap();
    assert_eq!(
        encode_address(&account),
        "nano_1jg8zygjg3pp5w644emqcbmjqpnzmubfni3kfe1s8pooeuxsw49fdq1mco9j"
    );
    assert_eq!(
        TEST_NETWORK_ID,
        "B1D60C0B886B57401EF5A1DAA04340E53726AA6F4D706C085706F31BBD100CEE"
    );
    // The key published in nano-node's source (34F0A37A…) belongs to the dev network, not to test: its public key and
    // account are different from the test genesis, so it can never fund a test-network account.
    let dev_private = h32("34F0A37AAD20F4A260F0A5B3CB3D7FB50673212263E58A380BC10474BB039CE4");
    assert_ne!(public_key(&dev_private), account);
}

fn state(balance: u128, frontier: [u8; 32], confirmed: [u8; 32]) -> AccountState {
    AccountState {
        exists: true,
        frontier,
        balance,
        representative: [2; 32],
        confirmed_frontier: confirmed,
        confirmed_balance: balance,
        height: 1,
        confirmation_height: 1,
    }
}

#[test]
fn block_construction_rules() {
    let me = [1u8; 32];
    let s = state(100, [3; 32], [3; 32]);
    let p = prepare_send(&s, me, [4; 32], 40).unwrap();
    assert_eq!(
        (
            p.block.balance,
            p.block.previous,
            p.block.link,
            p.block.representative
        ),
        (60, [3; 32], [4; 32], [2; 32])
    );
    assert!(prepare_send(&s, me, [4; 32], 101).is_err());
    assert!(prepare_send(&s, me, [4; 32], 0).is_err());
    assert!(
        prepare_send(&state(100, [3; 32], [8; 32]), me, [4; 32], 1).is_err(),
        "unconfirmed frontier is refused"
    );
    assert!(prepare_send(&AccountState::default(), me, [4; 32], 1).is_err());
    let r = Receivable {
        hash: [6; 32],
        amount: 25,
        source: None,
    };
    let recv = prepare_receive(&s, me, [9; 32], &r).unwrap();
    assert_eq!(
        (recv.block.balance, recv.block.link, recv.kind),
        (125, [6; 32], BlockKind::Receive)
    );
    let open = prepare_receive(&AccountState::default(), me, [9; 32], &r).unwrap();
    assert_eq!(
        (
            open.kind,
            open.block.previous,
            open.block.representative,
            open.block.balance,
            open.block.work_root()
        ),
        (BlockKind::Open, [0; 32], [9; 32], 25, me)
    );
    let ch = prepare_change(&s, me, [7; 32]).unwrap();
    assert_eq!(
        (ch.block.balance, ch.block.representative, ch.block.link),
        (100, [7; 32], [0; 32])
    );
}

#[test]
fn slip10_ed25519_official_vectors() {
    // SLIP-0010 test vector 1 for ed25519 (seed 000102030405060708090a0b0c0d0e0f).
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    assert_eq!(
        hex::encode(slip10_ed25519(&seed, &[]).unwrap()),
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
    );
    assert_eq!(
        hex::encode(slip10_ed25519(&seed, &[0]).unwrap()),
        "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
    );
    assert_eq!(
        hex::encode(slip10_ed25519(&seed, &[0, 1]).unwrap()),
        "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"
    );
}

#[test]
fn bip44_route_is_deterministic_and_index_separated() {
    let seed = [7u8; 64];
    let a = derive_bip44_private_key(&seed, 0).unwrap();
    assert_eq!(a, derive_bip44_private_key(&seed, 0).unwrap());
    assert_ne!(a, derive_bip44_private_key(&seed, 1).unwrap());
    assert_eq!(a, slip10_ed25519(&seed, &[44, 165, 0]).unwrap());
    assert!(derive_bip44_private_key(&seed, 0x8000_0000).is_err());
}
