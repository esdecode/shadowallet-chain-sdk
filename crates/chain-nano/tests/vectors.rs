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
fn mainnet_and_unpinned_networks_cannot_sign() {
    assert!(NanoNet::verify("live", LIVE_NETWORK_ID).is_err());
    assert!(NanoNet::verify("beta", LIVE_NETWORK_ID).is_err());
    assert!(NanoNet::verify("test", &"AB".repeat(32)).is_err());
    assert!(NanoNet::verify("beta", &"AB".repeat(32)).is_err());
    assert!(
        NanoNet::verify(
            "beta",
            "e1227cf974c1455a8b630433d94f3ddbf495eeac9add2481a4a1d90a0d00f488"
        )
        .is_ok()
    );
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
