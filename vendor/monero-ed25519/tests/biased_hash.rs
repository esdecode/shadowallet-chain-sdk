#![allow(missing_docs)]

use monero_ed25519::Point;

mod hex;

#[test]
fn biased_hash() {
  let reader = include_str!("./tests.txt");

  for line in reader.lines() {
    let mut words = line.split_whitespace();

    let command = words.next().unwrap();
    match command {
      "check_key" => {}
      "hash_to_ec" => {
        let preimage = hex::decode(words.next().unwrap());
        let actual = Point::biased_hash(preimage);
        let expected = hex::decode(words.next().unwrap());
        assert_eq!(actual.compress().to_bytes(), expected);
      }
      _ => unreachable!("unknown command"),
    }
  }
}

/// 4000 vectors produced by the ORIGINAL monero-ed25519 0.1.0 (crypto-bigint 0.5.5). The port to crypto-bigint 0.7
/// must reproduce every one of them exactly.
#[test]
fn biased_hash_matches_the_original_implementation() {
  let vectors = include_str!("./biased_hash_vectors.txt");
  let mut n = 0;
  for line in vectors.lines() {
    let mut w = line.split_whitespace();
    let input = hex::decode(w.next().unwrap());
    let expected = hex::decode(w.next().unwrap());
    assert_eq!(Point::biased_hash(input).compress().to_bytes(), expected, "vector {n}");
    n += 1;
  }
  assert_eq!(n, 4000);
}
