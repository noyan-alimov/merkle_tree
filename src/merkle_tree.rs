#![allow(dead_code)]
#![allow(unused_variables)]
use sha2::Digest;

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

#[derive(Debug, Clone, PartialEq)]
pub struct MerkleTree {
    hash: Hash,
    left: Option<Box<MerkleTree>>,
    right: Option<Box<MerkleTree>>,
}

/// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

impl MerkleTree {
    /// Gets root hash for this tree
    pub fn root(&self) -> Hash {
        self.hash.clone()
    }

    /// Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        let nodes = input.iter().map(|data| {
            MerkleTree {
                hash: hash_data(data),
                left: None,
                right: None,
            }
        }).collect::<Vec<MerkleTree>>();

        MerkleTree::construct_tree(nodes)
    }

    /// Constructs a Merkle tree from a list of nodes
    fn construct_tree(mut nodes: Vec<MerkleTree>) -> MerkleTree {
        while nodes.len() > 1 {
            let mut parent_nodes = Vec::new();

            for i in (0..nodes.len()).step_by(2) {
                let left = nodes.get(i).cloned().unwrap();
                let right = nodes.get(i + 1).cloned();

                // if there is no right node, we just use the left node as the parent
                let parent = match right {
                    None => left,
                    Some(right) => {
                        let hash = hash_concat(&left.hash, &right.hash);
                        MerkleTree {
                            hash,
                            left: Some(Box::new(left)),
                            right: Some(Box::new(right)),
                        }
                    }
                };

                parent_nodes.push(parent);
            }

            nodes = parent_nodes;
        }

        nodes.remove(0)
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        let tree = MerkleTree::construct(input);
        tree.root() == *root_hash
    }

    /// Verifies that the given data and proof_path correctly produce the given root_hash
    pub fn verify_proof(data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        let mut hash = hash_data(data);

        for (direction, sibling_hash) in &proof.hashes {
            hash = match direction {
                HashDirection::Left => hash_concat(sibling_hash, &hash),
                HashDirection::Right => hash_concat(&hash, sibling_hash),
            };
        }

        hash == *root_hash
    }

    /// Returns a list of hashes that can be used to prove that the given data is in this tree
    pub fn prove<'a>(&'a self, data: &Data) -> Option<Proof<'a>> {
        let mut proof = Proof::default();
        if self.prove_recursive(data, &mut proof) {
            Some(proof)
        } else {
            None
        }
    }

    /// Recursively tries to prove that the given data is in this tree and adds the hashes to the proof
    fn prove_recursive<'a>(&'a self, data: &Data, proof: &mut Proof<'a>) -> bool {
        if self.left.is_none() && self.right.is_none() {
            return &hash_data(data) == &self.hash;
        }

        if let Some(ref left) = self.left {
            if left.prove_recursive(data, proof) {
                // If the data is in the left subtree, add the hash of the right subtree to the proof, if it exists
                if let Some(ref right) = self.right {
                    proof.hashes.push((HashDirection::Right, &right.hash));
                }
                return true;
            }
        }

        if let Some(ref right) = self.right {
            if right.prove_recursive(data, proof) {
                // If the data is in the right subtree, add the hash of the left subtree to the proof
                if let Some(ref left) = self.left {
                    proof.hashes.push((HashDirection::Left, &left.hash));
                }
                return true;
            }
        }

        false
    }
}

fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

// #[cfg(tests)]
mod tests {
    use super::*;

    fn example_data(n: usize) -> Vec<Data> {
        let mut data = vec![];
        for i in 0..n {
            data.push(vec![i as u8]);
        }
        data
    }

    #[test]
    fn test_constructions() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        assert_eq!(hex::encode(tree.root()), expected_root);

        // Uncomment if your implementation allows for unbalanced trees
        let data = example_data(3);
        let tree = MerkleTree::construct(&data);
        let expected_root = "773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f";
        assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert_eq!(hex::encode(tree.root()), expected_root);
    }

    #[test]
    fn test_verification() {
        let data = example_data(3);
        let tree = MerkleTree::construct(&data);
        let root = tree.root();
        assert!(MerkleTree::verify(&data, &root));

        // test with invalid root
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let root = vec![0; 32];
        assert!(!MerkleTree::verify(&data, &root));
    }

    #[test]
    fn test_proofs() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let proof = tree.prove(&data[2]).unwrap();
        let root = tree.root();
        assert!(MerkleTree::verify_proof(&data[2], &proof, &root));

        // test with invalid root
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let proof = tree.prove(&data[2]).unwrap();
        let root = vec![0; 32];
        assert!(!MerkleTree::verify_proof(&data[2], &proof, &root));

        // test with invalid data
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let proof = tree.prove(&data[2]).unwrap();
        let root = tree.root();
        assert!(!MerkleTree::verify_proof(&data[3], &proof, &root));
    }
}