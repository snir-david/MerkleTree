import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes


class Node:
    def __init__(self, data):
        # nodes
        self.left = None
        self.right = None
        self.father = None
        # node level
        self.level = 1
        # data and hash
        self.data = data
        digest = hashlib.sha256()
        digest.update(str(data).encode())
        self.hash = digest.hexdigest()

    def recalc_tree(self):
        if self.father is None:
            digest = hashlib.sha256()
            digest.update(bytes(str(self.left.hash) + str(self.right.hash), 'utf8'))
            self.hash = digest.hexdigest()
            self.data = str(self.left.data) + str(self.right.data)
        else:
            digest = hashlib.sha256()
            digest.update(bytes(str(self.left.hash) + str(self.right.hash), 'utf8'))
            self.hash = digest.hexdigest()
            self.data = str(self.left.data) + str(self.right.data)
            self.father.recalc_tree()

    # Print the merkle tree
    def print_tree(self):
        if self.left:
            self.left.print_tree()
        print(self.data, self.hash)
        if self.right:
            self.right.print_tree()


class MerkleTree:

    def __init__(self, data):
        # node
        self.tree_root = Node(data)
        # tech details
        self.tree_size = 1
        self.leaves = [self.tree_root]

    def add(self, data):
        inc_tree_size = True
        # finding where need to add the new leaf
        for leaf in self.leaves:
            if leaf.level != self.tree_size:
                inc_tree_size = False
                break
        # if need to add new level return to root and adding new leaf
        while leaf.father is not None and inc_tree_size:
            leaf = leaf.father
        # adding new leaf to the right and recalculating the tree
        r_node = Node(data)
        f_node = Node('tmp')
        f_node.left = leaf
        f_node.right = r_node
        leaf.father = r_node.father = f_node
        f_node.recalc_tree()
        # adding leaf to leaves list
        self.leaves.append(r_node)
        # if needed increase tree size and leaves level and change root to current father node
        if inc_tree_size:
            self.tree_root = f_node
            self.tree_size += 1
            for leaf in self.leaves:
                leaf.level += 1
        else:
            self.tree_root.right = f_node
            f_node.father = self.tree_root
            self.tree_root.recalc_tree()

    def get_root(self):
        return self.tree_root.hash

    def get_proof(self, leaf_num):
        leaf = self.leaves[leaf_num]
        father = leaf.father
        proof = ""
        while father is not None:
            if leaf != father.right:
                proof += str(father.right.hash) + " "
            else:
                proof += str(father.left.hash) + " "
            leaf = father
            father = father.father
        root = str(self.get_root())
        root += " " + proof[:len(proof) - 1]
        return root

    def check_proof(self, inc_proof):
        # splitting string for proof
        hash_list = inc_proof.split(" ")
        # creating new list without root
        hash_without_root = []
        for i in range(0, len(hash_list)):
            if i != 1:
                hash_without_root.append(hash_list[i])
        # checking for every proof if it is right or left node in the tree
        node = self.tree_root
        node_location = []
        for i in range(0, len(hash_without_root) - 1):
            if node.left.hash == hash_without_root[len(hash_without_root) - (i + 1)]:
                node_location.append("left")
                node = node.right
            elif node.right.hash == hash_without_root[len(hash_without_root) - (i + 1)]:
                node_location.append("right")
                node = node.left
            else:
                print("hash not in tree")
                return False
        # reverse locations list and start iterating from leaves to root and calculating hash function
        node_location.reverse()
        for i in range(0, len(hash_without_root) - 1):
            digest = hashlib.sha256()
            # if proof is from the right
            if node_location[i] == 'right':
                digest.update((hash_without_root[i] + hash_without_root[i + 1]).encode())

            # if proof is from the left
            if node_location[i] == 'left':
                digest.update((hash_without_root[i + 1] + hash_without_root[i]).encode())
            hash_without_root[i + 1] = digest.hexdigest()
        if digest.hexdigest() == hash_list[1]:
            return True
        return False

    def create_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_root(self, sign_key):
        sign_root = sign_key.sign(
            self.get_root().encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return sign_root

    def verify_sign(self, verify_key, sign, text):
        try:
            verify_key.verify(
                sign,
                text.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


# Use the insert method to add nodes
root = MerkleTree(1)
root.add(2)
root.add(3)
root.add(4)
print("print tree")
root.tree_root.print_tree()
print("print tree root")
print(root.get_root())
proof = root.get_proof(2)
print("print prof")
print(proof)
proof = proof.replace("b", "c", 2)
print(root.check_proof(root.leaves[2].hash + " " + proof))
sk, pk = root.create_key()
sign = root.sign_root(sk)
try_root = root.get_root().replace("a", "v")
print(root.verify_sign(pk, sign, try_root))
