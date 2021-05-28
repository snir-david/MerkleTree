import hashlib
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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

    # input 1
    def add(self, data):
        inc_tree_size = True
        f_node = Node(None)
        leaves_len = len(self.leaves)
        # finding where need to add the new leaf
        if self.leaves[leaves_len - 1].level != self.tree_size:
            inc_tree_size = False
        # if need to add new level return to root and adding new leaf
        if inc_tree_size:
            leaf = self.tree_root
            f_node.left = leaf
        elif leaves_len % 2 == 0:
            leaf = self.leaves[leaves_len - 1].father
        else:
            leaf = self.leaves[leaves_len - 1]
        # adding new leaf to the right and recalculating the tree
        l_father = leaf.father
        r_node = Node(data)
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
            l_father.right = f_node
            f_node.father = l_father
            f_node.left.level += 1
            f_node.right.level = f_node.left.level
            l_father.recalc_tree()

    # input 2
    def get_root(self):
        return self.tree_root.hash

    # input 3
    def get_proof(self, leaf_num):
        leaf = self.leaves[int(leaf_num)]
        father = leaf.father
        proof = ""
        while father is not None:
            if leaf != father.right:
                proof += '1' + str(father.right.hash) + " "
            else:
                proof += '0' + str(father.left.hash) + " "
            leaf = father
            father = father.father
        root = str(self.get_root())
        root += " " + proof[:len(proof) - 1]
        return root

    # input 4
    def check_proof(self, inc_proof):
        # splitting string for proof
        hash_list = inc_proof.split(" ")
        # creating new list without root and hashing data of leaf
        hash_without_root = [hashlib.sha256(hash_list[0].encode()).hexdigest()]
        for i in range(1, len(hash_list)):
            if i != 1:
                hash_without_root.append(hash_list[i])
        # iterating from leaves to root and calculating hash function
        for i in range(0, len(hash_without_root) - 1):
            digest = hashlib.sha256()
            # if proof is from the right
            if hash_without_root[i + 1][0] == '1':
                digest.update((hash_without_root[i] + hash_without_root[i + 1][1:]).encode())
            # if proof is from the left
            if hash_without_root[i + 1][0] == '0':
                digest.update((hash_without_root[i + 1][1:] + hash_without_root[i]).encode())
            hash_without_root[i + 1] = digest.hexdigest()
        if digest.hexdigest() == hash_list[1]:
            return True
        return False

    # input 5
    def create_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048)
        public_key = private_key.public_key()
        sk_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pk_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        str_keys = str(sk_pem.decode()) + '\n' + str(pk_pem.decode())
        return str_keys

    # input 6
    def sign_root(self, sign_key):
        sk = serialization.load_pem_private_key(
            sign_key.encode(),
            password=None,
        )
        sign_root = sk.sign(self.get_root().encode(),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256())
        bs64sign = base64.b64encode(sign_root)
        return bs64sign.decode()

    # input 7
    def verify_sign(self, verify_key, sign, text):
        pk_pem = serialization.load_pem_public_key(
            verify_key.encode(),
            backend=None,
        )
        try:
            pk_pem.verify(
                base64.decodebytes(sign.encode()),
                text.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return 'True'
        except InvalidSignature:
            return 'False'


if __name__ == '__main__':
    root = MerkleTree(None)
    while True:
        user_input = input()
        line = user_input.splitlines()
        if user_input[0] == '1':
            if root.tree_root.data is not None:
                root.add(line[0][2:])
            else:
                root.tree_root = Node(line[0][2:])
                root.leaves.clear()
                root.leaves.append(root.tree_root)
        elif user_input[0] == '2':
            if root.tree_root.data is not None:
                print(root.get_root())
            else:
                print('')
        elif user_input[0] == '3':
            if root.tree_root.data is not None:
                print(root.get_proof(line[0][2:]))
            else:
                print('')
        elif user_input[0] == '4':
            if root.tree_root.data is not None:
                print(root.check_proof(line[0][2:]))
            else:
                print('')
        elif user_input[0] == '5':
            print(root.create_key())
        elif user_input[0] == '6':
            inp = input()
            while inp != '-----END RSA PRIVATE KEY-----':
                if inp != '':
                    user_input += '\n' + inp
                inp = input()
            user_input += '\n' + inp
            # read blank line
            inp = input()
            print(root.sign_root(user_input[2:]))
        elif user_input[0] == '7':
            inp = input()
            while inp != '-----END PUBLIC KEY-----':
                if inp != '':
                    user_input += '\n' + inp
                inp = input()
            user_input += '\n' + inp
            inp = input()
            while inp == '':
                inp = input()
            key_and_signed = inp
            split = key_and_signed.split(' ')
            if len(split) < 2:
                inp = input()
            split.append(inp)
            print(root.verify_sign(user_input[2:], split[0], split[1]))