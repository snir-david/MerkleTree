# Snir David Nahari, 205686538, Neriya Fisch, 315558692

# imports of relevant libraries (all of them allowed)
import hashlib
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# class Node represents node in merkle tree
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

    # function to recalculate tree when adding new leaf
    def recalc_tree(self):
        # while self.father != tree_root, calculate hash and keep going up on the tree until getting to root
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

    # helper method for texts - Print the merkle tree
    def print_tree(self):
        if self.left:
            self.left.print_tree()
        print(self.data, self.hash)
        if self.right:
            self.right.print_tree()


# class MerkleTree represents the merkle tree itself, containing root and array of the leaves
class MerkleTree:

    def __init__(self, data):
        # node
        self.tree_root = Node(data)
        # tech details
        self.tree_size = 1
        self.leaves = [self.tree_root]

    # input 1 - adding leaf
    def add(self, data):
        # bool var that check if need to add level to the tree
        inc_tree_size = True
        # init new node that will be father of the new leaf
        f_node = Node(None)
        leaves_len = len(self.leaves)
        # checking if tree need to add level - if last leaf is in the same level as tree size
        # need to add level to tree. else, add next to last leaf
        if self.leaves[leaves_len - 1].level != self.tree_size:
            inc_tree_size = False
        # if need to add new level return to root and adding new leaf to the right
        if inc_tree_size:
            leaf = self.tree_root
            f_node.left = leaf
        # if not needed new level to tree, check if number of leaves is even,
        # if it is left leaf will be father of the las leaf in array
        elif leaves_len % 2 == 0:
            leaf = self.leaves[leaves_len - 1].father
        # if number of leaves is odd,
        # left leaf will be last leaf added
        else:
            leaf = self.leaves[leaves_len - 1]
        # adding new leaf to the right and recalculating the tree
        l_father = leaf.father
        r_node = Node(data)
        # adding left and right nodes to father node
        f_node.left = leaf
        f_node.right = r_node
        # changing father to right and left nodes
        leaf.father = r_node.father = f_node
        # recalc tree
        f_node.recalc_tree()
        # adding leaf to leaves list
        self.leaves.append(r_node)
        # if needed increase tree size and leaves level and change root to current father node
        # and add level to tree and all leaves
        if inc_tree_size:
            self.tree_root = f_node
            self.tree_size += 1
            for leaf in self.leaves:
                leaf.level += 1
        # else, change right node of previous father of the left node and adding level to the relevant leaves
        # recalc tree on adding path
        else:
            l_father.right = f_node
            f_node.father = l_father
            f_node.left.level += 1
            f_node.right.level = f_node.left.level
            l_father.recalc_tree()

    # input 2 - calc root
    def get_root(self):
        return self.tree_root.hash

    # input 3 - return proof of inclusion
    def get_proof(self, leaf_num):
        # find the wanted leaf
        leaf = self.leaves[int(leaf_num)]
        father = leaf.father
        proof = ""
        # getting the proof according to leaf
        while father is not None:
            # if leaf is not the right leaf, add right leaf to proof (also add 1 before digest)
            if leaf != father.right:
                proof += '1' + str(father.right.hash) + " "
            # if leaf is not the left leaf, add right leaf to proof (also add 0 before digest)
            else:
                proof += '0' + str(father.left.hash) + " "
            # go to the upper level, change leaf to be father, and father to father of father
            leaf = father
            father = father.father
        # adding root to proof and return proof
        root = str(self.get_root())
        root += " " + proof[:len(proof) - 1]
        return root

    # input 4 - check inclusion of proof
    def check_proof(self, inc_proof):
        # splitting string for proof
        hash_list = inc_proof.split(" ")
        # creating new list without root and hashing data of first leaf
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
        # checking if final digest is equal to root
        if digest.hexdigest() == hash_list[1]:
            return True
        return False

    # input 5 - create sk and pk
    def create_key(self):
        # generate private key
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048)
        # generate public key using the private key
        public_key = private_key.public_key()
        # serialize sk and pk
        sk_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pk_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # setting the format and return keys
        str_keys = str(sk_pem.decode()) + '\n' + str(pk_pem.decode())
        return str_keys

    # input 6 - sign given a sk on tree root
    def sign_root(self, sign_key):
        # load sk
        sk = serialization.load_pem_private_key(
            sign_key.encode(),
            password=None,
        )
        # sign on root usin sk
        sign_root = sk.sign(self.get_root().encode(),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256())
        # encode to base64 and return signed root
        bs64sign = base64.b64encode(sign_root)
        return bs64sign.decode()

    # input 7 - check if sign is valid
    def verify_sign(self, verify_key, sign, text):
        # load pk
        pk_pem = serialization.load_pem_public_key(
            verify_key.encode(),
            backend=None,
        )
        # try to verify signature - catch if signature is not valid
        try:
            # if signature valid - return true
            pk_pem.verify(
                base64.decodebytes(sign.encode()),
                text.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        # else, signature not valid catch and return false
        except InvalidSignature:
            return False


# class SparseMerkelTree represents a sparse merkle tree
class SparseMerkelTree:
    def __init__(self):
        #define all the class members
        self.hashes = ['0']
        self.createHashesArray()
        self.tree_root = Node(self.hashes[0])
        self.tree_root.level = 0

    # create an array of deafult values to all level when the tree is new fill of zeroes
    def createHashesArray(self):
        for i in range(0, 256):
            level = hashlib.sha256()
            level.update(self.hashes[0].encode() + self.hashes[0].encode())
            self.hashes.insert(0, level.hexdigest())

    #adding node to thr tree because his value is not the deafult value anymore
    def addNode(self, node, side, level):
        new_node = Node(self.hashes[level])
        new_node.level = level
        new_node.father = node
        if side == '1':
            node.right = new_node
        else:
            node.left = new_node
        return new_node

    # chane the leaf data from 0 to 1 and then go up on the road and update the nodes that need to be updated
    def markLeaf(self, digest):
        node = self.tree_root
        bin_value = bin(int(digest, base=16))[2:].zfill(256)
        level = 1
        for digit in bin_value:
            if digit == '1' and node.right is not None:
                node = node.right
            elif digit == '1' and node.right is None:
                node = self.addNode(node, 1, level)
            elif digit == '0' and node.left is not None:
                node = node.left
            elif digit == '0' and node.left is None:
                node = self.addNode(node, 0, level)
            level += 1
        node.data = 1
        reverse_digest = bin_value[::-1]
        level = 256
        for i in reverse_digest:
            new_data = hashlib.sha256()
            # right child and have a brother
            if i == '1' and node.father.left is not None:
                new_data.update(bytes(str(node.data) + str(node.father.left.data), 'utf8'))
                node = node.father
                node.data = new_data.hexdigest()
            # right child and have no brother
            elif i == '1' and node.father.left is None:
                new_data.update(bytes(str(node.data) + str(self.hashes[level]), 'utf8'))
                node = node.father
                node.data = new_data.hexdigest()
            # left child and have a brother
            elif i == '0' and node.father.right is not None:
                new_data.update(bytes(str(node.data) + str(node.father.right.data), 'utf8'))
                node = node.father
                node.data = new_data.hexdigest()
            # left child and have no brother
            elif i == '0' and node.father.right is None:
                new_data.update(bytes(str(node.data) + str(self.hashes[level]), 'utf8'))
                node = node.father
                node.data = new_data.hexdigest()
            level -= 1

    # input 10 - getting proof of smt
    def proof(self, digest):
        node = self.tree_root
        bin_value = bin(int(digest, base=16))[2:].zfill(256)
        level = 0
        proof = []
        #go in the inputed road to the leaf
        for digit in bin_value:
            if node.data == self.hashes[level]:
                proof.insert(0, node.data)
                break
            level += 1
            if digit == '1' and node.right is not None:
                if node.left is not None:
                    proof.insert(0, node.left.data)
                else:
                    proof.insert(0, self.hashes[level])
                node = node.right
            elif digit == '1' and node.right is None:
                if node.left is not None:
                    proof.insert(0, node.left.data)
                else:
                    proof.insert(0, self.hashes[level])
                node = self.addNode(node, 1, level)
            elif digit == '0' and node.left is not None:
                if node.right is not None:
                    proof.insert(0, node.right.data)
                else:
                    proof.insert(0, self.hashes[level])
                node = node.left
            elif digit == '0' and node.left is None:
                if node.right is not None:
                    proof.insert(0, node.right.data)
                else:
                    proof.insert(0, self.hashes[level])
                node = self.addNode(node, 0, level)
        proof.insert(0, self.tree_root.data)
        # create the output proof from the buttom to the top (the root is in the beginning)
        output = ""
        for x in proof:
            output += str(x) + " "
        return output

    # input 11 - checking proof of smt
    def check_proof(self, input):
        road = input.pop(0)
        bin_value = bin(int(road, base=16))[2:].zfill(256)
        reverse = bin_value[::-1]
        data = input.pop(0)
        #if the leaf is 1 and the proof isnt full its have to be false
        if data == '1' and len(input) != 258:
            return False
        root = input[0]
        proof = []
        level = 256
        y = 0
        #take the deafult values
        for i in range(258, len(input), -1):
            y += 1
            proof.append(self.hashes[level])
            level -= 1
        counter = 1
        level += 1
        # take from the proof
        for digit in reverse[256 - level:]:
            hash = hashlib.sha256()
            if digit == '1':
                hash.update((input[counter] + proof[-1]).encode())
            else:
                hash.update((proof[-1] + input[counter]).encode())
            proof.append(hash.hexdigest())
            counter += 1
        if proof[-1] == root:
            return True
        return False


# main function - checking the input and selecting the right function accordingly
if __name__ == '__main__':
    # init empty Merkle Tree and Sparse Tree
    root = MerkleTree(None)
    smt = SparseMerkelTree()
    while True:
        # get user input
        user_input = input()
        # split according to space
        line = user_input.split()
        if line[0] == '1':
            # if tree is not empty add new node
            if root.tree_root.data is not None:
                root.add(line[1])
            # tree is still empty, change root to be current node
            else:
                root.tree_root = Node(line[1])
                root.leaves.clear()
                root.leaves.append(root.tree_root)
        elif line[0] == '2':
            # if tree is not empty return root
            if root.tree_root.data is not None:
                print(root.get_root())
            # else print empty line
            else:
                print()
        elif line[0] == '3':
            # if tree is not empty return root
            if root.tree_root.data is not None:
                print(root.get_proof(line[1]))
            # else print empty line
            else:
                print()
        elif line[0] == '4':
            print(root.check_proof(user_input[2:]))
        elif line[0] == '5':
            print(root.create_key())
        elif user_input[0] == '6':
            # keep getting input until end of the key
            inp = input()
            while inp != '-----END RSA PRIVATE KEY-----':
                if inp != '':
                    user_input += '\n' + inp
                inp = input()
            user_input += '\n' + inp
            # read blank line in the end of the input
            inp = input()
            print(root.sign_root(user_input[2:]))
        elif user_input[0] == '7':
            # keep getting input until end of the key
            inp = input()
            while inp != '-----END PUBLIC KEY-----':
                if inp != '':
                    user_input += '\n' + inp
                inp = input()
            user_input += '\n' + inp
            # read blank line in the end of the input
            inp = input()
            # read empty more lines if there is and getting key and signed data
            while inp == '':
                inp = input()
            # checking if got key and signed data
            key_and_signed = inp
            split = key_and_signed.split(' ')
            if len(split) < 2:
                inp = input()
            split.append(inp)
            print(root.verify_sign(user_input[2:], split[0], split[1]))
        elif line[0] == '8':
            # if tree is not empty return root
            if smt.tree_root.data is not None:
                smt.markLeaf(line[1])
            else:
                print()
        elif line[0] == '9':
            # if tree is not empty return root
            if smt.tree_root.data is not None:
                print(smt.tree_root.data)
            # else print empty line
            else:
                print()
        elif line[0] == "10":
            # if tree is not empty return root
            if smt.tree_root.data is not None:
                proof = smt.proof(line[1])
                print(proof)
            # else print empty line
            else:
                print()
        elif line[0] == "11":
            flag = smt.check_proof(line[1:])
            print(flag)
        # else print empty line
        else:
            print()
