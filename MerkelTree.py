import hashlib


class Node:

    def __init__(self, data):
        self.left = None
        self.right = None
        self.father = None
        self.data = data
        digest = hashlib.sha256()
        digest.update(str(data).encode())
        self.digest = digest

    def add(self, data):
        # Compare the new value with the parent node
        curr_digest = hashlib.sha256()
        curr_digest.update(str(data).encode())
        if self.digest:
            if curr_digest.hexdigest() < self.digest.hexdigest():
                if self.left is None:
                    self.left = Node(data)
                    self.right = Node(self.data)
                    self.left.father = self.right.father = self
                    self.recalc_tree()
                else:
                    self.left.add(data)
            elif curr_digest.hexdigest() > self.digest.hexdigest():
                if self.right is None:
                    self.right = Node(data)
                    self.left = Node(self.data)
                    self.left.father = self.right.father = self
                    self.recalc_tree()
                else:
                    self.right.add(data)
        else:
            self.digest = curr_digest

    # Print the merkel tree
    def print_tree(self):
        if self.left:
            self.left.print_tree()
        print(self.data, self.digest.digest(), self, self.father)
        if self.right:
            self.right.print_tree()

    def recalc_tree(self):
        if self.father is None:
            digest = hashlib.sha256()
            digest.update((self.left.digest.digest() + self.right.digest.digest()))
            self.digest = digest
            self.data = str(self.left.data) + str(self.right.data)
        else:
            digest = hashlib.sha256()
            digest.update((self.left.digest.digest() + self.right.digest.digest()))
            self.digest = digest
            self.data = str(self.left.data) + str(self.right.data)
            self.father.recalc_tree()

    def get_root(self):
        if self.father is None:
            return self.digest.hexdigest()
        self.father.get_root()

    def find_leaf(self, leaf_num):
        leaf_list = []
        nodes_visited = []
        while len(leaf_list) != leaf_num:
            if self.left is None and self.right is None:
                leaf_list.append(self)
                nodes_visited.append(self)
                self = self.father
            else:
                if self.left in nodes_visited:
                    if self.right in nodes_visited:
                        nodes_visited.append(self)
                        self = self.father.right
                    else:
                        self = self.right
                else:
                    self = self.left
        return leaf_list.pop()

    def get_proof(self, leaf_num):
        leaf = self.find_leaf(leaf_num)
        father = leaf.father
        proof = []
        if leaf != father.right:
            proof.append(father.right.digest.digest())
        else:
            proof.append(father.left.digest.digest())
        while father is not None:
            if father != father.right:
                proof.append(father.right.digest.digest())
                father = father.father
            else:
                proof.append(father.left.digest.digest())
                father = father.father
        proof.insert(0, self.get_root())
        return proof

    def check_proof(self, inc_proof):
        # hash_list = inc_proof.split(" ")
        # hash_without_root = []
        # for i in range(0, len(inc_proof)):
        #     if i != 1:
        #         hash_without_root.append(inc_proof[i])
        digest = hashlib.sha256()
        for i in range(1, len(inc_proof) - 1):
            tmp_hash = inc_proof[i] + inc_proof[i + 1]
            digest.update(tmp_hash)
            print(digest.digest())
            inc_proof[i+1] = digest.digest()
        print(digest.hexdigest())
        if digest.hexdigest() == inc_proof[0]:
            return True
        return False


# Use the insert method to add nodes
root = Node(1)
root.add(2)
root.add(3)
root.add(4)
print("print tree")
root.print_tree()
print("print tree root")
print(root.get_root())
node = root.find_leaf(3)
print(node.digest.digest())
proof = root.get_proof(3)
print("print prof")
print(proof)
proof.insert(1, node.digest.digest())
root.check_proof(proof)
