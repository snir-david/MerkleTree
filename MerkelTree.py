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
        print(self.data, self.digest.hexdigest(), self, self.father)
        if self.right:
            self.right.print_tree()

    def recalc_tree(self):
        if self.father is None:
            digest = hashlib.sha256()
            digest.update(bytes(self.left.digest.hexdigest(), 'utf8'))
            digest.update(bytes(self.right.digest.hexdigest(), 'utf8'))
            self.digest = digest
            self.data = str(self.left.data) + str(self.right.data)
        else:
            digest = hashlib.sha256()
            digest.update(bytes(self.left.digest.hexdigest(), 'utf8'))
            digest.update(bytes(self.right.digest.hexdigest(), 'utf8'))
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
        while len(leaf_list) != leaf_num + 1:
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
        proof = ""
        if leaf != father.right:
            proof += str(father.right.data)
        else:
            proof += str(father.left.data)
        leaf = father
        father = father.father
        while father is not None:
            if leaf != father.right:
                proof += " " + str(father.right.data)
            else:
                proof += " " + str(father.left.data)
            leaf = father
            father = father.father
        root = str(self.get_root())
        root += " " + proof
        return root

    def check_proof(self, inc_proof):
        hash_list = inc_proof.split(" ")
        hash_without_root = []
        for i in range(0, len(hash_list)):
            if i != 1:
                hash_without_root.append(hash_list[i])
        digest = hashlib.sha256()
        tmp_digest = hashlib.sha256()
        # digest.update(bytes(hash_without_root[0] + hash_without_root[1], 'utf8'))
        # print(digest.hexdigest())
        for i in range(0, len(hash_without_root)-1):
            digest.update(bytes(hash_without_root[i] + hash_without_root[i+1], 'utf8'))
            hash_without_root[i+1] = digest.hexdigest()
            print(digest.hexdigest())
        print(digest.hexdigest())
        if digest.hexdigest() == hash_list[1]:
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
node = root.find_leaf(2)
proof = root.get_proof(2)
print("print prof")
print(proof)
root.check_proof(str(node.digest.hexdigest()) + " " + proof)
