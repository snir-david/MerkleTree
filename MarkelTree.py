import hashlib


class Node:

    def __init__(self, data):
        self.left = None
        self.right = None
        digest = hashlib.sha256()
        digest.update(str(data).encode())
        self.digest = digest

    def insert(self, data):
        # Compare the new value with the parent node
        curr_digest = hashlib.sha256()
        curr_digest.update(str(data).encode())
        if self.digest:
            if curr_digest.hexdigest() < self.digest.hexdigest():
                if self.left is None:
                    copy_node = self.digest
                    self.left = Node(data)
                    self.right = Node(copy_node)
                    digest = hashlib.sha256()
                    digest.update(str(data).encode())
                    digest.update(str(copy_node).encode())
                    self.digest = digest
                    print(data, digest.hexdigest())
                else:
                    self.left.insert(data)
            elif curr_digest.hexdigest() > self.digest.hexdigest():
                if self.right is None:
                    copy_node = self.digest
                    self.right = Node(data)
                    self.left = Node(copy_node)
                    digest = hashlib.sha256()
                    digest.update(str(copy_node).encode())
                    digest.update(str(data).encode())
                    self.digest = digest
                    print(data, digest.hexdigest())
                else:
                    self.right.insert(data)
        else:
            self.digest = curr_digest
            print(data, curr_digest.hexdigest())

    # Print the tree
    def print_tree(self):
        if self.left:
            self.left.print_tree()
        print(self.digest.hexdigest()),
        if self.right:
            self.right.print_tree()


# Use the insert method to add nodes
root = Node("hi")
root.insert("how")
root.insert("are")
root.insert("you")

root.print_tree()
