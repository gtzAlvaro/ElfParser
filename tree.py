import dwarf_h as dh

class Node:
    def __init__(self, value):
        self.value = value # data
        self.children = [] # references to other nodes

    def add_child(self, child_node):
        # creates parent-child relationship
        self.children.append(child_node)

    def remove_child(self, child_node):
        # removes parent-child relationship
        self.children = [child for child in self.children
                        if child is not child_node]

    def traverse(self):
        # moves through each node referenced from self downwards
        print(self.value)
        for child in self.children:
            child.traverse()

    def display(self, level=0):
        # display tree structure
        name = self.value.tag
        repeat = level
        if level > 0:
            repeat = level - 1

        branch = 0
        if level > 0:
            branch = 1

        if self.value.abbrev_number == 0:
            print(f"{repeat*'|   '}{branch*'|-- '}{name}")
        elif hasattr(self.value, 'DW_AT_name'):
            print(f"{repeat*'|   '}{branch*'|-- '}{self.value.DW_AT_name}")
        else:
            print(f"{repeat*'|   '}{branch*'|-- '}{dh.DW_TAG[name]}")
        for child in self.children:
            child.display(level+1)

    def search(self, attribute, value):
        for child in self.children:
            if child.value.abbrev_number == 0:
                continue

            if not hasattr(child.value, attribute):
                continue

            if value == getattr(child.value, attribute):
                return child

            if len(child.children) > 0:
                node = child.search(attribute, value)
                if node is None:
                    continue

                return node
