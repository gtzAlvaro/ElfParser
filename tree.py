

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
        nodes_to_visit = [self]
        while len(nodes_to_visit) > 0:
            current_node = nodes_to_visit.pop()
            print(current_node.value)
            nodes_to_visit += current_node.children

    def search(self, typeof, value):
        for child in self.children:
            if child.value.abbrev_number == 0:
                continue

            if typeof == 'attributes':
                dw_at, dw_form = value
                if dw_at in child.value.attributes: # DW_AT_name
                    if dw_form == child.value.attributes[dw_at].value:
                        return child
            else:
                if value == getattr(child.value, typeof):
                    return child

            if len(child.children) > 0:
                node = child.search(typeof, value)
                if node is None:
                    continue

                return node
