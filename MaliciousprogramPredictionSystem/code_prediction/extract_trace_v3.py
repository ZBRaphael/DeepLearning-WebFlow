#
# Reference Lister
#
# List all functions and all references to them in the current section.
#
# Implemented using direct IDA Plugin API calls
#
from __future__ import print_function

import csv
# Reference Lister
#
# List all functions and all references to them in the current section.
#
# Implemented using direct IDA Plugin API calls
#
import os

import idaapi
import idautils
import idc
import argparse

# parser = argparse.ArgumentParser()
# parser.add_argument('-i', '--input_path', dest='input_path',
#                     help='The data folder saving binaries information', type=str, required=True)
# args = parser.parse_args()
file_store_path = r"."



def tran(num):
    return{
        '0': 'void',
        '2': 'mem',
        '3': 'phrase',
        '5': 'imm',
        '6': 'far',
        '7': 'near',
    }.get(num, str(num))


class CFGNode:
    def __init__(self, block):
        self.block = block
        self.addr = block.startEA
        self.child = set()


class CFGTree:
    def __init__(self):
        self.root = set()
        self.nodeDict = dict()

    def putRootNode(self, root):
        # if addr in rootAddr, ths addr is not the first time to see.
        rootAddr = root.startEA
        if rootAddr not in self.nodeDict:
            rootNode = CFGNode(root)
            self.nodeDict[rootAddr] = rootNode
            self.root.add(rootNode)

    def insertNodeFast(self, pre, cur):
        # print("0x%x,  0x%x" % (pre.startEA, cur.startEA))
        preAddr = pre.startEA
        curAddr = cur.startEA
        if preAddr in self.nodeDict:
            preNode = self.nodeDict[preAddr]
            if curAddr in self.nodeDict:
                curNode = self.nodeDict[curAddr]
            else:
                curNode = CFGNode(cur)
                self.nodeDict[curAddr] = curNode
            preNode.child.add(curNode)

    def print_deepest_path(self):
        # CS_OP_INVALID = 0,  ///< uninitialized/invalid operand.
        # CS_OP_REG,      1   ///< Register operand.
        # CS_OP_IMM,      2   ///< Immediate operand.
        # CS_OP_MEM,      3   ///< Memory operand.
        def ext_instruction(file_name, addr_start, addr_end):
            name_fun = GetFunctionName(addr_start)
            row = ''
            for addr in Heads(addr_start, addr_end):

                ins = ''
                thisOperand = idc.GetMnem(addr)
                oPtype1 = idc.GetOpType(addr, 0)
                oPtype2 = idc.GetOpType(addr, 1)
                # assemblydata = parametertype(oPtype1)+' '+parametertype(oPtype2)
                if(oPtype1 == 1 or oPtype1 == 4):
                    oPtype1 = idc.GetOpnd(addr, 0)
                if(oPtype2 == 1 or oPtype2 == 4):
                    oPtype2 = idc.GetOpnd(addr, 1)
                if thisOperand == "call":
                    call_fun_name = GetOpnd(addr, 0)
                    keyInstr = LocByName(call_fun_name)
                    fflags = idc.get_func_flags(keyInstr)
                    if (fflags & idc.FUNC_LIB) or (fflags & idc.FUNC_THUNK):
                        ins = thisOperand+'_'+idc.GetOpnd(addr, 0)+'_0'
                        row = row + ' '+ins
                        continue
                ins = str(thisOperand)+'_'+tran(str(oPtype1)) + \
                    '_'+tran(str(oPtype2))
                row = row + ' '+ins
            return row
            # file_name.writerow([name_fun, hex(addr_start), hex(addr_end), row])

        deepset = list()
        path = list()
        all_path = list()

        def print_path_deepest(head):
            global deepset
            global path
            global all_path
            # print(deepset)
            if head is None:
                return
            if head in all_path:
                return
            # print(path)
            all_path.append(head)
            path.append(head)
            # print("********\n",path)
            if len(deepset) < len(path):
                # print(len(deepset),len(path))
                deepset = [i for i in path]
                # print(deepset)
            for elem in head.child:
                print_path_deepest(elem)
            path.remove(head)
            # print("#######\n",path)

        def print_path_all(head):
            global path
            # print(deepset)
            if head is None:
                return
            if head in path:
                return
            path.append(head)
            for elem in head.child:
                print_path_all(elem)
        f = open(file_store_path+'\\'+'test'+'.csv', 'wb')
        saveFile = csv.writer(f)
        saveFile.writerow(["name", "start", "end", "Op"])
        for fun_node in self.root:
            name_fun = GetFunctionName(fun_node.addr)
            fflags = idc.get_func_flags(fun_node.addr)
            if not((fflags & idc.FUNC_LIB) or (fflags & idc.FUNC_THUNK)):
                global path
                path = list()
                global deepset
                deepset = list()
                global all_path
                all_path = list()
                # print(deepset)
                # path.clear()

                print_path_deepest(fun_node)
                row_fun = ''
                fun_addr_end = idc.FindFuncEnd(fun_node.addr)
                for bb in deepset:
                    ins_bb = ext_instruction(
                        saveFile, bb.block.startEA, bb.block.end_ea)
                    row_fun = row_fun+' '+ins_bb
                saveFile.writerow(
                    [name_fun, hex(fun_node.addr), hex(fun_addr_end), row_fun])
                # print(hex(fun_node.addr))


def construct_cfg(flow, funcea, seg_start, seg_end):
    for block in flow:
        if len(list(block.preds())) == 0 and block.startEA == funcea:
            cfgTree.putRootNode(block)

    for block in flow:
        for succBB in block.succs():
            if succBB.startEA >= seg_start and succBB.end_ea <= seg_end:
                cfgTree.insertNodeFast(block, succBB)


def main():
    global cfgTree
    cfgTree = CFGTree()

    seg = idaapi.get_segm_by_name("__text")

    # Loop from segment start to end
    func_ea = seg.startEA

    # Get a function at the start of the segment (if any)
    func = idaapi.get_func(func_ea)
    if func is None:
        # No function there, try to get the next one
        func = idaapi.get_next_func(func_ea)

    seg_start = seg.startEA
    seg_end = seg.end_ea
    while func is not None and func.start_ea < seg_end:
        funcea = func.start_ea
        fflags = idc.get_func_flags(funcea)
        if (fflags & idc.FUNC_LIB) or (fflags & idc.FUNC_THUNK):
            continue

        # print("Function %s at 0x%x" % (idc.get_func_name(funcea), funcea))
        flow = idaapi.FlowChart(idaapi.get_func(funcea), flags=idaapi.FC_PREDS)
        construct_cfg(flow, funcea, seg_start, seg_end)
        func = idaapi.get_next_func(funcea)
    cfgTree.print_deepest_path()
    # cfgTree.printToFile()
    # cfgTree.printTree()


if __name__ == "__main__":
    idc.Wait()
    main()
    idc.Exit(0)

