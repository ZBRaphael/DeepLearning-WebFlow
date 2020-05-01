import csv
import os

import idaapi
import idautils
import idc

def clean():
    heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    for i in heads:
      SetColor(i, CIC_ITEM, 0xFFFFFF)
def SetBBColor(ea, color):
    f = idaapi.get_func(ea)
    if not f:
        SetColor(ea, CIC_ITEM, color)
        return
    fc = idaapi.FlowChart(f)
    list_BB=[]
    tag = False
    for BB in fc:
        if BB.startEA <= ea:
            if BB.endEA > ea:
                tag = True
                break
    if not tag:
        SetColor(ea, CIC_ITEM, color)
        return
    for ea in range(BB.startEA, BB.endEA):
        SetColor(ea, CIC_ITEM, color)


def main():
    # clean()
    PRED_CSV = "test_p.csv"
    csvFileObj = open(PRED_CSV, 'r')
    csvReader = csv.reader(csvFileObj)
    addr_list = []
    for line in csvReader:
        if csvReader.line_num == 1:
            continue
        # elif line[4] == 0:
        
        elif line[4]=='1':
            addr_list.append(int(line[1][:-1], 16))
        # print(line)
    print(addr_list)
    for i in addr_list:
        SetBBColor(i,0x0000FF)

if __name__ == '__main__':
    idc.Wait()
    main()