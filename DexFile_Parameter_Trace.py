#Trace parameters of a function
#@author zhuangshao
#@category Dex
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.util.importer import MessageLog
from ghidra.file.formats.android.dex.analyzer import DexHeaderFormatAnalyzer
from ghidra.file.formats.android.dex.analyzer import DexAnalysisState
from ghidra.file.formats.android.dex.util import DexUtil
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighParam, PcodeOp, PcodeOpAST
from ghidra.program.model.symbol import SymbolType

import logging
import struct


# Init Default Logger
logger = logging.getLogger('Default_logger')
logger.setLevel(logging.DEBUG)
consolehandler = logging.StreamHandler()
console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
consolehandler.setFormatter(console_format)
logger.addHandler(consolehandler)


# Auxiliary
Check_Funcs = ['']
External_Symbols = {}
Target_Funcs = ['logd', 'url']
Examined_Funcs = {}
dexAnalysisState = DexAnalysisState.getState(currentProgram)
DexHeader = dexAnalysisState.getHeader()
def getString(string_idx):
    StringItem = DexHeader.getStrings().get(string_idx)
    return StringItem.getStringDataItem().getString()
def getType(type_idx):
    TypeItem = DexHeader.getTypes().get(type_idx)
    descriptor_idx = TypeItem.getDescriptorIndex()
    return getString(descriptor_idx)    
def getField(field_idx):
    FieldItem = DexHeader.getFields().get(field_idx)
    name_idx = FieldItem.getNameIndex()
    field_name = getString(name_idx)
    class_idx = FieldItem.getClassIndex()
    class_name = getType(class_idx)
    return class_name + "." + field_name
def getMethod(method_idx):
    MethodItem = DexHeader.getMethods().get(method_idx)
    name_idx = MethodItem.getNameIndex()
    func_name = getString(name_idx)
    class_idx = MethodItem.getClassIndex()
    class_name = getType(class_idx)
    return class_name + "->" + func_name
def getExternalSymbols():
    ExSymbols = currentProgram.getSymbolTable().getExternalSymbols()
    for ExSymbol in ExSymbols:
        External_Symbols[ExSymbol.getName()] = ExSymbol
def checkFunctionList():
    for Check_Func in Check_Funcs:
        if Check_Func in External_Symbols:
            print("Cun Zai: {}".format(Check_Func))
            Check_Func_Symbol = External_Symbols[Check_Func]
            Check_Func_Symbol_External_Addr = Check_Func_Symbol.getReferences()[0].getFromAddress()
            Check_Func_Symbol_Refs = getReferencesTo(Check_Func_Symbol_External_Addr)
            for Check_Func_Symbol_Ref in Check_Func_Symbol_Refs:
                if Check_Func_Symbol_Refs.getReferenceType().isCall():
                    print("Shi Yong: {}".format(Check_Func))
                    break


# Main Functions
class FunctionAnalyzer(object):

    def __init__(self, function, logger=logger):
        self.function = function
        self.logger = logger
        self.prepare()
 
    def prepare(self):
        Decompiler = DecompInterface()
        Decompiler.openProgram(currentProgram)
        Decompiled_Func = Decompiler.decompileFunction(self.function, 30, getMonitor())
        self.highfunction = Decompiled_Func.getHighFunction()
        #print("High Function information: {}".format(self.highfunction.getFunctionPrototype()))
        
    def start_analyse(self, address, param_index):
        self.logger.debug("Reference address is: {}".format(address))
        PcodeOps = self.highfunction.getPcodeOps(address)
        while PcodeOps.hasNext():
            PcodeOpAST = PcodeOps.next()
            print("*****\n{}\n*****".format(PcodeOpAST))
            Opcode = PcodeOpAST.getOpcode()
            if Opcode == PcodeOp.CALL or Opcode == PcodeOp.CALLIND:
                #print("Found CALL/CALLIND at 0x{}".format(PcodeOpAST.getInput(0).getPCAddress()))
                Target_Param_Varnode = PcodeOpAST.getInput(param_index)
                #print("Target Param Varnode: {}".format(Target_Param_Varnode))
                Target_Param_Varnode_Analyzer = VarnodeAnalyzer()
                Target_Param_Varnode_Analyzer.analyse_node(Target_Param_Varnode, PcodeOpAST)
       

class VarnodeAnalyzer(object):

    def __init__(self, logger=logger):
        self.logger = logger
        
    def analyse_node(self, varnode, pcode):
        logger.debug("Varnode: {}".format(varnode))
        Varnode_Type = varnode.isInput()
        if Varnode_Type == 1:
            Target_Param_Varnode_Index = (varnode.getOffset() - 256) / 4 + 1
            Current_Func = getFunctionContaining(pcode.getSeqnum().getTarget())
            References = getReferencesTo(Current_Func.getEntryPoint())
            for Reference in References:
                Reference_Addr = Reference.getFromAddress()
                if Reference_Addr.toString() != "Entry Point" and Reference.getReferenceType().isCall():
                    Reference_Func = getFunctionContaining(Reference_Addr)
                    logger.debug("Reference function is: {}".format(Reference_Func))
                    if Reference_Func not in Examined_Funcs:
                        Examined_Funcs[Reference_Func] = FunctionAnalyzer(Reference_Func)
                    Reference_Func_Analyzer = Examined_Funcs[Reference_Func]
                    Reference_Func_Analyzer.start_analyse(Reference_Addr, Target_Param_Varnode_Index)      
        else:
            Pcode_Def = varnode.getDef()
            logger.debug("Pcode Define: {}".format(Pcode_Def))
            self.analyse_pcode(Pcode_Def)

    def analyse_pcode(self, pcode):
        Opcode = pcode.getOpcode()
        if Opcode == PcodeOp.CAST:
            Target_Varnode = pcode.getInput(0)
            self.analyse_node(Target_Varnode, pcode)
        if Opcode == PcodeOp.COPY:
            Target_Varnode = pcode.getInput(0)
            self.analyse_node(Target_Varnode, pcode)
        elif Opcode == PcodeOp.CALL or Opcode == PcodeOp.CALLIND:
            Method_Varnode = pcode.getInput(0)
            Pcode_Def_Method_Varnode = Method_Varnode.getDef()
            Method_Idx = Pcode_Def_Method_Varnode.getInput(1).getOffset()
            Method_Name = getMethod(Method_Idx)
            print("Method: {}".format(Method_Name))
            
            Pcode_Seqnum = pcode.getSeqnum()
            Pcode_Addr = Pcode_Seqnum.getTarget()
            Pcode_Ins = getInstructionAt(Pcode_Addr)
            Target_Method_Addrs = Pcode_Ins.getFlows()
            Target_Method_Addr = Target_Method_Addrs[0]
            Target_Method_Symbol_Type = getSymbolAt(Target_Method_Addr).getSymbolType()
            if Target_Method_Symbol_Type == SymbolType.FUNCTION:
                print("Pcode-Op CALL/CALLIND target method is local function!")
                for i in range(2, len(pcode.getInputs())):
                    Param_Target_Varnode = pcode.getInput(i)
                    self.analyse_node(Param_Target_Varnode, pcode)
                Target_Func = getFunctionAt(Target_Method_Addr)
                if Target_Func not in Examined_Funcs:
                    Examined_Funcs[Target_Func] = FunctionAnalyzer(Target_Func)
                Target_Func_Analyzer = Examined_Funcs[Target_Func]
                Target_Func_Instruction = getInstructionAt(Target_Method_Addr)
                Target_Func_Addresses = Target_Func.getBody()
                while Target_Func_Addresses.contains(Target_Func_Instruction.getAddress()):
                    PcodeOps = Target_Func_Analyzer.highfunction.getPcodeOps(Target_Func_Instruction.getAddress())
                    while PcodeOps.hasNext():
                        PcodeOpAST = PcodeOps.next()
                        print("*****\n{}\n*****".format(PcodeOpAST))
                        if PcodeOpAST.getOpcode() == PcodeOp.RETURN:
                            Ret_Varnode = PcodeOpAST.getInput(1)
                            self.analyse_node(Ret_Varnode, PcodeOpAST)
                    Target_Func_Instruction = Target_Func_Instruction.getNext()
            elif Target_Method_Symbol_Type == SymbolType.LABEL:
                print("Pcode-Op CALL/CALLIND target method is external function!")
                if len(pcode.getInputs()) > 1:
                    Fun_Target_Varnode = pcode.getInput(1)
                    self.analyse_node(Fun_Target_Varnode, pcode)
                    #for i in range(2, len(pcode.getInputs())):
                        #Param_Target_Varnode = pcode.getInput(i)
                        #self.analyse_node(Param_Target_Varnode, pcode)  
            else:
                print("Pcode-Op CALL/CALLIND target method type! {}".format(Target_Method_Symbol_Type))
        elif Opcode == PcodeOp.CPOOLREF:
            Pcode_Seqnum = pcode.getSeqnum()
            Pcode_Addr = Pcode_Seqnum.getTarget()
            Pcode_Ins = getInstructionAt(Pcode_Addr)
            Pcode_Ins_Str = Pcode_Ins.toString()
            #print("Pcode belongs to Instruction: {}".format(Pcode_Ins_Str))
            if "const_string" in Pcode_Ins_Str:
                String_Idx = pcode.getInput(1).getOffset()
                logger.debug("String: {}".format(getString(String_Idx)))
            elif "new_instance" in Pcode_Ins_Str:
                Class_Idx = pcode.getInput(1).getOffset()
            elif "get_object" in Pcode_Ins_Str:
                Field_Idx = pcode.getInput(1).getOffset()
            elif "invoke_" in Pcode_Ins_Str:
                Method_Idx = pcode.getInput(1).getOffset()
            else:
                logger.debug("Pcode-Op CPOOLREF at instruction! {}".format(Pcode_Ins_Str))       
        elif Opcode == PcodeOp.NEW:
            Class_Varnode = pcode.getInput(0)
            Pcode_Def_Class_Varnode = Class_Varnode.getDef()
            Class_Idx = Pcode_Def_Class_Varnode.getInput(1).getOffset()
            print("Class: {}".format(getType(Class_Idx)))
            Pcode_Relates = pcode.getOutput().getDescendants()
            while Pcode_Relates.hasNext(): 
                Pcode_Relate = Pcode_Relates.next()
                print("Instance related Pcode: {}".format(Pcode_Relate))
                if Pcode_Relate.getOpcode() == PcodeOp.CALL or Pcode_Relate.getOpcode() == PcodeOp.CALLIND:
                    Method_Varnode = Pcode_Relate.getInput(0)
                    Pcode_Def_Method_Varnode = Method_Varnode.getDef()
                    Method_Idx = Pcode_Def_Method_Varnode.getInput(1).getOffset()
                    Method_Name = getMethod(Method_Idx)
                    print("Instance related method: {}".format(Method_Name))
                    for i in range(2, len(Pcode_Relate.getInputs())):
                        Param_Target_Varnode = Pcode_Relate.getInput(i)
                        self.analyse_node(Param_Target_Varnode, Pcode_Relate)
        elif Opcode == PcodeOp.LOAD:
            Field_Varnode = pcode.getInput(1)
            Pcode_Def_Field_Varnode = Field_Varnode.getDef()
            Field_Idx = Pcode_Def_Field_Varnode.getInput(1).getOffset()
            print("Field: {}".format(getField(Field_Idx)))
            print("ssss {}".format(pcode.getInput(0)))
                                   
    def StringBuilder(self, pcode):
        Target_Varnode = pcode.getInput(1)
        Pcode_Relates = Target_Varnode.getDescendants()
        while Pcode_Relates.hasNext():
            Pcode_Relate = Pcode_Relates.next()
            Pcode_Relate_Op = Pcode_Relate.getOpcode()
            if Pcode_Relate.getOpcode() == PcodeOp.CALL or Pcode_Relate.getOpcode() == Pcode.CALLIND:
                Method_Varnode = pcode.getInput(0)
                Pcode_Def_Method_Varnode = Method_Varnode.getDef()
                Method_Idx = Pcode_Def_Method_Varnode.getInput(1).getOffset()
                Method_Name = getMethod(Method_Idx)
                print("Method: {}".format(Method_Name))   

print(getField(0))             

if __name__ == '__main__':
    References = getReferencesTo(toAddr(0x50124204)) # Function's address
    logger.debug("Reference functions are: {}".format(References))
    for Reference in References:
        Reference_Addr = Reference.getFromAddress()
        if Reference.getReferenceType().isCall():
            Reference_Func = getFunctionContaining(Reference_Addr)
            logger.debug("Reference function is: {}".format(Reference_Func))
            if Reference_Func not in Examined_Funcs:
                Examined_Funcs[Reference_Func] = FunctionAnalyzer(Reference_Func)
            Reference_Func_Analyzer = Examined_Funcs[Reference_Func]
            Reference_Func_Analyzer.start_analyse(Reference_Addr, 2) # 2 is parameters index

