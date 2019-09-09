# -*- coding: utf-8 -*-
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Constants as OC_CONST
import logging
import re

OBJC_METHNAME = u'__objc_methname'
OBJC_CLASSNAME = u'__objc_classname'
OBJC_CLASSREFS = u'__objc_classrefs'
OBJC_DATA = u'__objc_data'
SYMBOLTYPE_LABEL = u'Label'
SYMBOLTYPE_FUNCTION = u'Function'
REFERENCETYPE_UNCONDITIONAL_CALL = u'UNCONDITIONAL_CALL'
OBJCCLASSPREFIX_META = u'_OBJC_METACLASS_$_'


methName_Dict = {}
className_Dict = {}
symbol_Dict = {}

functionList = []
referenceList = []

# debug = True
debug = False
# Init Default Logger
logger = logging.getLogger('Default_logger')
logger.setLevel(logging.INFO)
consolehandler = logging.StreamHandler()
console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
consolehandler.setFormatter(console_format)
logger.addHandler(consolehandler)

if debug:
	logger.setLevel(logging.DEBUG)

AdditionalCount = 0

class Function(object):
	"""docstring for Function"""
	def __init__(self, address, name):
		super(Function, self).__init__()
		self.address = address
		self.name = name

class Reference(object):
	"""docstring for Reference"""
	def __init__(self, callingAddr, fromAddr, toAddr):
		super(Reference, self).__init__()
		self.callingAddr = callingAddr
		self.fromAddr = fromAddr
		self.toAddr = toAddr
		
class ObjcMathName(object):
	"""docstring for ObjcMathName"""
	def __init__(self, cp, address, name):
		super(ObjcMathName, self).__init__()
		self.address = address
		self.name = name
		self.refTo = []
		self.refIter = cp.getListing().getDataAt(address).getReferenceIteratorTo()
		while self.refIter.hasNext():
			self.refTo.append(self.refIter.next())

def getMethName(cp, memBlk):
	for seg in memBlk:
		if seg.name == OBJC_METHNAME:
			global methName_Dict
			codeUnits = cp.getListing().getCodeUnits(seg.start,True)
			while codeUnits.hasNext():
				cu = codeUnits.next()
				if cu and cu.address < seg.end:
					methName = ObjcMathName(cp,cu.address,cu.value)
					methName_Dict[cu.address] = methName
				else:
					break
			break

class ObjcClassName(object):
	"""docstring for ObjcClassName"""
	def __init__(self, cp, address, name):
		super(ObjcClassName, self).__init__()
		self.address = address
		self.name = name
		self.refTo = []
		self.refIter = cp.getListing().getDataAt(address).getReferenceIteratorTo()
		while self.refIter.hasNext():
			self.refTo.append(self.refIter.next())
		
def getClassName(cp, memBlk):
	for seg in memBlk:
		if seg.name == OBJC_CLASSNAME:
			global className_Dict
			codeUnits = cp.getListing().getCodeUnits(seg.start,True)
			while codeUnits.hasNext():
				cu = codeUnits.next()
				if cu and cu.address < seg.end:
					if cu.value == u'\x01':
						continue
					className = ObjcClassName(cp,cu.address,cu.value)
					className_Dict[cu.address] = className
				else:
					break
			break

class Symbol(object):
	"""docstring for Symbol"""
	def __init__(self, sID, address, name, stype, parent, refs):
		super(Symbol, self).__init__()
		self.sID = sID
		self.address = address
		self.name = name
		self.stype = stype
		self.parent = parent
		self.refs = refs

def getFuncAddrByAddr(cp,callingAddress):
	entryAddr = None
	if cp.getListing().getFunctionContaining(callingAddress):
		entryAddr = cp.getListing().getFunctionContaining(callingAddress).entryPoint
	return entryAddr

def getSymbolTable(cp):
	symbolTable = cp.getSymbolTable()
	si = symbolTable.getSymbolIterator()
	global symbol_Dict
	global functionList
	global referenceList
	labelDict = {}
	while si.hasNext():
		s = si.next()
		symbol = Symbol(s.getID(), s.getAddress(), s.getName(), s.getSymbolType(), s.getParentSymbol(), s.getReferences())
		symbol_Dict[symbol.sID] = symbol
		if symbol.stype.toString() == SYMBOLTYPE_LABEL:
			labelDict[symbol.address.toString()] = symbol.name
		elif symbol.stype.toString() == SYMBOLTYPE_FUNCTION:
			tmpFunctionName = symbol.name
			if labelDict.has_key(symbol.address.toString()) and labelDict[symbol.address.toString()] != u'': # Bingo in Label
				funcLabel = labelDict[symbol.address.toString()]
				del labelDict[symbol.address.toString()]
				if funcLabel.find(symbol.name) != -1 and funcLabel.find(symbol.parent.name) != -1: # Got Class name and Method name
					if funcLabel.startswith(u'+') or funcLabel.startswith(u'-'): # Got OC Function Type (Class Func or Instance Func)
						tmpFunctionName = funcLabel[:1]+u'['+symbol.parent.name+u' '+symbol.name+u']'
			func = Function(symbol.address.toString(),tmpFunctionName)
			functionList.append(func)
			for ref in symbol.refs:
				if ref.referenceType.toString() == REFERENCETYPE_UNCONDITIONAL_CALL:
					fromFuncAddr = getFuncAddrByAddr(cp, ref.fromAddress)
					if fromFuncAddr:
						logger.debug("From: {}; At: {}; To: {}; Type:{}".format(fromFuncAddr, ref.fromAddress, ref.toAddress, ref.referenceType))
						reference = Reference(ref.fromAddress, fromFuncAddr, ref.toAddress)
						referenceList.append(reference)

# Helper to get function info by iterating instructions step by step
class CurrentState(object):
	def __init__(self, program):
		self.program = program
		self.symbolTable = program.getSymbolTable()
		self.currentClassName = u''
		self.currentMethodName = u''
		# flag for class and method
		self.classFlag = False
		self.methodFlag = False

	def isValid(self):
		return self.currentMethodName != u'' and self.currentClassName != u''

	def reset(self):
		self.currentClassName = u''
		self.currentMethodName = u''

		self.classFlag = False
		self.methodFlag = False

	def toString(self):
		return "[" + self.currentClassName + " " + self.currentMethodName + "]"

def isCallingObjcMsgSend(instruction):
	if instruction.getNumOperands() != 1:
		return False
	reference = instruction.getPrimaryReference(0)
	if reference == None:
		return False
	if not reference.getReferenceType().isCall() and not reference.getReferenceType().isJump():
		return False
	symbolTable = instruction.getProgram().getSymbolTable()
	symbol = symbolTable.getPrimarySymbol(reference.getToAddress())
	return isObjcNameMatch(symbol)

def isObjcNameMatch(symbol):
	name = symbol.getName()
	return name.startswith(OC_CONST.OBJC_MSG_SEND) or name == OC_CONST.READ_UNIX2003 or name.startswith("thunk" + OC_CONST.OBJC_MSG_SEND)

def markupInstruction(instruction, state):
	fromAddress = instruction.getMinAddress()
	function = state.program.getListing().getFunctionContaining(fromAddress)
	if function == None:
		return
	state.reset()
	global logger
	insIter = state.program.getListing().getInstructions(fromAddress, False)
	while insIter.hasNext():
		logger.debug("--Go Up--")
		instructionBefore = insIter.next()
		if not function.getBody().contains(instructionBefore.getMinAddress()):
			break # don't look outside of the function
		if not isValidInstruction(instructionBefore):
			continue
		opRefs = instructionBefore.getOperandReferences(1)
		logger.debug("=={} instruction: {}".format(instructionBefore.getMinAddress(),instructionBefore))
		logger.debug("==opRefs: {}".format(opRefs)) 
		if len(opRefs) != 1:
			continue
		toAddress = opRefs[0].getToAddress()
		block = state.program.getMemory().getBlock(toAddress)
		if block == None:
			continue
		space = currentProgram.getGlobalNamespace()
		pullNameThrough(state, toAddress)

		if state.isValid():
			break



'''
 * Objective-C class and method names are stored in the
 * "__cstring" memory block. The strings are referenced
 * by either the "class" block or the "message" block.
 * The references are through n-levels of pointer indirection
 * based on the specific target (x86 vs ppc vs arm).
 * This method will pull the string through the pointer indirection
 * and set the appropriate value in the current state.
'''
def pullNameThrough(state, address):
	block = state.program.getMemory().getBlock(address)
	if block == None:
		return None
	logger.debug("block name: {}".format(block.getName))
	if block.getName() == OBJC_METHNAME:
		state.methodFlag = True
		return state.program.getListing().getDefinedDataAt(address).getValue()
	elif block.getName() == OBJC_DATA:
		classRwPointerAddress = state.program.getListing().getDefinedDataAt(address).getComponent(4).getValue()
		classRwData = state.program.getListing().getDefinedDataAt(classRwPointerAddress)
		classNamePointer = classRwData.getComponent(3).getValue()
		className = state.program.getListing().getDefinedDataAt(classNamePointer).getValue()
		state.classFlag = True
		if className:
			return className
	elif block.getName() == OBJC_CLASSREFS:
		pass
	data = state.program.getListing().getDataAt(address)
	if data == None:
		data = state.program.getListing().getDataContaining(address)
		if data == None:
			return None
		data = data.getComponentAt(int(address.subtract(data.getAddress())))
		if data == None:
			return None
	references = data.getValueReferences()
	if len(references) == 0:
		return None
	if address == references[0].getToAddress():
		return None # self reference
	name = pullNameThrough(state, references[0].getToAddress())
	if state.classFlag:
		if state.currentClassName == u'':
			logger.debug("class found: {}".format(name))
			state.currentClassName = name
	if state.methodFlag:
		if state.currentMethodName == u'':
			logger.debug("message found: {}".format(name))
			state.currentMethodName = name
	return name

def isMessageBlock(block):
	return block.getName() == OBJC_METHNAME

def isClassBlock(block):
	return block.getName() == OC_CONST.OBJC_SECTION_CLASS_REFS or block.getName() == OC_CONST.OBJC_SECTION_CLASS

def isValidInstruction(instruction):
	if instruction.getNumOperands() != 2:
		return False
	isMOV = instruction.getMnemonicString() == "MOV" # intel
	isLWZ = instruction.getMnemonicString() == "lwz" # powerpc
	isLDR = instruction.getMnemonicString() == "ldr" # arm
	return isMOV or isLWZ or isLDR


def analyzeFunction(cp, function):
	insIter = cp.getListing().getInstructions(function.getBody(),True)
	state = CurrentState(cp)
	while insIter.hasNext():
		curIns = insIter.next()
		if isCallingObjcMsgSend(curIns):
			logger.debug('==========Calling MsgSend==========')
			logger.debug("===={}: {} // {}".format(curIns.getAddress(),curIns,curIns.getComment(0)))
			hitFlag = False
			for ref in referenceList:
				if ref.callingAddr == curIns.getAddress():
					hitFlag = True
					logger.debug("hit: {}, {}, {}".format(ref.fromAddr, ref.toAddr, ref.callingAddr))
					break

			global AdditionalCount
			comment = curIns.getComment(0)
			funcClass = u''
			funcMethod = u''
			secondMethod = u''
			if comment and comment.startswith(u'[') and comment.endswith(u']') and len(comment.split(u' ')) > 1:
				funcClass = comment.split(u' ')[0][1:]
				funcMethod = comment.split(u' ')[1][:-1]
				if funcClass.startswith(OBJCCLASSPREFIX_META):
					funcClass = funcClass[18:]
				funcClass = funcClass.replace(u'undefined', u'')
				funcMethod = funcMethod.replace(u'undefined', u'')
			if funcMethod == u'':
				markupInstruction(curIns, state)
				if state.isValid():
					funcClass = state.currentClassName
					funcMethod = state.currentMethodName
				else:
					continue
			if funcMethod.startswith(u'performSelector'):
				searchObj = re.search(u'(performSelector[a-zA-Z]*:)"([a-zA-Z0-9_]*)"',funcMethod)
				if searchObj:
					secondMethod = searchObj.group(2)
					logger.debug("Second Method: {}".format(secondMethod))
					tmpFunc = u'['+funcClass+u' '+secondMethod+u']'
					for func in functionList:
						if func.name.startswith(u'+') or func.name.startswith(u'-'):
							if func.name[1:] == tmpFunc:
								logger.debug("Second Method Found in functionList: {}".format(func.name))
								logger.debug("{}, {}, {}".format(function.entryPoint, curIns.address, func.address))
								ref = Reference(curIns.address, function.entryPoint, func.address)
								referenceList.append(ref)
								AdditionalCount += 1
								foundFlag = True
								break
					funcMethod = searchObj.group(1)
			searchObj = re.search(u'([a-zA-Z0-9]*:)"', funcMethod)
			if searchObj:
				funcMethod = searchObj.group(1)
			logger.debug("Class: {}; Method: {}".format(funcClass, funcMethod))
			tmpFunc = u''
			if funcClass and funcMethod:
				tmpFunc = u'['+funcClass+u' '+funcMethod+u']'
			elif funcClass == u'' and funcMethod:
				tmpFunc = funcMethod
			foundFlag = False
			for func in functionList:
				if func.name.startswith(u'+') or func.name.startswith(u'-'):
					if func.name[1:] == tmpFunc:
						logger.debug("Found in functionLsit: {}".format(func.name))
						ref = Reference(curIns.address, function.entryPoint, func.address)
						referenceList.append(ref)
						AdditionalCount += 1
						foundFlag = True
						break
				else:
					if func.name == tmpFunc:
						logger.debug("Found in functionLsit: {}".format(func.name))
						ref = Reference(curIns.address, function.entryPoint, func.address)
						referenceList.append(ref)
						AdditionalCount += 1
						foundFlag = True
						break
			if foundFlag:
				continue
			for item in methName_Dict:
				if methName_Dict[item].name == funcMethod:
					logger.debug("Found in __objc_methname: {}: {}".format(methName_Dict[item].address, funcMethod))
					ref = Reference(curIns.address, function.entryPoint, methName_Dict[item].address)
					referenceList.append(ref)
					
					AdditionalCount += 1
					foundFlag = True
					break


def analyzeInstructions(cp):
	funcIter = cp.getListing().getFunctions(True)
	while funcIter.hasNext():
		f = funcIter.next()
		fName = f.getName()
		entry = f.getEntryPoint()
		if entry:
			logger.debug("{}: {}".format(entry, fName))
			analyzeFunction(cp, f)
	print("Additional Methods Found: {}".format(AdditionalCount))

def analyzeFuncsAndRefs():
	global methName_Dict
	global className_Dict
	global symbol_Dict
	global functionList
	global referenceList

	cp = currentProgram
	memBlk = cp.memory.blocks
	if memBlk:
		getMethName(cp, memBlk)
		if debug and methName_Dict:
			print("Method Name")
			for item in methName_Dict:
				meth = methName_Dict[item]
				logger.debug("{}: {}, Ref:{}".format(item,meth.name,meth.refTo))

	if memBlk:
		getClassName(cp, memBlk)
		if debug and className_Dict:
			print("Class Name")
			for item in className_Dict:
				_class = className_Dict[item]
				logger.debug("{}: {}, Ref:{}".format(item,_class.name,_class.refTo))

	getSymbolTable(cp)
	if debug and symbol_Dict:
		print("Symbol Table")
		for item in sorted(symbol_Dict):
			symbol = symbol_Dict[item]
			logger.debug("{}: {}\t{}\t{}\t{}\t{}".format(symbol.sID, symbol.address, symbol.name, symbol.stype, symbol.parent.name, symbol.refs))

	for item in methName_Dict:
		func = Function(methName_Dict[item].address, methName_Dict[item].name)
		functionList.append(func)

	analyzeInstructions(cp)

	print("Function List:")
	for func in functionList:
		print("{}: {}".format(func.address, func.name))

	print("Reference List:")
	for ref in referenceList:
		print("From: {}, To: {}, Address: {}".format(ref.fromAddr, ref.toAddr, ref.callingAddr))

	return functionList, referenceList

if __name__ == '__main__':
	funcList, refList = analyzeFuncsAndRefs()
	
	print("\naddress,name")
	for func in funcList:
		print("{},{}".format(func.address, func.name))

	print("\nfrom,to,address")
	for ref in refList:
		print("{},{},{}".format(ref.fromAddr, ref.toAddr, ref.callingAddr))
