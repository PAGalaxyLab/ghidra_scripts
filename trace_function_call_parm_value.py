# Trace function call parameters value using Ghidra P-Code.
# @author dark-lbp
# @category
# @keybinding
# @menupath
# @toolbar
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighParam, PcodeOp, PcodeOpAST
from ghidra.program.model.address import GenericAddress
import logging
import struct


# debug = True
debug = False
process_is_64bit = False

# Init Default Logger
logger = logging.getLogger('Default_logger')
logger.setLevel(logging.INFO)
consolehandler = logging.StreamHandler()
console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
consolehandler.setFormatter(console_format)
logger.addHandler(consolehandler)

if debug:
    logger.setLevel(logging.DEBUG)

endian = currentProgram.domainFile.getMetadata()[u'Endian']
if endian == u'Big':
    is_big_endian = True
else:
    is_big_endian = False

process_type = currentProgram.domainFile.getMetadata()[u'Processor']
if process_type.endswith(u'64'):
    process_is_64bit = True

decompile_function_cache = {}


def is_address_in_current_program(address):
    for block in currentProgram.memory.blocks:
        if address.offset in range(block.getStart().offset,block.getEnd().offset):
            return True
    return False


def get_signed_value(input_data):
    pack_format = ""
    if is_big_endian:
        pack_format += ">"
    else:
        pack_format += "<"

    if process_is_64bit:
        pack_format += "L"
    else:
        pack_format += "I"

    logger.debug("type(input_data): {}".format(type(input_data)))
    data = struct.pack(pack_format.upper(), input_data.offset)
    signed_data = struct.unpack(pack_format.lower(), data)[0]

    return signed_data


class FlowNode(object):
    def __init__(self, var_node, logger=logger):
        """ Used to get VarNode value

        :param var_node:
        """
        self.var_node = var_node
        if logger is None:
            self.logger = logging.getLogger('FlowNode_logger')
            self.logger.setLevel(logging.INFO)
            consolehandler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
            consolehandler.setFormatter(console_format)
            self.logger.addHandler(consolehandler)
        else:
            self.logger = logger

    def get_value(self):
        """ Get VarNode value depend on it's type.

        :return:
        """
        if self.var_node.isAddress():
            self.logger.debug("Var_node isAddress")
            return self.var_node.getAddress()
        elif self.var_node.isConstant():
            self.logger.debug("Var_node isConstant")
            return self.var_node.getAddress()
        elif self.var_node.isUnique():
            self.logger.debug("Var_node isUnique")
            return calc_pcode_op(self.var_node.getDef())
        elif self.var_node.isRegister():
            self.logger.debug("Var_node isRegister")
            self.logger.debug(self.var_node.getDef())
            return calc_pcode_op(self.var_node.getDef())

        # https://github.com/NationalSecurityAgency/ghidra/issues/2283
        elif self.var_node.isPersistent():
            self.logger.debug("Var_node isPersistent")
            # TODO: Handler this later
            return
        elif self.var_node.isAddrTied():
            self.logger.debug("Var_node isAddrTied")
            return calc_pcode_op(self.var_node.getDef())
        elif self.var_node.isUnaffected():
            self.logger.debug("Var_node isUnaffected")
            # TODO: Handler this later
            return
        else:
            self.logger.debug("self.var_node: {}".format(self.var_node))


def calc_pcode_op(pcode):
    logger.debug("pcode: {}, type: {}".format(pcode, type(pcode)))
    if isinstance(pcode, PcodeOpAST):
        opcode = pcode.getOpcode()
        if opcode == PcodeOp.PTRSUB:
            logger.debug("PTRSUB")
            var_node_1 = FlowNode(pcode.getInput(0))
            var_node_2 = FlowNode(pcode.getInput(1))
            value_1 = var_node_1.get_value()
            value_2 = var_node_2.get_value()
            if isinstance(value_1, GenericAddress) and isinstance(value_2, GenericAddress):
                return value_1.offset + value_2.offset

            else:
                logger.debug("value_1: {}".format(value_1))
                logger.debug("value_2: {}".format(value_2))
                return None

        elif opcode == PcodeOp.CAST:
            logger.debug("CAST")
            var_node_1 = FlowNode(pcode.getInput(0))
            value_1 = var_node_1.get_value()
            if isinstance(value_1, GenericAddress):
                return value_1.offset

            else:
                return None

        elif opcode == PcodeOp.PTRADD:
            logger.debug("PTRADD")
            var_node_0 = FlowNode(pcode.getInput(0))
            var_node_1 = FlowNode(pcode.getInput(1))
            var_node_2 = FlowNode(pcode.getInput(2))
            try:
                value_0_point = var_node_0.get_value()
                logger.debug("value_0_point: {}".format(value_0_point))
                if not isinstance(value_0_point, GenericAddress):
                    return
                value_0 = toAddr(getInt(value_0_point))
                logger.debug("value_0: {}".format(value_0))
                logger.debug("type(value_0): {}".format(type(value_0)))
                value_1 = var_node_1.get_value()
                logger.debug("value_1: {}".format(value_1))
                logger.debug("type(value_1): {}".format(type(value_1)))
                if not isinstance(value_1, GenericAddress):
                    logger.debug("value_1 is not GenericAddress!")
                    return
                value_1 = get_signed_value(value_1.offset)
                # TODO: Handle input2 later
                value_2 = var_node_2.get_value()
                logger.debug("value_2: {}".format(value_2))
                logger.debug("type(value_2): {}".format(type(value_2)))
                if not isinstance(value_2, GenericAddress):
                    return
                output_value = value_0.add(value_1)
                logger.debug("output_value: {}".format(output_value))
                return output_value.offset

            except Exception as err:
                logger.debug("Got something wrong with calc PcodeOp.PTRADD : {}".format(err))
                return None

            except:
                logger.error("Got something wrong with calc PcodeOp.PTRADD ")
                return None

        elif opcode == PcodeOp.INDIRECT:
            logger.debug("INDIRECT")
            # TODO: Need find a way to handle INDIRECT operator.
            return None

        elif opcode == PcodeOp.MULTIEQUAL:
            logger.debug("MULTIEQUAL")
            # TODO: Add later
            return None

        elif opcode == PcodeOp.COPY:
            logger.debug("COPY")
            logger.debug("input_0: {}".format(pcode.getInput(0)))
            logger.debug("Output: {}".format(pcode.getOutput()))
            var_node_0 = FlowNode(pcode.getInput(0))
            value_0 = var_node_0.get_value()
            return value_0

    else:
        logger.debug("Found Unhandled opcode: {}".format(pcode))
        return None


class FunctionAnalyzer(object):

    def __init__(self, function, timeout=30, logger=logger):
        """

        :param function: Ghidra function object.
        :param timeout: timeout for decompile.
        :param logger: logger.
        """
        self.function = function
        self.timeout = timeout
        if logger is None:
            self.logger = logging.getLogger('target')
            self.logger.setLevel(logging.INFO)
            consolehandler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
            consolehandler.setFormatter(console_format)
            self.logger.addHandler(consolehandler)
        else:
            self.logger = logger
        self.hfunction = None
        self.call_pcodes = {}
        self.prepare()

    def prepare(self):
        self.hfunction = self.get_hfunction()
        self.get_all_call_pcode()

    def get_hfunction(self):
        decomplib = DecompInterface()
        decomplib.openProgram(currentProgram)
        timeout = self.timeout
        dRes = decomplib.decompileFunction(self.function, timeout, getMonitor())
        hfunction = dRes.getHighFunction()
        return hfunction

    def get_function_pcode(self):
        if self.hfunction:
            try:
                ops = self.hfunction.getPcodeOps()

            except:
                return None

            return ops

    def print_pcodes(self):
        ops = self.get_function_pcode()
        while ops.hasNext():
            pcodeOpAST = ops.next()
            print(pcodeOpAST)
            opcode = pcodeOpAST.getOpcode()
            print("Opcode: {}".format(opcode))
            if opcode == PcodeOp.CALL:
                print("We found Call at 0x{}".format(pcodeOpAST.getInput(0).PCAddress))
                call_addr = pcodeOpAST.getInput(0).getAddress()
                print("Calling {}(0x{}) ".format(getFunctionAt(call_addr), call_addr))
                inputs = pcodeOpAST.getInputs()
                for i in range(len(inputs)):
                    parm = inputs[i]
                    print("parm{}: {}".format(i, parm))

    def find_perv_call_address(self, address):
        try:
            address_index = sorted(self.call_pcodes.keys()).index(address)

        except Exception as err:
            return

        if address_index > 0:
            perv_address = sorted(self.call_pcodes.keys())[address_index - 1]
            return self.call_pcodes[perv_address]

    def find_next_call_address(self, address):
        try:
            address_index = sorted(self.call_pcodes.keys()).index(address)

        except Exception as err:
            return

        if address_index < len(self.call_pcodes) - 1:
            next_address = sorted(self.call_pcodes.keys())[address_index + 1]
            return self.call_pcodes[next_address]

    def get_all_call_pcode(self):
        ops = self.get_function_pcode()
        if not ops:
            return

        while ops.hasNext():
            pcodeOpAST = ops.next()
            opcode = pcodeOpAST.getOpcode()
            if opcode in [PcodeOp.CALL, PcodeOp.CALLIND]:
                op_call_addr = pcodeOpAST.getInput(0).PCAddress
                self.call_pcodes[op_call_addr] = pcodeOpAST

    def get_call_pcode(self, call_address):
        # TODO: Check call_address is in function.
        if call_address in self.call_pcodes:
            return self.call_pcodes[call_address]

        return

    def analyze_call_parms(self, call_address):
        parms = {}
        # TODO: Check call_address is in function.
        pcodeOpAST = self.get_call_pcode(call_address)
        if pcodeOpAST:
            self.logger.debug("We found target call at 0x{} in function {}(0x{})".format(
                pcodeOpAST.getInput(0).PCAddress, self.function.name, hex(self.function.entryPoint.offset)))
            opcode = pcodeOpAST.getOpcode()
            if opcode == PcodeOp.CALL:
                target_call_addr = pcodeOpAST.getInput(0).getAddress()
                self.logger.debug("target_call_addr: {}".format(target_call_addr))

            elif opcode == PcodeOp.CALLIND:
                target_call_addr = FlowNode(pcodeOpAST.getInput(0)).get_value()
                self.logger.debug("target_call_addr: {}".format(target_call_addr))

            inputs = pcodeOpAST.getInputs()
            for i in range(len(inputs))[1:]:
                parm = inputs[i]
                self.logger.debug("parm{}: {}".format(i, parm))
                parm_node = FlowNode(parm)
                self.logger.debug("parm_node: {}".format(parm_node))
                parm_value = parm_node.get_value()
                self.logger.debug("parm_value: {}".format(parm_value))
                if isinstance(parm_value, GenericAddress):
                    parm_value = parm_value.offset
                parms[i] = parm_value
                if parm_value:
                    self.logger.debug("parm{} value: {}".format(i, hex(parm_value)))
            return parms
        return

    def get_call_parm_value(self, call_address):
        parms_value = {}
        if not call_address in self.call_pcodes:
            return
        parms = self.analyze_call_parms(call_address)

        if not parms:
            return

        for i in parms:
            self.logger.debug("parms{}: {}".format(i, parms[i]))
            parm_value = parms[i]
            self.logger.debug("parm_value: {}".format(parm_value))
            parm_data = None
            if parm_value:
                if is_address_in_current_program(toAddr(parm_value)):
                    if getDataAt(toAddr(parm_value)):
                        parm_data = getDataAt(toAddr(parm_value))
                    elif getInstructionAt(toAddr(parm_value)):
                        parm_data = getFunctionAt(toAddr(parm_value))

            parms_value["parm_{}".format(i)] = {'parm_value': parm_value,
                                                'parm_data': parm_data
                                                }

        return parms_value


def dump_call_parm_value(call_address, search_functions=None):
    """

    :param call_address:
    :param search_functions: function name list to search
    :return:
    """
    target_function = getFunctionAt(call_address)
    parms_data = {}
    if target_function:
        target_references = getReferencesTo(target_function.getEntryPoint())
        for target_reference in target_references:
            # Filter reference type
            reference_type = target_reference.getReferenceType()
            logger.debug("reference_type: {}".format(reference_type))
            logger.debug("isJump: {}".format(reference_type.isJump()))
            logger.debug("isCall: {}".format(reference_type.isCall()))
            if not reference_type.isCall():
                logger.debug("skip!")
                continue

            call_addr = target_reference.getFromAddress()
            logger.debug("call_addr: {}".format(call_addr))
            function = getFunctionContaining(call_addr)
            logger.debug("function: {}".format(function))
            if not function:
                continue

            # search only targeted function
            if search_functions:
                if function.name not in search_functions:
                    continue

            function_address = function.getEntryPoint()
            if function_address in decompile_function_cache:
                target = decompile_function_cache[function_address]
            else:
                target = FunctionAnalyzer(function=function)
                decompile_function_cache[function_address] = target

            parms_data[call_addr] = {
                'call_addr': call_addr,
                'refrence_function_addr': function.getEntryPoint(),
                'refrence_function_name': function.name,
                'parms': {}
            }

            parms_value = target.get_call_parm_value(call_address=call_addr)
            if not parms_value:
                continue

            trace_data = parms_data[call_addr]
            trace_data['parms'] = parms_value

        return parms_data


if __name__ == '__main__':
    # search_functions = ['FUN_8003028c']
    search_functions = None
    function_address = askLong("Input function address to trace", "Please input the function address")
    target_function = getFunctionAt(toAddr(function_address))
    if target_function:
        print("target_function: {}".format(target_function))
        parms_data = dump_call_parm_value(toAddr(function_address))
        # print("parms: {}".format(parms))
        for call_addr in parms_data:
            call_parms = parms_data[call_addr]
            parm_data_string = ""
            for parm in sorted(call_parms['parms'].keys()):
                parm_value = call_parms['parms'][parm]['parm_value']
                parm_data = call_parms['parms'][parm]['parm_data']
                # print("parm_data: {} type:{}".format(parm_data, type(parm_data)))
                # print("parm_value: {} type:{}".format(parm_value, type(parm_value)))
                if parm_value:
                    parm_data_string += "{}({:#010x}), ".format(parm_data, parm_value)
                else:
                    # Handle None type
                    parm_data_string += "{}({}), ".format(parm_data, parm_value)
            # remove end ', '
            parm_data_string = parm_data_string.strip(', ')
            # print("parm_data_string: {}".format(parm_data_string))
            print("{}({}) at {:#010x} in {}({:#010x})".format(target_function.name, parm_data_string,
                                                              call_parms['call_addr'].offset,
                                                              call_parms['refrence_function_name'],
                                                              call_parms['refrence_function_addr'].offset
                                                              ))
    else:
        print("Can't find function at address: {:#010x}".format(function_address))
