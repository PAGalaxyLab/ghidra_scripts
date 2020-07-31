# Ghidra script for deobfuscating OLLVM control flow flattening
# select the assembly for state var initialization in Ghidra code listing interface and run the script

import os
import binascii
import logging

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.mem import *
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.plugin.assembler import Assemblers

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s][%(levelname)s] - %(message)s',
                    datefmt='%m/%d/%Y %H:%M:%S %p')

def get_last_pcode(block):
    pcode_iterator = block.getIterator()
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
        if not pcode_iterator.hasNext():
            return pcode

# check if the var is state_var
def is_state_var(state_var, var, depth=0):
    logging.debug('comparing %s to state var %s, depth %d' % (var, state_var, depth))
    if depth > 1:
        logging.warning('reach max depth for is_state_var: %s' % var)
        return False
    # for temp var, find its definition
    if var.isUnique():
        var_def = var.getDef()
        logging.debug('temp var def: %s' % var_def)
        if var_def.getOpcode() == PcodeOp.COPY:
            var = var_def.getInput(0)
            logging.debug('update var to %s' % var)
        elif var_def.getOpcode() == PcodeOp.MULTIEQUAL:
            # include phi node inputs
            for input_var in var_def.getInputs().tolist():
                if is_state_var(state_var, input_var, depth+1):
                    return True
    return state_var.getAddress() == var.getAddress()

# value of state var may need to be updated before compared to const
def const_update(const):
    # signed to unsigned
    return const & 0xffffffff

# find blocks setting state var to consts
def find_const_def_blocks(mem, state_var_size, pcode, depth, res, def_block):
    if depth > 3:
        logging.warning('reaching max depth in find_const_def_blocks')

    elif pcode is None:
        logging.warning('pcode is None')

    else:
        logging.debug('finding state var def in pcode %s of block %s, depth %d' % (pcode, pcode.getParent(), depth))
        if pcode.getOpcode() == PcodeOp.COPY:
            input_var = pcode.getInput(0)
            if def_block is None:
                # the block of COPY is the def block
                def_block = pcode.getParent()
                logging.debug('find COPY in block %s' % def_block)
            # is copying const to var?
            if input_var.isConstant():
                logging.debug('%s defines state var to const: %s' % (def_block, input_var))
                if def_block not in res:
                    res[def_block] = input_var.getOffset()
                else:
                    logging.warning('%s already defines state var to const %s, skipped' % (def_block, res[def_block]))
            else:
                # if input var is in ram, read its value
                if input_var.getAddress().getAddressSpace().getName() == u'ram':
                    if input_var.isAddress():
                        if state_var_size == 4:
                            ram_value = mem.getInt(input_var.getAddress())
                            res[def_block] = ram_value
                        elif state_var_size == 8:
                            ram_value = mem.getLong(input_var.getAddress())
                            res[def_block] = ram_value
                        else:
                            logging.warning('state var size %d not supported' % state_var_size)
                    else:
                        logging.warning('def of non-const input_var %s not found' % input_var)
                # not ram or const, trace back to const def
                else:
                    find_const_def_blocks(mem, state_var_size, input_var.getDef(), depth+1, res, def_block)

        elif pcode.getOpcode() == PcodeOp.MULTIEQUAL:
            for input_var in pcode.getInputs().tolist():
                find_const_def_blocks(mem, state_var_size, input_var.getDef(), depth+1, res, def_block)
        else:
            logging.warning('unsupported pcode %s, depth %d' % (pcode, depth))

class Patcher(object):
    def __init__(self, current_program):
        self.listing_db = current_program.getListing()
        self.asm = Assemblers.getAssembler(current_program)

    def patch_unconditional_jump(self, addr, target_addr):
        return None

    def patch_conditional_jump(self, ins, true_addr, false_addr):
        return None

    # patch the binary for updated CFG
    def do_patch(self, link):
        logging.debug('patching block for CFG %s' % str(link))

        block = link[0]
        ins = self.listing_db.getInstructions(block.getStop(), True).next()
        logging.debug('last ins in block to patch at %s: %s' % (block.getStop(), ins))

        patch_addr = ins.getMinAddress()

        # unconditional jump
        if len(link) == 2:
            target_addr = link[1].getStart().getOffset()
            asm_string = self.patch_unconditional_jump(patch_addr, target_addr)
            logging.debug('patching unconditional jump at %s to %s' % (patch_addr, asm_string))
            patched = self.asm.assembleLine(patch_addr, asm_string)
            if len(patched) > ins.getLength():
                logging.error('not enough space at %s for patch %s' % (patch_addr, asm_string))
                return None

        # conditional jump
        else:
            true_addr = link[1].getStart().getOffset()
            false_addr = link[2].getStart().getOffset()
            asm_string = self.patch_conditional_jump(ins, true_addr, false_addr)
            logging.debug('patching conditional jump at %s to %s' % (patch_addr, asm_string))

        if asm_string is not None:
            patch = self.asm.assemble(patch_addr, asm_string)
            patch_bytes = bytearray()
            patch_ins_iterator = patch.iterator()
            while patch_ins_iterator.hasNext():
                patch_bytes += bytearray(patch_ins_iterator.next().getBytes())
            return (patch_addr, patch_bytes)
        else:
            return None


class PatcherX86(Patcher):
    def __init__(self, current_program):
        super(PatcherX86, self).__init__(current_program)

    def patch_unconditional_jump(self, addr, target_addr):
        return 'JMP 0x%x' % target_addr

    def patch_conditional_jump(self, ins, true_addr, false_addr):
        op_str = str(ins.getMnemonicString())

        if op_str.startswith('CMOV'):
            return '%s 0x%x\nJMP 0x%x' % (op_str.replace('CMOV', 'J'), true_addr, false_addr)
        else:
            return None

class PatcherARM(Patcher):
    def __init__(self, current_program):
        super(PatcherARM, self).__init__(current_program)

    def patch_unconditional_jump(self, addr, target_addr):
        return 'b 0x%x' % target_addr

    def patch_conditional_jump(self, ins, true_addr, false_addr):
        op_str = str(ins.getMnemonicString())

        if op_str.startswith('cpy'):
            asm_string = '%s 0x%x\nb 0x%x' % (op_str.replace('cpy', 'b'), true_addr, false_addr)
        elif op_str.startswith('mov'):
            asm_string = '%s 0x%x\nb 0x%x' % (op_str.replace('mov', 'b'), true_addr, false_addr)
        else:
            logging.warning('ins %s not supported' % ins)
            asm_string = None

        return asm_string

class PatcherAArch64(PatcherARM):
    def __init__(self, current_program):
        super(PatcherAArch64, self).__init__(current_program)

    def patch_conditional_jump(self, ins, true_addr, false_addr):
        op_str = str(ins.getMnemonicString())

        if op_str == 'csel':
            # get the condition from the last operand
            condition = str(ins.getDefaultOperandRepresentation(3))
            # hack for CSEL: its pcode takes the last operand as def
            (true_addr, false_addr) = (false_addr, true_addr)
            asm_string = 'b.%s 0x%x\nb 0x%x' % (condition, true_addr, false_addr)
            return asm_string
        else:
            logging.warning('ins %s not supported' % ins)
            return None


def get_high_function(current_program, current_address):
    decomplib = DecompInterface()
    decomplib.openProgram(current_program)

    current_function = getFunctionContaining(current_address)
    decompile_res = decomplib.decompileFunction(current_function, 30, getMonitor())

    high_function = decompile_res.getHighFunction()
    return high_function

def get_state_var(high_function, current_address):
    pcode_iterator = high_function.getPcodeOps(current_address)
    pcode = None

    # find the pcode for COPYing const
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
        logging.debug('finding COPY const pcode: %s' % pcode)
        if pcode.getOpcode() == PcodeOp.COPY and pcode.getInput(0).isConstant():
            break

    logging.info('COPY const pcode: %s' % pcode)

    # find the state var in phi node
    depth = 0
    while pcode is not None and pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.debug('finding phi node: %s, depth %d' % (pcode, depth))
        if pcode.getOutput() is None:
            logging.warning('output is None in %s' % pcode)
            break
        pcode = pcode.getOutput().getLoneDescend()
        if depth > 5:
            break
        depth += 1

    if pcode is None or pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.error('cannot find phi node')
        return None
    else:
        logging.info('phi node: %s' % pcode)

    state_var = pcode.getOutput()
    logging.info('state var is %s' % state_var)
    return state_var


# map const values of state var to blocks
def compute_const_map(high_function, state_var):
    const_map = {}

    for block in high_function.getBasicBlocks():
        # search for conditional jump
        if block.getOutSize() != 2:
            continue

        last_pcode = get_last_pcode(block)
        if last_pcode.getOpcode() != PcodeOp.CBRANCH:
            continue

        condition = last_pcode.getInput(1)

        condition_pcode = condition.getDef()
        logging.debug('condition pcode: %s' % condition_pcode)

        condition_type = condition_pcode.getOpcode()

        if not condition_type in (PcodeOp.INT_NOTEQUAL, PcodeOp.INT_EQUAL):
            continue

        in0 = condition_pcode.getInput(0)
        in1 = condition_pcode.getInput(1)

        if in0.isConstant():
            const_var = in0
            compared_var = in1
        elif in1.isConstant():
            const_var = in1
            compared_var = in0
        else:
            logging.debug('not const var in comparision, skipped')
            continue

        if is_state_var(state_var, compared_var):
            if condition_type == PcodeOp.INT_NOTEQUAL:
                target_block = block.getFalseOut()
            else:
                target_block = block.getTrueOut()
            const_map[const_var.getOffset()] = target_block
        else:
            logging.debug('state_var not involved in %s' % condition_pcode)


    logging.info('const_map map:\n%s' % '\n'.join('0x%x: %s' % kv for kv in const_map.items()))
    return const_map


def find_state_var_defs(mem, state_var):
    phi_node = state_var.getDef()

    state_var_defs = {}

    for state_var_def in phi_node.getInputs().tolist():
        if state_var_def == state_var:
            continue
        pcode = state_var_def.getDef()
        logging.debug('output %s of pcode %s in block %s defines state var' % (state_var_def, pcode, pcode.getParent()))

        find_const_def_blocks(mem, state_var.getSize(), pcode, 0, state_var_defs, None)

    logging.info('blocks defining state var:\n%s' % '\n'.join('%s: %s' % (b, hex(v)) for b, v in state_var_defs.items()))
    return state_var_defs


def gen_cfg(const_map, state_var_defs):
    links = []

    # basic blocks for CMOVXX
    cmovbb = []

    for def_block, const in state_var_defs.items():

        # unconditional jump
        if def_block.getOutSize() == 1:
            const = const_update(const)
            if const in const_map:
                link = (def_block, const_map[const])
                logging.debug('unconditional jump link: %s' % str(link))
                links.append(link)
            else:
                logging.warning('cannot find const 0x%x in const_map' % const)

        # conditional jump
        elif def_block.getOutSize() == 2:
            const = const_update(const)
            true_out = def_block.getTrueOut()
            false_out = def_block.getFalseOut()
            logging.debug('%s true out: %s, false out %s' % (def_block, true_out, false_out))

            # true out block has state var def
            if true_out in state_var_defs:
                true_out_const = const_update(state_var_defs[true_out])
                if true_out_const not in const_map:
                    logging.warning('true out cannot find map from const 0x%x to block' % true_out_const)
                    continue
                true_out_block = const_map[true_out_const]
                logging.debug('true out to block: %s' % true_out_block)

                if false_out in state_var_defs:
                    false_out_const = const_update(state_var_defs[false_out])
                    if false_out_const not in const_map:
                        logging.warning('false out cannot find map from const 0x%x to block' % false_out_const)
                        continue
                    else:
                        false_out_block = const_map[false_out_const]
                        logging.debug('false out to block: %s' % false_out_block)

                # false out doesn't have const def, then use the def in current block for the false out
                elif const in const_map:
                    false_out_block = const_map[const]
                else:
                    logging.warning('mapping of const %s in block %s not found' % (const, def_block))
                    continue

                link = (def_block, true_out_block, false_out_block)
                logging.debug('conditional jump link: %s' % str(link))

                # the link from CMOVXX should be ignored since the current conditional jump would do it
                cmovbb.append(true_out)
                links.append(link)

            # false out block has state var def
            elif false_out in state_var_defs:
                false_out_const = const_update(state_var_defs[false_out])
                if false_out_const not in const_map:
                    logging.warning('false out cannot find map from const 0x%x to block' % false_out_const)
                    continue
                false_out_block = const_map[false_out_const]
                logging.debug('false out to block: %s' % false_out_block)

                # true out doesn't have const def, then use the def in current block for the true out
                if const in const_map:
                    true_out_block = const_map[const]
                    link = (def_block, true_out_block, false_out_block)
                    logging.debug('conditional jump link: %s' % str(link))
                    links.append(link)
                else:
                    logging.warning('mapping of const %s in block %s not found' % (const, def_block))
            else:
                logging.warning('no state var def in either trueout or falseout of block %s' % def_block)
        else:
            logging.warning('output block counts %d not supported' % def_block.getOutSize())

    # skip the link for CMOVXX
    links_res = []
    for link in links:
        if link[0] not in cmovbb:
            links_res.append(link)
        else:
            logging.debug('skip %s as CMOVXX' % str(link))

    logging.info('generated CFG links:\n%s' % '\n'.join(str(link) for link in links_res))
    return links_res

def patch_cfg(current_program, cfg_links):
    patches = []

    arch = current_program.getLanguage().getProcessor().toString()

    if arch == u'x86':
        patcher = PatcherX86(current_program)
    elif arch == u'ARM':
        patcher = PatcherARM(current_program)
    elif arch == u'AARCH64':
        patcher = PatcherAArch64(current_program)
    else:
        logging.error('arch %s not supported' % arch)
        return patches

    for link in cfg_links:
        try:
            patch_info = patcher.do_patch(link)
            if patch_info is not None:
                patches.append(patch_info)
        except Exception as e:
            logging.warning('failed to patch %s' % str(link))
            logging.warning(e)

    logging.info('patches:\n%s' % '\n'.join('%s: %s' % (addr, binascii.hexlify(patch)) for addr, patch in patches))
    return patches

def save_patched(current_program, mem, patches):
    fpath = current_program.getExecutablePath()
    patched_pach = '%s-patched' % fpath

    file_data = None

    if os.path.exists(patched_pach):
        fpath = patched_pach

    with open(fpath, 'rb') as fin:
        file_data = bytearray(fin.read())

    for addr, patch_bytes in patches:
        offset = mem.getAddressSourceInfo(addr).getFileOffset()
        file_data[offset:offset+len(patch_bytes)] = patch_bytes

    with open(patched_pach, 'wb') as fout:
        fout.write(file_data)
        logging.info('save patched file as %s' % patched_pach)

if __name__ == '__main__':
    current_mem = currentProgram.getMemory()

    current_high_function = get_high_function(currentProgram, currentAddress)
    current_state_var = get_state_var(current_high_function, currentAddress)

    current_const_map = compute_const_map(current_high_function, current_state_var)
    current_state_var_defs = find_state_var_defs(current_mem, current_state_var)
    current_cfg_links = gen_cfg(current_const_map, current_state_var_defs)

    current_patches = patch_cfg(currentProgram, current_cfg_links)
    #save_patched(currentProgram, current_mem, current_patches)
