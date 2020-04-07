# coding=utf-8
from ghidra.program.model.symbol.SourceType import USER_DEFINED
from galaxy_utility.function_analyzer import FunctionAnalyzer
from galaxy_utility.common import get_logger
import sys


"""
test_firmware download url.
http://download.tplinkcloud.com.cn/firmware/wr886nv7-ipv6-cn-up_2019-10-25_09.43.28_1572316888807.bin
"""

# debug = True
debug = False
process_is_64bit = False
logger = get_logger(__name__)

if debug:
    logger.setLevel(10)


if __name__ == '__main__':
    function_can_rename = {}
    # Function error print keywords.
    keywords = "Function %s assertion"

    # Get printf function object.
    printf_funciton = getFunction("printf")
    if not printf_funciton:
        sys.exit()

    # Get printf entry_point address object.
    printf_entry_point = printf_funciton.entryPoint

    # Get printf call references using getReferencesTo(printf_entry_point)
    printf_refs = getReferencesTo(printf_entry_point)
    for ref in printf_refs:
        # Only check printf call references.
        if ref.getReferenceType().isCall():
            ref_from_address = ref.getFromAddress()
            logger.debug("ref_from_address: {}".format(ref_from_address))
            ref_from_funciton = getFunctionContaining(ref_from_address)
            logger.debug("ref_from_funciton: {}".format(ref_from_funciton))
            if ref_from_funciton:
                # Only check unnamed function.
                if ref_from_funciton.name.startswith('FUN_'):
                    logger.debug(ref_from_funciton.name)
                    # Analyze function.
                    analyzer = FunctionAnalyzer(function=ref_from_funciton)
                    # Get printf parms value using PCode Trace.
                    printf_parms = analyzer.get_call_parm_value(ref_from_address)
                    logger.debug("printf_parms: {}".format(printf_parms))
                    try:
                        printf_parm1 = printf_parms["parm_1"]["parm_data"]
                        logger.debug("printf_parm1: {}".format(printf_parm1))
                        if not printf_parm1:
                            continue
                        printf_parm1_value = printf_parm1.getValue()

                        if "parm_2" not in printf_parms.keys():
                            continue
                        printf_parm2 = printf_parms["parm_2"]["parm_data"]
                        logger.debug("printf_parm2: {}".format(printf_parm2))
                        if not printf_parm2:
                            continue
                        printf_parm2_value = printf_parm2.getValue()

                        # Check is function error print.
                        if printf_parm1_value.startswith(keywords):
                            function_name = printf_parm2_value
                            logger.info("Rename {} to {}".format(ref_from_funciton.name, function_name))
                            ref_from_funciton.setName(function_name, USER_DEFINED)
                            if ref_from_funciton not in function_can_rename.keys():
                                function_can_rename[ref_from_funciton.name] = {
                                    "function_entry_point": ref_from_funciton.getEntryPoint(),
                                    "function_name": function_name
                                }

                    except Exception as err:
                        logger.error(err)

    for function_to_rename in function_can_rename:
        print("{}({}): {}".format(function_to_rename,
                                  function_can_rename[function_to_rename]['function_entry_point'],
                                  function_can_rename[function_to_rename]['function_name']
                                  ))
    print("Renamed {} functions using error print.".format(len(function_can_rename)))
