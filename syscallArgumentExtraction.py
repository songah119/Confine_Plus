import angr
import ailment
import re
import logging
import os
import util
import pyvex
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.analyses.reaching_definitions import FunctionHandler
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, ObservationPointType
from angr.sim_type import SimTypePointer, SimTypeChar, SimTypeInt, SimTypeFunction
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.atoms import Register
import claripy
global weakalias
global sysmap
global syslits
from io import StringIO
import sys
import seccomp
import subprocess
import printing
import extraction
global all_funcs

all_funcs = []
weakalias = []
syslits = []

sysmap = {}


class Syscallo:
    def __init__(self, name, address):
        self.name = name
        self.add = address


class CustomFunctionHandler(FunctionHandler):
    def __init__(self):
        pass

    def handle_local_function(self, state: "ReachingDefinitionsState", data: "FunctionCallData"):
        project = state.analysis.project
        # Run RDA on the callee
        func = project.kb.functions[data.address]
        # run RDA on the callee
        sub_rda = project.analyses.ReachingDefinitions(subject=func, init_state=state, function_handler=self,
                                                    observe_all=True, dep_graph=state.dep_graph)

        # migrate data from sub_rda to its parent
        state.analysis.function_calls.update(sub_rda.function_calls)
        state.analysis.model.observed_results.update(sub_rda.model.observed_results)

        # Call get_exit_livedefinitions() to obtain a single exit state from the function on which you just ran RDA

        sub_ld = get_exit_livedefinitions(func=func, rda_model=sub_rda.model)
        if sub_ld is not None:
            state.live_definitions = sub_ld

    def handle_impl_sprintf(self, state: "ReachingDefinitionsState", data: "FunctionCallData"):
        (dst_atom,), (format_atom,) = data.args_atoms[:2]

        # Assume format is a constant string
        format_str_addr = state.get_values(format_atom).one_value().concrete_value
        format_str = load_cstring_from_loader_memory(format_str_addr, as_str=True)
        format_arg_spec = re.findall(r"%(\w)", format_str)

        args = []
        for argspec in format_arg_spec:
            if argspec == "s":
                arg = SimTypePointer(SimTypeChar(), offset=0)
            elif argspec == "d":
                arg = SimTypeInt(signed=True)
            elif argspec == "u":
                arg = SimTypeInt(signed=False)
            else:
                raise NotImplementedError()
            args.append(arg)

        prototype = SimTypeFunction(data.function.prototype.args + args, data.function.prototype.returnty)._with_arch(
            state.arch
        )
        arg_atoms = self.c_args_as_atoms(state, data.function.calling_convention, prototype)

        (format_str_atom,) = state.pointer_to_atoms(
            state.get_values(format_atom), size=len(format_str), endness="Iend_BE"
        )

        source_atoms = [
            format_str_atom,
        ]

        dst_str = b""
        for fmt_arg_idx, argspec in enumerate(format_arg_spec):
            (fmt_arg_atom,) = arg_atoms[2 + fmt_arg_idx]
            fmt_arg_addr = state.get_values(fmt_arg_atom).one_value().concrete_value
            source_atoms.append(fmt_arg_atom)

            if argspec == "s":
                # Assume string type format argument is constant
                dst_str += load_cstring_from_loader_memory(fmt_arg_addr)[:-1]
                (str_atom,) = state.pointer_to_atoms(
                    state.get_values(format_atom), size=len(format_str), endness="Iend_BE"
                )
                source_atoms.append(str_atom)
            elif argspec == "u":
                dst_str += str(fmt_arg_addr).encode("utf-8")
            elif argspec == "d":
                fmt_arg_addr = (fmt_arg_addr-2**32) if fmt_arg_addr > 2**31 else fmt_arg_addr # Signed
                dst_str += str(fmt_arg_addr).encode("utf-8")
            else:
                raise NotImplementedError()
        dst_str += b"\x00"

        (dst,) = state.pointer_to_atoms(state.get_values(dst_atom), size=len(dst_str), endness="Iend_BE")
        data.depends(dst, *source_atoms, value=MultiValues(claripy.BVV(dst_str)))


def get_exit_livedefinitions(func, rda_model):
    """
    Get LiveDefinitions at all exits of a function, merge them, and return.
    """
    lds = []
    for block in func.endpoints:
        lds.append(rda_model.get_observation_by_node(block.addr, ObservationPointType.OP_AFTER))
    if len(lds) == 1:
        return lds[0]
    if len(lds) == 0:
        return None
    return lds[0].merge(*lds[1:])[0]

def load_cstring_from_loader_memory(addr: int, as_str: bool = False):
    global proj
    s = b""
    while True:
        char_addr = addr + len(s)
        try:
            v = proj.loader.memory.load(char_addr, 1)
        except:
            print("Failed to load cstring from loader memory at address %#x", char_addr)
            break
        if v == b"\x00":
            break
        s += v
    return s.decode("utf-8") if as_str else (s + b"\x00")


def main(containerName, libcVersion, containerPath):
    logging.getLogger('angr').setLevel('CRITICAL')
    logger = logging.getLogger('my-logger')
    logger.propagate = False

    weakAliasFile = open("./input/weakalias", "r")
    for line in weakAliasFile:
        line = line.strip()
        weakalias.append(line)
    weakAliasFile.close()

    syslitsFile = open("./input/MiniSyscall", "r")
    for line in syslitsFile:
        line = line.strip()
        syslits.append(line)
    syslitsFile.close()

    print("\n\n\033[0;37;42m   Please be patientt, the process takes time \033[0m \n")
    print("\033[5;37;40m it is executing ....\033[0;37;40m\n\n")
    extractLibcfuncs(libcVersion)

    global proj
    global cfg
    global manager
    global binname
    dir_list = os.listdir("./binaries/")
    for binary in dir_list:
        imported_funcs = []
        binname = binary
        test_file = open("./test/tests", "a")
        test_file.write("binary pre>>" + binary)
        proj = angr.Project("./binaries/" + binary, auto_load_libs=False)
        test_file.write("binary>>" + binary)
        test_file.write("\n")
        for sym in proj.loader.main_object.symbols:
            if sym.is_import:
                import_func = str(sym)
                import_func = import_func.replace('"', "")
                splitted_func = import_func.split()
                imported_funcs.append(splitted_func[1])

        manager = ailment.Manager(arch=proj.arch)
        try:
            cfg = proj.analyses.CFGFast(normalize=True)
            test_file.write("cfg>>" + cfg.project.filename + "\n")
            test_file.close()
        except:
            return -1

        funcalls = detectFunctionCalls(cfg)
        syscalls = detectSysCalls(funcalls)

        detectFuncalls(syscalls, containerName)
        detectDirectcalls(containerName)

        extraction.extract(binary, all_funcs, containerName, libcVersion, imported_funcs)
    printing.combine_argument_values(containerName, containerPath)


def extractLibcfuncs(libcVersion):
    proj1 = angr.Project("./input/libc-" + libcVersion + ".so", auto_load_libs=False)
    cfg1 = proj1.analyses.CFGFast(normalize=True)
    funcalls = detectFunctionCalls(cfg1)
    syscalls = detectSysCalls(funcalls)
    detectWrapBlocks(cfg1, syscalls)
    detectSysBlocks(cfg1)


def detectSysBlocks(cfg1):
    for func in cfg1.kb.functions:
        callList = []
        for block in cfg1.kb.functions[func].blocks:
            checked = False
            try:
                if "Ijk_Sys_" in block.vex.jumpkind:
                    for stmt in block.vex.statements:
                        if isinstance(stmt, pyvex.IRStmt.IMark):
                            callList.append(hex(stmt.addr))
                    checked = True
            except:
                continue
            if checked:

                if cfg1.kb.functions[func].name not in all_funcs:
                    all_funcs.append(cfg1.kb.functions[func].name)
    i = 0
    for func in all_funcs:
        if "@" in func:
            indx = func.index("@")
            all_funcs[i] = func[0:indx]
        i = i + 1


def detectWrapBlocks(cfg1, syscalls):
    addrs = []
    for sys in syscalls:
        addrs.append(sys.add)

    callsites = []
    for func in cfg1.kb.functions:
        for callsite in cfg1.kb.functions[func].get_call_sites():
            calltarget = cfg1.kb.functions[func].get_call_target(callsite)
            addr = hex(calltarget)

            if addr in addrs:
                checked = False
                for block in cfg1.kb.functions[func].blocks:
                    if not checked:
                        ind = addrs.index(addr)
                        callList = []
                        for stmt in block.vex.statements:
                            if isinstance(stmt, pyvex.IRStmt.IMark):
                                callList.append(hex(stmt.addr))
                            if isinstance(stmt, pyvex.IRStmt.AbiHint):
                                tmpadd = str(stmt.nia)
                                tmpadd = '0x' + tmpadd[2:].lstrip('0')
                                if tmpadd in addrs:
                                    if callList[-1] not in callsites:
                                        callsites.append(callList[-1])
                                    if cfg1.kb.functions[func].name not in all_funcs:
                                        all_funcs.append(cfg1.kb.functions[func].name)
                                        checked = True
                                        continue


def detectDirectcalls(containerName):
    for func in cfg.kb.functions:
        callList = []
        for block in cfg.kb.functions[func].blocks:
            checked = False
            try:
                if "Ijk_Sys_" in block.vex.jumpkind:
                    for stmt in block.vex.statements:
                        if isinstance(stmt, pyvex.IRStmt.IMark):
                            callList.append(hex(stmt.addr))
                    checked = True
            except:
                continue
            if checked:
                syscallargs_extractor(func, callList[-1], containerName)


def syscallargs_extractor(func, target: int, containerName):
    whiteSys = open("./result/result_" + containerName + "/syscallslist", "w")
    file = open("./error/syscalls", "a")
    file1 = open("./error/errors", "a")
    main_func = cfg.kb.functions[func]

    call_to_system_address = int(target, 16)
    check_function = proj.kb.functions.function(name=cfg.kb.functions[func].name)
    observation_point = ('insn', call_to_system_address, OP_BEFORE)

    
    custom_handler = CustomFunctionHandler()
    try:
        function_rda = proj.analyses.ReachingDefinitions(
            subject=check_function,
            observation_points=[observation_point],
            dep_graph=DepGraph(),
            function_handler=custom_handler,
            observe_all=True
        )
        state_before_call_to_system = function_rda.observed_results[observation_point]

    except:
        file.close()
        file1.write(binname)
        file1.write(":")
        file1.write(target)
        file1.write("\n")
        file1.close()
        return

    edi_offset = proj.arch.registers['eax'][0]
    try:
        edi_definition = list(state_before_call_to_system.register_definitions.get_objects_by_offset(edi_offset))[0]
        try:
            output = str(edi_definition)
            tmp = output.split(":")
            tmp = tmp[4]
            if "Undefined" not in output:
                indx1 = tmp.index("[")
                indx2 = tmp.index("]")
                tmp = tmp[indx1 + 2:indx2 - 1]
                syscall_name = sysmap[int(tmp, 16)]
                if syscall_name in syslits:
                    whiteSys.write(syscall_name + "\n")
                    regs = mapping(syscall_name)
                    syscall_name = syscall_name.replace("64", "")
                    syscall_name = syscall_name.replace("__", "")
                    file = open("./output/output_" + containerName + "/" + syscall_name, "a")
                else:
                    return
            else:
                return
        except:
            file.write("rax:" + str(output))
            regs = ['edi', 'esi', 'edx', 'ecx']

    except:
        file1 = open("./error/errorf", "a")
        file1.write(binname + ":" + target + ":eax" + "\n")
        file1.close()
        return

    for reg in regs:
        edi_offset = proj.arch.registers[reg][0]
        output = ""
        try:
            edi_definition = list(state_before_call_to_system.register_definitions.get_objects_by_offset(edi_offset))[0]
            output = str(edi_definition)

        except:
            old_stdout = sys.stdout
            result = StringIO()
            sys.stdout = result
            for block in cfg.kb.functions[func].blocks:
                print(block.pp())
                tmp_str = result.getvalue()
                lines = tmp_str.split('\n')
                tmp_line = lines[len(lines) - 3].split(':')
                if target == tmp_line[0]:
                    sys.stdout = old_stdout
                    test = check_manual(lines, reg)
                    if test is not None:
                        file.write(reg + ":")
                        file.write("'" + test + "';")
                        break

                    else:
                        file.write(reg + "-" + binname + "-" + target + ":Undefined;")
                        break
                result = StringIO()
                sys.stdout = result
            continue

        tmp = output.split(":")
        tmp = tmp[4]
        if "Undefined" not in output:
            try:
                indx1 = tmp.index("[")
                indx2 = tmp.index("]")
                tmp = tmp[indx1 + 1:indx2]
                file.write(reg + ":")
                file.write(tmp + ";")
            except:
                file.write(reg + ":")
                file.write(output + ";")

        else:
            file.write(reg + "-" + binname + "-" + target + ":Undefined;")
    file.write("\n")
    file.close()
    whiteSys.close()


def extract_arguments(func, target: int, objsys, containerName):
    sys_name = objsys.name.replace("64", "")
    sys_name = sys_name.replace("__", "")

    file = open("./output/output_" + containerName + "/" + sys_name, "a")
    main_func = cfg.kb.functions[func]
    call_to_system_address = int(target, 16)

    custom_handler = CustomFunctionHandler()

    check_function = proj.kb.functions.function(name=cfg.kb.functions[func].name)
    observation_point = ('insn', call_to_system_address, OP_BEFORE)
    file.write("extract_arg file>>" + cfg.project.filename + "\n")

    try:
        function_rda = proj.analyses.ReachingDefinitions(
            subject=check_function,
            observation_points=[observation_point],
            dep_graph=DepGraph(),
            function_handler=custom_handler,
            observe_all=True
        )
        state_before_call_to_system = function_rda.observed_results[observation_point]

    except:
        old_stdout = sys.stdout
        result = StringIO()
        sys.stdout = result
        registers = mapping(objsys.name)
        for block in cfg.kb.functions[func].blocks:
            print(block.pp())
            tmp_str = result.getvalue()
            lines = tmp_str.split('\n')
            tmp_line = lines[len(lines) - 3].split(':')
            if target == tmp_line[0]:
                for reg in registers:
                    test = check_manual(lines, reg)
                    if test is not None:
                        file.write(reg + ":")
                        file.write("'" + test + "';")
                    else:
                        file.write(reg + "-" + binname + "-" + target + ":Undefined;")
                break
            result = StringIO()
            sys.stdout = result
        file.write("\n")
        sys.stdout = old_stdout

        return 0

    syscall_name = ""
    if "syscall" == objsys.name:
        edi_offset = proj.arch.registers['edi'][0]
        try:
            edi_definition = list(state_before_call_to_system.register_definitions.get_objects_by_offset(edi_offset))[0]
            try:
                output = str(edi_definition)
                tmp = output.split(":")
                tmp = tmp[4]
                if "Undefined" not in output:

                    indx1 = tmp.index("[")
                    indx2 = tmp.index("]")
                    tmp = tmp[indx1 + 2:indx2 - 1]
                    sys_num = int(tmp, 16)
                    if sys_num < 332:
                        syscall_name = sysmap[sys_num]
                    else:
                        return 0
                    if syscall_name in syslits:
                        syscall_name = syscall_name.replace("64", "")
                        syscall_name = syscall_name.replace("__", "")
                        file = open("./output/output_" + containerName + "/" + syscall_name, "a")
                    else:
                        return
                else:
                    return
            except:
                file.write(objsys.name + "-->")
                file.write("edi:" + str(output) + ";")

        except:
            old_stdout = sys.stdout
            result = StringIO()
            sys.stdout = result
            for block in cfg.kb.functions[func].blocks:
                print(block.pp())
                tmp_str = result.getvalue()
                lines = tmp_str.split('\n')
                tmp_line = lines[len(lines) - 3].split(':')
                if target == tmp_line[0]:
                    test = check_manual(lines, "edi")
                    if test is not None:
                        syscall_name = sysmap[int(test, 16)]
                        if syscall_name in syslits:
                            syscall_name = syscall_name.replace("64", "")
                            syscall_name = syscall_name.replace("__", "")
                            file = open("./output/output_" + containerName + "/" + syscall_name, "a")
                        else:
                            sys.stdout = old_stdout
                            return
                    else:
                        sys.stdout = old_stdout
                        return
                    break
                result = StringIO()
                sys.stdout = result
            sys.stdout = old_stdout

    if "syscall" == objsys.name:
        if syscall_name == '':
            return
        else:
            registers = mapping(syscall_name)
    else:
        registers = mapping(objsys.name)

    for reg in registers:
        edi_offset = proj.arch.registers[reg][0]

        try:
            edi_definition = list(state_before_call_to_system.register_definitions.get_objects_by_offset(edi_offset))[0]


        except:
            old_stdout = sys.stdout
            result = StringIO()
            sys.stdout = result
            for block in cfg.kb.functions[func].blocks:
                print(block.pp())
                tmp_str = result.getvalue()
                lines = tmp_str.split('\n')
                tmp_line = lines[len(lines) - 3].split(':')
                if target == tmp_line[0]:
                    sys.stdout = old_stdout
                    test = check_manual(lines, reg)
                    if test is not None:
                        file.write(reg + ":")
                        file.write("'0x" + test + "';")
                    else:
                        file.write(reg + "-" + binname + "-" + target + ":Undefined;")
                result = StringIO()
                sys.stdout = result
            continue

        try:
            output = str(edi_definition)
            tmp = output.split(":")
            tmp = tmp[4]
            if "Undefined" not in output:
                indx1 = tmp.index("[")
                indx2 = tmp.index("]")
                tmp = tmp[indx1 + 1:indx2]
                file.write(reg + ":")
                file.write(tmp + ";")

            else:
                if "252d9" in target:
                    old_stdout = sys.stdout
                    result = StringIO()
                    sys.stdout = result
                    for block in cfg.kb.functions[func].blocks:
                        print(block.pp())
                        tmp_str = result.getvalue()
                        lines = tmp_str.split('\n')
                        tmp_line = lines[len(lines) - 3].split(':')
                        if target == tmp_line[0]:
                            sys.stdout = old_stdout
                            test = check_manual(lines, reg)
                            if test is not None:
                                file.write(reg + ":")
                                file.write("'0x" + test + "';")
                            else:
                                file.write(reg + "-" + binname + "-" + target + ":Undefined;")
                        result = StringIO()
                        sys.stdout = result
                else:
                    file.write(reg + "-" + binname + "-" + target + ":Undefined;")

        except:
            output = str(edi_definition)
            file.write(reg + ":")
            file.write(output + ";")

    
    rdi_r = Register(72, 8)
    rsi_r = Register(64, 8)
    rdx_r = Register(32, 8)
    rcx_r = Register(24, 8)

    try:
        rdi_v = state_before_call_to_system.get_values(rdi_r).one_value()
        file.write("edi: " + hex(rdi_v.v) + ";")
        file.write("in " + hex(call_to_system_address) + "\t")
    except:
        print("value not found")
    try:
        rsi_v = state_before_call_to_system.get_values(rsi_r).one_value()
        file.write("esi: " + hex(rsi_v.v) + ";")
        file.write("in " + hex(call_to_system_address) + "\t")
    except:
        print("value not found")
    try:
        rdx_v = state_before_call_to_system.get_values(rdx_r).one_value()
        file.write("edx: " + hex(rdx_v.v) + ";")
        file.write("in " + hex(call_to_system_address) + "\t")
    except:
        print("value not found")
    try:
        rcx_v = state_before_call_to_system.get_values(rcx_r).one_value()
        file.write("ecx: " + hex(rcx_v.v) + ";")
        file.write("in " + hex(call_to_system_address) + "\t")
    except:
        print("value not found")

    file.write("\n")
    file.close()


def detectFuncalls(syscalls, containerName):
    addrs = []
    for sys in syscalls:
        addrs.append(sys.add)

    callsites = []
    for func in cfg.kb.functions:
        for callsite in cfg.kb.functions[func].get_call_sites():
            calltarget = cfg.kb.functions[func].get_call_target(callsite)
            addr = hex(calltarget)

            if addr in addrs:
                checked = False
                for block in cfg.kb.functions[func].blocks:
                    if not checked:
                        ind = addrs.index(addr)
                        callList = []
                        for stmt in block.vex.statements:
                            if isinstance(stmt, pyvex.IRStmt.IMark):
                                callList.append(hex(stmt.addr))
                            if isinstance(stmt, pyvex.IRStmt.AbiHint):
                                tmpadd = str(stmt.nia)
                                tmpadd = '0x' + tmpadd[2:].lstrip('0')
                                if tmpadd in addrs:
                                    if callList[-1] not in callsites:
                                        callsites.append(callList[-1])
                                        extract_arguments(func, callList[-1], syscalls[ind], containerName)
                                        checked = True
                                        continue


def check_manual(block, reg):
    for line in reversed(block):
        if reg in line:
            tmp = line.split()
            if tmp[1] == "mov":
                if reg in tmp[2]:
                    try:
                        test = int(tmp[3], 16)
                        return tmp[3]
                    except:
                        return None
            else:
                continue


def mapping(funcname):
    sysArgs = util.readDictFromFile('./input/AllSyscallArgs')
    if funcname == '':
        return 0
    return sysArgs[funcname]

def detectSysCalls(funcalls):
    syscalls = []
    for func in funcalls:
        if func.name in syslits:
            syscalls.append(func)
    return syscalls


def detectFunctionCalls(cfg):
    funcalls = []

    for func in cfg.kb.functions:
        tmp1 = Syscallo(cfg.functions[func].name, hex(cfg.functions[func].addr))
        funcalls.append(tmp1)

    return funcalls
