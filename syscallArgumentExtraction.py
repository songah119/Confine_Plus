import angr
import ailment
import io 
import re
import logging
import os
import util
import pyvex
from angr import Project
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
global weakalias
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



all_funcs=[]
weakalias=[]
syslits=[]

sysmap={}


class Syscallo:
    def __init__(self, name, address):
        self.name = name
        self.add = address

        
def main(containerName,libcVersion,containerPath):
    logging.getLogger('angr').setLevel('CRITICAL')
    logger = logging.getLogger('my-logger')
    logger.propagate = False
    sysmap =util.readDictFromFile('./input/AllSyscall')
    #print(sysmap[4])
    weakAliasFile=open("./input/weakalias","r")
    for line in weakAliasFile:
        line=line.strip()
        weakalias.append(line)
    weakAliasFile.close()
    syslitsFile=open("./input/MiniSyscall","r")
    for line in syslitsFile:
        line=line.strip()
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
                  imported_funcs=[]
                  binname=binary
                  proj = angr.Project("./binaries/"+binary, auto_load_libs=False)
                  for sym in proj.loader.main_object.symbols:
                     if sym.is_import:
                        import_func=str(sym)
                        import_func=import_func.replace('"', "")
                        splitted_func=import_func.split()
                        imported_funcs.append(splitted_func[1])
                  
                  manager = ailment.Manager(arch=proj.arch)
                  try:
                    cfg = proj.analyses.CFGFast(normalize=True)
                  except:
                    return -1    
                  funcalls=detectFunctionCalls(cfg)
                  syscalls=detectSysCalls(funcalls)
                  detectFuncalls(syscalls,containerName)
                  detectDirectcalls(containerName)
                  extraction.extract(binary,all_funcs,containerName,libcVersion,imported_funcs)
    printing.combine_argument_values(containerName,containerPath)
    
def extractLibcfuncs(libcVersion):
    proj1 = angr.Project("./input/libc-"+libcVersion+".so", auto_load_libs=False)
    cfg1 = proj1.analyses.CFGFast(normalize=True)
    funcalls=detectFunctionCalls(cfg1)
    syscalls=detectSysCalls(funcalls)
    detectWrapBlocks(cfg1,syscalls)
    detectSysBlocks(cfg1)
    
def detectSysBlocks(cfg1):
    for func in cfg1.kb.functions:
        callList=[]
        for block in cfg1.kb.functions[func].blocks:
            checked=False
            try:
                if "Ijk_Sys_" in block.vex.jumpkind:                    
                    for stmt in block.vex.statements:
                       if isinstance(stmt, pyvex.IRStmt.IMark):
                          callList.append(hex(stmt.addr))
                    checked=True
            except:
                continue
            if checked:
                
                if cfg1.kb.functions[func].name not in all_funcs:
                   all_funcs.append(cfg1.kb.functions[func].name)
                   
    
    i=0
    for func in all_funcs:
        
        if "@" in func:
            indx=func.index("@")
            all_funcs[i]=func[0:indx]
        i=i+1					    
    
def detectWrapBlocks(cfg1,syscalls):
    addrs=[]
    for sys in syscalls:
        addrs.append(sys.add)


    callsites=[]
    for func in cfg1.kb.functions:
        for callsite in cfg1.kb.functions[func].get_call_sites():
                calltarget=cfg1.kb.functions[func].get_call_target(callsite)
                addr=hex(calltarget)
                
                if addr in addrs:
                    checked=False
                    for block in cfg1.kb.functions[func].blocks:
                        if not checked:
                            ind=addrs.index(addr)
                            callList=[]
                            for stmt in block.vex.statements:
                                if isinstance(stmt, pyvex.IRStmt.IMark):
                                   callList.append(hex(stmt.addr))
                                if isinstance(stmt, pyvex.IRStmt.AbiHint):
                                   tmpadd=str(stmt.nia)
                                   tmpadd='0x'+tmpadd[2:].lstrip('0')
                                   if tmpadd in addrs:
                                      if callList[-1] not in callsites:
                                        callsites.append(callList[-1])
                                      if cfg1.kb.functions[func].name not in all_funcs:
                                        all_funcs.append(cfg1.kb.functions[func].name)
                                        checked=True
                                        continue
def detectDirectcalls(containerName):
    for func in cfg.kb.functions:
        callList=[]
        for block in cfg.kb.functions[func].blocks:
            checked=False
            try:
                if "Ijk_Sys_" in block.vex.jumpkind:                    
                    for stmt in block.vex.statements:
                       if isinstance(stmt, pyvex.IRStmt.IMark):
                          callList.append(hex(stmt.addr))
                    checked=True
            except:
                continue
            if checked:
                syscallargs_extractor(func,callList[-1],containerName)
      

def syscallargs_extractor(func,target: int,containerName):
    whiteSys=open("./result/result_"+containerName+"/syscallslist","w")
    file = open("./error/syscalls", "a")
    file1 = open("./error/errors", "a")
    main_func = cfg.kb.functions[func]
    
    call_to_system_address = int(target, 16)
    check_function = proj.kb.functions.function(name=cfg.kb.functions[func].name)
    observation_point = ('insn', call_to_system_address, OP_BEFORE)
    
    try: 
            function_rda = proj.analyses.ReachingDefinitions(
            subject=check_function,
            observation_points=[observation_point],
            dep_graph=DepGraph()
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
            output=str(edi_definition)
            tmp=output.split(":")
            tmp=tmp[4]
            if "Undefined" not in output:
               indx1=tmp.index("[")
               indx2=tmp.index("]")
               tmp=tmp[indx1+2:indx2-1]
               syscall_name=sysmap[int(tmp,16)]
               if syscall_name in syslits:
                    whiteSys.write(syscall_name+"\n")
                    regs=mapping(syscall_name)
                    syscall_name = syscall_name.replace("64", "")
                    syscall_name = syscall_name.replace("__", "")
                    file=open("./output/output_"+containerName+"/"+syscall_name,"a")
               else:
                    return
            else:
                    return
        except:
            file.write("rax:"+str(output))
            regs=['edi','esi','edx','ecx']
            
    except:
        file1 = open("./error/errorf", "a")
        file1.write(binname+":"+target+":eax"+"\n")
        file1.close()    
        return
    
    for reg in regs:
        edi_offset = proj.arch.registers[reg][0]
        output=""
        try:
            edi_definition = list(state_before_call_to_system.register_definitions.get_objects_by_offset(edi_offset))[0]
            output=str(edi_definition)
        
        except:
            old_stdout = sys.stdout
            result = StringIO()
            sys.stdout = result
            for block in cfg.kb.functions[func].blocks: 
                print(block.pp())
                tmp_str=result.getvalue()
                lines=tmp_str.split('\n')
                tmp_line=lines[len(lines)-3].split(':')
                if target==tmp_line[0]:
                    sys.stdout=old_stdout
                    test=check_manual(lines, reg)
                    if test is not None:
                        file.write(reg+":")
                        file.write("'"+test+"';")
                        break
                        
                    else:
                        file.write(reg+"-"+binname+"-"+target+":Undefined;")
                        break
                result = StringIO()
                sys.stdout = result
            continue
        
        tmp=output.split(":")
        tmp=tmp[4]
        if "Undefined" not in output:
            try:
                indx1=tmp.index("[")
                indx2=tmp.index("]")
                tmp=tmp[indx1+1:indx2]
                file.write(reg+":")
                file.write(tmp+";")
            except:
                file.write(reg+":")
                file.write(output+";")
                    
        else:
            file.write(reg+"-"+binname+"-"+target+":Undefined;")
    file.write("\n")            
    ###########################################################
    file.close() 
    whiteSys.close()
    
    
    
def extract_arguments(func,target: int,objsys,containerName):
    sys_name = objsys.name.replace("64", "")
    sys_name = sys_name.replace("__", "")   
    
    file = open("./output/output_"+containerName+"/"+sys_name, "a")
    main_func = cfg.kb.functions[func]
    call_to_system_address = int(target, 16)
    check_function = proj.kb.functions.function(name=cfg.kb.functions[func].name)
    observation_point = ('insn', call_to_system_address, OP_BEFORE)
 

    try:
        function_rda = proj.analyses.ReachingDefinitions(
        subject=check_function,
        observation_points=[observation_point],
        dep_graph=DepGraph()
        )
        state_before_call_to_system = function_rda.observed_results[observation_point]



    except:
        old_stdout = sys.stdout
        result = StringIO()
        sys.stdout = result
        registers=mapping(objsys.name)
        for block in cfg.kb.functions[func].blocks:
            print(block.pp())
            tmp_str=result.getvalue()
            lines=tmp_str.split('\n')
            tmp_line=lines[len(lines)-3].split(':')
            if target==tmp_line[0]:
                for reg in registers:
                    test=check_manual(lines, reg)
                    if test is not None:
                        file.write(reg+":")
                        file.write("'"+test+"';")
                    else:
                        file.write(reg+"-"+binname+"-"+target+":Undefined;")
                break
            result = StringIO()
            sys.stdout = result
        file.write("\n")
        sys.stdout=old_stdout

        return 0
        
    syscall_name=""
    if "syscall" == objsys.name:
       edi_offset = proj.arch.registers['edi'][0]
       try:
            edi_definition = list(state_before_call_to_system.register_definitions.get_objects_by_offset(edi_offset))[0]
            try:
                output=str(edi_definition)
                tmp=output.split(":")
                tmp=tmp[4]
                if "Undefined" not in output:

                    indx1=tmp.index("[")
                    indx2=tmp.index("]")
                    tmp=tmp[indx1+2:indx2-1]
                    sys_num=int(tmp,16)
                    if sys_num < 332:
                        syscall_name=sysmap[sys_num]
                    else:
                        return 0
                    if syscall_name in syslits:
                        syscall_name = syscall_name.replace("64", "")
                        syscall_name = syscall_name.replace("__", "")
                        file=open("./output/output_"+containerName+"/"+syscall_name,"a")
                        #file.write(objsys.name+"\n")
                    else:
                        return
                else:
                    return
            except:
                #syscall_name=str(output)
                file.write(objsys.name+"-->")
                file.write("edi:"+str(output)+";")
            
       except:
            old_stdout = sys.stdout
            result = StringIO()
            sys.stdout = result
            for block in cfg.kb.functions[func].blocks:
                print(block.pp())
                tmp_str=result.getvalue()
                lines=tmp_str.split('\n')
                tmp_line=lines[len(lines)-3].split(':')
                if target==tmp_line[0]:
                    test=check_manual(lines, "edi")
                    if test is not None:
                        syscall_name=sysmap[int(test,16)]
                        if syscall_name in syslits:
                            syscall_name = syscall_name.replace("64", "")
                            syscall_name = syscall_name.replace("__", "")
                            file=open("./output/output_"+containerName+"/"+syscall_name,"a")
                        else:
                            sys.stdout=old_stdout
                            return
                    else:
                        sys.stdout=old_stdout
                        return
                    break
                result = StringIO()
                sys.stdout = result
            #file.write("\n")
            sys.stdout=old_stdout
    
    if "syscall" == objsys.name:
        registers=mapping(syscall_name)
    if "syscall" != objsys.name:
        registers=mapping(objsys.name)
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
                tmp_str=result.getvalue()
                lines=tmp_str.split('\n')
                tmp_line=lines[len(lines)-3].split(':')
                if target==tmp_line[0]:
                    sys.stdout=old_stdout
                    test=check_manual(lines, reg)
                    if test is not None:                        
                        file.write(reg+":")
                        file.write("'0x"+test+"';")
                    else:
                        file.write(reg+"-"+binname+"-"+target+":Undefined;")
                result = StringIO()
                sys.stdout = result
            continue
        
        
        
        try:
            output=str(edi_definition)
            tmp=output.split(":")
            tmp=tmp[4]
            if "Undefined" not in output:
                indx1=tmp.index("[")
                indx2=tmp.index("]")
                tmp=tmp[indx1+1:indx2]
                file.write(reg+":")
                file.write(tmp+";")
                
            else:
                if "252d9" in target:
                    old_stdout = sys.stdout
                    result = StringIO()
                    sys.stdout = result
                    for block in cfg.kb.functions[func].blocks: 
                        print(block.pp())
                        tmp_str=result.getvalue()
                        lines=tmp_str.split('\n')
                        tmp_line=lines[len(lines)-3].split(':')
                        if target==tmp_line[0]:
                            sys.stdout=old_stdout
                            test=check_manual(lines, reg)
                            if test is not None:                        
                                file.write(reg+":")
                                file.write("'0x"+test+"';")
                            else:
                                file.write(reg+"-"+binname+"-"+target+":Undefined;")
                        result = StringIO()
                        sys.stdout = result    
                else:
                    file.write(reg+"-"+binname+"-"+target+":Undefined;")
        
        except:
            output=str(edi_definition)
            file.write(reg+":")
            file.write(output+";")
        
    file.write("\n")
    file.close()
        
    

  
def detectFuncalls(syscalls,containerName):
    addrs=[]
    for sys in syscalls:
        addrs.append(sys.add)


    callsites=[]
    for func in cfg.kb.functions:
        for callsite in cfg.kb.functions[func].get_call_sites():
                calltarget=cfg.kb.functions[func].get_call_target(callsite)
                addr=hex(calltarget)
                
                if addr in addrs:
                    checked=False
                    for block in cfg.kb.functions[func].blocks:
                        if not checked:
                            ind=addrs.index(addr)
                            callList=[]
                            for stmt in block.vex.statements:
                                if isinstance(stmt, pyvex.IRStmt.IMark):
                                   callList.append(hex(stmt.addr))
                                if isinstance(stmt, pyvex.IRStmt.AbiHint):
                                   tmpadd=str(stmt.nia)
                                   tmpadd='0x'+tmpadd[2:].lstrip('0')
                                   if tmpadd in addrs:
                                      if callList[-1] not in callsites:
                                        callsites.append(callList[-1])
                                        extract_arguments(func,callList[-1],syscalls[ind],containerName)
                                        checked=True
                                        continue
    

    
    
    
def check_manual(block, reg):
    for line in reversed(block):
        if reg in line:
           tmp=line.split()
           if tmp[1]=="mov":
              if reg in tmp[2]:
                 try:
                    test=int(tmp[3], 16)
                    return tmp[3]
                 except:    
                    return None
           else:
            continue

def mapping(funcname):
    sysArgs =util.readDictFromFile('./input/AllSyscallArgs')
    return sysArgs[funcname] 
    


def detectSysCalls(funcalls):
    syscalls=[]
    for func in funcalls:
        if func.name in syslits:
            syscalls.append(func)
    return syscalls 
    
    
def detectFunctionCalls(cfg):

    funcalls=[]
    
    for func in cfg.kb.functions:
        tmp1=Syscallo(cfg.functions[func].name, hex(cfg.functions[func].addr))
        funcalls.append(tmp1)

    return funcalls

    


