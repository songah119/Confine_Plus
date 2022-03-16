import os
import angr
import ailment
import io 
import re
import logging
import util
import pyvex
from angr import Project
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
import subprocess
import copy        
import graph
import subprocess

global func_added

logging.getLogger('angr').setLevel('CRITICAL')
func_added=[]
syscallmap = {}
syslist=[]


weakalias1 = {}
weakalias2 = {}

with open("glibc.weak") as f:
    for line1 in f:
        line1=line1.strip()
        (key, val) = line1.split(",")
        if weakalias1.__contains__(key):
            tmp=weakalias1[key]
            if val not in tmp:
                weakalias1[key].append(val)
        else:
            weakalias1.setdefault(key, [])
            weakalias1[key].append(val)
        if weakalias2.__contains__(val):
            tmp=weakalias2[val]
            if key not in tmp:
                weakalias2[val].append(key)
        else:
            weakalias2.setdefault(val, [])
            weakalias2[val].append(key)
class Syscallo:
    def __init__(self, name, address):
        self.name = name
        self.add = address

class argument_obj:
    def __init__(self, sysname, arguments):
        self.sysname = sysname
        self.args = {}
        args=arguments.split(",")
        for reg in args:
            reg_splitted=reg.split(":")
            if len(reg_splitted) > 1:
                if "Undefined" not in reg_splitted[1] and "SP" not in reg_splitted[1]:
                    self.args[reg_splitted[0]]=reg_splitted[1]
                else:
                    self.args[reg_splitted[0]]="Undefined"

  
def extract(name,all_funcs,containerName,libcVersion,imported_funcs):
    with open('./input/AllSyscall') as f:
          syscallmap= f.read()
    syslistFile=open("./input/MiniSyscall","r")
    for line in syslistFile:
         line=line.strip()
         syslist.append(line)
    syslistFile.close()
    checking=create_graph(name,libcVersion,containerName,imported_funcs)
    if checking==1:
        func_list=checking_mapping(name,all_funcs)
        arguments_value=Extract_args(func_list,libcVersion)
        print_args(arguments_value,containerName)
    else:
        return 
                            
              
def create_graph(name,libcVersion,containerName,imported_funcs):
    whiteSys=open("./result/result_"+containerName+"/syscallslist","a")
    rootLogger = logging.getLogger("coverage")
    rootLogger.setLevel(logging.CRITICAL)
    uniq_calls = imported_funcs
    glibcGraph = graph.Graph(rootLogger)
    glibcGraph.createGraphFromInput("./glibc."+libcVersion+".callgraph", ":")        
    glibcSyscallList=[]
    i=0
    while i < 400:
                glibcSyscallList.append("syscall(" + str(i) + ")")
                glibcSyscallList.append("syscall ( " + str(i) + " )")
                glibcSyscallList.append("syscall( " + str(i) + " )")
                i += 1
    for func in uniq_calls:
        leaves = glibcGraph.getLeavesFromStartNode(func , glibcSyscallList, list(),name)
        
    if len(uniq_calls)>0:    
        lines=[]
        file=open("./g_ouput/mapping_"+name,"r")
        output1=open("./g_ouput/final_mapping"+name,"a+")
        for line in file:
            line=line.strip()
            for syscall in syslist:
                if syscall in line:
                    tmp=line.split("->")
                    whiteSys.write(str(tmp[-1])+"\n")
                    if line not in lines:
                      output1.write(line+"\n") 
                      lines.append(line)

        file.close()
        output1.close()
        return 1
    else:
        return 0
    whiteSys.close()
def Extract_args(func_list,libcVersion):
    arguments_value={}
    with open("./input/syscalls."+libcVersion+".txt") as f:
        for line1 in f:
            line1=line1.strip()
            #print(line1)
            (key, val) = line1.split(";")
            if key in func_list:
                if arguments_value.__contains__(key):
                    splitted_args=val.split("&")
                    new_args=argument_obj(splitted_args[0],splitted_args[1])
                    if new_args not in arguments_value[key]:
                        arguments_value[key].append(new_args)
                else:
                    
                    arguments_value.setdefault(key, [])
                    splitted_args=val.split("&")
                    new_args=argument_obj(splitted_args[0],splitted_args[1])
                    arguments_value[key].append(new_args)

    f.close()
    return arguments_value

def print_args(arguments_value,containerName):
    uniq_args={}
    for key in arguments_value:
        sys_list=arguments_value[key]
        
        for sys_call in sys_list:
            if uniq_args.__contains__(sys_call.sysname):
                args_list=uniq_args[sys_call.sysname]
                if sys_call.args.__contains__('edi'):
                    if args_list.__contains__('edi'):
                       if sys_call.args['edi'] not in args_list['edi']:
                            args_list['edi'].append(sys_call.args['edi'])
                    else:
                        tmp=[]
                        tmp.append(sys_call.args['edi'])
                        args_list['edi']= tmp
                        
                if sys_call.args.__contains__('esi'):
                    if args_list.__contains__('esi'):
                       if sys_call.args['esi'] not in args_list['esi']:
                            args_list['esi'].append(sys_call.args['esi'])
                    else:
                        tmp=[]
                        tmp.append(sys_call.args['esi'])
                        args_list['esi']= tmp
                        
                if sys_call.args.__contains__('edx'):
                    if args_list.__contains__('edx'):
                       if sys_call.args['edx'] not in args_list['edx']:
                            args_list['edx'].append(sys_call.args['edx'])
                    else:
                        tmp=[]
                        tmp.append(sys_call.args['edx'])
                        args_list['edx']= tmp
                        
                if sys_call.args.__contains__('ecx'):
                    if args_list.__contains__('ecx'):
                       if sys_call.args['ecx'] not in args_list['ecx']:
                            args_list['ecx'].append(sys_call.args['ecx'])
                    else:
                        tmp=[]
                        tmp.append(sys_call.args['ecx'])
                        args_list['ecx']= tmp

                if sys_call.args.__contains__('r8d'):
                    if args_list.__contains__('r8d'):
                       if sys_call.args['r8d'] not in args_list['r8d']:
                            args_list['r8d'].append(sys_call.args['r8d'])
                    else:
                        tmp=[]
                        tmp.append(sys_call.args['r8d'])
                        args_list['r8d']= tmp
                        
                if sys_call.args.__contains__('r9d'):
                    if args_list.__contains__('r9d'):
                       if sys_call.args['r9d'] not in args_list['r9d']:
                            args_list['r9d'].append(sys_call.args['r9d'])
                    else:
                        tmp=[]
                        tmp.append(sys_call.args['r9d'])
                        args_list['r9d']= tmp                        
                        
                uniq_args[sys_call.sysname]=args_list
                
                
            else:
                args_list={}
                uniq_args.setdefault(sys_call.sysname, {})
                if sys_call.args.__contains__('edi'):
                    tmp=[]
                    tmp.append(sys_call.args['edi'])
                    args_list['edi']= tmp                   
                if sys_call.args.__contains__('esi'):
                    tmp=[]
                    tmp.append(sys_call.args['esi'])
                    args_list['esi']= tmp           
                if sys_call.args.__contains__('edx'):
                    tmp=[]
                    tmp.append(sys_call.args['edx'])
                    args_list['edx']= tmp            #for obj in obj.args
                if sys_call.args.__contains__('ecx'):
                    tmp=[]
                    tmp.append(sys_call.args['ecx'])
                    args_list['ecx']= tmp               
                if sys_call.args.__contains__('r8d'):
                    tmp=[]
                    tmp.append(sys_call.args['r8d'])
                    args_list['r8d']= tmp
                if sys_call.args.__contains__('r9d'):
                    tmp=[]
                    tmp.append(sys_call.args['r9d'])
                    args_list['r9d']= tmp                   
                    
                uniq_args[sys_call.sysname]=args_list

    for key in uniq_args:
        value=uniq_args[key]
        key=key.replace("__", "")
        key=key.replace("64", "")
        sys_file=open("./output/output_"+containerName+"/"+key,"a+")
        for reg in value:
            tmp=str(value[reg])
            sys_file.write(reg+":")
            tmp=tmp.replace("[","")
            tmp=tmp.replace("]","")
            sys_file.write(tmp)
            sys_file.write(";")            
        sys_file.write("\n")
        sys_file.close()
             
def checking_mapping(name,all_funcs):
    mapping = open("./g_ouput/final_mapping"+name,"r")
    
    for line in mapping:
        line=line.rstrip()
        splittedItems = line.split("->")
        lent=len(splittedItems)
        syscallname=splittedItems[lent-1]
        if syscallname in syslist:
            for i in reversed(range(lent)):
                if splittedItems[i] not in syslist:
                  if "None" not in splittedItems[i]:
                    if splittedItems[i]=="malloc":
                        splittedItems[i]="sysmalloc"
                    if splittedItems[i] in all_funcs:
                        if splittedItems[i] not in func_added:
                            func_added.append(splittedItems[i])
                            break
                        else:
                            break
                       
                    else:
                        if splittedItems[i]+"64" in all_funcs:
                           if splittedItems[i]+"64" not in func_added:
                               func_added.append(splittedItems[i]+"64")
                               break
                           else:
                                break
                        else: 
                            if "__"+splittedItems[i] in all_funcs:
                               if "__"+splittedItems[i] not in func_added:
                                   func_added.append("__"+splittedItems[i])
                                   break
                               else:
                                   break
                            else:   
                                if "__"+splittedItems[i]+"64" in all_funcs:
                                   if "__"+splittedItems[i]+"64" not in func_added:
                                       func_added.append("__"+splittedItems[i]+"64")
                                       break
                                   else:
                                       break
                                else:
                                    tmp=splittedItems[i].replace("__", "")
                                    if tmp in all_funcs:
                                        if tmp not in func_added:
                                            func_added.append(tmp)
                                            break
                                        else:
                                            break
                                    else:
                                        tmp=splittedItems[i].replace("64", "")
                                        if tmp in all_funcs:
                                            if tmp not in func_added:
                                                func_added.append(tmp)
                                                break
                                            else:
                                                break
                                        else:
                                            tmp=splittedItems[i].replace("64", "")
                                            tmp=splittedItems[i].replace("__", "")
                                            if tmp in all_funcs:
                                                if tmp not in func_added:
                                                    func_added.append(tmp)
                                                    break
                                                else:
                                                    break
                                            else:
                                                if weakalias1.__contains__(splittedItems[i]):
                                                    check=False
                                                    tmp_val=weakalias1[splittedItems[i]]
                                                    for func in tmp_val:
                                                        if func in all_funcs and func not in syslist:
                                                            if func not in func_added:
                                                                func_added.append(func)
                                                                check=True
                                                                break
                                                            else:
                                                                check=True
                                                                break
                                                    if  check:
                                                        break
                                                    else:                                           
                                                        if weakalias2.__contains__(splittedItems[i]):
                                                            check=False
                                                            tmp_val=weakalias2[splittedItems[i]]
                                                            for func in tmp_val:
                                                                if func in all_funcs and func not in syslist:
                                                                    if func not in func_added:
                                                                        func_added.append(func)
                                                                        check=True
                                                                        break
                                                                                    
                                                                    else:
                                                                        check=True
                                                                        break
                                                                                    
                                                            if  check:
                                                                break

    mapping.close()
    return func_added

