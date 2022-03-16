import os
import re
import seccomp
import logging
import subprocess
import util 

syslist=[]
arg_map = {'edi':'0','esi':'1','edx':'2','ecx':'3','r8d':'4','r9d':'5'}
def runCommand(cmd):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #print("running cmd: " + cmd)
    #proc.wait()
    (out, err) = proc.communicate()
    outStr = str(out.decode("utf-8"))
    errStr = str(err.decode("utf-8"))
    #print("finished running cmd: " + cmd)
    return (proc.returncode, outStr, errStr)
    #return (proc.returncode, out, err)
    
    
def create_profile(containerName,containerPath):
    white_list=[]
    syscallmap={}
    syscallmap=util.readDictFromFile('./input/AllSyscall')
    for key, value in syscallmap.items():
        syslist.append(value)
    
    whiteSys=open("./result/result_"+containerName+"/syscallslist","r")
    for line in whiteSys:
        line=line.strip()
        if line in syslist:
           #print(line+"1")
           if str(line) not in white_list:
              white_list.append(str(line))
       
    whiteSys.close()
    outputFile=open("./result/result_"+containerName+"/"+containerName+"-ConfinePlus.c","w")
    seccompTemplate = open("./input/seccomp-allow-1.txt", 'r')
    seccompTemplate2 = open("./input/seccomp-allow-2.txt", 'r')
    for line in seccompTemplate:
        outputFile.write(line)
    seccompTemplate.close()
    file=open("./result/result_"+containerName+"/syscalls","r")
    sys_names=[]
    num_args=0
    for line in file:                      
        num_args=num_args+1                      
        line=line.strip()                      
        tmp=line.split("-->")                      
        if tmp[0] not in sys_names:                      
              sys_names.append(tmp[0])
    for sysCall in white_list:
        if sysCall in sys_names:
            file_read=open("./result/result_"+containerName+"/syscalls","r")
            for line in file_read:
                tmp=line.split("-->")
                line=line.strip()
                if sysCall == tmp[0]:
                   tmp[1]=tmp[1].strip()
                   values=tmp[1].split(":")
                   arg_list=values[1].replace("[","")
                   arg_list=arg_list.replace("]","")
                   arg_list=arg_list.split(",")
                   for val in arg_list:
                       index=arg_map[values[0]]
                       outputFile.write(f"AllowWithArg({sysCall},{int(index)},{int(val)}),\n\t")
                       outputFile.flush()
            file_read.close()
             
        else:
            if sysCall!="":
                outputFile.write(f"Allow({sysCall}),\n\t")
                outputFile.flush()
    outputFile.write("BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),\n")
    for line in seccompTemplate2:
        outputFile.write(line)
    seccompTemplate2.close()
    obj_name=containerPath.split("/")
    outputFile.write('args[0] ="'+obj_name[-1]+'" \n')
    outputFile.write('execv("'+containerPath+'", args); \n')
    outputFile.write('} \n')
    outputFile.close()
    os.remove("./result/result_"+containerName+"/syscallslist")
    

def combine_argument_values(containerName,containerPath):
    syscalls_w = {}
    dir_list = os.listdir("./output/output_"+containerName+"/")
    f_write = open("./result/result_"+containerName+"/syscalls", "w")
    check=False
    fix=False
    for system_call in dir_list:
            if system_call=="ioctl":
               check=True 
            if system_call=="syscall":
                continue
            if system_call=="clone":
                fix=True
            file = open("./output/output_"+containerName+"/"+system_call, "r")
            for line in file:
                line=line.strip()
                line=line.replace("0x0x", "0x")
                values=line.split(";")
                for value in values:
                    value= value.rstrip('\r')
                    if value:
                        #print(value)
                        (key, val) = value.split(":")

                        if "-" in key:
                            keys=key.split("-")
                            if ("libcrypto" in key) and (check):
                                val="0x5421"
                            key=keys[0]
                        if fix:
                           key="edi"
                        if syscalls_w.__contains__(key):
                           tmp=syscalls_w[key]
                           if "," not in val:
                                val=val.replace("'", "")
                                val=val.replace(" ", "")
                                val=val.strip()
                                if val not in tmp:
                                    syscalls_w[key].append(val)
                                   
                           else:
                                vals=val.split(",")
                                for val in vals:
                                    val=val.replace("'", "")
                                    val=val.replace(" ", "")
                                    val=val.strip()
                                    if val not in tmp:
                                       syscalls_w[key].append(val)
                              
                        else:
                           syscalls_w.setdefault(key, [])
                           if "," not in val:
                               val=val.replace("'", "")
                               val=val.replace(" ", "")
                               
                               syscalls_w[key].append(val)
                           else:
                               vals=val.split(",")
                               
                               for val in vals:
                                  val=val.replace("'", "")
                                  val=val.replace(" ", "")
                                  tmp=syscalls_w[key]
                                  val=val.strip()
                                  if val not in tmp:
                                     syscalls_w[key].append(val)
            
            for key, value in syscalls_w.items():
                if ("Undefined" not in str(value)) and ("SP" not in str(value)):
                    #print(value)
                    i=0
                    for val in value:
                        val=int(val, 16)
                        value[i]=val
                        i=i+1
                    #missing in glibc call graph
                    if (system_call=="mmap") and (key=="ecx"):
                        add=[2050,50,2066,2]
                        for item in add:
                            if item not in value:
                                value.append(item)
                        f_write.write(system_call+'-->'+str(key)+ ':'+ str(value)+'\n')
                    else:
                        f_write.write(system_call+'-->'+str(key)+ ':'+ str(value)+'\n')
            syscalls_w={}
            file.close()
            fix=False
            check=False
    f_write.close()
    create_profile(containerName,containerPath)