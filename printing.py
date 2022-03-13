import os
import re
import seccomp
import logging
import subprocess


arg_map = {'edi':'0','esi':'1','edx':'2','ecx':'3','r8d':'4','r9d':'5'}
def runCommand(cmd):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    outStr = str(out.decode("utf-8"))
    errStr = str(err.decode("utf-8"))
    return (proc.returncode, outStr, errStr)
    
    
def create_profile(containerName):
    evalFile=open("./output/aggrigatedResult.txt","a")
    blackProfile=open("./result/result_"+containerName+"/blackProfile.txt","w")
    inputFile=open("./input/seccomp.c","r")
    outputFile=open("./result/result_"+containerName+"/"+containerName+"-ConfinePlus.c","w")

    seccompTemplate = open("./input/seccomp-allow-1.txt", 'r')
    for line in seccompTemplate:
        outputFile.write(line)
    seccompTemplate.close()
        
    start=False
    checked=False
    blackSyscalls=[]
    for line in inputFile:
        if ("Kill" not in line) and (not start):
            continue
        else:
            if "define Kill" in line:
                continue
            else:
                if "Kill" in line:
                    sysname = line[line.find('(')+1:line.find(')')]
                    blackSyscalls.append(sysname)
                    blackProfile.write(sysname+"\n")
                    start=True
                    
                else:
                    if not checked:
                       checked=True
                       allsys_array = []
                       file=open("./input/cmd1","r")
                       cmd=""
                       for line in file:
                           cmd=cmd+line
                           (returncode, out1, err) = runCommand(cmd)
                           if ( returncode != 0 ):
                               print("extracting system call list fails: " + err)
                               quit()
                       file.close()
                       for line in out1.split('\n'):
                           line=line.strip()
                           allsys_array.append(line)
                       file.close()            
                       
                       white_list=[]
                       for elem in allsys_array:
                          if elem not in blackSyscalls:
                             white_list.append(elem)
                             
                             
                       file=open("./result/result_"+containerName+"/syscalls","r")      
                       sys_names=[]
                       num_args=0
                       for line in file:
                          num_args=num_args+1
                          line=line.strip()
                          tmp=line.split("-->")
                          if tmp[0] not in sys_names:
                                sys_names.append(tmp[0]) 
                       evalFile.write("Result for:"+str(containerName)+"\n")
                       evalFile.write("Num of filtered system calls for arg-filtering: "+str(len(sys_names))+"\n")
                       evalFile.write("Num of filtered arguments for arg-filtering: "+str(num_args)+"\n")
                       for sysCall in white_list:
                            if sysCall in sys_names:
                                file_read=open("./result/result_"+containerName+"/syscalls","r")
                                for line in file_read:
                                    tmp=line.split("-->")
                                    line=line.strip()
                                    if sysCall == tmp[0]:
                                       #args={}
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
                    else:
                        outputFile.write(line)
                        outputFile.flush()
    outputFile.close()
    inputFile.close()
    blackProfile.close()
    evalFile.close()
def combine_argument_values(containerName):
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
                if "Undefined" not in value:
                    i=0
                    for val in value:
                        val=int(val, 16)
                        value[i]=val
                        i=i+1
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
    create_profile(containerName)