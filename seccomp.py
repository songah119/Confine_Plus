import os, sys, subprocess, signal
import json

arg_map = {'edi':'0','esi':'1','edx':'2','ecx':'3','r8d':'4','r9d':'5'}
SECCOMP_PROFILE = ('{"defaultAction": "SCMP_ACT_ALLOW",'
    '"architectures": ['
    '"SCMP_ARCH_X86_64",'
    '"SCMP_ARCH_X86",'
    '"SCMP_ARCH_X32"],'
    '"syscalls": []}'
    )

SECCOMP_PROFILE_WL = ('{"defaultAction": "SCMP_ACT_ERRNO",'
    '"architectures": ['
    '"SCMP_ARCH_X86_64",'
    '"SCMP_ARCH_X86",'
    '"SCMP_ARCH_X32"],'
    '"syscalls": []}'
    )

class Seccomp():
    """
    This class can be used to create a graph and run DFS and BFS on it
    """
    def __init__(self, logger):
        self.logger = logger

    def loadDefaultTemplate(self):
        return json.loads(SECCOMP_PROFILE)

    def loadDefaultTemplateWl(self):
        return json.loads(SECCOMP_PROFILE_WL)

    def loadTemplate(self, profilePath):
        try:
            myProfile = open(profilePath, 'r')
            myProfileStr = myProfile.read()
            result = json.loads(myProfileStr)
        except Exception as e:
            self.logger.warning("Trying to load old profile from: %s, but doesn't exist: %s", profilePath, str(e))
            result = ""
        return result
   
    def syscallTemplate(self):
        return json.loads('{"name": "","action": "SCMP_ACT_ERRNO","args": []}')
 
    def syscallTemplateWl(self):
        return json.loads('{"name": "","action": "SCMP_ACT_ALLOW","args": []}')
    
    def createProfile(self, syscalls):
        
        template = self.loadDefaultTemplate()  # load json as dict
        
        for call in syscalls:
            newsyscall = self.syscallTemplate()
            newsyscall["name"] = call
            template["syscalls"].append(newsyscall)

        return json.dumps(template, indent=4)
    
    def createProfileWhitelist(self, syscalls,sys_names,filename):
        #print(sys_names)
        #syscall all sys calls
        #sys_names only confined sys calls
        #sys_names=[]
        template = self.loadDefaultTemplateWl() 
        for call in syscalls:
            if call in sys_names:
                file_read=open(filename,"r")
                for line in file_read:
                    tmp=line.split("-->")
                    line=line.strip()
                    if call == tmp[0]:
                       #args={}
                       tmp[1]=tmp[1].strip()
                       values=tmp[1].split(":")
                       arg_list=values[1].replace("[","")
                       arg_list=arg_list.replace("]","")
                       arg_list=arg_list.split(",")
                       for val in arg_list:
                           #print(int(val))
                           args={}
                           val=val.replace(" ","")
                           newsyscall = self.syscallTemplateWl()
                           newsyscall["name"] = call
                           index=arg_map[values[0]]
                           args["index"]=int(index)
                           args["op"]="SCMP_CMP_EQ"
                           args["value"]=int(val)
                           #print(args)
                           newsyscall["args"].append(args)
                           #print(args)
                           template["syscalls"].append(newsyscall)
                file_read.close()
                
                       
            else:
                newsyscall = self.syscallTemplateWl()
                newsyscall["name"] = call
                args={}
                template["syscalls"].append(newsyscall)
        
    
        return json.dumps(template, indent=4)
    
    def createProfileWithOld(self, profilePath, syscalls):
        self.logger.debug("createProfileWithOld called with profilePath: %s", profilePath)
        if ( self.loadTemplate(profilePath) == "" ):  # load json as dict
            return self.createProfile(syscalls)

        newTemplate = self.loadDefaultTemplate()

        for syscallItem in oldTemplate["syscalls"]:
            if ( syscallItem["name"] in syscalls ):
                newsyscall = self.syscallTemplate()
                newsyscall["name"] = syscallItem["name"]
                newTemplate["syscalls"].append(newsyscall)
    
        return json.dumps(newTemplate, indent=4)
