import ast
import util
import os
import sys
import syscallArgumentExtraction




os.system("rm -rf ./error")
os.system("rm -rf ./g_ouput")
os.system("mkdir error g_ouput result output")
os.system("mkdir ./output/output_"+sys.argv[1])
os.system("mkdir ./result/result_"+sys.argv[1])
syscallArgumentExtraction.main(sys.argv[1],sys.argv[2])
                 
