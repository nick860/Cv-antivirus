#!/usr/bin/env python
# -*- coding: utf-8 -*
""" Algorithms FOR ANTI-VIRUS 2020 - Nick Glebov
IMPORTANT: MADE IN PYTHON 2.7

The program is able to scan a file and Explore the behavior of this file
through Windows 10


The imports:

time- The sleep function helps to organize different
Actions via running processes. Moreover the moudle helpful in case of
Of reciving the current date time, which needed in some functions

sys- Needed for WindowQ object

os- Needed for all those functions that related in files activities

threading.Semaphore- be able to sync between function and commands 

subprocess- running the file

psutil- getting cpu usege of the current scanned file

pickle- collects list packges to Server to be showen 
"""
#!/usr/bin/env python
# -*- coding: utf-8 -*
try:
    import pickle
    import subprocess
    import time
    import os
    import re
    import threading
    import sys
    import socket         
    global ready
    mutex = threading.Semaphore(1)
    global addres
    import psutil
    addres = '192.168.1.20'
    
#====================================CPU====================================
    
    def process(proc):
        """
        find the pid of given psutil process object
        """
        global CPU
        #running 7 seconds and checks cpu useges
        CPU.append(str(proc.cpu_percent(interval=7)))
        
#====================================PORTS==================================
        
    def CheckBefore():
        """
        checks prots state before running the virus
        """
        global Before,After
        os.system('netstat -ano > befe.txt') #the state of ports before running the virus
        with open(r"befe.txt",'r') as input_file:
                        words=input_file.read()
        Before=re.findall('[A-Z]{3}.*?LISTENING+.*?[0-9]+|.*?ESTABLISHED+.*?[0-9]+',words)

    def CheckAfter():
        """
        checks prots state while virus running
        """        
        global Before,After
        mutex.acquire() #Prevents command conflict
        os.system('netstat -ano > afae.txt')
        mutex.release() 
        with open(r"afae.txt",'r') as input_file:
                           words=input_file.read()
        After=re.findall('[A-Z]{3}.*?LISTENING+.*?[0-9]+|.*?ESTABLISHED+.*?[0-9]+',words)
        checking()

    def killTorun(portKill):
        try:
             #killing the port connection - prevents conflicts of software functions    
             txt='taskkill /PID '+portKill+' /F'
             os.system(txt)
        except:
            pass
          
    def checking():
        """
        summarize between above states- before and after
        """
        try: 
            global Before,After, Port, addres, s
            os.system('fc afae.txt befe.txt > portResults.txt')
            with open("portResults.txt",'r') as f:
                    data=f.read()        
            arr= re.findall('[A-Z]{3}.*?[E].*?[\n]',data)
            newArr=[]     
            for i in arr:
               if i.find("BEFE.TXT")==-1:
                     newArr.append(i)



            txt=""
            for i in newArr:
                if newArr.count(i)==1:
                    txt=i
                    break
                       

            port= txt[43:53]
            IdportToKill= txt[69:74]
            print port
                
            if InBlackList(port) !="no": #ports between 11000 - 14000
                    Port.append(port)
                    killTorun(IdportToKill)
        except:
            raise
            pass

        
    def InBlackList(portDest): 
         for x in range (11000,14000): #ports between 11000 - 14000
            if portDest.find(str(x))!=-1:
                return str(x)
         return "no"

#====================================Registry==================================            
    def getArrOfKeys(watcher,auto):
      """
      gets keys in spacific registry path  
      """
      #regi.py goes recursive and gets all keys and values from selected path 
      txt=subprocess.check_output("regi.py "+watcher+" "+auto,shell=True)      
      arr=[]
      arr2=[]
      keys=re.findall(".*?:",txt)
      values=re.findall(":.*?\n",txt)
      for i in values:
              arr2.append(i[1:-2])
            
      for i in keys:
            arr.append(i[:-1])
      return (arr,arr2)

    def get_dict(values,keys):
     """
     getting the information of each key
     """
     fine_me={} # the Dictionary of key:value (registry value) 
     values2=[]
     i2=-1
     for i in range(len(values)):
       x=values[i]
       while x.find(")")!=-1:
            i2=i2+1
            txt= x[x.find("(")+1:x.find(")")]
            x=x[x.find(")")+1:]
            values2.append(txt)
            fine_me[str(i2)+txt]=keys[i]
     return (fine_me,values2)

                         
    def whathappend(value,value2,dicB,dicA,num):
     """
     Which kinds of differences noticed while running the virus
     """
     global Reg,AutoRun
     save=[]
     i=-1    
     for val in value2:
        i=i+1
        if (val in value)==False:
            if dicA:
                   save.append("In "+dicA[str(i)+val]+" ["+val+"] value added!!")
            else:
                   save.append(val+" added!!") #added value from above key
     i=-1
     for val in value:
        i=i+1
        if (val in value2)==False:
            if dicB:        
                    save.append("In "+dicB[str(i)+val]+" ["+val+"] value deleted!!")
            else:
                    save.append(val+" deleted!!") #deleted value from above key
     for i in save:
         if num=="1":
             AutoRun.append(i)
         else:
             Reg.append(i)
             
    def registry(): #registry checker - spacific path 
        """
        checking for spacifc path - long one - before changes
        """
        global before_keys,before_values2,dicB,path
        answer=getArrOfKeys(path,"0")
        before_keys=answer[0]
        before_values=answer[1]
        before_values2= []
        dicB,before_values2=get_dict(before_values,before_keys)

        

    def registry2(): 
        """
        checking for spacifc path - long one - after changes
        """
        global before_keys,before_values2,dicB,path, s
        answer=getArrOfKeys(path,"0")
        after_keys=answer[0]
        after_values=answer[1]
        after_values2= []
        
        dicA,after_values2=get_dict(after_values,after_keys)
        whathappend(before_values2,after_values2,dicB,dicA,"0")
        whathappend(before_keys,after_keys,None,None,"0")
    
    def registry_Autorun(): #registry checker - spacific path (AutoRun)
        """
        checking keys Especially for Autorun changes - short one 
        """
        global ready
        answer=getArrOfKeys("Software\Microsoft\Windows\CurrentVersion","1")
        auto_values=answer[1]
        auto_keys=answer[0]
        auto_values_before=[]
        dicB,auto_values_before=get_dict(auto_values,auto_keys)

        while ready==False:
           pass
        
        time.sleep(3)
        answer2=getArrOfKeys("Software\Microsoft\Windows\CurrentVersion","1")
        after_auto_values=answer2[1]
        after_auto_keys=answer2[0]
        auto_values_after=[]
        dicA,auto_values_after=get_dict(after_auto_values,after_auto_keys)

        whathappend(auto_values_before,auto_values_after,dicB,dicA,"1")
        whathappend(auto_keys,after_auto_keys,None,None,"1")
        
    def OpenVirus():
       """
       Running the added file to system
       """
       global ready,v,file_end, proc
       while ready==False:
           time.sleep(0.02)
           pass
        
       print "=============================RUNNING==========================="
       print file_end
       if file_end=="exe":
           os.system("virus2."+file_end)
       else:
           proc = subprocess.Popen(['python', "virus2."+file_end], shell=False)
           time.sleep(1)
           try:
               pid = proc.pid
               proc = psutil.Process(int(str(pid)))
               t34 = threading.Thread(target=process, args=[proc])
               t34.start()
           except:
               
               print "short"
       v=True
       
#====================================SYS32==================================
    def CheckBeforeHandle():
       os.system('handle -p python>BeforeH.txt')
 
    def CheckAfterHandle():
       mutex.acquire() 
       os.system('handle -p python>AfterH.txt')
       mutex.release()
       findOut()   

    def findOut():
        """
        finding files damage - for example in system32 of windows 10 op
        """
        global Han, s
        mutex.acquire()
        os.system('fc BeforeH.txt AfterH.txt > results.txt')
        mutex.release()
       
        try:      
            with open(r"results.txt",'r') as input_file:
                  words=input_file.read()
            words=words.replace("\n","")
              
            while 1:
                if words.find("C:\Python27\Scripts")!=-1:
                   words= words[words.find("C:\Python27\Scripts"):]
                   save=words[:words.find(" ")]
                   Han.append(save)
                   words=words[words.find(" "):]
                else:
                    break
        except:
            raise
        
    def connctionToServer():
        """
        connecting with the server and sending data for any activity 
        """
        global ready, Reg, Han, Port, results,addres,AutoRun, file_end, s, proc
        results=None
        ready=False
        s = socket.socket()       # Create a socket object
        host = addres             # Get local machine name
        port = 60077              # Reserve a port for your service.

        s.connect((host, port))
        s.send("keep")
        while True:
            
            num=1
            file_end=""
            dat=""
            time.sleep(2)                                                              
            ready=False
            data = s.recv(2005500)
            while data.find("don't")!=-1: #if the user does hash scan 
                time.sleep(0.002)
                s.send("keep")
                data = s.recv(10000)
                
            if num==1:
                file_end=data[:data.find(";")]
                data=data[data.find(";")+1:]
                num=0    
            if not data:
                   break

            size=0 
            with open("C:\Users\Admin\Music\poc-poc\OPEN\\virus2."+file_end, 'wb') as f:
              f.write(data)
              size=len(data)+len(file_end)
              while size==10000:            #if the user sended a heavy file 
                data = s.recv(10000)
                size=len(data)
                f.write(data)
                
            ready=True
            time.sleep(2)
            ready=True
                   
            while results==None :           #wait until the program finished the scan 
                time.sleep(0.002)
                pass
            try:    
                proc.terminate()
            except:
                pass
            last_list=[] 
            last_list.append(Reg)
            last_list.append(Han)
            last_list.append(Port)
            last_list.append(results)
            last_list.append(CPU)
            last_list.append(AutoRun)

            data=pickle.dumps(last_list) 
            s.send(data)

            try:
                main1.join()
            except:
                pass
            main1 = threading.Thread(target=main, args=[]) #new cycle of scanning 
            main1.start()
            results=None
            
            
        f.close()
        s.close()
        
    def Test():
        """
        Dominating on each function by multi-threads sycn
        """
        global Reg, Han, Port, CPU, ready, results,AutoRun,proc
        t1 = threading.Thread(target=OpenVirus, args=[])
        t1.start()
        
        while ready==False:
               time.sleep(0.002)
               pass

        time.sleep(2)
        s.send("15")   #The progression increased by 15
        t2 = threading.Thread(target=registry2, args=[])
        t2.start()
        time.sleep(2)
        s.send("46")   #The progression increased by 31     
        t4 = threading.Thread(target=findOut, args=[])
        t4.start()     
        time.sleep(2)
        s.send("70")   #The progression increased by 24 
        start = time.clock()
       
        time.sleep(2)
        CheckAfterHandle()       
        t3 = threading.Thread(target=CheckAfter, args=[])
        t3.start()
        s.send("88")  #The progression increased by 18 
        time.sleep(2)

       
        
        end = time.clock()
        s.send("94") #The progression increased by 6
        
        if len(Reg)==0 and len(Han)==0 and len(Port)==0 and len(AutoRun):    
            results="no virus"
        else:
            results="virus"
        
        
    def main():
        """
        sets variables and global variables
        sets threading to check the computer state before running the virus 
        """
        global Reg, Han, Port, CPU, results,AutoRun,proc
        global before_keys, before_values2, dicB, path, file_end
        t11 = threading.Thread(target=registry_Autorun, args=[])
        t11.start()
        before_keys=[]
        before_values2=[]
        dicB={}
        path="Printers\Defaults"
        registry()
        Reg=[] #list that collects all the registry data 
        Han=[] #list that collects all the sys32 data
        Port=[] #list that collects all the ports data 
        CPU=[]  #list that collects all the cpu data
        AutoRun=[] #list that collects all the autorun data
        CheckBeforeHandle() #checks the sys32 state before running the virus
        CheckBefore()
        global Before,After,ready
        ready=False 
        Before=[] #ports state before scanning the virus 
        After=[]  #ports state after scanning the virus 
        Test()
        global BeforeH,AfterH
        BeforeH=[] #sys32 state before scanning the virus 
        AfterH=[]  #sys32 state after scanning the virus

except:
    raise


threading.Thread(target=connctionToServer, args=[]).start() # Always stay connected
main()
