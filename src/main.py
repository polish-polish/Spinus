'''
Created on Nov 5, 2019

@author: yangke
'''
import argparse
import os
import re      
from pygdbmi.gdbcontroller import GdbController
from pygdbmi import gdbmiparser
from pprint import pprint
subject='/home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/focus-bugs-libxml2/libxml2'
fn='%s/test/XPath/xptr/chaptersrange' % subject

if __name__ == '__main__':
    parser = argparse.ArgumentParser ()    
    parser.add_argument ('-d', '--directory', type=str, required=True, help="The directory of crash inputs.")
    args = parser.parse_args ()
    print "\nParsing %s .." % args.directory
    cnt=0
    classes=0
    res=dict()
    num=0
    for root, dirs, files in os.walk(args.directory):
        for filename in files:
            fn=filename
            num+=1
            if fn=='README.txt':continue
            #if num<165:continue
            #if(fn!="id:000253,sig:11,src:001070+004333,op:splice,rep:32"):
            #    continue
            #print '%s/testXPath --xptr -i %s/test/XPath/docs/chapters -f %s' %(subject,subject,args.directory+fn)
            
            # Start gdb process
            gdbmi = GdbController()
            #print(gdbmi.get_subprocess_cmd())  # print actual command run as subprocess
            
            # Load binary a.out and get structured response
            #response = gdbmi.write('-file-exec-file /home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/libxml2/testXPath')
            response = gdbmi.write('file %s/testXPath' % subject)
            
            #response = gdbmi.write('-exec-arguments --xptr -i /home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/libxml2/test/XPath/docs/chapters -f /home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/libxml2/test/XPath/xptr/chaptersrange')
            response = gdbmi.write('set args --xptr -i %s/test/XPath/docs/chapters -f %s' % (subject,args.directory+fn))
            
            #response = gdbmi.write('-break-insert main')  # machine interface (MI) commands start with a '-'
            response = gdbmi.write('b main')
            #pprint(response)
        #     response = gdbmi.write('break main')  # normal gdb commands work too, but the return value is slightly different
        #     response = gdbmi.write('-exec-run')
            response = gdbmi.write('run')
            
            
        #     response = gdbmi.write('-exec-next', timeout_sec=0.1)  # the wait time can be modified from the default of 1 second
        #     response = gdbmi.write('next')
        #     response = gdbmi.write('next', raise_error_on_timeout=False)
        #     response = gdbmi.write('next', raise_error_on_timeout=True, timeout_sec=0.01)
            #response = gdbmi.write('-exec-continue')
            response = gdbmi.write('continue')
            #pprint(response)
            #r_dict=gdbmiparser.parse_response(response);
            
            if (len(response)>1):
                #pprint(pprint(response[-2]['payload']))
                index=1
                target=None
                for r in response[::-1]:
                    index+=1
                    if r['message']=='stopped' and r['type']=='notify':
                        target=response[-index]
                        break
                pprint(response[-6:]) 
                if target==None:
                    print "err:%s" % fn
                    pprint(response)
                    response = gdbmi.exit()
                    break  
                
                if target['message']==None and target['type']=='console' and isinstance(target['payload'],unicode) and re.match(r'[0-9]+.*',target['payload']):
                    if target['payload'] not in res:
                        res[target['payload']]=[fn]
                        classes+=1
                        print "class(%d) %s" % (classes,fn)
                        print target['payload']
                    cnt+=1
                    print "[%d] %s" % (cnt,fn)
                elif target['message']==u'thread-group-exited' and target['type']=='notify' and isinstance(target['payload'],dict) and target['payload'][u'exit-code']==u'0':
                    print "[%d] NORMAL EXIT %s" %(num,fn)
                    response = gdbmi.exit()
                    continue
                else:
                    print "err:%s" % fn
                    pprint(response)
                    response = gdbmi.exit()
                    break
            else:
                print "err:%s" % fn
                pprint (response)
                response = gdbmi.exit()
                break
            response = gdbmi.write('bt')
            #pprint(response)
            response = gdbmi.send_signal_to_gdb('SIGKILL')  # name of signal is okay
            
#             response = gdbmi.send_signal_to_gdb(2)  # value of signal is okay too
#             response = gdbmi.interrupt_gdb()  # sends SIGINT to gdb
#             response = gdbmi.write('continue')
            response = gdbmi.exit()
    print "Total files %d. Total analyzed:%d." %(num,cnt)
    print "Classes:"
    j=0
    for key, value in res.items():
        j+=1
        print "CLASS[%d]:" % j
        print key
        print value