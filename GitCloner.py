#!/usr/bin/env python
#-*-coding:utf-8-*-
# Git Clone Using Python
# Crafted By -Scav-engeR-
import urllib,os,sys
class main():
        def __init__(self):
                # Github Url
                self.s=sys.argv[1]
                if not ".git" in self.s:
                        print("++ ussage: "+sys.argv[0]+" https://github.com/........git")
                elif not "https://github.com/" in self.s:
                        print("- Incorrect Address: "+self.s)
                else:
                        try:
                                self.checl=urllib.urlopen(self.s).getcode()
                        except:
                                print('- Connection Error')
                                sys.exit()
                        if self.checl == 404:
                                print("- Address is incorrect! Cloning has failed damnit "+self.s)
                        else:
                                print("cloning into "+self.s.split('/')[4]).replace('.git','')
                                a=self.s.split('/')[-1].replace('.git','')
                                self.down=self.s.replace('.git','/archive/master.zip')
                                self.filename= a+".zip"
                                try:
                                        urllib.urlretrieve(self.down,self.filename)
                                except Exception as f:
                                        print("- "+str(f))
                                        sys.exit()
                                print("extracting "+self.s.split('/')[4]+"...").replace('.git','')
                                os.system('unzip %s;mv *-master %s;rm -rf %s'%(self.filename,self.filename.replace('.zip',''),self.filename))
                                print("completed successfully ..")
                                print("output: "+self.filename.replace('.zip',''))

if __name__ == "__main__":
        if (len(sys.argv)) !=2:
                print("++ ussage: "+sys.argv[0]+" https://github.com/USER_ID/REPO_NAME.git ++")
        else:
                try:
                        main()
                except:
                        sys.exit("[!] Exiting ...")
