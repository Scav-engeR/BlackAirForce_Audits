import os
import re
import urllib

def runcrawler(site):
	rawstr = "://(\d+\.\d+\.\d+\.\d+\:\d+)"
	try:
		outfile = re.findall(rawstr,site)[0].replace(":","-")
		print(outfile)
	except Exception as e:
		outfile = site.replace("http://","").replace("https://","").replace(":","-").replace("/","")
	try:
		cmd = "./xrayzor.py webscan --basic-crawler {0} --html-output ./html/{1}.html".format(site,outfile)
		print(cmd)
		os.system(cmd)
	except Exception as e:
		pass

# 检查url是否重复扫描
def checklog(site):
	logsites = open("checklog.txt","r").readlines()
	for logsite in logsites:
		site = site.replace("\n","")
		logsite = logsite.replace("\n","")
		if logsite == site:
			return False
	return True

if __name__ == "__main__":
	sites = open("urls.txt","r")
	for site in sites:
		if checklog(site):
			site = site.replace("\n","")
			runcrawler(site)
			with open("checklog.txt","a+") as f:
				f.write(site + "\n")
