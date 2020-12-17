#pip3 install pypac
#pip3 install pymmh3

import pymmh3 as mmh3 #we are using pure python implementation of mmh3 
from multiprocessing.pool import ThreadPool
from time import time as timer
from pypac import PACSession #for bypass proxy setting using pac for corporate env, also substitute requests module
import codecs
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#initialize session
s = PACSession()
#max time to wait for request connection
max_time = 3

#Signature for solarwind orion
Signature = {-1776962843:"Solarwinds Orion"}

#vulnerable version string
string_check = ['2020.2','2019.4']
a = {}
spacing = "    "


def display_banner():
	banner_text = '''

  	Minimal Tool for detecting SolarWind Sunburst

  	developer: JT 
  	github: https://github.com/pas3rr
	'''
	print(f"{banner_text}")


def get_request(url):
	try:
		r = s.get(url, verify=False,timeout=max_time)
		favicon = codecs.encode(r.content,"base64")
		hash = mmh3.hash(favicon)
		key = hash
		#set the key to a dict, with optional value as list
		a.setdefault(key, [])
		a[key].append(url)
		return url, hash, None

	except Exception as e:
		return url, None, e

def verify_version(url):
		try:
			urls_version = f"{url}/Orion/Login.aspx"
			r = s.get(urls_version,verify=False,timeout=max_time)
			for i in string_check:
				success = re.search(i, r.text)
				false_positive = re.search("2020.2.1", r.text)
				if success and false_positive == None:
					print(f"{spacing}(Critical){url} is vulnerable")

		except Exception as e:
			print(e)


def main():
	display_banner()
	urls_favicon = []
	file = open("url.txt", "r")

	for line in file:
		if line.strip()[-1] == "/":
			urls_favicon.append(line.strip() + "favicon.ico")	
		else:
			urls_favicon.append(line.strip() + "/favicon.ico")

	print(f"\n[Requesting URLs]")
	start = timer()
	results = ThreadPool(20).imap_unordered(get_request, urls_favicon)

	for url, hash, error in results:
		if error is None:
			#url[:-12] is for without favicon
			print(f"{spacing}(Success) {url[:-12]}")
		else:
			print(f"{spacing}(Error) {url[:-12]}")

	print(f"\n[Detection Results]")

	#debug Signature keys
	#print(Signature.keys())

	# for each of the keys in a 
	for i in a.keys():
		# check for the keys in a with Signature keys
		if i in Signature.keys():
			#print out Signature total hits 
			print(f"{Signature[i]} {str(i)} Total Hit: {str(len(a[i]))}")
			#if there is a hash value in a.[i] 
			#(a[i]) is a list of urls
			if len(a[i]) > 0:
				#for url in a.[i]
				for url in a[i]:
					#for each of the success url, we check for the version
					url = f"{url[:-12]}"
					print(f"{spacing}{url}")
					verify_version(url)

	print("\n[Done]")



if __name__ == "__main__":
	main()
