#pip3 install pypac
#pip3 install pymmh3
#special thanks to Devansh batham on his favicon osint techniques
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

  	MiniScript for detecting Solarwinds Sunburst

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
					print(f"{spacing}(Critical) {url} is vulnerable to version: {i}")
				else:
					print(f"{spacing}(Fail) {url} does not contain vulnerable version: {i}")
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

	for i in a.keys():
		if i in Signature.keys():
			print(f"{Signature[i]} {str(i)} Total URLs to test: {str(len(a[i]))}")
			if len(a[i]) > 0:
				for url in a[i]:
					url = f"{url[:-12]}"
					print(f"{spacing}{url}")
					verify_version(url)

	print("\n[Done]")



if __name__ == "__main__":
	main()
