import sys
import requests
import json

if len(sys.argv) == 1:
	print("Error: Please Check Syntax!!")
	print("Plesae Input Command Like Below")
	print("Usage: python3 {} [URL]".format(sys.argv[0]))
	print("Example: python3 WAF.py https://aaa.bbb.ccc")
	exit(1)

url = sys.argv[1] #URL 
file = open("Patterns.txt","r") #Pattern File, "r" is read only mode

#Initial Variables
request_count	= 0
success_count 	= 0 
failed_count 	= 0 
allowed_count 	= 0 
blocked_count 	= 0 
error_count 	= 0 

PASS = []
#Headers
headers = {'User-Agent': 'galaxy', 'Contents-Type': 'application/json'} 
#cookies
cookies = {'session_id': 'ID'} 


for waf in file:
	request_count += 1
	print('> GET {}{}'.format(url, waf.strip())) #strip is remove meaningless space
	try:
		request = requests.get(url, params=waf, headers=headers) # Can change method,parameter,headers,cookies
		print("< status_code = {}{}".format(request.status_code, headers))
		success_count += 1
		if request.status_code == 200:
			allowed_count += 1
			PASS.append(waf)
		elif request.status_code == {400, 403}:
			blocked_count += 1
		else:
			print('** Failed: status_code={}, params: {}'.format(request.status_code, waf))
	except Exception as ex:
		failed_count += 1

print("\n")
print('## WAF Test {} ##'.format(url))
print('  Total requests: {:} requests'.format(request_count))
print('Success requests: {:} requests'.format(success_count))
print(' Failed requests: {:} requests'.format(failed_count))
print('Allowed requests: {:} requests'.format(allowed_count))
print('Blocked requests: {:} requests'.format(blocked_count))
print("\n")

file.close()

file_pass = open('TSE_Security.json', 'w') # save as Json Filename, "w" is write mode
file_pass.write(json.dumps(PASS, indent=2, ensure_ascii=False))
file_pass.close()




