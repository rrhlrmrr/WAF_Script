import sys
import requests
import argparse
import json

#Headers
headers = {'User-Agent': 'TSE_TEST'} 
#cookies
cookies = {'session_id': 'ID'}

#GET Functions
def GET():
	GLIST = [] #Initial List
	
	G_request_count	= 0 #Initial Variables
	G_success_count = 0 
	G_failed_count 	= 0 
	G_allowed_count = 0 
	G_blocked_count = 0 

	
	gfile = open("GET.txt", "r") #Pattern File, "r" is read only mode
	for gwaf in gfile:
		G_request_count += 1
		print('> GET {}{}'.format(gurl, gwaf.strip())) #strip is remove meaningless space
		try:
			g_request = requests.get(gurl, params=gwaf, headers=headers) # Can change method,parameter,headers,cookies
			print("< status_code = {} headers = {}".format(g_request.status_code, headers))
			G_success_count += 1
			if g_request.status_code == 200:
				G_allowed_count += 1
				GLIST.append(gwaf)
			elif g_request.status_code == 403:
				G_blocked_count += 1
			else:
				print('** Failed: status_code={}, params: {}'.format(g_request.status_code, gwaf))
		except Exception as gex:
			G_failed_count += 1
	print("\n")
	print('## WAF GET Test {} ##'.format(gurl))
	print('  Total requests: {:} requests'.format(G_request_count))
	print('Success requests: {:} requests'.format(G_success_count))
	print(' Failed requests: {:} requests'.format(G_failed_count))
	print('Allowed requests: {:} requests'.format(G_allowed_count))
	print('Blocked requests: {:} requests'.format(G_blocked_count))
	print("\n")
	gfile.close()
	file_pass = open('TSE_GET.json', 'w') # Format as Json, "w" is write mode
	file_pass.write(json.dumps(GLIST, indent=2, ensure_ascii=False))
	file_pass.close()
	return 0

#POST Function
def POST():
	
	#Initial Variables
	P_allowed_count = 0 
	P_blocked_count = 0 

	# Format Change as dict
	
	#Format as dict for xml
	PDICT = {}
	pfile = open("POST.txt", "r", encoding="UTF=8") #Pattern File, "r" is read only mode
	for line in pfile:
		key, value = line.split()
		PDICT[key] = value
	
	"""
	#Format as dict for json
	PDICT = {}
	pfile = open("POST.txt", 'r', encoding="UTF-8")
	for line in pfile:
		items = line.split()
		key, values = items[0], items[1:]
		PDICT[key] = values
	"""
	PLIST=[]	
	print('> POST {}{}'.format(purl, PDICT)) #strip is remove meaningless space
	p_request = requests.post(purl, data=PDICT) #json= or data=
	print('< status_code = {} Content-Type = {} body = {}'.format(p_request.status_code, p_request.request.headers['Content-Type'], p_request.request.body))
	if p_request.status_code == 200:
		P_allowed_count += 1
		PLIST.append(p_request.request.body)
	elif p_request.status_code == 403:
		P_blocked_count += 1
	else:
		print('** Failed: status_code={}, body: {}'.format(p_request.status_code, p_request.request.body))

	print("\n")
	print('## WAF POST Test {} ##'.format(purl))
	print('Allowed requests: {:} requests'.format(P_allowed_count))
	print('Blocked requests: {:} requests'.format(P_blocked_count))
	print("\n")
	pfile.close()
	file_pass = open('TSE_POST.json', 'w') # Format as Json, "w" is write mode
	file_pass.write(json.dumps(PLIST, indent=2, ensure_ascii=False))
	file_pass.close()
	return 0

#Options
parser = argparse.ArgumentParser()
parser.add_argument("-g", "--get",
                help="Use HTTP Get Method")
parser.add_argument("-p", "--post",
				help="Use HTTP Post Method")
args = parser.parse_args() #After analysis into the variables

gurl = args.get  #GET Options URL
purl = args.post #POST Options URL

#Select option
if str(sys.argv[1]) in {'-g', '--get'}:
	GET()
elif str(sys.argv[1]) in {"-p", "--post"}:
	POST()
