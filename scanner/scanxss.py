from urllib2 import urlopen
from BeautifulSoup import BeautifulSoup
import urllib
import urlparse
import threading
import sys
import urllib2
import requests 
from cookielib import CookieJar
import sqlite3
import time

########### CONSTANTS ########### 
 
#.............SQL QUERIES.............#
DELETE_TABLE_QUERY = '''DELETE FROM VULNS''';
INSERT_VULN_QUERY = '''INSERT INTO VULNS(url, vuln)VALUES(?,?)''';
SELECT_VULNS_QUERY = '''SELECT vuln FROM VULNS'''; 
#............END SQL QUERIES..............#
#.................ERRORS..................#
ERR_DB_CONNECTION = "Error connecting to database";
ERR_PARSING_INPUTS = "Can not parse inputs";
ERR_INVALID_URL = 'Invalid URL, format https://domain.com?queryname=??';
ERR_PAYLOADS_NOT_EXISTS = 'payloads.txt not exist'
ERR_OPEN_PAGE = 'Verify your conection or the url';
ERR_SUBMIT_FORM = "fail to submit form";
#...............END ERRORS................#
#...............MESSAGES..................#
LINKS_FOUNDED = "Links founded %s";
POSTS_FOUNDED = "Posts founded %s";
SEARCHING_XSS = "Searching XSS";
SEARCHING_LINKS = "Serching Links...";
EXECUTE_RESULTS_TABLE = "Execute 'python results.py' when script finish.";
WITHOUT_VULNERABILITIES = "there are not vulnerabilities in url that you enter";
INICIAL_MESSAGE = """
	XSS.py search web xss vulnerabilities by analyzing the html code.
	If input url has parameters then first will analyze said url with 
	the list available in payloads.txt,then vulnerabilities found will
	be tested in the rest of the links in HTML code. But if the input 
	url does not contain parameters, then the available links will be 
	searched and then , payloads will be applied. \n\n\n""";
#.............END MESSAGES................#

	    	

def main():

 	inputs = getInputs();										
	splitedUrl = splitUrl(inputs.get('url'));
	payloads = readPayloads();									

	if not splitedUrl.get('query'):
		soup,cookiejar = openPage(inputs.get('url'),inputs.get('cookies'));
		links = getLinks(soup,splitedUrl);
		gets,posts = getForms(soup,splitedUrl);
		links = links + gets; 

		print setTextStyle(LINKS_FOUNDED % (str(len(links))));
		print setTextStyle(POSTS_FOUNDED % (str(len(posts))));
		print setTextStyle(SEARCHING_XSS);
		print setTextStyle(EXECUTE_RESULTS_TABLE);

		if links:
			threadManager(links,payloads,inputs.get('threads'),inputs.get('cookies'),cookiejar,'link');
		if posts:
			threadManager(posts,payloads,inputs.get('threads'),inputs.get('cookies'),cookiejar,'post');

	else:
		print setTextStyle(SEARCHING_XSS);

		vulnerabilities = list();
		cursor = database.cursor();
		findXssQueries(inputs.get('url'),payloads,inputs.get('cookies'));
		vulnTable = cursor.execute(SELECT_VULNS_QUERY);
		[vulnerabilities.append(row[0]) for row in vulnTable]; # VULNERABILITIES ON INPUT URL PARAMS
		soup,cookiejar = openPage(splitedUrl.get('address'),inputs.get('cookies'));

		links = getLinks(soup,splitedUrl);
		gets,posts = getForms(soup,splitedUrl); 
		links = links + gets;
		
		print setTextStyle(LINKS_FOUNDED % (str(len(links))));
		print setTextStyle(POSTS_FOUNDED % (str(len(posts))));
		print setTextStyle(EXECUTE_RESULTS_TABLE);

		if vulnerabilities:
			if links:
				threadManager(links,vulnerabilities,inputs.get('threads'),inputs.get('cookies'),cookiejar,'link');
			if posts:
				threadManager(posts,vulnerabilities,inputs.get('threads'),inputs.get('cookies'),cookiejar,'post');	
		else:
			print setTextStyle(WITHOUT_VULNERABILITIES);	
			sys.exit(0);

				
def databaseConnection():
	try:
		database = sqlite3.connect('vuln.db',check_same_thread = False);
		cursor = database.cursor();
		cursor.execute(DELETE_TABLE_QUERY);
		database.commit();
		return database;
	except:
		print setTextStyle(ERR_DB_CONNECTION);
		sys.exit(0);

def getInputs():
	try:
		url = raw_input(setTextStyle('URL: ')).strip();
		threads = raw_input(setTextStyle('THREADS: ')).strip();
		cookie = raw_input(setTextStyle('COOKIE (enter to continue): ')).strip();
		inputs = dict();
		cookies = list();

		if not threads:
			threads = 1;
		else:
			threads = int(threads);

		while cookie:
			cookies.append(cookie);
			cookie = raw_input(setTextStyle('COOKIE (enter to continue): ')).strip();

		inputs['url'] = url;
		inputs['threads']	= threads;
		inputs['cookies'] = cookies;
		return inputs;
	except: 
		print setTextStyle(ERR_PARSING_INPUTS);	


def splitUrl(url):
	try: 
		parser = urlparse.urlparse(url);
		protocol = '%s%s' % (parser.scheme,'://');
		domain = parser.netloc;
		path = parser.path;
		query = parser.query;
		address = '%s%s%s' % (protocol,domain,path);

		if protocol and domain and path and address:
			data = dict({'url':url,
						 'protocol':protocol,
						 'domain': domain,
						 'path':path,
						 'query':query,
						 'address':address});
			return data;
		else:
			print setTextStyle(ERR_INVALID_URL);
			sys.exit(0);

	except:
		print setTextStyle(ERR_INVALID_URL);		
		sys.exit(0);

def readPayloads():
	try:
		file = open('payloads.txt', 'r'); 
		lines = file.readlines();
		payloads = [x.strip() for x in lines];
		file.close();
		return payloads;
	except:
		print setTextStyle(ERR_PAYLOADS_NOT_EXISTS);
		sys.exit(0);


def openPage(url,cookies):
	try:
		cookiejar = CookieJar();
		opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookiejar));
		for cookie in cookies:
			opener.addheaders.append(('Cookie', cookie));
		page = opener.open(url);
		soup = BeautifulSoup(page);
		return soup,cookiejar;
	except:
		print setTextStyle(ERR_OPEN_PAGE);
		sys.exit(0);	

def getLinks(soup,data):
	START_QUERY_PARAM = '?';
	NEW_QUERY_PARAM = '=??&';
	links = list();
	for a in soup.findAll('a', href=True):
		href = urlparse.urlparse(a.get('href'));
		if (not href.netloc or href.netloc == data.get('domain')) and href.query :         #Only get links of the same domain
			queryParser = urlparse.parse_qsl(href.query);
			queryParams = START_QUERY_PARAM;
			for x,y in queryParser:
				queryParams += x + NEW_QUERY_PARAM;
			queryParams = queryParams[:-1]
			if not href.netloc:
				link = '%s%s%s%s' % (data.get('protocol'),data.get('domain'),href.path,queryParams);
				if link not in links and  data.get('url') != link:
					links.append(link);  
			else: 
				link = href.geturl()+queryParams;
				if link not in links and  data.get('url') != link:
					links.append(link);            	    

	return links; 	

def getForms(soup,data):
	NEW_QUERY_PARAM = '=??&';
	START_QUERY_PARAM = '?';
	getForms = list();
	postForms = list();
	
	for form in soup.findAll('form'):
		domain = '' ;
		if form.get('action'):
			action = urlparse.urlparse(form.get('action'));
			domain = action.netloc.replace('www.','');
			address = '%s%s%s' % (data.get('protocol'),domain,action.path);
			url = action.geturl();
			
		if domain == data.get('domain') or not domain or form.get('action') == START_QUERY_PARAM: 
			if form.get('method') in ['GET','get',None] :
				inputs = form.findAll('input');
				queryParams = START_QUERY_PARAM;

				for element in inputs:
					if element.get('type') != 'submit':
						queryParams += str(element.get('name')) + NEW_QUERY_PARAM;
				queryParams = queryParams[:-1];
				if not form.get('action'):
					link = data.get('address') + queryParams;
				else:
					if data.get('domain') in form.get('action'):
						link = form.get('action') + queryParams;
					else:
						link = 	data.get('protocol') + data.get('domain') +  form.get('action') + queryParams;
				
				if link not in getForms and data.get('url') != link:
					getForms.append(link);
                
			else:
				inputs = form.findAll('input')
				params = list();
				for element in inputs:
					if element.get('type') != 'submit':
						params.append(str(element.get('name')));
				
				textareas = form.findAll('textarea');	
				for textarea in textareas:
					params.append(str(textarea.get('name')));

				if not form.get('action') or form.get('action') == START_QUERY_PARAM:
					link = data.get('address'); 
				else:
					if data.get('address')[-1:] != '/':
						link = data.get('address')+form.get('action')
					else:
						link = data.get('address')[:-1]+form.get('action');	
				if params:
					postForms.append([link,params]);						 		
	
	return getForms,postForms


def threadManager(links,payloads,threads,cookies,cookiejar,type):
	linksByThread = len(links) / threads
	if not linksByThread:
		linksByThread = 1;
	threadLinks = [links[x:x+linksByThread] for x in xrange(0, len(links), linksByThread)];
	for i in range(len(threadLinks)):
		thread = None; 
		if type == 'link':
			thread = threading.Thread(target=evalLinks, args=(threadLinks[i],payloads,cookies)); 
		else:
			thread = threading.Thread(target=evalPostForms, args=(threadLinks[i],payloads,cookiejar));
		thread.lock = threading.Lock()
		thread.start()
		time.sleep(0.5)
	      

def evalLinks(links,payloads,cookies):
	for link in links:
		findXssQueries(link,payloads,cookies);


def findXssQueries(link,payloads,cookies):
	QUERY_VAR = '??'
	cursor = database.cursor();
	for payload in payloads:
		quoted_query = urllib.quote(payload);
		url_payload = link.replace(QUERY_VAR,quoted_query);
		try:
			opener = urllib2.build_opener()
			for ck in cookies:
				opener.addheaders.append(('Cookie', ck));

			urlop = opener.open(url_payload);	
			if urlop.getcode() == 200:
				soup = BeautifulSoup(urlop);
				xss = findXssInResponse(link,soup,payload)    
				if xss:
					cursor.execute(INSERT_VULN_QUERY, (link,payload))
					database.commit();

		 				      				
		except:
			dummy = "";
			

def evalPostForms(forms,payloads,cookieJarResponse):
	for form in forms:
		findXssOnPostForms(form[0],form[1],payloads,cookieJarResponse)


def findXssOnPostForms(link,inputs,payloads,cookiejar):
	EQUALS = '=';
	session = requests.Session();
	opener = urllib2.build_opener();
	cursor = database.cursor();

	for cookie in cookiejar:
		opener.addheaders.append(('Cookie', cookie.name+EQUALS+cookie.value));

	for payload in payloads:
		data = {}
		for inputData in inputs:
			data[inputData] = payload
		try:	
			data_encoded = urllib.urlencode(data)	
			response = opener.open(link, data_encoded)
			soup = BeautifulSoup(response)
			xss = findXssInResponse(link,soup,payload)    
			if xss:
				cursor.execute(INSERT_VULN_QUERY, (link,payload))
				database.commit();
		except:
			dummy = ""
			
		
def findXssInResponse(link,soup,payload):
	SCRIPT_TAG = "<script>";
	inlineParams = list(['<a onclick="','<img src="','<IFRAME src="'])

	if SCRIPT_TAG in payload:
		blockquotes = soup.findAll('blockquote')
		if not blockquotes:
			for elem in soup.findAll(['script']):
				if str(elem.extract()) == payload:
					return True  
		else:
			inBlockquote = False
			for blockquote in blockquotes:
				for elem in blockquote.findAll(['script']):
					if str(elem.extract()) == payload:
						inBlockquote = True;
			if not inBlockquote:
				for elem in soup.findAll(['script']):
					if str(elem.extract()) == payload:
						return True  		
	else:
		for param in inlineParams:
			if  param+payload in str(soup):
				return True    

	return False			 
				


def setTextStyle(text):
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'
	return BOLD + RED + text + END;



if __name__ == '__main__':

	print setTextStyle(INICIAL_MESSAGE);
	database = databaseConnection();
	main();
