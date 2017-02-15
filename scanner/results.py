
import tabulate
import sqlite3


def show_data():
	''' Show database registers '''
	db = sqlite3.connect('vuln.db')
	cursor = db.cursor()
	result = []
	data = cursor.execute('''SELECT url, vuln, method, postParams FROM VULNS''')
	headers = ["URL", "PAYLOAD","METHOD","POSTPARAMS"]
	for row in data:
		result.append([row[0], row[1], row[2] , row[3]])
	print ""
	print tabulate.tabulate(result, headers)
	print ""
	print ""
	db.close(); 


show_data()