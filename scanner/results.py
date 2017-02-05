
import tabulate
import sqlite3


def show_data():
	''' Show database registers '''
	db = sqlite3.connect('vuln.db')
	cursor = db.cursor()
	result = []
	data = cursor.execute('''SELECT url, vuln FROM VULNS''')
	headers = ["URL", "PAYLOAD"]
	for row in data:
		result.append([row[0], row[1]])
	print ""
	print tabulate.tabulate(result, headers)
	print ""
	print ""
	db.close(); 


show_data()