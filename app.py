from flask import Flask
from flask import request
from flask import json
import json
import re
import requests
import os

class SparkBot(object):
    botKey = os.environ['BOTKEY']
    apicEmUser = os.environ['APICEM_USER']
    apicEmPw = os.environ['APICEM_PW']
    apicEmUrl = os.environ['APICEM_URL']
    botId = os.environ['BOTID']

    def __init__(self):
        pass

    def getSparkTxt(self, msgId):
        myHeaders = {
            'content-type': 'application/json',
            'Authorization': self.botKey
        }
        url = "https://api.ciscospark.com/v1/messages/" + msgId
        response = requests.get(url, headers = myHeaders).json()
        return response['text']

    def replyToRoom(self, roomId, msg):
        myHeaders = {
            'content-type': 'application/json',
            'Authorization': self.botKey
        }
        url = "https://api.ciscospark.com/v1/messages/"
        payload = {
            "roomId": roomId,
            "text": msg
        }
        response = requests.post(url, headers = myHeaders, data = json.dumps(payload)).json()
        return True
        
    def getApicTicket(self):
        url = self.apicEmUrl + '/api/v1/ticket'
        myHeaders = {
            'content-type': 'application/json'
        }
        payload = {
            "username": self.apicEmUser,
            "password": self.apicEmPw
        }
        response = requests.post(url, verify = False, headers = myHeaders, data = json.dumps(payload)).json()
        return response['response']['serviceTicket']
     
    def deleteApicTicket(self, ticketId):
        url = self.apicEmUrl + '/api/v1/ticket/' + ticketId
        myHeaders = {
            'content-type': 'application/json',
            'X-Auth-Token': ticketId
        }
        response = requests.delete(url, verify = False, headers = myHeaders)
        return True
     
    def createPathTrace(self, ticketId, protocol, sourceIP, sourcePort, destIP, destPort):
        url = self.apicEmUrl + '/api/v1/flow-analysis/'
        myHeaders = {
            'content-type': 'application/json',
            'X-Auth-Token': ticketId
        }
        payload = {
            'protocol': protocol,
            'sourceIP': sourceIP,
            'sourcePort': sourcePort,
            'destIP': destIP,
            'destPort': destPort,
            'periodicRefresh': 'false'
        }
        response = requests.post(url, verify = False, headers = myHeaders, data = json.dumps(payload)).json()
        return response['response']['flowAnalysisId']
    
    def getPathTrace(self, ticketId, flowId):
        url = self.apicEmUrl + '/api/v1/flow-analysis/' + flowId
        myHeaders = {
            'content-type': 'application/json',
            'X-Auth-Token': ticketId
        }
        response = requests.get(url, verify = False, headers = myHeaders).json()
        status = response['response']['request']['status']
        path = []
        for devices in response['response']['networkElementsInfo']:
            path += [{ 'ip':devices['ip'], 'type':devices['type']}]
        return {
            'status': status,
            'path': path
        }

    def getBotId(self):
        return self.botId



app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello World!"

@app.route("/spark", methods=['GET', 'POST'])
def spark():
    bot = SparkBot()
    if(request.method == "POST"):
        jsondata = request.json
        sparkmsg = bot.getSparkTxt(jsondata['data']['id'])
        sparkroom = jsondata['data']['roomId']
        if(jsondata['data']['personId'] == bot.getBotId()):
            return ('', 204)

        ## Check for Path Trace Request
        tracecheck = re.search("!trace ([0-9\.]+):([0-9]+) ([0-9\.]+):([0-9])+ (tcp|udp|icmp)",sparkmsg)
        if tracecheck:
            apicticket = bot.getApicTicket()
            pathtraceid = bot.createPathTrace(
                apicticket,
                tracecheck.group(5),
                tracecheck.group(1),
                tracecheck.group(2),
                tracecheck.group(3),
                tracecheck.group(4)
            )
            bot.deleteApicTicket(apicticket)
            bot.replyToRoom(sparkroom, "Path trace initiated, check it with !results "+ pathtraceid)
            return ('', 204)

        ## Check for Path Trace Results
        result = re.search("!results ([0-9a-f\-]+)", sparkmsg)
        if result:
            apicticket = bot.getApicTicket()
            path = bot.getPathTrace(apicticket,result.group(1))
            bot.deleteApicTicket(apicticket)
            pathmsg = "Overall status: " + path['status']
            pathmsg += " :: "
            pathcount = len(path['path'])
            px = 0
            for devlist in path['path']:
                px += 1 
                pathmsg += devlist['ip'] + ' (' + devlist['type'] + ')'
                if(px != pathcount):
                    pathmsg += " <--> "
            bot.replyToRoom(sparkroom, "Path trace complete. " + pathmsg)
            return ('', 204)
        
        ## Provide static-defined host lookups via Sparkbot
        host = re.search("!host (merrill-laptop|exchange)", sparkmsg)
        if (host and (host.group(1) == 'merrill-laptop')):
            bot.replyToRoom(sparkroom, "merrill-laptop 65.1.1.46")
            return ('', 204)
        if (host and (host.group(1) == 'exchange')):
            bot.replyToRoom(sparkroom, "exchange 212.1.10.20")
            return ('', 204)
        else:
            bot.replyToRoom(sparkroom, "Command not valid.")
            return ('', 204)
    else:
        return("Hello World")


if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0')
