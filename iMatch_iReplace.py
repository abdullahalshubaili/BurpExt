# The goal of this burp extension is to encode b64 the value of the parameter 'fw' which sqlmap will be injecting (param 'fw' is json so that why we are looking for work-around)

#so far all i can do is printing the value of 'fw'
from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from datetime import datetime
import re
import sys
import os

newParam = ""

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("imatch and ireplace")
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)
        return
   
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        global newParam    
        if messageIsRequest:

            requestInfo = self._helpers.analyzeRequest(currentRequest)
            
            parameter = requestInfo.getParameters()
            #print "Intercepting message at:", parameter
            #newHeaders = list(parameter)
            #newHeaders.append("hiiiiii")        
            parameters = requestInfo.getParameters()
            #print newHeaders
            
            for parameter in parameters:
                
                print "parameter:"
                print parameter.getName()
                tocompare = parameter.getName()
                
                print "parameter value:"
                print parameter.getValue()
                
                json = parameter.getValue()
                encodejson = self._helpers.base64Encode(json)
                print "encode json ",encodejson
                newParam2 =  "fw="+encodejson
                newParam = [newParam2]
                print newParam
            
            if 'fw' in tocompare:
                print "hhhh"
                #newParam.append(newParam)
                print "after append ",newParam
                
                
               # for p in self._helpers.analyzeRequest(currentRequest.getRequest()).getParameters():
               #     newRequest = []
               #     newRequest = self._helpers.buildParameter(parameter.getName(),"a",parameter.getType())
               #     print "newRequest",newRequest
               #     currentRequest.setRequest(newRequest)
               #     print "currentRequest",currentRequest
                    #encodeme.append(self.helpers.base64Encode(encodeme) + parameter.getValue())
                    #encodeme.append("via: " + parameter.getValue())
                   # newme = self._helpers.removeParameter(currentResquest,parameter)
                   # currentRequest.setRequest(newme)
                   # print newme
            #        testmario = self._helpers.removeParameter(currentRequest.getRequest(), parameter)
            #        currentRequest.setRequest(testmario)
            #if     not messageIsRequest:
            return newParam
    print "hmmmm "
    
    def processProxyMessage(self, messageIsRequest, message):
        print "time for changing", newParam
        
        #n = message.getParameter()
        #print "plapalpalpalpalpalpalpalpal",n
        
        if messageIsRequest:
            messageInfo = message.getMessageInfo()
            headers =  self._helpers.analyzeRequest(messageInfo.getRequest()).getHeaders()
            
            
            #HERE extract the value of 'fw' param then b64encode it then pass it to self._helpert.buildHttpMessage 
            
            head = headers.get
            print "headers",headers
#            for header in  headers:
#                #ip = map(str, (random.randint(0, 255)  for n in range(4))))
#		ip = '10.10.10.10'
#                xforward = "asdasd"
#
#                #globalv = self._helpers.buildHttp
#
#		headers.add(xforward)
#		newRequest = self._helpers.buildHttpMessage(headers ,None) 
#		messageInfo.setRequest(newRequest)
