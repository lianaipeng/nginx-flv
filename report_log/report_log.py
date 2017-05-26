#!/usr/bin/python
# edge log monitor  
import json
import time
import httplib
import urllib
import hashlib
import pycurl
import StringIO

REPORT_POLL     = 10
LOG_FILE        = '/home/MOMO/servers/nginx-flv/logs/rtmp/rtmp.log'

OFFSET_FILE     = './log_offset.txt'
def get_log_offset():
    linesc = 0
    offset = 0
    try:
        f = open(OFFSET_FILE, 'r') 
        try: 
            lines = f.readlines()
            for line in lines :  
                splits = line.split(":")
                if len(splits) == 2 and splits[0] == "offset":
                    offset = int(splits[1])
                elif len(splits) == 2 and splits[0] == "linesc":
                    linesc = int(splits[1])
            # end for
        finally:
            f.close();
            print "OK: close this file"
            return linesc,offset
    except IOError:
        print "Error: not found file or open file failed"
    return 0,0
#end get_log_offset()

def set_log_offset(linesc, offset):
    try:
        f = open(OFFSET_FILE, 'wb')
        try:
            ostr = "linesc:%d\noffset:%d" % (linesc,offset)
            f.write(ostr)
        finally:
            f.close()
            print "OK: close this file"
    except IOError:
        print "Error: not found file or open file failed"
# end set_log_offset

def send_log_content(sjson) :
    current_ts = int(time.time())
    
    secret = "46a654742f93ac6be5b3645c74d2574f"
    content = str(current_ts) + secret + sjson + str(current_ts)
    
    md5 = hashlib.md5()   
    md5.update(content)   
    sign = md5.hexdigest() 
    
    url = "https://live-api.immomo.com/ext/edge/report"
    conn = httplib.HTTPSConnection("live-api.immomo.com",443)

   # ########## GET request
   # param = "?time=" + str(current_ts)
   # param += "&random=" + str(current_ts)
   # param += "&sign=" + str(sign)
   # param += "&sJson="+ str(sjson)
   # url += param
   # conn.request(method="GET", url=url)
   # print "#########################"
   # response = conn.getresponse()
   # res= response.read()
   # print res 
    
    ########## POST request
    param = "time=" + str(current_ts)
    param += "&random=" + str(current_ts)
    param += "&sign=" + str(sign)
    param += "&sJson="+ str(sjson)
    # print param
    c = pycurl.Curl()
    c.setopt(c.URL, url)
    buf = StringIO.StringIO()
    c.setopt(c.WRITEFUNCTION, buf.write)
    c.setopt(c.POSTFIELDS, str(param))
    c.setopt(c.TIMEOUT, 1)
    
    c.perform()
    if c.getinfo(c.HTTP_CODE) != 200 :
        print buf.getvalue()
    buf.close()
    c.close()
#end send_log_content

watch_dic = {}
def get_line_json(line) :
    str_list = line.split("EDGE")
    if len(str_list) == 3:
        # print str_list[1]
        json_obj = json.loads(str_list[1])
        if json_obj.has_key('_type') == False :
            return
        
        _type = json_obj['_type']
        if (_type == 'v2.edgePullStart' or _type == 'v2.edgePullStop' or 
                _type == 'v2.edgePushStart' or _type == 'v2.edgePushStop' or
                _type == 'v2.edgeBufferStart' or _type == 'v2.edgeBufferStop' or
                _type == 'v2.edgeBackSource'):
            #print _type
            send_log_content(str_list[1])
        elif (_type == 'v2.edgePullWatch' or _type == 'v2.edgePushWatch'):
            if (json_obj.has_key('name') and json_obj.has_key('protocolType') and 
                    json_obj.has_key('timestamp') and json_obj.has_key('session') and
                    json_obj.has_key('serverIP') and json_obj.has_key('clientIP') and
                    json_obj.has_key('host') and json_obj.has_key('body') and
                    json_obj.has_key('_type')) :
                #print _type
                session = json_obj["session"]
                body = json_obj["body"]
                body['timestamp'] = json_obj['timestamp']

                if watch_dic.has_key(session) :
                    #print "watch_dic has key " + session
                    watch_dic[session]["body"].append(body)
                else :
                    #print "watch_dic has no key " + session
                    tmp_dic = {}
                    tmp_dic['_type']        = json_obj['_type']
                    tmp_dic['name']         = json_obj['name']
                    tmp_dic['protocolType'] = json_obj['protocolType']
                    tmp_dic['timestamp']    = json_obj['timestamp']
                    tmp_dic['serverIP']     = json_obj['serverIP']
                    tmp_dic['clientIP']     = json_obj['clientIP']
                    tmp_dic['session']      = json_obj['session']
                    tmp_dic['host']         = json_obj['host']
                    tmp_dic['body']         = [body]

                    watch_dic[session] = tmp_dic
            else:
                print "Error: no key exist"
        else:
            print "Error: error _type or no _type"
    else:
         print "Error: error string format. EDGE count:" + str(len(str_list)-1)
# end get_line_json 


def get_log_content(offset):
    linecount = 0
    newoffset = int(offset)
    try :
        f = open(LOG_FILE, 'r')
        f.seek(int(offset), 0)
        try :
            lines = f.readlines()
            for line in lines :
                linecount += 1
                newoffset += len(line)  
                print "linecount:%d offset:%d" % (int(linecount), int(newoffset))
                get_line_json(line)
        finally:
            f.close()
            print "OK: close this file"
            return linecount,newoffset
    except:
        print "Error: not found file or open file failed"
    return 0,0
# end get_log_content


if __name__ == "__main__":
    while True:
        print "############## poll start ##############"
        oldlinesc, oldoffset = get_log_offset()
        linesc = oldlinesc
        print "old linesc:%d offset:%d" % (oldlinesc, oldoffset)
        newlinesc,newoffset = get_log_content(oldoffset)
        linesc += int(newlinesc)
        print "new linesc:%d offset:%d" % (linesc, newoffset)
        set_log_offset(linesc, newoffset)
        #set_log_offset(0)
    
        for k,v in watch_dic.items():
            sjson = json.dumps(v)
            #print sjson
            send_log_content(sjson)
        watch_dic.clear()
        
        time.sleep(REPORT_POLL)
    # end while 
# end __main__
